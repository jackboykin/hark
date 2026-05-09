const std = @import("std");
const monotonic = @import("monotonic.zig");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;
const File = Io.File;
const testing = std.testing;
const na = @import("net_address.zig");
const sys = @import("sys.zig");
const tls = @import("tls");

const AddressKey = na.AddressKey;

// ── TcpPooledConnection ─────────────────────────────────────────────

pub const TcpPooledConnection = struct {
    sock: posix.fd_t,
    last_used: i64,
    query_count: u16,
    max_queries: u16 = 200,

    pub fn destroyBroken(self: *TcpPooledConnection, allocator: Allocator) void {
        sys.close(self.sock);
        allocator.destroy(self);
    }

    pub fn isExpired(self: *const TcpPooledConnection) bool {
        return self.query_count >= self.max_queries;
    }

    pub fn recordUse(self: *TcpPooledConnection) void {
        self.query_count +|= 1;
    }

    pub fn initCounters(self: *TcpPooledConnection) void {
        self.query_count = 1;
    }
};

pub const TcpConnectionPool = ConnectionPool(TcpPooledConnection);

// ── PooledConnection (TLS) ──────────────────────────────────────────

pub const PooledConnection = struct {
    sock: posix.fd_t,
    net_reader: File.Reader,
    net_writer: File.Writer,
    tls: tls.Connection,
    last_used: i64,
    /// Per-RFC 7766 §6.2.1: bound queries on a single TLS session. Matches the
    /// Do53 TCP pool cap so DoT and Do53 connection lifetimes are symmetric.
    query_count: u16 = 0,
    max_queries: u16 = 200,

    // Inline buffers — stable addresses since struct is heap-allocated.
    net_read_buf: [tls.input_buffer_len]u8,
    net_write_buf: [tls.output_buffer_len]u8,

    /// Close TLS session and underlying socket.
    pub fn closeAndDestroy(self: *PooledConnection, allocator: Allocator) void {
        self.tls.close() catch {};
        sys.close(self.sock);
        allocator.destroy(self);
    }

    /// Close socket without TLS shutdown (for error paths).
    pub fn destroyBroken(self: *PooledConnection, allocator: Allocator) void {
        sys.close(self.sock);
        allocator.destroy(self);
    }

    pub fn isExpired(self: *const PooledConnection) bool {
        return self.query_count >= self.max_queries;
    }

    pub fn recordUse(self: *PooledConnection) void {
        self.query_count +|= 1;
    }

    pub fn initCounters(self: *PooledConnection) void {
        self.query_count = 1;
    }
};

// ── ConnectionPool (comptime generic) ───────────────────────────────

const max_entries_default: usize = 32;
/// Per-upstream warm-connection cap (RFC 7766 §6.2.2). Bounds concurrent
/// in-flight TCP/DoT queries to a single authoritative.
const per_key_cap: usize = 8;

pub fn ConnectionPool(comptime Conn: type) type {
    return struct {
        const Self = @This();

        /// Per-key LIFO of idle connections. `append` at the end, `pop`
        /// from the end — reusing the most-recently-used conn keeps the
        /// TCP/TLS session warmest. When full, `appendEvictingOldest`
        /// drops index 0 (insertion-oldest for this key).
        const Slots = struct {
            items: [per_key_cap]*Conn = undefined,
            len: u8 = 0,

            fn isEmpty(self: *const Slots) bool {
                return self.len == 0;
            }

            fn isFull(self: *const Slots) bool {
                return self.len == per_key_cap;
            }

            fn append(self: *Slots, conn: *Conn) void {
                self.items[self.len] = conn;
                self.len += 1;
            }

            fn pop(self: *Slots) *Conn {
                self.len -= 1;
                return self.items[self.len];
            }

            fn appendEvictingOldest(self: *Slots, conn: *Conn) *Conn {
                const evicted = self.items[0];
                for (1..self.len) |i| self.items[i - 1] = self.items[i];
                self.items[self.len - 1] = conn;
                return evicted;
            }

            fn removeAt(self: *Slots, idx: u8) *Conn {
                const evicted = self.items[idx];
                var i: u8 = idx + 1;
                while (i < self.len) : (i += 1) self.items[i - 1] = self.items[i];
                self.len -= 1;
                return evicted;
            }
        };

        allocator: Allocator,
        entries: std.AutoHashMap(AddressKey, Slots),
        total_conns: usize = 0,
        mutex: Io.Mutex = Io.Mutex.init,
        io: Io,
        max_idle_sec: i64 = 30,
        max_entries: usize = max_entries_default,
        now_fn: *const fn () i64 = &monotonic.nowSec,

        pub fn init(allocator: Allocator, io: Io) Self {
            return .{
                .allocator = allocator,
                .entries = std.AutoHashMap(AddressKey, Slots).init(allocator),
                .io = io,
            };
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            var iter = self.entries.iterator();
            while (iter.next()) |entry| {
                const slots = entry.value_ptr;
                for (slots.items[0..slots.len]) |conn| conn.destroyBroken(self.allocator);
            }
            self.entries.deinit();
            self.total_conns = 0;
        }

        /// Retrieve a cached connection for the given key. Returns null if
        /// no idle connection exists or all cached entries for the key
        /// have expired.
        pub fn acquire(self: *Self, key: AddressKey) ?*Conn {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);

            // Opportunistic idle sweep only when pool is above half capacity
            if (self.total_conns >= self.max_entries / 2) self.evictIdleLocked();

            const slots = self.entries.getPtr(key) orelse return null;
            const now = self.now_fn();
            while (!slots.isEmpty()) {
                const conn = slots.pop();
                self.total_conns -= 1;
                const is_stale = now - conn.last_used > self.max_idle_sec;
                if (is_stale or conn.isExpired()) {
                    conn.destroyBroken(self.allocator);
                    continue;
                }
                if (slots.isEmpty()) _ = self.entries.remove(key);
                return conn;
            }
            _ = self.entries.remove(key);
            return null;
        }

        /// Return a connection to the pool (alive=true) or discard it (alive=false).
        pub fn release(self: *Self, key: AddressKey, conn: *Conn, alive: bool) void {
            if (!alive) {
                conn.destroyBroken(self.allocator);
                return;
            }
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            conn.last_used = self.now_fn();
            conn.recordUse();
            self.insertLocked(key, conn);
        }

        /// Store a newly established connection in the pool.
        pub fn store(self: *Self, key: AddressKey, conn: *Conn) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            conn.last_used = self.now_fn();
            conn.initCounters();
            self.insertLocked(key, conn);
        }

        fn insertLocked(self: *Self, key: AddressKey, conn: *Conn) void {
            if (self.total_conns >= self.max_entries) self.evictGlobalOldestLocked();

            const gop = self.entries.getOrPut(key) catch {
                conn.destroyBroken(self.allocator);
                return;
            };
            if (!gop.found_existing) gop.value_ptr.* = .{};

            if (gop.value_ptr.isFull()) {
                const evicted = gop.value_ptr.appendEvictingOldest(conn);
                evicted.destroyBroken(self.allocator);
                // total_conns unchanged: evicted one, added one.
                self.assertCountInvariant();
                return;
            }
            gop.value_ptr.append(conn);
            self.total_conns += 1;
            self.assertCountInvariant();
        }

        /// Debug-only: `total_conns` must match the sum of slot lengths.
        /// Guards against desync in the per-key vs. global bookkeeping.
        fn assertCountInvariant(self: *Self) void {
            if (!std.debug.runtime_safety) return;
            var sum: usize = 0;
            var iter = self.entries.iterator();
            while (iter.next()) |entry| sum += entry.value_ptr.len;
            std.debug.assert(sum == self.total_conns);
        }

        /// Remove connections that have been idle longer than max_idle_sec.
        /// Caller must hold mutex.
        fn evictIdleLocked(self: *Self) void {
            const now = self.now_fn();
            var empty_keys_buf: [max_entries_default]AddressKey = undefined;
            var empty_count: usize = 0;

            var iter = self.entries.iterator();
            while (iter.next()) |entry| {
                const slots = entry.value_ptr;
                var write: u8 = 0;
                for (slots.items[0..slots.len]) |conn| {
                    if (now - conn.last_used > self.max_idle_sec) {
                        conn.destroyBroken(self.allocator);
                        self.total_conns -= 1;
                    } else {
                        slots.items[write] = conn;
                        write += 1;
                    }
                }
                slots.len = write;
                if (slots.isEmpty() and empty_count < empty_keys_buf.len) {
                    empty_keys_buf[empty_count] = entry.key_ptr.*;
                    empty_count += 1;
                }
            }
            for (empty_keys_buf[0..empty_count]) |k| _ = self.entries.remove(k);
            self.assertCountInvariant();
        }

        /// Evict the globally oldest (lowest last_used) connection. Caller
        /// must hold mutex.
        fn evictGlobalOldestLocked(self: *Self) void {
            var oldest_key: ?AddressKey = null;
            var oldest_idx: u8 = 0;
            var oldest_time: i64 = std.math.maxInt(i64);

            var iter = self.entries.iterator();
            while (iter.next()) |entry| {
                const slots = entry.value_ptr;
                for (slots.items[0..slots.len], 0..) |conn, idx| {
                    if (conn.last_used < oldest_time) {
                        oldest_time = conn.last_used;
                        oldest_key = entry.key_ptr.*;
                        oldest_idx = @intCast(idx);
                    }
                }
            }
            if (oldest_key) |k| {
                const slots = self.entries.getPtr(k) orelse return;
                const conn = slots.removeAt(oldest_idx);
                conn.destroyBroken(self.allocator);
                self.total_conns -= 1;
                if (slots.isEmpty()) _ = self.entries.remove(k);
            }
        }
    };
}

// ── Tests ────────────────────────────────────────────────────────────

const TlsPool = ConnectionPool(PooledConnection);

test "AddressKey fromAddress IPv4" {
    const addr = na.initIp4(.{ 1, 1, 1, 1 }, 853);
    const key = AddressKey.fromAddress(addr);
    try testing.expectEqual(@as(u8, @intCast(posix.AF.INET)), key.family);
    try testing.expectEqual(@as(u16, 853), key.port);
    try testing.expectEqual(@as(u8, 1), key.addr[0]);
    try testing.expectEqual(@as(u8, 1), key.addr[1]);
    try testing.expectEqual(@as(u8, 1), key.addr[2]);
    try testing.expectEqual(@as(u8, 1), key.addr[3]);
}

test "AddressKey fromAddress IPv6" {
    const addr = na.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 853, 0, 0);
    const key = AddressKey.fromAddress(addr);
    try testing.expectEqual(@as(u8, @intCast(posix.AF.INET6)), key.family);
    try testing.expectEqual(@as(u16, 853), key.port);
    try testing.expectEqual(@as(u8, 0x20), key.addr[0]);
    try testing.expectEqual(@as(u8, 0x01), key.addr[1]);
}

test "AddressKey equality" {
    const a1 = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));
    const a2 = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));
    const a3 = AddressKey.fromAddress(na.initIp4(.{ 8, 8, 8, 8 }, 853));

    // Same address produces same key
    try testing.expectEqual(a1, a2);
    // Different address produces different key
    try testing.expect(!std.meta.eql(a1, a3));
}

test "ConnectionPool idle eviction with injectable now_fn" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TlsPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    pool.max_idle_sec = 10;
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));

    // Create a fake pooled connection (just for pool mechanics testing)
    const conn = try createTestConnection(testing.allocator);
    pool.store(key, conn);

    // Should be acquirable immediately
    try testing.expect(pool.entries.count() == 1);

    // Advance time past idle threshold
    fake_time = 1020; // 20 seconds later, past max_idle_sec=10

    // acquire should evict the stale entry
    const result = pool.acquire(key);
    try testing.expect(result == null);
    try testing.expect(pool.entries.count() == 0);
}

test "ConnectionPool store and acquire" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TlsPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));

    const conn = try createTestConnection(testing.allocator);
    pool.store(key, conn);

    // Advance time slightly (within idle window)
    fake_time = 1005;
    const acquired = pool.acquire(key);
    try testing.expect(acquired != null);
    try testing.expect(pool.entries.count() == 0); // removed from pool on acquire

    // Release back
    pool.release(key, acquired.?, true);
    try testing.expect(pool.entries.count() == 1);
}

test "ConnectionPool release not alive frees connection" {
    var pool = TlsPool.init(testing.allocator, undefined);
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));
    const conn = try createTestConnection(testing.allocator);

    // Release with alive=false should free
    pool.release(key, conn, false);
    // No leak = success (testing.allocator detects leaks)
}

test "ConnectionPool max entries eviction" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TlsPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    pool.max_entries = 2;
    defer pool.deinit();

    // Store 2 connections
    const conn1 = try createTestConnection(testing.allocator);
    const key1 = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));
    pool.store(key1, conn1);

    fake_time = 1001;
    const conn2 = try createTestConnection(testing.allocator);
    const key2 = AddressKey.fromAddress(na.initIp4(.{ 8, 8, 8, 8 }, 853));
    pool.store(key2, conn2);

    try testing.expectEqual(@as(usize, 2), pool.entries.count());

    // Store a 3rd — should evict the oldest (conn1)
    fake_time = 1002;
    const conn3 = try createTestConnection(testing.allocator);
    const key3 = AddressKey.fromAddress(na.initIp4(.{ 9, 9, 9, 9 }, 853));
    pool.store(key3, conn3);

    try testing.expectEqual(@as(usize, 2), pool.entries.count());
    // conn1's key should be gone
    try testing.expect(pool.entries.get(key1) == null);
}

/// Create a minimal PooledConnection for unit testing pool mechanics.
/// Uses a dup'd /dev/null fd so close() is safe.
///
/// Note: `tls` is `undefined`. Pool tests reach the connection only via
/// `destroyBroken` (which doesn't touch `.tls`), never `closeAndDestroy`
/// (which calls `tls.close()`). If the pool's release path ever switches
/// to `closeAndDestroy`, this helper must populate a real `tls.Connection`.
fn createTestConnection(allocator: Allocator) !*PooledConnection {
    const dev_null = try sys.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    const sock = try sys.dup(dev_null);
    sys.close(dev_null);

    const conn = try allocator.create(PooledConnection);
    conn.* = .{
        .sock = sock,
        .net_reader = undefined,
        .net_writer = undefined,
        .tls = undefined,
        .last_used = 0,
        .net_read_buf = undefined,
        .net_write_buf = undefined,
    };
    return conn;
}

fn createTestTcpConnection(allocator: Allocator) !*TcpPooledConnection {
    const dev_null = try sys.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    const sock = try sys.dup(dev_null);
    sys.close(dev_null);

    const conn = try allocator.create(TcpPooledConnection);
    conn.* = .{
        .sock = sock,
        .last_used = 0,
        .query_count = 0,
    };
    return conn;
}

test "ConnectionPool multi-entry per key (LIFO)" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TlsPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));

    const c1 = try createTestConnection(testing.allocator);
    pool.store(key, c1);
    fake_time = 1001;
    const c2 = try createTestConnection(testing.allocator);
    pool.store(key, c2);
    fake_time = 1002;
    const c3 = try createTestConnection(testing.allocator);
    pool.store(key, c3);

    try testing.expectEqual(@as(usize, 3), pool.total_conns);
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    // LIFO: acquire returns the most recently stored
    const a1 = pool.acquire(key).?;
    try testing.expectEqual(c3, a1);
    const a2 = pool.acquire(key).?;
    try testing.expectEqual(c2, a2);
    const a3 = pool.acquire(key).?;
    try testing.expectEqual(c1, a3);
    try testing.expectEqual(@as(usize, 0), pool.total_conns);
    try testing.expect(pool.acquire(key) == null);

    pool.release(key, a1, true);
    pool.release(key, a2, true);
    pool.release(key, a3, true);
    try testing.expectEqual(@as(usize, 3), pool.total_conns);
}

test "ConnectionPool per-key cap evicts oldest within key" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TlsPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));

    // Fill to per-key cap
    for (0..per_key_cap) |_| {
        const c = try createTestConnection(testing.allocator);
        pool.store(key, c);
        fake_time += 1;
    }
    try testing.expectEqual(@as(usize, per_key_cap), pool.total_conns);

    // One more — triggers appendEvictingOldest, total_conns unchanged
    const c_new = try createTestConnection(testing.allocator);
    pool.store(key, c_new);
    try testing.expectEqual(@as(usize, per_key_cap), pool.total_conns);

    // LIFO: c_new is on top
    const got = pool.acquire(key).?;
    try testing.expectEqual(c_new, got);
    pool.release(key, got, true);
}

test "TlsPool max queries eviction (RFC 7766 §6.2.1)" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TlsPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 853));
    const conn = try createTestConnection(testing.allocator);
    conn.max_queries = 3;
    pool.store(key, conn); // initCounters → query_count = 1

    const a1 = pool.acquire(key).?;
    pool.release(key, a1, true); // recordUse → query_count = 2
    const a2 = pool.acquire(key).?;
    pool.release(key, a2, true); // recordUse → query_count = 3

    // Cap reached: acquire detects isExpired and discards.
    const result = pool.acquire(key);
    try testing.expect(result == null);
    try testing.expect(pool.entries.count() == 0);
}

test "TcpConnectionPool max queries eviction" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TcpConnectionPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 53));
    const conn = try createTestTcpConnection(testing.allocator);
    conn.max_queries = 3;
    pool.store(key, conn);

    // Simulate repeated releases to bump query_count
    const a1 = pool.acquire(key).?;
    pool.release(key, a1, true); // query_count = 2
    const a2 = pool.acquire(key).?;
    pool.release(key, a2, true); // query_count = 3

    // acquire should reject it due to max_queries (>= 3)
    const result = pool.acquire(key);
    try testing.expect(result == null);
    try testing.expect(pool.entries.count() == 0);
}
