const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const net = std.net;
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;
const Allocator = mem.Allocator;
const testing = std.testing;

// ── AddressKey ───────────────────────────────────────────────────────

pub const AddressKey = struct {
    family: u8,
    addr: [16]u8,
    port: u16,

    pub fn fromAddress(address: net.Address) AddressKey {
        var key = AddressKey{ .family = 0, .addr = .{0} ** 16, .port = 0 };
        switch (address.any.family) {
            posix.AF.INET => {
                key.family = @intCast(posix.AF.INET);
                const bytes = @as(*const [4]u8, @ptrCast(&address.in.sa.addr));
                @memcpy(key.addr[0..4], bytes);
                key.port = address.in.getPort();
            },
            posix.AF.INET6 => {
                key.family = @intCast(posix.AF.INET6);
                @memcpy(&key.addr, &address.in6.sa.addr);
                key.port = address.in6.getPort();
            },
            else => {},
        }
        return key;
    }
};

// ── PooledConnection ─────────────────────────────────────────────────

pub const PooledConnection = struct {
    sock: posix.fd_t,
    stream: net.Stream,
    net_reader: net.Stream.Reader,
    net_writer: net.Stream.Writer,
    tls_client: tls.Client,
    last_used: i64,

    // Inline buffers — stable addresses since struct is heap-allocated.
    net_read_buf: [tls.Client.min_buffer_len]u8,
    net_write_buf: [tls.Client.min_buffer_len]u8,
    tls_read_buf: [tls.Client.min_buffer_len]u8,
    tls_write_buf: [tls.Client.min_buffer_len]u8,

    /// Close TLS session and underlying socket.
    pub fn closeAndDestroy(self: *PooledConnection, allocator: Allocator) void {
        self.tls_client.end() catch {};
        posix.close(self.sock);
        allocator.destroy(self);
    }

    /// Close socket without TLS shutdown (for error paths).
    pub fn destroyBroken(self: *PooledConnection, allocator: Allocator) void {
        posix.close(self.sock);
        allocator.destroy(self);
    }
};

// ── ConnectionPool ───────────────────────────────────────────────────

const max_entries_default: usize = 32;

pub const ConnectionPool = struct {
    allocator: Allocator,
    entries: std.AutoHashMap(AddressKey, *PooledConnection),
    max_idle_sec: i64 = 30,
    max_entries: usize = max_entries_default,
    now_fn: *const fn () i64 = &defaultNow,

    pub fn init(allocator: Allocator) ConnectionPool {
        return .{
            .allocator = allocator,
            .entries = std.AutoHashMap(AddressKey, *PooledConnection).init(allocator),
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.destroyBroken(self.allocator);
        }
        self.entries.deinit();
    }

    /// Retrieve a cached connection for the given key. Returns null if
    /// no connection exists or the cached entry has expired.
    pub fn acquire(self: *ConnectionPool, key: AddressKey) ?*PooledConnection {
        // Opportunistic sweep of idle connections
        self.evictIdle();

        const kv = self.entries.fetchRemove(key) orelse return null;
        const conn = kv.value;

        // Check staleness
        const now = self.now_fn();
        if (now - conn.last_used > self.max_idle_sec) {
            conn.closeAndDestroy(self.allocator);
            return null;
        }

        return conn;
    }

    /// Return a connection to the pool (alive=true) or discard it (alive=false).
    pub fn release(self: *ConnectionPool, key: AddressKey, conn: *PooledConnection, alive: bool) void {
        if (!alive) {
            conn.destroyBroken(self.allocator);
            return;
        }
        conn.last_used = self.now_fn();
        self.entries.put(key, conn) catch {
            conn.destroyBroken(self.allocator);
        };
    }

    /// Store a newly established connection in the pool.
    pub fn store(self: *ConnectionPool, key: AddressKey, conn: *PooledConnection) void {
        // Evict if at capacity
        if (self.entries.count() >= self.max_entries) {
            self.evictOldest();
        }
        conn.last_used = self.now_fn();
        self.entries.put(key, conn) catch {
            conn.destroyBroken(self.allocator);
        };
    }

    /// Remove all connections that have been idle longer than max_idle_sec.
    pub fn evictIdle(self: *ConnectionPool) void {
        const now = self.now_fn();
        var to_remove: [max_entries_default]AddressKey = undefined;
        var remove_count: usize = 0;

        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (now - entry.value_ptr.*.last_used > self.max_idle_sec) {
                if (remove_count < max_entries_default) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |k| {
            if (self.entries.fetchRemove(k)) |kv| {
                kv.value.destroyBroken(self.allocator);
            }
        }
    }

    fn evictOldest(self: *ConnectionPool) void {
        var oldest_key: ?AddressKey = null;
        var oldest_time: i64 = std.math.maxInt(i64);

        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.*.last_used < oldest_time) {
                oldest_time = entry.value_ptr.*.last_used;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |k| {
            if (self.entries.fetchRemove(k)) |kv| {
                kv.value.destroyBroken(self.allocator);
            }
        }
    }

    fn defaultNow() i64 {
        return std.time.timestamp();
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "AddressKey fromAddress IPv4" {
    const addr = net.Address.initIp4(.{ 1, 1, 1, 1 }, 853);
    const key = AddressKey.fromAddress(addr);
    try testing.expectEqual(@as(u8, @intCast(posix.AF.INET)), key.family);
    try testing.expectEqual(@as(u16, 853), key.port);
    try testing.expectEqual(@as(u8, 1), key.addr[0]);
    try testing.expectEqual(@as(u8, 1), key.addr[1]);
    try testing.expectEqual(@as(u8, 1), key.addr[2]);
    try testing.expectEqual(@as(u8, 1), key.addr[3]);
}

test "AddressKey fromAddress IPv6" {
    const addr = net.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 853, 0, 0);
    const key = AddressKey.fromAddress(addr);
    try testing.expectEqual(@as(u8, @intCast(posix.AF.INET6)), key.family);
    try testing.expectEqual(@as(u16, 853), key.port);
    try testing.expectEqual(@as(u8, 0x20), key.addr[0]);
    try testing.expectEqual(@as(u8, 0x01), key.addr[1]);
}

test "AddressKey equality" {
    const a1 = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 853));
    const a2 = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 853));
    const a3 = AddressKey.fromAddress(net.Address.initIp4(.{ 8, 8, 8, 8 }, 853));

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

    var pool = ConnectionPool.init(testing.allocator);
    pool.now_fn = &now_fn.now;
    pool.max_idle_sec = 10;
    defer pool.deinit();

    const key = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 853));

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

    var pool = ConnectionPool.init(testing.allocator);
    pool.now_fn = &now_fn.now;
    defer pool.deinit();

    const key = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 853));

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
    var pool = ConnectionPool.init(testing.allocator);
    defer pool.deinit();

    const key = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 853));
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

    var pool = ConnectionPool.init(testing.allocator);
    pool.now_fn = &now_fn.now;
    pool.max_entries = 2;
    defer pool.deinit();

    // Store 2 connections
    const conn1 = try createTestConnection(testing.allocator);
    const key1 = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 853));
    pool.store(key1, conn1);

    fake_time = 1001;
    const conn2 = try createTestConnection(testing.allocator);
    const key2 = AddressKey.fromAddress(net.Address.initIp4(.{ 8, 8, 8, 8 }, 853));
    pool.store(key2, conn2);

    try testing.expectEqual(@as(usize, 2), pool.entries.count());

    // Store a 3rd — should evict the oldest (conn1)
    fake_time = 1002;
    const conn3 = try createTestConnection(testing.allocator);
    const key3 = AddressKey.fromAddress(net.Address.initIp4(.{ 9, 9, 9, 9 }, 853));
    pool.store(key3, conn3);

    try testing.expectEqual(@as(usize, 2), pool.entries.count());
    // conn1's key should be gone
    try testing.expect(pool.entries.get(key1) == null);
}

/// Create a minimal PooledConnection for unit testing pool mechanics.
/// Uses a dup'd /dev/null fd so close() is safe.
fn createTestConnection(allocator: Allocator) !*PooledConnection {
    const dev_null = try posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    const sock = try posix.dup(dev_null);
    posix.close(dev_null);

    const conn = try allocator.create(PooledConnection);
    conn.* = .{
        .sock = sock,
        .stream = net.Stream{ .handle = sock },
        .net_reader = undefined,
        .net_writer = undefined,
        .tls_client = undefined,
        .last_used = 0,
        .net_read_buf = undefined,
        .net_write_buf = undefined,
        .tls_read_buf = undefined,
        .tls_write_buf = undefined,
    };
    return conn;
}
