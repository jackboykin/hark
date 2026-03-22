const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;
const testing = std.testing;
const AddressKey = @import("connection_pool.zig").AddressKey;

// ── TcpPooledConnection ─────────────────────────────────────────────

pub const TcpPooledConnection = struct {
    sock: posix.fd_t,
    last_used: i64,
    query_count: u16,

    pub fn closeAndDestroy(self: *TcpPooledConnection, allocator: Allocator) void {
        posix.close(self.sock);
        allocator.destroy(self);
    }
};

// ── TcpConnectionPool ───────────────────────────────────────────────

const max_entries_default: usize = 32;

pub const TcpConnectionPool = struct {
    allocator: Allocator,
    entries: std.AutoHashMap(AddressKey, *TcpPooledConnection),
    mutex: std.Thread.Mutex = .{},
    max_idle_sec: i64 = 30,
    max_entries: usize = max_entries_default,
    max_queries: u16 = 200,
    now_fn: *const fn () i64 = &defaultNow,

    pub fn init(allocator: Allocator) TcpConnectionPool {
        return .{
            .allocator = allocator,
            .entries = std.AutoHashMap(AddressKey, *TcpPooledConnection).init(allocator),
        };
    }

    pub fn deinit(self: *TcpConnectionPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.closeAndDestroy(self.allocator);
        }
        self.entries.deinit();
    }

    /// Retrieve a cached connection for the given key. Returns null if
    /// no connection exists, the entry has expired, or the query cap is hit.
    pub fn acquire(self: *TcpConnectionPool, key: AddressKey) ?*TcpPooledConnection {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Opportunistic idle sweep only when pool is above half capacity
        if (self.entries.count() >= self.max_entries / 2) self.evictIdleLocked();

        const kv = self.entries.fetchRemove(key) orelse return null;
        const conn = kv.value;

        const now = self.now_fn();
        if (now - conn.last_used > self.max_idle_sec or conn.query_count >= self.max_queries) {
            conn.closeAndDestroy(self.allocator);
            return null;
        }

        return conn;
    }

    /// Return a connection to the pool (alive=true) or discard it (alive=false).
    pub fn release(self: *TcpConnectionPool, key: AddressKey, conn: *TcpPooledConnection, alive: bool) void {
        if (!alive) {
            conn.closeAndDestroy(self.allocator);
            return;
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        conn.last_used = self.now_fn();
        conn.query_count +|= 1;
        self.putReplaceLocked(key, conn);
    }

    /// Store a newly established connection in the pool.
    pub fn store(self: *TcpConnectionPool, key: AddressKey, conn: *TcpPooledConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.count() >= self.max_entries) {
            self.evictOldestLocked();
        }
        conn.last_used = self.now_fn();
        conn.query_count = 1;
        self.putReplaceLocked(key, conn);
    }

    fn putReplaceLocked(self: *TcpConnectionPool, key: AddressKey, conn: *TcpPooledConnection) void {
        const result = self.entries.fetchPut(key, conn) catch {
            conn.closeAndDestroy(self.allocator);
            return;
        };
        if (result) |old| {
            old.value.closeAndDestroy(self.allocator);
        }
    }

    fn evictIdleLocked(self: *TcpConnectionPool) void {
        const now = self.now_fn();
        var to_remove: [max_entries_default]AddressKey = undefined;
        var remove_count: usize = 0;

        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (now - entry.value_ptr.*.last_used > self.max_idle_sec) {
                to_remove[remove_count] = entry.key_ptr.*;
                remove_count += 1;
                if (remove_count >= max_entries_default) break;
            }
        }

        for (to_remove[0..remove_count]) |k| {
            if (self.entries.fetchRemove(k)) |kv| {
                kv.value.closeAndDestroy(self.allocator);
            }
        }
    }

    fn evictOldestLocked(self: *TcpConnectionPool) void {
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
                kv.value.closeAndDestroy(self.allocator);
            }
        }
    }

    fn defaultNow() i64 {
        return @import("monotonic.zig").nowSec();
    }
};

// ── Tests ────────────────────────────────────────────────────────────

fn createTestConnection(allocator: Allocator) !*TcpPooledConnection {
    const dev_null = try posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    const sock = try posix.dup(dev_null);
    posix.close(dev_null);

    const conn = try allocator.create(TcpPooledConnection);
    conn.* = .{
        .sock = sock,
        .last_used = 0,
        .query_count = 0,
    };
    return conn;
}

test "TcpConnectionPool store and acquire" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TcpConnectionPool.init(testing.allocator);
    pool.now_fn = &now_fn.now;
    defer pool.deinit();

    const key = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 53));
    const conn = try createTestConnection(testing.allocator);
    pool.store(key, conn);

    fake_time = 1005;
    const acquired = pool.acquire(key);
    try testing.expect(acquired != null);
    try testing.expect(pool.entries.count() == 0);

    pool.release(key, acquired.?, true);
    try testing.expect(pool.entries.count() == 1);
}

test "TcpConnectionPool idle eviction" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TcpConnectionPool.init(testing.allocator);
    pool.now_fn = &now_fn.now;
    pool.max_idle_sec = 10;
    defer pool.deinit();

    const key = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 53));
    const conn = try createTestConnection(testing.allocator);
    pool.store(key, conn);
    try testing.expect(pool.entries.count() == 1);

    fake_time = 1020;
    const result = pool.acquire(key);
    try testing.expect(result == null);
    try testing.expect(pool.entries.count() == 0);
}

test "TcpConnectionPool max entries eviction" {
    var fake_time: i64 = 1000;
    const now_fn = struct {
        var time_ptr: *i64 = undefined;
        fn now() i64 {
            return time_ptr.*;
        }
    };
    now_fn.time_ptr = &fake_time;

    var pool = TcpConnectionPool.init(testing.allocator);
    pool.now_fn = &now_fn.now;
    pool.max_entries = 2;
    defer pool.deinit();

    const conn1 = try createTestConnection(testing.allocator);
    const key1 = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 53));
    pool.store(key1, conn1);

    fake_time = 1001;
    const conn2 = try createTestConnection(testing.allocator);
    const key2 = AddressKey.fromAddress(net.Address.initIp4(.{ 8, 8, 8, 8 }, 53));
    pool.store(key2, conn2);
    try testing.expectEqual(@as(usize, 2), pool.entries.count());

    fake_time = 1002;
    const conn3 = try createTestConnection(testing.allocator);
    const key3 = AddressKey.fromAddress(net.Address.initIp4(.{ 9, 9, 9, 9 }, 53));
    pool.store(key3, conn3);

    try testing.expectEqual(@as(usize, 2), pool.entries.count());
    try testing.expect(pool.entries.get(key1) == null);
}

test "TcpConnectionPool release not alive frees connection" {
    var pool = TcpConnectionPool.init(testing.allocator);
    defer pool.deinit();

    const key = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 53));
    const conn = try createTestConnection(testing.allocator);

    pool.release(key, conn, false);
    // No leak = success (testing.allocator detects leaks)
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

    var pool = TcpConnectionPool.init(testing.allocator);
    pool.now_fn = &now_fn.now;
    pool.max_queries = 3;
    defer pool.deinit();

    const key = AddressKey.fromAddress(net.Address.initIp4(.{ 1, 1, 1, 1 }, 53));
    const conn = try createTestConnection(testing.allocator);
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
