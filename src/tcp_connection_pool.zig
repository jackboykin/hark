const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const pool_mod = @import("connection_pool.zig");
const AddressKey = pool_mod.AddressKey;
const na = @import("net_address.zig");
const sys = @import("sys.zig");

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

// ── TcpConnectionPool ───────────────────────────────────────────────

pub const TcpConnectionPool = pool_mod.ConnectionPool(TcpPooledConnection);

// ── Tests ────────────────────────────────────────────────────────────

fn createTestConnection(allocator: Allocator) !*TcpPooledConnection {
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

test "TcpConnectionPool store and acquire" {
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

    var pool = TcpConnectionPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    pool.max_idle_sec = 10;
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 53));
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

    var pool = TcpConnectionPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    pool.max_entries = 2;
    defer pool.deinit();

    const conn1 = try createTestConnection(testing.allocator);
    const key1 = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 53));
    pool.store(key1, conn1);

    fake_time = 1001;
    const conn2 = try createTestConnection(testing.allocator);
    const key2 = AddressKey.fromAddress(na.initIp4(.{ 8, 8, 8, 8 }, 53));
    pool.store(key2, conn2);
    try testing.expectEqual(@as(usize, 2), pool.entries.count());

    fake_time = 1002;
    const conn3 = try createTestConnection(testing.allocator);
    const key3 = AddressKey.fromAddress(na.initIp4(.{ 9, 9, 9, 9 }, 53));
    pool.store(key3, conn3);

    try testing.expectEqual(@as(usize, 2), pool.entries.count());
    try testing.expect(pool.entries.get(key1) == null);
}

test "TcpConnectionPool release not alive frees connection" {
    var pool = TcpConnectionPool.init(testing.allocator, undefined);
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 53));
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

    var pool = TcpConnectionPool.init(testing.allocator, undefined);
    pool.now_fn = &now_fn.now;
    defer pool.deinit();

    const key = AddressKey.fromAddress(na.initIp4(.{ 1, 1, 1, 1 }, 53));
    const conn = try createTestConnection(testing.allocator);
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
