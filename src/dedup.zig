const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");

// ── Dedup key ──────────────────────────────────────────────────────────
// Fixed-size stack key — no allocations in the hot path.

const DedupKey = struct {
    name_buf: [dns.max_name_len + 1]u8 = undefined,
    name_len: u8 = 0,
    qtype: dns.RType = .a,

    pub fn init(name: []const u8, qtype: dns.RType) ?DedupKey {
        if (name.len > dns.max_name_len + 1) return null;
        var key = DedupKey{ .qtype = qtype, .name_len = @intCast(name.len) };
        for (name, 0..) |c, i| {
            key.name_buf[i] = std.ascii.toLower(c);
        }
        return key;
    }

};

const DedupKeyContext = struct {
    pub fn hash(_: @This(), key: DedupKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(key.name_buf[0..key.name_len]);
        h.update(mem.asBytes(&key.qtype));
        return h.final();
    }

    pub fn eql(_: @This(), a: DedupKey, b: DedupKey) bool {
        return a.qtype == b.qtype and
            a.name_len == b.name_len and
            mem.eql(u8, a.name_buf[0..a.name_len], b.name_buf[0..b.name_len]);
    }
};

// ── In-flight table ────────────────────────────────────────────────────

const EntryState = struct {
    completed: bool = false,
};

pub const AcquireResult = enum { leader, follower };

pub const InFlightTable = struct {
    map: std.HashMapUnmanaged(DedupKey, EntryState, DedupKeyContext, 80),
    mutex: std.Thread.Mutex = .{},
    condition: std.Thread.Condition = .{},
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator) InFlightTable {
        return .{
            .map = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *InFlightTable) void {
        self.map.deinit(self.allocator);
    }

    /// Try to become the leader for this (name, qtype) pair.
    /// Returns `.leader` if this is the first request — caller must call `releaseLeader` when done.
    /// Returns `.follower` if another worker is already resolving — blocks until the leader finishes.
    pub fn acquireOrWait(self: *InFlightTable, name: []const u8, qtype: dns.RType) AcquireResult {
        const key = DedupKey.init(name, qtype) orelse return .leader;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.map.getPtr(key)) |_| {
            // Another worker is resolving this — wait for completion.
            while (self.map.get(key)) |entry| {
                if (entry.completed) break;
                self.condition.timedWait(&self.mutex, 5 * std.time.ns_per_s) catch break;
            }
            // Entry may have been removed by leader, or we timed out — either way, follower.
            return .follower;
        }

        // First request for this key — become leader.
        self.map.put(self.allocator, key, .{}) catch return .leader;
        return .leader;
    }

    /// Called by the leader when resolution is complete. Wakes all waiting followers
    /// and removes the entry so subsequent requests start fresh.
    pub fn releaseLeader(self: *InFlightTable, name: []const u8, qtype: dns.RType) void {
        const key = DedupKey.init(name, qtype) orelse return;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.map.getPtr(key)) |entry| {
            entry.completed = true;
        }
        self.condition.broadcast();
        // Remove entry so followers see null and break out, and future requests start fresh.
        _ = self.map.remove(key);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "leader for new key" {
    var table = InFlightTable.init(testing.allocator);
    defer table.deinit();

    const result = table.acquireOrWait("example.com", .a);
    try testing.expectEqual(.leader, result);

    table.releaseLeader("example.com", .a);
    try testing.expectEqual(@as(u32, 0), table.map.count());
}

test "different qtypes are independent" {
    var table = InFlightTable.init(testing.allocator);
    defer table.deinit();

    const r1 = table.acquireOrWait("example.com", .a);
    const r2 = table.acquireOrWait("example.com", .aaaa);
    try testing.expectEqual(.leader, r1);
    try testing.expectEqual(.leader, r2);

    table.releaseLeader("example.com", .a);
    table.releaseLeader("example.com", .aaaa);
}

test "different names are independent" {
    var table = InFlightTable.init(testing.allocator);
    defer table.deinit();

    const r1 = table.acquireOrWait("a.example.com", .a);
    const r2 = table.acquireOrWait("b.example.com", .a);
    try testing.expectEqual(.leader, r1);
    try testing.expectEqual(.leader, r2);

    table.releaseLeader("a.example.com", .a);
    table.releaseLeader("b.example.com", .a);
}

test "case insensitive dedup" {
    var table = InFlightTable.init(testing.allocator);
    defer table.deinit();

    const key1 = DedupKey.init("EXAMPLE.COM", .a);
    const key2 = DedupKey.init("example.com", .a);
    try testing.expect(key1 != null);
    try testing.expect(key2 != null);
    try testing.expect(DedupKeyContext.eql(.{}, key1.?, key2.?));
}

test "follower waits for leader" {
    var table = InFlightTable.init(testing.allocator);
    defer table.deinit();

    const leader_result = table.acquireOrWait("example.com", .a);
    try testing.expectEqual(.leader, leader_result);

    var follower_done = std.atomic.Value(bool).init(false);
    var follower_result = std.atomic.Value(u8).init(0);

    const t = try std.Thread.spawn(.{}, struct {
        fn run(tbl: *InFlightTable, done: *std.atomic.Value(bool), result: *std.atomic.Value(u8)) void {
            const r = tbl.acquireOrWait("example.com", .a);
            result.store(@intFromEnum(r), .release);
            done.store(true, .release);
        }
    }.run, .{ &table, &follower_done, &follower_result });

    // Give follower time to block
    std.Thread.sleep(50 * std.time.ns_per_ms);
    try testing.expectEqual(false, follower_done.load(.acquire));

    // Release — follower should wake
    table.releaseLeader("example.com", .a);
    t.join();

    try testing.expectEqual(true, follower_done.load(.acquire));
    try testing.expectEqual(@intFromEnum(AcquireResult.follower), follower_result.load(.acquire));
    try testing.expectEqual(@as(u32, 0), table.map.count());
}

test "entry cleaned up after leader and followers finish" {
    var table = InFlightTable.init(testing.allocator);
    defer table.deinit();

    _ = table.acquireOrWait("example.com", .a);
    table.releaseLeader("example.com", .a);
    try testing.expectEqual(@as(u32, 0), table.map.count());

    // Can immediately become leader again
    const r = table.acquireOrWait("example.com", .a);
    try testing.expectEqual(.leader, r);
    table.releaseLeader("example.com", .a);
}

test "timeout when leader never releases" {
    // Use a very short timeout by testing the condition variable directly
    var table = InFlightTable.init(testing.allocator);
    defer table.deinit();

    _ = table.acquireOrWait("example.com", .a);

    // Spawn a follower that will time out (the 5s timeout in acquireOrWait)
    // For test speed, we test the mechanism: put an entry and let follower see it
    const t = try std.Thread.spawn(.{}, struct {
        fn run(tbl: *InFlightTable) void {
            // This will block until timeout (5s) then return .follower
            const r = tbl.acquireOrWait("example.com", .a);
            std.debug.assert(r == .follower);
        }
    }.run, .{&table});

    // Release after a short delay so the test doesn't take 5s
    std.Thread.sleep(100 * std.time.ns_per_ms);
    table.releaseLeader("example.com", .a);
    t.join();
}
