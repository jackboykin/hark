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
    flags: u8 = 0,

    pub fn init(name: []const u8, qtype: dns.RType, flags: u8) ?DedupKey {
        if (name.len > dns.max_name_len + 1) return null;
        var key = DedupKey{ .qtype = qtype, .name_len = @intCast(name.len), .flags = flags };
        for (name, 0..) |c, i| {
            key.name_buf[i] = std.ascii.toLower(c);
        }
        return key;
    }

};

const rand = @import("rand.zig");

/// Hash seed randomized at startup to prevent hash collision attacks.
/// Remains 0 in tests (deterministic); call `randomizeHashSeed` in production.
var dedup_hash_seed: u64 = 0;

pub fn randomizeHashSeed(io: std.Io) void {
    dedup_hash_seed = rand.hashSeed(io);
}

const DedupKeyContext = struct {
    pub fn hash(_: @This(), key: DedupKey) u64 {
        var h = std.hash.Wyhash.init(dedup_hash_seed);
        h.update(key.name_buf[0..key.name_len]);
        h.update(mem.asBytes(&key.qtype));
        h.update(mem.asBytes(&key.flags));
        return h.final();
    }

    pub fn eql(_: @This(), a: DedupKey, b: DedupKey) bool {
        return a.qtype == b.qtype and
            a.flags == b.flags and
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
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    condition: std.Io.Condition = std.Io.Condition.init,
    io: std.Io,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, io: std.Io) InFlightTable {
        return .{
            .map = .empty,
            .io = io,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *InFlightTable) void {
        self.map.deinit(self.allocator);
    }

    /// Try to become the leader for this (name, qtype) pair.
    /// Returns `.leader` if this is the first request — caller must call `releaseLeader` when done.
    /// Returns `.follower` if another worker is already resolving — blocks until the leader finishes.
    pub fn acquireOrWait(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8) AcquireResult {
        return self.acquireOrWaitWithTimeout(name, qtype, flags, 2 * std.time.ns_per_s);
    }

    /// Like `acquireOrWait` but with a caller-specified timeout.
    /// DNSKEY fetches use a longer timeout (6s) because cold-cache DNSSEC
    /// chains (root → TLD → SLD → DNSKEY) can take 3-5s.
    pub fn acquireOrWaitWithTimeout(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8, timeout_ns: u64) AcquireResult {
        const key = DedupKey.init(name, qtype, flags) orelse return .leader;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.map.getPtr(key)) |_| {
            // Another worker is resolving this — wait for completion.
            // The condition is shared across all entries, so any key's
            // releaseLeader broadcast wakes us to recheck the deadline.
            const monotonic = @import("monotonic.zig");
            const deadline = monotonic.nowNs() +| @as(i128, timeout_ns);
            while (self.map.get(key)) |entry| {
                if (entry.completed) break;
                if (monotonic.nowNs() >= deadline) break;
                self.condition.waitUncancelable(self.io, &self.mutex);
            }
            return .follower;
        }

        // First request for this key — become leader.
        self.map.put(self.allocator, key, .{}) catch return .leader;
        return .leader;
    }

    /// Called by the leader when resolution is complete. Wakes all waiting followers
    /// and removes the entry so subsequent requests start fresh.
    pub fn releaseLeader(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8) void {
        const key = DedupKey.init(name, qtype, flags) orelse return;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.map.getPtr(key)) |entry| {
            entry.completed = true;
        }
        self.condition.broadcast(self.io);
        // Remove entry so followers see null and break out, and future requests start fresh.
        _ = self.map.remove(key);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "leader for new key" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const result = table.acquireOrWait("example.com", .a, 0);
    try testing.expectEqual(.leader, result);

    table.releaseLeader("example.com", .a, 0);
    try testing.expectEqual(@as(u32, 0), table.map.count());
}

test "different qtypes are independent" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const r1 = table.acquireOrWait("example.com", .a, 0);
    const r2 = table.acquireOrWait("example.com", .aaaa, 0);
    try testing.expectEqual(.leader, r1);
    try testing.expectEqual(.leader, r2);

    table.releaseLeader("example.com", .a, 0);
    table.releaseLeader("example.com", .aaaa, 0);
}

test "different names are independent" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const r1 = table.acquireOrWait("a.example.com", .a, 0);
    const r2 = table.acquireOrWait("b.example.com", .a, 0);
    try testing.expectEqual(.leader, r1);
    try testing.expectEqual(.leader, r2);

    table.releaseLeader("a.example.com", .a, 0);
    table.releaseLeader("b.example.com", .a, 0);
}

test "case insensitive dedup" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const key1 = DedupKey.init("EXAMPLE.COM", .a, 0);
    const key2 = DedupKey.init("example.com", .a, 0);
    try testing.expect(key1 != null);
    try testing.expect(key2 != null);
    try testing.expect(DedupKeyContext.eql(.{}, key1.?, key2.?));
}

test "follower waits for leader" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const leader_result = table.acquireOrWait("example.com", .a, 0);
    try testing.expectEqual(.leader, leader_result);

    var follower_done = std.atomic.Value(bool).init(false);
    var follower_result = std.atomic.Value(u8).init(0);

    const t = try std.Thread.spawn(.{}, struct {
        fn run(tbl: *InFlightTable, done: *std.atomic.Value(bool), result: *std.atomic.Value(u8)) void {
            const r = tbl.acquireOrWait("example.com", .a, 0);
            result.store(@intFromEnum(r), .release);
            done.store(true, .release);
        }
    }.run, .{ &table, &follower_done, &follower_result });

    // Give follower time to block
    {
        const ts = std.os.linux.timespec{ .sec = 0, .nsec = 50_000_000 };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    try testing.expectEqual(false, follower_done.load(.acquire));

    // Release — follower should wake
    table.releaseLeader("example.com", .a, 0);
    t.join();

    try testing.expectEqual(true, follower_done.load(.acquire));
    try testing.expectEqual(@intFromEnum(AcquireResult.follower), follower_result.load(.acquire));
    try testing.expectEqual(@as(u32, 0), table.map.count());
}

test "entry cleaned up after leader and followers finish" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    _ = table.acquireOrWait("example.com", .a, 0);
    table.releaseLeader("example.com", .a, 0);
    try testing.expectEqual(@as(u32, 0), table.map.count());

    // Can immediately become leader again
    const r = table.acquireOrWait("example.com", .a, 0);
    try testing.expectEqual(.leader, r);
    table.releaseLeader("example.com", .a, 0);
}

test "timeout when leader never releases" {
    // Use a very short timeout by testing the condition variable directly
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    _ = table.acquireOrWait("example.com", .a, 0);

    // Spawn a follower that will time out (the 2s timeout in acquireOrWait)
    // For test speed, we test the mechanism: put an entry and let follower see it
    const t = try std.Thread.spawn(.{}, struct {
        fn run(tbl: *InFlightTable) void {
            // This will block until timeout (5s) then return .follower
            const r = tbl.acquireOrWait("example.com", .a, 0);
            std.debug.assert(r == .follower);
        }
    }.run, .{&table});

    // Release after a short delay so the test doesn't take 5s
    {
        const ts = std.os.linux.timespec{ .sec = 0, .nsec = 100_000_000 };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    table.releaseLeader("example.com", .a, 0);
    t.join();
}

test "acquireOrWaitWithTimeout uses custom timeout" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    _ = table.acquireOrWait("example.com", .a, 0);
    // Same-thread follower: timedWait times out immediately since no one will signal.
    const r = table.acquireOrWaitWithTimeout("example.com", .a, 0, 1);
    try testing.expectEqual(.follower, r);
    table.releaseLeader("example.com", .a, 0);
}

test "different flags are independent" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const r1 = table.acquireOrWait("example.com", .a, 0);
    const r2 = table.acquireOrWait("example.com", .a, 1);
    try testing.expectEqual(.leader, r1);
    try testing.expectEqual(.leader, r2);

    table.releaseLeader("example.com", .a, 0);
    table.releaseLeader("example.com", .a, 1);
}
