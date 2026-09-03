const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");

// Fixed-size stack key — no allocations in the hot path.

/// Populations that must not coalesce; `internal` keeps the resolver's own
/// DNSKEY/DS/NS fetches off the client query that triggered them.
pub const flag_cd: u8 = 1;
pub const flag_revalidate: u8 = 2;
pub const flag_internal: u8 = 4;

const DedupKey = struct {
    name_buf: [dns.max_name_len + 1]u8 = undefined,
    name_len: u8 = 0,
    qtype: dns.RType = .a,
    flags: u8 = 0,

    fn init(name: []const u8, qtype: dns.RType, flags: u8) ?DedupKey {
        if (name.len > dns.max_name_len + 1) return null;
        var key = DedupKey{ .qtype = qtype, .name_len = @intCast(name.len), .flags = flags };
        for (name, 0..) |c, i| {
            key.name_buf[i] = std.ascii.toLower(c);
        }
        return key;
    }
};

const rand = @import("rand.zig");
const monotonic = @import("monotonic.zig");

/// Hash seed randomized at startup to prevent hash collision attacks.
/// Remains 0 in tests (deterministic); call `randomizeHashSeed` in production.
var dedup_hash_seed: u64 = 0;

pub fn randomizeHashSeed(io: std.Io) void {
    dedup_hash_seed = rand.hashSeed(io);
}

const DedupKeyContext = struct {
    pub fn hash(_: @This(), key: DedupKey) u64 {
        const tag = (@as(u32, @backingInt(key.qtype)) << 8) | key.flags;
        return std.hash.Wyhash.hash(dedup_hash_seed ^ tag, key.name_buf[0..key.name_len]);
    }

    pub fn eql(_: @This(), a: DedupKey, b: DedupKey) bool {
        return a.qtype == b.qtype and
            a.flags == b.flags and
            a.name_len == b.name_len and
            mem.eql(u8, a.name_buf[0..a.name_len], b.name_buf[0..b.name_len]);
    }
};

const AcquireResult = enum { leader, follower, uncoordinated };

/// One mutex + condvar per shard; broadcast wakes only that shard's
/// followers. Power of two so modulo compiles to a mask.
const shard_count = 64;
const shard_mask: u64 = shard_count - 1;

const Shard = struct {
    map: std.HashMapUnmanaged(DedupKey, void, DedupKeyContext, 80) = .empty,
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    condition: std.Io.Condition = std.Io.Condition.init,

    fn deinit(self: *Shard, allocator: mem.Allocator) void {
        self.map.deinit(allocator);
    }
};

pub const InFlightTable = struct {
    shards: [shard_count]Shard,
    io: std.Io,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, io: std.Io) InFlightTable {
        return .{ .shards = @splat(.{}), .io = io, .allocator = allocator };
    }

    pub fn deinit(self: *InFlightTable) void {
        for (&self.shards) |*s| s.deinit(self.allocator);
    }

    /// Total entry count across shards. Locks each shard briefly; only used
    /// in tests and not on the hot path.
    fn count(self: *InFlightTable) u32 {
        var total: u32 = 0;
        for (&self.shards) |*s| {
            s.mutex.lockUncancelable(self.io);
            defer s.mutex.unlock(self.io);
            total += s.map.count();
        }
        return total;
    }

    fn shardFor(self: *InFlightTable, key: DedupKey) *Shard {
        return &self.shards[DedupKeyContext.hash(.{}, key) & shard_mask];
    }

    /// Join the in-flight group for `(name, qtype, flags)`.
    /// Returns `.leader` if this is the first request — caller must call `releaseLeader` when done.
    /// Returns `.follower` if another worker is already resolving — blocks until the leader finishes.
    /// Returns `.uncoordinated` if the entry could not be allocated: resolve, don't release
    /// (that would evict a real leader and wake its followers early).
    ///
    /// The default 2s budget bounds how long a follower waits on the leader.
    /// It's shorter than typical recursive-resolver client timeouts (5-10s);
    /// a sub-second client API would need explicit deadline propagation here.
    /// Passing `null` defers the clock read so the leader fast path skips it.
    pub fn acquireOrWait(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8) AcquireResult {
        return self.acquireOrWaitImpl(name, qtype, flags, null);
    }

    /// Like `acquireOrWait` but takes an absolute monotonic deadline. Callers
    /// pass `monotonic.nowNs() + relative_ns` so the wait honors the real
    /// remaining budget.
    pub fn acquireOrWaitWithTimeout(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8, deadline_ns: i128) AcquireResult {
        return self.acquireOrWaitImpl(name, qtype, flags, deadline_ns);
    }

    fn acquireOrWaitImpl(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8, deadline_ns_opt: ?i128) AcquireResult {
        const key = DedupKey.init(name, qtype, flags) orelse return .uncoordinated;
        const shard = self.shardFor(key);

        shard.mutex.lockUncancelable(self.io);
        defer shard.mutex.unlock(self.io);

        if (shard.map.contains(key)) {
            // Wait on this shard's condvar. Any same-shard release wakes us;
            // we exit when our entry is gone or the deadline expires.
            const deadline_ns = deadline_ns_opt orelse (monotonic.nowNs() + 2 * std.time.ns_per_s);
            while (shard.map.contains(key)) {
                // Deadline hit, leader still in-flight: return .follower anyway;
                // the caller re-resolves on its own. A rare duplicate upstream
                // query beats blocking past the client budget.
                if (monotonic.nowNs() >= deadline_ns) break;
                shard.condition.waitUncancelable(self.io, &shard.mutex);
            }
            return .follower;
        }

        shard.map.put(self.allocator, key, {}) catch return .uncoordinated;
        return .leader;
    }

    /// Non-blocking: become the leader or bail. Unlike `acquireOrWait`, followers
    /// are not enqueued — `false` means "someone else is handling this, skip."
    /// Used by background tasks that have nothing to return to a follower
    /// (prefetch, async validation).
    pub fn tryAcquireLeader(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8) bool {
        const key = DedupKey.init(name, qtype, flags) orelse return false;
        const shard = self.shardFor(key);
        shard.mutex.lockUncancelable(self.io);
        defer shard.mutex.unlock(self.io);
        if (shard.map.contains(key)) return false;
        shard.map.put(self.allocator, key, {}) catch return false;
        return true;
    }

    /// Called by the leader when resolution is complete. Wakes all waiting followers
    /// in the key's shard and removes the entry so subsequent requests start fresh.
    pub fn releaseLeader(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8) void {
        const key = DedupKey.init(name, qtype, flags) orelse return;
        const shard = self.shardFor(key);

        shard.mutex.lockUncancelable(self.io);
        defer shard.mutex.unlock(self.io);

        _ = shard.map.remove(key);
        shard.condition.broadcast(self.io);
    }
};

test "leader for new key" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const result = table.acquireOrWait("example.com", .a, 0);
    try testing.expectEqual(.leader, result);

    table.releaseLeader("example.com", .a, 0);
    try testing.expectEqual(@as(u32, 0), table.count());
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

    try testing.expectEqual(.leader, table.acquireOrWait("example.com", .a, 0));

    var started = std.atomic.Value(bool).init(false);
    var follower_done = std.atomic.Value(bool).init(false);
    var follower_result = std.atomic.Value(u8).init(0);

    const t = try std.Thread.spawn(.{}, struct {
        fn run(tbl: *InFlightTable, started_flag: *std.atomic.Value(bool), done: *std.atomic.Value(bool), result: *std.atomic.Value(u8)) void {
            started_flag.store(true, .release);
            const r = tbl.acquireOrWait("example.com", .a, 0);
            result.store(@backingInt(r), .release);
            done.store(true, .release);
        }
    }.run, .{ &table, &started, &follower_done, &follower_result });

    // Wait until the follower has at least begun executing — a slow CI
    // runner that hadn't even scheduled the thread would false-pass the
    // "not done" check below otherwise (silent miss, not flake).
    while (!started.load(.acquire)) std.Thread.yield() catch {};

    // Tiny sleep to let the follower reach the condvar wait. The window
    // between started.store() and the wait itself is a handful of
    // instructions — microseconds even on slow runners.
    {
        const ts = std.os.linux.timespec{ .sec = 0, .nsec = 5_000_000 };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    try testing.expectEqual(false, follower_done.load(.acquire));

    table.releaseLeader("example.com", .a, 0);
    t.join();

    try testing.expectEqual(true, follower_done.load(.acquire));
    try testing.expectEqual(@backingInt(AcquireResult.follower), follower_result.load(.acquire));
    try testing.expectEqual(@as(u32, 0), table.count());
}

test "acquireOrWaitWithTimeout uses custom timeout" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    _ = table.acquireOrWait("example.com", .a, 0);
    const r = table.acquireOrWaitWithTimeout("example.com", .a, 0, monotonic.nowNs());
    try testing.expectEqual(.follower, r);
    table.releaseLeader("example.com", .a, 0);
}

test "different flags are independent" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const r1 = table.acquireOrWait("example.com", .a, 0);
    const r2 = table.acquireOrWait("example.com", .a, flag_internal);
    try testing.expectEqual(.leader, r1);
    try testing.expectEqual(.leader, r2);

    table.releaseLeader("example.com", .a, 0);
    table.releaseLeader("example.com", .a, flag_internal);
}

test "CD bit partitions dedup groups" {
    // CD=0 and CD=1 must map to distinct dedup keys so they do not
    // coalesce. RFC 6840 §5.9: CD=1 clients want data regardless of
    // validation state, CD=0 clients want validation. Fusing them means
    // one population gets the wrong semantics.
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const cd0: u8 = 0;
    const cd1: u8 = flag_cd;

    const leader_cd0 = table.acquireOrWait("example.com", .a, cd0);
    try testing.expectEqual(.leader, leader_cd0);

    const leader_cd1 = table.acquireOrWait("example.com", .a, cd1);
    try testing.expectEqual(.leader, leader_cd1);

    table.releaseLeader("example.com", .a, cd0);
    table.releaseLeader("example.com", .a, cd1);
    try testing.expectEqual(@as(u32, 0), table.count());
}

test "leader fail; follower retry becomes new leader" {
    // Locks the recursive.zig retry pattern: when the original leader's
    // fetch fails (releaseLeader with no cache population), waiting
    // followers wake with .follower; their second acquireOrWait must
    // promote them to .leader so exactly one retries the upstream fetch.
    // Regression target: a future helper that swallows the post-wake
    // re-acquire would leave followers stuck waiting on a cache entry
    // that will never appear.
    //
    // Single-threaded: an expired deadline lets the same thread observe
    // .follower without actually blocking, then retry after the leader
    // releases. Deterministic — no sleep, no thread spawn. Avoids the
    // CI-flake landmine that comes with multi-thread timing tests.
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    try testing.expectEqual(.leader, table.acquireOrWait("example.com", .dnskey, 0));

    // Same-thread "follower" with already-expired deadline: returns .follower
    // immediately, exactly as a real follower would after the leader's release
    // wakes it (the wake-then-recheck path returns the same enum value).
    const first = table.acquireOrWaitWithTimeout("example.com", .dnskey, 0, monotonic.nowNs());
    try testing.expectEqual(.follower, first);

    // Leader "fails" — release without populating any cache.
    table.releaseLeader("example.com", .dnskey, 0);

    // The retry must promote the next caller to leader; the entry was
    // removed on release. If a future refactor accidentally left the entry
    // in place, this would return .follower again and the caller would
    // wait forever on a cache that nothing populates.
    const second = table.acquireOrWait("example.com", .dnskey, 0);
    try testing.expectEqual(.leader, second);
    table.releaseLeader("example.com", .dnskey, 0);
    try testing.expectEqual(@as(u32, 0), table.count());
}

test "tryAcquireLeader coalesces without enqueueing followers" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    try testing.expect(table.tryAcquireLeader("example.com", .dnskey, 0));
    try testing.expect(!table.tryAcquireLeader("example.com", .dnskey, 0));
    table.releaseLeader("example.com", .dnskey, 0);
    try testing.expectEqual(@as(u32, 0), table.count());

    try testing.expect(table.tryAcquireLeader("example.com", .dnskey, 0));
    table.releaseLeader("example.com", .dnskey, 0);
}
