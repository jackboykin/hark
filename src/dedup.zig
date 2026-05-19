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
const monotonic = @import("monotonic.zig");

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

pub const AcquireResult = enum { leader, follower };

/// One mutex + condvar per shard; broadcast wakes only that shard's
/// followers. Power of two so modulo compiles to a mask.
const shard_count = 64;
const shard_mask: u64 = shard_count - 1;

/// Per-shard cap = 2 × (max_entries / shard_count). The 2× headroom keeps
/// uniform-hashing variance well below the cap (max-shard load goes as
/// `N/k + sqrt(2·(N/k)·ln k)` ≈ 170 here); saturation requires a real
/// flood, not a fortunate distribution. Worst-case memory ≈ 8.5 MiB.
pub const max_entries: u32 = 8192;
const per_shard_cap: u32 = 2 * max_entries / shard_count;

/// TTL after which a leader's slot is presumed stranded (panicked leader,
/// missed releaseLeader). 10× the longest legitimate dedup hold (DNSKEY
/// chain ≈ 6s); live resolutions can't be reaped in flight.
const stale_ttl_ms: i64 = 60 * std.time.ms_per_s;

/// Reap fires only on inserts into a near-saturated shard. Bounded victims
/// per pass; successive inserts amortize the rest.
const reap_watermark: u32 = (per_shard_cap * 3) / 4;
const max_victims_per_reap: usize = 64;

const Shard = struct {
    /// Value is the monotonic-ms insert stamp; drives the TTL reap.
    map: std.HashMapUnmanaged(DedupKey, i64, DedupKeyContext, 80) = .empty,
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    condition: std.Io.Condition = std.Io.Condition.init,

    fn deinit(self: *Shard, allocator: mem.Allocator) void {
        self.map.deinit(allocator);
    }
};

/// Drop up to `max_victims_per_reap` entries past their TTL. Caller holds
/// `shard.mutex`. Two-pass because the stdlib HashMap iterator is
/// invalidated by in-place removal. Broadcasts on eviction in case any
/// follower is parked on a victim — safe even if a future TTL change
/// brings it below the max follower deadline.
fn reapStaleLocked(shard: *Shard, io: std.Io, now_ms: i64) void {
    var victims: [max_victims_per_reap]DedupKey = undefined;
    var n: usize = 0;
    var it = shard.map.iterator();
    while (it.next()) |e| {
        if (n >= max_victims_per_reap) break;
        if (now_ms - e.value_ptr.* > stale_ttl_ms) {
            victims[n] = e.key_ptr.*;
            n += 1;
        }
    }
    for (victims[0..n]) |k| _ = shard.map.remove(k);
    if (n > 0) shard.condition.broadcast(io);
}

/// Insert `key` as a new leader if the shard has room. Reaps inline when
/// near saturation so stranded slots don't permanently consume capacity.
/// Caller holds `shard.mutex`. Returns false at cap (after reap).
///
/// Open edge: a leader that holds for longer than `stale_ttl_ms` can be
/// reaped and replaced by a successor; the original's eventual
/// `releaseLeader` removes the successor's entry, waking that cohort to
/// retry. Bounded fanout, narrow window — accepted rather than threading
/// a generation token through the public API.
fn tryInsertLeaderLocked(shard: *Shard, io: std.Io, allocator: mem.Allocator, key: DedupKey, now_ms: i64) bool {
    if (shard.map.count() >= reap_watermark) reapStaleLocked(shard, io, now_ms);
    if (shard.map.count() >= per_shard_cap) return false;
    shard.map.put(allocator, key, now_ms) catch return false;
    return true;
}

pub const InFlightTable = struct {
    shards: [shard_count]Shard,
    io: std.Io,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, io: std.Io) InFlightTable {
        var shards: [shard_count]Shard = undefined;
        for (&shards) |*s| s.* = .{};
        return .{ .shards = shards, .io = io, .allocator = allocator };
    }

    pub fn deinit(self: *InFlightTable) void {
        for (&self.shards) |*s| s.deinit(self.allocator);
    }

    /// Total entry count across shards. Locks each shard briefly; only used
    /// in tests and not on the hot path.
    pub fn count(self: *InFlightTable) u32 {
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

    /// Try to become the leader for this (name, qtype) pair.
    /// Returns `.leader` if this is the first request — caller must call `releaseLeader` when done.
    /// Returns `.follower` if another worker is already resolving — blocks until the leader finishes.
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
    /// remaining budget. DNSKEY fetches use a longer (6s) deadline because
    /// cold-cache DNSSEC chains (root → TLD → SLD → DNSKEY) can take 3-5s.
    pub fn acquireOrWaitWithTimeout(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8, deadline_ns: i128) AcquireResult {
        return self.acquireOrWaitImpl(name, qtype, flags, deadline_ns);
    }

    fn acquireOrWaitImpl(self: *InFlightTable, name: []const u8, qtype: dns.RType, flags: u8, deadline_ns_opt: ?i128) AcquireResult {
        const key = DedupKey.init(name, qtype, flags) orelse return .leader;
        const shard = self.shardFor(key);

        shard.mutex.lockUncancelable(self.io);
        defer shard.mutex.unlock(self.io);

        if (shard.map.getPtr(key)) |_| {
            // Wait on this shard's condvar. Any same-shard release wakes us;
            // we exit when our entry is gone or the deadline expires.
            const deadline_ns = deadline_ns_opt orelse (monotonic.nowNs() + 2 * std.time.ns_per_s);
            while (shard.map.get(key)) |_| {
                if (monotonic.nowNs() >= deadline_ns) break;
                shard.condition.waitUncancelable(self.io, &shard.mutex);
            }
            return .follower;
        }

        // Cap-hit returns .leader uncoordinated (no insert, no bookkeeping).
        // Eviction-on-cap would wake real queries' followers and double
        // upstream amplification — uncoordinated is the lesser evil.
        _ = tryInsertLeaderLocked(shard, self.io, self.allocator, key, monotonic.nowMs());
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
        if (shard.map.get(key)) |_| return false;
        return tryInsertLeaderLocked(shard, self.io, self.allocator, key, monotonic.nowMs());
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

// ── Tests ──────────────────────────────────────────────────────────────

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
            result.store(@intFromEnum(r), .release);
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
    try testing.expectEqual(@intFromEnum(AcquireResult.follower), follower_result.load(.acquire));
    try testing.expectEqual(@as(u32, 0), table.count());
}

test "acquireOrWaitWithTimeout uses custom timeout" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    _ = table.acquireOrWait("example.com", .a, 0);
    // Same-thread follower with already-expired deadline: returns immediately.
    const r = table.acquireOrWaitWithTimeout("example.com", .a, 0, monotonic.nowNs());
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

test "CD bit partitions dedup groups" {
    // CD=0 and CD=1 must map to distinct dedup keys so they do not
    // coalesce. RFC 6840 §5.9: CD=1 clients want data regardless of
    // validation state, CD=0 clients want validation. Fusing them means
    // one population gets the wrong semantics.
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    const cd0: u8 = 0;
    const cd1: u8 = 1;

    const leader_cd0 = table.acquireOrWait("example.com", .a, cd0);
    try testing.expectEqual(.leader, leader_cd0);

    // CD=1 for the same (name, qtype) must become its own leader, not wait.
    const leader_cd1 = table.acquireOrWait("example.com", .a, cd1);
    try testing.expectEqual(.leader, leader_cd1);

    table.releaseLeader("example.com", .a, cd0);
    table.releaseLeader("example.com", .a, cd1);
    try testing.expectEqual(@as(u32, 0), table.count());
}

test "table caps entries at max_entries" {
    var table = InFlightTable.init(testing.allocator, testing.io);
    defer table.deinit();

    // Natural fill: per_shard_cap's headroom absorbs uniform variance, so
    // every entry lands. A regression to a stingier cap would drop some.
    var name_buf: [32]u8 = undefined;
    for (0..max_entries) |i| {
        const name = std.fmt.bufPrint(&name_buf, "n{d}.example.com", .{i}) catch unreachable;
        try testing.expectEqual(.leader, table.acquireOrWait(name, .a, 0));
    }
    try testing.expectEqual(@as(u32, max_entries), table.count());

    // Overflow: 2× more names so some shards reliably hit cap. Refused
    // inserts still return .leader (uncoordinated) — graceful degradation.
    var caps_observed: usize = 0;
    for (0..2 * max_entries) |i| {
        const name = std.fmt.bufPrint(&name_buf, "overflow{d}.example.com", .{i}) catch unreachable;
        if (!table.tryAcquireLeader(name, .a, 0)) caps_observed += 1;
    }
    try testing.expect(caps_observed > 0);

    for (0..max_entries) |i| {
        const name = std.fmt.bufPrint(&name_buf, "n{d}.example.com", .{i}) catch unreachable;
        table.releaseLeader(name, .a, 0);
    }
    for (0..2 * max_entries) |i| {
        const name = std.fmt.bufPrint(&name_buf, "overflow{d}.example.com", .{i}) catch unreachable;
        table.releaseLeader(name, .a, 0);
    }
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
    // Second attempt returns false immediately (no wait), does not add an entry.
    try testing.expect(!table.tryAcquireLeader("example.com", .dnskey, 0));
    table.releaseLeader("example.com", .dnskey, 0);
    try testing.expectEqual(@as(u32, 0), table.count());

    // Freed — next claim succeeds again.
    try testing.expect(table.tryAcquireLeader("example.com", .dnskey, 0));
    table.releaseLeader("example.com", .dnskey, 0);
}

test "reapStaleLocked drops entries past the TTL, leaves fresh ones intact" {
    var shard = Shard{};
    defer shard.deinit(testing.allocator);

    const now_ms = monotonic.nowMs();
    const stale_ms = now_ms - stale_ttl_ms - 1;

    const stale_key = DedupKey.init("stale.example.com", .a, 0).?;
    const fresh_key = DedupKey.init("fresh.example.com", .a, 0).?;
    try shard.map.put(testing.allocator, stale_key, stale_ms);
    try shard.map.put(testing.allocator, fresh_key, now_ms);

    reapStaleLocked(&shard, testing.io, now_ms);

    try testing.expect(shard.map.get(stale_key) == null);
    try testing.expect(shard.map.get(fresh_key) != null);
}

test "reapStaleLocked is bounded by max_victims_per_reap per pass" {
    var shard = Shard{};
    defer shard.deinit(testing.allocator);

    const now_ms = monotonic.nowMs();
    const stale_ms = now_ms - stale_ttl_ms - 1;

    // Bounded victims per pass; successive passes finish the job.
    const total = max_victims_per_reap + 5;
    var name_buf: [32]u8 = undefined;
    for (0..total) |i| {
        const name = std.fmt.bufPrint(&name_buf, "n{d}", .{i}) catch unreachable;
        const k = DedupKey.init(name, .a, 0).?;
        try shard.map.put(testing.allocator, k, stale_ms);
    }
    try testing.expectEqual(@as(u32, @intCast(total)), shard.map.count());

    reapStaleLocked(&shard, testing.io, now_ms);
    try testing.expectEqual(@as(u32, 5), shard.map.count());

    reapStaleLocked(&shard, testing.io, now_ms);
    try testing.expectEqual(@as(u32, 0), shard.map.count());
}

test "tryInsertLeaderLocked reaps a stranded slot when shard hits watermark" {
    var shard = Shard{};
    defer shard.deinit(testing.allocator);

    const fresh_ms = monotonic.nowMs();
    const stale_ms = fresh_ms - stale_ttl_ms - 1;

    const victim_key = DedupKey.init("victim.example.com", .a, 0).?;
    try shard.map.put(testing.allocator, victim_key, stale_ms);

    var name_buf: [32]u8 = undefined;
    var i: u32 = 0;
    while (shard.map.count() < reap_watermark) : (i += 1) {
        const name = std.fmt.bufPrint(&name_buf, "f{d}", .{i}) catch unreachable;
        const k = DedupKey.init(name, .a, 0).?;
        try shard.map.put(testing.allocator, k, fresh_ms);
    }

    const newcomer = DedupKey.init("newcomer.example.com", .a, 0).?;
    try testing.expect(tryInsertLeaderLocked(&shard, testing.io, testing.allocator, newcomer, fresh_ms));
    try testing.expect(shard.map.get(victim_key) == null);
    try testing.expect(shard.map.get(newcomer) != null);
}
