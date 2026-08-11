const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;

// ── Constants (Unbound/Knot consensus) ───────────────────────────────

/// Initial timeout for unknown servers (Unbound 376, Knot 400).
const initial_timeout_ms: u32 = 400;

/// Minimum RTO floor. With the rttvar floor (srtt/4) guaranteeing
/// jitter headroom, this only catches degenerate sub-millisecond RTTs.
const min_timeout_ms: u32 = 50;

/// Maximum RTO cap (Knot).
const max_timeout_ms: u32 = 10_000;

/// Consecutive timeouts before marking dead (Knot).
const dead_threshold: u8 = 4;

/// How long a dead server stays dead (Knot).
const dead_duration_ms: i64 = 1_000;

/// Maximum backoff doublings (Knot: cap at 256x initial).
const max_backoff_shifts: u8 = 8;

/// Cap on tracked nameserver entries; bounds memory under random-server
/// load. Dropped entries revert to `initial_timeout_ms` next observation.
const default_max_entries: u32 = 4_096;

/// Hedge stagger = `hedge_multiplier × min_rtt`. 3× lands roughly at p95 for
/// well-behaved RTT distributions (Dean–Barroso "Tail at Scale", CACM 2013).
const hedge_multiplier: u32 = 3;

/// Re-anchor min_rtt after this long without a new minimum — lets the floor
/// track upward on route changes that move the path's true floor.
const hedge_decay_ms: i64 = 30_000;

/// Cold-start hedge stagger used when no min_rtt sample exists yet.
const hedge_cold_default_ms: u32 = initial_timeout_ms / 4;
/// Absolute ceiling on the hedge stagger.
const max_hedge_stagger_ms: u32 = 300;

// ── RttState ─────────────────────────────────────────────────────────

const RttState = struct {
    srtt_us: i64, // Smoothed RTT (microseconds)
    rttvar_us: i64, // RTT variance
    consecutive_timeouts: u8,
    dead_until_ms: i64, // Timestamp when dead period ends
    min_rtt_us: i64, // Windowed minimum RTT (re-anchored after hedge_decay_ms)
    min_rtt_stamp_ms: i64, // Timestamp of last min_rtt update
};

// ── RttCache ─────────────────────────────────────────────────────────

const EntryMap = std.HashMap(AddressKey, RttState, AddressKey.HashCtx, std.hash_map.default_max_load_percentage);

/// Shard count: same scheme as cache.zig — distribute lock + probe cost
/// across N independent maps keyed on the high bits of AddressKey.HashCtx.
/// The single-rwlock RttCache showed lock-acquire/release at ~5–8% of CPU
/// on the miss workload at thread counts ≥ 32.
const shard_count: u32 = 16;
const shard_mask: u32 = shard_count - 1;

const Shard = struct {
    entries: EntryMap,
    rwlock: ?std.Io.RwLock,
    /// High-water mark of any `dead_until_ms` ever written in this shard.
    /// Read atomically without the rwlock by `isDead`'s fast path; cache-line
    /// aligned so the reads don't pull in the rwlock's reader-count line.
    latest_dead_until_ms: std.atomic.Value(i64) align(std.atomic.cache_line) =
        std.atomic.Value(i64).init(0),
};

pub const RttCache = struct {
    shards: [shard_count]Shard,
    io: std.Io,
    now_fn: *const fn () i64,
    /// Caller-visible global cap (referenced in tests as the saturation point).
    max_entries: u32,
    /// Precomputed `ceilDiv(max_entries, shard_count)`. Each insert checks it
    /// against the local shard count, so storing it avoids a redundant divide.
    per_shard_cap: u32,

    pub const Config = struct {
        allocator: Allocator,
        io: std.Io,
        thread_safe: bool = false,
        max_entries: u32 = default_max_entries,
    };

    pub fn init(cfg: Config) RttCache {
        var shards: [shard_count]Shard = undefined;
        for (&shards) |*s| s.* = .{
            .entries = EntryMap.init(cfg.allocator),
            .rwlock = if (cfg.thread_safe) std.Io.RwLock.init else null,
        };
        return .{
            .shards = shards,
            .io = cfg.io,
            .now_fn = &@import("monotonic.zig").nowMs,
            .max_entries = cfg.max_entries,
            .per_shard_cap = (cfg.max_entries + shard_count - 1) / shard_count,
        };
    }

    pub fn deinit(self: *RttCache) void {
        for (&self.shards) |*s| s.entries.deinit();
    }

    fn shardFor(self: *RttCache, key: AddressKey) *Shard {
        const h: u32 = @truncate(AddressKey.HashCtx.hash(.{}, key) >> 32);
        return &self.shards[h & shard_mask];
    }

    /// Return the recommended timeout in ms for this server.
    pub fn getTimeout(self: *RttCache, key: AddressKey) u32 {
        const shard = self.shardFor(key);
        if (shard.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlockShared(self.io);

        const state = shard.entries.get(key) orelse return initial_timeout_ms;
        return computeTimeout(state);
    }

    /// Record a successful response with measured RTT (microseconds).
    pub fn recordSuccess(self: *RttCache, key: AddressKey, rtt_us: i64) void {
        const now_ms = self.now_fn();
        const shard = self.shardFor(key);
        if (shard.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlock(self.io);

        const gop = shard.entries.getOrPut(key) catch return;
        if (!gop.found_existing) {
            // First sample: srtt = R, rttvar = R/2
            gop.value_ptr.* = .{
                .srtt_us = rtt_us,
                .rttvar_us = @divTrunc(rtt_us, 2),
                .consecutive_timeouts = 0,
                .dead_until_ms = 0,
                .min_rtt_us = rtt_us,
                .min_rtt_stamp_ms = now_ms,
            };
        } else {
            // RFC 6298 EWMA update
            const delta: i64 = @intCast(@abs(gop.value_ptr.srtt_us - rtt_us));
            gop.value_ptr.rttvar_us = 3 * @divTrunc(gop.value_ptr.rttvar_us, 4) + @divTrunc(delta, 4);
            gop.value_ptr.srtt_us = 7 * @divTrunc(gop.value_ptr.srtt_us, 8) + @divTrunc(rtt_us, 8);
            gop.value_ptr.consecutive_timeouts = 0;
            gop.value_ptr.dead_until_ms = 0;

            // Min-RTT tracking: re-anchor if stale, else take the running min.
            // Re-anchoring lets the floor track upward on route changes.
            if (now_ms - gop.value_ptr.min_rtt_stamp_ms > hedge_decay_ms) {
                gop.value_ptr.min_rtt_us = rtt_us;
                gop.value_ptr.min_rtt_stamp_ms = now_ms;
            } else if (rtt_us < gop.value_ptr.min_rtt_us) {
                gop.value_ptr.min_rtt_us = rtt_us;
                gop.value_ptr.min_rtt_stamp_ms = now_ms;
            }
        }
        if (shard.entries.count() > self.per_shard_cap) evictOneFrom(shard, key);
    }

    /// Hedge stagger for the leading-leg server, in ms. Callers must filter
    /// dead servers (via `isDead`) before calling — this returns a stagger
    /// even for entries with stale samples.
    pub fn getHedgeStagger(self: *RttCache, key: AddressKey) u32 {
        const shard = self.shardFor(key);
        if (shard.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlockShared(self.io);

        const state = shard.entries.get(key) orelse return hedge_cold_default_ms;
        if (state.min_rtt_us <= 0) return hedge_cold_default_ms;

        const stagger_us = @as(i64, hedge_multiplier) * state.min_rtt_us;
        const stagger_ms: u32 = @intCast(@max(1, @divTrunc(stagger_us, 1000)));
        return @max(min_timeout_ms, @min(stagger_ms, max_hedge_stagger_ms));
    }

    /// Record a timeout for this server (exponential backoff + dead marking).
    pub fn recordTimeout(self: *RttCache, key: AddressKey) void {
        const shard = self.shardFor(key);
        if (shard.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlock(self.io);

        const gop = shard.entries.getOrPut(key) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .srtt_us = @as(i64, initial_timeout_ms) * 1000,
                .rttvar_us = @as(i64, initial_timeout_ms) * 500,
                .consecutive_timeouts = 1,
                .dead_until_ms = 0,
                .min_rtt_us = 0, // Unset — getHedgeStagger returns cold default.
                .min_rtt_stamp_ms = 0,
            };
        } else {
            if (gop.value_ptr.consecutive_timeouts < 255) {
                gop.value_ptr.consecutive_timeouts += 1;
            }
            if (gop.value_ptr.consecutive_timeouts >= dead_threshold) {
                const new_deadline = self.now_fn() + dead_duration_ms;
                gop.value_ptr.dead_until_ms = new_deadline;
                // Bump the shard's lock-free death gate. Held under exclusive
                // rwlock so no other writer can interleave; .release pairs with
                // the .acquire in isDead so a fast-path reader that sees the
                // new high-water also sees the dead_until_ms write above.
                const cur = shard.latest_dead_until_ms.load(.monotonic);
                if (new_deadline > cur) shard.latest_dead_until_ms.store(new_deadline, .release);
            }
        }
        if (shard.entries.count() > self.per_shard_cap) evictOneFrom(shard, key);
    }

    /// Evict one non-`protected` entry; a flood across many servers must not
    /// erase healthy root/TLD scoring all at once. Lock is held by caller.
    fn evictOneFrom(shard: *Shard, protected: AddressKey) void {
        var it = shard.entries.iterator();
        while (it.next()) |kv| {
            if (std.meta.eql(kv.key_ptr.*, protected)) continue;
            shard.entries.removeByPtr(kv.key_ptr);
            return;
        }
    }

    /// Clear death-tracking without an RTT sample (DoT successes must not
    /// shape Do53 estimates, but must break the one-way timeout ratchet).
    pub fn recordAlive(self: *RttCache, key: AddressKey) void {
        const shard = self.shardFor(key);
        if (shard.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlock(self.io);
        const state = shard.entries.getPtr(key) orelse return;
        state.consecutive_timeouts = 0;
        state.dead_until_ms = 0;
    }

    /// Check whether the server is currently marked dead. If `now_ms` is past
    /// the shard's death high-water, no entry can be dead and the rwlock is
    /// skipped — the dominant case under healthy upstream.
    pub fn isDead(self: *RttCache, key: AddressKey, now_ms: i64) bool {
        const shard = self.shardFor(key);
        if (now_ms >= shard.latest_dead_until_ms.load(.acquire)) return false;

        if (shard.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlockShared(self.io);

        const state = shard.entries.get(key) orelse return false;
        return state.dead_until_ms > now_ms;
    }

    pub fn nowMs(self: *const RttCache) i64 {
        return self.now_fn();
    }

    fn count(self: *const RttCache) usize {
        var total: usize = 0;
        for (&self.shards) |*s| total += s.entries.count();
        return total;
    }
};

fn computeTimeout(state: RttState) u32 {
    // RTO = srtt + 4 * rttvar (RFC 6298), but never tighter than 2× the
    // smoothed RTT. Without this floor, consistent RTTs drive rttvar → 0
    // and the timeout converges to exactly the RTT — any jitter causes
    // a timeout that cascades into repeated failures.
    const base_us = @max(state.srtt_us + 4 * state.rttvar_us, 2 * state.srtt_us);
    const base_ms: u32 = @intCast(@max(1, @divTrunc(base_us, 1000)));

    // Exponential backoff: double per consecutive timeout, capped
    const shift: u5 = @intCast(@min(state.consecutive_timeouts, max_backoff_shifts));
    const backed_off = @as(u64, base_ms) << shift;

    return @intCast(@max(min_timeout_ms, @min(backed_off, max_timeout_ms)));
}

// ── Tests ────────────────────────────────────────────────────────────

var test_now_ms: i64 = 1000;

fn testNowMs() i64 {
    return test_now_ms;
}

fn testAddr(last_octet: u8) AddressKey {
    return AddressKey.fromAddress(na.initIp4(.{ 10, 0, 0, last_octet }, 53));
}

test "getTimeout returns initial for unknown server" {
    var cache = RttCache.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer cache.deinit();
    cache.now_fn = &testNowMs;

    try testing.expectEqual(initial_timeout_ms, cache.getTimeout(testAddr(1)));
}

test "recordSuccess updates EWMA" {
    var cache = RttCache.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer cache.deinit();
    cache.now_fn = &testNowMs;

    const key = testAddr(1);

    // First sample: srtt = 100ms, rttvar = 50ms → RTO = 300
    // rttvar floor = srtt/4 = 25ms, actual rttvar = 50ms > 25ms, no effect
    cache.recordSuccess(key, 100_000);
    try testing.expectEqual(@as(u32, 300), cache.getTimeout(key)); // 100 + 4*50

    // Second sample: 200ms → srtt moves toward 200, variance adjusts
    cache.recordSuccess(key, 200_000);
    const t2 = cache.getTimeout(key);
    try testing.expect(t2 > 0);
    try testing.expect(t2 <= max_timeout_ms);
}

test "entries map is bounded under random-server load" {
    // Saturates AT the cap (single-entry eviction); does not oscillate to 0.
    var cache = RttCache.init(.{
        .allocator = testing.allocator,
        .io = testing.io,
        .max_entries = 32,
    });
    defer cache.deinit();
    cache.now_fn = &testNowMs;

    var i: u32 = 0;
    while (i < 512) : (i += 1) {
        const key = AddressKey.fromAddress(na.initIp4(.{
            @intCast((i >> 16) & 0xff),
            @intCast((i >> 8) & 0xff),
            @intCast(i & 0xff),
            1,
        }, 53));
        if (i & 1 == 0) cache.recordSuccess(key, 50_000) else cache.recordTimeout(key);
        try testing.expect(cache.count() <= cache.max_entries);
    }
    // With sharded per-shard caps the steady-state count depends on hash
    // distribution; floor at half to catch entry loss without flaking on
    // legitimate distribution variance.
    try testing.expect(cache.count() >= cache.max_entries / 2);
}

test "concurrent inserts under cap pressure stay bounded" {
    // Pins the lock invariant for evictOne: if the cap-check or eviction
    // were ever moved outside the rwlock, two threads racing inside
    // evictOne could invalidate each other's iterator and corrupt the map.
    var cache = RttCache.init(.{
        .allocator = testing.allocator,
        .io = testing.io,
        .thread_safe = true,
        .max_entries = 64,
    });
    defer cache.deinit();
    cache.now_fn = &testNowMs;

    const Worker = struct {
        const inserts = 512;
        cache: *RttCache,
        thread_id: u8,

        fn run(self: *@This()) void {
            var i: u32 = 0;
            while (i < inserts) : (i += 1) {
                const k = AddressKey.fromAddress(na.initIp4(.{
                    self.thread_id,
                    @intCast((i >> 8) & 0xff),
                    @intCast(i & 0xff),
                    1,
                }, 53));
                if (i & 1 == 0) self.cache.recordSuccess(k, 50_000) else self.cache.recordTimeout(k);
            }
        }
    };

    const num_threads = 4;
    var workers: [num_threads]Worker = undefined;
    var threads: [num_threads]std.Thread = undefined;
    for (0..num_threads) |i| {
        workers[i] = .{ .cache = &cache, .thread_id = @intCast(i + 1) };
        threads[i] = try std.Thread.spawn(.{}, Worker.run, .{&workers[i]});
    }
    for (threads) |t| t.join();

    try testing.expect(cache.count() <= cache.max_entries);
    try testing.expect(cache.count() >= cache.max_entries / 2);
}

test "getHedgeStagger returns cold default for unknown server" {
    var cache = RttCache.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer cache.deinit();
    cache.now_fn = &testNowMs;

    try testing.expectEqual(hedge_cold_default_ms, cache.getHedgeStagger(testAddr(1)));
}

test "getHedgeStagger uses 3x min_rtt clamped to [50, 300]" {
    var cache = RttCache.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer cache.deinit();
    cache.now_fn = &testNowMs;
    test_now_ms = 1000;

    const key = testAddr(1);

    // 80ms, 60ms, 90ms — minimum is 60ms → stagger = 180ms
    cache.recordSuccess(key, 80_000);
    cache.recordSuccess(key, 60_000);
    cache.recordSuccess(key, 90_000);
    try testing.expectEqual(@as(u32, 180), cache.getHedgeStagger(key));

    // Floor: 5ms → 3*5=15 → clamped to 50ms
    const key_low = testAddr(2);
    cache.recordSuccess(key_low, 5_000);
    try testing.expectEqual(@as(u32, 50), cache.getHedgeStagger(key_low));

    // Ceiling: 200ms → 3*200=600 → clamped to 300ms
    const key_high = testAddr(3);
    cache.recordSuccess(key_high, 200_000);
    try testing.expectEqual(@as(u32, 300), cache.getHedgeStagger(key_high));
}

test "min_rtt re-anchors after hedge_decay_ms" {
    var cache = RttCache.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer cache.deinit();
    cache.now_fn = &testNowMs;
    test_now_ms = 1000;

    const key = testAddr(1);

    // Anchor at 20ms.
    cache.recordSuccess(key, 20_000);
    try testing.expectEqual(@as(u32, 60), cache.getHedgeStagger(key));

    // Within decay window, 100ms doesn't move the floor.
    test_now_ms = 1000 + hedge_decay_ms - 1;
    cache.recordSuccess(key, 100_000);
    try testing.expectEqual(@as(u32, 60), cache.getHedgeStagger(key));

    // Past decay window, 100ms re-anchors → 3*100=300 (at the ceiling).
    test_now_ms = 1000 + hedge_decay_ms + 1;
    cache.recordSuccess(key, 100_000);
    try testing.expectEqual(@as(u32, 300), cache.getHedgeStagger(key));
}

test "hedge stagger survives transient timeouts that inflate RTO" {
    // The win: hedge fires at p95 even when one timeout has doubled the RTO.
    var cache = RttCache.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer cache.deinit();
    cache.now_fn = &testNowMs;
    test_now_ms = 1000;

    const key = testAddr(1);
    cache.recordSuccess(key, 20_000);
    const rto_clean = cache.getTimeout(key);
    const hedge = cache.getHedgeStagger(key);

    cache.recordTimeout(key);

    try testing.expect(cache.getTimeout(key) > rto_clean); // RTO backs off
    try testing.expectEqual(hedge, cache.getHedgeStagger(key)); // hedge unchanged
}

test "recordTimeout does not disturb min_rtt" {
    var cache = RttCache.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer cache.deinit();
    cache.now_fn = &testNowMs;
    test_now_ms = 1000;

    const key = testAddr(1);
    cache.recordSuccess(key, 50_000);
    const before = cache.getHedgeStagger(key);

    cache.recordTimeout(key);
    cache.recordTimeout(key);
    cache.recordTimeout(key);
    cache.recordTimeout(key);

    try testing.expectEqual(before, cache.getHedgeStagger(key));
}

test "recordTimeout increments consecutive count and marks dead" {
    var cache = RttCache.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer cache.deinit();
    cache.now_fn = &testNowMs;
    test_now_ms = 1000;

    const key = testAddr(2);

    // Prime with a success
    cache.recordSuccess(key, 100_000);
    try testing.expect(!cache.isDead(key, cache.nowMs()));

    // Timeout 4 times → should be dead
    cache.recordTimeout(key);
    cache.recordTimeout(key);
    cache.recordTimeout(key);
    cache.recordTimeout(key);
    try testing.expect(cache.isDead(key, cache.nowMs()));

    // After dead_duration_ms, should recover
    test_now_ms = 1000 + dead_duration_ms + 1;
    try testing.expect(!cache.isDead(key, cache.nowMs()));
}
