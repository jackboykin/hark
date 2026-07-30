const std = @import("std");
const mem = std.mem;
const math = std.math;
const testing = std.testing;
const Allocator = mem.Allocator;
const na = @import("net_address.zig");
const AddressKey = na.AddressKey;
const RttCache = @import("ns_rtt.zig").RttCache;
const dns = @import("dns.zig");
const rand = @import("rand.zig");

// ── Constants ────────────────────────────────────────────────────────

/// Discount factor: γ = 0.995 → half-life ≈ 138 observations.
const default_gamma: f32 = 0.995;

/// Prior parameters: Beta(1,1) = uniform/uninformative.
const alpha_prior: f32 = 1.0;
const beta_prior: f32 = 1.0;

/// Max NS per zone (13 IPv4 + 13 IPv6).
const max_order = 26;

/// Cap on tracked (zone, server) arms; bounds memory under random-zone
/// load. Lost arms reset to the Beta(1,1) prior on next observation.
const default_max_arms: u32 = 16_384;

// ── Outcome ──────────────────────────────────────────────────────────

pub const Outcome = enum {
    /// Valid answer received (may be referral, NODATA, NXDOMAIN — all are
    /// legitimate authoritative behavior).
    success,
    /// TC bit set, required TCP fallback (server alive but costly).
    truncated,
    /// SERVFAIL, REFUSED, or other server error rcode.
    server_error,
    /// No response within timeout.
    timeout,
    /// Response failed DNSSEC validation.
    validation_failure,
};

/// Map an outcome + elapsed time to a reward in [0,1].
/// Latency component: linear ramp from 1.0 at 0ms to 0.5 at ≥1000ms.
fn reward(outcome: Outcome, elapsed_us: i64) f32 {
    return switch (outcome) {
        .timeout => 0.0,
        .validation_failure => 0.0,
        .server_error => 0.1,
        .truncated => 0.3 * latencyFactor(elapsed_us),
        .success => latencyFactor(elapsed_us),
    };
}

fn latencyFactor(elapsed_us: i64) f32 {
    const ms: f32 = @floatFromInt(@divTrunc(@max(elapsed_us, 0), 1000));
    return @max(0.5, 1.0 - ms / 2000.0);
}

// ── Arm Key & State ──────────────────────────────────────────────────

/// Compound key: (zone, nameserver address). Per-zone keying prevents
/// the Disablance Attack (IETF draft-zhang-dnsop-ns-selection V1) and
/// SRTT Subversion (V2).
const ArmKey = struct {
    zone_hash: u64,
    addr_key: AddressKey,
};

/// Compose AddressKey's hash with the precomputed `zone_hash` so we skip
/// re-running AddressKey.HashCtx (FNV-1a + Murmur3 fmix64) over the whole
/// key on every `discountAndRead` / `recordOutcome` lookup, while still
/// picking up the randomized seed AddressKey.HashCtx already applies.
const ArmKeyContext = struct {
    pub fn hash(_: @This(), key: ArmKey) u64 {
        var h = AddressKey.HashCtx.hash(.{}, key.addr_key);
        h ^= key.zone_hash;
        h *%= 0x100000001b3;
        return h;
    }

    pub fn eql(_: @This(), a: ArmKey, b: ArmKey) bool {
        return a.zone_hash == b.zone_hash and
            AddressKey.HashCtx.eql(.{}, a.addr_key, b.addr_key);
    }
};

const ArmState = struct {
    alpha: f32 = alpha_prior,
    beta: f32 = beta_prior,
};

// ── NsSelector ───────────────────────────────────────────────────────

const ArmMap = std.HashMap(ArmKey, ArmState, ArmKeyContext, std.hash_map.default_max_load_percentage);

/// Sharded to bound mutex contention as resolution-threads scales. Each shard
/// owns its own map and mutex; the per-shard cap is `ceil(max_arms / shard_count)`
/// so total capacity remains bounded by `max_arms` (modulo per-shard rounding).
const shard_count: u32 = 16;
const shard_mask: u32 = shard_count - 1;

const Shard = struct {
    arms: ArmMap,
    mutex: ?std.Io.Mutex,
};

pub const NsSelector = struct {
    shards: [shard_count]Shard,
    io: std.Io,
    gamma: f32,
    max_arms: u32,
    per_shard_cap: u32,

    pub const Config = struct {
        allocator: Allocator,
        io: std.Io,
        thread_safe: bool = false,
        max_arms: u32 = default_max_arms,
    };

    pub fn init(cfg: Config) NsSelector {
        var shards: [shard_count]Shard = undefined;
        for (&shards) |*s| s.* = .{
            .arms = ArmMap.init(cfg.allocator),
            .mutex = if (cfg.thread_safe) std.Io.Mutex.init else null,
        };
        return .{
            .shards = shards,
            .io = cfg.io,
            .gamma = default_gamma,
            .max_arms = cfg.max_arms,
            .per_shard_cap = (cfg.max_arms + shard_count - 1) / shard_count,
        };
    }

    pub fn deinit(self: *NsSelector) void {
        for (&self.shards) |*s| s.arms.deinit();
    }

    fn count(self: *NsSelector) usize {
        var total: usize = 0;
        for (&self.shards) |*s| {
            if (s.mutex) |*mtx| mtx.lockUncancelable(self.io);
            defer if (s.mutex) |*mtx| mtx.unlock(self.io);
            total += s.arms.count();
        }
        return total;
    }

    inline fn shardFor(self: *NsSelector, key: ArmKey) *Shard {
        // Low bits are safe: ArmKeyContext.hash composes an already
        // fmix64-finalized AddressKey hash. (ns_rtt.shardFor must use high
        // bits off the raw FNV-1a chain instead.)
        const h = ArmKeyContext.hash(.{}, key);
        return &self.shards[@as(u32, @truncate(h)) & shard_mask];
    }

    /// Returned ordering: live servers (sorted by Thompson sample, descending)
    /// followed by dead servers (shuffled). `live_count` tells callers where
    /// the boundary is so they can skip the per-server `isDead` re-check on
    /// the primary path; a final fallback can still reach `order[live_count..]`
    /// when every live attempt has failed.
    pub const Selection = struct {
        order: []const usize,
        live_count: usize,
    };

    /// Select servers using Thompson Sampling. Returns ordered indices
    /// into `servers`: best Thompson draw first, dead servers last.
    /// RttCache is still consulted for dead-server status.
    pub fn selectServers(
        self: *NsSelector,
        zone: dns.Name,
        servers: []const na.Address,
        rtt_cache: ?*RttCache,
        order_buf: *[max_order]usize,
    ) Selection {
        const zh = zoneHash(zone);

        var live_count: usize = 0;
        var dead_count: usize = 0;
        var samples: [max_order]f32 = undefined;
        const now_ms = if (rtt_cache) |rc| rc.nowMs() else 0;

        // Per-arm shard locks: N acquisitions per call, each uncontended in
        // the common case. Discount + read are fused in one locked region.
        for (servers, 0..) |server, i| {
            const addr_key = AddressKey.fromAddress(server);

            // Check dead status via RttCache (hard failure override).
            const is_dead = if (rtt_cache) |rc| rc.isDead(addr_key, now_ms) else false;
            if (is_dead) {
                order_buf[max_order - 1 - dead_count] = i;
                dead_count += 1;
                continue;
            }

            const arm_key = ArmKey{ .zone_hash = zh, .addr_key = addr_key };
            const state = self.discountAndRead(arm_key);

            order_buf[live_count] = i;
            // Beta(1,1) is uniform: skip Marsaglia-Tsang Gamma machinery when
            // the arm is at the uninformed prior (no observations, or floored
            // back to it by discount). Dominant case on cold resolutions.
            // Float == is bit-exact here because discountAndRead floors both
            // fields back to the prior via @max with the same constants.
            samples[live_count] = if (state.alpha == alpha_prior and state.beta == beta_prior)
                rand.fastUniformFloat(self.io)
            else
                betaSample(self.io, state.alpha, state.beta);
            live_count += 1;
        }

        // Sort live servers by Thompson sample (descending).
        sortByScoreDesc(order_buf[0..live_count], samples[0..live_count]);

        // Append dead servers (shuffled).
        if (dead_count > 0) {
            var dead_buf: [max_order]usize = undefined;
            for (0..dead_count) |d| {
                dead_buf[d] = order_buf[max_order - 1 - d];
            }
            rand.fastShuffle(usize, self.io, dead_buf[0..dead_count]);
            @memcpy(order_buf[live_count..][0..dead_count], dead_buf[0..dead_count]);
        }

        return .{
            .order = order_buf[0 .. live_count + dead_count],
            .live_count = live_count,
        };
    }

    /// Record the outcome of querying a nameserver.
    pub fn recordOutcome(
        self: *NsSelector,
        zone: dns.Name,
        server: na.Address,
        outcome: Outcome,
        elapsed_us: i64,
    ) void {
        const arm_key = ArmKey{
            .zone_hash = zoneHash(zone),
            .addr_key = AddressKey.fromAddress(server),
        };
        const shard = self.shardFor(arm_key);
        if (shard.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (shard.mutex) |*mtx| mtx.unlock(self.io);

        const r = reward(outcome, elapsed_us);

        const gop = shard.arms.getOrPut(arm_key) catch return;
        if (!gop.found_existing) gop.value_ptr.* = ArmState{};
        gop.value_ptr.alpha += r;
        gop.value_ptr.beta += (1.0 - r);

        if (shard.arms.count() > self.per_shard_cap) evictOneLocked(shard, arm_key);
    }

    /// Evict one non-`protected` arm from a shard the caller holds. A flood
    /// across many zones must not erase healthy root/TLD posteriors at once;
    /// the per-shard cap bounds eviction scope.
    fn evictOneLocked(shard: *Shard, protected: ArmKey) void {
        var it = shard.arms.iterator();
        while (it.next()) |kv| {
            if (std.meta.eql(kv.key_ptr.*, protected)) continue;
            shard.arms.removeByPtr(kv.key_ptr);
            return;
        }
    }

    // ── Internal ─────────────────────────────────────────────────────

    /// Apply discount γ if the arm exists, then return its (possibly updated)
    /// state. Single-shard lock; caller must not hold any other shard.
    fn discountAndRead(self: *NsSelector, key: ArmKey) ArmState {
        const shard = self.shardFor(key);
        if (shard.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (shard.mutex) |*mtx| mtx.unlock(self.io);

        if (shard.arms.getPtr(key)) |state| {
            state.alpha = @max(alpha_prior, state.alpha * self.gamma);
            state.beta = @max(beta_prior, state.beta * self.gamma);
            return state.*;
        }
        return ArmState{};
    }
};

// ── Zone Hashing ─────────────────────────────────────────────────────

/// Hash a dns.Name into a u64 for use as zone key. Case-insensitive.
fn zoneHash(name: dns.Name) u64 {
    var h: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for (name.labels) |label| {
        for (label) |c| {
            const lower: u8 = if (c >= 'A' and c <= 'Z') c + 32 else c;
            h ^= lower;
            h *%= 0x100000001b3; // FNV-1a prime
        }
        h ^= '.';
        h *%= 0x100000001b3;
    }
    return h;
}

// ── Beta Distribution Sampling ───────────────────────────────────────
//
// Beta(α, β) = Gamma(α,1) / (Gamma(α,1) + Gamma(β,1))
// Gamma(α,1) via Marsaglia-Tsang (2000) for α ≥ 1.
// Our α, β are always ≥ 1.0 due to the prior floor.

fn betaSample(io: std.Io, alpha: f32, beta: f32) f32 {
    const x = gammaSample(io, alpha);
    const y = gammaSample(io, beta);
    const sum = x + y;
    if (sum <= 0) return 0.5; // degenerate — return prior mean
    return x / sum;
}

/// Marsaglia-Tsang method for Gamma(α, 1) where α ≥ 1.
fn gammaSample(io: std.Io, alpha: f32) f32 {
    std.debug.assert(alpha >= 1.0);

    const d = alpha - 1.0 / 3.0;
    const c = 1.0 / @sqrt(9.0 * d);

    while (true) {
        var v: f32 = undefined;
        var x: f32 = undefined;

        // Rejection: draw normal x such that v = (1 + c*x)³ > 0
        while (true) {
            x = normalSample(io);
            v = 1.0 + c * x;
            if (v > 0) break;
        }
        v = v * v * v;

        const u = rand.fastUniformFloat(io);
        // Fast accept (avoids log ~83% of the time)
        if (u < 1.0 - 0.0331 * (x * x) * (x * x)) return d * v;
        // Slow accept
        if (@log(u) < 0.5 * x * x + d * (1.0 - v + @log(v))) return d * v;
    }
}

/// Standard normal via Box-Muller transform.
fn normalSample(io: std.Io) f32 {
    const r1 = rand.fastUniformFloat(io);
    const r2 = rand.fastUniformFloat(io);
    // Avoid log(0)
    const safe_r1 = @max(r1, 1e-10);
    return @sqrt(-2.0 * @log(safe_r1)) * @cos(2.0 * math.pi * r2);
}

// ── Sorting ──────────────────────────────────────────────────────────

/// Sort indices by corresponding scores (descending). Insertion sort
/// is fine for N ≤ 26.
fn sortByScoreDesc(indices: []usize, scores: []f32) void {
    std.debug.assert(indices.len == scores.len);
    var i: usize = 1;
    while (i < indices.len) : (i += 1) {
        const key_idx = indices[i];
        const key_score = scores[i];
        var j: usize = i;
        while (j > 0 and scores[j - 1] < key_score) : (j -= 1) {
            indices[j] = indices[j - 1];
            scores[j] = scores[j - 1];
        }
        indices[j] = key_idx;
        scores[j] = key_score;
    }
}

// ── Tests ────────────────────────────────────────────────────────────

test "reward mapping" {
    // Timeout → 0.0
    try testing.expectEqual(@as(f32, 0.0), reward(.timeout, 0));
    try testing.expectEqual(@as(f32, 0.0), reward(.validation_failure, 100_000));
    // Server error → 0.1
    try testing.expectEqual(@as(f32, 0.1), reward(.server_error, 50_000));
    // Success at 0ms → 1.0
    try testing.expectEqual(@as(f32, 1.0), reward(.success, 0));
    // Success at 1000ms → 0.5
    try testing.expectEqual(@as(f32, 0.5), reward(.success, 1_000_000));
    // Success at 500ms → 0.75
    try testing.expectEqual(@as(f32, 0.75), reward(.success, 500_000));
}

test "latency factor" {
    try testing.expectEqual(@as(f32, 1.0), latencyFactor(0));
    try testing.expectEqual(@as(f32, 0.75), latencyFactor(500_000));
    try testing.expectEqual(@as(f32, 0.5), latencyFactor(1_000_000));
    // Clamped at 0.5 for very slow
    try testing.expectEqual(@as(f32, 0.5), latencyFactor(5_000_000));
}

test "zone hash case insensitive" {
    const lower = dns.Name{ .labels = &.{ "example", "com" } };
    const upper = dns.Name{ .labels = &.{ "EXAMPLE", "COM" } };
    const mixed = dns.Name{ .labels = &.{ "eXaMpLe", "cOm" } };
    try testing.expectEqual(zoneHash(lower), zoneHash(upper));
    try testing.expectEqual(zoneHash(lower), zoneHash(mixed));
}

test "zone hash different zones differ" {
    const a = dns.Name{ .labels = &.{ "example", "com" } };
    const b = dns.Name{ .labels = &.{ "example", "org" } };
    try testing.expect(zoneHash(a) != zoneHash(b));
}

test "ArmKeyContext: 16-shard distribution in the LOW bits" {
    // shardFor truncates the LOW bits of ArmKeyContext.hash — safe only
    // because the composed AddressKey hash is fmix64-finalized before the
    // zone xor/multiply. ns_rtt's sibling test (net_address.zig) pins the
    // HIGH bits; this pins the low-bit floor so a hash tweak that breaks
    // low-bit diffusion single-shards loudly instead of silently.
    const zone = zoneHash(dns.Name{ .labels = &.{ "example", "com" } });
    const addr_key = AddressKey.fromAddress(na.initIp4(.{ 192, 0, 2, 1 }, 53));

    // Axis 1: sequential addresses, fixed zone.
    var counts: [16]u32 = @splat(0);
    var i: u32 = 0;
    while (i < 4096) : (i += 1) {
        const k = ArmKey{
            .zone_hash = zone,
            .addr_key = AddressKey.fromAddress(na.initIp4(.{
                @intCast((i >> 16) & 0xff),
                @intCast((i >> 8) & 0xff),
                @intCast(i & 0xff),
                1,
            }, 53)),
        };
        counts[@as(u32, @truncate(ArmKeyContext.hash(.{}, k))) & shard_mask] += 1;
    }
    // Uniform expectation 256/bucket; same ±60%-class floor/ceiling as the
    // net_address sibling test.
    for (counts) |c| {
        try testing.expect(c >= 100);
        try testing.expect(c <= 700);
    }

    // Axis 2: sequential zone hashes, fixed address (many zones, one server).
    counts = @splat(0);
    var z: u64 = 0;
    while (z < 4096) : (z += 1) {
        const k = ArmKey{ .zone_hash = z, .addr_key = addr_key };
        counts[@as(u32, @truncate(ArmKeyContext.hash(.{}, k))) & shard_mask] += 1;
    }
    for (counts) |c| {
        try testing.expect(c >= 100);
        try testing.expect(c <= 700);
    }
}

test "beta sample in range" {
    // Draw many samples, all should be in (0, 1)
    for (0..1000) |_| {
        const s = betaSample(testing.io, 1.0, 1.0);
        try testing.expect(s >= 0.0 and s <= 1.0);
    }
    // Skewed distribution: alpha >> beta → samples mostly near 1.0
    var sum: f32 = 0;
    for (0..1000) |_| {
        sum += betaSample(testing.io, 100.0, 1.0);
    }
    try testing.expect(sum / 1000.0 > 0.9);
}

test "selectServers basic ordering" {
    var sel = NsSelector.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer sel.deinit();

    const zone = dns.Name{ .labels = &.{ "example", "com" } };
    const servers = [_]na.Address{
        na.initIp4(.{ 10, 0, 0, 1 }, 53),
        na.initIp4(.{ 10, 0, 0, 2 }, 53),
    };

    // Record: server 0 is terrible, server 1 is great
    for (0..50) |_| {
        sel.recordOutcome(zone, servers[0], .timeout, 0);
        sel.recordOutcome(zone, servers[1], .success, 10_000); // 10ms
    }

    // Over many trials, server 1 should usually be picked first
    var server1_first: usize = 0;
    var order_buf: [max_order]usize = undefined;
    for (0..100) |_| {
        const order = sel.selectServers(zone, &servers, null, &order_buf);
        if (order.order.len > 0 and order.order[0] == 1) server1_first += 1;
    }
    // Should be first >90% of the time
    try testing.expect(server1_first > 90);
}

test "discount causes re-exploration" {
    var sel = NsSelector.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer sel.deinit();
    sel.gamma = 0.9; // Aggressive discount for test

    const zone = dns.Name{ .labels = &.{ "test", "com" } };
    const servers = [_]na.Address{
        na.initIp4(.{ 10, 0, 0, 1 }, 53),
        na.initIp4(.{ 10, 0, 0, 2 }, 53),
    };

    // Make server 0 look bad initially
    for (0..20) |_| {
        sel.recordOutcome(zone, servers[0], .timeout, 0);
        sel.recordOutcome(zone, servers[1], .success, 10_000);
    }

    // Now run many selections without new observations (just discounting)
    // Both arms should decay toward the prior, increasing server 0's chances
    var order_buf: [max_order]usize = undefined;
    var server0_first: usize = 0;
    for (0..200) |_| {
        const order = sel.selectServers(zone, &servers, null, &order_buf);
        if (order.order.len > 0 and order.order[0] == 0) server0_first += 1;
    }
    // After heavy discounting, server 0 should get picked sometimes (re-explored)
    try testing.expect(server0_first > 10);
}

test "arms map is bounded under random-zone load" {
    // Saturates AT the cap (single-entry eviction); does not oscillate to 0.
    var sel = NsSelector.init(.{
        .allocator = testing.allocator,
        .io = testing.io,
        .max_arms = 64,
    });
    defer sel.deinit();

    var label_buf: [16]u8 = undefined;
    var i: u32 = 0;
    while (i < 1024) : (i += 1) {
        const label = std.fmt.bufPrint(&label_buf, "z{d}", .{i}) catch unreachable;
        const zone = dns.Name{ .labels = &.{ label, "test" } };
        const server = na.initIp4(.{ 10, 0, 0, @intCast(i & 0xff) }, 53);
        sel.recordOutcome(zone, server, .success, 10_000);
        try testing.expect(sel.count() <= sel.max_arms);
    }
    // With sharded per-shard caps the steady-state count depends on hash
    // distribution; floor at half to catch arm loss without flaking on
    // legitimate distribution variance.
    try testing.expect(sel.count() >= sel.max_arms / 2);
}

test "per-zone isolation" {
    var sel = NsSelector.init(.{ .allocator = testing.allocator, .io = testing.io });
    defer sel.deinit();

    const zone_a = dns.Name{ .labels = &.{ "a", "com" } };
    const zone_b = dns.Name{ .labels = &.{ "b", "com" } };
    const servers = [_]na.Address{
        na.initIp4(.{ 10, 0, 0, 1 }, 53),
        na.initIp4(.{ 10, 0, 0, 2 }, 53),
    };

    // Server 0 is great in zone_a but terrible in zone_b; server 1 is the
    // mirror image. Same arms, swapped reputations across zones — selection
    // must track each zone's history independently.
    for (0..50) |_| {
        sel.recordOutcome(zone_a, servers[0], .success, 10_000);
        sel.recordOutcome(zone_a, servers[1], .timeout, 0);
        sel.recordOutcome(zone_b, servers[0], .timeout, 0);
        sel.recordOutcome(zone_b, servers[1], .success, 10_000);
    }

    var order_buf: [max_order]usize = undefined;
    var a0_first: usize = 0;
    var b1_first: usize = 0;
    for (0..100) |_| {
        const oa = sel.selectServers(zone_a, &servers, null, &order_buf);
        if (oa.order.len > 0 and oa.order[0] == 0) a0_first += 1;
        const ob = sel.selectServers(zone_b, &servers, null, &order_buf);
        if (ob.order.len > 0 and ob.order[0] == 1) b1_first += 1;
    }
    try testing.expect(a0_first > 90);
    try testing.expect(b1_first > 90);
}
