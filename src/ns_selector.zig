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

pub const Outcome = enum {
    /// Valid answer received (may be referral, NODATA, NXDOMAIN — all are
    /// legitimate authoritative behavior).
    success,
    /// TC bit set, required TCP fallback (server alive but costly).
    truncated,
    /// SERVFAIL, REFUSED, or other server error rcode.
    server_error,
    timeout,
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
        // The zone fold leaves the composed hash unavalanched, and both halves
        // carry a consumer: shardIndex the top, ArmMap's probe the bottom.
        return na.fmix64(AddressKey.HashCtx.hash(.{}, key.addr_key) ^ key.zone_hash);
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

const ArmMap = std.HashMap(ArmKey, ArmState, ArmKeyContext, std.hash_map.default_max_load_percentage);

/// Sharded to bound mutex contention as resolution-threads scales. Each shard
/// owns its own map and mutex; the per-shard cap is `ceil(max_arms / shard_count)`
/// so total capacity remains bounded by `max_arms` (modulo per-shard rounding).
const shard_count: u32 = 16;
const shard_mask: u32 = shard_count - 1;

/// Shard from the top half, matching `ns_rtt`: `std.HashMap` probes from the
/// low bits of the same hash, so sharing them clusters every shard's index.
inline fn shardIndex(h: u64) u32 {
    return @as(u32, @truncate(h >> 32)) & shard_mask;
}

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
        return &self.shards[shardIndex(ArmKeyContext.hash(.{}, key))];
    }

    pub fn selectServers(
        self: *NsSelector,
        zone: dns.Name,
        servers: []const na.Address,
        rtt_cache: ?*RttCache,
        order_buf: *[max_order]usize,
    ) []const usize {
        const zh = zoneHash(zone);

        var live_count: usize = 0;
        var samples: [max_order]f32 = undefined;
        const now_ms = if (rtt_cache) |rc| rc.nowMs() else 0;

        // Per-arm shard locks: N acquisitions per call, each uncontended in
        // the common case. Discount + read are fused in one locked region.
        for (servers, 0..) |server, i| {
            const addr_key = AddressKey.fromAddress(server);
            if (rtt_cache) |rc| if (rc.isDead(addr_key, now_ms)) continue;

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

        sortByScoreDesc(order_buf[0..live_count], samples[0..live_count]);
        return order_buf[0..live_count];
    }

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

test "reward mapping" {
    try testing.expectEqual(@as(f32, 0.0), reward(.timeout, 0));
    try testing.expectEqual(@as(f32, 0.0), reward(.validation_failure, 100_000));
    try testing.expectEqual(@as(f32, 0.1), reward(.server_error, 50_000));
    try testing.expectEqual(@as(f32, 1.0), reward(.success, 0));
    try testing.expectEqual(@as(f32, 0.5), reward(.success, 1_000_000));
    try testing.expectEqual(@as(f32, 0.75), reward(.success, 500_000));
}

test "latency factor" {
    try testing.expectEqual(@as(f32, 1.0), latencyFactor(0));
    try testing.expectEqual(@as(f32, 0.75), latencyFactor(500_000));
    try testing.expectEqual(@as(f32, 0.5), latencyFactor(1_000_000));
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

test "ArmKeyContext: 16-shard distribution in both halves" {
    // Both halves carry a consumer: shardIndex subsets the top, ArmMap probes
    // the bottom. Pin both so a tweak that kills either single-shards loudly.
    // Axis 0: sequential addresses, one zone. Axis 1: sequential zones, one address.
    const zone = zoneHash(dns.Name{ .labels = &.{ "example", "com" } });
    const addr_key = AddressKey.fromAddress(na.initIp4(.{ 192, 0, 2, 1 }, 53));
    for (0..2) |axis| {
        var hi: [16]u32 = @splat(0);
        var lo: [16]u32 = @splat(0);
        for (0..4096) |n| {
            const k: ArmKey = if (axis == 0) .{
                .zone_hash = zone,
                .addr_key = AddressKey.fromAddress(na.initIp4(.{
                    @intCast((n >> 16) & 0xff), @intCast((n >> 8) & 0xff), @intCast(n & 0xff), 1,
                }, 53)),
            } else .{ .zone_hash = @intCast(n), .addr_key = addr_key };
            const h = ArmKeyContext.hash(.{}, k);
            hi[shardIndex(h)] += 1;
            lo[@as(u32, @truncate(h)) & shard_mask] += 1;
        }
        // Uniform expectation 256/bucket; ±60%-class bounds, as net_address's sibling.
        for (hi) |c| try testing.expect(c >= 100 and c <= 700);
        for (lo) |c| try testing.expect(c >= 100 and c <= 700);
    }
}

test "beta sample in range" {
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

    for (0..50) |_| {
        sel.recordOutcome(zone, servers[0], .timeout, 0);
        sel.recordOutcome(zone, servers[1], .success, 10_000);
    }

    var server1_first: usize = 0;
    var order_buf: [max_order]usize = undefined;
    for (0..100) |_| {
        const order = sel.selectServers(zone, &servers, null, &order_buf);
        if (order.len > 0 and order[0] == 1) server1_first += 1;
    }
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
        if (order.len > 0 and order[0] == 0) server0_first += 1;
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
        if (oa.len > 0 and oa[0] == 0) a0_first += 1;
        const ob = sel.selectServers(zone_b, &servers, null, &order_buf);
        if (ob.len > 0 and ob[0] == 1) b1_first += 1;
    }
    try testing.expect(a0_first > 90);
    try testing.expect(b1_first > 90);
}
