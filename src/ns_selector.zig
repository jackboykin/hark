const std = @import("std");
const mem = std.mem;
const math = std.math;
const testing = std.testing;
const Allocator = mem.Allocator;
const AddressKey = @import("connection_pool.zig").AddressKey;
const RttCache = @import("ns_rtt.zig").RttCache;
const dns = @import("dns.zig");
const rand = @import("rand.zig");
const na = @import("net_address.zig");

// ── Constants ────────────────────────────────────────────────────────

/// Discount factor: γ = 0.995 → half-life ≈ 138 observations.
const default_gamma: f32 = 0.995;

/// Prior parameters: Beta(1,1) = uniform/uninformative.
const alpha_prior: f32 = 1.0;
const beta_prior: f32 = 1.0;

/// Max NS per zone (13 IPv4 + 13 IPv6).
pub const max_order = 26;

// ── Outcome ──────────────────────────────────────────────────────────

pub const Outcome = enum {
    /// Valid answer received (may be referral, NODATA, NXDOMAIN — all are
    /// legitimate authoritative behaviour).
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

const ArmState = struct {
    alpha: f32 = alpha_prior,
    beta: f32 = beta_prior,
};

// ── NsSelector ───────────────────────────────────────────────────────

pub const NsSelector = struct {
    arms: std.AutoHashMap(ArmKey, ArmState),
    mutex: ?std.Io.Mutex,
    io: std.Io = undefined,
    gamma: f32,

    pub fn init(allocator: Allocator, io: std.Io) NsSelector {
        return .{
            .arms = std.AutoHashMap(ArmKey, ArmState).init(allocator),
            .mutex = null,
            .io = io,
            .gamma = default_gamma,
        };
    }

    pub fn initThreadSafe(allocator: Allocator, io: std.Io) NsSelector {
        return .{
            .arms = std.AutoHashMap(ArmKey, ArmState).init(allocator),
            .mutex = std.Io.Mutex.init,
            .io = io,
            .gamma = default_gamma,
        };
    }

    pub fn deinit(self: *NsSelector) void {
        self.arms.deinit();
    }

    /// Select servers using Thompson Sampling. Returns ordered indices
    /// into `servers`: best Thompson draw first, dead servers last.
    /// RttCache is still consulted for dead-server status.
    pub fn selectServers(
        self: *NsSelector,
        zone: dns.Name,
        servers: []const na.Address,
        rtt_cache: ?*RttCache,
        order_buf: *[max_order]usize,
    ) []usize {
        if (self.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (self.mutex) |*mtx| mtx.unlock(self.io);

        const zh = zoneHash(zone);

        // Discount all arms for this zone (lazy: only on selection).
        self.discountZone(zh, servers);

        var live_count: usize = 0;
        var dead_count: usize = 0;
        var samples: [max_order]f32 = undefined;

        for (servers, 0..) |server, i| {
            const addr_key = AddressKey.fromAddress(server);

            // Check dead status via RttCache (hard failure override).
            const is_dead = if (rtt_cache) |rc| rc.isDead(addr_key) else false;
            if (is_dead) {
                order_buf[max_order - 1 - dead_count] = i;
                dead_count += 1;
                continue;
            }

            const arm_key = ArmKey{ .zone_hash = zh, .addr_key = addr_key };
            const state = self.arms.get(arm_key) orelse ArmState{};

            order_buf[live_count] = i;
            samples[live_count] = betaSample(self.io, state.alpha, state.beta);
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
            rand.shuffle(usize, self.io, dead_buf[0..dead_count]);
            @memcpy(order_buf[live_count..][0..dead_count], dead_buf[0..dead_count]);
        }

        return order_buf[0 .. live_count + dead_count];
    }

    /// Record the outcome of querying a nameserver.
    pub fn recordOutcome(
        self: *NsSelector,
        zone: dns.Name,
        server: na.Address,
        outcome: Outcome,
        elapsed_us: i64,
    ) void {
        if (self.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (self.mutex) |*mtx| mtx.unlock(self.io);

        const arm_key = ArmKey{
            .zone_hash = zoneHash(zone),
            .addr_key = AddressKey.fromAddress(server),
        };
        const r = reward(outcome, elapsed_us);

        const gop = self.arms.getOrPut(arm_key) catch return;
        if (!gop.found_existing) gop.value_ptr.* = ArmState{};
        gop.value_ptr.alpha += r;
        gop.value_ptr.beta += (1.0 - r);
    }

    /// Return the confidence score (Beta mean) for a server in a zone.
    /// Returns null if no observations exist.
    pub fn confidence(self: *NsSelector, zone: dns.Name, server: na.Address) ?f32 {
        if (self.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (self.mutex) |*mtx| mtx.unlock(self.io);

        const arm_key = ArmKey{
            .zone_hash = zoneHash(zone),
            .addr_key = AddressKey.fromAddress(server),
        };
        const state = self.arms.get(arm_key) orelse return null;
        return state.alpha / (state.alpha + state.beta);
    }

    // ── Internal ─────────────────────────────────────────────────────

    /// Apply discount γ to all arms matching this zone and server set.
    fn discountZone(self: *NsSelector, zh: u64, servers: []const na.Address) void {
        for (servers) |server| {
            const arm_key = ArmKey{ .zone_hash = zh, .addr_key = AddressKey.fromAddress(server) };
            if (self.arms.getPtr(arm_key)) |state| {
                state.alpha = @max(alpha_prior, state.alpha * self.gamma);
                state.beta = @max(beta_prior, state.beta * self.gamma);
            }
        }
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

        const u = rand.uniformFloat(io);
        // Fast accept (avoids log ~83% of the time)
        if (u < 1.0 - 0.0331 * (x * x) * (x * x)) return d * v;
        // Slow accept
        if (@log(u) < 0.5 * x * x + d * (1.0 - v + @log(v))) return d * v;
    }
}

/// Standard normal via Box-Muller transform.
fn normalSample(io: std.Io) f32 {
    const r1 = rand.uniformFloat(io);
    const r2 = rand.uniformFloat(io);
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

test "beta sample in range" {
    // Draw many samples, all should be in (0, 1)
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const s = betaSample(testing.io, 1.0, 1.0);
        try testing.expect(s >= 0.0 and s <= 1.0);
    }
    // Skewed distribution: alpha >> beta → samples mostly near 1.0
    var sum: f32 = 0;
    i = 0;
    while (i < 1000) : (i += 1) {
        sum += betaSample(testing.io, 100.0, 1.0);
    }
    try testing.expect(sum / 1000.0 > 0.9);
}

test "selectServers basic ordering" {
    var sel = NsSelector.init(testing.allocator, testing.io);
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
        if (order.len > 0 and order[0] == 1) server1_first += 1;
    }
    // Should be first >90% of the time
    try testing.expect(server1_first > 90);
}

test "discount causes re-exploration" {
    var sel = NsSelector.init(testing.allocator, testing.io);
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
        if (order.len > 0 and order[0] == 0) server0_first += 1;
    }
    // After heavy discounting, server 0 should get picked sometimes (re-explored)
    try testing.expect(server0_first > 10);
}

test "recordOutcome updates state" {
    var sel = NsSelector.init(testing.allocator, testing.io);
    defer sel.deinit();

    const zone = dns.Name{ .labels = &.{ "example", "com" } };
    const server = na.initIp4(.{ 10, 0, 0, 1 }, 53);

    sel.recordOutcome(zone, server, .success, 50_000);
    const c = sel.confidence(zone, server).?;
    // After one success at 50ms (reward ≈ 0.975): alpha ≈ 1.975, beta ≈ 1.025
    // confidence ≈ 0.66
    try testing.expect(c > 0.5);
}

test "confidence returns null for unknown" {
    var sel = NsSelector.init(testing.allocator, testing.io);
    defer sel.deinit();

    const zone = dns.Name{ .labels = &.{ "unknown", "com" } };
    const server = na.initIp4(.{ 10, 0, 0, 99 }, 53);
    try testing.expectEqual(@as(?f32, null), sel.confidence(zone, server));
}

test "per-zone isolation" {
    var sel = NsSelector.init(testing.allocator, testing.io);
    defer sel.deinit();

    const zone_a = dns.Name{ .labels = &.{ "a", "com" } };
    const zone_b = dns.Name{ .labels = &.{ "b", "com" } };
    const server = na.initIp4(.{ 10, 0, 0, 1 }, 53);

    // Same server, different zones — independent state
    for (0..20) |_| sel.recordOutcome(zone_a, server, .success, 10_000);
    for (0..20) |_| sel.recordOutcome(zone_b, server, .timeout, 0);

    const ca = sel.confidence(zone_a, server).?;
    const cb = sel.confidence(zone_b, server).?;
    try testing.expect(ca > 0.8);
    try testing.expect(cb < 0.2);
}
