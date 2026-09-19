const std = @import("std");
const testing = std.testing;

/// Initial timeout for unknown servers (Unbound 376, Knot 400).
const initial_timeout_ms: u32 = 400;

/// Minimum RTO floor. With the rttvar floor (srtt/4) guaranteeing
/// jitter headroom, this only catches degenerate sub-millisecond RTTs.
/// Per round trip; a cold exchange gets one per `Transport.coldRtts`. At
/// 50 a two-round-trip exchange to a 20 ms server timed out once in ~400.
const min_timeout_ms: u32 = 100;
const min_stagger_ms: u32 = 50;

/// How a query reaches a server. The estimate is the exchange leg on an
/// established path, the same quantity on every transport; a cold
/// exchange first pays the handshake.
pub const Transport = enum {
    udp,
    tcp,
    dot,

    /// Round trips a cold exchange costs, handshake included.
    pub fn coldRtts(t: Transport) u32 {
        return switch (t) {
            .udp => 1,
            .tcp => 2,
            .dot => 3,
        };
    }
};

/// Maximum RTO cap (Knot).
const max_timeout_ms: u32 = 10_000;

/// Consecutive timeouts before marking dead (Knot).
const dead_threshold: u8 = 4;

/// Not shorter than `dead_probe_timeout_ms`, so probes never overlap.
const dead_duration_ms: i64 = 2_000;
const dead_max_shifts: u8 = 4;

/// Knot KR_CONN_RTT_MAX.
const dead_probe_timeout_ms: u32 = 2_000;

/// Maximum backoff doublings (Knot: cap at 256x initial).
const max_backoff_shifts: u8 = 8;

/// Servers tracked at once; past it an arbitrary one is forgotten and
/// reverts to `initial_timeout_ms`. Every glue address is attacker-chosen.
pub const max_entries: u32 = 4_096;

/// Hedge stagger = `hedge_multiplier × min_rtt`. 3× lands roughly at p95 for
/// well-behaved RTT distributions (Dean–Barroso "Tail at Scale", CACM 2013).
const hedge_multiplier: u32 = 3;

/// Re-anchor min_rtt after this long without a new minimum — lets the floor
/// track upward on route changes that move the path's true floor.
const hedge_decay_ms: i64 = 30_000;

const max_hedge_stagger_ms: u32 = 300;

/// Non-last server cap (Knot KR_CONN_RTT_MAX, RFC 1035 §4.2.1 ≥2 s).
const failover_timeout_cap_ms: u32 = 2000;

/// One server's estimate.
pub const RttState = struct {
    /// 0 until the first observation.
    srtt_us: i64 = 0,
    rttvar_us: i64 = 0,
    consecutive_timeouts: u8 = 0,
    dead_until_ms: i64 = 0,
    /// Windowed minimum; 0 until a reply.
    min_rtt_us: i64 = 0,
    min_rtt_stamp_ms: i64 = 0,

    pub const unknown: RttState = .{};

    /// A reply after `rtt_us`, whatever its rcode.
    pub fn observe(s: *RttState, rtt_us: i64, now_ms: i64) void {
        const rtt = @max(rtt_us, 1);
        if (s.srtt_us == 0) {
            s.srtt_us = rtt;
            s.rttvar_us = @divTrunc(rtt, 2);
        } else {
            // RFC 6298 EWMA update
            const delta: i64 = @intCast(@abs(s.srtt_us - rtt));
            s.rttvar_us = 3 * @divTrunc(s.rttvar_us, 4) + @divTrunc(delta, 4);
            s.srtt_us = 7 * @divTrunc(s.srtt_us, 8) + @divTrunc(rtt, 8);
        }
        // Re-anchoring lets the floor follow a route change upward.
        if (s.min_rtt_us == 0 or rtt < s.min_rtt_us or now_ms - s.min_rtt_stamp_ms > hedge_decay_ms) {
            s.min_rtt_us = rtt;
            s.min_rtt_stamp_ms = now_ms;
        }
        s.consecutive_timeouts = 0;
        s.dead_until_ms = 0;
    }

    /// True on the timeout that marks the server dead.
    pub fn observeTimeout(s: *RttState, now_ms: i64) bool {
        if (s.srtt_us == 0) {
            s.srtt_us = @as(i64, initial_timeout_ms) * 1000;
            s.rttvar_us = @as(i64, initial_timeout_ms) * 500;
        }
        if (s.consecutive_timeouts < 255) s.consecutive_timeouts += 1;
        if (s.consecutive_timeouts < dead_threshold) return false;
        s.dead_until_ms = now_ms + s.deadWindowMs();
        return s.consecutive_timeouts == dead_threshold;
    }

    pub fn isDead(s: RttState, now_ms: i64) bool {
        return s.consecutive_timeouts >= dead_threshold and s.dead_until_ms > now_ms;
    }

    /// What a cold exchange over `transport` needs. A non-last server is
    /// capped so a walk can still fail over.
    pub fn timeout(s: RttState, is_last: bool, transport: Transport) u32 {
        const base = s.rto();
        const want = if (is_last) base else @min(base, failover_timeout_cap_ms);
        return want * transport.coldRtts();
    }

    /// Null until a reply.
    pub fn hedgeStagger(s: RttState) ?u32 {
        if (s.min_rtt_us <= 0) return null;
        const stagger_ms: u32 = @intCast(@max(1, @divTrunc(@as(i64, hedge_multiplier) * s.min_rtt_us, 1000)));
        return @max(min_stagger_ms, @min(stagger_ms, max_hedge_stagger_ms));
    }

    fn rto(s: RttState) u32 {
        if (s.srtt_us == 0) return initial_timeout_ms;
        // RTO = srtt + 4 * rttvar (RFC 6298), but never tighter than 2× the
        // smoothed RTT. Without this floor, consistent RTTs drive rttvar → 0
        // and the timeout converges to exactly the RTT — any jitter causes
        // a timeout that cascades into repeated failures.
        const base_us = @max(s.srtt_us + 4 * s.rttvar_us, 2 * s.srtt_us);
        const base_ms: u32 = @intCast(@max(1, @divTrunc(base_us, 1000)));

        const shift: u5 = @intCast(@min(s.consecutive_timeouts, max_backoff_shifts));
        const backed_off = @as(u64, base_ms) << shift;

        const cap = if (s.consecutive_timeouts >= dead_threshold) dead_probe_timeout_ms else max_timeout_ms;
        return @intCast(@max(min_timeout_ms, @min(backed_off, cap)));
    }

    fn deadWindowMs(s: RttState) i64 {
        const shift: u5 = @intCast(@min(s.consecutive_timeouts - dead_threshold, dead_max_shifts));
        return dead_duration_ms << shift;
    }
};

test "hedge stagger is 3x min_rtt clamped to [50, 300]" {
    var s: RttState = .unknown;
    for ([_]i64{ 80_000, 60_000, 90_000 }) |rtt| s.observe(rtt, 1000);
    try testing.expectEqual(@as(u32, 180), s.hedgeStagger());
    var low: RttState = .unknown;
    low.observe(5_000, 1000);
    try testing.expectEqual(@as(u32, 50), low.hedgeStagger());
    var high: RttState = .unknown;
    high.observe(200_000, 1000);
    try testing.expectEqual(@as(u32, 300), high.hedgeStagger());
}

test "min_rtt re-anchors after hedge_decay_ms" {
    var s: RttState = .unknown;
    s.observe(20_000, 1000);
    try testing.expectEqual(@as(u32, 60), s.hedgeStagger());
    s.observe(100_000, 1000 + hedge_decay_ms - 1);
    try testing.expectEqual(@as(u32, 60), s.hedgeStagger());
    s.observe(100_000, 1000 + hedge_decay_ms + 1);
    try testing.expectEqual(@as(u32, 300), s.hedgeStagger());
}

test "timeouts inflate the RTO but leave the hedge stagger" {
    var s: RttState = .unknown;
    s.observe(20_000, 1000);
    const rto_clean = s.timeout(true, .udp);
    const hedge = s.hedgeStagger();
    for (0..dead_threshold) |_| _ = s.observeTimeout(1000);
    try testing.expect(s.timeout(true, .udp) > rto_clean);
    try testing.expectEqual(hedge, s.hedgeStagger());
}

test "the threshold timeout marks dead; the window lapses and escalates to a cap" {
    var s: RttState = .unknown;
    s.observe(100_000, 1000);
    for (0..dead_threshold - 1) |_| try testing.expect(!s.observeTimeout(1000));
    try testing.expect(s.observeTimeout(1000));
    try testing.expect(s.isDead(1000));
    try testing.expectEqual(dead_probe_timeout_ms, s.timeout(true, .udp));
    try testing.expect(!s.isDead(1000 + dead_duration_ms));
    for (0..dead_max_shifts + 3) |_| try testing.expect(!s.observeTimeout(1000));
    try testing.expectEqual(dead_duration_ms << dead_max_shifts, s.deadWindowMs());
    s.observe(100_000, 1000);
    try testing.expect(!s.isDead(1000));
}

test "a cold exchange costs the transport's round trips of the estimate" {
    var s: RttState = .unknown;
    try testing.expectEqual(initial_timeout_ms * 2, s.timeout(true, .tcp));
    for (0..8) |_| s.observe(150_000, 1000);
    const udp = s.timeout(true, .udp);
    try testing.expect(udp > min_timeout_ms);
    try testing.expectEqual(udp * 2, s.timeout(true, .tcp));
    try testing.expectEqual(udp * 3, s.timeout(true, .dot));
    // The failover cap bounds one round trip; the cold total is above it.
    for (0..3) |_| _ = s.observeTimeout(1000);
    try testing.expect(s.timeout(true, .udp) > failover_timeout_cap_ms);
    try testing.expectEqual(failover_timeout_cap_ms * 2, s.timeout(false, .tcp));
}
