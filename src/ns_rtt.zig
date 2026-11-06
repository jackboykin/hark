//! Each server's round-trip estimate, and what it decides: the timeout and
//! hedge stagger an exchange gets, the wait a send to it draws, and when a
//! silent server counts as dead.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const AddressKey = @import("net_address.zig").AddressKey;

const initial_timeout_ms: u32 = 400;

/// RFC 6298's first RTO, R + 4 * R/2, with the initial timeout as R.
const silent_base_ms: u32 = 3 * initial_timeout_ms;

/// At 50 a two-round-trip exchange to a 20 ms server timed out once in ~400.
const min_timeout_ms: u32 = 100;
const min_stagger_ms: u32 = 50;

pub const Transport = enum {
    udp,
    tcp,

    /// Handshake included.
    pub fn coldRtts(t: Transport) u32 {
        return switch (t) {
            .udp => 1,
            .tcp => 2,
        };
    }
};

const max_timeout_ms: u32 = 10_000;

const dead_threshold: u8 = 4;

const dead_duration_ms: i64 = 2_000;
const dead_max_shifts: u8 = 4;

const dead_probe_timeout_ms: u32 = 2_000;

const max_backoff_shifts: u8 = 8;

/// Every glue address is attacker-chosen.
pub const max_entries: u32 = 4_096;

/// Roughly p95 of a well-behaved RTT distribution (Dean–Barroso, "The Tail at Scale").
const hedge_multiplier: u32 = 3;

const hedge_decay_ms: i64 = 30_000;

const max_hedge_stagger_ms: u32 = 300;

/// srtt averages about 15 samples at its gain of 1/8, so it is unsure by
/// their spread over √15, about 4.
const sure_divisor = 4;

const forget_ms: i64 = 10 * std.time.ms_per_min;

const loss_one: u16 = 1 << 15;

/// Near standard normal from 64 random bits: four 16-bit uniforms summed,
/// centred and scaled to unit variance.
pub fn normal(bits: u64) f64 {
    var sum: u64 = 0;
    inline for (0..4) |k| sum += bits >> (16 * k) & 0xffff;
    return (@as(f64, @floatFromInt(sum)) - 2 * 65535.0) * (@sqrt(3.0) / 65536.0);
}

/// In the order servers are asked.
pub const Track = enum {
    timed,
    untimed,
    silent,
    dead,

    pub fn mayAnswer(t: Track) bool {
        return switch (t) {
            .timed, .untimed => true,
            .silent, .dead => false,
        };
    }
};

/// RFC 1035 §4.2.1 ≥2 s.
const failover_timeout_cap_ms: u32 = 2000;

/// Round trips in µs fit 32 bits: no reply outlives its deadline.
pub const RttState = struct {
    srtt_us: u32 = 0,
    rttvar_us: u32 = 0,
    consecutive_timeouts: u8 = 0,
    dead_until_ms: i64 = 0,
    min_rtt_us: u32 = 0,
    min_rtt_stamp_ms: i64 = 0,
    heard_ms: i64 = 0,
    loss: u16 = 0,

    pub const unknown: RttState = .{};

    /// Any reply, whatever its rcode.
    pub fn observe(s: *RttState, rtt_us: i64, now_ms: i64) void {
        const rtt: u32 = @intCast(std.math.clamp(rtt_us, 1, std.math.maxInt(u32)));
        if (s.min_rtt_us == 0) {
            s.srtt_us = rtt;
            s.rttvar_us = rtt / 2;
            s.loss = 0;
        } else {
            // RFC 6298
            const delta = @max(s.srtt_us, rtt) - @min(s.srtt_us, rtt);
            s.rttvar_us = 3 * (s.rttvar_us / 4) + delta / 4;
            s.srtt_us = 7 * (s.srtt_us / 8) + rtt / 8;
            s.loss -= s.loss / 8;
        }
        s.heard_ms = now_ms;
        // Re-anchoring lets the floor follow a route change upward.
        if (s.min_rtt_us == 0 or rtt < s.min_rtt_us or now_ms - s.min_rtt_stamp_ms > hedge_decay_ms) {
            s.min_rtt_us = rtt;
            s.min_rtt_stamp_ms = now_ms;
        }
        s.consecutive_timeouts = 0;
        s.dead_until_ms = 0;
    }

    pub fn observeTimeout(s: *RttState, now_ms: i64) void {
        if (s.consecutive_timeouts < 255) s.consecutive_timeouts += 1;
        s.loss += (loss_one - s.loss) / 8;
        if (s.consecutive_timeouts < dead_threshold) return;
        s.dead_until_ms = @max(s.dead_until_ms, now_ms + s.deadWindowMs());
    }

    pub fn sent(s: *RttState, due_ms: i64) void {
        if (s.consecutive_timeouts >= dead_threshold) s.dead_until_ms = @max(s.dead_until_ms, due_ms);
    }

    pub fn isDead(s: RttState, now_ms: i64) bool {
        return s.consecutive_timeouts >= dead_threshold and s.dead_until_ms > now_ms;
    }

    pub fn track(s: RttState, now_ms: i64) Track {
        if (s.isDead(now_ms)) return .dead;
        if (s.min_rtt_us == 0) return if (s.consecutive_timeouts == 0) .untimed else .silent;
        return .timed;
    }

    /// One draw, in µs, from a standard normal `z`.
    pub fn wait(s: RttState, now_ms: i64, rounds: u32, hold_ms: u32, z: f64) u64 {
        const srtt: f64 = @floatFromInt(s.srtt_us);
        const sure = @as(f64, @floatFromInt(s.rttvar_us)) / sure_divisor;
        const unheard: f64 = @floatFromInt(@max(0, now_ms - s.heard_ms));
        const width = @sqrt(sure * sure + srtt * srtt * unheard * (1.0 / @as(f64, forget_ms)));
        const rtt = @max(1, srtt + z * width);
        const lost = @as(f64, @floatFromInt(s.loss)) / loss_one * @as(f64, @floatFromInt(hold_ms)) * std.time.us_per_ms;
        return @intFromFloat(@as(f64, @floatFromInt(rounds)) * rtt + lost);
    }

    pub fn timeout(s: RttState, is_last: bool, rounds: u32) u32 {
        const base = s.rto();
        const want = if (is_last) base else @min(base, failover_timeout_cap_ms);
        return want * rounds;
    }

    pub fn hedgeStagger(s: RttState) ?u32 {
        if (s.min_rtt_us == 0) return null;
        const stagger_ms: u32 = @intCast(@max(1, @divTrunc(@as(i64, hedge_multiplier) * s.min_rtt_us, 1000)));
        return @max(min_stagger_ms, @min(stagger_ms, max_hedge_stagger_ms));
    }

    fn rto(s: RttState) u32 {
        if (s.min_rtt_us == 0 and s.consecutive_timeouts == 0) return initial_timeout_ms;
        const base_ms = if (s.min_rtt_us == 0) silent_base_ms else s.estimateMs();

        const shift: u5 = @intCast(@min(s.consecutive_timeouts, max_backoff_shifts));
        const backed_off = @as(u64, base_ms) << shift;

        const cap = if (s.consecutive_timeouts >= dead_threshold) dead_probe_timeout_ms else max_timeout_ms;
        return @intCast(@max(min_timeout_ms, @min(backed_off, cap)));
    }

    /// RFC 6298, but never under 2× srtt: steady RTTs drive rttvar to 0 and
    /// then any jitter times out.
    fn estimateMs(s: RttState) u32 {
        const srtt: i64 = s.srtt_us;
        const base_us = @max(srtt + 4 * @as(i64, s.rttvar_us), 2 * srtt);
        return @intCast(@max(1, @divTrunc(base_us, 1000)));
    }

    fn deadWindowMs(s: RttState) i64 {
        const shift: u5 = @intCast(@min(s.consecutive_timeouts - dead_threshold, dead_max_shifts));
        return dead_duration_ms << shift;
    }
};

pub const Table = ServerTable(RttState);

/// What hark holds per server, in a table sized once: `ways` slots a set, the
/// set the address's seeded hash picks. A newcomer takes an empty slot in
/// its set, else the one written longest ago, so a flood of glue addresses
/// displaces its own estimates before those in use, and nothing allocates
/// or leaves a tombstone after init.
pub fn ServerTable(comptime State: type) type {
    return struct {
        /// A slot's hash, high bit set; zero is empty.
        tags: [slots]u32,
        keys: [slots]AddressKey,
        written_ms: [slots]i64,
        states: [slots]State,

        const Self = @This();

        const ways = 8;
        const slots = max_entries;
        const sets = slots / ways;

        /// Only the tags are written, so a slot's page stays untouched until
        /// a server lands in it.
        pub fn create(gpa: Allocator) !*Self {
            const t = try gpa.create(Self);
            t.tags = @splat(0);
            return t;
        }

        fn slot(key: AddressKey) struct { set: usize, tag: u32 } {
            const h = AddressKey.HashCtx.hash(.{}, key);
            return .{ .set = @as(usize, @intCast(h % sets)) * ways, .tag = @as(u32, @truncate(h >> 32)) | 1 << 31 };
        }

        fn find(t: *const Self, set: usize, tag: u32, key: AddressKey) ?usize {
            for (set..set + ways) |i| if (t.tags[i] == tag and t.keys[i].eql(key)) return i;
            return null;
        }

        pub fn get(t: *Self, key: AddressKey) ?*State {
            const at = slot(key);
            return &t.states[t.find(at.set, at.tag, key) orelse return null];
        }

        /// The state to write for `key`, made unknown if it had none.
        pub fn write(t: *Self, key: AddressKey, now_ms: i64) *State {
            const at = slot(key);
            const i = t.find(at.set, at.tag, key) orelse claim: {
                var oldest = at.set;
                for (at.set..at.set + ways) |i| {
                    if (t.tags[i] == 0) break :claim t.claim(i, at.tag, key);
                    if (t.written_ms[i] < t.written_ms[oldest]) oldest = i;
                }
                break :claim t.claim(oldest, at.tag, key);
            };
            t.written_ms[i] = now_ms;
            return &t.states[i];
        }

        fn claim(t: *Self, i: usize, tag: u32, key: AddressKey) usize {
            t.tags[i] = tag;
            t.keys[i] = key;
            t.states[i] = .unknown;
            return i;
        }
    };
}

test "a newcomer to a full set takes the slot written longest ago" {
    const na = @import("net_address.zig");
    const t = try Table.create(testing.allocator);
    defer testing.allocator.destroy(t);
    var same: [Table.ways + 1]AddressKey = undefined;
    const set = Table.slot(.fromAddress(na.initIp4(.{ 192, 0, 2, 1 }, 0))).set;
    var n: usize = 0;
    var port: u16 = 1;
    while (n < same.len) : (port += 1) {
        const k: AddressKey = .fromAddress(na.initIp4(.{ 192, 0, 2, 1 }, port));
        if (Table.slot(k).set != set) continue;
        same[n] = k;
        n += 1;
    }
    for (same[0..Table.ways], 0..) |k, i| t.write(k, @intCast(i)).observe(1000, 0);
    _ = t.write(same[0], Table.ways);
    try testing.expectEqual(RttState.unknown, t.write(same[Table.ways], Table.ways + 1).*);
    try testing.expectEqual(null, t.get(same[1]));
    for (same[0..Table.ways], 0..) |k, i| if (i != 1) try testing.expectEqual(1000, t.get(k).?.srtt_us);
}

test "a reply ranks above no history, and no history above silence" {
    var slow: RttState = .unknown;
    slow.observe(900_000, 1000);
    var silent: RttState = .unknown;
    silent.observeTimeout(1000);
    var dead = slow;
    for (0..dead_threshold) |_| dead.observeTimeout(1000);
    const untimed: RttState = .unknown;
    try testing.expectEqual(.timed, slow.track(1000));
    try testing.expectEqual(.untimed, untimed.track(1000));
    try testing.expectEqual(.silent, silent.track(1000));
    try testing.expectEqual(.dead, dead.track(1000));
    var lossy = slow;
    lossy.observeTimeout(1000);
    try testing.expectEqual(.timed, lossy.track(1000));
}

test "a drawn wait counts its round trips and losses, and widens unheard" {
    var s: RttState = .unknown;
    for (0..20) |_| s.observe(20_000, 1000);
    try testing.expectEqual(60_000, s.wait(1000, 3, 100, 0));
    var lossy = s;
    lossy.observeTimeout(1000);
    try testing.expect(lossy.wait(1000, 1, 100, 0) > s.wait(1000, 1, 100, 0));
    try testing.expect(s.wait(1000 + forget_ms, 1, 100, -1) < s.wait(1000, 1, 100, -1));
}

test "a server's first reply sets its estimate, whatever timeouts came before" {
    var clean: RttState = .unknown;
    clean.observe(20_000, 1000);
    for (1..dead_threshold + 1) |timeouts| {
        var lost: RttState = .unknown;
        for (0..timeouts) |_| lost.observeTimeout(1000);
        lost.observe(20_000, 1000);
        try testing.expectEqual(clean, lost);
    }
}

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
    const rto_clean = s.timeout(true, 1);
    const hedge = s.hedgeStagger();
    for (0..dead_threshold) |_| s.observeTimeout(1000);
    try testing.expect(s.timeout(true, 1) > rto_clean);
    try testing.expectEqual(hedge, s.hedgeStagger());
}

test "the threshold timeout marks dead; the window lapses to one probe and escalates to a cap" {
    var s: RttState = .unknown;
    s.observe(100_000, 1000);
    for (0..dead_threshold - 1) |_| s.observeTimeout(1000);
    try testing.expect(!s.isDead(1000));
    s.observeTimeout(1000);
    try testing.expect(s.isDead(1000));
    try testing.expectEqual(dead_probe_timeout_ms, s.timeout(true, 1));
    try testing.expect(!s.isDead(1000 + dead_duration_ms));
    s.sent(9001);
    try testing.expect(s.isDead(9000));
    try testing.expect(!s.isDead(9001));
    for (0..dead_max_shifts + 3) |_| s.observeTimeout(1000);
    try testing.expectEqual(dead_duration_ms << dead_max_shifts, s.deadWindowMs());
    s.observe(100_000, 1000);
    try testing.expect(!s.isDead(1000));
}

test "only the last server's wait runs past the failover cap" {
    var s: RttState = .unknown;
    for (0..8) |_| s.observe(150_000, 1000);
    for (0..3) |_| s.observeTimeout(1000);
    try testing.expect(s.timeout(true, 1) > failover_timeout_cap_ms);
    try testing.expectEqual(failover_timeout_cap_ms, s.timeout(false, 1));
}
