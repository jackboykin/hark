const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const AddressKey = @import("net_address.zig").AddressKey;

const initial_timeout_ms: u32 = 400;

/// At 50 a two-round-trip exchange to a 20 ms server timed out once in ~400.
const min_timeout_ms: u32 = 100;
const min_stagger_ms: u32 = 50;

pub const Transport = enum {
    udp,
    tcp,

    /// Handshake included.
    fn coldRtts(t: Transport) u32 {
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

/// Estimates closer than this are noise.
const band_us: i64 = 50 * std.time.us_per_ms;

/// Past every band a reply reaches: never timed, then timed out and never
/// answered, then dead.
pub const untimed_band = dead_band - 2;
pub const silent_band = dead_band - 1;
pub const dead_band = std.math.maxInt(i64);

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

    pub const unknown: RttState = .{};

    /// Any reply, whatever its rcode.
    pub fn observe(s: *RttState, rtt_us: i64, now_ms: i64) void {
        const rtt: u32 = @intCast(std.math.clamp(rtt_us, 1, std.math.maxInt(u32)));
        if (s.srtt_us == 0) {
            s.srtt_us = rtt;
            s.rttvar_us = rtt / 2;
        } else {
            // RFC 6298
            const delta = @max(s.srtt_us, rtt) - @min(s.srtt_us, rtt);
            s.rttvar_us = 3 * (s.rttvar_us / 4) + delta / 4;
            s.srtt_us = 7 * (s.srtt_us / 8) + rtt / 8;
        }
        // Re-anchoring lets the floor follow a route change upward.
        if (s.min_rtt_us == 0 or rtt < s.min_rtt_us or now_ms - s.min_rtt_stamp_ms > hedge_decay_ms) {
            s.min_rtt_us = rtt;
            s.min_rtt_stamp_ms = now_ms;
        }
        s.consecutive_timeouts = 0;
        s.dead_until_ms = 0;
    }

    pub fn observeTimeout(s: *RttState, now_ms: i64) void {
        if (s.srtt_us == 0) {
            s.srtt_us = initial_timeout_ms * 1000;
            s.rttvar_us = initial_timeout_ms * 500;
        }
        if (s.consecutive_timeouts < 255) s.consecutive_timeouts += 1;
        if (s.consecutive_timeouts < dead_threshold) return;
        s.dead_until_ms = @max(s.dead_until_ms, now_ms + s.deadWindowMs());
    }

    pub fn sent(s: *RttState, due_ms: i64) void {
        if (s.consecutive_timeouts >= dead_threshold) s.dead_until_ms = @max(s.dead_until_ms, due_ms);
    }

    pub fn isDead(s: RttState, now_ms: i64) bool {
        return s.consecutive_timeouts >= dead_threshold and s.dead_until_ms > now_ms;
    }

    /// Lower is asked first. A reply alone places a server by round trip:
    /// the estimate a timeout leaves one that has never answered is how
    /// long to wait for it, not how far it is.
    pub fn band(s: RttState, now_ms: i64) i64 {
        if (s.isDead(now_ms)) return dead_band;
        if (s.min_rtt_us == 0) return if (s.srtt_us == 0) untimed_band else silent_band;
        return @divTrunc(@as(i64, s.srtt_us), band_us);
    }

    pub fn timeout(s: RttState, is_last: bool, transport: Transport) u32 {
        const base = s.rto();
        const want = if (is_last) base else @min(base, failover_timeout_cap_ms);
        return want * transport.coldRtts();
    }

    pub fn hedgeStagger(s: RttState) ?u32 {
        if (s.min_rtt_us == 0) return null;
        const stagger_ms: u32 = @intCast(@max(1, @divTrunc(@as(i64, hedge_multiplier) * s.min_rtt_us, 1000)));
        return @max(min_stagger_ms, @min(stagger_ms, max_hedge_stagger_ms));
    }

    fn rto(s: RttState) u32 {
        if (s.srtt_us == 0) return initial_timeout_ms;
        // RFC 6298, but never under 2× srtt: steady RTTs drive rttvar to 0
        // and then any jitter times out.
        const srtt: i64 = s.srtt_us;
        const base_us = @max(srtt + 4 * @as(i64, s.rttvar_us), 2 * srtt);
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

/// Every server's estimate, in a table sized once: `ways` slots a set, the
/// set the address's seeded hash picks. A newcomer takes an empty slot in
/// its set, else the one written longest ago, so a flood of glue addresses
/// displaces its own estimates before those in use, and nothing allocates
/// or leaves a tombstone after init.
pub const Table = struct {
    /// A slot's hash, high bit set; zero is empty.
    tags: [slots]u32,
    keys: [slots]AddressKey,
    written_ms: [slots]i64,
    states: [slots]RttState,

    const ways = 8;
    const slots = max_entries;
    const sets = slots / ways;

    /// Only the tags are written, so a slot's page stays untouched until
    /// a server lands in it.
    pub fn create(gpa: Allocator) !*Table {
        const t = try gpa.create(Table);
        t.tags = @splat(0);
        return t;
    }

    fn slot(key: AddressKey) struct { set: usize, tag: u32 } {
        const h = AddressKey.HashCtx.hash(.{}, key);
        return .{ .set = @as(usize, @intCast(h % sets)) * ways, .tag = @as(u32, @truncate(h >> 32)) | 1 << 31 };
    }

    fn find(t: *const Table, set: usize, tag: u32, key: AddressKey) ?usize {
        for (set..set + ways) |i| if (t.tags[i] == tag and t.keys[i].eql(key)) return i;
        return null;
    }

    pub fn get(t: *Table, key: AddressKey) ?*RttState {
        const at = slot(key);
        return &t.states[t.find(at.set, at.tag, key) orelse return null];
    }

    /// The estimate to write for `key`, made unknown if it had none.
    pub fn write(t: *Table, key: AddressKey, now_ms: i64) *RttState {
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

    fn claim(t: *Table, i: usize, tag: u32, key: AddressKey) usize {
        t.tags[i] = tag;
        t.keys[i] = key;
        t.states[i] = .unknown;
        return i;
    }
};

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
    try testing.expect(slow.band(1000) < untimed.band(1000));
    try testing.expect(untimed.band(1000) < silent.band(1000));
    try testing.expect(silent.band(1000) < dead.band(1000));
    var lossy = slow;
    lossy.observeTimeout(1000);
    try testing.expectEqual(slow.band(1000), lossy.band(1000));
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
    const rto_clean = s.timeout(true, .udp);
    const hedge = s.hedgeStagger();
    for (0..dead_threshold) |_| s.observeTimeout(1000);
    try testing.expect(s.timeout(true, .udp) > rto_clean);
    try testing.expectEqual(hedge, s.hedgeStagger());
}

test "the threshold timeout marks dead; the window lapses to one probe and escalates to a cap" {
    var s: RttState = .unknown;
    s.observe(100_000, 1000);
    for (0..dead_threshold - 1) |_| s.observeTimeout(1000);
    try testing.expect(!s.isDead(1000));
    s.observeTimeout(1000);
    try testing.expect(s.isDead(1000));
    try testing.expectEqual(dead_probe_timeout_ms, s.timeout(true, .udp));
    try testing.expect(!s.isDead(1000 + dead_duration_ms));
    s.sent(9001);
    try testing.expect(s.isDead(9000));
    try testing.expect(!s.isDead(9001));
    for (0..dead_max_shifts + 3) |_| s.observeTimeout(1000);
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
    for (0..3) |_| s.observeTimeout(1000);
    try testing.expect(s.timeout(true, .udp) > failover_timeout_cap_ms);
    try testing.expectEqual(failover_timeout_cap_ms * 2, s.timeout(false, .tcp));
}
