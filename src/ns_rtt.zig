const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const AddressKey = @import("connection_pool.zig").AddressKey;
const na = @import("net_address.zig");

// ── Constants (Unbound/Knot consensus) ───────────────────────────────

/// Initial timeout for unknown servers (Unbound 376, Knot 400).
pub const initial_timeout_ms: u32 = 400;

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

// ── RttState ─────────────────────────────────────────────────────────

const RttState = struct {
    srtt_us: i64, // Smoothed RTT (microseconds)
    rttvar_us: i64, // RTT variance
    consecutive_timeouts: u8,
    dead_until_ms: i64, // Timestamp when dead period ends
};

// ── RttCache ─────────────────────────────────────────────────────────

pub const RttCache = struct {
    entries: std.AutoHashMap(AddressKey, RttState),
    mutex: ?std.Io.Mutex,
    io: std.Io = undefined,
    now_fn: *const fn () i64,

    pub fn init(allocator: Allocator) RttCache {
        return .{
            .entries = std.AutoHashMap(AddressKey, RttState).init(allocator),
            .mutex = null,
            .now_fn = &@import("monotonic.zig").nowMs,
        };
    }

    pub fn initThreadSafe(allocator: Allocator, io: std.Io) RttCache {
        return .{
            .entries = std.AutoHashMap(AddressKey, RttState).init(allocator),
            .mutex = std.Io.Mutex.init,
            .io = io,
            .now_fn = &@import("monotonic.zig").nowMs,
        };
    }

    pub fn deinit(self: *RttCache) void {
        self.entries.deinit();
    }

    /// Return the recommended timeout in ms for this server.
    pub fn getTimeout(self: *RttCache, key: AddressKey) u32 {
        if (self.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (self.mutex) |*mtx| mtx.unlock(self.io);

        const state = self.entries.get(key) orelse return initial_timeout_ms;
        return computeTimeout(state);
    }

    /// Record a successful response with measured RTT (microseconds).
    pub fn recordSuccess(self: *RttCache, key: AddressKey, rtt_us: i64) void {
        if (self.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (self.mutex) |*mtx| mtx.unlock(self.io);

        const gop = self.entries.getOrPut(key) catch return;
        if (!gop.found_existing) {
            // First sample: srtt = R, rttvar = R/2
            gop.value_ptr.* = .{
                .srtt_us = rtt_us,
                .rttvar_us = @divTrunc(rtt_us, 2),
                .consecutive_timeouts = 0,
                .dead_until_ms = 0,
            };
        } else {
            // RFC 6298 EWMA update
            const delta = @as(i64, @intCast(@abs(gop.value_ptr.srtt_us - rtt_us)));
            gop.value_ptr.rttvar_us = 3 * @divTrunc(gop.value_ptr.rttvar_us, 4) + @divTrunc(delta, 4);
            gop.value_ptr.srtt_us = 7 * @divTrunc(gop.value_ptr.srtt_us, 8) + @divTrunc(rtt_us, 8);
            gop.value_ptr.consecutive_timeouts = 0;
            gop.value_ptr.dead_until_ms = 0;
        }
    }

    /// Record a timeout for this server (exponential backoff + dead marking).
    pub fn recordTimeout(self: *RttCache, key: AddressKey) void {
        if (self.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (self.mutex) |*mtx| mtx.unlock(self.io);

        const gop = self.entries.getOrPut(key) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .srtt_us = @as(i64, initial_timeout_ms) * 1000,
                .rttvar_us = @as(i64, initial_timeout_ms) * 500,
                .consecutive_timeouts = 1,
                .dead_until_ms = 0,
            };
        } else {
            if (gop.value_ptr.consecutive_timeouts < 255) {
                gop.value_ptr.consecutive_timeouts += 1;
            }
            if (gop.value_ptr.consecutive_timeouts >= dead_threshold) {
                gop.value_ptr.dead_until_ms = self.now_fn() + dead_duration_ms;
            }
        }
    }

    /// Check whether the server is currently marked dead.
    pub fn isDead(self: *RttCache, key: AddressKey) bool {
        if (self.mutex) |*mtx| mtx.lockUncancelable(self.io);
        defer if (self.mutex) |*mtx| mtx.unlock(self.io);

        const state = self.entries.get(key) orelse return false;
        return state.dead_until_ms > self.now_fn();
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
    var cache = RttCache.init(testing.allocator);
    defer cache.deinit();
    cache.now_fn = &testNowMs;

    try testing.expectEqual(initial_timeout_ms, cache.getTimeout(testAddr(1)));
}

test "recordSuccess updates EWMA" {
    var cache = RttCache.init(testing.allocator);
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

test "recordTimeout increments consecutive count and marks dead" {
    var cache = RttCache.init(testing.allocator);
    defer cache.deinit();
    cache.now_fn = &testNowMs;
    test_now_ms = 1000;

    const key = testAddr(2);

    // Prime with a success
    cache.recordSuccess(key, 100_000);
    try testing.expect(!cache.isDead(key));

    // Timeout 4 times → should be dead
    cache.recordTimeout(key);
    cache.recordTimeout(key);
    cache.recordTimeout(key);
    cache.recordTimeout(key);
    try testing.expect(cache.isDead(key));

    // After dead_duration_ms, should recover
    test_now_ms = 1000 + dead_duration_ms + 1;
    try testing.expect(!cache.isDead(key));
}
