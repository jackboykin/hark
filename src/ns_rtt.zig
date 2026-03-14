const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const AddressKey = @import("connection_pool.zig").AddressKey;

// ── Constants (Unbound/Knot consensus) ───────────────────────────────

/// Initial timeout for unknown servers (Unbound 376, Knot 400).
pub const initial_timeout_ms: u32 = 400;

/// Minimum RTO floor. With the rttvar floor (srtt/4) guaranteeing
/// jitter headroom, this only catches degenerate sub-millisecond RTTs.
const min_timeout_ms: u32 = 50;

/// Maximum RTO cap (Knot).
const max_timeout_ms: u32 = 10_000;

/// RTT band for "equally good" servers (Unbound).
const rtt_band_ms: u32 = 400;

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
    mutex: ?std.Thread.Mutex,
    now_fn: *const fn () i64,

    pub fn init(allocator: Allocator) RttCache {
        return .{
            .entries = std.AutoHashMap(AddressKey, RttState).init(allocator),
            .mutex = null,
            .now_fn = &defaultNowMs,
        };
    }

    pub fn initThreadSafe(allocator: Allocator) RttCache {
        return .{
            .entries = std.AutoHashMap(AddressKey, RttState).init(allocator),
            .mutex = .{},
            .now_fn = &defaultNowMs,
        };
    }

    pub fn deinit(self: *RttCache) void {
        self.entries.deinit();
    }

    /// Return the recommended timeout in ms for this server.
    pub fn getTimeout(self: *RttCache, key: AddressKey) u32 {
        if (self.mutex) |*mtx| mtx.lock();
        defer if (self.mutex) |*mtx| mtx.unlock();

        const state = self.entries.get(key) orelse return initial_timeout_ms;
        return computeTimeout(state);
    }

    /// Record a successful response with measured RTT (microseconds).
    pub fn recordSuccess(self: *RttCache, key: AddressKey, rtt_us: i64) void {
        if (self.mutex) |*mtx| mtx.lock();
        defer if (self.mutex) |*mtx| mtx.unlock();

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
        if (self.mutex) |*mtx| mtx.lock();
        defer if (self.mutex) |*mtx| mtx.unlock();

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
        if (self.mutex) |*mtx| mtx.lock();
        defer if (self.mutex) |*mtx| mtx.unlock();

        const state = self.entries.get(key) orelse return false;
        return state.dead_until_ms > self.now_fn();
    }

    /// Unbound-style RTT-band selection: find best RTT, randomly pick
    /// among servers within best + rtt_band_ms, dead servers last.
    /// Returns a slice of `order_buf` containing indices into `servers`.
    pub fn selectServers(
        self: *RttCache,
        servers: []const std.net.Address,
        order_buf: *[max_order]usize,
    ) []usize {
        if (self.mutex) |*mtx| mtx.lock();
        defer if (self.mutex) |*mtx| mtx.unlock();

        const now = self.now_fn();
        var live_count: usize = 0;
        var dead_count: usize = 0;
        var best_timeout: u32 = std.math.maxInt(u32);

        // Partition: live servers first, dead servers at the end
        for (servers, 0..) |server, i| {
            const key = AddressKey.fromAddress(server);
            const state = self.entries.get(key);
            const is_dead = if (state) |s| s.dead_until_ms > now else false;

            if (is_dead) {
                order_buf[max_order - 1 - dead_count] = i;
                dead_count += 1;
            } else {
                order_buf[live_count] = i;
                live_count += 1;
                const t = if (state) |s| computeTimeout(s) else initial_timeout_ms;
                if (t < best_timeout) best_timeout = t;
            }
        }

        // Shuffle live servers within the RTT band to the front
        // (Fisher-Yates on the "good" subset, then append "worse" live, then dead)
        const band_limit = best_timeout +| rtt_band_ms;
        var good_count: usize = 0;

        // Classify live servers as "good" (within band) or "worse"
        for (0..live_count) |j| {
            const idx = order_buf[j];
            const key = AddressKey.fromAddress(servers[idx]);
            const state = self.entries.get(key);
            const t = if (state) |s| computeTimeout(s) else initial_timeout_ms;
            if (t <= band_limit) {
                // Swap into the good partition
                const tmp = order_buf[good_count];
                order_buf[good_count] = order_buf[j];
                order_buf[j] = tmp;
                good_count += 1;
            }
        }

        // Shuffle the "good" set
        fisherYatesShuffle(order_buf[0..good_count]);

        // Shuffle the dead servers too (avoid always hitting the same one first)
        if (dead_count > 0) {
            // Copy dead indices from the end into contiguous positions after live
            var dead_buf: [max_order]usize = undefined;
            for (0..dead_count) |d| {
                dead_buf[d] = order_buf[max_order - 1 - d];
            }
            fisherYatesShuffle(dead_buf[0..dead_count]);
            @memcpy(order_buf[live_count..][0..dead_count], dead_buf[0..dead_count]);
        }

        return order_buf[0 .. live_count + dead_count];
    }

    const max_order = 26; // max_servers_per_level (13 IPv4 + 13 IPv6)
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

fn fisherYatesShuffle(items: []usize) void {
    if (items.len <= 1) return;
    var i: usize = items.len - 1;
    while (i > 0) : (i -= 1) {
        const j = std.crypto.random.uintLessThan(usize, i + 1);
        const tmp = items[i];
        items[i] = items[j];
        items[j] = tmp;
    }
}

fn defaultNowMs() i64 {
    return std.time.milliTimestamp();
}

// ── Tests ────────────────────────────────────────────────────────────

var test_now_ms: i64 = 1000;

fn testNowMs() i64 {
    return test_now_ms;
}

fn testAddr(last_octet: u8) AddressKey {
    return AddressKey.fromAddress(std.net.Address.initIp4(.{ 10, 0, 0, last_octet }, 53));
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

test "selectServers puts dead servers last" {
    var cache = RttCache.init(testing.allocator);
    defer cache.deinit();
    cache.now_fn = &testNowMs;
    test_now_ms = 1000;

    const servers = [_]std.net.Address{
        std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 53),
        std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 53),
        std.net.Address.initIp4(.{ 10, 0, 0, 3 }, 53),
    };

    const key1 = AddressKey.fromAddress(servers[0]);

    // Make server 1 dead
    cache.recordSuccess(key1, 100_000);
    for (0..dead_threshold) |_| cache.recordTimeout(key1);
    try testing.expect(cache.isDead(key1));

    var order_buf: [RttCache.max_order]usize = undefined;
    const order = cache.selectServers(&servers, &order_buf);

    try testing.expectEqual(@as(usize, 3), order.len);
    // Dead server (index 0) should be last
    try testing.expectEqual(@as(usize, 0), order[order.len - 1]);
}

test "selectServers prefers lower RTT within band" {
    var cache = RttCache.init(testing.allocator);
    defer cache.deinit();
    cache.now_fn = &testNowMs;
    test_now_ms = 1000;

    const servers = [_]std.net.Address{
        std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 53), // slow: 2000ms RTT
        std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 53), // fast: 10ms RTT
    };

    // Record a slow server
    cache.recordSuccess(AddressKey.fromAddress(servers[0]), 2_000_000);
    // Record a fast server
    cache.recordSuccess(AddressKey.fromAddress(servers[1]), 10_000);

    var order_buf: [RttCache.max_order]usize = undefined;
    const order = cache.selectServers(&servers, &order_buf);

    try testing.expectEqual(@as(usize, 2), order.len);
    // Fast server (index 1) should come before slow server (index 0)
    // because slow server is outside the RTT band
    try testing.expectEqual(@as(usize, 1), order[0]);
    try testing.expectEqual(@as(usize, 0), order[1]);
}
