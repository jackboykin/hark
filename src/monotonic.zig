/// Monotonic time helpers (CLOCK_BOOTTIME). Immune to NTP jumps.
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

fn gettime() ?std.posix.timespec {
    var ts: std.posix.timespec = undefined;
    return if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) == .SUCCESS) ts else null;
}

// Test-clock offset (seconds). Added to every clock read so scenarios can
// `STEP n TIME_PASSES ELAPSE k` and observe TTL expiry without sleeping.
// Production builds compile this out — `testOffsetSec` is a comptime-known
// 0 so the optimizer drops the load entirely.
var test_offset_secs: std.atomic.Value(i64) = std.atomic.Value(i64).init(0);

inline fn testOffsetSec() i64 {
    if (!build_options.testing_enabled) return 0;
    return test_offset_secs.load(.monotonic);
}

/// Advance the synthetic test clock by `secs`. No-op in production builds.
/// Driven from the scenario-control DNS-query intercept (see `server.zig`).
pub fn advanceTestClock(secs: i64) void {
    if (!build_options.testing_enabled) return;
    _ = test_offset_secs.fetchAdd(secs, .monotonic);
}

pub fn nowSec() i64 {
    return (gettime() orelse return 0).sec + testOffsetSec();
}

pub fn nowMs() i64 {
    const ts = gettime() orelse return 0;
    return ts.sec * std.time.ms_per_s + @divTrunc(ts.nsec, std.time.ns_per_ms) + testOffsetSec() * std.time.ms_per_s;
}

pub fn nowUs() i64 {
    const ts = gettime() orelse return 0;
    return ts.sec * std.time.us_per_s + @divTrunc(ts.nsec, std.time.ns_per_us) + testOffsetSec() * std.time.us_per_s;
}

pub fn nowNs() i128 {
    const ts = gettime() orelse return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec + @as(i128, testOffsetSec()) * std.time.ns_per_s;
}

/// Wall-clock seconds (CLOCK_REALTIME) for DNSSEC signature validation
/// and log timestamps. Uses wall clock because RRSIG inception/expiration
/// are epoch seconds (RFC 4034 §3.1.5). Also offset by the test clock so
/// scenarios that exercise signature expiry advance in lockstep with the
/// cache clock.
pub fn wallclockSec() i64 {
    var ts: std.posix.timespec = undefined;
    const base: i64 = if (linux.errno(linux.clock_gettime(.REALTIME, &ts)) == .SUCCESS) ts.sec else 0;
    return base + testOffsetSec();
}
