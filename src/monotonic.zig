/// Monotonic time helpers (CLOCK_BOOTTIME). Immune to NTP jumps.
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

// Test-clock offset (seconds). Added to every clock read so scenarios can
// `STEP n TIME_PASSES ELAPSE k` and observe TTL expiry without sleeping.
// Production builds compile this out — `testOffsetSec` is a comptime-known
// 0 so the optimizer drops the load entirely.
var test_offset_secs: i64 = 0;

inline fn testOffsetSec() i64 {
    if (!build_options.testing_enabled) return 0;
    return test_offset_secs;
}

/// Advance the synthetic test clock by `secs`. No-op in production builds.
/// Driven from the scenario-control DNS-query intercept (see `serve.zig`).
pub fn advanceTestClock(secs: i64) void {
    if (!build_options.testing_enabled) return;
    test_offset_secs += secs;
}

pub fn nowNs() i128 {
    var ts: std.posix.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
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
