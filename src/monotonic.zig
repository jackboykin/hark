//! The clocks: boot time for ages and deadlines, wall time for signature
//! windows (RFC 4034 §3.1.5) and log stamps, both run ahead under -Dtesting
//! by an offset the live harness advances.
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

var test_offset_secs: i64 = 0;

inline fn testOffsetSec() i64 {
    return if (build_options.testing_enabled) test_offset_secs else 0;
}

pub fn advanceTestClock(secs: i64) void {
    if (build_options.testing_enabled) test_offset_secs += secs;
}

/// BOOTTIME never steps with NTP, and keeps counting through suspend.
pub fn nowNs() i64 {
    const ts = read(.BOOTTIME);
    return (ts.sec + testOffsetSec()) * std.time.ns_per_s + ts.nsec;
}

pub fn wallclockSec() i64 {
    return read(.REALTIME_COARSE).sec + testOffsetSec();
}

fn read(clock: linux.clockid_t) std.posix.timespec {
    var ts: std.posix.timespec = undefined;
    if (linux.errno(linux.clock_gettime(clock, &ts)) != .SUCCESS) @panic("clock_gettime failed");
    return ts;
}
