//! The clocks: boot time for ages and deadlines, immune to NTP jumps; wall
//! time for signature windows (RFC 4034 §3.1.5) and log stamps. Under
//! -Dtesting both run ahead by an offset the live harness advances, so a
//! scenario sees TTLs lapse without sleeping; otherwise the offset is a
//! comptime 0.
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

pub fn nowNs() i64 {
    var ts: std.posix.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return (ts.sec + testOffsetSec()) * std.time.ns_per_s + ts.nsec;
}

pub fn wallclockSec() i64 {
    var ts: std.posix.timespec = undefined;
    const base: i64 = if (linux.errno(linux.clock_gettime(.REALTIME, &ts)) == .SUCCESS) ts.sec else 0;
    return base + testOffsetSec();
}
