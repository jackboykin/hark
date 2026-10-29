//! The clocks: boot time for ages and deadlines, wall time for signature
//! windows (RFC 4034 §3.1.5) and log stamps, both run ahead under -Dtesting
//! by an offset the live harness advances.
const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

/// So a scenario sees TTLs lapse without sleeping; a comptime 0 unless
/// -Dtesting.
var test_offset_secs: i64 = 0;

inline fn testOffsetSec() i64 {
    return if (build_options.testing_enabled) test_offset_secs else 0;
}

pub fn advanceTestClock(secs: i64) void {
    if (build_options.testing_enabled) test_offset_secs += secs;
}

/// Boot time, immune to NTP jumps.
pub fn nowNs() i64 {
    const ts = read(.BOOTTIME);
    return (ts.sec + testOffsetSec()) * std.time.ns_per_s + ts.nsec;
}

/// Whole seconds want no counter read: the coarse clock is the kernel's
/// last tick, a few ms behind at most.
pub fn wallclockSec() i64 {
    return read(.REALTIME_COARSE).sec + testOffsetSec();
}

/// Zero would stop time: nothing would lapse, and signatures be judged in 1970.
fn read(clock: linux.clockid_t) std.posix.timespec {
    var ts: std.posix.timespec = undefined;
    if (linux.errno(linux.clock_gettime(clock, &ts)) != .SUCCESS) @panic("clock_gettime failed");
    return ts;
}
