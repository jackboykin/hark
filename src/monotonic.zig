/// Monotonic time helpers (CLOCK_BOOTTIME). Immune to NTP jumps.
/// In Zig 0.16, posix.clock_gettime may move — update only this file.
const std = @import("std");

pub fn nowSec() i64 {
    const ts = std.posix.clock_gettime(.BOOTTIME) catch return 0;
    return ts.sec;
}

pub fn nowMs() i64 {
    const ts = std.posix.clock_gettime(.BOOTTIME) catch return 0;
    return ts.sec * std.time.ms_per_s + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

pub fn nowUs() i64 {
    const ts = std.posix.clock_gettime(.BOOTTIME) catch return 0;
    return ts.sec * std.time.us_per_s + @divTrunc(ts.nsec, std.time.ns_per_us);
}

pub fn nowNs() i128 {
    const ts = std.posix.clock_gettime(.BOOTTIME) catch return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}
