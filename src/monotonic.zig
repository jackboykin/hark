/// Monotonic time helpers (CLOCK_BOOTTIME). Immune to NTP jumps.
const std = @import("std");
const linux = std.os.linux;

fn gettime() ?std.posix.timespec {
    var ts: std.posix.timespec = undefined;
    return if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) == .SUCCESS) ts else null;
}

pub fn nowSec() i64 {
    return (gettime() orelse return 0).sec;
}

pub fn nowMs() i64 {
    const ts = gettime() orelse return 0;
    return ts.sec * std.time.ms_per_s + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

pub fn nowUs() i64 {
    const ts = gettime() orelse return 0;
    return ts.sec * std.time.us_per_s + @divTrunc(ts.nsec, std.time.ns_per_us);
}

pub fn nowNs() i128 {
    const ts = gettime() orelse return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

/// Wall-clock seconds (CLOCK_REALTIME) for DNSSEC signature validation
/// and log timestamps. Uses wall clock because RRSIG inception/expiration
/// are epoch seconds (RFC 4034 §3.1.5).
pub fn wallclockSec() i64 {
    var ts: std.posix.timespec = undefined;
    return if (linux.errno(linux.clock_gettime(.REALTIME, &ts)) == .SUCCESS) ts.sec else 0;
}
