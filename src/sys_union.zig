//! The socket and deadline-I/O surface hark asks of the OS. Portable code
//! lives here; syscall wrappers come from the per-OS file and are re-exported,
//! so the list below is what a new platform has to provide.
//!
//! Used by the TCP/TLS path and the inbound server/event-loop sockets.
//! Outbound UDP uses std.Io.net.Socket directly; do not add new callers
//! here for paths that have an Io alternative.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const monotonic = @import("monotonic.zig");

const os = switch (builtin.os.tag) {
    .linux => @import("sys_linux.zig"),
    else => @compileError("no sys backend for " ++ @tagName(builtin.os.tag)),
};

pub const socket = os.socket;
pub const bind = os.bind;
pub const connect = os.connect;
pub const close = os.close;
pub const shutdown = os.shutdown;
pub const listen = os.listen;
pub const sendto = os.sendto;
pub const getsockname = os.getsockname;
pub const write = os.write;
pub const setQuickAck = os.setQuickAck;

/// Arm SO_RCVTIMEO/SO_SNDTIMEO. `ms` is floored at 1 because the kernel reads
/// `timeval{0,0}` as *no timeout*: deadline arithmetic that truncated to zero
/// would otherwise fail open, in the one call asking for a bound. Use
/// `clearSocketTimeout` where infinite is what you mean.
pub fn setSocketTimeout(sock: posix.fd_t, opt: u32, ms: u32) void {
    const bounded = @max(ms, 1);
    const timeout = posix.timeval{
        .sec = @intCast(bounded / 1000),
        .usec = @intCast(@as(u64, bounded % 1000) * 1000),
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, opt, std.mem.asBytes(&timeout)) catch {};
}

/// Disarm SO_RCVTIMEO/SO_SNDTIMEO — the syscall blocks indefinitely and the
/// deadline is enforced in userspace instead. The explicit spelling of the
/// `timeval{0,0}` sentinel.
pub fn clearSocketTimeout(sock: posix.fd_t, opt: u32) void {
    const none = posix.timeval{ .sec = 0, .usec = 0 };
    posix.setsockopt(sock, posix.SOL.SOCKET, opt, std.mem.asBytes(&none)) catch {};
}

/// Disable Nagle's algorithm. Kernel persists this across the fd lifetime.
/// With Nagle on + delayed-ACK on the peer, length-prefix + body writes (or
/// back-to-back queries on a pooled connection) can stall up to 40 ms.
pub fn setNoDelay(sock: posix.fd_t) void {
    const one: c_int = 1;
    posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
}

/// Read adapter for a single buffer. Wraps the slice in the one-element
/// iovec `std.Io.net.Stream.read` expects, which dispatches the read through
/// `io.operate(.net_read)` — the 0.17 replacement for the removed
/// `io.vtable.netRead` method.
pub fn netRead(io: std.Io, handle: posix.fd_t, buf: []u8) std.Io.net.Stream.Reader.Error!usize {
    var iovec = [_][]u8{buf};
    // net_read only reads the handle; address is never touched on the read path.
    const stream: std.Io.net.Stream = .{ .socket = .{ .handle = handle, .address = undefined } };
    return stream.read(io, &iovec);
}

pub fn netWrite(io: std.Io, handle: posix.fd_t, buf: []const u8) std.Io.net.Stream.Writer.Error!usize {
    return netWriteVec(io, handle, buf, &.{""}, 0);
}

/// `data` must be non-empty: `""` with `splat=0` is a header-only iovec.
pub fn netWriteVec(io: std.Io, handle: posix.fd_t, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
    return (try io.operate(.{ .net_write = .{
        .socket_handle = handle,
        .header = header,
        .data = data,
        .splat = splat,
    } })).net_write;
}

/// Errors from the deadline-bounded exact-I/O loops below. `Closed` is a
/// clean peer FIN (`n == 0`) — routine on client connections; `IoFailed`
/// wraps any read/write syscall error.
const DeadlineIoError = error{ Timeout, PollFailed, IoFailed, Closed };

/// Read exactly `buf.len` bytes from `handle` before `deadline_ns`. Every
/// iteration polls with the remaining deadline before issuing a netRead —
/// the slow-trickle mitigation: a peer dripping one byte per syscall
/// can't reset a per-syscall timer that doesn't exist.
pub fn readExactDeadline(io: std.Io, handle: posix.fd_t, buf: []u8, deadline_ns: i128) DeadlineIoError!void {
    var total: usize = 0;
    while (total < buf.len) {
        try pollReady(handle, posix.POLL.IN, deadline_ns);
        const n = netRead(io, handle, buf[total..]) catch return error.IoFailed;
        if (n == 0) return error.Closed;
        total += n;
    }
}

/// Write all of `data` to `handle` before `deadline_ns`. Deadline
/// semantics mirror `readExactDeadline`.
pub fn writeAllDeadline(io: std.Io, handle: posix.fd_t, data: []const u8, deadline_ns: i128) DeadlineIoError!void {
    var total: usize = 0;
    while (total < data.len) {
        try pollReady(handle, posix.POLL.OUT, deadline_ns);
        const n = netWrite(io, handle, data[total..]) catch return error.IoFailed;
        if (n == 0) return error.Closed;
        total += n;
    }
}

/// Wait up to `deadline_ns` for `handle` to be ready for `events`
/// (`posix.POLL.IN` / `posix.POLL.OUT`). Userspace timeout enforcement
/// for transports whose read/write goes through `Io.net`'s vtable —
/// `netReadPosix`/`netWritePosix` treat `EAGAIN` as a programmer bug,
/// so `SO_RCVTIMEO`/`SO_SNDTIMEO` can't be used to bound those calls.
/// Polling first puts the deadline in userspace where it belongs.
pub fn pollReady(handle: posix.fd_t, events: i16, deadline_ns: i128) error{ Timeout, PollFailed }!void {
    const remaining_ns = deadline_ns - monotonic.nowNs();
    if (remaining_ns <= 0) return error.Timeout;
    const wait_ms: i32 = @intCast(@min(@divFloor(remaining_ns, 1_000_000), std.math.maxInt(i32)));
    var pfd = [_]posix.pollfd{.{ .fd = handle, .events = events, .revents = 0 }};
    const n = posix.poll(&pfd, wait_ms) catch return error.PollFailed;
    if (n == 0) return error.Timeout;
    // POLLNVAL means the fd is invalid (closed elsewhere mid-poll). The
    // subsequent read/write would hit EBADF and panic via errnoBug, so
    // catch it here. POLLERR/POLLHUP can fire alongside the requested
    // event; let the read/write surface the kernel's specific error.
    if (pfd[0].revents & posix.POLL.NVAL != 0) return error.PollFailed;
}

/// Milliseconds left until `deadline_ns`, for arming a kernel socket timeout.
/// Sub-millisecond residue is `error.Timeout`, not zero: the budget is spent.
pub fn remainingTimeoutMs(deadline_ns: i128) error{Timeout}!u32 {
    const remaining_ns = deadline_ns - monotonic.nowNs();
    if (remaining_ns < std.time.ns_per_ms) return error.Timeout;
    return @intCast(@min(
        @divFloor(remaining_ns, std.time.ns_per_ms),
        std.math.maxInt(u32),
    ));
}

test "remainingTimeoutMs: sub-millisecond residue is Timeout, not an unbounded socket" {
    const now = monotonic.nowNs();

    // Regression: a few hundred microseconds of budget truncated to
    // 0 ms, and setSocketTimeout wrote timeval{0,0} — no timeout at all.
    try std.testing.expectError(error.Timeout, remainingTimeoutMs(now + 999_999));
    try std.testing.expectError(error.Timeout, remainingTimeoutMs(now));
    try std.testing.expectError(error.Timeout, remainingTimeoutMs(now - std.time.ns_per_s));

    // A full millisecond is the smallest arming budget.
    // Margin is generous on purpose: a stingy one makes the test fail under
    // scheduling noise, which is the same machine-dependence the jiffies
    // assertions above had to shed.
    try std.testing.expect(try remainingTimeoutMs(now + 500 * std.time.ns_per_ms) >= 1);

    // Absurd deadlines saturate rather than wrap.
    try std.testing.expectEqual(
        @as(u32, std.math.maxInt(u32)),
        try remainingTimeoutMs(now + @as(i128, std.math.maxInt(i64))),
    );
}
