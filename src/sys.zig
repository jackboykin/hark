/// Thin wrappers around std.os.linux.* syscalls with error handling.
/// Replaces the removed std.posix socket functions in Zig 0.16.
/// Matches the old posix.* signatures for mechanical migration.
///
/// Used by the TCP/TLS path and the inbound server/event-loop sockets.
/// Outbound UDP uses std.Io.net.Socket directly; do not add new callers
/// here for paths that have an Io alternative.
///
/// sendto/write/read retry on EINTR internally. SIGINT/SIGTERM are blocked
/// and delivered via signalfd, but other unblocked signals (SIGPIPE,
/// profilers, etc.) can still interrupt blocking syscalls; looping avoids
/// dropping in-flight queries. connect/accept surface Interrupted because
/// retry semantics are context-dependent.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const monotonic = @import("monotonic.zig");

pub fn socket(af: u32, sock_type: u32, protocol: u32) !posix.fd_t {
    const rc = linux.socket(af, sock_type, protocol);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES => error.PermissionDenied,
        .AFNOSUPPORT => error.AddressFamilyNotSupported,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        else => |e| posix.unexpectedErrno(e),
    };
}

pub fn bind(fd: posix.fd_t, addr: *const posix.sockaddr, len: posix.socklen_t) !void {
    return switch (linux.errno(linux.bind(fd, addr, len))) {
        .SUCCESS => {},
        .ACCES => error.AccessDenied,
        .ADDRINUSE => error.AddressInUse,
        .BADF => unreachable,
        .INVAL => error.AlreadyBound,
        .NOTSOCK => unreachable,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .NOMEM => error.SystemResources,
        else => |e| posix.unexpectedErrno(e),
    };
}

pub fn connect(fd: posix.fd_t, addr: *const posix.sockaddr, len: posix.socklen_t) !void {
    return switch (linux.errno(linux.connect(fd, addr, len))) {
        .SUCCESS => {},
        .ACCES => error.PermissionDenied,
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .AFNOSUPPORT => error.AddressFamilyNotSupported,
        .ALREADY => error.AlreadyConnecting,
        .CONNREFUSED => error.ConnectionRefused,
        .INPROGRESS => error.WouldBlock,
        .INTR => error.Interrupted,
        .ISCONN => error.AlreadyConnected,
        .NETUNREACH => error.NetworkUnreachable,
        .HOSTUNREACH => error.HostUnreachable,
        .NOENT => error.FileNotFound,
        .TIMEDOUT => error.ConnectionTimedOut,
        else => |e| posix.unexpectedErrno(e),
    };
}

pub fn close(fd: posix.fd_t) void {
    _ = linux.close(fd);
}

pub fn listen(fd: posix.fd_t, backlog: u31) !void {
    return switch (linux.errno(linux.listen(fd, backlog))) {
        .SUCCESS => {},
        .ADDRINUSE => error.AddressInUse,
        .BADF, .NOTSOCK => unreachable,
        .OPNOTSUPP => error.OperationNotSupported,
        else => |e| posix.unexpectedErrno(e),
    };
}

pub fn sendto(fd: posix.fd_t, buf: []const u8, flags: u32, addr: ?*const posix.sockaddr, len: posix.socklen_t) !usize {
    while (true) {
        const rc = linux.sendto(fd, buf.ptr, buf.len, flags, addr, len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .BADF, .NOTSOCK => unreachable,
            .CONNRESET => error.ConnectionResetByPeer,
            .INTR => continue,
            .MSGSIZE => error.MessageTooBig,
            .PIPE => error.BrokenPipe,
            .NOBUFS, .NOMEM => error.SystemResources,
            else => |e| posix.unexpectedErrno(e),
        };
    }
}

pub fn getsockname(fd: posix.fd_t, addr: *posix.sockaddr, len: *posix.socklen_t) !void {
    return switch (linux.errno(linux.getsockname(fd, addr, len))) {
        .SUCCESS => {},
        .BADF, .NOTSOCK => unreachable,
        .FAULT => unreachable,
        .INVAL => error.AddressNotAvailable,
        else => |e| posix.unexpectedErrno(e),
    };
}

pub fn getpeername(fd: posix.fd_t, addr: *posix.sockaddr, len: *posix.socklen_t) !void {
    return switch (linux.errno(linux.getpeername(fd, addr, len))) {
        .SUCCESS => {},
        .BADF, .NOTSOCK => unreachable,
        .FAULT => unreachable,
        .NOTCONN => error.NotConnected,
        .INVAL => error.AddressNotAvailable,
        else => |e| posix.unexpectedErrno(e),
    };
}

pub fn write(fd: posix.fd_t, buf: []const u8) !usize {
    while (true) {
        const rc = linux.write(fd, buf.ptr, buf.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .BADF => unreachable,
            .INTR => continue,
            .IO => error.InputOutput,
            .NOSPC => error.NoSpaceLeft,
            .PIPE => error.BrokenPipe,
            .NOMEM => error.SystemResources,
            else => |e| posix.unexpectedErrno(e),
        };
    }
}

pub fn read(fd: posix.fd_t, buf: []u8) !usize {
    while (true) {
        const rc = linux.read(fd, buf.ptr, buf.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .BADF => unreachable,
            .INTR => continue,
            .IO => error.InputOutput,
            .NOMEM => error.SystemResources,
            else => |e| posix.unexpectedErrno(e),
        };
    }
}

pub fn open(path: [*:0]const u8, flags: std.posix.O, mode: std.posix.mode_t) !posix.fd_t {
    const rc = linux.openat(@bitCast(@as(i32, linux.AT.FDCWD)), path, flags, mode);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES => error.AccessDenied,
        .EXIST => error.PathAlreadyExists,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOENT => error.FileNotFound,
        .NOMEM => error.SystemResources,
        else => |e| posix.unexpectedErrno(e),
    };
}

pub fn dup(fd: posix.fd_t) !posix.fd_t {
    const rc = linux.dup(fd);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .BADF => unreachable,
        .MFILE => error.ProcessFdQuotaExceeded,
        else => |e| posix.unexpectedErrno(e),
    };
}

pub fn fcntl(fd: posix.fd_t, cmd: i32, arg: usize) !usize {
    const rc = linux.fcntl(fd, cmd, arg);
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .BADF => unreachable,
        .INVAL => error.InvalidArgument,
        else => |e| posix.unexpectedErrno(e),
    };
}

/// Takes the kernel's `linux.sigset_t`, not `posix.sigset_t`. The two are the
/// same array only in a no-libc build; linking libc (which `-Dtsan` forces)
/// widens the posix one to glibc's 128 bytes and the mismatch fails to compile.
/// Every caller already builds its mask with `linux.sigemptyset`, so stay on
/// the kernel ABI end to end.
pub fn signalfd(fd: posix.fd_t, mask: *const linux.sigset_t, flags: u32) !posix.fd_t {
    const rc = linux.signalfd(fd, mask, flags);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .BADF, .INVAL => unreachable,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NODEV, .NOMEM => error.SystemResources,
        else => |e| posix.unexpectedErrno(e),
    };
}

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
    posix.setsockopt(sock, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
}

/// Suppress the next delayed-ACK on this socket. Kernel auto-clears the flag
/// after the next ACK fires, so re-arm after every recv on a pooled fd.
pub fn setQuickAck(sock: posix.fd_t) void {
    const one: c_int = 1;
    posix.setsockopt(sock, linux.IPPROTO.TCP, linux.TCP.QUICKACK, std.mem.asBytes(&one)) catch {};
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

/// Write adapter for a single contiguous buffer, through `io.operate(.net_write)`
/// — the 0.17 replacement for the removed `io.vtable.netWrite` method. `data`
/// must be non-empty (its last element is the splat pattern), so the
/// empty-string sentinel with `splat=0` elides into a header-only iovec.
pub fn netWrite(io: std.Io, handle: posix.fd_t, buf: []const u8) std.Io.net.Stream.Writer.Error!usize {
    return (try io.operate(.{ .net_write = .{
        .socket_handle = handle,
        .header = buf,
        .data = &.{""},
        .splat = 0,
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
fn pollReady(handle: posix.fd_t, events: i16, deadline_ns: i128) error{ Timeout, PollFailed }!void {
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
fn remainingTimeoutMs(deadline_ns: i128) error{Timeout}!u32 {
    const remaining_ns = deadline_ns - monotonic.nowNs();
    if (remaining_ns < std.time.ns_per_ms) return error.Timeout;
    return @intCast(@min(
        @divFloor(remaining_ns, std.time.ns_per_ms),
        std.math.maxInt(u32),
    ));
}

/// Recompute remaining timeout from absolute deadline (slow-trickle mitigation).
/// `opt` is SO_RCVTIMEO or SO_SNDTIMEO — set only the direction the next syscall uses.
pub fn updateTimeout(sock: posix.fd_t, opt: u32, deadline_ns: i128) error{Timeout}!void {
    setSocketTimeout(sock, opt, try remainingTimeoutMs(deadline_ns));
}

test "setNoDelay and setQuickAck flip the kernel TCP options" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const sock = try socket(linux.AF.INET, posix.SOCK.STREAM, 0);
    defer close(sock);

    var val: c_int = -1;
    var len: posix.socklen_t = @sizeOf(c_int);

    // NODELAY default is 0 (Nagle on); confirm the helper flips it to 1.
    {
        const rc = linux.getsockopt(sock, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&val), &len);
        try std.testing.expectEqual(@as(linux.E, .SUCCESS), linux.errno(rc));
        try std.testing.expectEqual(@as(c_int, 0), val);
    }
    setNoDelay(sock);
    {
        val = -1;
        len = @sizeOf(c_int);
        const rc = linux.getsockopt(sock, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&val), &len);
        try std.testing.expectEqual(@as(linux.E, .SUCCESS), linux.errno(rc));
        try std.testing.expectEqual(@as(c_int, 1), val);
    }

    // QUICKACK is one-shot: the kernel auto-clears after the next ACK fires,
    // so this just verifies the setsockopt succeeds and the kernel reports 1.
    setQuickAck(sock);
    {
        val = -1;
        len = @sizeOf(c_int);
        const rc = linux.getsockopt(sock, linux.IPPROTO.TCP, linux.TCP.QUICKACK, std.mem.asBytes(&val), &len);
        try std.testing.expectEqual(@as(linux.E, .SUCCESS), linux.errno(rc));
        try std.testing.expectEqual(@as(c_int, 1), val);
    }
}

test "setSocketTimeout never disarms the timeout; clearSocketTimeout is how you mean it" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const sock = try socket(linux.AF.INET, posix.SOCK.STREAM, 0);
    defer close(sock);

    const readTimeout = struct {
        fn tv(s: posix.fd_t) !posix.timeval {
            var out: posix.timeval = undefined;
            var len: posix.socklen_t = @sizeOf(posix.timeval);
            const rc = linux.getsockopt(s, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&out), &len);
            try std.testing.expectEqual(@as(linux.E, .SUCCESS), linux.errno(rc));
            return out;
        }
    }.tv;

    // Assertions are inequalities on purpose: the kernel stores SO_*TIMEO in
    // jiffies and getsockopt converts back, so a 1 ms request reads back as
    // 1000 us at CONFIG_HZ=1000 but 4000 us at HZ=250 (Debian/Ubuntu generic)
    // and 3333 us at HZ=300 (Arch). Exact equality here passes only on the
    // machine it was written on.

    // The regression: a deadline of a few hundred microseconds truncates to
    // connect_ms == 0, and timeval{0,0} means *no timeout* to the kernel —
    // a blocking read that never returns. Floor it instead.
    setSocketTimeout(sock, posix.SO.RCVTIMEO, 0);
    const floored = try readTimeout(sock);
    try std.testing.expect(floored.sec != 0 or floored.usec != 0);
    // Armed, and rounded up to at most one jiffy at the coarsest supported HZ.
    try std.testing.expectEqual(@as(@TypeOf(floored.sec), 0), floored.sec);
    try std.testing.expect(floored.usec > 0 and floored.usec <= 10_000);

    // Ordinary values are not meaningfully altered by the floor.
    setSocketTimeout(sock, posix.SO.RCVTIMEO, 2500);
    const normal = try readTimeout(sock);
    const normal_us = @as(i64, normal.sec) * 1_000_000 + normal.usec;
    try std.testing.expect(normal_us >= 2_500_000 and normal_us < 2_510_000);

    // Infinite is still reachable, but only by asking for it by name.
    clearSocketTimeout(sock, posix.SO.RCVTIMEO);
    const cleared = try readTimeout(sock);
    try std.testing.expectEqual(@as(@TypeOf(cleared.sec), 0), cleared.sec);
    try std.testing.expectEqual(@as(@TypeOf(cleared.usec), 0), cleared.usec);
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
