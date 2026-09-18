//! Linux syscall wrappers with error unions, matching the old posix.*
//! signatures. Reach them through sys_union.zig; import this file directly
//! only for what has no meaning off Linux (signalfd).
//!
//! sendto/write retry on EINTR internally. SIGINT/SIGTERM are blocked
//! and delivered via signalfd, but other unblocked signals (SIGPIPE,
//! profilers, etc.) can still interrupt blocking syscalls; looping avoids
//! dropping in-flight queries. connect/accept surface Interrupted because
//! retry semantics are context-dependent.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const sys = @import("sys_union.zig");

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

pub fn shutdown(fd: posix.fd_t) void {
    _ = linux.shutdown(fd, linux.SHUT.RDWR);
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

/// Suppress the next delayed-ACK on this socket. Kernel auto-clears the flag
/// after the next ACK fires, so re-arm after every recv on a pooled fd.
pub fn setQuickAck(sock: posix.fd_t) void {
    const one: c_int = 1;
    posix.setsockopt(sock, linux.IPPROTO.TCP, linux.TCP.QUICKACK, std.mem.asBytes(&one)) catch {};
}

test "setNoDelay and setQuickAck flip the kernel TCP options" {
    const sock = try sys.socket(linux.AF.INET, posix.SOCK.STREAM, 0);
    defer sys.close(sock);

    var val: c_int = -1;
    var len: posix.socklen_t = @sizeOf(c_int);

    {
        const rc = linux.getsockopt(sock, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&val), &len);
        try std.testing.expectEqual(@as(linux.E, .SUCCESS), linux.errno(rc));
        try std.testing.expectEqual(@as(c_int, 0), val);
    }
    sys.setNoDelay(sock);
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
    const sock = try sys.socket(linux.AF.INET, posix.SOCK.STREAM, 0);
    defer sys.close(sock);

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
    sys.setSocketTimeout(sock, posix.SO.RCVTIMEO, 0);
    const floored = try readTimeout(sock);
    try std.testing.expect(floored.sec != 0 or floored.usec != 0);
    // Armed, and rounded up to at most one jiffy at the coarsest supported HZ.
    try std.testing.expectEqual(@as(@TypeOf(floored.sec), 0), floored.sec);
    try std.testing.expect(floored.usec > 0 and floored.usec <= 10_000);

    sys.setSocketTimeout(sock, posix.SO.RCVTIMEO, 2500);
    const normal = try readTimeout(sock);
    const normal_us = @as(i64, normal.sec) * 1_000_000 + normal.usec;
    try std.testing.expect(normal_us >= 2_500_000 and normal_us < 2_510_000);

    sys.clearSocketTimeout(sock, posix.SO.RCVTIMEO);
    const cleared = try readTimeout(sock);
    try std.testing.expectEqual(@as(@TypeOf(cleared.sec), 0), cleared.sec);
    try std.testing.expectEqual(@as(@TypeOf(cleared.usec), 0), cleared.usec);
}
