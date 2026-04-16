/// Thin wrappers around std.os.linux.* syscalls with error handling.
/// Replaces the removed std.posix socket functions in Zig 0.16.
/// Matches the old posix.* signatures for mechanical migration.
///
/// sendto/recvfrom/write/read retry on EINTR internally. SIGINT/SIGTERM are
/// blocked and delivered via signalfd, but other unblocked signals (SIGPIPE,
/// profilers, etc.) can still interrupt blocking syscalls; looping avoids
/// dropping in-flight queries. connect/accept surface Interrupted because
/// retry semantics are context-dependent.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

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

pub fn send(fd: posix.fd_t, buf: []const u8, flags: u32) !usize {
    return sendto(fd, buf, flags, null, 0);
}

pub fn recv(fd: posix.fd_t, buf: []u8, flags: u32) !usize {
    return recvfrom(fd, buf, flags, null, null);
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
            .NOMEM => error.SystemResources,
            else => |e| posix.unexpectedErrno(e),
        };
    }
}

pub fn recvfrom(fd: posix.fd_t, buf: []u8, flags: u32, addr: ?*posix.sockaddr, len: ?*posix.socklen_t) !usize {
    while (true) {
        const rc = linux.recvfrom(fd, buf.ptr, buf.len, flags, addr, len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .BADF, .NOTSOCK => unreachable,
            .CONNREFUSED => error.ConnectionRefused,
            .INTR => continue,
            .NOMEM => error.SystemResources,
            .CONNRESET => error.ConnectionResetByPeer,
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
    // Use openat with AT.FDCWD
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

pub fn accept(fd: posix.fd_t, addr: ?*posix.sockaddr, len: ?*posix.socklen_t, flags: u32) !posix.fd_t {
    const rc = linux.accept4(fd, addr, len, flags);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => error.WouldBlock,
        .BADF, .NOTSOCK => unreachable,
        .CONNABORTED => error.ConnectionAborted,
        .INTR => error.Interrupted,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOMEM, .NOBUFS => error.SystemResources,
        .PERM => error.PermissionDenied,
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

pub fn setSocketTimeouts(sock: posix.fd_t, ms: u32) void {
    setSocketTimeout(sock, posix.SO.RCVTIMEO, ms);
    setSocketTimeout(sock, posix.SO.SNDTIMEO, ms);
}

pub fn setSocketTimeout(sock: posix.fd_t, opt: u32, ms: u32) void {
    const timeout = posix.timeval{
        .sec = @intCast(ms / 1000),
        .usec = @intCast(@as(u64, ms % 1000) * 1000),
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, opt, std.mem.asBytes(&timeout)) catch {};
}

pub fn pipe() ![2]posix.fd_t {
    var fds: [2]i32 = undefined;
    return switch (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true, .NONBLOCK = true }))) {
        .SUCCESS => .{ fds[0], fds[1] },
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOMEM => error.SystemResources,
        else => |e| posix.unexpectedErrno(e),
    };
}
