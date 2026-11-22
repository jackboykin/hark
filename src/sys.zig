//! The socket surface hark asks of the OS. Syscall wrappers come from the
//! per-OS file and are re-exported, so the list below is what a new platform
//! has to provide. Addresses convert to and from sockaddr here.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const mem = std.mem;
const na = @import("net_address.zig");

const os = switch (builtin.os.tag) {
    .linux => @import("sys_linux.zig"),
    else => @compileError("no sys backend for " ++ @tagName(builtin.os.tag)),
};

pub const socket = os.socket;
pub const bind = os.bind;
pub const connect = os.connect;
pub const detach = os.detach;
pub const close = os.close;
pub const listen = os.listen;
pub const sendto = os.sendto;
pub const write = os.write;
pub const writeNoWait = os.writeNoWait;

pub const PosixAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

pub fn toSockaddr(addr: *const na.Address, storage: *PosixAddress) posix.socklen_t {
    return switch (addr.*) {
        .ip4 => |ip4| {
            storage.in = .{
                .port = mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |ip6| {
            storage.in6 = .{
                .port = mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            return @sizeOf(posix.sockaddr.in6);
        },
    };
}

pub fn fromSockaddr(sa: *const PosixAddress) na.Address {
    return switch (sa.any.family) {
        posix.AF.INET => .{ .ip4 = .{
            .port = mem.bigToNative(u16, sa.in.port),
            .bytes = @bitCast(sa.in.addr),
        } },
        posix.AF.INET6 => .{ .ip6 = .{
            .port = mem.bigToNative(u16, sa.in6.port),
            .bytes = sa.in6.addr,
            .flow = sa.in6.flowinfo,
            .interface = .{ .index = sa.in6.scope_id },
        } },
        else => unreachable,
    };
}

pub fn afU32(addr: na.Address) u32 {
    return switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

pub fn connectTo(fd: posix.fd_t, addr: *const na.Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try connect(fd, &storage.any, sa_len);
}

pub fn bindTo(fd: posix.fd_t, addr: *const na.Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try bind(fd, &storage.any, sa_len);
}
