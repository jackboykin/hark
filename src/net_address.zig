/// Address type and helpers, replacing std.net.Address with std.Io.net.IpAddress.
/// Provides initIp4/initIp6 constructors matching the old API, plus sockaddr
/// conversion for raw linux syscall usage (sys.zig).
const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const sys = @import("sys.zig");

pub const Address = std.Io.net.IpAddress;
pub const Ip4 = std.Io.net.Ip4Address;
pub const Ip6 = std.Io.net.Ip6Address;

pub fn initIp4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn initIp6(bytes: [16]u8, port: u16, flow: u32, scope: u32) Address {
    return .{ .ip6 = .{ .bytes = bytes, .port = port, .flow = flow, .interface = .{ .index = scope } } };
}


/// PosixAddress union for sockaddr conversion (matches Io.Threaded.PosixAddress).
pub const PosixAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

/// Convert an Address to a posix sockaddr. Returns the sockaddr length.
pub fn toSockaddr(addr: *const Address, storage: *PosixAddress) posix.socklen_t {
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

/// Convert a posix sockaddr to an Address.
pub fn fromSockaddr(sa: *const PosixAddress) Address {
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

/// Address family as u32 for socket() calls.
pub fn afU32(addr: Address) u32 {
    return switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

/// Get the local address bound to a socket.
pub fn getSockName(fd: posix.fd_t) !Address {
    var pa: PosixAddress = undefined;
    var len: posix.socklen_t = @sizeOf(PosixAddress);
    try sys.getsockname(fd, @ptrCast(&pa), &len);
    return fromSockaddr(&pa);
}

/// Format an address as "ip:port" into a caller-provided buffer.
pub fn format(addr: Address, buf: []u8) []const u8 {
    return switch (addr) {
        .ip4 => |v4| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
            v4.bytes[0], v4.bytes[1], v4.bytes[2], v4.bytes[3], v4.port,
        }) catch "?",
        .ip6 => |v6| std.fmt.bufPrint(buf, "[{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}]:{d}", .{
            mem.readInt(u16, v6.bytes[0..2], .big),  mem.readInt(u16, v6.bytes[2..4], .big),
            mem.readInt(u16, v6.bytes[4..6], .big),  mem.readInt(u16, v6.bytes[6..8], .big),
            mem.readInt(u16, v6.bytes[8..10], .big),  mem.readInt(u16, v6.bytes[10..12], .big),
            mem.readInt(u16, v6.bytes[12..14], .big), mem.readInt(u16, v6.bytes[14..16], .big),
            v6.port,
        }) catch "?",
    };
}

/// Connect a socket to an Address (converts to sockaddr internally).
pub fn connectTo(fd: posix.fd_t, addr: *const Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try sys.connect(fd, &storage.any, sa_len);
}

/// Bind a socket to an Address (converts to sockaddr internally).
pub fn bindTo(fd: posix.fd_t, addr: *const Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try sys.bind(fd, &storage.any, sa_len);
}

/// Compare two addresses by IP only, ignoring port.
pub fn ipEqual(a: Address, b: Address) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip6 => |b6| mem.eql(u8, &a6.bytes, &b6.bytes),
            .ip4 => false,
        },
    };
}
