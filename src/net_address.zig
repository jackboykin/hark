/// Address type and helpers, replacing std.net.Address with std.Io.net.IpAddress.
/// Wraps std.Io.net.IpAddress with convenience constructors and sockaddr
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
            mem.readInt(u16, v6.bytes[0..2], .big),   mem.readInt(u16, v6.bytes[2..4], .big),
            mem.readInt(u16, v6.bytes[4..6], .big),   mem.readInt(u16, v6.bytes[6..8], .big),
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

/// Returns true if the address is in a private, reserved, or loopback range
/// that should not be contacted during recursive resolution (DNS rebinding defense).
pub fn isNonRoutableNs(addr: Address) bool {
    return switch (addr) {
        .ip4 => |v4| isNonRoutableIp4(v4.bytes),
        .ip6 => |v6| isNonRoutableIp6(v6.bytes),
    };
}

fn isNonRoutableIp4(b: [4]u8) bool {
    if (b[0] == 0) return true; // 0.0.0.0/8  (this network)
    if (b[0] == 10) return true; // 10.0.0.0/8  (RFC 1918)
    if (b[0] == 127) return true; // 127.0.0.0/8 (loopback)
    if (b[0] == 169 and b[1] == 254) return true; // 169.254.0.0/16 (link-local)
    if (b[0] == 172 and (b[1] & 0xf0) == 16) return true; // 172.16.0.0/12 (RFC 1918)
    if (b[0] == 192 and b[1] == 168) return true; // 192.168.0.0/16 (RFC 1918)
    if (b[0] >= 224) return true; // 224.0.0.0/4+ (multicast + reserved)
    return false;
}

fn isNonRoutableIp6(b: [16]u8) bool {
    return switch (b[0]) {
        0x00 => isNonRoutableIp6Zero(b),
        0xfc, 0xfd => true, // fc00::/7  (unique local)
        0xfe => (b[1] & 0xc0) == 0x80, // fe80::/10 (link-local)
        0xff => true, // ff00::/8  (multicast)
        else => false,
    };
}

fn isNonRoutableIp6Zero(b: [16]u8) bool {
    // All addresses starting with 0x00: check for ::, ::1, and ::ffff:mapped
    if (!mem.eql(u8, b[1..10], &([_]u8{0} ** 9))) return false;
    if (b[10] == 0 and b[11] == 0) {
        // :: (unspecified) or ::1 (loopback)
        return mem.eql(u8, b[12..15], &([_]u8{0} ** 3)) and b[15] <= 1;
    }
    if (b[10] == 0xff and b[11] == 0xff) {
        // ::ffff:0:0/96 (IPv4-mapped) — check the mapped IPv4 address
        return isNonRoutableIp4(b[12..16].*);
    }
    return false;
}

// ── Tests ────────────────────────────────────────────────────────────

const testing = std.testing;

test "isNonRoutableNs blocks private/reserved IPv4" {
    // Loopback
    try testing.expect(isNonRoutableNs(initIp4(.{ 127, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 127, 255, 255, 255 }, 53)));
    // RFC 1918
    try testing.expect(isNonRoutableNs(initIp4(.{ 10, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 172, 16, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 172, 31, 255, 255 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 192, 168, 1, 1 }, 53)));
    // Link-local
    try testing.expect(isNonRoutableNs(initIp4(.{ 169, 254, 1, 1 }, 53)));
    // This network
    try testing.expect(isNonRoutableNs(initIp4(.{ 0, 0, 0, 0 }, 53)));
    // Multicast
    try testing.expect(isNonRoutableNs(initIp4(.{ 224, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 255, 255, 255, 255 }, 53)));
}

test "isNonRoutableNs allows routable IPv4" {
    try testing.expect(!isNonRoutableNs(initIp4(.{ 1, 1, 1, 1 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 8, 8, 8, 8 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 192, 0, 2, 1 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 198, 51, 100, 1 }, 53)));
    // 172.15.x and 172.32.x are routable
    try testing.expect(!isNonRoutableNs(initIp4(.{ 172, 15, 255, 255 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 172, 32, 0, 1 }, 53)));
}

test "isNonRoutableNs blocks private/reserved IPv6" {
    // Loopback ::1
    try testing.expect(isNonRoutableNs(initIp6(.{0} ** 15 ++ .{1}, 53, 0, 0)));
    // Unspecified ::
    try testing.expect(isNonRoutableNs(initIp6(.{0} ** 16, 53, 0, 0)));
    // Unique local fc00::/7
    try testing.expect(isNonRoutableNs(initIp6(.{ 0xfc, 0 } ++ .{0} ** 14, 53, 0, 0)));
    try testing.expect(isNonRoutableNs(initIp6(.{ 0xfd, 0x12 } ++ .{0} ** 14, 53, 0, 0)));
    // Link-local fe80::/10
    try testing.expect(isNonRoutableNs(initIp6(.{ 0xfe, 0x80 } ++ .{0} ** 14, 53, 0, 0)));
    // Multicast ff00::/8
    try testing.expect(isNonRoutableNs(initIp6(.{ 0xff, 0x02 } ++ .{0} ** 14, 53, 0, 0)));
    // IPv4-mapped ::ffff:127.0.0.1
    try testing.expect(isNonRoutableNs(initIp6(.{0} ** 10 ++ .{ 0xff, 0xff, 127, 0, 0, 1 }, 53, 0, 0)));
    // IPv4-mapped ::ffff:10.0.0.1
    try testing.expect(isNonRoutableNs(initIp6(.{0} ** 10 ++ .{ 0xff, 0xff, 10, 0, 0, 1 }, 53, 0, 0)));
}

test "isNonRoutableNs allows routable IPv6" {
    // 2001:db8::1 (documentation, but routable from resolver perspective)
    try testing.expect(!isNonRoutableNs(initIp6(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1}, 53, 0, 0)));
    // IPv4-mapped ::ffff:1.1.1.1 (routable mapped address)
    try testing.expect(!isNonRoutableNs(initIp6(.{0} ** 10 ++ .{ 0xff, 0xff, 1, 1, 1, 1 }, 53, 0, 0)));
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
