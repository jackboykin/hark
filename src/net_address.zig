//! std.Io.net.IpAddress, with constructors, a hashable key, and sockaddr
//! conversion for the raw syscalls.
const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const sys = @import("sys.zig");
const rand = @import("rand.zig");
const acl = @import("acl.zig");

pub const Address = std.Io.net.IpAddress;

pub fn initIp4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn initIp6(bytes: [16]u8, port: u16) Address {
    return .{ .ip6 = .{ .bytes = bytes, .port = port } };
}

/// Murmur3's fmix64. FNV-1a's multiply only carries upward, so without it
/// the low bits, which the hash map reads, barely vary across IPv4 keys.
fn fmix64(h0: u64) u64 {
    var h = h0;
    h ^= h >> 33;
    h *%= 0xff51afd7ed558ccd;
    h ^= h >> 33;
    h *%= 0xc4ceb9fe1a85ec53;
    h ^= h >> 33;
    return h;
}

pub const AddressKey = struct {
    family: u8,
    addr: [16]u8,
    port: u16,

    pub fn eql(a: AddressKey, b: AddressKey) bool {
        return a.family == b.family and a.port == b.port and mem.eql(u8, &a.addr, &b.addr);
    }

    pub fn isLoopback(a: AddressKey) bool {
        if (a.family == std.posix.AF.INET) return a.addr[0] == 127;
        return mem.eql(u8, &a.addr, &(@as([15]u8, @splat(0)) ++ [_]u8{1}));
    }

    pub fn ip4(bytes: [4]u8, port: u16) AddressKey {
        var addr: [16]u8 = @splat(0);
        addr[0..4].* = bytes;
        return .{ .family = @intCast(posix.AF.INET), .addr = addr, .port = port };
    }

    pub fn ip6(bytes: [16]u8, port: u16) AddressKey {
        return .{ .family = @intCast(posix.AF.INET6), .addr = bytes, .port = port };
    }

    pub fn fromAddress(address: Address) AddressKey {
        return switch (address) {
            .ip4 => |v4| .ip4(v4.bytes, v4.port),
            .ip6 => |v6| .ip6(v6.bytes, v6.port),
        };
    }

    pub fn toAddress(k: AddressKey) Address {
        return if (k.family == posix.AF.INET) initIp4(k.addr[0..4].*, k.port) else initIp6(k.addr, k.port);
    }

    pub const HashCtx = struct {
        pub fn hash(_: @This(), key: AddressKey) u64 {
            const lo = mem.readInt(u64, key.addr[0..8], .little);
            const hi = mem.readInt(u64, key.addr[8..16], .little);
            const tag = (@as(u64, key.family) << 16) | key.port;
            var h: u64 = rand.hash_seed ^ 0xcbf29ce484222325;
            h ^= lo;
            h *%= 0x100000001b3;
            h ^= hi;
            h *%= 0x100000001b3;
            h ^= tag;
            h *%= 0x100000001b3;
            return fmix64(h);
        }

        pub fn eql(_: @This(), a: AddressKey, b: AddressKey) bool {
            return a.eql(b);
        }
    };
};

pub const PosixAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

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

pub fn isUnspecified(addr: Address) bool {
    return switch (addr) {
        inline else => |a| mem.allEqual(u8, &a.bytes, 0),
    };
}

pub fn afU32(addr: Address) u32 {
    return switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

pub fn format(addr: Address, buf: []u8) []const u8 {
    var w = std.Io.Writer.fixed(buf);
    addr.format(&w) catch return "?";
    return w.buffered();
}

pub fn connectTo(fd: posix.fd_t, addr: *const Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try sys.connect(fd, &storage.any, sa_len);
}

pub fn bindTo(fd: posix.fd_t, addr: *const Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try sys.bind(fd, &storage.any, sa_len);
}

pub fn ipEqual(a: Address, b: Address) bool {
    return switch (a) {
        .ip4 => |x| b == .ip4 and mem.eql(u8, &x.bytes, &b.ip4.bytes),
        .ip6 => |x| b == .ip6 and mem.eql(u8, &x.bytes, &b.ip6.bytes),
    };
}

/// A superset of the special-use table: nameserver contact also refuses
/// multicast, which the answer scrub (rebinding.zig) deliberately serves.
pub fn isNonRoutableNs(addr: AddressKey) bool {
    return if (addr.family == posix.AF.INET) isNonRoutableIp4(addr.addr[0..4].*) else isNonRoutableIp6(addr.addr);
}

fn isNonRoutableIp4(b: [4]u8) bool {
    return isSpecialUseIp4(b) or multicast_ip4.holds(mem.readInt(u32, &b, .big));
}

fn isNonRoutableIp6(b: [16]u8) bool {
    if (isIp4Mapped(&b)) return isNonRoutableIp4(b[12..16].*);
    return isSpecialUseIp6(b) or multicast_ip6.holds(mem.readInt(u128, &b, .big));
}

const special_use_ip4: Prefixes(u32) = .of(&.{
    "0.0.0.0/8",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "198.18.0.0/15",
    "240.0.0.0/4",
});

const special_use_ip6: Prefixes(u128) = .of(&.{
    "::/96",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
});

const multicast_ip4 = Prefix(u32).of("224.0.0.0/4");
const multicast_ip6 = Prefix(u128).of("ff00::/8");

pub fn isSpecialUseIp4(b: [4]u8) bool {
    return special_use_ip4.holds(mem.readInt(u32, &b, .big));
}

/// An IPv4-mapped address is judged as IPv4, so a mapped 127.0.0.1 doesn't
/// slip through as a v6 address the v6 set has no opinion on.
pub fn isSpecialUseIp6(b: [16]u8) bool {
    if (isIp4Mapped(&b)) return isSpecialUseIp4(b[12..16].*);
    return special_use_ip6.holds(mem.readInt(u128, &b, .big));
}

fn Prefix(comptime Int: type) type {
    return struct {
        net: Int,
        mask: Int,

        fn of(comptime cidr: []const u8) @This() {
            @setEvalBranchQuota(10_000);
            const c = acl.parse(cidr).?;
            const bytes = switch (c.address) {
                .ip4 => |a| a.bytes,
                .ip6 => |a| a.bytes,
            };
            const mask: Int = if (c.prefix == 0) 0 else ~@as(Int, 0) << @intCast(@bitSizeOf(Int) - c.prefix);
            return .{ .net = mem.readInt(Int, &bytes, .big), .mask = mask };
        }

        fn holds(p: @This(), a: Int) bool {
            return a & p.mask == p.net;
        }
    };
}

fn Prefixes(comptime Int: type) type {
    return struct {
        all: []const Prefix(Int),
        by_lead: [256]u16,

        fn of(comptime cidrs: []const []const u8) @This() {
            @setEvalBranchQuota(100_000);
            var all: [cidrs.len]Prefix(Int) = undefined;
            var by_lead: [256]u16 = @splat(0);
            for (&all, cidrs, 0..) |*p, c, i| {
                p.* = .of(c);
                const net = lead(p.net);
                const mask = lead(p.mask);
                for (&by_lead, 0..) |*may, l| {
                    if ((l ^ net) & mask == 0) may.* |= 1 << i;
                }
            }
            const final = all;
            return .{ .all = &final, .by_lead = by_lead };
        }

        fn holds(comptime set: @This(), a: Int) bool {
            const may = set.by_lead[lead(a)];
            if (may == 0) return false;
            inline for (set.all, 0..) |p, i| if (may & (1 << i) != 0 and p.holds(a)) return true;
            return false;
        }

        fn lead(a: Int) u8 {
            return @truncate(a >> (@bitSizeOf(Int) - 8));
        }
    };
}

pub fn isIp4Mapped(bytes: []const u8) bool {
    return bytes.len == 16 and mem.readInt(u64, bytes[0..8], .big) == 0 and mem.readInt(u32, bytes[8..12], .big) == 0xffff;
}

const testing = std.testing;

test "AddressKey.HashCtx: eql peers hash equal, distinct peers diverge" {
    const ctx: AddressKey.HashCtx = .{};
    const a = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 53));
    const b = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 53));
    const c = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 5353));
    const d = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 5 }, 53));
    const e = AddressKey.fromAddress(initIp6([_]u8{ 1, 2, 3, 4 } ++ @as([12]u8, @splat(0)), 53));

    try testing.expect(ctx.eql(a, b));
    try testing.expectEqual(ctx.hash(a), ctx.hash(b));
    try testing.expect(!ctx.eql(a, c));
    try testing.expect(ctx.hash(a) != ctx.hash(c));
    try testing.expect(!ctx.eql(a, d));
    try testing.expect(ctx.hash(a) != ctx.hash(d));
    try testing.expect(!ctx.eql(a, e));
    try testing.expect(ctx.hash(a) != ctx.hash(e));
}

test "AddressKey.HashCtx: the hash seed shifts the hash space" {
    const ctx: AddressKey.HashCtx = .{};
    const k = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 53));
    const h0 = ctx.hash(k);
    const saved = rand.hash_seed;
    defer rand.hash_seed = saved;
    rand.hash_seed = 0xdeadbeefcafef00d;
    const h1 = ctx.hash(k);
    try testing.expect(h0 != h1);
}

test "special-use IPv4 set covers RFC 1918 + loopback + link-local + TEST-NET + CGNAT" {
    inline for ([_][4]u8{
        .{ 0, 0, 0, 0 },
        .{ 10, 1, 2, 3 },
        .{ 100, 64, 0, 1 }, // CGNAT
        .{ 100, 127, 255, 255 }, // CGNAT upper edge
        .{ 127, 0, 0, 1 },
        .{ 169, 254, 1, 1 },
        .{ 172, 16, 0, 1 },
        .{ 172, 31, 255, 255 },
        .{ 192, 0, 0, 1 }, // IETF
        .{ 192, 0, 2, 1 }, // TEST-NET-1
        .{ 192, 168, 1, 1 },
        .{ 198, 18, 0, 1 }, // benchmarking
        .{ 198, 19, 255, 255 },
        .{ 198, 51, 100, 1 }, // TEST-NET-2
        .{ 203, 0, 113, 1 }, // TEST-NET-3
        .{ 240, 0, 0, 1 },
        .{ 255, 255, 255, 255 },
    }) |bytes| try testing.expect(isSpecialUseIp4(bytes));
}

test "special-use IPv4 set leaves routable space alone (incl. boundaries + multicast)" {
    inline for ([_][4]u8{
        .{ 1, 1, 1, 1 },
        .{ 8, 8, 8, 8 },
        .{ 100, 63, 255, 255 }, // just below CGNAT
        .{ 100, 128, 0, 0 }, // just above CGNAT
        .{ 172, 15, 255, 255 }, // just below RFC 1918
        .{ 172, 32, 0, 0 }, // just above RFC 1918
        .{ 192, 0, 1, 1 }, // 192.0.1/24 allocated, not reserved
        .{ 198, 17, 255, 255 }, // just below benchmarking
        .{ 198, 20, 0, 0 }, // just above benchmarking
        .{ 224, 0, 0, 1 }, // multicast — deliberately not blocked
        .{ 239, 255, 255, 255 },
    }) |bytes| try testing.expect(!isSpecialUseIp4(bytes));
}

test "special-use IPv6 set covers ::/::1, ULA, link-local, docs, mapped-v4" {
    try testing.expect(isSpecialUseIp6(@as([16]u8, @splat(0))));
    try testing.expect(isSpecialUseIp6(@as([15]u8, @splat(0)) ++ [_]u8{1}));
    try testing.expect(isSpecialUseIp6(@as([12]u8, @splat(0)) ++ [_]u8{ 127, 0, 0, 1 }));
    try testing.expect(isSpecialUseIp6([_]u8{0xfc} ++ @as([15]u8, @splat(0))));
    try testing.expect(isSpecialUseIp6([_]u8{0xfd} ++ @as([15]u8, @splat(0))));
    try testing.expect(isSpecialUseIp6([_]u8{ 0xfe, 0x80 } ++ @as([14]u8, @splat(0))));
    try testing.expect(isSpecialUseIp6([_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([12]u8, @splat(0))));
    try testing.expect(isSpecialUseIp6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 }));
    try testing.expect(!isSpecialUseIp6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 1, 1, 1, 1 }));
    try testing.expect(!isSpecialUseIp6([_]u8{ 0xff, 0x02 } ++ @as([14]u8, @splat(0))));
    try testing.expect(!isSpecialUseIp6([_]u8{ 0x26, 0x06 } ++ @as([14]u8, @splat(0))));
}

test "isNonRoutableNs blocks special-use + multicast IPv4" {
    try testing.expect(isNonRoutableNs(.ip4(.{ 127, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(.ip4(.{ 224, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(.ip4(.{ 239, 255, 255, 255 }, 53)));
    try testing.expect(isNonRoutableNs(.ip4(.{ 255, 255, 255, 255 }, 53)));
}

test "isNonRoutableNs blocks special-use + multicast IPv6" {
    try testing.expect(isNonRoutableNs(.ip6(@as([15]u8, @splat(0)) ++ [_]u8{1}, 53)));
    try testing.expect(isNonRoutableNs(.ip6(@splat(0), 53)));
    try testing.expect(isNonRoutableNs(.ip6([_]u8{ 0xfc, 0 } ++ @as([14]u8, @splat(0)), 53)));
    try testing.expect(isNonRoutableNs(.ip6([_]u8{ 0xfd, 0x12 } ++ @as([14]u8, @splat(0)), 53)));
    try testing.expect(isNonRoutableNs(.ip6([_]u8{ 0xfe, 0x80 } ++ @as([14]u8, @splat(0)), 53)));
    try testing.expect(isNonRoutableNs(.ip6([_]u8{ 0xff, 0x02 } ++ @as([14]u8, @splat(0)), 53)));
    try testing.expect(isNonRoutableNs(.ip6([_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([11]u8, @splat(0)) ++ [_]u8{1}, 53)));
    try testing.expect(isNonRoutableNs(.ip6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(.ip6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 10, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(.ip6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 224, 0, 0, 1 }, 53)));
}

test "isNonRoutableNs allows routable IPv6" {
    try testing.expect(!isNonRoutableNs(.ip6([_]u8{ 0x26, 0x06 } ++ @as([14]u8, @splat(0)), 53)));
    try testing.expect(!isNonRoutableNs(.ip6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 1, 1, 1, 1 }, 53)));
}
