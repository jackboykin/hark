//! CIDR prefixes: `[server].clients`, which the server's UDP and TCP
//! front-ends enforce, and the rebinding scrub's extra sets.
const std = @import("std");
const mem = std.mem;
const Address = std.Io.net.IpAddress;

pub const Cidr = struct {
    address: Address,
    prefix: u8,

    fn matches(self: Cidr, addr: Address) bool {
        return switch (addr) {
            .ip4 => |v4| self.matchesBytes(&v4.bytes),
            .ip6 => |v6| self.matchesBytes(&v6.bytes),
        };
    }

    pub fn matchesBytes(self: Cidr, bytes: []const u8) bool {
        return switch (self.address) {
            .ip4 => |v4| bytes.len == 4 and prefixMatch(bytes, &v4.bytes, self.prefix),
            .ip6 => |v6| bytes.len == 16 and prefixMatch(bytes, &v6.bytes, self.prefix),
        };
    }
};

pub fn parse(s: []const u8) ?Cidr {
    const slash = mem.findScalar(u8, s, '/');
    const addr_str = s[0 .. slash orelse s.len];
    var address: Address = if (mem.findScalar(u8, addr_str, ':') != null)
        .{ .ip6 = std.Io.net.Ip6Address.parse(addr_str, 0) catch return null }
    else
        .{ .ip4 = std.Io.net.Ip4Address.parse(addr_str, 0) catch return null };
    const bytes: []u8 = switch (address) {
        .ip4 => |*a| &a.bytes,
        .ip6 => |*a| &a.bytes,
    };
    const bits: u8 = @intCast(bytes.len * 8);
    const prefix = if (slash) |i| std.fmt.parseInt(u8, s[i + 1 ..], 10) catch return null else bits;
    if (prefix > bits) return null;
    normalizeInPlace(bytes, prefix);
    return .{ .address = address, .prefix = prefix };
}

pub fn allow(entries: []const Cidr, addr: Address) bool {
    for (entries) |e| if (e.matches(addr)) return true;
    return false;
}

fn netmaskByte(rem: u3) u8 {
    return ~(@as(u8, 0xFF) >> rem);
}

fn prefixMatch(addr: []const u8, network: []const u8, prefix: u8) bool {
    std.debug.assert(addr.len == network.len);
    const full = prefix / 8;
    if (full > addr.len) return false;
    if (!mem.eql(u8, addr[0..full], network[0..full])) return false;
    const rem: u3 = @intCast(prefix % 8);
    if (rem == 0) return true;
    const mask = netmaskByte(rem);
    return (addr[full] & mask) == (network[full] & mask);
}

fn normalizeInPlace(buf: []u8, prefix: u8) void {
    const full = prefix / 8;
    const rem: u3 = @intCast(prefix % 8);
    if (full < buf.len) {
        if (rem == 0) {
            for (buf[full..]) |*b| b.* = 0;
        } else {
            buf[full] &= netmaskByte(rem);
            for (buf[full + 1 ..]) |*b| b.* = 0;
        }
    }
}

const testing = std.testing;

fn ip4(bytes: [4]u8) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = 0 } };
}

fn ip6(bytes: [16]u8) Address {
    return .{ .ip6 = .{ .bytes = bytes, .port = 0 } };
}

test "parse v4 normalizes host bits" {
    const c = parse("192.168.1.255/24") orelse return error.ParseFailed;
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 0 }, &c.address.ip4.bytes);
}

test "parse bare v4 address is /32" {
    const c = parse("10.0.0.5") orelse return error.ParseFailed;
    try testing.expectEqual(@as(u8, 32), c.prefix);
}

test "parse rejects invalid prefix" {
    try testing.expect(parse("10.0.0.0/33") == null);
    try testing.expect(parse("::1/129") == null);
    try testing.expect(parse("garbage") == null);
}

test "matchesBytes accepts bare rdata bytes" {
    const v4 = parse("10.0.0.0/8") orelse return error.ParseFailed;
    try testing.expect(v4.matchesBytes(&[_]u8{ 10, 1, 2, 3 }));
    try testing.expect(!v4.matchesBytes(&[_]u8{ 11, 1, 2, 3 }));
    try testing.expect(!v4.matchesBytes(&@as([16]u8, @splat(0))));

    const v6 = parse("fc00::/7") orelse return error.ParseFailed;
    try testing.expect(v6.matchesBytes(&([_]u8{0xfc} ++ @as([15]u8, @splat(0)))));
    try testing.expect(v6.matchesBytes(&([_]u8{0xfd} ++ @as([15]u8, @splat(0)))));
    try testing.expect(!v6.matchesBytes(&([_]u8{0xfe} ++ @as([15]u8, @splat(0)))));
    try testing.expect(!v6.matchesBytes(&[_]u8{ 1, 2, 3, 4 }));
}
