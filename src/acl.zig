/// CIDR-based access control. Used by the server's UDP and TCP
/// front-ends to enforce `[server].allow-from` from the operator's
/// config. An empty entry list means "no ACL" — every client allowed
/// (back-compatible default).
///
/// Scope: a recursive resolver bound to a public IP without an ACL is
/// an open recursive resolver and a reflection-amplification surface
/// (BCP 140). Default-loopback config keeps the absent-ACL case safe;
/// operators flipping listen= to a public address must opt in to a
/// CIDR list to deserve service.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const na = @import("net_address.zig");

pub const Family = enum(u8) { v4, v6 };

pub const Cidr = struct {
    /// Network bytes, normalised so all bits past `prefix` are zero.
    /// 4 bytes for v4, 16 for v6.
    bytes: [16]u8,
    prefix: u8,
    family: Family,

    pub fn matches(self: Cidr, addr: na.Address) bool {
        switch (addr) {
            .ip4 => |v4| {
                if (self.family != .v4) return false;
                return prefixMatch(&v4.bytes, self.bytes[0..4], self.prefix);
            },
            .ip6 => |v6| {
                if (self.family != .v6) return false;
                return prefixMatch(&v6.bytes, self.bytes[0..16], self.prefix);
            },
        }
    }
};

/// Parse "192.168.1.0/24" or "2001:db8::/32" into a Cidr. Bare addresses
/// take an implied /32 (v4) or /128 (v6).
pub fn parse(s: []const u8) ?Cidr {
    const slash = mem.indexOfScalar(u8, s, '/');
    const addr_str = if (slash) |i| s[0..i] else s;
    const prefix_str = if (slash) |i| s[i + 1 ..] else null;

    // v6 addresses contain ':'.
    if (mem.indexOfScalar(u8, addr_str, ':') != null) {
        const ip6 = std.Io.net.Ip6Address.parse(addr_str, 0) catch return null;
        const default_prefix: u8 = 128;
        const prefix = if (prefix_str) |p| std.fmt.parseInt(u8, p, 10) catch return null else default_prefix;
        if (prefix > 128) return null;
        var c = Cidr{ .bytes = .{0} ** 16, .prefix = prefix, .family = .v6 };
        @memcpy(&c.bytes, &ip6.bytes);
        normaliseInPlace(c.bytes[0..16], prefix);
        return c;
    }

    const ip4 = std.Io.net.Ip4Address.parse(addr_str, 0) catch return null;
    const default_prefix: u8 = 32;
    const prefix = if (prefix_str) |p| std.fmt.parseInt(u8, p, 10) catch return null else default_prefix;
    if (prefix > 32) return null;
    var c = Cidr{ .bytes = .{0} ** 16, .prefix = prefix, .family = .v4 };
    @memcpy(c.bytes[0..4], &ip4.bytes);
    normaliseInPlace(c.bytes[0..4], prefix);
    return c;
}

/// Returns true when `entries` is empty (back-compat: no ACL configured)
/// or when `addr` matches at least one entry.
pub fn allow(entries: []const Cidr, addr: na.Address) bool {
    if (entries.len == 0) return true;
    for (entries) |e| if (e.matches(addr)) return true;
    return false;
}

fn prefixMatch(addr: []const u8, network: []const u8, prefix: u8) bool {
    std.debug.assert(addr.len == network.len);
    const full = prefix / 8;
    if (full > addr.len) return false;
    if (!mem.eql(u8, addr[0..full], network[0..full])) return false;
    const rem: u3 = @intCast(prefix % 8);
    if (rem == 0) return true;
    const shift: u4 = @as(u4, 8) - @as(u4, rem);
    const mask: u8 = @truncate(@as(u16, 0xFF) << shift);
    return (addr[full] & mask) == (network[full] & mask);
}

fn normaliseInPlace(buf: []u8, prefix: u8) void {
    const full = prefix / 8;
    const rem: u3 = @intCast(prefix % 8);
    if (full < buf.len) {
        if (rem == 0) {
            for (buf[full..]) |*b| b.* = 0;
        } else {
            const shift: u4 = @as(u4, 8) - @as(u4, rem);
            const mask: u8 = @truncate(@as(u16, 0xFF) << shift);
            buf[full] &= mask;
            for (buf[full + 1 ..]) |*b| b.* = 0;
        }
    }
}

const testing = std.testing;

test "parse v4 with prefix" {
    const c = parse("192.168.1.0/24") orelse return error.ParseFailed;
    try testing.expectEqual(Family.v4, c.family);
    try testing.expectEqual(@as(u8, 24), c.prefix);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 0 }, c.bytes[0..4]);
}

test "parse v4 normalises host bits" {
    const c = parse("192.168.1.255/24") orelse return error.ParseFailed;
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 0 }, c.bytes[0..4]);
}

test "parse bare v4 address is /32" {
    const c = parse("10.0.0.5") orelse return error.ParseFailed;
    try testing.expectEqual(@as(u8, 32), c.prefix);
}

test "parse v6 with prefix" {
    const c = parse("2001:db8::/32") orelse return error.ParseFailed;
    try testing.expectEqual(Family.v6, c.family);
    try testing.expectEqual(@as(u8, 32), c.prefix);
}

test "parse rejects invalid prefix" {
    try testing.expect(parse("10.0.0.0/33") == null);
    try testing.expect(parse("::1/129") == null);
    try testing.expect(parse("garbage") == null);
}

test "matches v4 prefix" {
    const c = parse("192.168.1.0/24") orelse return error.ParseFailed;
    try testing.expect(c.matches(na.initIp4(.{ 192, 168, 1, 5 }, 0)));
    try testing.expect(c.matches(na.initIp4(.{ 192, 168, 1, 255 }, 0)));
    try testing.expect(!c.matches(na.initIp4(.{ 192, 168, 2, 0 }, 0)));
    try testing.expect(!c.matches(na.initIp4(.{ 10, 0, 0, 1 }, 0)));
}

test "matches /32 single host" {
    const c = parse("127.0.0.1/32") orelse return error.ParseFailed;
    try testing.expect(c.matches(na.initIp4(.{ 127, 0, 0, 1 }, 0)));
    try testing.expect(!c.matches(na.initIp4(.{ 127, 0, 0, 2 }, 0)));
}

test "matches v6 single host" {
    const c = parse("::1/128") orelse return error.ParseFailed;
    try testing.expect(c.matches(na.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 0, 0, 0)));
    try testing.expect(!c.matches(na.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, 0, 0, 0)));
}

test "matches family mismatch fails" {
    const v4 = parse("0.0.0.0/0") orelse return error.ParseFailed;
    try testing.expect(!v4.matches(na.initIp6(.{0} ** 16, 0, 0, 0)));
}

test "allow with empty entries permits all" {
    try testing.expect(allow(&.{}, na.initIp4(.{ 8, 8, 8, 8 }, 0)));
    try testing.expect(allow(&.{}, na.initIp6(.{0} ** 16, 0, 0, 0)));
}

test "allow returns false when no entry matches" {
    const c = parse("127.0.0.0/8") orelse return error.ParseFailed;
    const list = [_]Cidr{c};
    try testing.expect(!allow(&list, na.initIp4(.{ 8, 8, 8, 8 }, 0)));
    try testing.expect(allow(&list, na.initIp4(.{ 127, 1, 2, 3 }, 0)));
}
