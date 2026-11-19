//! The zones hark holds itself: names whose answers an RFC fixes, kept as
//! zone data and answered under the ordinary rules for NXDOMAIN, NODATA and
//! a DS.

const std = @import("std");
const mem = std.mem;
const dns = @import("dns.zig");

pub const Zone = struct {
    /// The zone whose data this is. hark holds it at and below `top`, which
    /// sits below the apex where an RFC fixes part of its parent's namespace.
    zone: dns.Name,
    top: dns.Name,
    records: []const Record = &.{},
    /// Every name below `top` answers as `top` (RFC 6761 §6.3).
    flat: bool = false,
    /// A stub zone the operator names takes these names over; config refuses
    /// one over the rest, whose RFCs fix their answers outright.
    default: bool = false,
    /// The apex's DS leaves for the parent only for a DO asker, whose answer
    /// must prove; any other DS question is the zone's own (RFC 8375 §4.4.B).
    ds_needs_do: bool = false,

    fn empty(comptime apex: []const u8) Zone {
        const name: dns.Name = .lit(apex);
        const soa: dns.RData = .{ .soa = .{ .mname = name, .rname = .lit("nobody.invalid"), .serial = 1, .refresh = 3600, .retry = 1200, .expire = 604800, .minimum = ttl } };
        return .{ .zone = name, .top = name, .default = true, .ds_needs_do = true, .records = &.{
            .{ .owner = name, .rtype = .soa, .rdata = soa },
            .{ .owner = name, .rtype = .ns, .rdata = .{ .ns = name } },
        } };
    }
};

const Record = struct {
    owner: dns.Name,
    rtype: dns.RType,
    rdata: dns.RData,
};

const localhost: dns.Name = .lit("localhost");
const ipv4only: dns.Name = .lit("ipv4only.arpa");

// Only home.arpa and service.arpa hold their SOA, so only they answer as a
// zone, with AA and the SOA in a denial. The rest get neither: their RFCs fix
// answers no SOA could agree with.
const zones = [_]Zone{
    // RFC 6761 §6.3, §6.4, §6.2 and RFC 7686 §2 fix names in the root's
    // namespace, so the DS at each is the root's, held here too.
    .{ .zone = .root, .top = localhost, .flat = true, .records = &.{
        .{ .owner = localhost, .rtype = .a, .rdata = .{ .a = .{ 127, 0, 0, 1 } } },
        .{ .owner = localhost, .rtype = .aaaa, .rdata = .{ .aaaa = @as([15]u8, @splat(0)) ++ [_]u8{1} } },
    } },
    .{ .zone = .root, .top = .lit("invalid") },
    .{ .zone = .root, .top = .lit("test"), .default = true },
    .{ .zone = .root, .top = .lit("onion") },
    // RFC 8375 §4.4.B, and RFC 9665 §8.4 in the same words.
    .empty("home.arpa"),
    .empty("service.arpa"),
    // RFC 8880 §7.1.
    .{ .zone = ipv4only, .top = ipv4only, .records = &.{
        .{ .owner = ipv4only, .rtype = .a, .rdata = .{ .a = .{ 192, 0, 0, 170 } } },
        .{ .owner = ipv4only, .rtype = .a, .rdata = .{ .a = .{ 192, 0, 0, 171 } } },
    } },
};

fn holding(name: dns.Name) ?*const Zone {
    for (&zones) |*z| if (name.isSubdomainOf(z.top)) return z;
    return null;
}

/// Names whose answer an RFC fixes, which no operator may send elsewhere.
pub fn fixed(name: dns.Name) bool {
    const z = holding(name) orelse return false;
    return !z.default;
}

pub fn answering(name: dns.Name, qtype: dns.RType, do_bit: bool) ?*const Zone {
    const z = holding(name) orelse return null;
    // A DS is its parent's data (RFC 4035 §2.4): at an apex it is asked there.
    const parents = qtype == .ds and name.eql(z.zone);
    return if (parents and (do_bit or !z.ds_needs_do)) null else z;
}

pub const Synthesized = struct {
    rcode: dns.RCode = .no_error,
    aa: bool = false,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
};

pub fn answer(arena: mem.Allocator, z: *const Zone, q: dns.Question) !Synthesized {
    const at = if (z.flat) z.top else q.name;
    const soa = try records(arena, z, z.zone, z.zone, .soa);
    var out: Synthesized = .{ .aa = soa.len > 0, .authorities = soa };
    for (z.records) |r| {
        if (r.owner.isSubdomainOf(at)) break;
    } else {
        out.rcode = .name_error;
        return out;
    }
    out.answers = try records(arena, z, at, q.name, q.qtype);
    if (out.answers.len > 0) out.authorities = &.{};
    return out;
}

fn records(arena: mem.Allocator, z: *const Zone, at: dns.Name, owner: dns.Name, rtype: dns.RType) ![]const dns.ResourceRecord {
    var rrs: std.ArrayList(dns.ResourceRecord) = .empty;
    for (z.records) |r| if (r.rtype == rtype and r.owner.eql(at))
        try rrs.append(arena, try .init(arena, .{ .name = owner, .rtype = rtype, .rclass = .in, .ttl = ttl, .rdata = r.rdata }));
    return rrs.items;
}

const ttl: u32 = 10800;

const testing = std.testing;

const Expect = struct { rcode: dns.RCode = .no_error, answers: usize = 0 };

fn expectAnswer(want: ?Expect, name: []const u8, qtype: dns.RType) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const q: dns.Question = .{ .name = try dns.parseDottedName(arena.allocator(), name), .qtype = qtype, .qclass = .in };
    const z = answering(q.name, qtype, true) orelse return testing.expectEqual(null, want);
    const got = try answer(arena.allocator(), z, q);
    try testing.expectEqual(want, Expect{ .rcode = got.rcode, .answers = got.answers.len });
    try testing.expect(!got.aa and got.authorities.len == 0);
    for (got.answers) |rr| try testing.expect(rr.name.eql(q.name));
}

test "localhost and every name below it are loopback" {
    try expectAnswer(.{ .answers = 1 }, "LocalHost", .a);
    try expectAnswer(.{ .answers = 1 }, "localhost.", .aaaa);
    try expectAnswer(.{}, "localhost.", .mx);
    try expectAnswer(.{}, "localhost.", .ds);
    try expectAnswer(.{ .answers = 1 }, "a.*.foo.localhost.", .a);
}

test "names an RFC denies are denied, their DS too" {
    try expectAnswer(.{ .rcode = .name_error }, "invalid.", .a);
    try expectAnswer(.{ .rcode = .name_error }, "test.", .ds);
    try expectAnswer(.{ .rcode = .name_error }, "something.onion.", .a);
}

test "ipv4only.arpa: its DS is arpa's, and nothing is below it" {
    try expectAnswer(.{ .answers = 2 }, "ipv4only.arpa.", .a);
    try expectAnswer(.{}, "ipv4only.arpa.", .txt);
    try expectAnswer(null, "ipv4only.arpa.", .ds);
    try expectAnswer(.{ .rcode = .name_error }, "foo.ipv4only.arpa.", .ds);
}

test "a name hark does not hold falls through" {
    try expectAnswer(null, "example.com.", .a);
    try expectAnswer(null, "arpa", .a);
}
