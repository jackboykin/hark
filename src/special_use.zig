/// RFC 6761 special-use domain names: short-circuit resolution before any
/// upstream traffic. Names that the spec reserves to never reach DNS leak
/// queries (and DNS metadata) to the root if not intercepted.
///
/// Coverage:
///   localhost.            RFC 6761 §6.3   → 127.0.0.1 / ::1 / NODATA
///   *.localhost.          RFC 6761 §6.3   → same as parent
///   invalid.              RFC 6761 §6.4   → NXDOMAIN
///   test.                 RFC 6761 §6.2   → NXDOMAIN
///   home.arpa.            RFC 8375 §4.4.B → RFC 6303 §3 empty zone; DS with
///                                           DO real
///   service.arpa.         RFC 9665 §8.4   → the same
///   onion.                RFC 7686 §2     → NXDOMAIN
///   ipv4only.arpa.        RFC 8880 §7.1   → A 192.0.0.170/171, else NODATA
///                                           (DS real, subdomains NXDOMAIN)
///
/// Only home.arpa and service.arpa are specified as zones. The rest are
/// hark's own synthesis, AA clear and SOA-less: their RFCs want answers
/// (RFC 6761 §6.3, RFC 7686 §2, RFC 8880 §7.2) no SOA could agree with.
///
/// Only forwarders must pass `ipv4only.arpa` to an upstream DNS64; hark
/// never forwards, and NODATA for AAAA means "no NAT64" to a stub.
///
/// Deliberately *not* short-circuited:
///   example. / example.{com,net,org}   IANA-hosted; authoritative answers
///                                      already correct, intercepting
///                                      breaks documentation tests.
const std = @import("std");
const mem = std.mem;
const dns = @import("dns.zig");

pub const Own = struct {
    is: union(enum) {
        nxdomain,
        nodata,
        answer: []const dns.RData,
    },
    zone: ?*const Zone = null,
};

pub const Zone = struct {
    apex: dns.Name,
    soa: []const dns.RData,
    ns: []const dns.RData,

    fn of(comptime apex: []const []const u8) Zone {
        const name: dns.Name = .{ .labels = apex };
        const nobody: dns.Name = .{ .labels = &.{ "nobody", "invalid" } };
        return .{
            .apex = name,
            .soa = &.{.{ .soa = .{ .mname = name, .rname = nobody, .serial = 1, .refresh = 3600, .retry = 1200, .expire = 604800, .minimum = ttl } }},
            .ns = &.{.{ .ns = name }},
        };
    }
};

const own_zones = [_]Zone{ .of(&.{ "home", "arpa" }), .of(&.{ "service", "arpa" }) };

const loopback4: []const dns.RData = &.{.{ .a = .{ 127, 0, 0, 1 } }};
const loopback6: []const dns.RData = &.{.{ .aaaa = @as([15]u8, @splat(0)) ++ [_]u8{1} }};
/// RFC 7050 §8.
const ipv4only: []const dns.RData = &.{ .{ .a = .{ 192, 0, 0, 170 } }, .{ .a = .{ 192, 0, 0, 171 } } };

/// hark's own answer to the question, or null: ask the DNS.
pub fn classify(name: dns.Name, qtype: dns.RType, do_bit: bool) ?Own {
    const n = name.labels.len;
    if (n == 0) return null;
    const last = name.labels[n - 1];
    if (is(last, "localhost")) return switch (qtype) {
        .a => .{ .is = .{ .answer = loopback4 } },
        .aaaa => .{ .is = .{ .answer = loopback6 } },
        else => .{ .is = .nodata },
    };
    if (is(last, "invalid") or is(last, "test") or is(last, "onion")) return .{ .is = .nxdomain };
    if (!is(last, "arpa") or n < 2) return null;
    const second = name.labels[n - 2];
    for (&own_zones) |*z| if (is(second, z.apex.labels[0])) {
        if (n > 2) return .{ .is = .nxdomain, .zone = z };
        return switch (qtype) {
            .soa => .{ .is = .{ .answer = z.soa }, .zone = z },
            .ns => .{ .is = .{ .answer = z.ns }, .zone = z },
            // arpa delegates the apex, and its DS is asked there, with DO
            // and only then.
            .ds => if (do_bit) null else .{ .is = .nodata, .zone = z },
            else => .{ .is = .nodata, .zone = z },
        };
    };
    if (is(second, "ipv4only")) {
        if (n > 2) return .{ .is = .nxdomain };
        return switch (qtype) {
            .a => .{ .is = .{ .answer = ipv4only } },
            .ds => null,
            else => .{ .is = .nodata },
        };
    }
    return null;
}

/// At or below a name whose answer its RFC fixes, which no operator may
/// send elsewhere: localhost (RFC 6761 §6.3), invalid (§6.4), onion (RFC
/// 7686 §2), ipv4only.arpa (RFC 8880 §7.1). test is the operator's "by
/// default" only (RFC 6761 §6.2); home.arpa and service.arpa may be
/// served (RFC 8375 §4.4.B, RFC 6303 §3).
pub fn fixed(name: dns.Name) bool {
    const n = name.labels.len;
    if (n == 0) return false;
    const last = name.labels[n - 1];
    if (is(last, "localhost") or is(last, "invalid") or is(last, "onion")) return true;
    return n >= 2 and is(last, "arpa") and is(name.labels[n - 2], "ipv4only");
}

fn is(label: []const u8, word: []const u8) bool {
    return std.ascii.eqlIgnoreCase(label, word);
}

/// hark's own reply to a special-use name.
pub const Synthesized = struct {
    rcode: dns.RCode = .no_error,
    aa: bool = false,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
};

pub fn synthesize(allocator: mem.Allocator, q: dns.Question, own: Own) !Synthesized {
    var out: Synthesized = .{ .aa = own.zone != null };
    switch (own.is) {
        .nxdomain, .nodata => {
            if (own.is == .nxdomain) out.rcode = .name_error;
            const z = own.zone orelse return out;
            out.authorities = try records(allocator, z.apex, .soa, z.soa);
        },
        // Lowercased, as every owner from upstream is.
        .answer => |rdatas| out.answers = try records(allocator, try dns.cloneNameLower(allocator, q.name), q.qtype, rdatas),
    }
    return out;
}

fn records(allocator: mem.Allocator, owner: dns.Name, rtype: dns.RType, rdatas: []const dns.RData) ![]const dns.ResourceRecord {
    const rrs = try allocator.alloc(dns.ResourceRecord, rdatas.len);
    for (rrs, rdatas) |*rr, rdata| rr.* = .{ .name = owner, .rtype = rtype, .rclass = .in, .ttl = ttl, .rdata = rdata };
    return rrs;
}

/// RFC 6303 §3's TTL, for every answer hark makes itself.
const ttl: u32 = 10800;

const testing = std.testing;

fn expectOwn(want: ?Own, name: []const u8, qtype: dns.RType) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(want, classify(try dns.parseDottedName(arena.allocator(), name), qtype, true));
}

test "classify localhost A → loopback" {
    try expectOwn(.{ .is = .{ .answer = loopback4 } }, "localhost.", .a);
    try expectOwn(.{ .is = .{ .answer = loopback4 } }, "LocalHost", .a);
    try expectOwn(.{ .is = .{ .answer = loopback6 } }, "localhost.", .aaaa);
    try expectOwn(.{ .is = .nodata }, "localhost.", .mx);
    try expectOwn(.{ .is = .{ .answer = loopback4 } }, "foo.localhost.", .a);
}

test "classify NXDOMAIN names" {
    try expectOwn(.{ .is = .nxdomain }, "invalid.", .a);
    try expectOwn(.{ .is = .nxdomain }, "foo.bar.invalid", .aaaa);
    try expectOwn(.{ .is = .nxdomain }, "test.", .a);
    try expectOwn(.{ .is = .nxdomain }, "something.onion.", .a);
    try expectOwn(.{ .is = .nxdomain, .zone = &own_zones[0] }, "foo.home.arpa", .aaaa);
}

test "classify ipv4only.arpa: DS falls through, apex is not its own subdomain" {
    try expectOwn(.{ .is = .{ .answer = ipv4only } }, "ipv4only.arpa.", .a);
    try expectOwn(null, "ipv4only.arpa.", .ds);
    try expectOwn(.{ .is = .nxdomain }, "foo.ipv4only.arpa.", .ds);
}

test "classify no match falls through" {
    try expectOwn(null, "example.com.", .a);
    try expectOwn(null, "invalidish.example.com", .a);
    try expectOwn(null, "notlocalhost.", .a);
    try expectOwn(null, "testing.com", .a);
    try expectOwn(null, "arpa", .a);
    // A literal dot inside a label is not a subdomain boundary: `foo\.invalid`
    // is one label and must resolve, not synthesize NXDOMAIN.
    try expectOwn(null, "foo\\.invalid", .a);
    try expectOwn(null, "bar\\.test.example.com", .a);
    // ...but an escaped backslash before the dot leaves it a real boundary.
    try expectOwn(.{ .is = .nxdomain }, "x\\\\.invalid", .a);
}

test "synthesize localhost A produces 127.0.0.1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const q: dns.Question = .{ .name = try dns.parseDottedName(arena.allocator(), "LocalHost."), .qtype = .a, .qclass = .in };
    const msg = try synthesize(arena.allocator(), q, classify(q.name, q.qtype, false).?);
    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    try testing.expectEqual(dns.RCode.no_error, msg.rcode);
    try testing.expect(!msg.aa);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &msg.answers[0].rdata.a);
    try testing.expectEqualStrings("localhost", msg.answers[0].name.labels[0]);
}
