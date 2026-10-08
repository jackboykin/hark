/// RFC 6761 special-use domain names: short-circuit resolution before any
/// upstream traffic. Names that the spec reserves to never reach DNS leak
/// queries (and DNS metadata) to the root if not intercepted.
///
/// Coverage:
///   localhost.            RFC 6761 §6.3   → 127.0.0.1 / ::1 / NODATA
///   *.localhost.          RFC 6761 §6.3   → same as parent
///   invalid.              RFC 6761 §6.4   → NXDOMAIN
///   test.                 RFC 6761 §6.2   → NXDOMAIN
///   home.arpa.            RFC 8375 §4.4.B → NODATA, DS with DO real
///   *.home.arpa.          RFC 8375 §4.4.B → NXDOMAIN
///   onion.                RFC 7686 §2     → NXDOMAIN
///   ipv4only.arpa.        RFC 8880 §7.1   → A 192.0.0.170/171, else NODATA
///                                           (DS real, subdomains NXDOMAIN)
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

pub const Own = union(enum) {
    /// RFC 1035 §4.1.1 NXDOMAIN. No SOA synthesized; client gets RA-only.
    nxdomain,
    /// NOERROR with empty answer (the name exists but the qtype does not).
    nodata,
    answer: []const dns.RData,
};

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
        .a => .{ .answer = loopback4 },
        .aaaa => .{ .answer = loopback6 },
        else => .nodata,
    };
    if (is(last, "invalid") or is(last, "test") or is(last, "onion")) return .nxdomain;
    if (!is(last, "arpa") or n < 2) return null;
    const second = name.labels[n - 2];
    if (is(second, "home")) {
        if (n > 2) return .nxdomain;
        return if (qtype == .ds and do_bit) null else .nodata;
    }
    if (is(second, "ipv4only")) {
        if (n > 2) return .nxdomain;
        return switch (qtype) {
            .a => .{ .answer = ipv4only },
            .ds => null,
            else => .nodata,
        };
    }
    return null;
}

fn is(label: []const u8, word: []const u8) bool {
    return std.ascii.eqlIgnoreCase(label, word);
}

/// hark's own reply to a special-use name.
pub const Synthesized = struct {
    rcode: dns.RCode = .no_error,
    answers: []const dns.ResourceRecord = &.{},
};

pub fn synthesize(allocator: mem.Allocator, q: dns.Question, own: Own) !Synthesized {
    const rdatas = switch (own) {
        .nxdomain => return .{ .rcode = .name_error },
        .nodata => return .{},
        .answer => |rdatas| rdatas,
    };
    // Lowercase the client-typed name so synthesized owners match the
    // `tryParseMessage` scrub policy.
    const labels = try allocator.alloc([]const u8, q.name.labels.len);
    for (labels, q.name.labels) |*l, from| l.* = try std.ascii.allocLowerString(allocator, from);
    const answers = try allocator.alloc(dns.ResourceRecord, rdatas.len);
    for (answers, rdatas) |*rr, rdata| rr.* = .{ .name = .{ .labels = labels }, .rtype = q.qtype, .rclass = .in, .ttl = fixed_ttl, .rdata = rdata };
    return .{ .answers = answers };
}

const fixed_ttl: u32 = 86_400;

const testing = std.testing;

fn expectOwn(want: ?Own, name: []const u8, qtype: dns.RType) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(want, classify(try dns.parseDottedName(arena.allocator(), name), qtype, true));
}

test "classify localhost A → loopback" {
    try expectOwn(.{ .answer = loopback4 }, "localhost.", .a);
    try expectOwn(.{ .answer = loopback4 }, "LocalHost", .a);
    try expectOwn(.{ .answer = loopback6 }, "localhost.", .aaaa);
    try expectOwn(.nodata, "localhost.", .mx);
    try expectOwn(.{ .answer = loopback4 }, "foo.localhost.", .a);
}

test "classify NXDOMAIN names" {
    try expectOwn(.nxdomain, "invalid.", .a);
    try expectOwn(.nxdomain, "foo.bar.invalid", .aaaa);
    try expectOwn(.nxdomain, "test.", .a);
    try expectOwn(.nxdomain, "something.onion.", .a);
    try expectOwn(.nxdomain, "foo.home.arpa", .aaaa);
}

test "classify ipv4only.arpa: DS falls through, apex is not its own subdomain" {
    try expectOwn(.{ .answer = ipv4only }, "ipv4only.arpa.", .a);
    try expectOwn(null, "ipv4only.arpa.", .ds);
    try expectOwn(.nxdomain, "foo.ipv4only.arpa.", .ds);
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
    try expectOwn(.nxdomain, "x\\\\.invalid", .a);
}

test "synthesize localhost A produces 127.0.0.1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const q: dns.Question = .{ .name = try dns.parseDottedName(arena.allocator(), "LocalHost."), .qtype = .a, .qclass = .in };
    const msg = try synthesize(arena.allocator(), q, classify(q.name, q.qtype, false).?);
    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    try testing.expectEqual(dns.RCode.no_error, msg.rcode);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &msg.answers[0].rdata.a);
    try testing.expectEqualStrings("localhost", msg.answers[0].name.labels[0]);
}
