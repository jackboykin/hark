/// RFC 6761 special-use domain names: short-circuit resolution before any
/// upstream traffic. Names that the spec reserves to never reach DNS leak
/// queries (and DNS metadata) to the root if not intercepted.
///
/// Coverage:
///   localhost.            RFC 6761 §6.3   → 127.0.0.1 / ::1 / NODATA
///   *.localhost.          RFC 6761 §6.3   → same as parent
///   invalid.              RFC 6761 §6.4   → NXDOMAIN
///   test.                 RFC 6761 §6.2   → NXDOMAIN
///   home.arpa.            RFC 8375 §3     → NXDOMAIN (DNS-context only)
///   onion.                RFC 7686 §2     → NXDOMAIN
///   127.in-addr.arpa.     RFC 6761 §6.3   → PTR localhost.
///   <::1>.ip6.arpa.       RFC 6761 §6.3   → PTR localhost.
///
/// Deliberately *not* short-circuited:
///   example. / example.{com,net,org}   IANA-hosted; authoritative answers
///                                      already correct, intercepting
///                                      breaks documentation tests.
const std = @import("std");
const mem = std.mem;
const dns = @import("dns.zig");
const synthesizedMessage = @import("response.zig").synthesizedMessage;

pub const Action = enum {
    /// Not a special-use name — fall through to normal resolution.
    none,
    /// RFC 1035 §4.1.1 NXDOMAIN. No SOA synthesized; client gets RA-only.
    nxdomain,
    /// Synthesize an A record for 127.0.0.1.
    localhost_a,
    /// Synthesize an AAAA record for ::1.
    localhost_aaaa,
    /// Synthesize a PTR record pointing at localhost.
    localhost_ptr,
    /// NOERROR with empty answer (the name exists but the qtype does not).
    nodata,
};

const localhost_label = "localhost";

/// Classify a query against the RFC 6761 special-use table.
pub fn classify(name: []const u8, qtype: dns.RType) Action {
    // Strip a single trailing dot so "localhost." and "localhost" match.
    const stripped = if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;

    if (eqlOrSubdomainOf(stripped, localhost_label)) {
        return switch (qtype) {
            .a => .localhost_a,
            .aaaa => .localhost_aaaa,
            else => .nodata,
        };
    }

    if (eqlOrSubdomainOf(stripped, "invalid")) return .nxdomain;
    if (eqlOrSubdomainOf(stripped, "test")) return .nxdomain;
    if (eqlOrSubdomainOf(stripped, "onion")) return .nxdomain;
    if (eqlOrSubdomainOf(stripped, "home.arpa")) return .nxdomain;

    // 127.0.0.0/8 reverse — RFC 6761 §6.3 says any 127/8 PTR resolves to
    // localhost. (The narrower 1.0.0.127 special case is generalised here.)
    if (eqlOrSubdomainOf(stripped, "127.in-addr.arpa")) {
        return if (qtype == .ptr) .localhost_ptr else .nodata;
    }
    // ::1 reverse — 32 zero nibbles + 1 + ip6.arpa.
    if (std.ascii.eqlIgnoreCase(stripped, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa")) {
        return if (qtype == .ptr) .localhost_ptr else .nodata;
    }

    return .none;
}

/// `name` equals `tail` or is a subdomain of it. Both parameters are
/// expected without trailing dot. ASCII case-insensitive.
fn eqlOrSubdomainOf(name: []const u8, tail: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, tail)) return true;
    if (name.len <= tail.len + 1) return false;
    if (name[name.len - tail.len - 1] != '.') return false;
    return std.ascii.eqlIgnoreCase(name[name.len - tail.len ..], tail);
}

/// Synthesize a complete dns.Message for the matched action. The returned
/// records reference allocator-owned memory; caller (the resolver) typically
/// passes its per-query arena.
pub fn synthesize(
    allocator: mem.Allocator,
    name: []const u8,
    action: Action,
) !dns.Message {
    std.debug.assert(action != .none);
    // Lowercase the client-typed name so synthesized owners match the
    // `tryParseMessage` scrub policy.
    var lower_buf: [dns.max_name_len + 1]u8 = undefined;
    if (name.len > lower_buf.len) return error.NameTooLong;
    const lower = dns.lowerNameIntoBuf(&lower_buf, name);
    const qname = try dns.parseDottedName(allocator, lower);

    var answers: []dns.ResourceRecord = &.{};
    var rcode: dns.RCode = .no_error;

    switch (action) {
        .none => unreachable,
        .nxdomain => rcode = .name_error,
        .nodata => {},
        .localhost_a => {
            const arr = try allocator.alloc(dns.ResourceRecord, 1);
            arr[0] = .{
                .name = qname,
                .rtype = .a,
                .rclass = .in,
                .ttl = ttl_localhost,
                .rdata = .{ .a = .{ 127, 0, 0, 1 } },
            };
            answers = arr;
        },
        .localhost_aaaa => {
            const arr = try allocator.alloc(dns.ResourceRecord, 1);
            const aaaa = [_]u8{0} ** 15 ++ [_]u8{1};
            arr[0] = .{
                .name = qname,
                .rtype = .aaaa,
                .rclass = .in,
                .ttl = ttl_localhost,
                .rdata = .{ .aaaa = aaaa },
            };
            answers = arr;
        },
        .localhost_ptr => {
            const arr = try allocator.alloc(dns.ResourceRecord, 1);
            const target = try dns.parseDottedName(allocator, "localhost.");
            arr[0] = .{
                .name = qname,
                .rtype = .ptr,
                .rclass = .in,
                .ttl = ttl_localhost,
                .rdata = .{ .ptr = target },
            };
            answers = arr;
        },
    }

    return synthesizedMessage(answers, &.{}, rcode, false);
}

/// Synthetic responses are stable forever — RFC 6761 names cannot be
/// re-delegated without an RFC update. Use a long TTL.
const ttl_localhost: u32 = 86_400;

const testing = std.testing;

test "classify localhost A → loopback" {
    try testing.expectEqual(Action.localhost_a, classify("localhost.", .a));
    try testing.expectEqual(Action.localhost_a, classify("localhost", .a));
    try testing.expectEqual(Action.localhost_a, classify("LocalHost", .a));
    try testing.expectEqual(Action.localhost_aaaa, classify("localhost.", .aaaa));
    try testing.expectEqual(Action.nodata, classify("localhost.", .mx));
    try testing.expectEqual(Action.localhost_a, classify("foo.localhost.", .a));
}

test "classify NXDOMAIN names" {
    try testing.expectEqual(Action.nxdomain, classify("invalid.", .a));
    try testing.expectEqual(Action.nxdomain, classify("foo.bar.invalid", .aaaa));
    try testing.expectEqual(Action.nxdomain, classify("test.", .a));
    try testing.expectEqual(Action.nxdomain, classify("something.onion.", .a));
    try testing.expectEqual(Action.nxdomain, classify("home.arpa.", .a));
    try testing.expectEqual(Action.nxdomain, classify("foo.home.arpa", .aaaa));
}

test "classify reverse 127/8 PTR → localhost" {
    try testing.expectEqual(Action.localhost_ptr, classify("1.0.0.127.in-addr.arpa.", .ptr));
    try testing.expectEqual(Action.localhost_ptr, classify("100.50.0.127.in-addr.arpa", .ptr));
}

test "classify ::1 reverse PTR → localhost" {
    const ipv6_one_rev = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
    try testing.expectEqual(Action.localhost_ptr, classify(ipv6_one_rev, .ptr));
}

test "classify no match falls through" {
    try testing.expectEqual(Action.none, classify("example.com.", .a));
    try testing.expectEqual(Action.none, classify("invalidish.example.com", .a));
    // notlocalhost should not match localhost (suffix-of-label, not subdomain)
    try testing.expectEqual(Action.none, classify("notlocalhost.", .a));
    // testing. is not test. (the dot boundary matters)
    try testing.expectEqual(Action.none, classify("testing.com", .a));
}

test "synthesize localhost A produces 127.0.0.1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try synthesize(arena.allocator(), "localhost.", .localhost_a);
    try testing.expectEqual(@as(u16, 1), msg.header.an_count);
    try testing.expectEqual(dns.RCode.no_error, msg.header.flags.rcode);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &msg.answers[0].rdata.a);
}

test "synthesize nxdomain has no answers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try synthesize(arena.allocator(), "invalid.", .nxdomain);
    try testing.expectEqual(dns.RCode.name_error, msg.header.flags.rcode);
    try testing.expectEqual(@as(u16, 0), msg.header.an_count);
}
