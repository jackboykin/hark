//! The delegation walk's pure decisions: QNAME minimisation, zone cuts, and
//! which sibling failure a stub sees.
const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const na = @import("net_address.zig");

pub const max_servers_per_level = 26;
/// QMIN probe ceiling; past it, queries go straight to the full qname
/// (RFC 9156's MAX_MINIMIZE_COUNT).
pub const max_minimize_count = 10;

/// What a minimised probe's reply does to the walk.
pub const ProbeStep = union(enum) {
    referral: Referral,
    /// Stop minimising (RFC 9156 relaxed mode).
    nxdomain,
    nodata,
    answered,
    failed,
};

pub fn probeStep(response: dns.Message, target: dns.Name, zone: dns.Name, policy: AddrPolicy) ProbeStep {
    switch (response.header.flags.rcode) {
        // Error replies can carry authority NS that delegate nothing.
        .no_error => {},
        .name_error => return .nxdomain,
        else => return .failed,
    }
    if (extractReferral(response, target, zone, policy)) |referral| return .{ .referral = referral };
    return if (response.answers.len > 0) .answered else .nodata;
}

/// Names and addresses borrow from the response.
pub const Referral = struct {
    zone_cut: dns.Name,
    /// Names with glue come first; `unglued()` is the rest.
    ns_names: [max_servers_per_level]dns.Name,
    ns_count: usize,
    glued: usize,
    addrs: [max_servers_per_level]na.Address,
    ttls: [max_servers_per_level]u32,
    addr_count: usize,

    pub fn nsNames(r: *const Referral) []const dns.Name {
        return r.ns_names[0..r.ns_count];
    }

    pub fn unglued(r: *const Referral) []const dns.Name {
        return r.ns_names[r.glued..r.ns_count];
    }
};

/// Address-construction policy applied when materializing referral glue.
/// Defaults are production-safe; tests override to redirect at scripted
/// authorities on non-privileged ports in 127/8.
pub const AddrPolicy = struct {
    upstream_port: u16 = 53,
    allow_loopback: bool = false,

    pub fn address(policy: AddrPolicy, rr: dns.ResourceRecord) ?na.Address {
        const addr = switch (rr.rtype) {
            .a => na.initIp4(rr.rdata.a, policy.upstream_port),
            .aaaa => na.initIp6(rr.rdata.aaaa, policy.upstream_port, 0, 0),
            else => return null,
        };
        return if (!policy.allow_loopback and na.isNonRoutableNs(addr)) null else addr;
    }
};

pub fn extractReferral(
    response: dns.Message,
    target: dns.Name,
    parent_zone: dns.Name,
    policy: AddrPolicy,
) ?Referral {
    var zone_cut: ?dns.Name = null;
    var zone_cut_depth: usize = 0;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and target.isSubdomainOf(rr.name)) {
            if (zone_cut == null or rr.name.labels.len > zone_cut_depth) {
                zone_cut = rr.name;
                zone_cut_depth = rr.name.labels.len;
            }
        }
    }
    const zc = zone_cut orelse return null;

    // A valid referral always delegates to a child zone — the zone cut must
    // be strictly deeper than the current parent zone.  If the authority
    // section contains NS records for the same zone (or a parent), it is
    // not a referral (e.g. a server returning its own NS records alongside
    // a CNAME answer).  RFC 1034 §4.2.1, RFC 8499 §7.
    if (zc.labels.len <= parent_zone.labels.len) return null;

    var ns_count: usize = 0;
    var ns_names: [max_servers_per_level]dns.Name = undefined;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and rr.name.eql(zc)) {
            if (ns_count < max_servers_per_level) {
                ns_names[ns_count] = rr.rdata.ns;
                ns_count += 1;
            }
        }
    }

    var glue_addrs: [max_servers_per_level]na.Address = undefined;
    var glue_ttls: [max_servers_per_level]u32 = undefined;
    var glue_count: usize = 0;
    var glued: usize = 0;
    for (response.additionals) |rr| {
        if (rr.rtype != .a and rr.rtype != .aaaa) continue;
        // Bailiwick: glue name must be within the parent zone (the zone
        // the referring server is authoritative for). `isSubdomainOf`
        // already returns true when parent is root, so all glue is
        // accepted under root referrals.
        if (!rr.name.isSubdomainOf(parent_zone)) continue;

        for (ns_names[0..ns_count], 0..) |ns_name, i| {
            if (ns_name.eql(rr.name)) {
                if (glue_count < max_servers_per_level) {
                    glue_addrs[glue_count] = policy.address(rr) orelse break;
                    glue_ttls[glue_count] = rr.ttl;
                    glue_count += 1;
                    if (i >= glued) {
                        mem.swap(dns.Name, &ns_names[i], &ns_names[glued]);
                        glued += 1;
                    }
                }
                break;
            }
        }
    }
    return .{
        .zone_cut = zc,
        .ns_names = ns_names,
        .ns_count = ns_count,
        .glued = glued,
        .addrs = glue_addrs,
        .ttls = glue_ttls,
        .addr_count = glue_count,
    };
}

/// A lame sibling's referral when the cut is `zone` itself, read from
/// `zone`'s parent. .fr and afnic.fr share g.ext.nic.fr but not d.nic.fr.
pub fn referralAtCut(response: dns.Message, zone: dns.Name, policy: AddrPolicy) ?Referral {
    if (response.header.flags.aa or response.answers.len != 0 or zone.labels.len == 0) return null;
    return extractReferral(response, zone, .{ .labels = zone.labels[1..] }, policy);
}

/// RFC 1034 §4.3.5: drop this reply and ask a sibling. SERVFAIL, REFUSED
/// and FORMERR (hark never retries without EDNS); a lame reply, non-AA
/// NOERROR with no answer, no SOA and no cut below `parent_zone`; a
/// recursor's cache, RA set and AA clear, which an RD-clear query gets
/// only from a server that recursed on its own. A recursor's referral
/// is still followed. validateResponse guarantees `questions[0]`.
pub fn shouldTrySibling(response: dns.Message, parent_zone: dns.Name, policy: AddrPolicy) bool {
    const flags = response.header.flags;
    const rec_lame = flags.ra and !flags.aa;
    switch (flags.rcode) {
        .server_failure, .refused, .format_error => return true,
        .name_error => return rec_lame,
        .no_error => {},
        else => return false,
    }
    if (flags.aa) return false;
    if (response.answers.len != 0) return rec_lame;
    for (response.authorities) |rr| if (rr.rtype == .soa) return rec_lame;
    return extractReferral(response, response.questions[0].name, parent_zone, policy) == null;
}

const test_header: dns.Header = .{
    .id = 0x1234,
    .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = false, .ra = false, .z = 0, .ad = false, .cd = false, .rcode = .no_error },
};

fn nsRr(zone: dns.Name, ns_name: dns.Name) dns.ResourceRecord {
    return .{ .name = zone, .rtype = .ns, .rclass = .in, .ttl = 172800, .rdata = .{ .ns = ns_name } };
}

fn glueA(name: dns.Name, addr: [4]u8) dns.ResourceRecord {
    return .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 172800, .rdata = .{ .a = addr } };
}

const root: dns.Name = .{ .labels = &.{} };
const example: dns.Name = .{ .labels = &.{ "example", "com" } };
const www: dns.Name = .{ .labels = &.{ "www", "example", "com" } };
const ns1: dns.Name = .{ .labels = &.{ "ns1", "example", "com" } };

fn reply(authorities: []const dns.ResourceRecord, additionals: []const dns.ResourceRecord) dns.Message {
    return .{ .header = test_header, .questions = &.{}, .authorities = authorities, .additionals = additionals };
}

test "shouldTrySibling: lame is empty non-AA NOERROR with no SOA and no referral" {
    const zone: dns.Name = .{ .labels = &.{"com"} };
    const questions: []const dns.Question = &.{.{ .name = www, .qtype = .a, .qclass = .in }};
    var msg = dns.Message{ .header = test_header, .questions = questions };
    try testing.expect(shouldTrySibling(msg, zone, .{}));

    msg.header.flags.aa = true;
    try testing.expect(!shouldTrySibling(msg, zone, .{}));
    msg.header.flags.aa = false;

    const soa = dns.ResourceRecord{ .name = zone, .rtype = .soa, .rclass = .in, .ttl = 600, .rdata = .{ .soa = .{ .mname = zone, .rname = zone, .serial = 1, .refresh = 1, .retry = 1, .expire = 1, .minimum = 600 } } };
    msg.authorities = &.{soa};
    try testing.expect(!shouldTrySibling(msg, zone, .{}));

    msg.authorities = &.{nsRr(www, zone)};
    try testing.expect(!shouldTrySibling(msg, zone, .{}));
    msg.authorities = &.{nsRr(.{ .labels = &.{"fake"} }, zone)};
    try testing.expect(shouldTrySibling(msg, zone, .{}));

    msg.authorities = &.{};
    msg.header.flags.rcode = .refused;
    try testing.expect(shouldTrySibling(msg, zone, .{}));
    msg.header.flags.rcode = .name_error;
    try testing.expect(!shouldTrySibling(msg, zone, .{}));

    msg.header.flags.ra = true;
    try testing.expect(shouldTrySibling(msg, zone, .{}));
    msg.header.flags.aa = true;
    try testing.expect(!shouldTrySibling(msg, zone, .{}));
    msg.header.flags.aa = false;
    msg.header.flags.rcode = .no_error;
    msg.authorities = &.{soa};
    try testing.expect(shouldTrySibling(msg, zone, .{}));
    msg.authorities = &.{};
    msg.answers = &.{glueA(www, .{ 10, 20, 30, 40 })};
    try testing.expect(shouldTrySibling(msg, zone, .{}));
    msg.header.flags.ra = false;
    try testing.expect(!shouldTrySibling(msg, zone, .{}));
}

test "probeStep: referral only from NOERROR, NXDOMAIN stops, NODATA and data step" {
    var msg = reply(&.{nsRr(example, ns1)}, &.{glueA(ns1, .{ 192, 0, 2, 1 })});
    try testing.expect(probeStep(msg, www, root, .{}) == .referral);

    msg.header.flags.rcode = .name_error;
    try testing.expect(probeStep(msg, www, root, .{}) == .nxdomain);
    msg.header.flags.rcode = .server_failure;
    try testing.expect(probeStep(msg, www, root, .{}) == .failed);

    msg.header.flags.rcode = .no_error;
    msg.authorities = &.{};
    try testing.expect(probeStep(msg, www, root, .{}) == .nodata);
    msg.answers = &.{glueA(example, .{ 192, 0, 2, 1 })};
    try testing.expect(probeStep(msg, www, root, .{}) == .answered);
}

test "referralAtCut refers from one label above the zone" {
    const zone: dns.Name = .{ .labels = &.{ "afnic", "fr" } };
    const ns: dns.Name = .{ .labels = &.{ "ns", "afnic", "fr" } };
    var msg = reply(&.{nsRr(zone, ns)}, &.{glueA(ns, .{ 1, 2, 3, 7 })});
    const r = referralAtCut(msg, zone, .{}) orelse return error.TestExpectedReferral;
    try testing.expect(r.zone_cut.eql(zone));
    try testing.expectEqual(@as(usize, 1), r.addr_count);

    msg.header.flags.aa = true;
    try testing.expect(referralAtCut(msg, zone, .{}) == null);
    msg.header.flags.aa = false;
    try testing.expect(referralAtCut(msg, root, .{}) == null);
}

test "extractReferral with NS and glue A records" {
    const result = extractReferral(reply(&.{nsRr(example, ns1)}, &.{glueA(ns1, .{ 1, 2, 3, 4 })}), www, root, .{}) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), result.addr_count);
    try testing.expectEqual(na.initIp4(.{ 1, 2, 3, 4 }, 53).ip4.bytes, result.addrs[0].ip4.bytes);
    try testing.expectEqual(@as(u16, 53), result.addrs[0].getPort());
    try testing.expect(result.zone_cut.eql(example));
}

test "extractReferral with no NS records returns null" {
    try testing.expect(extractReferral(reply(&.{}, &.{}), example, root, .{}) == null);
}

test "extractReferral with NS but no glue returns zero addrs" {
    const result = extractReferral(reply(&.{nsRr(example, ns1)}, &.{}), www, root, .{}) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 0), result.addr_count);
    try testing.expectEqual(@as(usize, 1), result.ns_count);
    try testing.expect(result.zone_cut.eql(example));
    try testing.expect(result.ns_names[0].eqlExact(ns1));
}

test "extractReferral case-insensitive glue matching" {
    const upper: dns.Name = .{ .labels = &.{ "NS1", "EXAMPLE", "COM" } };
    const result = extractReferral(reply(&.{nsRr(example, ns1)}, &.{glueA(upper, .{ 1, 2, 3, 4 })}), www, root, .{}) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), result.addr_count);
}

test "extractReferral rejects private IP glue (DNS rebinding defense)" {
    const result = extractReferral(reply(&.{nsRr(example, ns1)}, &.{glueA(ns1, .{ 127, 0, 0, 1 })}), www, root, .{}) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 0), result.addr_count);
}

test "extractReferral accepts loopback glue when policy.allow_loopback = true" {
    // Locks in the test-only opt-in branch: with allow_loopback=true,
    // loopback glue is *not* rejected. Without this test, inverting the
    // boolean default would silently pass every other test.
    const result = extractReferral(
        reply(&.{nsRr(example, ns1)}, &.{glueA(ns1, .{ 127, 0, 0, 1 })}),
        www,
        root,
        .{ .allow_loopback = true, .upstream_port = 5353 },
    ) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), result.addr_count);
    try testing.expectEqual(@as(u16, 5353), result.addrs[0].getPort());
}

test "extractReferral rejects out-of-zone glue" {
    const evil: dns.Name = .{ .labels = &.{ "ns1", "evil", "org" } };
    const result = extractReferral(reply(&.{nsRr(example, evil)}, &.{glueA(evil, .{ 6, 6, 6, 6 })}), www, .{ .labels = &.{"com"} }, .{}) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 0), result.addr_count);
}

test "extractReferral without glue carries multiple NS names" {
    const other1: dns.Name = .{ .labels = &.{ "ns1", "other", "net" } };
    const other2: dns.Name = .{ .labels = &.{ "ns2", "other", "net" } };
    const result = extractReferral(reply(&.{ nsRr(example, other1), nsRr(example, other2) }, &.{}), www, root, .{}) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 0), result.addr_count);
    try testing.expectEqual(@as(usize, 2), result.ns_count);
    try testing.expect(result.zone_cut.eql(example));
}

test "extractReferral with AAAA glue returns IPv6 address" {
    const ipv6 = [_]u8{ 0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const glue: dns.ResourceRecord = .{ .name = ns1, .rtype = .aaaa, .rclass = .in, .ttl = 172800, .rdata = .{ .aaaa = ipv6 } };
    const result = extractReferral(reply(&.{nsRr(example, ns1)}, &.{glue}), www, root, .{}) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), result.addr_count);
    try testing.expectEqual(@as(u16, 53), result.addrs[0].getPort());
    try testing.expectEqual(na.initIp6(ipv6, 53, 0, 0).ip6.bytes, result.addrs[0].ip6.bytes);
}

test "extractReferral rejects same-zone NS as non-referral" {
    // A server returning NS records for its own zone (e.g. alongside a CNAME
    // answer) is not a referral — the zone cut must be strictly deeper than
    // the parent zone.  RFC 1034 §4.2.1, RFC 8499 §7.
    const api: dns.Name = .{ .labels = &.{ "api", "example", "com" } };
    try testing.expect(extractReferral(reply(&.{nsRr(example, ns1)}, &.{glueA(ns1, .{ 192, 0, 2, 1 })}), api, example, .{}) == null);
}
