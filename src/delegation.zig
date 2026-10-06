//! The delegation walk's pure decisions: QNAME minimisation, zone cuts, and
//! which sibling failure a stub sees.
const std = @import("std");
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
    /// Stop minimising; RFC 8020 when vouched for.
    nxdomain,
    nodata,
    answered,
    failed,
};

pub fn probeStep(response: dns.Message, target: dns.Name, zone: dns.Name) ProbeStep {
    switch (response.header.flags.rcode) {
        // Error replies can carry authority NS that delegate nothing.
        .no_error => {},
        .name_error => return .nxdomain,
        else => return .failed,
    }
    if (extractReferral(response, target, zone)) |referral| return .{ .referral = referral };
    return if (response.answers.len > 0) .answered else .nodata;
}

/// Borrows from the response.
pub const Referral = struct {
    zone_cut: dns.Name,
    ns_names: [max_servers_per_level]dns.Name,
    ns_count: usize,

    pub fn nsNames(r: *const Referral) []const dns.Name {
        return r.ns_names[0..r.ns_count];
    }
};

/// Which addresses a walk may send to.
/// Defaults are production-safe; tests override to redirect at scripted
/// authorities on non-privileged ports in 127/8.
pub const AddrPolicy = struct {
    upstream_port: u16 = 53,
    allow_loopback: bool = false,

    pub fn address(policy: AddrPolicy, rr: dns.ResourceRecord) ?na.Address {
        return switch (rr.rtype) {
            .a => na.initIp4(rr.rdata.a, policy.upstream_port),
            .aaaa => na.initIp6(rr.rdata.aaaa, policy.upstream_port, 0, 0),
            else => null,
        };
    }

    pub fn allows(policy: AddrPolicy, addr: na.Address) bool {
        return policy.allow_loopback or !na.isNonRoutableNs(addr);
    }
};

pub fn extractReferral(response: dns.Message, target: dns.Name, parent_zone: dns.Name) ?Referral {
    // Servers that set AA on referrals still refer: only answers or an SOA
    // make the NS the zone's own.
    if (response.header.flags.aa and response.answers.len > 0) return null;
    for (response.authorities) |rr| if (rr.rtype == .soa and target.isSubdomainOf(rr.name)) return null;
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
        if (rr.rtype == .ns and rr.name.eql(zc) and ns_count < max_servers_per_level) {
            ns_names[ns_count] = rr.rdata.ns;
            ns_count += 1;
        }
    }
    return .{ .zone_cut = zc, .ns_names = ns_names, .ns_count = ns_count };
}

/// RFC 1034 §5.3.3: drop this reply and ask a sibling. Any rcode but an
/// answer's, extended ones too (RFC 6891 §6.1.3; hark never retries
/// without EDNS on FORMERR or BADVERS); a lame reply, non-AA
/// NOERROR with no answer, no SOA and no cut below `parent_zone`; a
/// recursor's cache, RA set and AA clear, which an RD-clear query gets
/// only from a server that recursed on its own. A recursor's referral
/// is still followed. validateResponse guarantees `questions[0]`.
pub fn shouldTrySibling(response: dns.Message, parent_zone: dns.Name) bool {
    const flags = response.header.flags;
    const rec_lame = flags.ra and !flags.aa;
    if (response.opt) |o| if (o.extended_rcode != 0) return true;
    switch (flags.rcode) {
        .no_error => {},
        .name_error, .yx_domain => return rec_lame,
        else => return true,
    }
    if (flags.aa) return false;
    if (response.answers.len != 0) return rec_lame;
    for (response.authorities) |rr| if (rr.rtype == .soa) return rec_lame;
    return extractReferral(response, response.questions[0].name, parent_zone) == null;
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

const www: dns.Name = .{ .labels = &.{ "www", "example", "com" } };

test "shouldTrySibling: lame is empty non-AA NOERROR with no SOA and no referral" {
    const zone: dns.Name = .{ .labels = &.{"com"} };
    const questions: []const dns.Question = &.{.{ .name = www, .qtype = .a, .qclass = .in }};
    var msg = dns.Message{ .header = test_header, .questions = questions };
    try testing.expect(shouldTrySibling(msg, zone));

    msg.header.flags.aa = true;
    try testing.expect(!shouldTrySibling(msg, zone));
    msg.header.flags.aa = false;

    const soa = dns.ResourceRecord{ .name = zone, .rtype = .soa, .rclass = .in, .ttl = 600, .rdata = .{ .soa = .{ .mname = zone, .rname = zone, .serial = 1, .refresh = 1, .retry = 1, .expire = 1, .minimum = 600 } } };
    msg.authorities = &.{soa};
    try testing.expect(!shouldTrySibling(msg, zone));

    msg.authorities = &.{nsRr(www, zone)};
    try testing.expect(!shouldTrySibling(msg, zone));
    msg.authorities = &.{nsRr(.{ .labels = &.{"fake"} }, zone)};
    try testing.expect(shouldTrySibling(msg, zone));

    msg.authorities = &.{};
    msg.header.flags.rcode = .refused;
    try testing.expect(shouldTrySibling(msg, zone));
    msg.header.flags.rcode = .name_error;
    try testing.expect(!shouldTrySibling(msg, zone));

    msg.header.flags.ra = true;
    try testing.expect(shouldTrySibling(msg, zone));
    msg.header.flags.aa = true;
    try testing.expect(!shouldTrySibling(msg, zone));
    msg.header.flags.aa = false;
    msg.header.flags.rcode = .no_error;
    msg.authorities = &.{soa};
    try testing.expect(shouldTrySibling(msg, zone));
    msg.authorities = &.{};
    msg.answers = &.{glueA(www, .{ 10, 20, 30, 40 })};
    try testing.expect(shouldTrySibling(msg, zone));
    msg.header.flags.ra = false;
    try testing.expect(!shouldTrySibling(msg, zone));
    // BADVERS: header rcode 0, extended 1.
    msg.opt = .{ .udp_payload_size = 1232, .extended_rcode = 1, .version = 0, .do_bit = false, .options = &.{} };
    try testing.expect(shouldTrySibling(msg, zone));
}

test "a private address is never sent to (DNS rebinding defense)" {
    try testing.expect(!(AddrPolicy{}).allows(na.initIp4(.{ 127, 0, 0, 1 }, 53)));
}
