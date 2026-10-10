//! The delegation walk's pure decisions: QNAME minimisation, zone cuts, and
//! which sibling failure a stub sees.
const std = @import("std");
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

    pub fn wire(policy: AddrPolicy, rr: dns.WireRecord) ?na.Address {
        return switch (rr.rtype()) {
            .a => na.initIp4(rr.rdata()[0..4].*, policy.upstream_port),
            .aaaa => na.initIp6(rr.rdata()[0..16].*, policy.upstream_port, 0, 0),
            else => null,
        };
    }

    pub fn allows(policy: AddrPolicy, addr: na.Address) bool {
        return (policy.allow_loopback and loopback(addr)) or !na.isNonRoutableNs(addr);
    }

    fn loopback(addr: na.Address) bool {
        return switch (addr) {
            .ip4 => |v4| v4.bytes[0] == 127,
            .ip6 => |v6| std.mem.eql(u8, &v6.bytes, &(@as([15]u8, @splat(0)) ++ [_]u8{1})),
        };
    }
};

pub fn extractReferral(response: dns.Message, target: dns.Name, parent_zone: dns.Name) ?Referral {
    // Servers that set AA on referrals still refer: only answers or an SOA
    // make the NS the zone's own.
    if (response.header.flags.aa and response.answers.len > 0) return null;
    if (soaAbove(response.authorities, target)) return null;
    // The deepest NS owner above the target, and strictly below the zone
    // asked: NS at the zone itself are its own, not a delegation (RFC 1034
    // §4.2.1).
    var zc = parent_zone;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and target.isSubdomainOf(rr.name) and rr.name.labels.len > zc.labels.len) zc = rr.name;
    }
    if (zc.labels.len == parent_zone.labels.len) return null;

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

pub fn soaAbove(authorities: []const dns.ResourceRecord, name: dns.Name) bool {
    for (authorities) |rr| if (rr.rtype == .soa and name.isSubdomainOf(rr.name)) return true;
    return false;
}

/// RFC 1034 §5.3.3: drop this reply and ask a sibling. Any rcode but an
/// answer's, extended ones too (RFC 6891 §6.1.3; hark never retries
/// without EDNS on FORMERR or BADVERS), and a recursor's cache: RA set, AA
/// clear. A recursor's referral is still followed.
pub fn shouldTrySibling(response: dns.Message, parent_zone: dns.Name) bool {
    const flags = response.header.flags;
    if (response.opt) |o| if (o.extended_rcode != 0) return true;
    switch (flags.rcode) {
        .no_error, .name_error, .yx_domain => {},
        else => return true,
    }
    if (!flags.ra or flags.aa) return false;
    return flags.rcode != .no_error or response.answers.len != 0 or extractReferral(response, response.questions[0].name, parent_zone) == null;
}
