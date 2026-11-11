//! The delegation walk's pure decisions: QNAME minimisation, zone cuts, and
//! which sibling failure a stub sees.
const std = @import("std");
const dns = @import("dns.zig");
const na = @import("net_address.zig");

pub const max_servers_per_level = 26;
pub const max_minimize_count = 10;

pub const ProbeStep = union(enum) {
    referral: Referral,
    nxdomain,
    nodata,
    answered,
    failed,
};

pub fn probeStep(response: dns.Message, target: dns.Name, zone: dns.Name) ProbeStep {
    switch (response.header.flags.rcode) {
        .no_error => {},
        .name_error => return .nxdomain,
        else => return .failed,
    }
    if (extractReferral(response, target, zone)) |referral| return .{ .referral = referral };
    return if (response.answers.len > 0) .answered else .nodata;
}

pub const Referral = struct {
    zone_cut: dns.Name,
    ns_names: [max_servers_per_level]dns.Name,
    ns_count: usize,
};

pub const AddrPolicy = struct {
    upstream_port: u16 = 53,
    allow_loopback: bool = false,

    pub fn address(policy: AddrPolicy, rr: dns.ResourceRecord) ?na.AddressKey {
        return switch (rr.rtype) {
            .a => .ip4(rr.a(), policy.upstream_port),
            .aaaa => .ip6(rr.aaaa(), policy.upstream_port),
            else => null,
        };
    }

    pub fn allows(policy: AddrPolicy, addr: na.AddressKey) bool {
        return (policy.allow_loopback and addr.isLoopback()) or !na.isNonRoutableNs(addr);
    }
};

pub fn extractReferral(response: dns.Message, target: dns.Name, parent_zone: dns.Name) ?Referral {
    // Some servers set AA on a referral: only an answer or an SOA makes the NS the zone's own.
    if (response.header.flags.aa and response.answers.len > 0) return null;
    if (soaAbove(response.authorities, target)) return null;
    var zc = parent_zone;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and target.isSubdomainOf(rr.name) and rr.name.depth() > zc.depth()) zc = rr.name;
    }
    if (zc.depth() == parent_zone.depth()) return null;

    var ns_count: usize = 0;
    var ns_names: [max_servers_per_level]dns.Name = undefined;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and rr.name.eql(zc) and ns_count < max_servers_per_level) {
            ns_names[ns_count] = rr.ns();
            ns_count += 1;
        }
    }
    return .{ .zone_cut = zc, .ns_names = ns_names, .ns_count = ns_count };
}

pub fn soaAbove(authorities: []const dns.ResourceRecord, name: dns.Name) bool {
    for (authorities) |rr| if (rr.rtype == .soa and name.isSubdomainOf(rr.name)) return true;
    return false;
}

pub fn shouldTrySibling(response: dns.Message, parent_zone: dns.Name) bool {
    const flags = response.header.flags;
    if (response.opt) |o| if (o.extended_rcode != 0) return true;
    switch (flags.rcode) {
        .no_error, .name_error, .yx_domain => {},
        else => return true,
    }
    // RA without AA is a recursor's cache (RFC 1034 §5.3.3): ask a sibling,
    // unless it refers, which is still followed.
    if (!flags.ra or flags.aa) return false;
    return flags.rcode != .no_error or response.answers.len != 0 or extractReferral(response, response.question.?.name, parent_zone) == null;
}
