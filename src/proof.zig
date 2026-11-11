//! Denial-of-existence proofs: NSEC and NSEC3 geometry in canonical order
//! (RFC 4034 §6.1, RFC 5155), what an authority section proves or fails to,
//! and how a referral classifies its delegation.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const rrsig = @import("rrsig.zig");

const Sha1 = std.crypto.hash.Sha1;

pub const SecurityStatus = enum {
    /// Proves nothing: incomplete, or spoken from the wrong side of a cut.
    unchecked,
    secure,
    /// Proven only through an Opt-Out span, which may hide unsigned
    /// delegations, so never AD (RFC 5155 §9.2).
    insecure,
    /// Contradicted by signed data, or refused unread: a mixed or flooded
    /// section, a spent budget.
    bogus,
};

fn isInsecureDelegationProof(type_bit_maps: []const u8) bool {
    return !dns.typeBitmapContains(type_bit_maps, .ds) and isAncestorDelegation(type_bit_maps);
}

pub fn isProperAncestor(zone: dns.Name, name: dns.Name) bool {
    return zone.depth() < name.depth() and name.isSubdomainOf(zone);
}

pub fn deepestApex(name: dns.Name, rtype: dns.RType) dns.Name {
    return if (rtype == .ds) name.parent() orelse name else name;
}

pub const Delegation = enum {
    unsigned,
    unproven,
    bogus,
};

pub fn classifyDelegation(
    authorities: []const dns.ResourceRecord,
    child_zone: dns.Name,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) Delegation {
    for (authorities) |rr| {
        if (rr.rtype == .ds and rr.name.eql(child_zone)) return .unproven;
    }
    if (!isProperAncestor(zone, child_zone)) return .unproven;
    if (hasMixedNsecNsec3(authorities)) return .bogus;

    for (authorities) |rr| {
        var next: dns.Name.Buf = undefined;
        if (rr.rtype == .nsec and rr.name.eql(child_zone))
            return if (isInsecureDelegationProof(rr.nsec(&next).type_bit_maps)) .unsigned else .unproven;
    }

    const salt, const iterations = switch (nsec3ChainParams(authorities, zone)) {
        .params => |p| .{ p.salt, p.iterations },
        .verdict => |v| return if (v == .bogus) .bogus else .unproven,
    };
    const child_hash = budgetedNsec3Hash(child_zone, salt, iterations, budget) catch return .bogus;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
        if (mem.eql(u8, &owner_hash, &child_hash))
            return if (isInsecureDelegationProof(rr.nsec3().type_bit_maps)) .unsigned else .unproven;
    }
    // RFC 5155 §8.6: closest encloser, then an Opt-Out span over the next
    // closer. No wildcard step: delegations are never synthesized.
    const found = switch (nsec3ClosestEncloser(authorities, child_zone, child_hash, salt, iterations, zone, budget)) {
        .found => |f| f,
        .verdict => |v| return if (v == .bogus) .bogus else .unproven,
    };
    // An owner match returned above, so the next closer hash is defined.
    std.debug.assert(found.ce.depth() < child_zone.depth());
    return if (nsec3Cover(authorities, zone, &found.next_closer_hash) == true) .unsigned else .unproven;
}

/// The longest suffix of qname shared with either bound of a covering NSEC
/// (RFC 4035 §5.4). Null when a bound sits at or below qname: then qname
/// exists. The result aliases qname's bytes.
pub fn closestEncloser(qname: dns.Name, bound_a: dns.Name, bound_b: dns.Name) ?dns.Name {
    const a = qname.shared(bound_a);
    const b = qname.shared(bound_b);
    const ce = if (a.depth() >= b.depth()) a else b;
    return if (ce.depth() == qname.depth()) null else ce;
}

test closestEncloser {
    const t = std.testing;
    const qname = dns.Name.lit("a.b.example.com");
    const owner = dns.Name.lit("z.b.example.com");
    const next = dns.Name.lit("example.com");
    try t.expectEqual(@as(u8, 3), closestEncloser(qname, owner, next).?.depth());
    const below = dns.Name.lit("x.a.b.example.com");
    try t.expectEqual(null, closestEncloser(qname, below, next));
    try t.expectEqual(null, closestEncloser(.root, owner, next));
}

fn inOpenRangeWrap(lo_vs_x: std.math.Order, x_vs_hi: std.math.Order, lo_vs_hi: std.math.Order) bool {
    return if (lo_vs_hi == .lt) lo_vs_x == .lt and x_vs_hi == .lt else lo_vs_x == .lt or x_vs_hi == .lt;
}

fn isAncestorDelegation(type_bit_maps: []const u8) bool {
    return dns.typeBitmapContains(type_bit_maps, .ns) and
        !dns.typeBitmapContains(type_bit_maps, .soa);
}

/// RFC 6840 §4.1: a parent-side delegation record or a DNAME owner denies
/// nothing below itself. Without this a TLD's genuine record at
/// `example.com` denies the whole child zone.
fn provesNothingBelowOwner(type_bit_maps: []const u8) bool {
    return isAncestorDelegation(type_bit_maps) or
        dns.typeBitmapContains(type_bit_maps, .dname);
}

/// RFC 6840 §4.1, §4.4: a parent-side record may deny only DS at its owner,
/// and a child apex (SOA set) never carries DS, so its missing DS bit must
/// not prove the delegation unsigned. Callers answer `.unchecked`, not
/// `.bogus`: the record is genuine, just from the wrong side.
fn wrongSideOfCut(type_bit_maps: []const u8, qname: dns.Name, qtype: dns.RType) bool {
    if (qtype == .ds) {
        // The root has no parent: its apex record is all that can answer.
        return !qname.isRoot() and dns.typeBitmapContains(type_bit_maps, .soa);
    }
    return isAncestorDelegation(type_bit_maps);
}

pub fn nsecCovers(nsec_owner: dns.Name, nsec: dns.NsecData, qname: dns.Name) bool {
    if (isProperAncestor(nsec_owner, qname) and
        provesNothingBelowOwner(nsec.type_bit_maps))
    {
        return false;
    }

    return inOpenRangeWrap(
        nsec_owner.order(qname),
        qname.order(nsec.next_domain_name),
        nsec_owner.order(nsec.next_domain_name),
    );
}

/// A next name below qname makes qname an empty non-terminal, which exists
/// (RFC 4592 §2.2.2). Denying it under NXDOMAIN would drop its whole
/// subtree from RFC 8020 caches.
pub fn nsecProvesNameNonexistence(
    nsec_owner: dns.Name,
    nsec: dns.NsecData,
    qname: dns.Name,
) bool {
    return nsecCovers(nsec_owner, nsec, qname) and !nsec.next_domain_name.isSubdomainOf(qname);
}

fn nsecProvesEnt(nsec_owner: dns.Name, nsec: dns.NsecData, qname: dns.Name) bool {
    return nsecCovers(nsec_owner, nsec, qname) and nsec.next_domain_name.isSubdomainOf(qname);
}

/// RFC 6840 §4.3: a CNAME at the owner would have answered any qtype.
fn bitmapContradictsNodata(type_bit_maps: []const u8, qtype: dns.RType) bool {
    return dns.typeBitmapContains(type_bit_maps, qtype) or
        dns.typeBitmapContains(type_bit_maps, .cname);
}

const nsec3_opt_out: u8 = 0x01;

/// RFC 5155 §8.1, §8.2: a record with an unknown hash algorithm or any
/// flag bit but Opt-Out is ignored, not read as if the bit were clear.
fn inChain(rr: dns.ResourceRecord, zone: dns.Name) bool {
    if (rr.rtype != .nsec3 or !rr.name.isSubdomainOf(zone)) return false;
    return rr.nsec3().hash_algorithm == .sha1 and rr.nsec3().flags & ~nsec3_opt_out == 0;
}

/// An honest proof needs at most 3 NSEC or NSEC3 records. More is refused
/// before any hashing or verifying (NsecTrap; Knot uses the same cap).
pub const max_proof_records: usize = 8;

pub fn denialZone(authorities: []const dns.ResourceRecord, target: dns.Name) ?dns.Name {
    var soa: ?dns.Name = null;
    var signer: ?dns.Name = null;
    for (authorities) |rr| {
        const z = switch (rr.rtype) {
            .soa => rr.name,
            .rrsig => switch (rr.rrsig().type_covered) {
                .nsec, .nsec3 => rr.rrsig().signer_name,
                else => continue,
            },
            else => continue,
        };
        if (!target.isSubdomainOf(z)) continue;
        const best = if (rr.rtype == .soa) &soa else &signer;
        if (best.* == null or z.depth() > best.*.?.depth()) best.* = z;
    }
    return soa orelse signer;
}

pub fn proofFlood(authorities: []const dns.ResourceRecord) bool {
    var n: usize = 0;
    for (authorities) |rr| {
        if (rr.rtype == .nsec or rr.rtype == .nsec3) n += 1;
    }
    return n > max_proof_records;
}

pub fn nsec3Hash(name: dns.Name, salt: []const u8, iterations: u16) [Sha1.digest_length]u8 {
    var hash: [Sha1.digest_length]u8 = undefined;
    var hasher = Sha1.init(.{});
    hasher.update(name.wire);
    hasher.update(salt);
    hasher.final(&hash);

    for (0..iterations) |_| {
        var h2 = Sha1.init(.{});
        h2.update(&hash);
        h2.update(salt);
        h2.final(&hash);
    }

    return hash;
}

pub fn base32HexDecode(dest: []u8, encoded: []const u8) error{InvalidBase32}!usize {
    var bits: u32 = 0;
    var bit_count: u4 = 0;
    var out: usize = 0;

    for (encoded) |c| {
        const val: u5 = switch (c) {
            '0'...'9' => @intCast(c - '0'),
            'A'...'V' => @intCast(c - 'A' + 10),
            'a'...'v' => @intCast(c - 'a' + 10),
            else => return error.InvalidBase32,
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if (bit_count >= 8) {
            bit_count -= 8;
            if (out >= dest.len) return error.InvalidBase32;
            dest[out] = @intCast((bits >> bit_count) & 0xFF);
            out += 1;
        }
    }
    return out;
}

pub fn base32HexEncode(dest: []u8, data: []const u8) []const u8 {
    const alphabet = "0123456789abcdefghijklmnopqrstuv";
    var bits: u32 = 0;
    var bit_count: u4 = 0;
    var out: usize = 0;

    for (data) |b| {
        bits = (bits << 8) | b;
        bit_count += 8;
        while (bit_count >= 5) {
            bit_count -= 5;
            dest[out] = alphabet[@intCast((bits >> bit_count) & 0x1F)];
            out += 1;
        }
    }
    if (bit_count > 0) {
        dest[out] = alphabet[@intCast((bits << (5 - bit_count)) & 0x1F)];
        out += 1;
    }
    return dest[0..out];
}

fn nsec3HashInRange(
    owner_hash: []const u8,
    next_hash: []const u8,
    target_hash: []const u8,
) bool {
    return inOpenRangeWrap(
        mem.order(u8, owner_hash, target_hash),
        mem.order(u8, target_hash, next_hash),
        mem.order(u8, owner_hash, next_hash),
    );
}

fn nsec3OwnerHash(name: dns.Name) ?[Sha1.digest_length]u8 {
    if (name.isRoot()) return null;
    const label = name.leaf();
    if (label.len != Sha1.digest_length * 8 / 5) return null;
    var result: [Sha1.digest_length]u8 = undefined;
    const n = base32HexDecode(&result, label) catch return null;
    if (n != Sha1.digest_length) return null;
    return result;
}

fn supportedNsec3OwnerHash(rr: dns.ResourceRecord, zone: dns.Name) ?[Sha1.digest_length]u8 {
    return if (inChain(rr, zone)) nsec3OwnerHash(rr.name) else null;
}

/// Callers fail closed to `.bogus` when the budget is spent: an exhausted
/// hash budget is the attack itself (CVE-2023-50868).
fn budgetedNsec3Hash(
    name: dns.Name,
    salt: []const u8,
    iterations: u16,
    budget: *rrsig.ValidationBudget,
) error{ValidationBudgetExhausted}![Sha1.digest_length]u8 {
    try budget.consumeNsec3(nsec3HashBlocks(name, salt.len, iterations));
    return nsec3Hash(name, salt, iterations);
}

fn nsec3HashBlocks(name: dns.Name, salt_len: usize, iterations: u16) u32 {
    return sha1Blocks(name.wire.len + salt_len) + @as(u32, iterations) * sha1Blocks(Sha1.digest_length + salt_len);
}

fn sha1Blocks(message_len: usize) u32 {
    return @intCast((message_len + 8) / 64 + 1);
}

fn hasMixedNsecNsec3(authorities: []const dns.ResourceRecord) bool {
    var has_nsec = false;
    var has_nsec3 = false;
    for (authorities) |rr| {
        if (rr.rtype == .nsec) has_nsec = true;
        if (rr.rtype == .nsec3) has_nsec3 = true;
    }
    return has_nsec and has_nsec3;
}

/// `zone` must be the signer the caller verified these records under.
/// Range geometry cannot tell zones apart: without it one genuine wrap NSEC
/// from any signed zone (`zzz.example.net NSEC example.net`) denies
/// arbitrary names elsewhere.
pub fn validateNegativeProof(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) SecurityStatus {
    if (!qname.isSubdomainOf(zone)) return .bogus;
    if (hasMixedNsecNsec3(authorities)) return .bogus;
    for (authorities) |rr| {
        if (rr.rtype == .nsec and rr.name.isSubdomainOf(zone))
            return validateNsecNegativeProof(authorities, qname, qtype, is_nxdomain, zone);
    }
    return validateNsec3NegativeProof(authorities, qname, qtype, is_nxdomain, zone, budget);
}

fn validateNsecNegativeProof(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    zone: dns.Name,
) SecurityStatus {
    var matching_nsec: ?dns.ResourceRecord = null;
    var covering_nsec: ?dns.ResourceRecord = null;
    var ent = false;
    for (authorities) |rr| {
        if (rr.rtype != .nsec or !rr.name.isSubdomainOf(zone)) continue;
        var next: dns.Name.Buf = undefined;
        const nsec = rr.nsec(&next);
        if (matching_nsec == null and rr.name.eql(qname)) matching_nsec = rr;
        if (covering_nsec == null and nsecProvesNameNonexistence(rr.name, nsec, qname)) covering_nsec = rr;
        if (nsecProvesEnt(rr.name, nsec, qname)) ent = true;
    }
    var next: dns.Name.Buf = undefined;

    if (is_nxdomain) {
        const covering = covering_nsec orelse return .unchecked;
        const ce = closestEncloser(qname, covering.name, covering.nsec(&next).next_domain_name) orelse
            return .unchecked;

        // No check that the closest encloser owns an NSEC: it is a suffix of a
        // verified bound, so it exists (RFC 4592 §2.2.2), and as an empty
        // non-terminal it owns none. Such a check refuses every ip6.arpa NXDOMAIN.
        var wc_buf: dns.Name.Buf = undefined;
        const wildcard = dns.Name.child(&wc_buf, "*", ce) orelse return .unchecked;

        var wildcard_denied = false;
        for (authorities) |rr| {
            if (rr.rtype != .nsec or !rr.name.isSubdomainOf(zone)) continue;
            if (rr.name.eql(wildcard)) return .bogus;
            var other: dns.Name.Buf = undefined;
            if (nsecProvesNameNonexistence(rr.name, rr.nsec(&other), wildcard)) wildcard_denied = true;
        }
        return if (wildcard_denied) .secure else .unchecked;
    }

    if (matching_nsec) |rr| {
        const types = rr.nsec(&next).type_bit_maps;
        if (wrongSideOfCut(types, qname, qtype)) return .unchecked;
        return if (bitmapContradictsNodata(types, qtype)) .bogus else .secure;
    }

    if (ent) return .secure;

    const cov = covering_nsec orelse return .unchecked;
    const ce = closestEncloser(qname, cov.name, cov.nsec(&next).next_domain_name) orelse
        return .unchecked;

    var wc_buf: dns.Name.Buf = undefined;
    const wildcard = dns.Name.child(&wc_buf, "*", ce) orelse return .unchecked;

    for (authorities) |rr| {
        if (rr.rtype != .nsec or !rr.name.isSubdomainOf(zone)) continue;
        var other: dns.Name.Buf = undefined;
        const nsec = rr.nsec(&other);
        if (rr.name.eql(wildcard)) {
            if (wrongSideOfCut(nsec.type_bit_maps, qname, qtype))
                return .unchecked;
            if (bitmapContradictsNodata(nsec.type_bit_maps, qtype))
                return .bogus;
            return .secure;
        }
        // RFC 4035 §5.4 shape under NOERROR: qname and `*.CE` both denied. The
        // rcode is unsigned, so the proof decides. `nsecCovers`, not name
        // nonexistence: a wildcard that is an empty non-terminal is NODATA too.
        if (nsecCovers(rr.name, nsec, wildcard))
            return .secure;
    }
    return .unchecked;
}

const Nsec3ChainParams = union(enum) {
    params: struct { salt: []const u8, iterations: u16 },
    verdict: SecurityStatus,
};

fn nsec3ChainParams(authorities: []const dns.ResourceRecord, zone: dns.Name) Nsec3ChainParams {
    if (proofFlood(authorities)) return .{ .verdict = .bogus };

    // RFC 5155 §8.2: one parameter set or bogus. Within one chain nothing
    // covers the hash of a name that owns a record; a second chain's spans
    // could, forging next-closer coverage and with it Opt-Out.
    var first: ?dns.Nsec3Data = null;
    for (authorities) |rr| {
        if (!inChain(rr, zone)) continue;
        const n3 = rr.nsec3();
        if (first == null) first = n3;
        if (n3.iterations != first.?.iterations or !mem.eql(u8, n3.salt, first.?.salt)) return .{ .verdict = .bogus };
    }
    const f = first orelse return .{ .verdict = .unchecked };
    return .{ .params = .{ .salt = f.salt, .iterations = f.iterations } };
}

const ClosestEncloser = union(enum) {
    found: struct { ce: dns.Name, next_closer_hash: [Sha1.digest_length]u8 },
    verdict: SecurityStatus,
};

fn nsec3ClosestEncloser(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qname_hash: [Sha1.digest_length]u8,
    salt: []const u8,
    iterations: u16,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) ClosestEncloser {
    var below_hash: [Sha1.digest_length]u8 = undefined;
    var up: ?dns.Name = qname;
    while (up) |ancestor| : (up = ancestor.parent()) {
        if (ancestor.depth() < zone.depth()) break;
        const ancestor_hash = if (ancestor.depth() == qname.depth()) qname_hash else budgetedNsec3Hash(
            ancestor,
            salt,
            iterations,
            budget,
        ) catch return .{ .verdict = .bogus };
        for (authorities) |rr| {
            const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
            if (!mem.eql(u8, &owner_hash, &ancestor_hash)) continue;
            if (provesNothingBelowOwner(rr.nsec3().type_bit_maps)) return .{ .verdict = .unchecked };
            return .{ .found = .{ .ce = ancestor, .next_closer_hash = below_hash } };
        }
        below_hash = ancestor_hash;
    }
    return .{ .verdict = .unchecked };
}

/// Null when no span covers `hash`, else whether any coverer has Opt-Out.
/// Every coverer is read, not the first: the sender picks the order.
fn nsec3Cover(authorities: []const dns.ResourceRecord, zone: dns.Name, hash: *const [Sha1.digest_length]u8) ?bool {
    var covered = false;
    var optout = false;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
        if (!nsec3HashInRange(&owner_hash, rr.nsec3().next_hashed_owner, hash)) continue;
        covered = true;
        if (rr.nsec3().flags & nsec3_opt_out != 0) optout = true;
    }
    return if (covered) optout else null;
}

/// RFC 4035 §5.3.4: a wildcard-expanded answer whose RRSIG names `labels`
/// must come with proof that nothing exists between qname and that
/// encloser, or a captured `*.zone` answer replays as any name in the zone.
pub fn proveNoCloserMatch(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    labels: u8,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) SecurityStatus {
    return switch (noCloserMatch(authorities, qname, labels, zone, budget)) {
        .nsec => .secure,
        .nsec3 => |nc| {
            const optout = nsec3Cover(authorities, zone, &nc) orelse return .bogus;
            return if (optout) .insecure else .secure;
        },
        .verdict => |v| v,
    };
}

pub const NoCloserMatch = union(enum) {
    nsec: dns.Name,
    nsec3: [Sha1.digest_length]u8,
    verdict: SecurityStatus,

    pub fn restsOn(p: NoCloserMatch, rr: dns.ResourceRecord, zone: dns.Name) bool {
        return switch (p) {
            .nsec => |owner| rr.rtype == .nsec and rr.name.eql(owner),
            .nsec3 => |nc| if (supportedNsec3OwnerHash(rr, zone)) |h| nsec3HashInRange(&h, rr.nsec3().next_hashed_owner, &nc) else false,
            .verdict => false,
        };
    }
};

pub fn noCloserMatch(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    labels: u8,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) NoCloserMatch {
    if (labels >= qname.depth()) return .{ .verdict = .bogus };
    const ce = qname.ancestor(labels);
    for (authorities) |rr| {
        if (rr.rtype != .nsec or !rr.name.isSubdomainOf(zone)) continue;
        var next: dns.Name.Buf = undefined;
        const nsec = rr.nsec(&next);
        if (!nsecProvesNameNonexistence(rr.name, nsec, qname)) continue;
        // A cover of qname whose closest encloser is `ce` also covers the next
        // closer name, which is what §5.3.4 asks for. A cover bounded below
        // `ce` proves a deeper name exists: the wrong wildcard answered.
        const nsec_ce = closestEncloser(qname, rr.name, nsec.next_domain_name) orelse continue;
        if (nsec_ce.eql(ce)) return .{ .nsec = rr.name };
    }

    const salt, const iterations = switch (nsec3ChainParams(authorities, zone)) {
        .params => |p| .{ p.salt, p.iterations },
        // This proof is owed, so its absence is bogus, not merely unproven.
        .verdict => |v| return .{ .verdict = if (v == .unchecked) .bogus else v },
    };
    const next_closer = qname.ancestor(labels + 1);
    return .{ .nsec3 = budgetedNsec3Hash(next_closer, salt, iterations, budget) catch return .{ .verdict = .bogus } };
}

fn validateNsec3NegativeProof(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) SecurityStatus {
    const salt, const iterations = switch (nsec3ChainParams(authorities, zone)) {
        .params => |p| .{ p.salt, p.iterations },
        .verdict => |v| return v,
    };

    const qname_hash = budgetedNsec3Hash(qname, salt, iterations, budget) catch return .bogus;

    if (!is_nxdomain) {
        for (authorities) |rr| {
            const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
            if (mem.eql(u8, &owner_hash, &qname_hash)) {
                const nsec3 = rr.nsec3();
                if (wrongSideOfCut(nsec3.type_bit_maps, qname, qtype)) return .unchecked;
                return if (bitmapContradictsNodata(nsec3.type_bit_maps, qtype)) .bogus else .secure;
            }
        }
    }

    const found = switch (nsec3ClosestEncloser(authorities, qname, qname_hash, salt, iterations, zone, budget)) {
        .found => |f| f,
        .verdict => |v| return v,
    };
    const ce = found.ce;

    // The name exists, contradicting NXDOMAIN. This also keeps the undefined
    // next closer hash of a qname match from being read.
    if (ce.depth() == qname.depth()) return .bogus;

    const nc_hash = found.next_closer_hash;

    var wc_buf: dns.Name.Buf = undefined;
    const wildcard = dns.Name.child(&wc_buf, "*", ce) orelse return .unchecked;
    const wc_hash = budgetedNsec3Hash(wildcard, salt, iterations, budget) catch return .bogus;

    const nc_cover = nsec3Cover(authorities, zone, &nc_hash);
    const nc_covered = nc_cover != null;
    const nc_optout = nc_cover orelse false;
    var wc_proven = false;
    var wc_optout = false;
    var wc_contradicted = false;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
        const nsec3 = rr.nsec3();

        if (nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &wc_hash)) {
            wc_proven = true;
            if (nsec3.flags & nsec3_opt_out != 0) wc_optout = true;
        } else if (mem.eql(u8, &owner_hash, &wc_hash)) {
            if (is_nxdomain or bitmapContradictsNodata(nsec3.type_bit_maps, qtype)) {
                wc_contradicted = true;
            } else if (!wrongSideOfCut(nsec3.type_bit_maps, qname, qtype)) {
                wc_proven = true;
            }
        }
    }
    // RFC 5155 §8.6: an unsigned delegation under Opt-Out owns no NSEC3, so
    // the Opt-Out span over the next closer is the whole DS proof. It ranks
    // above a wildcard contradiction: the delegation exists, so no wildcard
    // applies to it.
    if (qtype == .ds and !is_nxdomain and nc_covered and nc_optout) return .insecure;

    // Before the Opt-Out fallthrough below, which would otherwise launder a
    // NODATA over a signed wildcard that owns the type.
    if (wc_contradicted) return .bogus;

    if (nc_covered and wc_proven) return if (nc_optout or wc_optout) .insecure else .secure;

    // RFC 5155 errata 3441: with no wildcard proof, a name in an Opt-Out span
    // may be an unsigned delegation or an omitted empty non-terminal, so
    // NODATA for any qtype is insecure. NXDOMAIN still owes the wildcard.
    if (!is_nxdomain and nc_covered and nc_optout) return .insecure;
    return .unchecked;
}

const test_root = dns.Name.root;
const test_com = dns.Name.lit("com");

test "classifyDelegation with DS present" {
    const child_zone = dns.Name.lit("example.com");

    const authorities = [_]dns.ResourceRecord{.fixture(.{
        .name = child_zone,
        .rtype = .ds,
        .rclass = .in,
        .ttl = 86400,
        .rdata = .{ .ds = .{
            .key_tag = 12345,
            .algorithm = .rsasha256,
            .digest_type = .sha256,
            .digest = &@as([32]u8, @splat(0xAA)),
        } },
    })};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, child_zone, test_com, &b));
}

test "classifyDelegation with NSEC proving no DS" {
    const child_zone = dns.Name.lit("example.com");

    const next = dns.Name.lit("next.com");
    const authorities = [_]dns.ResourceRecord{nsecRrWithBitmap(child_zone, next, &.{ 0x00, 0x01, 0x60 })};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unsigned, classifyDelegation(&authorities, child_zone, test_com, &b));
}

test "classifyDelegation rejects invalid NSEC proofs (RFC 6840 §4.4)" {
    const child_zone = dns.Name.lit("example.com");
    const next = dns.Name.lit("next.com");

    const cases = [_][]const u8{
        &[_]u8{ 0x00, 0x01, 0x22 }, // NS + SOA (child-zone apex, not parent delegation)
        &[_]u8{ 0x00, 0x01, 0x40 }, // A only (no NS — not a delegation point)
    };
    for (cases) |type_bit_maps| {
        const authorities = [_]dns.ResourceRecord{nsecRrWithBitmap(child_zone, next, type_bit_maps)};
        var b: rrsig.ValidationBudget = .{};
        try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, child_zone, test_com, &b));
    }
}

test "NSEC name non-existence" {
    const alpha = dns.Name.lit("alpha.example.com");
    const gamma = dns.Name.lit("gamma.example.com");

    const nsec_data = dns.NsecData{
        .next_domain_name = gamma,
        .type_bit_maps = &.{},
    };

    const beta = dns.Name.lit("beta.example.com");
    try testing.expect(nsecProvesNameNonexistence(alpha, nsec_data, beta));

    const zeta = dns.Name.lit("zeta.example.com");
    try testing.expect(!nsecProvesNameNonexistence(alpha, nsec_data, zeta));

    try testing.expect(!nsecProvesNameNonexistence(alpha, nsec_data, alpha));
}

test "NSEC type non-existence" {
    const name = dns.Name.lit("example.com");

    const nsec_data = dns.NsecData{
        .next_domain_name = dns.Name.lit("next"),
        .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x62 },
    };

    const authorities = [_]dns.ResourceRecord{nsecRrWithBitmap(name, nsec_data.next_domain_name, nsec_data.type_bit_maps)};
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, name, .aaaa, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, name, .a, false, test_root, &b));
}

test "NSEC NODATA bogus when CNAME bit set (RFC 6840 §4.3)" {
    const name = dns.Name.lit("example.com");

    const cname_present = dns.NsecData{
        .next_domain_name = dns.Name.lit("next"),
        .type_bit_maps = &[_]u8{ 0x00, 0x03, 0x04, 0x00, 0x80 },
    };
    const present = [_]dns.ResourceRecord{nsecRrWithBitmap(name, cname_present.next_domain_name, cname_present.type_bit_maps)};
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&present, name, .aaaa, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&present, name, .cname, false, test_root, &b));

    const cname_absent = dns.NsecData{
        .next_domain_name = dns.Name.lit("next"),
        .type_bit_maps = &[_]u8{ 0x00, 0x03, 0x00, 0x00, 0x80 },
    };
    const absent = [_]dns.ResourceRecord{nsecRrWithBitmap(name, cname_absent.next_domain_name, cname_absent.type_bit_maps)};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&absent, name, .aaaa, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&absent, name, .cname, false, test_root, &b));
}

test "NSEC3 hash range check" {
    const owner = [_]u8{ 0x10, 0x20, 0x30 };
    const next = [_]u8{ 0x50, 0x60, 0x70 };

    const target_in = [_]u8{ 0x30, 0x40, 0x50 };
    try testing.expect(nsec3HashInRange(&owner, &next, &target_in));

    const target_before = [_]u8{ 0x05, 0x06, 0x07 };
    try testing.expect(!nsec3HashInRange(&owner, &next, &target_before));

    const target_after = [_]u8{ 0x80, 0x90, 0xA0 };
    try testing.expect(!nsec3HashInRange(&owner, &next, &target_after));
}

test "NSEC3 hash range wrap-around" {
    const owner = [_]u8{ 0xF0, 0xF0, 0xF0 };
    const next = [_]u8{ 0x10, 0x10, 0x10 };

    const target_after = [_]u8{ 0xF5, 0xF5, 0xF5 };
    try testing.expect(nsec3HashInRange(&owner, &next, &target_after));

    const target_before_next = [_]u8{ 0x05, 0x05, 0x05 };
    try testing.expect(nsec3HashInRange(&owner, &next, &target_before_next));

    const target_between = [_]u8{ 0x50, 0x50, 0x50 };
    try testing.expect(!nsec3HashInRange(&owner, &next, &target_between));
}

test "a section mixing NSEC and NSEC3 proves nothing" {
    const name = dns.Name.lit("example.com");
    const nsec = nsecRr(name, name);
    const mixed = [_]dns.ResourceRecord{ nsec, makeNsec3Rr(name, &.{}, &@as([20]u8, @splat(0)), &.{}) };
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&.{nsec}, name, .a, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&mixed, name, .a, false, test_root, &b));
}

test "validateNegativeProof rejects an ancestor-delegation NSEC (RFC 6840 §4.1)" {
    const cut = dns.Name.lit("example.com");
    const next = dns.Name.lit("f.com");
    const parent_side = [_]u8{ 0x00, 0x01, 0x20 };
    const child_apex = [_]u8{ 0x00, 0x01, 0x22 };
    const victim = dns.Name.lit("www.example.com");

    var b: rrsig.ValidationBudget = .{};
    const parent_auth = [_]dns.ResourceRecord{nsecRrWithBitmap(cut, next, &parent_side)};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&parent_auth, victim, .a, true, test_root, &b),
    );
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&parent_auth, cut, .a, false, test_root, &b),
    );
    try testing.expectEqual(
        SecurityStatus.secure,
        validateNegativeProof(&parent_auth, cut, .ds, false, test_root, &b),
    );

    const child_auth = [_]dns.ResourceRecord{nsecRrWithBitmap(cut, next, &child_apex)};
    try testing.expectEqual(
        SecurityStatus.secure,
        validateNegativeProof(&child_auth, victim, .a, true, test_root, &b),
    );
}

test "validateNegativeProof NSEC NXDOMAIN" {
    const alpha = dns.Name.lit("alpha.example.com");
    const gamma = dns.Name.lit("gamma.example.com");
    const example_com = dns.Name.lit("example.com");

    const authorities = [_]dns.ResourceRecord{
        nsecRr(alpha, gamma),
        nsecRr(example_com, alpha), // covers *.example.com: example.com -> alpha.example.com
    };

    const beta = dns.Name.lit("beta.example.com");
    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
}

test "validateNegativeProof NSEC NXDOMAIN without wildcard denial" {
    const alpha = dns.Name.lit("alpha.example.com");
    const gamma = dns.Name.lit("gamma.example.com");

    const authorities = [_]dns.ResourceRecord{nsecRr(alpha, gamma)};

    const beta = dns.Name.lit("beta.example.com");
    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, status);
}

pub fn nsecRr(owner: dns.Name, next: dns.Name) dns.ResourceRecord {
    return nsecRrWithBitmap(owner, next, &.{});
}

test "validateNegativeProof NSEC NXDOMAIN deep CE (not zone apex)" {
    const aaa_sub = dns.Name.lit("aaa.sub.example.com");
    const zzz_sub = dns.Name.lit("zzz.sub.example.com");
    const sub = dns.Name.lit("sub.example.com");
    const missing = dns.Name.lit("missing.sub.example.com");

    const authorities = [_]dns.ResourceRecord{
        nsecRr(aaa_sub, zzz_sub), // covers qname: aaa < missing < zzz
        nsecRr(sub, aaa_sub), // covers *.sub.example.com: sub < *.sub < aaa.sub
    };
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, missing, .a, true, test_root, &b));
}

test "validateNegativeProof NSEC NXDOMAIN deep CE rejects wrong-level wildcard" {
    const aaa_sub = dns.Name.lit("aaa.sub.example.com");
    const zzz_sub = dns.Name.lit("zzz.sub.example.com");
    const example_com = dns.Name.lit("example.com");
    const aaa = dns.Name.lit("aaa.example.com");
    const missing = dns.Name.lit("missing.sub.example.com");

    const authorities = [_]dns.ResourceRecord{
        nsecRr(aaa_sub, zzz_sub),
        nsecRr(example_com, aaa), // covers *.example.com only (wrong level)
    };
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, missing, .a, true, test_root, &b));
}

test "validateNegativeProof NSEC NXDOMAIN deep qname still needs wildcard denial" {
    const aaa = dns.Name.lit("aaa.example.com");
    const zzz = dns.Name.lit("zzz.example.com");
    const qname = dns.Name.lit("a.b.c.example.com");
    const authorities = [_]dns.ResourceRecord{nsecRr(aaa, zzz)};
    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, qname, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, status);
}

test "validateNegativeProof NSEC NODATA at empty non-terminal (live ip6.arpa shape)" {
    const owner = dns.Name.lit("1.4.2.ip6.arpa");
    const next = dns.Name.lit("0.6.2.ip6.arpa");
    const qname = dns.Name.lit("6.2.ip6.arpa");
    const authorities = [_]dns.ResourceRecord{nsecRr(owner, next)};
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
}

test "validateNegativeProof NSEC NXDOMAIN with ENT closest encloser (live ip6.arpa shape)" {
    const authorities = [_]dns.ResourceRecord{
        nsecRr(
            .lit("3.6.2.ip6.arpa"),
            .lit("0.8.2.ip6.arpa"),
        ),
        nsecRr(
            .lit("1.4.2.ip6.arpa"),
            .lit("0.6.2.ip6.arpa"),
        ),
    };
    const qname = dns.Name.lit("xx.6.2.ip6.arpa");
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

test "validateNegativeProof NSEC NXDOMAIN single NSEC covers both" {
    const example_com = dns.Name.lit("example.com");
    const zeta = dns.Name.lit("zeta.example.com");

    const authorities = [_]dns.ResourceRecord{nsecRr(example_com, zeta)};

    const beta = dns.Name.lit("beta.example.com");
    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
}

fn setNsec3(rr: *dns.ResourceRecord, comptime field: []const u8, value: anytype) void {
    var d = rr.nsec3();
    @field(d, field) = value;
    rr.* = .fixture(.{ .name = rr.name, .rtype = .nsec3, .rclass = rr.rclass, .ttl = rr.ttl, .rdata = .{ .nsec3 = d } });
}

fn nsecRrWithBitmap(owner: dns.Name, next: dns.Name, bitmap: []const u8) dns.ResourceRecord {
    return .fixture(.{
        .name = owner,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .nsec = .{ .next_domain_name = next, .type_bit_maps = bitmap } },
    });
}

test "validateNegativeProof NSEC NXDOMAIN at an empty non-terminal is refused" {
    const apex = dns.Name.lit("ip6.arpa");
    const next = dns.Name.lit("3.0.0.1.0.0.2.ip6.arpa");
    const qname = dns.Name.lit("2.ip6.arpa");
    const authorities = [_]dns.ResourceRecord{nsecRr(apex, next)};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&authorities, qname, 2, apex, &b));
}

test "validateNegativeProof NSEC NODATA wildcard-expanded (RFC 4035 §3.1.3.4)" {
    const lotus = dns.Name.lit("lotus.go-vip.net");
    const ns1 = dns.Name.lit("ns1.go-vip.net");
    const wildcard = dns.Name.lit("*.go-vip.net");
    const acme = dns.Name.lit("_acme-challenge.go-vip.net");
    const qname = dns.Name.lit("nasa-tv.go-vip.net");

    const wc_bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x08, 0x00, 0x03 };
    const authorities = [_]dns.ResourceRecord{
        nsecRr(lotus, ns1),
        nsecRrWithBitmap(wildcard, acme, &wc_bitmap),
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .https, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .https, true, test_root, &b));
}

test "validateNegativeProof NSEC NODATA wildcard with qtype present is .bogus" {
    const lotus = dns.Name.lit("lotus.go-vip.net");
    const ns1 = dns.Name.lit("ns1.go-vip.net");
    const wildcard = dns.Name.lit("*.go-vip.net");
    const acme = dns.Name.lit("_acme-challenge.go-vip.net");
    const qname = dns.Name.lit("nasa-tv.go-vip.net");

    const wc_bitmap = [_]u8{ 0x00, 0x09, 0x40, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x40 };
    const authorities = [_]dns.ResourceRecord{
        nsecRr(lotus, ns1),
        nsecRrWithBitmap(wildcard, acme, &wc_bitmap),
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .https, false, test_root, &b));
}

test "validateNegativeProof NSEC NODATA wildcard with CNAME present is .bogus" {
    const lotus = dns.Name.lit("lotus.go-vip.net");
    const ns1 = dns.Name.lit("ns1.go-vip.net");
    const wildcard = dns.Name.lit("*.go-vip.net");
    const acme = dns.Name.lit("_acme-challenge.go-vip.net");
    const qname = dns.Name.lit("nasa-tv.go-vip.net");

    const wc_bitmap = [_]u8{ 0x00, 0x01, 0x04 };
    const authorities = [_]dns.ResourceRecord{
        nsecRr(lotus, ns1),
        nsecRrWithBitmap(wildcard, acme, &wc_bitmap),
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
}

test "validateNegativeProof NSEC NODATA covering but no wildcard proof is .unchecked" {
    const aaa = dns.Name.lit("aaa.example.com");
    const zzz = dns.Name.lit("zzz.example.com");
    const qname = dns.Name.lit("missing.example.com");
    const authorities = [_]dns.ResourceRecord{nsecRr(aaa, zzz)};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
}

pub fn makeNsec3OwnerName(hash: [Sha1.digest_length]u8, zone: dns.Name, bufs: *Nsec3OwnerBufs) dns.Name {
    return dns.Name.child(&bufs.name, base32HexEncode(&bufs.enc, &hash), zone).?;
}

pub const Nsec3OwnerBufs = struct {
    enc: [32]u8 = undefined,
    name: dns.Name.Buf = undefined,
    low: [Sha1.digest_length]u8 = undefined,
    high: [Sha1.digest_length]u8 = undefined,
};

pub fn makeNsec3Rr(
    owner_name: dns.Name,
    salt: []const u8,
    next_hashed_owner: []const u8,
    type_bit_maps: []const u8,
) dns.ResourceRecord {
    return .fixture(.{
        .name = owner_name,
        .rtype = .nsec3,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .nsec3 = .{
            .hash_algorithm = .sha1,
            .flags = 0,
            .iterations = 0,
            .salt = salt,
            .next_hashed_owner = next_hashed_owner,
            .type_bit_maps = type_bit_maps,
        } },
    });
}

fn makeCoveringNsec3(
    target_hash: [Sha1.digest_length]u8,
    zone: dns.Name,
    salt: []const u8,
    bufs: *Nsec3OwnerBufs,
) dns.ResourceRecord {
    bufs.low = target_hash;
    bufs.high = target_hash;
    bufs.low[19] -|= 1;
    bufs.high[19] +|= 1;
    const owner = makeNsec3OwnerName(bufs.low, zone, bufs);
    return makeNsec3Rr(owner, salt, &bufs.high, &.{});
}

test "nsec3Hash RFC 5155 Appendix B" {
    const name = dns.Name.lit("example");
    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    var enc_buf: [32]u8 = undefined;
    try testing.expectEqualStrings("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", base32HexEncode(&enc_buf, &nsec3Hash(name, &salt, 12)));
}

test "nsec3OwnerHash refuses an owner that is no SHA-1 hash" {
    try testing.expect(nsec3OwnerHash(.lit("tooshort")) == null);
    try testing.expect(nsec3OwnerHash(.root) == null);
}

test "NSEC3 unknown hash algorithm is ignored and the proof fails closed (RFC 5155 §8.1)" {
    const qname = dns.Name.lit("example.com");
    const owner_name = dns.Name.lit("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com");
    const next: [20]u8 = @splat(0xFF);
    const authorities = [_]dns.ResourceRecord{.fixture(.{
        .name = owner_name,
        .rtype = .nsec3,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{
            .nsec3 = .{
                .hash_algorithm = @fromBackingInt(@intCast(2)), // not sha1
                .flags = 0,
                .iterations = 0,
                .salt = &.{},
                .next_hashed_owner = &next,
                .type_bit_maps = &.{},
            },
        },
    })};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, qname, test_com, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&authorities, qname, 1, test_root, &b));
}

test "NSEC3 rejects an ancestor-delegation record (RFC 6840 §4.1)" {
    const salt: []const u8 = &.{};
    const zone_name = dns.Name.lit("com");
    const cut = dns.Name.lit("example.com");
    const below = dns.Name.lit("www.example.com");

    const cut_hash = nsec3Hash(cut, salt, 0);
    var bufs: Nsec3OwnerBufs = .{};
    const cut_owner = makeNsec3OwnerName(cut_hash, zone_name, &bufs);
    const parent_side = [_]u8{ 0x00, 0x01, 0x20 };

    var b: rrsig.ValidationBudget = .{};
    const at_cut = [_]dns.ResourceRecord{makeNsec3Rr(cut_owner, salt, &@as([20]u8, @splat(0xFF)), &parent_side)};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&at_cut, cut, .a, false, test_root, &b),
    );
    try testing.expectEqual(
        SecurityStatus.secure,
        validateNegativeProof(&at_cut, cut, .ds, false, test_root, &b),
    );

    const wide = [_]dns.ResourceRecord{
        makeNsec3Rr(cut_owner, salt, &@as([20]u8, @splat(0xFF)), &parent_side),
    };
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&wide, below, .a, true, test_root, &b),
    );
}

test "NSEC3 child-side apex cannot deny DS (RFC 6840 §4.4)" {
    const salt: []const u8 = &.{};
    const apex = dns.Name.lit("example.com");
    const hash = nsec3Hash(apex, salt, 0);
    var bufs: Nsec3OwnerBufs = .{};
    const owner = makeNsec3OwnerName(hash, apex, &bufs);
    const child_apex = [_]u8{ 0x00, 0x07, 0x62, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80 };

    var b: rrsig.ValidationBudget = .{};
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner, salt, &@as([20]u8, @splat(0xFF)), &child_apex)};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&authorities, apex, .ds, false, test_root, &b),
    );
    try testing.expectEqual(
        SecurityStatus.secure,
        validateNegativeProof(&authorities, apex, .txt, false, test_root, &b),
    );
}

test "NSEC3 NODATA - CNAME in bitmap is .bogus" {
    const qname = dns.Name.lit("alias.com");
    const salt: []const u8 = &.{};
    const hash = nsec3Hash(qname, salt, 0);

    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(hash, test_com, &bufs);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x04 })};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
}

test "NSEC3 NXDOMAIN - missing wildcard cover" {
    const qname = dns.Name.lit("gone.example.com");
    const ce_name = dns.Name.lit("example.com");
    const zone_name = dns.Name.lit("com");
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(nsec3Hash(ce_name, salt, 0), zone_name, &bufs1);

    var bufs2: Nsec3OwnerBufs = .{};
    const nc_rr = makeCoveringNsec3(nsec3Hash(qname, salt, 0), zone_name, salt, &bufs2);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &.{}),
        nc_rr,
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

const com_apex_bitmap = [_]u8{ 0x00, 0x07, 0x22, 0x00, 0x00, 0x00, 0x00, 0x02, 0x90 };
const com_delegation_bitmap = [_]u8{ 0x00, 0x06, 0x20, 0x00, 0x00, 0x00, 0x00, 0x12 };

const OptOutProof = struct {
    ce_bufs: Nsec3OwnerBufs = .{},
    nc_bufs: Nsec3OwnerBufs = .{},
    wc_bufs: Nsec3OwnerBufs = .{},
    ce_next: [Sha1.digest_length]u8 = undefined,
    rrs: [3]dns.ResourceRecord = undefined,

    fn init(self: *@This(), qname: dns.Name, opt_out: bool) !void {
        const zone_name = dns.Name.lit("com");
        const salt: []const u8 = &.{};
        const ce = zone_name;
        const ce_hash = nsec3Hash(ce, salt, 0);
        const ce_owner = makeNsec3OwnerName(ce_hash, zone_name, &self.ce_bufs);
        // The CE's range must end just past its own owner. A maximal range would
        // also cover the next closer, and the coverer's flag under test goes unread.
        self.ce_next = ce_hash;
        self.ce_next[Sha1.digest_length - 1] +|= 1;
        self.rrs[0] = makeNsec3Rr(ce_owner, salt, &self.ce_next, &com_apex_bitmap);
        setNsec3(&self.rrs[0], "flags", nsec3_opt_out);

        self.rrs[1] = makeCoveringNsec3(nsec3Hash(qname, salt, 0), zone_name, salt, &self.nc_bufs);
        setNsec3(&self.rrs[1], "type_bit_maps", &com_delegation_bitmap);
        setNsec3(&self.rrs[1], "flags", if (opt_out) nsec3_opt_out else 0);

        var wc_buf: dns.Name.Buf = undefined;
        const wildcard = dns.Name.child(&wc_buf, "*", ce).?;
        self.rrs[2] = makeCoveringNsec3(nsec3Hash(wildcard, salt, 0), zone_name, salt, &self.wc_bufs);
    }

    fn ds(self: *const @This()) []const dns.ResourceRecord {
        return self.rrs[0..2];
    }
};

test "NSEC3 Opt-Out proves no DS, without AD (RFC 5155 §8.6 / §9.2)" {
    const qname = dns.Name.lit("amazon.com");
    var p: OptOutProof = .{};
    try p.init(qname, true);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.insecure,
        validateNegativeProof(p.ds(), qname, .ds, false, test_root, &b),
    );
}

test "NSEC3 DS NODATA needs the Opt-Out flag (RFC 5155 §8.6)" {
    const qname = dns.Name.lit("amazon.com");
    var p: OptOutProof = .{};
    try p.init(qname, false);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(p.ds(), qname, .ds, false, test_root, &b),
    );
}

test "NSEC3 Opt-Out NODATA is insecure for any qtype, never NXDOMAIN (RFC 5155 errata 3441)" {
    const qname = dns.Name.lit("amazon.com");
    var p: OptOutProof = .{};
    try p.init(qname, true);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.insecure,
        validateNegativeProof(p.ds(), qname, .a, false, test_root, &b),
    );
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(p.ds(), qname, .ds, true, test_root, &b),
    );
}

test "NSEC3 reserved Flag bits make a record invisible (RFC 5155 §8.2)" {
    const qname = dns.Name.lit("amazon.com");
    var b: rrsig.ValidationBudget = .{};
    {
        var p: OptOutProof = .{};
        try p.init(qname, true);
        setNsec3(&p.rrs[1], "flags", nsec3_opt_out | 0x02);
        try testing.expectEqual(
            SecurityStatus.unchecked,
            validateNegativeProof(p.ds(), qname, .ds, false, test_root, &b),
        );
    }
    {
        var p: OptOutProof = .{};
        try p.init(qname, true);
        setNsec3(&p.rrs[1], "flags", 0x02);
        try testing.expectEqual(
            SecurityStatus.unchecked,
            validateNegativeProof(p.ds(), qname, .ds, false, test_root, &b),
        );
    }
}

test "NSEC3 proof mixing two parameter sets is bogus (RFC 5155 §8.2)" {
    const qname = dns.Name.lit("amazon.com");
    var p: OptOutProof = .{};
    try p.init(qname, true);
    setNsec3(&p.rrs[1], "salt", "X");
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        validateNegativeProof(p.ds(), qname, .ds, false, test_root, &b),
    );
}

test "NSEC3 Opt-Out NXDOMAIN must not set AD (RFC 5155 §9.2)" {
    const qname = dns.Name.lit("victim.com");
    var b: rrsig.ValidationBudget = .{};
    {
        var p: OptOutProof = .{};
        try p.init(qname, true);
        try testing.expectEqual(
            SecurityStatus.insecure,
            validateNegativeProof(&p.rrs, qname, .a, true, test_root, &b),
        );
    }
    {
        var p: OptOutProof = .{};
        try p.init(qname, false);
        try testing.expectEqual(
            SecurityStatus.secure,
            validateNegativeProof(&p.rrs, qname, .a, true, test_root, &b),
        );
    }
}

test "NSEC3 NODATA under Opt-Out outranks a wildcard CNAME at the encloser (RFC 5155 §8.6, errata 3441)" {
    const qname = dns.Name.lit("unsigned.com");
    var p: OptOutProof = .{};
    try p.init(qname, true);
    var bufs: Nsec3OwnerBufs = .{};
    var wl: dns.Name.Buf = undefined;
    const wc = dns.Name.child(&wl, "*", test_com).?;
    const cname_only = [_]u8{ 0x00, 0x01, 0x04 };
    const wc_rr = makeNsec3Rr(makeNsec3OwnerName(nsec3Hash(wc, &.{}, 0), test_com, &bufs), &.{}, &p.nc_bufs.high, &cname_only);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&.{ p.rrs[0], p.rrs[1], wc_rr }, qname, .ds, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&.{ p.rrs[0], p.rrs[1], wc_rr }, qname, .a, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(p.ds(), qname, .a, false, test_root, &b));
}

test "NSEC3 wildcard coverer with Opt-Out counts wherever it sits in the section" {
    const qname = dns.Name.lit("victim.com");
    var p: OptOutProof = .{};
    try p.init(qname, false);
    var stale_first = p.rrs ++ [_]dns.ResourceRecord{p.rrs[2]};
    setNsec3(&stale_first[3], "flags", nsec3_opt_out);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&stale_first, qname, .a, true, test_root, &b));
}

test "NSEC3 Opt-Out NODATA-by-CE-proof must not set AD (RFC 5155 §9.2)" {
    const qname = dns.Name.lit("victim.com");
    var b: rrsig.ValidationBudget = .{};
    {
        var p: OptOutProof = .{};
        try p.init(qname, true);
        try testing.expectEqual(
            SecurityStatus.insecure,
            validateNegativeProof(&p.rrs, qname, .a, false, test_root, &b),
        );
    }
    {
        var p: OptOutProof = .{};
        try p.init(qname, false);
        try testing.expectEqual(
            SecurityStatus.secure,
            validateNegativeProof(&p.rrs, qname, .a, false, test_root, &b),
        );
    }
}

test "NSEC3 NODATA wildcard-expanded (RFC 5155 §8.7)" {
    const qname = dns.Name.lit("missing.example.com");
    const ce_name = dns.Name.lit("example.com");
    const wc_name = dns.Name.lit("*.example.com");
    const zone_name = dns.Name.lit("com");
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(nsec3Hash(ce_name, salt, 0), zone_name, &bufs1);
    var bufs2: Nsec3OwnerBufs = .{};
    const nc_rr = makeCoveringNsec3(nsec3Hash(qname, salt, 0), zone_name, salt, &bufs2);
    var bufs3: Nsec3OwnerBufs = .{};
    const wc_owner = makeNsec3OwnerName(nsec3Hash(wc_name, salt, 0), zone_name, &bufs3);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        makeNsec3Rr(wc_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .https, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .https, true, test_root, &b));
}

test "NSEC3 NODATA NXDOMAIN-shape under NOERROR (RFC 5155 §8.4)" {
    const qname = dns.Name.lit("missing.example.com");
    const ce_name = dns.Name.lit("example.com");
    const wc_name = dns.Name.lit("*.example.com");
    const zone_name = dns.Name.lit("com");
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(nsec3Hash(ce_name, salt, 0), zone_name, &bufs1);
    var bufs2: Nsec3OwnerBufs = .{};
    const nc_rr = makeCoveringNsec3(nsec3Hash(qname, salt, 0), zone_name, salt, &bufs2);
    var bufs3: Nsec3OwnerBufs = .{};
    const wc_rr = makeCoveringNsec3(nsec3Hash(wc_name, salt, 0), zone_name, salt, &bufs3);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        wc_rr,
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
}

test "classifyDelegation NSEC3 match" {
    const child_zone = dns.Name.lit("unsigned.example.com");
    const zone_name = dns.Name.lit("example.com");
    const salt: []const u8 = &.{};

    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(nsec3Hash(child_zone, salt, 0), zone_name, &bufs);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x20 })};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unsigned, classifyDelegation(&authorities, child_zone, zone_name, &b));
}

test "classifyDelegation NSEC3 signed below or beside the cut proves nothing" {
    const child_zone = dns.Name.lit("bank.com");
    const salt: []const u8 = &.{ 0xAA, 0xBB };
    var bufs: [2]Nsec3OwnerBufs = .{ .{}, .{} };
    var span = makeCoveringNsec3(nsec3Hash(child_zone, salt, 0), test_com, salt, &bufs[0]);
    setNsec3(&span, "flags", nsec3_opt_out);
    const ce = makeNsec3Rr(makeNsec3OwnerName(nsec3Hash(test_com, salt, 0), test_com, &bufs[1]), salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x22 });

    var b: rrsig.ValidationBudget = .{};
    for ([_]struct { dns.Name, Delegation }{
        .{ test_com, .unsigned },
        .{ .lit("evil.com"), .unproven },
        .{ .lit("bank.com"), .unproven },
    }) |case| {
        try testing.expectEqual(case[1], classifyDelegation(&.{ ce, span }, child_zone, case[0], &b));
    }
}

test "classifyDelegation NSEC3 Opt-Out span below a secure delegation proves nothing (RFC 5155 §8.6)" {
    const victim = dns.Name.lit("victim.com");
    const child_zone = dns.Name.lit("x.victim.com");
    const salt: []const u8 = &.{};
    var bufs: [4]Nsec3OwnerBufs = .{ .{}, .{}, .{}, .{} };
    var span = makeCoveringNsec3(nsec3Hash(child_zone, salt, 0), test_com, salt, &bufs[0]);
    setNsec3(&span, "flags", nsec3_opt_out);
    const apex = makeNsec3Rr(makeNsec3OwnerName(nsec3Hash(test_com, salt, 0), test_com, &bufs[1]), salt, &bufs[0].high, &[_]u8{ 0x00, 0x01, 0x22 });
    const cut = makeNsec3Rr(makeNsec3OwnerName(nsec3Hash(victim, salt, 0), test_com, &bufs[2]), salt, &bufs[0].high, &[_]u8{ 0x00, 0x06, 0x20, 0x00, 0x00, 0x00, 0x00, 0x10 });

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&.{ span, apex, cut }, child_zone, test_com, &b));
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&.{span}, child_zone, test_com, &b));
    const direct = dns.Name.lit("unsigned.com");
    var span2 = makeCoveringNsec3(nsec3Hash(direct, salt, 0), test_com, salt, &bufs[3]);
    setNsec3(&span2, "flags", nsec3_opt_out);
    try testing.expectEqual(Delegation.unsigned, classifyDelegation(&.{ span2, apex }, direct, test_com, &b));
}

test "NSEC3 hash budget exhaustion" {
    const qname = dns.Name.lit("l00.l01.l02.l03.l04.l05.l06.l07.l08.l09.l10.l11.l12.l13.l14.l15." ++
        "l16.l17.l18.l19.l20.l21.l22.l23.l24.l25.l26.l27.l28.l29.l30.l31.l32.example.com");
    const salt: []const u8 = &.{};

    var bufs: Nsec3OwnerBufs = .{};
    const zone_name = dns.Name.lit("com");
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_name, &bufs);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0x43)), &.{})};

    var b: rrsig.ValidationBudget = .{ .max_nsec3_blocks = 32 };
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

test "NSEC3 iterations cost budget, never a verdict (RFC 9276 §3.2)" {
    const qname = dns.Name.lit("www.example.com");
    var bufs: Nsec3OwnerBufs = .{};
    const zone_name = dns.Name.lit("com");
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_name, &bufs);
    var authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, &.{}, &@as([20]u8, @splat(0x43)), &.{})};
    setNsec3(&authorities[0], "iterations", 200);

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, zone_name, test_root, &b));
    try testing.expect(!b.exhausted());

    setNsec3(&authorities[0], "iterations", 65535);
    b = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
    try testing.expect(b.stopped == .nsec3);
}

test "classifyDelegation refuses mixed NSEC3 parameter sets before hashing (RFC 5155 §8.2)" {
    const N: usize = 6;
    const child_zone = dns.Name.lit("victim.example.com");
    const zone_name = dns.Name.lit("example.com");

    var bufs: [N]Nsec3OwnerBufs = undefined;
    var unique_salts: [N][1]u8 = undefined;
    var rrs: [N]dns.ResourceRecord = undefined;
    const next_owner: [20]u8 = @splat(0xFF);

    for (0..N) |i| {
        bufs[i] = .{};
        unique_salts[i] = .{@as(u8, @intCast(i))};
        const owner = makeNsec3OwnerName(@as([20]u8, @splat(@as(u8, @intCast(i ^ 0xA5)))), zone_name, &bufs[i]);
        rrs[i] = makeNsec3Rr(owner, &unique_salts[i], &next_owner, &.{});
    }

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.bogus, classifyDelegation(&rrs, child_zone, zone_name, &b));
    try testing.expectEqual(@as(u32, 0), b.nsec3_blocks_spent);
}

test "refuses NSEC3 floods before hashing or verifying (Knot >8-record cap)" {
    const N: usize = max_proof_records + 1;
    const zone_name = dns.Name.lit("example.com");
    const salt: []const u8 = &.{};
    const next_owner: [20]u8 = @splat(0xFF);

    var bufs: [N]Nsec3OwnerBufs = undefined;
    var rrs: [N]dns.ResourceRecord = undefined;
    for (0..N) |i| {
        bufs[i] = .{};
        const owner = makeNsec3OwnerName(@as([20]u8, @splat(@as(u8, @intCast(i ^ 0xA5)))), zone_name, &bufs[i]);
        rrs[i] = makeNsec3Rr(owner, salt, &next_owner, &.{});
    }

    var b: rrsig.ValidationBudget = .{};
    const child_zone = dns.Name.lit("victim.example.com");
    try testing.expectEqual(Delegation.bogus, classifyDelegation(&rrs, child_zone, zone_name, &b));
    const qname = dns.Name.lit("absent.example.com");
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&rrs, qname, .a, true, test_root, &b));
    try testing.expectEqual(@as(u32, 0), b.nsec3_blocks_spent);
}

test "NSEC3 budget accumulates across negative-proof calls" {
    const qname = dns.Name.lit("example.com");
    const salt: []const u8 = &.{};

    var bufs: Nsec3OwnerBufs = .{};
    const zone_name = dns.Name.lit("com");
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_name, &bufs);
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0x43)), &.{})};

    var b: rrsig.ValidationBudget = .{ .max_nsec3_blocks = 3 };
    const first = validateNegativeProof(&authorities, qname, .a, false, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, first);
    try testing.expectEqual(@as(u32, 3), b.nsec3_blocks_spent);
    const second = validateNegativeProof(&authorities, qname, .a, false, test_root, &b);
    try testing.expectEqual(SecurityStatus.bogus, second);
}

test "an NSEC3 NXDOMAIN proof hashes its next closer once" {
    const qname = dns.Name.lit("www.example.com");
    const next_closer = dns.Name.lit("example.com");
    const wildcard = dns.Name.lit("*.com");
    const salt: []const u8 = &.{};
    var bufs: [3]Nsec3OwnerBufs = .{ .{}, .{}, .{} };
    const ce_next: [20]u8 = @splat(0);
    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(makeNsec3OwnerName(nsec3Hash(test_com, salt, 0), test_com, &bufs[0]), salt, &ce_next, &com_apex_bitmap),
        makeCoveringNsec3(nsec3Hash(next_closer, salt, 0), test_com, salt, &bufs[1]),
        makeCoveringNsec3(nsec3Hash(wildcard, salt, 0), test_com, salt, &bufs[2]),
    };
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, true, test_com, &b));
    try testing.expectEqual(@as(u32, 4), b.nsec3_blocks_spent);
}

test "nsec3Hash KAT: wire-captured jsc.nasa.gov owner hash" {
    const child_zone = dns.Name.lit("jsc.nasa.gov");
    const salt = [_]u8{ 0xA3, 0xB6, 0xC3, 0xF4, 0x96, 0x50, 0x04, 0xE9 };
    const computed = nsec3Hash(child_zone, &salt, 10);

    var expected: [Sha1.digest_length]u8 = undefined;
    _ = try base32HexDecode(&expected, "DF7PJ50CNKS1EEOTS4FK0RPUAVGUGL2T");
    try testing.expectEqualSlices(u8, &expected, &computed);
}

test "proveNoCloserMatch NSEC" {
    const foo = dns.Name.lit("foo.example.com");
    const zone = dns.Name.lit("example.com");
    const cover = [_]dns.ResourceRecord{nsecRr(.lit("bar.example.com"), .lit("zzz.example.com"))};
    const elsewhere = [_]dns.ResourceRecord{nsecRr(.lit("aaa.example.com"), .lit("bbb.example.com"))};
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, proveNoCloserMatch(&cover, foo, 2, zone, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&.{}, foo, 2, zone, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&elsewhere, foo, 2, zone, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&cover, foo, 1, zone, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&cover, foo, 3, zone, &b));

    const a_b = dns.Name.lit("a.b.example.com");
    const deep = [_]dns.ResourceRecord{nsecRr(.lit("0.b.example.com"), .lit("z.b.example.com"))};
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&deep, a_b, 2, zone, &b));
    try testing.expectEqual(SecurityStatus.secure, proveNoCloserMatch(&deep, a_b, 3, zone, &b));
}

test "proveNoCloserMatch NSEC3" {
    const qname = dns.Name.lit("foo.example.com");
    const ce = dns.Name.lit("example.com");
    const zone_name = dns.Name.lit("example.com");
    const salt: []const u8 = &.{};
    var bufs: Nsec3OwnerBufs = .{};
    var nc = makeCoveringNsec3(nsec3Hash(qname, salt, 0), zone_name, salt, &bufs);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, proveNoCloserMatch(&.{nc}, qname, 2, ce, &b));
    setNsec3(&nc, "flags", nsec3_opt_out);
    try testing.expectEqual(SecurityStatus.insecure, proveNoCloserMatch(&.{nc}, qname, 2, ce, &b));
    var ce_bufs: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(nsec3Hash(ce, salt, 0), zone_name, &ce_bufs);
    const ce_only = [_]dns.ResourceRecord{makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &.{})};
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&ce_only, qname, 2, ce, &b));
}

test "base32hex decode ignores case and refuses characters outside the alphabet" {
    var buf1: [20]u8 = undefined;
    var buf2: [20]u8 = undefined;
    const n1 = try base32HexDecode(&buf1, "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM");
    const n2 = try base32HexDecode(&buf2, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");
    try testing.expectEqualSlices(u8, buf1[0..n1], buf2[0..n2]);
    try testing.expectError(error.InvalidBase32, base32HexDecode(&buf1, "INVALID!CHARS@@@@@@@@@@@@@@@@@@@!"));
}
