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
    /// Not yet checked (DNSSEC disabled or initial state)
    unchecked,
    /// Fully validated chain from root trust anchor
    secure,
    /// Provably unsigned (no DS from signed parent) — valid, not an error
    insecure,
    /// Validation failed — MUST return ServFail
    bogus,
};

/// RFC 6840 §4.4: an NSEC/NSEC3 type bitmap proves an insecure delegation
/// when DS is absent, NS is present (proving delegation), and SOA is absent
/// (proving this is the parent-zone record, not a child-zone apex record).
fn isInsecureDelegationProof(type_bit_maps: []const u8) bool {
    return !dns.typeBitmapContains(type_bit_maps, .ds) and isAncestorDelegation(type_bit_maps);
}

pub fn isProperAncestor(zone: dns.Name, name: dns.Name) bool {
    return zone.labels.len < name.labels.len and name.isSubdomainOf(zone);
}

pub fn deepestApex(name: dns.Name, rtype: dns.RType) dns.Name {
    return if (rtype == .ds and name.labels.len > 0) .{ .labels = name.labels[1..] } else name;
}

pub const Delegation = enum {
    unsigned,
    unproven,
    bogus,
};

/// `zone` is the signer the caller verified the section under. The §8.6
/// closest-encloser walk stops a genuine Opt-Out span of `com` covering
/// `hash(x.victim.com)` from routing signed `victim.com` to unsigned servers.
pub fn classifyDelegation(
    authorities: []const dns.ResourceRecord,
    child_zone: dns.Name,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) Delegation {
    for (authorities) |rr| {
        if (rr.rtype == .ds and rr.name.eql(child_zone)) return .unproven;
    }
    // A no-DS proof is the parent's to make.
    if (!isProperAncestor(zone, child_zone)) return .unproven;
    if (hasMixedNsecNsec3(authorities)) return .bogus;

    for (authorities) |rr| {
        if (rr.rtype == .nsec and rr.name.eql(child_zone))
            return if (isInsecureDelegationProof(rr.rdata.nsec.type_bit_maps)) .unsigned else .unproven;
    }

    const salt, const iterations = switch (nsec3ChainParams(authorities, zone)) {
        .params => |p| .{ p.salt, p.iterations },
        .verdict => |v| return if (v == .bogus) .bogus else .unproven,
    };
    const child_hash = budgetedNsec3Hash(child_zone, salt, iterations, budget) catch return .bogus;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
        if (mem.eql(u8, &owner_hash, &child_hash))
            return if (isInsecureDelegationProof(rr.rdata.nsec3.type_bit_maps)) .unsigned else .unproven;
    }
    // RFC 5155 §8.6: closest encloser, then an Opt-Out span over the next
    // closer. No wildcard step: delegations are never synthesized.
    const ce = switch (nsec3ClosestEncloser(authorities, child_zone, child_hash, salt, iterations, zone, budget)) {
        .found => |f| f,
        .verdict => |v| return if (v == .bogus) .bogus else .unproven,
    };
    // Offset 0 is the owner match returned on above.
    std.debug.assert(ce.offset != 0);
    return if (nsec3Cover(authorities, zone, &ce.next_closer_hash) == true) .unsigned else .unproven;
}

/// Compare two DNS names in canonical ordering (RFC 4034 §6.1).
/// Labels are compared case-insensitively from rightmost to leftmost.
/// Returns .lt, .eq, or .gt.
pub fn canonicalNameOrder(a: dns.Name, b: dns.Name) std.math.Order {
    const min_labels = @min(a.labels.len, b.labels.len);
    for (0..min_labels) |i| {
        const a_idx = a.labels.len - 1 - i;
        const b_idx = b.labels.len - 1 - i;
        const cmp = cmpLabelsCI(a.labels[a_idx], b.labels[b_idx]);
        if (cmp != .eq) return cmp;
    }
    return std.math.order(a.labels.len, b.labels.len);
}

/// Number of trailing labels shared between two names (case-insensitive).
/// Used to derive the closest encloser from an NSEC that covers qname.
fn commonSuffixLabels(a: dns.Name, b: dns.Name) usize {
    const min_labels = @min(a.labels.len, b.labels.len);
    for (0..min_labels) |i| {
        const al = a.labels[a.labels.len - 1 - i];
        const bl = b.labels[b.labels.len - 1 - i];
        if (cmpLabelsCI(al, bl) != .eq) return i;
    }
    return min_labels;
}

/// Closest encloser of qname derived from a covering NSEC's endpoints
/// (RFC 4035 §5.4 / RFC 8198 §5.3): the longest label-suffix of qname also
/// shared with either bound. Null when a bound sits at or below qname: then
/// qname exists and is its own encloser. The result aliases qname's labels.
pub fn closestEncloser(qname: dns.Name, bound_a: dns.Name, bound_b: dns.Name) ?dns.Name {
    const depth = @max(commonSuffixLabels(qname, bound_a), commonSuffixLabels(qname, bound_b));
    if (depth >= qname.labels.len) return null;
    return .{ .labels = qname.labels[qname.labels.len - depth ..] };
}

test closestEncloser {
    const t = std.testing;
    const qname = dns.Name{ .labels = &.{ "a", "b", "example", "com" } };
    // Ordinary cover: CE is the deepest shared suffix of either bound.
    const owner = dns.Name{ .labels = &.{ "z", "b", "example", "com" } };
    const next = dns.Name{ .labels = &.{ "example", "com" } };
    try t.expectEqual(@as(usize, 3), closestEncloser(qname, owner, next).?.labels.len);
    // A bound below qname says qname exists.
    const below = dns.Name{ .labels = &.{ "x", "a", "b", "example", "com" } };
    try t.expectEqual(null, closestEncloser(qname, below, next));
    try t.expectEqual(null, closestEncloser(.{ .labels = &.{} }, owner, next));
}

fn cmpLabelsCI(a: []const u8, b: []const u8) std.math.Order {
    const min_len = @min(a.len, b.len);
    for (a[0..min_len], b[0..min_len]) |ac, bc| {
        const al = std.ascii.toLower(ac);
        const bl = std.ascii.toLower(bc);
        if (al < bl) return .lt;
        if (al > bl) return .gt;
    }
    return std.math.order(a.len, b.len);
}

/// Check if `target` falls in the open range (low, high) with wrap-around.
/// Works for both NSEC canonical name ordering and NSEC3 hash ordering.
fn inOpenRangeWrap(low: std.math.Order, target_vs_high: std.math.Order, low_vs_high: std.math.Order) bool {
    // low = cmp(low, target), so .lt means low < target
    if (low == .lt and target_vs_high == .lt) return true;
    if (low_vs_high == .gt or low_vs_high == .eq) {
        if (low == .lt or target_vs_high == .lt) return true;
    }
    return false;
}

/// RFC 6840 §4.1: an "ancestor delegation" NSEC/NSEC3 — NS bit set, SOA bit
/// clear — sits on the *parent* side of a zone cut. (The RFC's third
/// condition, signer shorter than owner, is implied: a zone's own apex
/// always carries SOA.)
fn isAncestorDelegation(type_bit_maps: []const u8) bool {
    return dns.typeBitmapContains(type_bit_maps, .ns) and
        !dns.typeBitmapContains(type_bit_maps, .soa);
}

/// RFC 6840 §4.1: records that prove nothing *below* their own owner name.
/// An ancestor delegation may not deny anything under the cut — the child is
/// authoritative there — and beneath a DNAME owner names are synthesized
/// rather than absent.
///
/// Without this, a TLD operator's genuine, correctly-signed record denies a
/// whole child zone: `example.com NSEC f.com` spans the entire example.com
/// subtree in canonical order, and an NSEC3 matching `hash(example.com)`
/// serves as closest encloser for every name in the child.
fn provesNothingBelowOwner(type_bit_maps: []const u8) bool {
    return isAncestorDelegation(type_bit_maps) or
        dns.typeBitmapContains(type_bit_maps, .dname);
}

/// RFC 6840 §4.1 + §4.4: whether a bitmap is on the wrong side of a zone cut
/// to deny `qtype` *at its own owner name*. A parent-side record knows only
/// NS/DS, so it may prove nothing but DS; a child-side record (SOA set) never
/// carries DS, so a missing DS bit there is not evidence that the delegation
/// is unsigned — that is an authenticated downgrade waiting to happen.
///
/// Unusable, not self-contradictory: callers return `.unchecked`, because the
/// server merely answered from the wrong side of its own cut.
fn wrongSideOfCut(type_bit_maps: []const u8, qname: dns.Name, qtype: dns.RType) bool {
    if (qtype == .ds) {
        // The root has no parent, so its own apex record is the only thing
        // that can ever answer for it.
        return qname.labels.len > 0 and dns.typeBitmapContains(type_bit_maps, .soa);
    }
    return isAncestorDelegation(type_bit_maps);
}

/// Whether `qname` falls in the open range (owner, next) of an NSEC allowed
/// to speak for it (RFC 6840 §4.1). Geometry only; meaning is decided below.
pub fn nsecCovers(nsec_owner: dns.Name, nsec: dns.NsecData, qname: dns.Name) bool {
    // Strictly below only: a range starting at an ancestor still legitimately
    // denies siblings in the same zone.
    if (qname.labels.len > nsec_owner.labels.len and qname.isSubdomainOf(nsec_owner) and
        provesNothingBelowOwner(nsec.type_bit_maps))
    {
        return false;
    }

    return inOpenRangeWrap(
        canonicalNameOrder(nsec_owner, qname),
        canonicalNameOrder(qname, nsec.next_domain_name),
        canonicalNameOrder(nsec_owner, nsec.next_domain_name),
    );
}

/// Whether an NSEC proves `qname` does not exist. One home for every consumer
/// (NXDOMAIN, wildcard denial, no-closer-match, aggressive use) so the ENT rule
/// can't be missing at one of them: an ENT denied under NXDOMAIN has its
/// whole subtree dropped by RFC 8020 caches.
pub fn nsecProvesNameNonexistence(
    nsec_owner: dns.Name,
    nsec: dns.NsecData,
    qname: dns.Name,
) bool {
    return nsecCovers(nsec_owner, nsec, qname) and !nsec.next_domain_name.isSubdomainOf(qname);
}

/// Whether an NSEC proves `qname` is an empty non-terminal: a next name below
/// qname means qname exists (RFC 4592 §2.2.2) and, owning no NSEC, has no
/// data. Existing names never match wildcards, so this settles NODATA alone.
fn nsecProvesEnt(nsec_owner: dns.Name, nsec: dns.NsecData, qname: dns.Name) bool {
    return nsecCovers(nsec_owner, nsec, qname) and nsec.next_domain_name.isSubdomainOf(qname);
}

/// RFC 4035 §5.4 + RFC 6840 §4.3: a NODATA proof fails if the bitmap
/// asserts qtype — or a CNAME, which would have answered the query —
/// exists at the owner. Also gates aggressive-use synthesis.
fn bitmapContradictsNodata(type_bit_maps: []const u8, qtype: dns.RType) bool {
    return dns.typeBitmapContains(type_bit_maps, qtype) or
        dns.typeBitmapContains(type_bit_maps, .cname);
}

/// RFC 5155 §3.1.2. A covered name may or may not exist as an insecure
/// delegation, so the span denies signed data only — hence §9.2's ban on AD.
const nsec3_opt_out: u8 = 0x01;

/// RFC 5155 §8.2: "A validator MUST ignore NSEC3 RRs with a Flag fields value
/// other than zero or one." Ignoring beats interpreting both ways: `0x02` read
/// as Opt-Out-clear turns a record we must discard into a forgery accusation,
/// `0x03` read as Opt-Out-set hands over the weaker verdict.
fn nsec3FlagsReserved(nsec3: dns.Nsec3Data) bool {
    return nsec3.flags & ~nsec3_opt_out != 0;
}

/// Per-message NSEC/NSEC3 ceiling (Knot 5.7.1, Unbound NsecTrap). An honest
/// proof needs ≤3; more is refused `.bogus` before any hashing or verifying.
pub const max_proof_records: usize = 8;

pub fn proofFlood(authorities: []const dns.ResourceRecord) bool {
    var n: usize = 0;
    for (authorities) |rr| {
        if (rr.rtype == .nsec or rr.rtype == .nsec3) n += 1;
    }
    return n > max_proof_records;
}

pub fn nsec3Hash(
    name: dns.Name,
    salt: []const u8,
    iterations: u16,
) error{BufferTooSmall}![Sha1.digest_length]u8 {
    var name_wire: [dns.max_name_len + 2]u8 = undefined;
    const name_len = try rrsig.writeCanonicalNameWire(&name_wire, name);

    // IH(0) = H(name_wire || salt)
    var hash: [Sha1.digest_length]u8 = undefined;
    var hasher = Sha1.init(.{});
    hasher.update(name_wire[0..name_len]);
    hasher.update(salt);
    hasher.final(&hash);

    // IH(k) = H(IH(k-1) || salt)
    var i: u16 = 0;
    while (i < iterations) : (i += 1) {
        var h2 = Sha1.init(.{});
        h2.update(&hash);
        h2.update(salt);
        h2.final(&hash);
    }

    return hash;
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
    if (name.labels.len == 0) return null;
    const label = name.labels[0];
    if (label.len != 32) return null; // SHA-1 = 20 bytes = 32 base32hex chars
    var result: [Sha1.digest_length]u8 = undefined;
    const n = dns.base32HexDecode(&result, label) catch return null;
    if (n != Sha1.digest_length) return null;
    return result;
}

/// Decode a record's owner name as a SHA-1 NSEC3 hash. Skips records that
/// aren't NSEC3 or use an unsupported hash algorithm — defence-in-depth so
/// an unknown-algo NSEC3 can't contribute to a SHA-1 negative proof.
fn supportedNsec3OwnerHash(rr: dns.ResourceRecord, zone: dns.Name) ?[Sha1.digest_length]u8 {
    if (rr.rtype != .nsec3 or !rr.name.isSubdomainOf(zone)) return null;
    if (rr.rdata.nsec3.hash_algorithm != .sha1) return null;
    if (nsec3FlagsReserved(rr.rdata.nsec3)) return null;
    return nsec3OwnerHash(rr.name);
}

const BudgetedHashError = error{ ValidationBudgetExhausted, HashFailed };

/// Compute NSEC3 hash, charging the per-query budget. Callers map both
/// ValidationBudgetExhausted (CVE-2023-50868, fail-closed) and HashFailed to .bogus.
fn budgetedNsec3Hash(
    name: dns.Name,
    salt: []const u8,
    iterations: u16,
    budget: *rrsig.ValidationBudget,
) BudgetedHashError![Sha1.digest_length]u8 {
    try budget.consumeNsec3(nsec3HashBlocks(name, salt.len, iterations));
    return nsec3Hash(name, salt, iterations) catch return error.HashFailed;
}

fn nsec3HashBlocks(name: dns.Name, salt_len: usize, iterations: u16) u32 {
    var name_len: usize = 1;
    for (name.labels) |l| name_len += l.len + 1;
    return sha1Blocks(name_len + salt_len) + @as(u32, iterations) * sha1Blocks(Sha1.digest_length + salt_len);
}

fn sha1Blocks(message_len: usize) u32 {
    return @intCast((message_len + 8) / 64 + 1);
}

/// Check if a response mixes NSEC and NSEC3.
/// Returns true if mixed (should reject the proof).
fn hasMixedNsecNsec3(authorities: []const dns.ResourceRecord) bool {
    var has_nsec = false;
    var has_nsec3 = false;
    for (authorities) |rr| {
        if (rr.rtype == .nsec) has_nsec = true;
        if (rr.rtype == .nsec3) has_nsec3 = true;
    }
    return has_nsec and has_nsec3;
}

/// Validate an NXDOMAIN or NODATA response using NSEC/NSEC3 proofs.
/// Returns the security status of the negative proof.
///
/// `zone` is the signer the caller authenticated these records under. It is
/// not optional bookkeeping: geometry alone cannot tell an unrelated zone's
/// NSEC from this zone's, so without it one genuine, publicly-fetchable wrap
/// NSEC out of any signed zone denies arbitrary names (`zzz.example.net NSEC
/// example.net` covers victim.com, the closest encloser clamps to root, and
/// the same record covers the wildcard).
///
/// Tests that exercise pure range geometry pass root, which makes the check
/// vacuous by construction.
pub fn validateNegativeProof(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) SecurityStatus {
    // A proof signed by some other zone says nothing about this name.
    if (!qname.isSubdomainOf(zone)) return .bogus;

    if (hasMixedNsecNsec3(authorities)) return .bogus;

    // One scan for both shapes: matching_nsec (owner == qname) → direct NODATA;
    // covering_nsec (range covers qname) → wildcard-NODATA (§3.1.3.4) or
    // NXDOMAIN-shape-under-NOERROR (§5.4 — proof shape is signed, not rcode).
    var matching_nsec: ?dns.ResourceRecord = null;
    var covering_nsec: ?dns.ResourceRecord = null;
    var ent = false;
    var any_nsec = false;
    for (authorities) |rr| {
        if (rr.rtype != .nsec) continue;
        // An owner outside the signing zone cannot be part of its chain, so
        // it is not proof material here regardless of what its range spans.
        if (!rr.name.isSubdomainOf(zone)) continue;
        any_nsec = true;
        if (matching_nsec == null and rr.name.eql(qname)) matching_nsec = rr;
        if (covering_nsec == null and
            nsecProvesNameNonexistence(rr.name, rr.rdata.nsec, qname))
        {
            covering_nsec = rr;
        }
        if (nsecProvesEnt(rr.name, rr.rdata.nsec, qname)) ent = true;
    }

    // NODATA arm. Bitmap contradicting NODATA → .bogus (signed, hence forgery).
    if (!is_nxdomain and any_nsec) {
        if (matching_nsec) |rr| {
            // Answered from the wrong side of its own cut: unusable, not
            // contradictory (RFC 6840 §4.1/§4.4). A parent-side NSEC owed us
            // a referral; a child-side one owed us nothing about DS.
            if (wrongSideOfCut(rr.rdata.nsec.type_bit_maps, qname, qtype))
                return .unchecked;
            return if (bitmapContradictsNodata(rr.rdata.nsec.type_bit_maps, qtype)) .bogus else .secure;
        }

        // ENT before wildcard (Unbound nsec_proves_nodata): every qmin step
        // through ip6.arpa's nibble tree lands here.
        if (ent) return .secure;

        if (covering_nsec) |cov| {
            const ce = closestEncloser(qname, cov.name, cov.rdata.nsec.next_domain_name) orelse
                return .unchecked;

            var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
            const wildcard = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unchecked;

            for (authorities) |rr| {
                if (rr.rtype != .nsec or !rr.name.isSubdomainOf(zone)) continue;
                if (rr.name.eql(wildcard)) {
                    // §3.1.3.4: *.CE exists; qtype + CNAME must be absent.
                    // A wildcard delegation's parent-side record denies
                    // nothing (RFC 6840 §4.1).
                    if (wrongSideOfCut(rr.rdata.nsec.type_bit_maps, qname, qtype))
                        return .unchecked;
                    if (bitmapContradictsNodata(rr.rdata.nsec.type_bit_maps, qtype))
                        return .bogus;
                    return .secure;
                }
                // §5.4 proof under NOERROR rcode: *.CE denied + qname denied.
                // A wildcard that is itself an ENT matches and owns nothing:
                // also NODATA.
                if (nsecCovers(rr.name, rr.rdata.nsec, wildcard))
                    return .secure;
            }
            return .unchecked;
        }
    }

    // RFC 4035 §5.4: NXDOMAIN requires both name denial AND wildcard denial at
    // the closest encloser. The CE is the longest label-suffix of qname that is
    // also a suffix of the covering NSEC's owner or next_domain_name.
    if (is_nxdomain and any_nsec) {
        const covering = covering_nsec orelse return .unchecked;
        const ce = closestEncloser(qname, covering.name, covering.rdata.nsec.next_domain_name) orelse
            return .unchecked;

        // No separate CE-existence check: CE is by construction a label-
        // suffix of a signature-verified NSEC bound, and every ancestor of
        // an existing name exists (RFC 4592 §2.2.2); ENTs never own an NSEC,
        // so an owner/next == CE check would reject every ip6.arpa NXDOMAIN.
        // Unbound proves name-error from qname + wildcard denial alone;
        // forged NSECs die at RRSIG verification, not here.
        var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
        const wildcard = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unchecked;

        // An NSEC owned by *.CE says the wildcard exists: NXDOMAIN was the wrong rcode.
        var wildcard_denied = false;
        for (authorities) |rr| {
            if (rr.rtype != .nsec or !rr.name.isSubdomainOf(zone)) continue;
            if (rr.name.eql(wildcard)) return .bogus;
            if (nsecProvesNameNonexistence(rr.name, rr.rdata.nsec, wildcard)) wildcard_denied = true;
        }
        return if (wildcard_denied) .secure else .unchecked;
    }

    return validateNsec3NegativeProof(authorities, qname, qtype, is_nxdomain, zone, budget);
}

/// The zone whose keys an authority section's proofs rest on: the signer of
/// its first RRSIG. `verifyAuthorityProofSigs` only reports .secure when every
/// NSEC/NSEC3/SOA owner verifies under a key fetched for this name, so after
/// a .secure verdict this name is the proof's whole authority.
pub fn authoritySigner(authorities: []const dns.ResourceRecord) ?dns.Name {
    for (authorities) |rr| {
        if (rr.rtype == .rrsig) return rr.rdata.rrsig.signer_name;
    }
    return null;
}

const Nsec3ChainParams = union(enum) {
    params: struct { salt: []const u8, iterations: u16 },
    verdict: SecurityStatus,
};

fn nsec3ChainParams(authorities: []const dns.ResourceRecord, zone: dns.Name) Nsec3ChainParams {
    if (proofFlood(authorities)) return .{ .verdict = .bogus };

    var salt: []const u8 = &.{};
    var iterations: u16 = 0;
    var found_nsec3 = false;
    for (authorities) |rr| {
        if (rr.rtype != .nsec3 or !rr.name.isSubdomainOf(zone)) continue;
        const nsec3 = rr.rdata.nsec3;
        // §8.1 and §8.2: unknown hash algorithms and reserved flags are
        // ignored, so they can't define the chain's parameters. A section
        // holding only such records proves nothing and fails closed, as
        // §8.1 expects and Unbound (filter_init) and Knot (hash_name) do.
        if (nsec3.hash_algorithm != .sha1 or nsec3FlagsReserved(nsec3)) continue;
        salt = nsec3.salt;
        iterations = nsec3.iterations;
        found_nsec3 = true;
        break;
    }
    if (!found_nsec3) return .{ .verdict = .unchecked };

    // RFC 5155 §8.2: MAY treat disagreeing hash/iterations/salt as bogus, as
    // Unbound's `param_set_same` (`val_nsec3.c:1583`) does. One parameter set is
    // what makes Opt-Out sound: within a chain nothing covers `hash(qname)` when
    // a record owns that name, because some `next` equals it exactly and ranges
    // are open at both ends. A second chain forges next-closer coverage.
    for (authorities) |rr| {
        if (rr.rtype != .nsec3 or !rr.name.isSubdomainOf(zone)) continue;
        const n3 = rr.rdata.nsec3;
        if (n3.hash_algorithm != .sha1 or nsec3FlagsReserved(n3)) continue; // §8.1/§8.2: ignored
        if (n3.iterations != iterations or !mem.eql(u8, n3.salt, salt)) return .{ .verdict = .bogus };
    }
    return .{ .params = .{ .salt = salt, .iterations = iterations } };
}

const ClosestEncloser = union(enum) {
    found: struct { offset: usize, next_closer_hash: [Sha1.digest_length]u8 },
    verdict: SecurityStatus,
};

/// RFC 5155 §8.3: hash qname and each ancestor until one owns an NSEC3.
/// RFC 6840 §4.1: a delegation or DNAME owner anchors nothing below it, else
/// a TLD's delegation NSEC3 would enclose every name in the child zone.
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
    for (0..qname.labels.len) |label_offset| {
        // Nothing above the signer is in its chain; don't pay to hash it.
        if (qname.labels.len - label_offset < zone.labels.len) break;
        const ancestor_hash = if (label_offset == 0) qname_hash else budgetedNsec3Hash(
            .{ .labels = qname.labels[label_offset..] },
            salt,
            iterations,
            budget,
        ) catch return .{ .verdict = .bogus };
        for (authorities) |rr| {
            const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
            if (!mem.eql(u8, &owner_hash, &ancestor_hash)) continue;
            if (provesNothingBelowOwner(rr.rdata.nsec3.type_bit_maps)) return .{ .verdict = .unchecked };
            return .{ .found = .{ .offset = label_offset, .next_closer_hash = below_hash } };
        }
        below_hash = ancestor_hash;
    }
    return .{ .verdict = .unchecked };
}

/// Whether some NSEC3 span covers `hash`, and if so whether any coverer has
/// Opt-Out. All coverers, not the first: an attacker picks the order.
fn nsec3Cover(authorities: []const dns.ResourceRecord, zone: dns.Name, hash: *const [Sha1.digest_length]u8) ?bool {
    var covered = false;
    var optout = false;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
        if (!nsec3HashInRange(&owner_hash, rr.rdata.nsec3.next_hashed_owner, hash)) continue;
        covered = true;
        if (rr.rdata.nsec3.flags & nsec3_opt_out != 0) optout = true;
    }
    return if (covered) optout else null;
}

/// RFC 4035 §5.3.4: without proof that nothing exists between `qname` and the
/// closest encloser the RRSIG's `labels` names, a captured `*.zone` answer
/// replays as any name in the zone. Cf. Unbound `nsec3_prove_wildcard`.
pub fn proveNoCloserMatch(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    labels: u8,
    zone: dns.Name,
    budget: *rrsig.ValidationBudget,
) SecurityStatus {
    if (labels >= qname.labels.len) return .bogus;
    const ce = dns.Name{ .labels = qname.labels[qname.labels.len - labels ..] };
    for (authorities) |rr| {
        if (rr.rtype != .nsec or !rr.name.isSubdomainOf(zone)) continue;
        if (!nsecProvesNameNonexistence(rr.name, rr.rdata.nsec, qname)) continue;
        // §5.3.4 asks for a cover of the next closer name; a cover of `qname`
        // whose closest encloser is `ce` is the same fact (both bounds fall
        // outside `ce`'s subtree on `qname`'s side, so the next closer sits
        // between them too). A cover bounded below `ce` instead proves a
        // deeper name exists: wrong wildcard.
        const nsec_ce = closestEncloser(qname, rr.name, rr.rdata.nsec.next_domain_name) orelse continue;
        if (nsec_ce.eql(ce)) return .secure;
    }

    // No NSEC3 chain either: the owed proof is absent.
    const salt, const iterations = switch (nsec3ChainParams(authorities, zone)) {
        .params => |p| .{ p.salt, p.iterations },
        .verdict => |v| return if (v == .unchecked) .bogus else v,
    };
    const next_closer = dns.Name{ .labels = qname.labels[qname.labels.len - labels - 1 ..] };
    const nc_hash = budgetedNsec3Hash(next_closer, salt, iterations, budget) catch return .bogus;
    const optout = nsec3Cover(authorities, zone, &nc_hash) orelse return .bogus;
    return if (optout) .insecure else .secure;
}

/// Validate NSEC3 negative proofs (RFC 5155 §8.4/§8.5/§8.6/§8.7).
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

    // hash(qname) is needed by both the NODATA direct-match check and the CE
    // walk's label_offset==0 iteration; compute once.
    const qname_hash = budgetedNsec3Hash(qname, salt, iterations, budget) catch return .bogus;

    // Direct NODATA at hash(qname) (RFC 5155 §8.5). Bitmap contradicting
    // NODATA → .bogus (mirrors NSEC arm).
    if (!is_nxdomain) {
        for (authorities) |rr| {
            const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
            if (mem.eql(u8, &owner_hash, &qname_hash)) {
                const nsec3 = rr.rdata.nsec3;
                // Same side-of-cut rule as the NSEC arm (RFC 6840 §4.1/§4.4).
                if (wrongSideOfCut(nsec3.type_bit_maps, qname, qtype)) return .unchecked;
                if (bitmapContradictsNodata(nsec3.type_bit_maps, qtype)) {
                    return .bogus;
                }
                return .secure;
            }
        }
        // No owner-match: fall through to CE proof. Handles wildcard-NODATA
        // (§8.6) and NXDOMAIN-shape-under-NOERROR (§8.4).
    }

    // Closest-encloser proof (RFC 5155 §8.4 / §8.6). Shared by NXDOMAIN rcode
    // and NODATA fallthrough; the wildcard step below distinguishes them.
    const found = switch (nsec3ClosestEncloser(authorities, qname, qname_hash, salt, iterations, zone, budget)) {
        .found => |f| f,
        .verdict => |v| return v,
    };
    const ce_offset = found.offset;

    // CE == qname contradicts NXDOMAIN (and wildcard-expansion semantics).
    if (ce_offset == 0) return .bogus;

    const nc_hash = found.next_closer_hash;

    var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
    const ce = dns.Name{ .labels = qname.labels[ce_offset..] };
    const wildcard = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unchecked;
    const wc_hash = budgetedNsec3Hash(wildcard, salt, iterations, budget) catch return .bogus;

    // Wildcard step: covered (§8.4) or, under NOERROR only, owner-match lacking
    // qtype and CNAME (§8.6). Any other owner-match means *.CE exists and the
    // answer should have been an expansion or NODATA.
    const nc_cover = nsec3Cover(authorities, zone, &nc_hash);
    const nc_covered = nc_cover != null;
    const nc_optout = nc_cover orelse false;
    var wc_proven = false;
    var wc_optout = false;
    var wc_contradicted = false;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
        const nsec3 = rr.rdata.nsec3;

        // Every record, not the first: spans from two chain versions can
        // both verify, and the attacker orders them.
        if (nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &wc_hash)) {
            wc_proven = true;
            // An Opt-Out span denies signed data only: `*.CE` may still be
            // an unsigned delegation.
            if (nsec3.flags & nsec3_opt_out != 0) wc_optout = true;
        } else if (mem.eql(u8, &owner_hash, &wc_hash)) {
            if (is_nxdomain or bitmapContradictsNodata(nsec3.type_bit_maps, qtype)) {
                wc_contradicted = true;
            } else if (!wrongSideOfCut(nsec3.type_bit_maps, qname, qtype)) {
                wc_proven = true;
            }
        }
    }
    // RFC 5155 §8.6, NODATA for DS: an unsigned delegation under Opt-Out
    // matches no NSEC3, so CE match plus the Opt-Out span over the next
    // closer is the whole proof, wildcard unread — a DS answer is about a
    // name that exists (Unbound `nsec3_prove_nods`). §9.2: the span may hold
    // unsigned delegations, so no AD.
    if (qtype == .ds and !is_nxdomain and nc_covered and nc_optout) return .insecure;

    // A signed record saying `*.CE` owns qtype (or exists under NXDOMAIN) is
    // a lie no other record can outvote: under Opt-Out it would launder a
    // NODATA over a signed wildcard expansion.
    if (wc_contradicted) return .bogus;

    // RFC 5155 §9.2: AD MUST NOT be set when the next-closer coverer has
    // Opt-Out — that span may hold insecure delegations, so the denial is not
    // fully proven. Not DS-scoped, so every qtype (Unbound `val_nsec3.c:1231`,
    // `:1386`), and the wildcard coverer for the same reason.
    if (nc_covered and wc_proven) return if (nc_optout or wc_optout) .insecure else .secure;

    // Errata 3441 on §8.5: no wildcard proof, but the name sits in an
    // Opt-Out span — an unsigned delegation or an ENT the signer left out
    // (§7.1) — so NODATA for any qtype is insecure (Unbound
    // `nsec3_do_prove_nodata` case 5, Knot `kr_nsec3_no_data`).
    if (!is_nxdomain and nc_covered and nc_optout) return .insecure;
    return .unchecked;
}

/// Zone argument for tests that exercise pure range geometry: root makes the
/// qname/owner binding vacuous, so those tests keep testing exactly what they
/// tested before it existed.
const test_root = dns.Name{ .labels = &.{} };
pub const test_com = dns.Name{ .labels = &.{"com"} };

test "classifyDelegation with DS present" {
    const child_zone = dns.Name{
        .labels = &.{
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };

    const authorities = [_]dns.ResourceRecord{.{
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
    }};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, child_zone, test_com, &b));
}

test "classifyDelegation with NSEC proving no DS" {
    const child_zone = dns.Name{
        .labels = &.{
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };

    // NSEC record at child zone name, no DS in bitmap
    // Bitmap: A(1)=0x40, NS(2)=0x20 => byte 0 = 0x60
    const authorities = [_]dns.ResourceRecord{.{
        .name = child_zone,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 86400,
        .rdata = .{
            .nsec = .{
                .next_domain_name = dns.Name{
                    .labels = &.{
                        @as([]const u8, "next"),
                        @as([]const u8, "com"),
                    },
                },
                .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x60 }, // A + NS, no SOA/DS: parent-side cut
            },
        },
    }};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unsigned, classifyDelegation(&authorities, child_zone, test_com, &b));
}

test "classifyDelegation with no DS and no proof" {
    const child_zone = dns.Name{
        .labels = &.{
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };

    const ns_name = dns.Name{
        .labels = &.{
            @as([]const u8, "ns1"),
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };
    const authorities = [_]dns.ResourceRecord{.{
        .name = child_zone,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 86400,
        .rdata = .{ .ns = ns_name },
    }};

    // No DS and no NSEC/NSEC3 proof — indeterminate, so unproven
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, child_zone, test_com, &b));
}

test "classifyDelegation rejects invalid NSEC proofs (RFC 6840 §4.4)" {
    const child_zone = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const next = dns.Name{
        .labels = &.{ @as([]const u8, "next"), @as([]const u8, "com") },
    };

    // Both must return .secure — forces validation, unsigned child will SERVFAIL
    const cases = [_][]const u8{
        &[_]u8{ 0x00, 0x01, 0x22 }, // NS + SOA (child-zone apex, not parent delegation)
        &[_]u8{ 0x00, 0x01, 0x40 }, // A only (no NS — not a delegation point)
    };
    for (cases) |type_bit_maps| {
        const authorities = [_]dns.ResourceRecord{.{
            .name = child_zone,
            .rtype = .nsec,
            .rclass = .in,
            .ttl = 86400,
            .rdata = .{ .nsec = .{ .next_domain_name = next, .type_bit_maps = type_bit_maps } },
        }};
        var b: rrsig.ValidationBudget = .{};
        try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, child_zone, test_com, &b));
    }
}

test "canonical name ordering" {
    const root = dns.Name{ .labels = &.{} };
    const com = dns.Name{ .labels = &.{@as([]const u8, "com")} };
    const example_com = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const a_example_com = dns.Name{
        .labels = &.{ @as([]const u8, "a"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const z_example_com = dns.Name{
        .labels = &.{ @as([]const u8, "z"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const net = dns.Name{ .labels = &.{@as([]const u8, "net")} };

    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(root, com));
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(com, net));
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(com, example_com));
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(example_com, a_example_com));
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(a_example_com, z_example_com));
    try testing.expectEqual(std.math.Order.eq, canonicalNameOrder(com, com));
    try testing.expectEqual(std.math.Order.gt, canonicalNameOrder(net, com));
}

test "NSEC name non-existence" {
    const alpha = dns.Name{
        .labels = &.{ @as([]const u8, "alpha"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const gamma = dns.Name{
        .labels = &.{ @as([]const u8, "gamma"), @as([]const u8, "example"), @as([]const u8, "com") },
    };

    const nsec_data = dns.NsecData{
        .next_domain_name = gamma,
        .type_bit_maps = &.{},
    };

    const beta = dns.Name{
        .labels = &.{ @as([]const u8, "beta"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    try testing.expect(nsecProvesNameNonexistence(alpha, nsec_data, beta));

    const zeta = dns.Name{
        .labels = &.{ @as([]const u8, "zeta"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    try testing.expect(!nsecProvesNameNonexistence(alpha, nsec_data, zeta));

    try testing.expect(!nsecProvesNameNonexistence(alpha, nsec_data, alpha));
}

test "NSEC type non-existence" {
    const name = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };

    // Bitmap has A, NS and SOA but not AAAA
    // A(1)=0x40, NS(2)=0x20, SOA(6)=0x02 => byte0 = 0x62
    const nsec_data = dns.NsecData{
        .next_domain_name = dns.Name{ .labels = &.{@as([]const u8, "next")} },
        .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x62 },
    };

    const authorities = [_]dns.ResourceRecord{nsecRrWithBitmap(name, nsec_data.next_domain_name, nsec_data.type_bit_maps)};
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, name, .aaaa, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, name, .a, false, test_root, &b));
}

test "NSEC NODATA bogus when CNAME bit set (RFC 6840 §4.3)" {
    const name = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };

    // Bitmap with CNAME (5) at byte 0 bit 2 (0x04) and TXT (16) at byte 2 bit 7 (0x80).
    // Block: window 0, length 3, bytes 0x04, 0x00, 0x80.
    const cname_present = dns.NsecData{
        .next_domain_name = dns.Name{ .labels = &.{@as([]const u8, "next")} },
        .type_bit_maps = &[_]u8{ 0x00, 0x03, 0x04, 0x00, 0x80 },
    };
    const present = [_]dns.ResourceRecord{nsecRrWithBitmap(name, cname_present.next_domain_name, cname_present.type_bit_maps)};
    var b: rrsig.ValidationBudget = .{};
    // A query for AAAA must NOT be proved nonexistent — the CNAME would chain it.
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&present, name, .aaaa, false, test_root, &b));
    // A query for CNAME itself: the bit IS set, so proof fails (correctly).
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&present, name, .cname, false, test_root, &b));

    // Bitmap with TXT only — no CNAME, no AAAA.
    const cname_absent = dns.NsecData{
        .next_domain_name = dns.Name{ .labels = &.{@as([]const u8, "next")} },
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
    // Wrap-around: owner > next (last NSEC3 in zone)
    const owner = [_]u8{ 0xF0, 0xF0, 0xF0 };
    const next = [_]u8{ 0x10, 0x10, 0x10 };

    const target_after = [_]u8{ 0xF5, 0xF5, 0xF5 };
    try testing.expect(nsec3HashInRange(&owner, &next, &target_after));

    const target_before_next = [_]u8{ 0x05, 0x05, 0x05 };
    try testing.expect(nsec3HashInRange(&owner, &next, &target_before_next));

    const target_between = [_]u8{ 0x50, 0x50, 0x50 };
    try testing.expect(!nsec3HashInRange(&owner, &next, &target_between));
}

test "mixed NSEC/NSEC3 detection" {
    const name = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };

    const nsec_only = [_]dns.ResourceRecord{.{
        .name = name,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .nsec = .{
            .next_domain_name = name,
            .type_bit_maps = &.{},
        } },
    }};
    try testing.expect(!hasMixedNsecNsec3(&nsec_only));

    const nsec3_only = [_]dns.ResourceRecord{makeNsec3Rr(name, &.{}, &@as([20]u8, @splat(0)), &.{})};
    try testing.expect(!hasMixedNsecNsec3(&nsec3_only));

    const mixed = [_]dns.ResourceRecord{
        nsec_only[0],
        nsec3_only[0],
    };
    try testing.expect(hasMixedNsecNsec3(&mixed));
}

test "validateNegativeProof NSEC NODATA" {
    const name = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };

    // NSEC at the example.com apex has A, NS and SOA but not AAAA. SOA is
    // load-bearing: NS without it would make this the parent side of a cut,
    // which RFC 6840 §4.1 bars from proving anything but DS.
    const authorities = [_]dns.ResourceRecord{.{
        .name = name,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{
            .nsec = .{
                .next_domain_name = dns.Name{
                    .labels = &.{ @as([]const u8, "next"), @as([]const u8, "com") },
                },
                .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x62 }, // A + NS + SOA
            },
        },
    }};

    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, name, .aaaa, false, test_root, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
}

test "validateNegativeProof rejects an ancestor-delegation NSEC (RFC 6840 §4.1)" {
    // `example.com NSEC f.com` with NS set and SOA clear is the com side of
    // the cut. In canonical order its range spans the entire example.com
    // subtree, so without §4.1 a TLD operator's genuine, correctly-signed
    // record authenticates NXDOMAIN for every name in the child zone — and
    // NODATA for every type at the cut itself.
    const cut = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "f", "com" } };
    const parent_side = [_]u8{ 0x00, 0x01, 0x20 }; // NS only
    const child_apex = [_]u8{ 0x00, 0x01, 0x22 }; // NS + SOA
    const victim = dns.Name{ .labels = &.{ "www", "example", "com" } };

    var b: rrsig.ValidationBudget = .{};
    const parent_auth = [_]dns.ResourceRecord{nsecRrWithBitmap(cut, next, &parent_side)};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&parent_auth, victim, .a, true, test_root, &b),
    );
    // NODATA at the cut itself is equally barred — for every type but DS,
    // which is the one thing that does live on the parent side.
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&parent_auth, cut, .a, false, test_root, &b),
    );
    try testing.expectEqual(
        SecurityStatus.secure,
        validateNegativeProof(&parent_auth, cut, .ds, false, test_root, &b),
    );

    // Same geometry signed by the child: an apex NSEC carries SOA, and its
    // range legitimately denies names in its own zone.
    const child_auth = [_]dns.ResourceRecord{nsecRrWithBitmap(cut, next, &child_apex)};
    try testing.expectEqual(
        SecurityStatus.secure,
        validateNegativeProof(&child_auth, victim, .a, true, test_root, &b),
    );
}

test "validateNegativeProof NSEC NXDOMAIN" {
    const alpha = dns.Name{ .labels = &.{ "alpha", "example", "com" } };
    const gamma = dns.Name{ .labels = &.{ "gamma", "example", "com" } };
    const example_com = dns.Name{ .labels = &.{ "example", "com" } };

    // Two NSECs: one covering qname, one covering *.example.com.
    // *.example.com sorts before alpha.example.com, so we need an NSEC
    // that covers the wildcard range.
    const authorities = [_]dns.ResourceRecord{
        nsecRr(alpha, gamma),
        nsecRr(example_com, alpha), // covers *.example.com: example.com -> alpha.example.com
    };

    const beta = dns.Name{ .labels = &.{ "beta", "example", "com" } };
    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
}

test "validateNegativeProof NSEC NXDOMAIN without wildcard denial" {
    const alpha = dns.Name{ .labels = &.{ "alpha", "example", "com" } };
    const gamma = dns.Name{ .labels = &.{ "gamma", "example", "com" } };

    const authorities = [_]dns.ResourceRecord{nsecRr(alpha, gamma)};

    const beta = dns.Name{ .labels = &.{ "beta", "example", "com" } };
    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, status);
}

pub fn nsecRr(owner: dns.Name, next: dns.Name) dns.ResourceRecord {
    return .{
        .name = owner,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .nsec = .{ .next_domain_name = next, .type_bit_maps = &.{} } },
    };
}

test "validateNegativeProof NSEC NXDOMAIN deep CE (not zone apex)" {
    // qname = missing.sub.example.com; CE is sub.example.com, NOT example.com.
    // Covering NSEC endpoints share sub.example.com with qname; wildcard denial
    // must be at *.sub.example.com, not *.example.com.
    const aaa_sub = dns.Name{ .labels = &.{ "aaa", "sub", "example", "com" } };
    const zzz_sub = dns.Name{ .labels = &.{ "zzz", "sub", "example", "com" } };
    const sub = dns.Name{ .labels = &.{ "sub", "example", "com" } };
    const missing = dns.Name{ .labels = &.{ "missing", "sub", "example", "com" } };

    const authorities = [_]dns.ResourceRecord{
        nsecRr(aaa_sub, zzz_sub), // covers qname: aaa < missing < zzz
        nsecRr(sub, aaa_sub), // covers *.sub.example.com: sub < *.sub < aaa.sub
    };
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, missing, .a, true, test_root, &b));
}

test "validateNegativeProof NSEC NXDOMAIN deep CE rejects wrong-level wildcard" {
    // Same qname but the only wildcard denial present is for *.example.com,
    // not *.sub.example.com. RFC 4035 §5.4 requires denial at the CE; this
    // proof is incomplete and must NOT validate as secure.
    const aaa_sub = dns.Name{ .labels = &.{ "aaa", "sub", "example", "com" } };
    const zzz_sub = dns.Name{ .labels = &.{ "zzz", "sub", "example", "com" } };
    const example_com = dns.Name{ .labels = &.{ "example", "com" } };
    const aaa = dns.Name{ .labels = &.{ "aaa", "example", "com" } };
    const missing = dns.Name{ .labels = &.{ "missing", "sub", "example", "com" } };

    const authorities = [_]dns.ResourceRecord{
        nsecRr(aaa_sub, zzz_sub),
        nsecRr(example_com, aaa), // covers *.example.com only (wrong level)
    };
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, missing, .a, true, test_root, &b));
}

test "validateNegativeProof NSEC NXDOMAIN deep qname still needs wildcard denial" {
    // qname = a.b.c.example.com, single NSEC covering it. CE derives to
    // example.com, so the proof needs *.example.com denied — absent here.
    // Guards the incompleteness bar after the CE-equality check was removed:
    // a lone covering NSEC must never validate NXDOMAIN as secure.
    const aaa = dns.Name{ .labels = &.{ "aaa", "example", "com" } };
    const zzz = dns.Name{ .labels = &.{ "zzz", "example", "com" } };
    const qname = dns.Name{ .labels = &.{ "a", "b", "c", "example", "com" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(aaa, zzz)};
    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, qname, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, status);
}

test "validateNegativeProof NSEC NODATA at empty non-terminal (live ip6.arpa shape)" {
    // Captured 2026-07-24 from b.ip6-servers.arpa: `A 6.2.ip6.arpa` (a
    // qname-minimization step of a 2600::/12 PTR) answers NOERROR/NODATA
    // with a single NSEC 1.4.2.ip6.arpa -> 0.6.2.ip6.arpa. The next name
    // descends below qname ⇒ qname is an ENT ⇒ complete proof.
    const owner = dns.Name{ .labels = &.{ "1", "4", "2", "ip6", "arpa" } };
    const next = dns.Name{ .labels = &.{ "0", "6", "2", "ip6", "arpa" } };
    const qname = dns.Name{ .labels = &.{ "6", "2", "ip6", "arpa" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(owner, next)};
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
}

test "validateNegativeProof NSEC NXDOMAIN with ENT closest encloser (live ip6.arpa shape)" {
    // Captured 2026-07-24: `A xx.6.2.ip6.arpa` -> NXDOMAIN with two NSECs:
    // 3.6.2 -> 0.8.2 covers qname (CE = 6.2.ip6.arpa, an ENT no NSEC
    // names), 1.4.2 -> 0.6.2 covers the wildcard *.6.2.ip6.arpa. CE
    // existence is implied by the bounds' shared suffix.
    const authorities = [_]dns.ResourceRecord{
        nsecRr(
            .{ .labels = &.{ "3", "6", "2", "ip6", "arpa" } },
            .{ .labels = &.{ "0", "8", "2", "ip6", "arpa" } },
        ),
        nsecRr(
            .{ .labels = &.{ "1", "4", "2", "ip6", "arpa" } },
            .{ .labels = &.{ "0", "6", "2", "ip6", "arpa" } },
        ),
    };
    const qname = dns.Name{ .labels = &.{ "xx", "6", "2", "ip6", "arpa" } };
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

test "validateNegativeProof NSEC NXDOMAIN single NSEC covers both" {
    // A single NSEC that covers both the qname AND the wildcard.
    // example.com -> zeta.example.com covers both *.example.com and
    // beta.example.com (both sort between example.com and zeta).
    const example_com = dns.Name{ .labels = &.{ "example", "com" } };
    const zeta = dns.Name{ .labels = &.{ "zeta", "example", "com" } };

    const authorities = [_]dns.ResourceRecord{nsecRr(example_com, zeta)};

    const beta = dns.Name{ .labels = &.{ "beta", "example", "com" } };
    var b: rrsig.ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
}

fn nsecRrWithBitmap(owner: dns.Name, next: dns.Name, bitmap: []const u8) dns.ResourceRecord {
    return .{
        .name = owner,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .nsec = .{ .next_domain_name = next, .type_bit_maps = bitmap } },
    };
}

test "validateNegativeProof NSEC NXDOMAIN at an empty non-terminal is refused" {
    // IANA's genuine `ip6.arpa NSEC 3.0.0.1.0.0.2.ip6.arpa` proves 2.ip6.arpa
    // is an ENT. Replayed under NXDOMAIN it must not verify, or the RFC 8020
    // cache denies every 2xxx PTR with AD set.
    const apex = dns.Name{ .labels = &.{ "ip6", "arpa" } };
    const next = dns.Name{ .labels = &.{ "3", "0", "0", "1", "0", "0", "2", "ip6", "arpa" } };
    const qname = dns.Name{ .labels = &.{ "2", "ip6", "arpa" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(apex, next)};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
    // Nor is the ENT a wildcard expansion's "no closer match".
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&authorities, qname, 2, apex, &b));
}

test "validateNegativeProof NSEC NODATA wildcard-expanded (RFC 4035 §3.1.3.4)" {
    // go-vip.net shape: HTTPS on a wildcard-expanded name. Covering NSEC
    // proves no closer match; *.CE NSEC has A+AAAA+RRSIG+NSEC, no HTTPS(65).
    const lotus = dns.Name{ .labels = &.{ "lotus", "go-vip", "net" } };
    const ns1 = dns.Name{ .labels = &.{ "ns1", "go-vip", "net" } };
    const wildcard = dns.Name{ .labels = &.{ "*", "go-vip", "net" } };
    const acme = dns.Name{ .labels = &.{ "_acme-challenge", "go-vip", "net" } };
    const qname = dns.Name{ .labels = &.{ "nasa-tv", "go-vip", "net" } };

    // A(1)+AAAA(28)+RRSIG(46)+NSEC(47); HTTPS(65) and CNAME(5) absent.
    const wc_bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x08, 0x00, 0x03 };
    const authorities = [_]dns.ResourceRecord{
        nsecRr(lotus, ns1),
        nsecRrWithBitmap(wildcard, acme, &wc_bitmap),
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .https, false, test_root, &b));
    // Same records under NXDOMAIN: *.CE exists, contradiction.
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .https, true, test_root, &b));
}

test "validateNegativeProof NSEC NODATA wildcard with qtype present is .bogus" {
    const lotus = dns.Name{ .labels = &.{ "lotus", "go-vip", "net" } };
    const ns1 = dns.Name{ .labels = &.{ "ns1", "go-vip", "net" } };
    const wildcard = dns.Name{ .labels = &.{ "*", "go-vip", "net" } };
    const acme = dns.Name{ .labels = &.{ "_acme-challenge", "go-vip", "net" } };
    const qname = dns.Name{ .labels = &.{ "nasa-tv", "go-vip", "net" } };

    // Wildcard bitmap claims HTTPS(65) present — contradicts NODATA claim.
    const wc_bitmap = [_]u8{ 0x00, 0x09, 0x40, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x40 };
    const authorities = [_]dns.ResourceRecord{
        nsecRr(lotus, ns1),
        nsecRrWithBitmap(wildcard, acme, &wc_bitmap),
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .https, false, test_root, &b));
}

test "validateNegativeProof NSEC NODATA wildcard with CNAME present is .bogus" {
    // RFC 6840 §4.3: *.CE with CNAME in bitmap means the answer should have
    // chased the CNAME, not returned NODATA.
    const lotus = dns.Name{ .labels = &.{ "lotus", "go-vip", "net" } };
    const ns1 = dns.Name{ .labels = &.{ "ns1", "go-vip", "net" } };
    const wildcard = dns.Name{ .labels = &.{ "*", "go-vip", "net" } };
    const acme = dns.Name{ .labels = &.{ "_acme-challenge", "go-vip", "net" } };
    const qname = dns.Name{ .labels = &.{ "nasa-tv", "go-vip", "net" } };

    const wc_bitmap = [_]u8{ 0x00, 0x01, 0x04 }; // CNAME(5) only
    const authorities = [_]dns.ResourceRecord{
        nsecRr(lotus, ns1),
        nsecRrWithBitmap(wildcard, acme, &wc_bitmap),
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
}

test "validateNegativeProof NSEC NODATA owner-match with qtype in bitmap is .bogus" {
    const name = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "com" } };
    const bitmap = [_]u8{ 0x00, 0x04, 0x62, 0x00, 0x00, 0x08 }; // A+NS+SOA+AAAA
    const authorities = [_]dns.ResourceRecord{nsecRrWithBitmap(name, next, &bitmap)};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, name, .aaaa, false, test_root, &b));
}

test "validateNegativeProof NSEC NODATA covering but no wildcard proof is .unchecked" {
    // Covering range starts at aaa.example.com, so *.example.com sorts before
    // the range and isn't covered. No *.CE NSEC either.
    const aaa = dns.Name{ .labels = &.{ "aaa", "example", "com" } };
    const zzz = dns.Name{ .labels = &.{ "zzz", "example", "com" } };
    const qname = dns.Name{ .labels = &.{ "missing", "example", "com" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(aaa, zzz)};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
}

/// Build an NSEC3 owner name by base32hex-encoding a hash and appending zone labels.
/// Returns the label slices and Name referencing them. Caller must keep returned
/// struct alive for as long as the Name is used.
pub fn makeNsec3OwnerName(hash: [Sha1.digest_length]u8, zone_labels: []const []const u8, bufs: *Nsec3OwnerBufs) dns.Name {
    bufs.labels[0] = dns.base32HexEncode(&bufs.enc, &hash);
    for (zone_labels, 0..) |zl, i| bufs.labels[1 + i] = zl;
    return dns.Name{ .labels = bufs.labels[0 .. 1 + zone_labels.len] };
}

pub const Nsec3OwnerBufs = struct {
    enc: [32]u8 = undefined,
    labels: [4][]const u8 = undefined,
    /// Owner/next hashes for `makeCoveringNsec3`.
    low: [Sha1.digest_length]u8 = undefined,
    high: [Sha1.digest_length]u8 = undefined,
};

pub fn makeNsec3Rr(
    owner_name: dns.Name,
    salt: []const u8,
    next_hashed_owner: []const u8,
    type_bit_maps: []const u8,
) dns.ResourceRecord {
    return .{
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
    };
}

/// Build an NSEC3 RR whose range covers `target_hash` (owner = hash-1, next = hash+1).
fn makeCoveringNsec3(
    target_hash: [Sha1.digest_length]u8,
    zone_labels: []const []const u8,
    salt: []const u8,
    bufs: *Nsec3OwnerBufs,
) dns.ResourceRecord {
    bufs.low = target_hash;
    bufs.high = target_hash;
    bufs.low[19] -|= 1;
    bufs.high[19] +|= 1;
    const owner = makeNsec3OwnerName(bufs.low, zone_labels, bufs);
    return makeNsec3Rr(owner, salt, &bufs.high, &.{});
}

test "base32hex decode/encode roundtrip" {
    // RFC 5155 Appendix B: "example" with salt aabbccdd, 12 iterations
    // Expected base32hex: 0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM
    const name = dns.Name{ .labels = &.{@as([]const u8, "example")} };
    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const hash = try nsec3Hash(name, &salt, 12);

    var enc_buf: [32]u8 = undefined;
    const encoded = dns.base32HexEncode(&enc_buf, &hash);
    // RFC 5155 Appendix B known-answer: covers nsec3Hash and base32HexEncode.
    try testing.expectEqualStrings("0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM", encoded);

    var dec_buf: [20]u8 = undefined;
    const n = try dns.base32HexDecode(&dec_buf, encoded);
    try testing.expectEqual(@as(usize, 20), n);
    try testing.expectEqualSlices(u8, &hash, dec_buf[0..n]);
}

test "nsec3OwnerHash extraction" {
    const name = dns.Name{ .labels = &.{@as([]const u8, "example")} };
    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const hash = try nsec3Hash(name, &salt, 12);

    var enc_buf: [32]u8 = undefined;
    const encoded = dns.base32HexEncode(&enc_buf, &hash);

    const owner_name = dns.Name{
        .labels = &.{ encoded, @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const extracted = nsec3OwnerHash(owner_name).?;
    try testing.expectEqualSlices(u8, &hash, &extracted);

    const bad_name = dns.Name{ .labels = &.{@as([]const u8, "tooshort")} };
    try testing.expect(nsec3OwnerHash(bad_name) == null);

    const empty_name = dns.Name{ .labels = &.{} };
    try testing.expect(nsec3OwnerHash(empty_name) == null);
}

test "NSEC3 unknown hash algorithm is ignored and the proof fails closed (RFC 5155 §8.1)" {
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const owner_name = dns.Name{
        .labels = &.{ @as([]const u8, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), @as([]const u8, "com") },
    };
    const next: [20]u8 = @splat(0xFF);
    const authorities = [_]dns.ResourceRecord{.{
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
    }};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, qname, test_com, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&authorities, qname, 1, test_root, &b));
}

test "NSEC3 NODATA - secure" {
    // Query: example.com AAAA (NODATA)
    // NSEC3 at hash(example.com) has A, NS and SOA but not AAAA, not CNAME.
    // SOA is load-bearing: NS without it is the parent side of a cut, which
    // RFC 6840 §4.1 bars from proving anything but DS.
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const salt: []const u8 = &.{};
    const hash = try nsec3Hash(qname, salt, 0);

    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(hash, zone_labels, &bufs);

    // Bitmap: A(bit1=0x40) + NS(bit2=0x20) + SOA(bit6=0x02) = 0x62
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x62 })};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
}

test "NSEC3 rejects an ancestor-delegation record (RFC 6840 §4.1)" {
    // NSEC3 is what com/net/org actually sign with, so the §4.1 rule matters
    // more here than on the NSEC path. Two shapes, one genuine record: com's
    // own NSEC3 matching hash(example.com) with NS set and SOA clear.
    const salt: []const u8 = &.{};
    const zone_labels: []const []const u8 = &.{"com"};
    const cut = dns.Name{ .labels = &.{ "example", "com" } };
    const below = dns.Name{ .labels = &.{ "www", "example", "com" } };

    const cut_hash = try nsec3Hash(cut, salt, 0);
    var bufs: Nsec3OwnerBufs = .{};
    const cut_owner = makeNsec3OwnerName(cut_hash, zone_labels, &bufs);
    const parent_side = [_]u8{ 0x00, 0x01, 0x20 }; // NS only

    // (a) NODATA at the cut for a non-DS type: the parent's bitmap says
    //     nothing about what the child holds.
    var b: rrsig.ValidationBudget = .{};
    const at_cut = [_]dns.ResourceRecord{makeNsec3Rr(cut_owner, salt, &@as([20]u8, @splat(0xFF)), &parent_side)};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&at_cut, cut, .a, false, test_root, &b),
    );
    // DS is the exception that makes the delegation NSEC3 useful at all.
    try testing.expectEqual(
        SecurityStatus.secure,
        validateNegativeProof(&at_cut, cut, .ds, false, test_root, &b),
    );

    // (b) NXDOMAIN below the cut: the delegation NSEC3 must not serve as
    //     closest encloser. The next-closer and wildcard hashes are covered
    //     trivially — 0x00..0xFF spans everything — which is exactly why the
    //     CE anchor is the check that has to hold.
    const wide = [_]dns.ResourceRecord{
        makeNsec3Rr(cut_owner, salt, &@as([20]u8, @splat(0xFF)), &parent_side),
    };
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&wide, below, .a, true, test_root, &b),
    );
}

test "NSEC3 child-side apex cannot deny DS (RFC 6840 §4.4)" {
    // A signed child's own apex NSEC3 never carries the DS bit — DS lives in
    // the parent. Reading its absence as proof of an unsigned delegation is
    // an authenticated downgrade of the whole child zone.
    const salt: []const u8 = &.{};
    const apex = dns.Name{ .labels = &.{ "example", "com" } };
    const hash = try nsec3Hash(apex, salt, 0);
    var bufs: Nsec3OwnerBufs = .{};
    const owner = makeNsec3OwnerName(hash, &.{ "example", "com" }, &bufs);
    // A NS SOA RRSIG NSEC DNSKEY — no DS.
    const child_apex = [_]u8{ 0x00, 0x07, 0x62, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80 };

    var b: rrsig.ValidationBudget = .{};
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner, salt, &@as([20]u8, @splat(0xFF)), &child_apex)};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&authorities, apex, .ds, false, test_root, &b),
    );
    // It still answers what it legitimately can.
    try testing.expectEqual(
        SecurityStatus.secure,
        validateNegativeProof(&authorities, apex, .txt, false, test_root, &b),
    );
}

test "NSEC3 NODATA - CNAME in bitmap is .bogus" {
    // Mirrors NSEC arm: owner-match with CNAME in bitmap contradicts NODATA.
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "alias"), @as([]const u8, "com") },
    };
    const salt: []const u8 = &.{};
    const hash = try nsec3Hash(qname, salt, 0);

    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(hash, &.{@as([]const u8, "com")}, &bufs);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x04 })};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
}

test "NSEC3 NXDOMAIN - closest encloser proof" {
    // CE = example.com, NC = nonexistent.example.com, WC = *.example.com
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "nonexistent"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const ce_name = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const wc_name = dns.Name{
        .labels = &.{ @as([]const u8, "*"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1);

    var bufs2: Nsec3OwnerBufs = .{};
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2);

    var bufs3: Nsec3OwnerBufs = .{};
    const wc_rr = makeCoveringNsec3(try nsec3Hash(wc_name, salt, 0), zone_labels, salt, &bufs3);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        wc_rr,
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

test "NSEC3 NXDOMAIN - missing wildcard cover" {
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "gone"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const ce_name = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1);

    var bufs2: Nsec3OwnerBufs = .{};
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &.{}),
        nc_rr,
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

// RFC 4034 §4.1.2 bitmaps from the capture below. The delegation one is used as
// the *coverer's* bitmap on purpose: code that consulted it would cry forgery.
const com_apex_bitmap = [_]u8{ 0x00, 0x07, 0x22, 0x00, 0x00, 0x00, 0x00, 0x02, 0x90 };
const com_delegation_bitmap = [_]u8{ 0x00, 0x06, 0x20, 0x00, 0x00, 0x00, 0x00, 0x12 };

/// `com`'s Opt-Out shape for a DS query at an unsigned delegation, captured from
/// a.gtld-servers.net for `amazon.com DS`:
///
///   CK0POJMG874LJREF7EFN8430QVIT8BSM.com. NSEC3 1 1 0 -
///       ck0q3udg8cekkae7rukpgct1dvssh8ll NS SOA RRSIG DNSKEY NSEC3PARAM
///   K200V84I256ANM893J2Q7LOV6CAIURDF.com. NSEC3 1 1 0 -
///       k201knr33bbbf7esfva94jv96315189d NS DS RRSIG
///
/// hash(amazon.com) = K201BQSV52HID9F4GFEU8D70JL1218CH sits in the second range.
/// None at the child, and decisively nothing covering hash(*.com). Ranges are
/// synthesized ±1 rather than transcribed.
const OptOutDsProof = struct {
    ce_bufs: Nsec3OwnerBufs = .{},
    nc_bufs: Nsec3OwnerBufs = .{},
    ce_next: [Sha1.digest_length]u8 = undefined,
    rrs: [2]dns.ResourceRecord = undefined,

    /// `opt_out = false` makes the coverer a plain name-denial, which without
    /// a wildcard step proves nothing.
    fn init(self: *@This(), qname: dns.Name, opt_out: bool) !void {
        const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
        const salt: []const u8 = &.{};
        const ce = dns.Name{ .labels = zone_labels };
        const ce_hash = try nsec3Hash(ce, salt, 0);
        const ce_owner = makeNsec3OwnerName(ce_hash, zone_labels, &self.ce_bufs);
        // The CE's range must stop just past its own owner, as `com`'s does.
        // Sibling tests use 0xFF… here; that would break these — one NSEC3 may
        // legitimately be both CE match and next-closer coverer, so a maximal
        // range lets the CE cover it and the flag under test goes unread.
        self.ce_next = ce_hash;
        self.ce_next[Sha1.digest_length - 1] +|= 1;
        self.rrs[0] = makeNsec3Rr(ce_owner, salt, &self.ce_next, &com_apex_bitmap);
        self.rrs[0].rdata.nsec3.flags = nsec3_opt_out;
        self.rrs[1] = makeCoveringNsec3(
            try nsec3Hash(qname, salt, 0),
            zone_labels,
            salt,
            &self.nc_bufs,
        );
        self.rrs[1].rdata.nsec3.type_bit_maps = &com_delegation_bitmap;
        self.rrs[1].rdata.nsec3.flags = if (opt_out) nsec3_opt_out else 0;
    }
};

test "NSEC3 Opt-Out proves no DS, without AD (RFC 5155 §8.6 / §9.2)" {
    // §8.7's wildcard step must not be demanded here.
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var p: OptOutDsProof = .{};
    try p.init(qname, true);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.insecure,
        validateNegativeProof(&p.rrs, qname, .ds, false, test_root, &b),
    );
}

test "NSEC3 DS NODATA needs the Opt-Out flag (RFC 5155 §8.6)" {
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var p: OptOutDsProof = .{};
    try p.init(qname, false);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&p.rrs, qname, .ds, false, test_root, &b),
    );
}

test "NSEC3 Opt-Out NODATA is insecure for any qtype, never NXDOMAIN (RFC 5155 errata 3441)" {
    // A name in an Opt-Out span is an unsigned delegation or an omitted ENT,
    // insecure either way. NXDOMAIN still owes the wildcard denial (§8.4).
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var p: OptOutDsProof = .{};
    try p.init(qname, true);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.insecure,
        validateNegativeProof(&p.rrs, qname, .a, false, test_root, &b),
    );
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&p.rrs, qname, .ds, true, test_root, &b),
    );
}

test "NSEC3 reserved Flag bits make a record invisible (RFC 5155 §8.2)" {
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var b: rrsig.ValidationBudget = .{};
    // 0x03 = Opt-Out plus an undefined bit. §8.2 discards the record, so the
    // proof loses its coverer and is merely incomplete.
    {
        var p: OptOutDsProof = .{};
        try p.init(qname, true);
        p.rrs[1].rdata.nsec3.flags = nsec3_opt_out | 0x02;
        try testing.expectEqual(
            SecurityStatus.unchecked,
            validateNegativeProof(&p.rrs, qname, .ds, false, test_root, &b),
        );
    }
    // 0x02 bites hardest: read as "Opt-Out clear" it turns a record hark must
    // discard into a `.bogus` accusation against an honest zone.
    {
        var p: OptOutDsProof = .{};
        try p.init(qname, true);
        p.rrs[1].rdata.nsec3.flags = 0x02;
        try testing.expectEqual(
            SecurityStatus.unchecked,
            validateNegativeProof(&p.rrs, qname, .ds, false, test_root, &b),
        );
    }
}

test "NSEC3 proof mixing two parameter sets is bogus (RFC 5155 §8.2)" {
    // A coverer hashed under a second salt can be made to span anything, which
    // forges next-closer coverage. Unbound's `param_set_same` refuses likewise.
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var p: OptOutDsProof = .{};
    try p.init(qname, true);
    p.rrs[1].rdata.nsec3.salt = "X";
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        validateNegativeProof(&p.rrs, qname, .ds, false, test_root, &b),
    );
}

/// The `com`-shaped Opt-Out NXDOMAIN: apex NSEC3 as CE, an Opt-Out NSEC3
/// covering the next closer, a coverer for the wildcard. The overwhelmingly
/// common negative shape in practice — com, net and org are all Opt-Out.
const OptOutNxProof = struct {
    ce_bufs: Nsec3OwnerBufs = .{},
    nc_bufs: Nsec3OwnerBufs = .{},
    wc_bufs: Nsec3OwnerBufs = .{},
    ce_next: [Sha1.digest_length]u8 = undefined,
    rrs: [3]dns.ResourceRecord = undefined,

    fn init(self: *@This(), qname: dns.Name, nc_opt_out: bool) !void {
        const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
        const salt: []const u8 = &.{};
        const ce = dns.Name{ .labels = zone_labels };
        const ce_hash = try nsec3Hash(ce, salt, 0);
        const ce_owner = makeNsec3OwnerName(ce_hash, zone_labels, &self.ce_bufs);
        self.ce_next = ce_hash;
        self.ce_next[Sha1.digest_length - 1] +|= 1;
        self.rrs[0] = makeNsec3Rr(ce_owner, salt, &self.ce_next, &com_apex_bitmap);
        self.rrs[0].rdata.nsec3.flags = nsec3_opt_out;

        self.rrs[1] = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &self.nc_bufs);
        self.rrs[1].rdata.nsec3.type_bit_maps = &com_delegation_bitmap;
        self.rrs[1].rdata.nsec3.flags = if (nc_opt_out) nsec3_opt_out else 0;

        var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
        const wildcard = dns.makeWildcardName(&wc_labels_buf, ce).?;
        self.rrs[2] = makeCoveringNsec3(try nsec3Hash(wildcard, salt, 0), zone_labels, salt, &self.wc_bufs);
    }
};

test "NSEC3 Opt-Out NXDOMAIN must not set AD (RFC 5155 §9.2)" {
    const qname = dns.Name{ .labels = &.{ "victim", "com" } };
    var b: rrsig.ValidationBudget = .{};
    {
        var p: OptOutNxProof = .{};
        try p.init(qname, true);
        try testing.expectEqual(
            SecurityStatus.insecure,
            validateNegativeProof(&p.rrs, qname, .a, true, test_root, &b),
        );
    }
    // The guard that matters: no Opt-Out on the coverer, AD still applies.
    // Losing it strips AD from every signed NXDOMAIN there is.
    {
        var p: OptOutNxProof = .{};
        try p.init(qname, false);
        try testing.expectEqual(
            SecurityStatus.secure,
            validateNegativeProof(&p.rrs, qname, .a, true, test_root, &b),
        );
    }
}

test "NSEC3 NODATA under Opt-Out outranks a wildcard CNAME at the encloser (RFC 5155 §8.6, errata 3441)" {
    // `*.com CNAME` in an Opt-Out zone: DS for an omitted delegation is
    // NODATA even with the wildcard's NSEC3 in the section. Any other qtype
    // the wildcard would have answered, so NODATA is a lie; without the
    // wildcard record the name may be an omitted ENT (errata 3441).
    const qname = dns.Name{ .labels = &.{ "unsigned", "com" } };
    var p: OptOutDsProof = .{};
    try p.init(qname, true);
    var bufs: Nsec3OwnerBufs = .{};
    var wl: [dns.max_label_count + 1][]const u8 = undefined;
    const wc = dns.makeWildcardName(&wl, test_com).?;
    const cname_only = [_]u8{ 0x00, 0x01, 0x04 };
    const wc_rr = makeNsec3Rr(makeNsec3OwnerName(try nsec3Hash(wc, &.{}, 0), test_com.labels, &bufs), &.{}, &p.nc_bufs.high, &cname_only);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&.{ p.rrs[0], p.rrs[1], wc_rr }, qname, .ds, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&.{ p.rrs[0], p.rrs[1], wc_rr }, qname, .a, false, test_root, &b));
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&.{ p.rrs[0], p.rrs[1] }, qname, .a, false, test_root, &b));
}

test "NSEC3 wildcard coverer with Opt-Out counts wherever it sits in the section" {
    // Two spans over hash(*.com) can both verify, from chain versions before
    // and after the span went Opt-Out. Reading only the first let the stale
    // one buy AD.
    const qname = dns.Name{ .labels = &.{ "victim", "com" } };
    var p: OptOutNxProof = .{};
    try p.init(qname, false);
    var stale_first = p.rrs ++ [_]dns.ResourceRecord{p.rrs[2]};
    stale_first[3].rdata.nsec3.flags = nsec3_opt_out;
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&stale_first, qname, .a, true, test_root, &b));
}

test "NSEC3 Opt-Out NODATA-by-CE-proof must not set AD (RFC 5155 §9.2)" {
    // Same records under NOERROR — the §8.4-shape path, which shares the
    // wildcard step. Unbound's match: `val_nsec3.c:1386`.
    const qname = dns.Name{ .labels = &.{ "victim", "com" } };
    var b: rrsig.ValidationBudget = .{};
    {
        var p: OptOutNxProof = .{};
        try p.init(qname, true);
        try testing.expectEqual(
            SecurityStatus.insecure,
            validateNegativeProof(&p.rrs, qname, .a, false, test_root, &b),
        );
    }
    {
        var p: OptOutNxProof = .{};
        try p.init(qname, false);
        try testing.expectEqual(
            SecurityStatus.secure,
            validateNegativeProof(&p.rrs, qname, .a, false, test_root, &b),
        );
    }
}

test "NSEC3 NODATA wildcard-expanded (RFC 5155 §8.7)" {
    const qname = dns.Name{ .labels = &.{ "missing", "example", "com" } };
    const ce_name = dns.Name{ .labels = &.{ "example", "com" } };
    const wc_name = dns.Name{ .labels = &.{ "*", "example", "com" } };
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1);
    var bufs2: Nsec3OwnerBufs = .{};
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2);
    // *.CE NSEC3 owner-match with bitmap = A(1) only; HTTPS(65) and CNAME(5) absent.
    var bufs3: Nsec3OwnerBufs = .{};
    const wc_owner = makeNsec3OwnerName(try nsec3Hash(wc_name, salt, 0), zone_labels, &bufs3);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        makeNsec3Rr(wc_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .https, false, test_root, &b));
    // Same records under NXDOMAIN: *.CE exists, contradiction.
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .https, true, test_root, &b));
}

test "NSEC3 NODATA NXDOMAIN-shape under NOERROR (RFC 5155 §8.4)" {
    // §8.4-shape proof (CE + next-closer + wildcard all covered) under NOERROR.
    const qname = dns.Name{ .labels = &.{ "missing", "example", "com" } };
    const ce_name = dns.Name{ .labels = &.{ "example", "com" } };
    const wc_name = dns.Name{ .labels = &.{ "*", "example", "com" } };
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1);
    var bufs2: Nsec3OwnerBufs = .{};
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2);
    var bufs3: Nsec3OwnerBufs = .{};
    const wc_rr = makeCoveringNsec3(try nsec3Hash(wc_name, salt, 0), zone_labels, salt, &bufs3);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        wc_rr,
    };

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
}

test "classifyDelegation NSEC3 match" {
    // NSEC3 owner matches hash(child_zone), DS absent → insecure
    const child_zone = dns.Name{
        .labels = &.{ @as([]const u8, "unsigned"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const zone_labels: []const []const u8 = &.{ @as([]const u8, "example"), @as([]const u8, "com") };
    const salt: []const u8 = &.{};

    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(try nsec3Hash(child_zone, salt, 0), zone_labels, &bufs);

    // NS only (no DS)
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x20 })};

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unsigned, classifyDelegation(&authorities, child_zone, .{ .labels = zone_labels }, &b));
}

test "classifyDelegation NSEC3 signed below or beside the cut proves nothing" {
    const child_zone = dns.Name{ .labels = &.{ "bank", "com" } };
    const salt: []const u8 = &.{ 0xAA, 0xBB };
    var bufs: [2]Nsec3OwnerBufs = .{ .{}, .{} };
    var span = makeCoveringNsec3(try nsec3Hash(child_zone, salt, 0), test_com.labels, salt, &bufs[0]);
    span.rdata.nsec3.flags = nsec3_opt_out;
    // Every Opt-Out referral carries the closest encloser `com` itself.
    const ce = makeNsec3Rr(makeNsec3OwnerName(try nsec3Hash(test_com, salt, 0), test_com.labels, &bufs[1]), salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x22 });

    var b: rrsig.ValidationBudget = .{};
    for ([_]struct { []const []const u8, Delegation }{
        .{ test_com.labels, .unsigned },
        .{ &.{ "evil", "com" }, .unproven },
        .{ &.{ "bank", "com" }, .unproven },
    }) |case| {
        try testing.expectEqual(case[1], classifyDelegation(&.{ ce, span }, child_zone, .{ .labels = case[0] }, &b));
    }
}

test "classifyDelegation NSEC3 Opt-Out span below a secure delegation proves nothing (RFC 5155 §8.6)" {
    // com's chain: `victim.com` signed (NS+DS), the rest Opt-Out. The walk
    // stops at victim.com's cut, so the span over hash(x.victim.com) proves
    // nothing.
    const victim = dns.Name{ .labels = &.{ "victim", "com" } };
    const child_zone = dns.Name{ .labels = &.{ "x", "victim", "com" } };
    const salt: []const u8 = &.{};
    var bufs: [4]Nsec3OwnerBufs = .{ .{}, .{}, .{}, .{} };
    var span = makeCoveringNsec3(try nsec3Hash(child_zone, salt, 0), test_com.labels, salt, &bufs[0]);
    span.rdata.nsec3.flags = nsec3_opt_out;
    const apex = makeNsec3Rr(makeNsec3OwnerName(try nsec3Hash(test_com, salt, 0), test_com.labels, &bufs[1]), salt, &bufs[0].high, &[_]u8{ 0x00, 0x01, 0x22 });
    const cut = makeNsec3Rr(makeNsec3OwnerName(try nsec3Hash(victim, salt, 0), test_com.labels, &bufs[2]), salt, &bufs[0].high, &[_]u8{ 0x00, 0x06, 0x20, 0x00, 0x00, 0x00, 0x00, 0x10 });

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&.{ span, apex, cut }, child_zone, test_com, &b));
    // Without the cut record the encloser is unproven.
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&.{span}, child_zone, test_com, &b));
    // A direct child of com in the same span is the honest Opt-Out shape.
    const direct = dns.Name{ .labels = &.{ "unsigned", "com" } };
    var span2 = makeCoveringNsec3(try nsec3Hash(direct, salt, 0), test_com.labels, salt, &bufs[3]);
    span2.rdata.nsec3.flags = nsec3_opt_out;
    try testing.expectEqual(Delegation.unsigned, classifyDelegation(&.{ span2, apex }, direct, test_com, &b));
}

test "classifyDelegation NSEC3 non-match" {
    const child_zone = dns.Name{
        .labels = &.{ @as([]const u8, "signed"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const zone_labels: []const []const u8 = &.{ @as([]const u8, "example"), @as([]const u8, "com") };
    const salt: []const u8 = &.{};

    const other_name = dns.Name{
        .labels = &.{ @as([]const u8, "other"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(try nsec3Hash(other_name, salt, 0), zone_labels, &bufs);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0)), &[_]u8{ 0x00, 0x01, 0x20 })};

    // NSEC3 doesn't cover the child zone — indeterminate, so unproven
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, child_zone, .{ .labels = zone_labels }, &b));
}

test "NSEC3 hash budget exhaustion" {
    // CVE-2023-50868: a deep ancestor walk under a tight budget exhausts before
    // the CE is found. Exhausting the whole-query budget is an attack signal, so
    // the proof fails CLOSED to .bogus rather than degrading to insecure.
    const deep_labels: []const []const u8 = &.{
        "l00", "l01",     "l02", "l03", "l04", "l05", "l06", "l07",
        "l08", "l09",     "l10", "l11", "l12", "l13", "l14", "l15",
        "l16", "l17",     "l18", "l19", "l20", "l21", "l22", "l23",
        "l24", "l25",     "l26", "l27", "l28", "l29", "l30", "l31",
        "l32", "example", "com",
    };
    const qname = dns.Name{ .labels = deep_labels };
    const salt: []const u8 = &.{};

    // One unrelated NSEC3 — will never match any ancestor, so budget gets exhausted
    var bufs: Nsec3OwnerBufs = .{};
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_labels, &bufs);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0x43)), &.{})};

    var b: rrsig.ValidationBudget = .{ .max_nsec3_blocks = 32 };
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

test "NSEC3 iterations cost budget, never a verdict (RFC 9276 §3.2)" {
    const qname = dns.Name{ .labels = &.{ "www", "example", "com" } };
    var bufs: Nsec3OwnerBufs = .{};
    const zone_labels: []const []const u8 = &.{"com"};
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_labels, &bufs);
    var authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, &.{}, &@as([20]u8, @splat(0x43)), &.{})};
    authorities[0].rdata.nsec3.iterations = 200;

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
    try testing.expectEqual(Delegation.unproven, classifyDelegation(&authorities, .{ .labels = zone_labels }, test_root, &b));
    try testing.expect(!b.exhausted());

    authorities[0].rdata.nsec3.iterations = 65535;
    b = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
    try testing.expect(b.nsec3Exhausted());
}

test "classifyDelegation refuses mixed NSEC3 parameter sets before hashing (RFC 5155 §8.2)" {
    const N: usize = 6;
    const child_zone = dns.Name{ .labels = &.{ "victim", "example", "com" } };
    const zone_labels: []const []const u8 = &.{ "example", "com" };

    var bufs: [N]Nsec3OwnerBufs = undefined;
    var unique_salts: [N][1]u8 = undefined;
    var rrs: [N]dns.ResourceRecord = undefined;
    const next_owner: [20]u8 = @splat(0xFF);

    for (0..N) |i| {
        bufs[i] = .{};
        unique_salts[i] = .{@as(u8, @intCast(i))};
        const owner = makeNsec3OwnerName(@as([20]u8, @splat(@as(u8, @intCast(i ^ 0xA5)))), zone_labels, &bufs[i]);
        rrs[i] = makeNsec3Rr(owner, &unique_salts[i], &next_owner, &.{});
    }

    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(Delegation.bogus, classifyDelegation(&rrs, child_zone, .{ .labels = zone_labels }, &b));
    try testing.expectEqual(@as(u32, 0), b.nsec3_blocks_spent);
}

test "refuses NSEC3 floods before hashing or verifying (Knot >8-record cap)" {
    const N: usize = max_proof_records + 1;
    const zone_labels: []const []const u8 = &.{ "example", "com" };
    const salt: []const u8 = &.{};
    const next_owner: [20]u8 = @splat(0xFF);

    var bufs: [N]Nsec3OwnerBufs = undefined;
    var rrs: [N]dns.ResourceRecord = undefined;
    for (0..N) |i| {
        bufs[i] = .{};
        const owner = makeNsec3OwnerName(@as([20]u8, @splat(@as(u8, @intCast(i ^ 0xA5)))), zone_labels, &bufs[i]);
        rrs[i] = makeNsec3Rr(owner, salt, &next_owner, &.{});
    }

    var b: rrsig.ValidationBudget = .{};
    const child_zone = dns.Name{ .labels = &.{ "victim", "example", "com" } };
    try testing.expectEqual(Delegation.bogus, classifyDelegation(&rrs, child_zone, .{ .labels = zone_labels }, &b));
    const qname = dns.Name{ .labels = &.{ "absent", "example", "com" } };
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&rrs, qname, .a, true, test_root, &b));
    try testing.expectEqual(@as(u32, 0), b.nsec3_blocks_spent);
}

test "NSEC3 budget accumulates across negative-proof calls" {
    // One ValidationBudget is shared across resolve(); two calls must
    // accumulate. NODATA-with-no-owner-match hashes qname once, then ancestors
    // in the CE walk; label_offset==0 reuses qname_hash, so a 2-label qname
    // costs 2 hashes per call (qname + com).
    const qname = dns.Name{ .labels = &.{ "example", "com" } };
    const salt: []const u8 = &.{};

    var bufs: Nsec3OwnerBufs = .{};
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_labels, &bufs);
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0x43)), &.{})};

    var b: rrsig.ValidationBudget = .{ .max_nsec3_blocks = 2 };
    const first = validateNegativeProof(&authorities, qname, .a, false, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, first);
    try testing.expectEqual(@as(u32, 2), b.nsec3_blocks_spent);
    const second = validateNegativeProof(&authorities, qname, .a, false, test_root, &b);
    try testing.expectEqual(SecurityStatus.bogus, second);
}

test "an NSEC3 NXDOMAIN proof hashes its next closer once" {
    const qname = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const next_closer = dns.Name{ .labels = &.{ "example", "com" } };
    const wildcard = dns.Name{ .labels = &.{ "*", "com" } };
    const salt: []const u8 = &.{};
    var bufs: [3]Nsec3OwnerBufs = .{ .{}, .{}, .{} };
    const ce_next: [20]u8 = @splat(0);
    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(makeNsec3OwnerName(try nsec3Hash(test_com, salt, 0), test_com.labels, &bufs[0]), salt, &ce_next, &com_apex_bitmap),
        makeCoveringNsec3(try nsec3Hash(next_closer, salt, 0), test_com.labels, salt, &bufs[1]),
        makeCoveringNsec3(try nsec3Hash(wildcard, salt, 0), test_com.labels, salt, &bufs[2]),
    };
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, true, test_com, &b));
    try testing.expectEqual(@as(u32, 4), b.nsec3_blocks_spent);
}

test "nsec3Hash KAT: wire-captured jsc.nasa.gov owner hash" {
    // Known-answer test against an authoritative-server NSEC3 proof, captured
    // from a1-32.akam.net for `jsc.nasa.gov DS`. Catches regressions in
    // iteration count, hash chaining, or canonical name wire encoding that
    // a roundtrip test would miss.
    const child_zone = dns.Name{ .labels = &.{ "jsc", "nasa", "gov" } };
    const salt = [_]u8{ 0xA3, 0xB6, 0xC3, 0xF4, 0x96, 0x50, 0x04, 0xE9 };
    const computed = try nsec3Hash(child_zone, &salt, 10);

    var expected: [Sha1.digest_length]u8 = undefined;
    _ = try dns.base32HexDecode(&expected, "DF7PJ50CNKS1EEOTS4FK0RPUAVGUGL2T");
    try testing.expectEqualSlices(u8, &expected, &computed);
}

test "proveNoCloserMatch NSEC" {
    // `*.example.com` (labels=2) answered `foo.example.com`.
    const foo = dns.Name{ .labels = &.{ "foo", "example", "com" } };
    const zone = dns.Name{ .labels = &.{ "example", "com" } };
    const cover = [_]dns.ResourceRecord{nsecRr(.{ .labels = &.{ "bar", "example", "com" } }, .{ .labels = &.{ "zzz", "example", "com" } })};
    const elsewhere = [_]dns.ResourceRecord{nsecRr(.{ .labels = &.{ "aaa", "example", "com" } }, .{ .labels = &.{ "bbb", "example", "com" } })};
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, proveNoCloserMatch(&cover, foo, 2, zone, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&.{}, foo, 2, zone, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&elsewhere, foo, 2, zone, &b));
    // Signed by `*.com`: the cover's closest encloser is example.com, not com.
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&cover, foo, 1, zone, &b));
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&cover, foo, 3, zone, &b));

    // Cover bounded inside `b.example.com` proves that name exists, so
    // `*.example.com` never matched (RFC 4592 §3.3.1); `*.b.example.com` did.
    const a_b = dns.Name{ .labels = &.{ "a", "b", "example", "com" } };
    const deep = [_]dns.ResourceRecord{nsecRr(.{ .labels = &.{ "0", "b", "example", "com" } }, .{ .labels = &.{ "z", "b", "example", "com" } })};
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&deep, a_b, 2, zone, &b));
    try testing.expectEqual(SecurityStatus.secure, proveNoCloserMatch(&deep, a_b, 3, zone, &b));
}

test "proveNoCloserMatch NSEC3" {
    const qname = dns.Name{ .labels = &.{ "foo", "example", "com" } };
    const ce = dns.Name{ .labels = &.{ "example", "com" } };
    const zone_labels: []const []const u8 = &.{ "example", "com" };
    const salt: []const u8 = &.{};
    var bufs: Nsec3OwnerBufs = .{};
    var nc = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs);
    var b: rrsig.ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, proveNoCloserMatch(&.{nc}, qname, 2, ce, &b));
    nc.rdata.nsec3.flags = nsec3_opt_out;
    try testing.expectEqual(SecurityStatus.insecure, proveNoCloserMatch(&.{nc}, qname, 2, ce, &b));
    // The CE's own record names the wildcard's parent and denies nothing.
    var ce_bufs: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce, salt, 0), zone_labels, &ce_bufs);
    const ce_only = [_]dns.ResourceRecord{makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &.{})};
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&ce_only, qname, 2, ce, &b));
}
