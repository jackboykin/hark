//! The chain of trust: root anchors, DNSKEY and DS, and RRset validation
//! against a signer's keys (RFC 4035 §5), over proof.zig and rrsig.zig.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

const proof = @import("proof.zig");
const rrsig = @import("rrsig.zig");

// ── Root Trust Anchors (IANA root-anchors.xml) ───────────────────────

pub const root_ds_records = [_]dns.DsData{
    // KSK-2017 (active signer)
    .{
        .key_tag = 20326,
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &[32]u8{
            0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39,
            0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
            0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34,
            0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
        },
    },
    // KSK-2024 (pre-published, signing starts Oct 2026)
    .{
        .key_tag = 38696,
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &[32]u8{
            0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71,
            0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74, 0x12, 0x19,
            0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48,
            0x3A, 0xF4, 0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16,
        },
    },
};

/// RFC 4034 §2.1.1–2: a DNSKEY is usable for RRSIG verification only if
/// the Zone Key flag (bit 7) is set and the protocol field is 3.
/// RFC 5011 §2.1 additionally bars revoked keys (bit 8) from validating.
fn isValidZoneKey(dk: dns.DnskeyData) bool {
    return dk.isZoneKey() and dk.protocol == 3 and !dk.isRevoked();
}

/// RFC 4509 §3: a SHA-1 DS is ignored when the RRset also carries a SHA-256
/// one hark can use — one for an unsupported key algorithm anchors nothing
/// (RFC 6840 §5.2), so it must not silence the SHA-1 that does.
fn dsEligible(ds: dns.DsData, ds_records: []const dns.DsData) bool {
    if (ds.digest_type != .sha1) return true;
    for (ds_records) |ds2| if (ds2.digest_type == .sha256 and rrsig.isSupportedAlgorithm(ds2.algorithm)) return false;
    return true;
}

/// Remembers nothing; unit tests exercise the math alone.
var test_memo: rrsig.VerifyMemo = .{};

test "dsEligible: SHA-1 yields to a usable SHA-256 DS anywhere in the RRset, not to an unusable one" {
    const ds = struct {
        fn make(tag: u16, algo: dns.DnssecAlgorithm, digest_type: dns.DigestType) dns.DsData {
            return .{ .key_tag = tag, .algorithm = algo, .digest_type = digest_type, .digest = &.{} };
        }
    }.make;
    const sha1 = ds(1, .ecdsap256sha256, .sha1);
    try testing.expect(dsEligible(sha1, &.{sha1}));
    try testing.expect(!dsEligible(sha1, &.{ sha1, ds(2, .ecdsap256sha256, .sha256) }));
    try testing.expect(dsEligible(sha1, &.{ sha1, ds(2, .ed448, .sha256) }));
    try testing.expect(dsEligible(ds(1, .ecdsap256sha256, .sha256), &.{ds(2, .ecdsap256sha256, .sha256)}));
}

pub fn validateDnskeyRrset(
    dnskey_records: []const dns.ResourceRecord,
    ds_records: []const dns.DsData,
    zone_name: dns.Name,
    now_u32: u32,
    budget: *rrsig.ValidationBudget,
    memo: *rrsig.VerifyMemo,
) rrsig.VerifyError!dns.RrsigData {
    // Filter to only DNSKEY records for signature verification.
    // Response answers may include RRSIG records alongside DNSKEYs;
    // including them in buildSignedData would corrupt the verification.
    // Overflow refuses instead of truncating: a signature that verifies over
    // dnskey_only[0..64] would authenticate a *subset* while the caller keeps
    // and caches every key in the message — appended forged keys would ride in
    // as trusted. Same rule as validateRrset and verifyAuthorityProofSigs.
    var dnskey_only: [64]dns.ResourceRecord = undefined;
    var dnskey_count: usize = 0;
    for (dnskey_records) |rr| {
        if (rr.rtype != .dnskey) continue;
        if (dnskey_count == dnskey_only.len) return error.InvalidKey;
        dnskey_only[dnskey_count] = rr;
        dnskey_count += 1;
    }
    const filtered = dnskey_only[0..dnskey_count];

    // Anchor pass: mark each usable zone key that some eligible DS
    // authenticates (tag + algorithm match, digest verifies). The DS
    // hashing happens once per key here, never per RRSIG attempt below.
    var key_tags: [64]u16 = undefined;
    var anchored: [64]bool = undefined;
    for (filtered, 0..) |rr, i| {
        const dk = rr.rdata.dnskey;
        key_tags[i] = rrsig.keyTag(dk);
        anchored[i] = blk: {
            if (!isValidZoneKey(dk)) break :blk false;
            for (ds_records) |ds| {
                if (ds.key_tag != key_tags[i]) continue;
                if (@backingInt(ds.algorithm) != @backingInt(dk.algorithm)) continue;
                if (!dsEligible(ds, ds_records)) continue;
                verifyDs(ds, dk, zone_name) catch continue;
                break :blk true;
            }
            break :blk false;
        };
    }

    // RFC 6840 §5.11: try every RRSIG covering DNSKEY against every
    // anchored key whose tag matches. One flat walk — a (rrsig, key)
    // pair is attempted at most once, so identical attempts are never
    // re-charged against the KeyTrap budget.
    // Unless the DS advertises ML-DSA-44: then only an ML-DSA-44 RRSIG
    // counts (draft-westerbaan-dnssec-mldsa §7.2, RFC 4035 §5.3.3 policy).
    const pq = hasMlDsaDs(ds_records);
    for (dnskey_records) |rrsig_rr| {
        if (rrsig_rr.rtype != .rrsig) continue;
        const sig = rrsig_rr.rdata.rrsig;
        if (sig.type_covered != .dnskey) continue;
        if (pq and sig.algorithm != .mldsa44) continue;
        for (filtered, 0..) |rr, i| {
            if (!anchored[i] or key_tags[i] != sig.key_tag) continue;
            if (try rrsig.tryVerifyRrsig(sig, rr.rdata.dnskey, filtered, now_u32, budget, memo)) return sig;
        }
    }
    return error.InvalidSignature;
}

/// A DS hark can't digest anchors nothing (RFC 4035 §5.2), so it demands
/// nothing either; the DS RRset is signed, so that is the zone's choice.
fn hasMlDsaDs(ds_records: []const dns.DsData) bool {
    for (ds_records) |ds| if (ds.algorithm == .mldsa44 and digestSupported(ds.digest_type) and dsEligible(ds, ds_records)) return true;
    return false;
}

/// A signature that cannot fit the 1232 B UDP payload, so every DO
/// answer from a zone signed with it truncates. Transport only: no
/// eligibility filter, the zone signs with it whether or not the DS
/// digest is one hark can use.
fn signatureExceedsUdp(alg: dns.DnssecAlgorithm) bool {
    return alg == .mldsa44; // 2420 B
}

pub fn dsExceedsUdp(rrs: []const dns.ResourceRecord) bool {
    for (rrs) |rr| if (rr.rtype == .ds and signatureExceedsUdp(rr.rdata.ds.algorithm)) return true;
    return false;
}

fn digestSupported(digest_type: dns.DigestType) bool {
    return switch (digest_type) {
        .sha1, .sha256, .sha384 => true,
        _ => false,
    };
}

/// The keys a verified keyset may validate with below the apex. Under a
/// DS advertising ML-DSA-44 only the ML-DSA-44 keys survive: the apex
/// already refused every other signature, and verifyRrsig binds an RRSIG
/// to a key of its own algorithm, so a classical RRSIG has nothing left to
/// verify against. No per-RRset check, no flag. The apex RRSIGs are dropped
/// too: no keyset consumer reads them and they would not verify over the
/// subset. Any other DS set leaves the keyset whole (RFC 6840 §5.11). The
/// result borrows `records` or lives in `allocator`; free it with an arena.
pub fn usableKeys(allocator: mem.Allocator, records: []const dns.ResourceRecord, ds_records: []const dns.DsData) ![]const dns.ResourceRecord {
    if (!hasMlDsaDs(ds_records)) return records;
    const keep = struct {
        fn f(rr: dns.ResourceRecord) bool {
            return rr.rtype == .dnskey and rr.rdata.dnskey.algorithm == .mldsa44;
        }
    }.f;
    var n: usize = 0;
    for (records) |rr| n += @intFromBool(keep(rr));
    const kept = try allocator.alloc(dns.ResourceRecord, n);
    n = 0;
    for (records) |rr| if (keep(rr)) {
        kept[n] = rr;
        n += 1;
    };
    return kept;
}

/// RFC 4034 §5.1.4: digest of canonical owner name || DNSKEY RDATA.
pub fn dsDigest(comptime Hash: type, owner: dns.Name, dnskey: dns.DnskeyData) error{BufferTooSmall}![Hash.digest_length]u8 {
    var name_buf: [255]u8 = undefined;
    const name_len = try rrsig.writeCanonicalNameWire(&name_buf, owner);
    var h = Hash.init(.{});
    h.update(name_buf[0..name_len]);
    h.update(&mem.toBytes(mem.nativeToBig(u16, dnskey.flags)));
    h.update(&.{ dnskey.protocol, @backingInt(dnskey.algorithm) });
    h.update(dnskey.public_key);
    return h.finalResult();
}

fn verifyDs(ds: dns.DsData, dnskey: dns.DnskeyData, owner_name: dns.Name) rrsig.VerifyError!void {
    const ok = switch (ds.digest_type) {
        .sha1 => mem.eql(u8, &try dsDigest(Sha1, owner_name, dnskey), ds.digest),
        .sha256 => mem.eql(u8, &try dsDigest(Sha256, owner_name, dnskey), ds.digest),
        .sha384 => mem.eql(u8, &try dsDigest(Sha384, owner_name, dnskey), ds.digest),
        _ => return error.UnsupportedAlgorithm,
    };
    if (!ok) return error.InvalidSignature;
}

/// RFC 4035 §5.2: a DS contributes an authentication path only when both its
/// key algorithm and digest type are implemented here. An authenticated DS
/// RRset with no such member must be treated as proven-no-DS (insecure), not
/// secure — otherwise every zone signed only with an unimplemented algorithm
/// SERVFAILs (live shape: ed448.nl / ed448.no, Ed448-only). Unbound's
/// equivalent is the "zone has no known algorithms" → sec_status_insecure
/// check; the digest arms mirror verifyDs.
pub fn anySupportedDs(records: []const dns.ResourceRecord) bool {
    for (records) |rr| {
        if (rr.rtype != .ds) continue;
        const ds = rr.rdata.ds;
        if (rrsig.isSupportedAlgorithm(ds.algorithm) and digestSupported(ds.digest_type)) return true;
    }
    return false;
}

/// Zone keys with tags computed once per call, not per RRSIG tried (TagTrap).
const Keyset = struct {
    keys: [64]dns.DnskeyData = undefined,
    tags: [64]u16 = undefined,
    len: usize = 0,

    /// Null past 64 keys, the ceiling `validateDnskeyRrset` admits.
    fn init(records: []const dns.ResourceRecord) ?Keyset {
        var k: Keyset = .{};
        for (records) |rr| {
            if (rr.rtype != .dnskey or !isValidZoneKey(rr.rdata.dnskey)) continue;
            if (k.len == k.keys.len) return null;
            k.keys[k.len] = rr.rdata.dnskey;
            k.tags[k.len] = rrsig.keyTag(rr.rdata.dnskey);
            k.len += 1;
        }
        return k;
    }
};

fn rrsetVerifiesWithAnyKey(
    sig: dns.RrsigData,
    keyset: *const Keyset,
    rrset: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *rrsig.ValidationBudget,
    memo: *rrsig.VerifyMemo,
) error{ValidationBudgetExhausted}!bool {
    for (keyset.keys[0..keyset.len], keyset.tags[0..keyset.len]) |dk, tag| {
        if (tag != sig.key_tag) continue;
        if (try rrsig.tryVerifyRrsig(sig, dk, rrset, now_u32, budget, memo)) return true;
    }
    return false;
}

/// The RRSIG covering (`owner`, `covered_type`). Owner-scoped: one response
/// can hold several RRsets of a type at different names, each with its own
/// signer — the hops of a CNAME chain.
pub fn findRrsigAt(
    records: []const dns.ResourceRecord,
    owner: dns.Name,
    covered_type: dns.RType,
) ?dns.RrsigData {
    for (records) |rr| {
        if (rr.rtype != .rrsig) continue;
        const sig = rr.rdata.rrsig;
        if (sig.type_covered == covered_type and rr.name.eql(owner)) return sig;
    }
    return null;
}

/// Validate the RRset at (`owner`, `covered_type`), trying every covering
/// RRSIG and every key matching its tag and algorithm (RFC 6840 §5.4).
/// `dnskey_records` must be *this* RRset's signer's keyset, which in a chain
/// crossing a zone cut differs between hops.
///
/// Returns the signature that verified, or null for bogus. TTL and wildcard
/// facts are read from that signature and nowhere else: deriving them from
/// the RRSIGs present would let an appended unverifiable one drive them.
pub fn validateRrset(
    records: []const dns.ResourceRecord,
    owner: dns.Name,
    covered_type: dns.RType,
    dnskey_records: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *rrsig.ValidationBudget,
    memo: *rrsig.VerifyMemo,
) ?dns.RrsigData {
    // Refuse rather than truncate: the caller sets AD on the *unpruned*
    // response, so verifying a signature over records[0..64] while
    // shipping 70 records launders the 6 attacker-appended RRs into an
    // authenticated answer. buildSignedData refuses >64 anyway.
    var filtered: [64]dns.ResourceRecord = undefined;
    var count: usize = 0;
    for (records) |rr| {
        if (rr.rtype != covered_type or !rr.name.eql(owner)) continue;
        if (count == filtered.len) return null;
        filtered[count] = rr;
        count += 1;
    }
    if (count == 0) return null;
    const keyset = Keyset.init(dnskey_records) orelse return null;

    for (records) |sig_rr| {
        if (sig_rr.rtype != .rrsig) continue;
        const sig = sig_rr.rdata.rrsig;
        if (sig.type_covered != covered_type) continue;
        if (!sig_rr.name.eql(owner)) continue;
        if (!rrsig.isSupportedAlgorithm(sig.algorithm)) continue;

        if (rrsetVerifiesWithAnyKey(sig, &keyset, filtered[0..count], now_u32, budget, memo) catch return null) return sig;
    }
    // Nothing verified on a zone already proven secure — bogus, even when
    // every candidate RRSIG used an unsupported algorithm: real supported
    // signatures existed (the zone's DS says so, RFC 4035 §5.2 filtered the
    // all-unsupported case to .insecure at the delegation) and were stripped.
    // A softer verdict here is a keyless downgrade; Unbound and BIND agree.
    return null;
}

/// Verify that every piece of negative-answer material in the authority
/// section — NSEC/NSEC3 proofs *and* the RFC 2308 SOA — has a valid RRSIG
/// signed by one of the provided DNSKEYs. The SOA is what a `.secure`
/// negative's TTL and a downstream validator's own verdict rest on; leaving
/// it unverified made AD=1 an overclaim (RFC 4035 §3.2.3 covers the whole
/// authority section). NS and glue stay exempt: at a zone cut they are
/// legitimately unsigned delegation data. On `.secure`, `ttl_cap` is lowered
/// to the tightest verified signature's bound — a proof-derived verdict must
/// not be cached past the signatures that justify it. No NSEC/NSEC3 at all
/// is `.unchecked`.
pub fn verifyAuthorityProofSigs(
    authorities: []const dns.ResourceRecord,
    dnskey_records: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *rrsig.ValidationBudget,
    memo: *rrsig.VerifyMemo,
    ttl_cap: ?*u32,
) proof.SecurityStatus {
    for (authorities) |rr| {
        if (rr.rtype == .nsec or rr.rtype == .nsec3) break;
    } else return .unchecked;
    if (proof.proofFlood(authorities)) return .bogus;
    const keyset = Keyset.init(dnskey_records) orelse return .bogus;

    for (authorities, 0..) |rr, i| {
        if (rr.rtype != .nsec and rr.rtype != .nsec3 and rr.rtype != .soa) continue;
        // A duplicated owner re-collects the same set; verify it once.
        const seen = for (authorities[0..i]) |prev| {
            if (prev.rtype == rr.rtype and prev.name.eql(rr.name)) break true;
        } else false;
        if (seen) continue;

        // Collect the RRset (all records with same owner+type). Overflow is
        // .bogus, not a truncated collect: verifying a sig over the first 16
        // would leave the overflow records unverified while validateNegativeProof
        // still reads them out of `authorities` as proof material.
        var rrset: [16]dns.ResourceRecord = undefined;
        var rrset_count: usize = 0;
        for (authorities) |rr2| {
            if (rr2.rtype != rr.rtype or !rr2.name.eql(rr.name)) continue;
            if (rrset_count == rrset.len) return .bogus;
            rrset[rrset_count] = rr2;
            rrset_count += 1;
        }

        var sig_verified = false;
        for (authorities) |sig_rr| {
            if (sig_rr.rtype != .rrsig) continue;
            const sig = sig_rr.rdata.rrsig;
            if (sig.type_covered != rr.rtype or !sig_rr.name.eql(rr.name)) continue;
            if (!rrsig.isSupportedAlgorithm(sig.algorithm)) continue;
            // Proof material is never wildcard-expanded (RFC 4035 §3.1.3.3 serves
            // the `*.CE` NSEC under its own owner), and the proofs read the owner
            // as served: a real `*.zone NSEC` signature would verify under any.
            if (sig.labels != rrsig.signedLabels(rr.name)) return .bogus;

            if (rrsetVerifiesWithAnyKey(sig, &keyset, rrset[0..rrset_count], now_u32, budget, memo) catch return .bogus) {
                if (ttl_cap) |cap| cap.* = @min(cap.*, rrsig.ttlCap(sig, now_u32));
                sig_verified = true;
                break;
            }
        }
        // RFC 4035 §5.3: every NSEC owner must verify. Only-unsupported-algo
        // owners are bogus too — see validateRrset's closing verdict.
        if (!sig_verified) return .bogus;
    }

    return .secure;
}

test "isValidZoneKey (RFC 4034 §2.1.1–2)" {
    // ZSK (flags=256, protocol=3) — valid
    try testing.expect(isValidZoneKey(.{ .flags = 256, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    // KSK (flags=257, protocol=3) — valid (SEP + zone key)
    try testing.expect(isValidZoneKey(.{ .flags = 257, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    // flags=0 — no zone key bit
    try testing.expect(!isValidZoneKey(.{ .flags = 0, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    // SEP-only (flags=1) — no zone key bit
    try testing.expect(!isValidZoneKey(.{ .flags = 1, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 256, .protocol = 0, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 256, .protocol = 1, .algorithm = .rsasha256, .public_key = &.{} }));
    // RFC 5011 §2.1: REVOKE bit set — must reject even with zone key + correct protocol
    try testing.expect(!isValidZoneKey(.{ .flags = 256 | 0x80, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 257 | 0x80, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
}

const test_dnskey = dns.DnskeyData{
    .flags = 257,
    .protocol = 3,
    .algorithm = .rsasha256,
    .public_key = &.{ 0x03, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD },
};

test "DS hash verification - sha1 and sha384 digest types" {
    // verifyDs's three digest arms collapse to one comptime helper; exercise
    // the sha1 and sha384 instantiations (the ML-DSA-44 vector pins sha256).
    const d1 = try dsDigest(Sha1, rrsig.test_owner, test_dnskey);
    try verifyDs(.{
        .key_tag = rrsig.keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha1,
        .digest = &d1,
    }, test_dnskey, rrsig.test_owner);

    const d384 = try dsDigest(Sha384, rrsig.test_owner, test_dnskey);
    try verifyDs(.{
        .key_tag = rrsig.keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha384,
        .digest = &d384,
    }, test_dnskey, rrsig.test_owner);
}

test "anySupportedDs: unsupported algorithm or digest contributes no path" {
    const zero_digest: [32]u8 = @splat(0);
    const ds_rr = struct {
        fn make(algo: dns.DnssecAlgorithm, digest_type: dns.DigestType) dns.ResourceRecord {
            return .{
                .name = rrsig.test_owner,
                .rtype = .ds,
                .rclass = .in,
                .ttl = 3600,
                .rdata = .{ .ds = .{
                    .key_tag = 1,
                    .algorithm = algo,
                    .digest_type = digest_type,
                    .digest = &zero_digest,
                } },
            };
        }
    }.make;

    // Ed448-only (the live ed448.nl shape) — no path.
    try testing.expect(!anySupportedDs(&.{ds_rr(.ed448, .sha256)}));
    // Supported algorithm, unknown digest — still no path.
    try testing.expect(!anySupportedDs(&.{ds_rr(.ecdsap256sha256, @fromBackingInt(3))}));
    // Non-DS records are ignored; empty set has no path.
    try testing.expect(!anySupportedDs(&.{}));
    // One supported member is enough, wherever it sits.
    try testing.expect(anySupportedDs(&.{ ds_rr(.ed448, .sha256), ds_rr(.ecdsap256sha256, .sha256) }));
    try testing.expect(anySupportedDs(&.{ds_rr(.mldsa44, .sha256)}));
}

test "validateDnskeyRrset rejects DNSKEY without RRSIG when DS exists" {
    // RFC 4035 §5.2: stripped RRSIG on DNSKEY must not bypass validation.
    var digest = try dsDigest(Sha256, rrsig.test_owner, test_dnskey);

    const ds = dns.DsData{
        .key_tag = rrsig.keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };

    // DNSKEY record with NO accompanying RRSIG — this is the attack vector
    const dnskey_records = [_]dns.ResourceRecord{.{
        .name = rrsig.test_owner,
        .rtype = .dnskey,
        .rclass = .in,
        .ttl = 86400,
        .rdata = .{ .dnskey = test_dnskey },
    }};

    var budget: rrsig.ValidationBudget = .{};
    try testing.expectError(
        error.InvalidSignature,
        validateDnskeyRrset(&dnskey_records, &.{ds}, rrsig.test_owner, 1700000000, &budget, &test_memo),
    );
}

test "validateDnskeyRrset refuses more DNSKEYs than the 64-key filter buffer" {
    // A hostile zone can serve >64 DNSKEYs over TCP. Skipping the overflow
    // would let a signature over the first 64 authenticate a set the caller
    // then caches whole — appended forgeries included — so overflow is a
    // hard refusal, not a truncated collect.
    var digest = try dsDigest(Sha256, rrsig.test_owner, test_dnskey);
    const ds = dns.DsData{
        .key_tag = rrsig.keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };

    // Distinct-tag filler keys fill the buffer; the DS-matching key lands at
    // index 64, exactly one past it.
    const filler = dns.DnskeyData{
        .flags = 257,
        .protocol = 3,
        .algorithm = .rsasha256,
        .public_key = &.{ 0x03, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44 },
    };
    try testing.expect(rrsig.keyTag(filler) != ds.key_tag);

    var records: [65]dns.ResourceRecord = undefined;
    for (records[0..64]) |*r| r.* = .{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 86400, .rdata = .{ .dnskey = filler } };
    records[64] = .{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 86400, .rdata = .{ .dnskey = test_dnskey } };

    var budget: rrsig.ValidationBudget = .{};
    try testing.expectError(
        error.InvalidKey,
        validateDnskeyRrset(&records, &.{ds}, rrsig.test_owner, 1700000000, &budget, &test_memo),
    );

    // 64 exactly is still accepted (and rejected on signature grounds, not
    // size) — the boundary is off-by-one sensitive.
    try testing.expectError(
        error.InvalidSignature,
        validateDnskeyRrset(records[0..64], &.{ds}, rrsig.test_owner, 1700000000, &budget, &test_memo),
    );
}

test "verifyAuthorityProofSigs: oversized owner+type is refused, not truncated" {
    // RFC 4034 §4: one NSEC per owner, so no honest signature covers 16.
    const nsec = dns.NsecData{
        .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
        .type_bit_maps = &.{ 0x00, 0x01, 0x62 },
    };
    var rrs: [17]dns.ResourceRecord = undefined;
    for (&rrs) |*r| r.* = .{
        .name = rrsig.test_owner,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .nsec = nsec },
    };

    var budget: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        proof.SecurityStatus.bogus,
        verifyAuthorityProofSigs(&rrs, &.{}, 1_700_000_000, &budget, &test_memo, null),
    );
    // 16 is within the buffer and fails on the ordinary no-signature path,
    // so the boundary is the size check and not a signature accident.
    var budget2: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        proof.SecurityStatus.bogus,
        verifyAuthorityProofSigs(rrs[0..16], &.{}, 1_700_000_000, &budget2, &test_memo, null),
    );
}

test "validateDnskeyRrset: a real signature over 64 keys cannot launder a 65th" {
    var recs: [65]dns.ResourceRecord = undefined;
    var pub_bufs: [65][32]u8 = undefined;
    for (&recs, 0..) |*r, i| {
        pub_bufs[i] = @splat(@intCast(i + 1));
        r.* = dnskeyRr(rrsig.test_owner, .{
            .flags = 256,
            .protocol = 3,
            .algorithm = .ed25519,
            .public_key = &pub_bufs[i],
        });
    }

    var sig_bytes: [64]u8 = undefined;
    var signer_pub: [32]u8 = undefined;
    const signed = try rrsig.testSignRrset(recs[0..64], .dnskey, rrsig.test_owner, .ed25519, &sig_bytes, &signer_pub);
    // The signing key must itself be in the RRset and DS-anchored, or the
    // refusal could be blamed on anchoring rather than on size.
    recs[0] = dnskeyRr(rrsig.test_owner, signed.dnskey);
    var sig2: [64]u8 = undefined;
    const resigned = try rrsig.testSignRrset(recs[0..64], .dnskey, rrsig.test_owner, .ed25519, &sig2, &signer_pub);
    recs[0] = dnskeyRr(rrsig.test_owner, resigned.dnskey);

    var digest = try dsDigest(Sha256, rrsig.test_owner, resigned.dnskey);
    const ds = dns.DsData{
        .key_tag = rrsig.keyTag(resigned.dnskey),
        .algorithm = .ed25519,
        .digest_type = .sha256,
        .digest = &digest,
    };
    const sig_rr = dns.ResourceRecord{
        .name = rrsig.test_owner,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .rrsig = resigned.rrsig },
    };

    // Control: the signed 64 plus their RRSIG validate.
    var ok: [65]dns.ResourceRecord = undefined;
    @memcpy(ok[0..64], recs[0..64]);
    ok[64] = sig_rr;
    var budget: rrsig.ValidationBudget = .{};
    _ = try validateDnskeyRrset(&ok, &.{ds}, rrsig.test_owner, 1_700_000_000, &budget, &test_memo);

    // The 65th key must not ride in on that signature.
    var laundered: [66]dns.ResourceRecord = undefined;
    @memcpy(laundered[0..65], &recs);
    laundered[65] = sig_rr;
    var budget2: rrsig.ValidationBudget = .{};
    try testing.expectError(
        error.InvalidKey,
        validateDnskeyRrset(&laundered, &.{ds}, rrsig.test_owner, 1_700_000_000, &budget2, &test_memo),
    );
}

test "validateDnskeyRrset caps the KeyTrap key×signature cross-product at the budget" {
    // CVE-2023-50387: colliding-tag keys × DNSKEY-covering RRSIGs force an N×M
    // verify cross-product. consumeVerify charges before any crypto, so the walk
    // halts at the ceiling however large N·M grows. Pins that against the walk's
    // next refactor.
    var digest = try dsDigest(Sha256, rrsig.test_owner, test_dnskey);
    const ds = dns.DsData{
        .key_tag = rrsig.keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };

    // 3 anchored copies of the DS-matching key × 40 tag-matching RRSIGs with
    // unverifiable signatures = 120 candidate attempts; the budget permits 8.
    var records: [43]dns.ResourceRecord = undefined;
    for (records[0..3]) |*r| r.* = .{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 86400, .rdata = .{ .dnskey = test_dnskey } };
    for (records[3..43]) |*r| r.* = .{
        .name = rrsig.test_owner,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 86400,
        .rdata = .{ .rrsig = .{
            .type_covered = .dnskey,
            .algorithm = .rsasha256,
            .labels = 2,
            .original_ttl = 86400,
            .sig_expiration = 0xFFFFFFFF,
            .sig_inception = 0,
            .key_tag = ds.key_tag,
            .signer_name = rrsig.test_owner,
            .signature = &.{ 0xDE, 0xAD, 0xBE, 0xEF },
        } },
    };

    const cap: u32 = 8;
    var budget: rrsig.ValidationBudget = .{ .max_sig_verify = cap };
    try testing.expectError(
        error.ValidationBudgetExhausted,
        validateDnskeyRrset(&records, &.{ds}, rrsig.test_owner, 1700000000, &budget, &test_memo),
    );
    try testing.expectEqual(cap, budget.sig_verify_spent);
}

test "validateRrset on DS without RRSIG returns .bogus (RFC 4035 §5.2)" {
    // A DS RRset that arrives at the resolver without a covering RRSIG
    // signed by the parent zone's DNSKEY MUST NOT be trusted as a chain
    // anchor.
    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const ds_record = dns.ResourceRecord{
        .name = owner,
        .rtype = .ds,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .ds = .{
            .key_tag = 12345,
            .algorithm = .rsasha256,
            .digest_type = .sha256,
            .digest = &@as([32]u8, @splat(0)),
        } },
    };
    const records = [_]dns.ResourceRecord{ds_record}; // No RRSIG present.
    var b: rrsig.ValidationBudget = .{};
    try testing.expect(validateRrset(&records, owner, .ds, &.{}, 1700000000, &b, &test_memo) == null);
}

test "DS hash verification - wrong digest fails" {
    const bad_digest: [32]u8 = @splat(0xFF);
    const ds = dns.DsData{ .key_tag = rrsig.keyTag(test_dnskey), .algorithm = .rsasha256, .digest_type = .sha256, .digest = &bad_digest };
    try testing.expectError(error.InvalidSignature, verifyDs(ds, test_dnskey, rrsig.test_owner));
}

test "ML-DSA-44: draft-westerbaan-dnssec-mldsa §6 example verifies (DS, key tag, RRSIG over MX)" {
    const dnskey_b64 =
        "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" ++
        "Eg==";
    const rrsig_b64 =
        "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" ++
        "VFVbg5SXo62wztPoAAAAAAAAAAAAAA0jNEY=";
    const decoder = std.base64.standard.Decoder;
    var pub_key: [MlDsa44.PublicKey.encoded_length]u8 = undefined;
    var signature: [MlDsa44.Signature.encoded_length]u8 = undefined;
    try testing.expectEqual(pub_key.len, try decoder.calcSizeForSlice(dnskey_b64));
    try testing.expectEqual(signature.len, try decoder.calcSizeForSlice(rrsig_b64));
    try decoder.decode(&pub_key, dnskey_b64);
    try decoder.decode(&signature, rrsig_b64);

    const dnskey = dns.DnskeyData{ .flags = 257, .protocol = 3, .algorithm = .mldsa44, .public_key = &pub_key };
    try testing.expectEqual(@as(u16, 59829), rrsig.keyTag(dnskey));

    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, "812cb1a22af04380e2f72d91c06c14eb1a918cf30037a8a9c67497e9264b4bfa");
    try verifyDs(.{ .key_tag = 59829, .algorithm = .mldsa44, .digest_type = .sha256, .digest = &digest }, dnskey, rrsig.test_owner);

    const mx = [_]dns.ResourceRecord{.{
        .name = rrsig.test_owner,
        .rtype = .mx,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .mx = .{ .preference = 10, .exchange = .{ .labels = &[_][]const u8{ "mail", "example", "com" } } } },
    }};
    var sig = dns.RrsigData{
        .type_covered = .mx,
        .algorithm = .mldsa44,
        .labels = 2,
        .original_ttl = 3600,
        .sig_expiration = 1440021600,
        .sig_inception = 1438207200,
        .key_tag = 59829,
        .signer_name = rrsig.test_owner,
        .signature = &signature,
    };
    var budget: rrsig.ValidationBudget = .{};
    try rrsig.verifyRrsig(sig, dnskey, &mx, 1439000000, &budget, &test_memo);

    signature[100] ^= 1;
    try testing.expectError(error.InvalidSignature, rrsig.verifyRrsig(sig, dnskey, &mx, 1439000000, &budget, &test_memo));
    signature[100] ^= 1;
    sig.signer_name = proof.test_com;
    try testing.expectError(error.InvalidSignature, rrsig.verifyRrsig(sig, dnskey, &mx, 1439000000, &budget, &test_memo));
}

test "NsecTrap: a proof flood is refused before any RRSIG is tried" {
    // Every RRSIG's tag matches the key, so each one tried draws on the budget.
    const zone_labels: []const []const u8 = &.{ "example", "com" };
    const next_owner: [20]u8 = @splat(0xFF);
    const key: dns.ResourceRecord = .{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 300, .rdata = .{ .dnskey = test_dnskey } };
    var bufs: [2 * (proof.max_proof_records + 1)]proof.Nsec3OwnerBufs = undefined;
    var rrs: [2 * (proof.max_proof_records + 1)]dns.ResourceRecord = undefined;
    for (0..proof.max_proof_records + 1) |i| {
        bufs[i] = .{};
        const owner = proof.makeNsec3OwnerName(@as([20]u8, @splat(@as(u8, @intCast(i ^ 0xA5)))), zone_labels, &bufs[i]);
        rrs[2 * i] = proof.makeNsec3Rr(owner, &.{}, &next_owner, &.{});
        rrs[2 * i + 1] = .{ .name = owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = .{
            .type_covered = .nsec3,
            .algorithm = .rsasha256,
            .labels = 3,
            .original_ttl = 300,
            .sig_expiration = 0xFFFFFFFF,
            .sig_inception = 0,
            .key_tag = rrsig.keyTag(test_dnskey),
            .signer_name = rrsig.test_owner,
            .signature = &.{ 0xDE, 0xAD },
        } } };
    }
    var at_cap: rrsig.ValidationBudget = .{};
    try testing.expectEqual(proof.SecurityStatus.bogus, verifyAuthorityProofSigs(rrs[0 .. 2 * proof.max_proof_records], &.{key}, 1700000000, &at_cap, &test_memo, null));
    try testing.expect(at_cap.sig_verify_spent > 0);
    var past: rrsig.ValidationBudget = .{};
    try testing.expectEqual(proof.SecurityStatus.bogus, verifyAuthorityProofSigs(&rrs, &.{key}, 1700000000, &past, &test_memo, null));
    try testing.expectEqual(@as(u32, 0), past.sig_verify_spent);
}

test "validateRrset propagates budget exhaustion as bogus" {
    // Pathological setup: one RRSIG covering A, with a DNSKEY whose key_tag
    // matches. The budget is pre-exhausted, so the very first verifyRrsig
    // attempt trips ValidationBudgetExhausted, which the caller maps to bogus.
    const dnskey = dns.DnskeyData{
        .flags = 256,
        .protocol = 3,
        .algorithm = .ecdsap256sha256,
        .public_key = &.{},
    };
    const tag = rrsig.keyTag(dnskey);
    const sig = dns.RrsigData{
        .type_covered = .a,
        .algorithm = .ecdsap256sha256,
        .labels = 2,
        .original_ttl = 300,
        .sig_expiration = 1700000000,
        .sig_inception = 1699000000,
        .key_tag = tag,
        .signer_name = rrsig.test_owner,
        .signature = &.{},
    };
    const answers = [_]dns.ResourceRecord{
        .{ .name = rrsig.test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        .{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = sig } },
    };
    const dnskeys = [_]dns.ResourceRecord{
        .{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 300, .rdata = .{ .dnskey = dnskey } },
    };
    var budget: rrsig.ValidationBudget = .{ .max_sig_verify = 0 };
    try testing.expect(validateRrset(&answers, rrsig.test_owner, .a, &dnskeys, 1699500000, &budget, &test_memo) == null);
}

// ── verifyAuthorityProofSigs: validation-bypass guards ────────────────
//
// These tests lock the "every NSEC/NSEC3 owner must verify" invariant
// (RFC 4035 §5.3, RFC 6840 §5.4/§5.11). A regression where the function
// accepts unsigned or unrelated NSEC records would let an attacker forge
// an NXDOMAIN response with insecure denial-of-existence — a DNSSEC
// validation bypass on the order of CVE-2023-50387.

fn rrsigRr(owner: dns.Name, type_covered: dns.RType, algorithm: dns.DnssecAlgorithm, key_tag: u16, signer: dns.Name) dns.ResourceRecord {
    return .{
        .name = owner,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .rrsig = .{
            .type_covered = type_covered,
            .algorithm = algorithm,
            .labels = @intCast(owner.labels.len),
            .original_ttl = 300,
            .sig_expiration = 1700000000,
            .sig_inception = 1699000000,
            .key_tag = key_tag,
            .signer_name = signer,
            .signature = &.{},
        } },
    };
}

const test_ecdsa_dnskey = dns.DnskeyData{
    .flags = 256,
    .protocol = 3,
    .algorithm = .ecdsap256sha256,
    .public_key = &.{},
};

fn dnskeyRr(owner: dns.Name, dnskey: dns.DnskeyData) dns.ResourceRecord {
    return .{ .name = owner, .rtype = .dnskey, .rclass = .in, .ttl = 300, .rdata = .{ .dnskey = dnskey } };
}

test "verifyAuthorityProofSigs: NSEC without RRSIG returns bogus" {
    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "example", "com" } };
    const authorities = [_]dns.ResourceRecord{proof.nsecRr(owner, next)};
    // No DNSKEYs needed; iteration fails the find-RRSIG step.
    var budget: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        proof.SecurityStatus.bogus,
        verifyAuthorityProofSigs(&authorities, &.{}, 1699500000, &budget, &test_memo, null),
    );
}

test "verifyAuthorityProofSigs: signed NSEC + unsigned NSEC returns bogus" {
    // Even if the FIRST NSEC carries an unsupported-algo RRSIG (which
    // would yield .insecure on its own), a SECOND NSEC with no RRSIG at
    // all must still drive the result to .bogus. The "every owner must
    // verify" invariant is non-negotiable.
    const owner1 = dns.Name{ .labels = &.{ "alpha", "example", "com" } };
    const next1 = dns.Name{ .labels = &.{ "beta", "example", "com" } };
    const owner2 = dns.Name{ .labels = &.{ "gamma", "example", "com" } };
    const next2 = dns.Name{ .labels = &.{ "delta", "example", "com" } };
    const signer = dns.Name{ .labels = &.{ "example", "com" } };
    const authorities = [_]dns.ResourceRecord{
        proof.nsecRr(owner1, next1),
        rrsigRr(owner1, .nsec, .dsasha1, 12345, signer), // unsupported algo, won't verify
        proof.nsecRr(owner2, next2),
        // no RRSIG for owner2 — bogus
    };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        proof.SecurityStatus.bogus,
        verifyAuthorityProofSigs(&authorities, &.{}, 1699500000, &budget, &test_memo, null),
    );
}

test "verifyAuthorityProofSigs: only-unsupported-algo RRSIG returns bogus" {
    // This function runs only under a zone already proven secure, where an
    // all-unsupported-algorithm zone never arrives (RFC 4035 §5.2 makes it
    // insecure at the delegation). An NSEC whose only RRSIG is unsupported
    // is therefore the stripped-signature shape, not a legitimate zone.
    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "example", "com" } };
    const signer = dns.Name{ .labels = &.{ "example", "com" } };
    const authorities = [_]dns.ResourceRecord{
        proof.nsecRr(owner, next),
        rrsigRr(owner, .nsec, .dsasha1, 12345, signer), // unsupported
    };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        proof.SecurityStatus.bogus,
        verifyAuthorityProofSigs(&authorities, &.{}, 1699500000, &budget, &test_memo, null),
    );
}

test "verifyAuthorityProofSigs: failing supported + unsupported RRSIG returns bogus" {
    // Laundering guard: a fake unsupported-algo RRSIG must not downgrade
    // a failing supported-algo RRSIG from .bogus to .insecure.
    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "example", "com" } };
    const signer = owner;
    const tag = rrsig.keyTag(test_ecdsa_dnskey);
    const authorities = [_]dns.ResourceRecord{
        proof.nsecRr(owner, next),
        rrsigRr(owner, .nsec, .dsasha1, 12345, signer), // unsupported
        rrsigRr(owner, .nsec, .ecdsap256sha256, tag, signer), // supported, empty sig → fails
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(signer, test_ecdsa_dnskey)};
    var budget: rrsig.ValidationBudget = .{};
    try testing.expectEqual(
        proof.SecurityStatus.bogus,
        verifyAuthorityProofSigs(&authorities, &dnskeys, 1699500000, &budget, &test_memo, null),
    );
}

test "validateRrset: an RRSIG at another owner cannot move this RRset's verdict" {
    // A signature at another owner says nothing about this RRset either way:
    // the verdict must be identical with and without the foreign RRSIG.
    const tag = rrsig.keyTag(test_ecdsa_dnskey);
    const other_owner = dns.Name{ .labels = &.{ "other", "com" } };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, test_ecdsa_dnskey)};

    const with_foreign = [_]dns.ResourceRecord{
        .{ .name = rrsig.test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(rrsig.test_owner, .a, .dsasha1, 0, rrsig.test_owner), // unsupported, this owner
        rrsigRr(other_owner, .a, .ecdsap256sha256, tag, other_owner), // supported, foreign owner
    };
    const without_foreign = with_foreign[0..2];

    var b1: rrsig.ValidationBudget = .{};
    var b2: rrsig.ValidationBudget = .{};
    try testing.expect(validateRrset(&with_foreign, rrsig.test_owner, .a, &dnskeys, 1699500000, &b1, &test_memo) == null);
    try testing.expect(validateRrset(without_foreign, rrsig.test_owner, .a, &dnskeys, 1699500000, &b2, &test_memo) == null);
}

test "validateRrset: failing supported + unsupported RRSIG returns bogus" {
    // Same-owner laundering on the answer-validation path.
    const tag = rrsig.keyTag(test_ecdsa_dnskey);
    const answers = [_]dns.ResourceRecord{
        .{ .name = rrsig.test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(rrsig.test_owner, .a, .dsasha1, 0, rrsig.test_owner),
        rrsigRr(rrsig.test_owner, .a, .ecdsap256sha256, tag, rrsig.test_owner), // empty sig → fails
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, test_ecdsa_dnskey)};
    var budget: rrsig.ValidationBudget = .{};
    try testing.expect(validateRrset(&answers, rrsig.test_owner, .a, &dnskeys, 1699500000, &budget, &test_memo) == null);
}

test "verifyAuthorityProofSigs refuses a wildcard-expanded NSEC" {
    // The zone's real `*.example.com NSEC a.example.com`, replayed under owner
    // `v.example.com`: labels 2 < 3 reconstructs `*.example.com` for the
    // signature, which verifies. As `v NSEC a` it is an apex wrap covering
    // every name after `v`, including ones that exist.
    const star = dns.Name{ .labels = &.{ "*", "example", "com" } };
    const a = dns.Name{ .labels = &.{ "a", "example", "com" } };
    const v = dns.Name{ .labels = &.{ "v", "example", "com" } };
    const real = [_]dns.ResourceRecord{proof.nsecRr(star, a)};
    var sig_buf: [64]u8 = undefined;
    var pub_buf: [32]u8 = undefined;
    const signed = try rrsig.testSignRrset(&real, .nsec, rrsig.test_owner, .ed25519, &sig_buf, &pub_buf);
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, signed.dnskey)};
    const sig_rr = dns.ResourceRecord{ .name = v, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } };
    const replayed = [_]dns.ResourceRecord{ proof.nsecRr(v, a), sig_rr };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expectEqual(proof.SecurityStatus.bogus, verifyAuthorityProofSigs(&replayed, &dnskeys, 1_700_000_000, &budget, &test_memo, null));

    const own_sig = dns.ResourceRecord{ .name = star, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } };
    const genuine = [_]dns.ResourceRecord{ real[0], own_sig };
    var budget2: rrsig.ValidationBudget = .{};
    try testing.expectEqual(proof.SecurityStatus.secure, verifyAuthorityProofSigs(&genuine, &dnskeys, 1_700_000_000, &budget2, &test_memo, null));
}

fn testSignMlDsa(
    rrset: []const dns.ResourceRecord,
    covered: dns.RType,
    signer: dns.Name,
    dnskey: dns.DnskeyData,
    kp: *const MlDsa44.KeyPair,
    sig_buf: *[MlDsa44.Signature.encoded_length]u8,
) !dns.RrsigData {
    var sig = dns.RrsigData{
        .type_covered = covered,
        .algorithm = .mldsa44,
        .labels = @intCast(rrsig.signedLabels(rrset[0].name)),
        .original_ttl = 300,
        .sig_inception = 1_699_000_000,
        .sig_expiration = 1_800_000_000,
        .key_tag = rrsig.keyTag(dnskey),
        .signer_name = signer,
        .signature = &.{},
    };
    var canonical_buf: [65536]u8 = undefined;
    const data = try rrsig.buildSignedData(&canonical_buf, sig, rrset);
    var s = try kp.signer(null);
    data.feed(&s);
    sig_buf.* = s.finalize().toBytes();
    sig.signature = sig_buf;
    return sig;
}

test "validateDnskeyRrset: a DS advertising ML-DSA-44 makes its signature the only one that counts" {
    const pq_kp = try MlDsa44.KeyPair.generateDeterministic(@splat(7));
    const pq_pub = pq_kp.public_key.toBytes();
    const pq_key = dns.DnskeyData{ .flags = 257, .protocol = 3, .algorithm = .mldsa44, .public_key = &pq_pub };
    var ed_pub: [32]u8 = undefined;
    var ed_sig: [64]u8 = undefined;
    const ed_key = dns.DnskeyData{ .flags = 256, .protocol = 3, .algorithm = .ed25519, .public_key = &ed_pub };
    const key = struct {
        fn rr(dk: dns.DnskeyData) dns.ResourceRecord {
            return .{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 300, .rdata = .{ .dnskey = dk } };
        }
        fn sig(s: dns.RrsigData) dns.ResourceRecord {
            return .{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = s } };
        }
    };
    // ed_pub is undefined until testSignRrset fills it, so the Ed25519 signature
    // goes first and the ML-DSA-44 one sees the finished keyset.
    const keys = [_]dns.ResourceRecord{ key.rr(ed_key), key.rr(pq_key) };
    const ed = try rrsig.testSignRrset(&keys, .dnskey, rrsig.test_owner, .ed25519, &ed_sig, &ed_pub);
    var pq_sig: [MlDsa44.Signature.encoded_length]u8 = undefined;
    const pq = try testSignMlDsa(&keys, .dnskey, rrsig.test_owner, pq_key, &pq_kp, &pq_sig);
    var ed_digest = try dsDigest(Sha256, rrsig.test_owner, ed_key);
    var pq_digest = try dsDigest(Sha256, rrsig.test_owner, pq_key);
    const ed_ds = dns.DsData{ .key_tag = rrsig.keyTag(ed_key), .algorithm = .ed25519, .digest_type = .sha256, .digest = &ed_digest };
    const pq_ds = dns.DsData{ .key_tag = rrsig.keyTag(pq_key), .algorithm = .mldsa44, .digest_type = .sha256, .digest = &pq_digest };

    // Downgrade: ML-DSA-44 signature stripped, classical one intact. Bogus.
    const stripped = keys ++ [_]dns.ResourceRecord{key.sig(ed.rrsig)};
    var b1: rrsig.ValidationBudget = .{};
    try testing.expectError(error.InvalidSignature, validateDnskeyRrset(&stripped, &.{ ed_ds, pq_ds }, rrsig.test_owner, 1_700_000_000, &b1, &test_memo));

    // Both present, either order: the ML-DSA-44 one is what verifies.
    const dual = keys ++ [_]dns.ResourceRecord{ key.sig(ed.rrsig), key.sig(pq) };
    var b2: rrsig.ValidationBudget = .{};
    try testing.expectEqual(dns.DnssecAlgorithm.mldsa44, (try validateDnskeyRrset(&dual, &.{ ed_ds, pq_ds }, rrsig.test_owner, 1_700_000_000, &b2, &test_memo)).algorithm);
    const dual_rev = keys ++ [_]dns.ResourceRecord{ key.sig(pq), key.sig(ed.rrsig) };
    try testing.expectEqual(dns.DnssecAlgorithm.mldsa44, (try validateDnskeyRrset(&dual_rev, &.{ pq_ds, ed_ds }, rrsig.test_owner, 1_700_000_000, &b2, &test_memo)).algorithm);

    // An ML-DSA-44 DS that anchors nothing demands nothing: unknown digest,
    // or SHA-1 beside a usable SHA-256 DS (RFC 4509 §3).
    const odd_ds = dns.DsData{ .key_tag = rrsig.keyTag(pq_key), .algorithm = .mldsa44, .digest_type = @fromBackingInt(9), .digest = &pq_digest };
    var b4: rrsig.ValidationBudget = .{};
    try testing.expectEqual(dns.DnssecAlgorithm.ed25519, (try validateDnskeyRrset(&stripped, &.{ ed_ds, odd_ds }, rrsig.test_owner, 1_700_000_000, &b4, &test_memo)).algorithm);
    var pq_sha1 = try dsDigest(Sha1, rrsig.test_owner, pq_key);
    const sha1_ds = dns.DsData{ .key_tag = rrsig.keyTag(pq_key), .algorithm = .mldsa44, .digest_type = .sha1, .digest = &pq_sha1 };
    try testing.expectEqual(dns.DnssecAlgorithm.ed25519, (try validateDnskeyRrset(&stripped, &.{ ed_ds, sha1_ds }, rrsig.test_owner, 1_700_000_000, &b4, &test_memo)).algorithm);

    // Only the ML-DSA-44 key survives into the keyset used below the apex;
    // without an ML-DSA-44 DS the keyset stays whole.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(dual.len, (try usableKeys(arena.allocator(), &dual, &.{ed_ds})).len);
    const kept = try usableKeys(arena.allocator(), &dual, &.{ ed_ds, pq_ds });
    try testing.expectEqual(@as(usize, 1), kept.len);
    try testing.expectEqual(dns.DnssecAlgorithm.mldsa44, kept[0].rdata.dnskey.algorithm);

    // No ML-DSA-44 DS: the key's presence in the DNSKEY RRset alone demands
    // nothing (RFC 6840 §5.11 MUST NOT; RFC 6781 §4.1.4 liberal rollover).
    var b3: rrsig.ValidationBudget = .{};
    try testing.expectEqual(dns.DnssecAlgorithm.ed25519, (try validateDnskeyRrset(&stripped, &.{ed_ds}, rrsig.test_owner, 1_700_000_000, &b3, &test_memo)).algorithm);
}

test "validateDnskeyRrset: RRSIG algorithm must match the DS-anchored key's" {
    // Ed25519 key labelled `.rsasha256`; the RRSIG says .ed25519 and carries the
    // key's tag, so only the algorithm comparison can refuse it.
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    // recs[0] aliases pub_bytes, which testSignRrset fills before signing.
    var recs: [2]dns.ResourceRecord = undefined;
    recs[0] = dnskeyRr(rrsig.test_owner, .{ .flags = 256, .protocol = 3, .algorithm = .rsasha256, .public_key = &pub_bytes });
    const signed = try rrsig.testSignRrset(recs[0..1], .dnskey, rrsig.test_owner, .rsasha256, &sig_bytes, &pub_bytes);
    recs[1] = .{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } };

    var digest = try dsDigest(Sha256, rrsig.test_owner, signed.dnskey);
    const ds = dns.DsData{
        .key_tag = rrsig.keyTag(signed.dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expectError(
        error.InvalidSignature,
        validateDnskeyRrset(&recs, &.{ds}, rrsig.test_owner, 1_700_000_000, &budget, &test_memo),
    );
}

test "validateRrset: the TTL cap comes from the signature that verified" {
    // Reducing over every RRSIG would let one unverifiable, freely appended
    // RRSIG zero a `.secure` entry's TTL. Unbound and Knot use the verifying one.
    //
    // `testSignRrset` signs original_ttl 300 / expiration 1_800_000_000, and
    // those fields are inside the signature, so the genuine values cannot be
    // edited after the fact — the junk RRSIG carries the hostile ones instead.
    const now: u32 = 1_700_000_000;
    const recs = [_]dns.ResourceRecord{
        .{ .name = rrsig.test_owner, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try rrsig.testSignRrset(&recs, .a, rrsig.test_owner, .ed25519, &sig_bytes, &pub_bytes);

    // Appended, unverifiable, and expiring in one second. Placed FIRST so a
    // naive scan would reach it before the real one.
    var junk = signed.rrsig;
    junk.key_tag = signed.rrsig.key_tag ^ 0x5555;
    junk.original_ttl = 1;
    junk.sig_expiration = now + 1;

    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, signed.dnskey)};
    const answers = [_]dns.ResourceRecord{
        recs[0],
        .{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = junk } },
        .{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = signed.rrsig } },
    };
    var budget: rrsig.ValidationBudget = .{};
    const sig = validateRrset(&answers, rrsig.test_owner, .a, &dnskeys, now, &budget, &test_memo).?;
    // The verifying signature's own bounds: original_ttl 300 against a
    // remaining window of 100_000_000 s. Never the junk record's 1.
    try testing.expectEqual(@as(u32, 300), rrsig.ttlCap(sig, now));
}

test "validateRrset: the cap takes the RFC 4035 §5.3.3 window when it is the shorter bound" {
    // Same signature, evaluated close to its expiration: now the remaining
    // window is what binds, not RFC 4034 §3.1.2's original TTL.
    const recs = [_]dns.ResourceRecord{
        .{ .name = rrsig.test_owner, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try rrsig.testSignRrset(&recs, .a, rrsig.test_owner, .ed25519, &sig_bytes, &pub_bytes);
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, signed.dnskey)};
    const answers = [_]dns.ResourceRecord{
        recs[0],
        .{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = signed.rrsig } },
    };
    // 60 s before the signature dies.
    const now: u32 = 1_800_000_000 - 60;
    var budget: rrsig.ValidationBudget = .{};
    const sig = validateRrset(&answers, rrsig.test_owner, .a, &dnskeys, now, &budget, &test_memo).?;
    try testing.expectEqual(@as(u32, 60), rrsig.ttlCap(sig, now));
}

test "validateRrset: >64-member RRset is bogus, not a validated prefix" {
    // The caller sets AD on the *unpruned* response, so a signature that
    // verifies over answers[0..64] must not authenticate a 70-record answer
    // section — the 6 appended records would ship authenticated.
    var recs: [70]dns.ResourceRecord = undefined;
    for (&recs, 0..) |*r, i| r.* = .{
        .name = rrsig.test_owner,
        .rtype = .a,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .a = .{ 10, 0, @intCast(i / 256), @intCast(i % 256) } },
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try rrsig.testSignRrset(recs[0..64], .a, rrsig.test_owner, .ed25519, &sig_bytes, &pub_bytes);
    const sig_rr = dns.ResourceRecord{
        .name = rrsig.test_owner,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .rrsig = signed.rrsig },
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, signed.dnskey)};

    var answers: [71]dns.ResourceRecord = undefined;
    @memcpy(answers[0..70], &recs);
    answers[70] = sig_rr;
    var budget: rrsig.ValidationBudget = .{};
    try testing.expect(validateRrset(&answers, rrsig.test_owner, .a, &dnskeys, 1_700_000_000, &budget, &test_memo) == null);

    // Control: the signed 64 on their own still validate.
    var exact: [65]dns.ResourceRecord = undefined;
    @memcpy(exact[0..64], recs[0..64]);
    exact[64] = sig_rr;
    var budget2: rrsig.ValidationBudget = .{};
    try testing.expect(validateRrset(&exact, rrsig.test_owner, .a, &dnskeys, 1_700_000_000, &budget2, &test_memo) != null);
}

test "validateRrset: all-unsupported algorithms are .bogus, not .secure" {
    // .secure would stamp AD on data no signature verified; .insecure would
    // let an injector swap real RRSIGs for one unsupported-algo signature and
    // get forged data served instead of SERVFAILed (the zone is known secure
    // here — the all-unsupported-zone case goes insecure at the delegation).
    const answers = [_]dns.ResourceRecord{
        .{ .name = rrsig.test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(rrsig.test_owner, .a, .dsasha1, 0, rrsig.test_owner),
    };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expect(validateRrset(&answers, rrsig.test_owner, .a, &.{}, 1699500000, &budget, &test_memo) == null);
}
