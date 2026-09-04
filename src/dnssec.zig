const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

// See verifyRsa for why we drive std.crypto.ff directly.
const RsaModulus = std.crypto.ff.Modulus(4096);
const RsaFe = RsaModulus.Fe;

const VerifyError = error{
    InvalidSignature,
    UnsupportedAlgorithm,
    InvalidKey,
    BufferTooSmall,
    SignatureExpired,
    /// CVE-2023-50387 (KeyTrap) defense: per-resolution signature-verify budget
    /// exhausted. Callers map this to .bogus; the response SERVFAILs.
    ValidationBudgetExhausted,
};

/// KeyTrap (CVE-2023-50387) cap on RRSIG verifies per query. Sized for a
/// cold-cache 5-level chain × dual-algo × KSK rollover. Raise if legitimate
/// zones SERVFAIL during rollover windows.
const max_sig_verify_per_resolution: u32 = 96;

/// NSEC3 hash cap per query (CVE-2023-50868). Whole-query exhaustion fails
/// CLOSED to `.bogus`; the per-record `max_nsec3_iterations` cap fails OPEN.
const max_nsec3_hashes_per_resolution: u32 = 96;

/// Per-query DNSSEC CPU budget (RRSIG verifies + NSEC3 hashes), shared tree-wide
/// by pointer across `cloneForThread` like `recursive.Budget`. Atomic
/// spent-up against a fixed ceiling: exactly `max` draws succeed then refuse
/// forever — never re-arms (a `fetchSub` down-counter would wrap u32 and silently
/// re-grant). Two separate counters so sig and NSEC3-hash exhaustion are independent.
pub const ValidationBudget = struct {
    sig_verify_spent: std.atomic.Value(u32) = .init(0),
    max_sig_verify: u32 = max_sig_verify_per_resolution,
    nsec3_hash_spent: std.atomic.Value(u32) = .init(0),
    max_nsec3_hash: u32 = max_nsec3_hashes_per_resolution,

    pub fn consumeVerify(self: *ValidationBudget) error{ValidationBudgetExhausted}!void {
        if (self.sig_verify_spent.fetchAdd(1, .monotonic) >= self.max_sig_verify)
            return error.ValidationBudgetExhausted;
    }

    fn consumeNsec3Hash(self: *ValidationBudget) error{ValidationBudgetExhausted}!void {
        if (self.nsec3_hash_spent.fetchAdd(1, .monotonic) >= self.max_nsec3_hash)
            return error.ValidationBudgetExhausted;
    }
};

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

/// RFC 6840 §5.2: a SHA-1 DS MUST NOT anchor trust when a SHA-256 DS
/// covers the same key tag. Applied uniformly to every anchoring check.
fn dsEligible(ds: dns.DsData, ds_records: []const dns.DsData) bool {
    if (ds.digest_type != .sha1) return true;
    for (ds_records) |ds2| {
        if (ds2.digest_type == .sha256 and ds2.key_tag == ds.key_tag) return false;
    }
    return true;
}

pub fn validateDnskeyRrset(
    dnskey_records: []const dns.ResourceRecord,
    ds_records: []const dns.DsData,
    zone_name: dns.Name,
    now_u32: u32,
    budget: *ValidationBudget,
) VerifyError!void {
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
        key_tags[i] = keyTag(dk);
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
    for (dnskey_records) |rrsig_rr| {
        if (rrsig_rr.rtype != .rrsig) continue;
        const rrsig = rrsig_rr.rdata.rrsig;
        if (rrsig.type_covered != .dnskey) continue;
        for (filtered, 0..) |rr, i| {
            if (!anchored[i] or key_tags[i] != rrsig.key_tag) continue;
            if (try tryVerifyRrsig(rrsig, rr.rdata.dnskey, filtered, now_u32, budget)) return;
        }
    }
    return error.InvalidSignature;
}

/// RFC 6840 §4.4: an NSEC/NSEC3 type bitmap proves an insecure delegation
/// when DS is absent, NS is present (proving delegation), and SOA is absent
/// (proving this is the parent-zone record, not a child-zone apex record).
fn isInsecureDelegationProof(type_bit_maps: []const u8) bool {
    return !dns.typeBitmapContains(type_bit_maps, .ds) and
        dns.typeBitmapContains(type_bit_maps, .ns) and
        !dns.typeBitmapContains(type_bit_maps, .soa);
}

/// Classify a child-zone delegation from the parent's authority section:
/// DS present, or NSEC/NSEC3 proving no DS (insecure), or neither.
///
/// `.secure` here does NOT mean "validated": it means "treat as signed,
/// proceed to DNSKEY/DS validation" — and an unsigned-but-unproven delegation
/// also returns `.secure`, so the validator (recursive.zig) fails closed to
/// SERVFAIL. Only `.insecure` asserts a proven (opt-out / no-DS) delegation.
pub fn isProperAncestor(zone: dns.Name, name: dns.Name) bool {
    return zone.labels.len < name.labels.len and name.isSubdomainOf(zone);
}

pub fn classifyDelegation(
    authorities: []const dns.ResourceRecord,
    child_zone: dns.Name,
    budget: *ValidationBudget,
) SecurityStatus {
    var has_ds = false;
    for (authorities) |rr| {
        if (rr.rtype == .ds and rr.name.eql(child_zone)) {
            has_ds = true;
            break;
        }
    }

    if (has_ds) return .secure;

    if (nsec3Flood(authorities)) return .bogus;

    // No DS — check for NSEC/NSEC3 proof of DS absence.
    // All NSEC3 records in a response share the same salt/iterations (RFC 9276),
    // so the child zone hash can be computed once and reused across all records.
    var cached_hash: ?[Sha1.digest_length]u8 = null;
    var cached_salt: []const u8 = &.{};
    var cached_iterations: u16 = 0;

    for (authorities) |rr| {
        if (rr.rtype == .nsec) {
            if (rr.name.eql(child_zone)) {
                if (isInsecureDelegationProof(rr.rdata.nsec.type_bit_maps)) return .insecure;
                // Not a valid delegation proof (RFC 6840 §4.4) — keep .secure
                // so unsigned child zones correctly SERVFAIL.
                return .secure;
            }
        }
        if (rr.rtype == .nsec3) {
            const nsec3 = rr.rdata.nsec3;
            // Permissive: skip unsupported hash algos to let a sibling NSEC3
            // still prove the zone insecure. Validation path is strict below.
            if (nsec3.hash_algorithm != .sha1) continue;
            // §8.2. Load-bearing here: the Opt-Out test below returns
            // `.insecure`, i.e. "unsigned delegation, stop validating".
            if (nsec3FlagsReserved(nsec3)) continue;
            // RFC 9276 §3.2: treat high-iteration NSEC3 as insecure. Per
            // RFC 5155 §7.3, all NSEC3 in a zone share the same iterations,
            // so one high-iteration record taints the whole proof.
            if (nsec3.iterations > max_nsec3_iterations) return .insecure;
            const owner_hash = nsec3OwnerHash(rr.name) orelse continue;
            // A no-DS proof lives in the parent, so the owner minus its hash
            // label must sit strictly above the cut. The hash alone binds
            // nothing: any signed zone can mint `<H(child)>.<its apex>`.
            if (!isProperAncestor(.{ .labels = rr.name.labels[1..] }, child_zone)) continue;

            // Reuse cached hash if salt/iterations match; cache misses charge
            // the per-resolution budget (the salt-cache-defeat surface).
            const child_hash = blk: {
                if (cached_hash) |h| {
                    if (cached_iterations == nsec3.iterations and
                        mem.eql(u8, cached_salt, nsec3.salt))
                        break :blk h;
                }
                const new_hash = budgetedNsec3Hash(child_zone, nsec3.salt, nsec3.iterations, budget) catch |e| switch (e) {
                    error.ValidationBudgetExhausted => return .bogus,
                    error.HashFailed => continue,
                };
                cached_hash = new_hash;
                cached_salt = nsec3.salt;
                cached_iterations = nsec3.iterations;
                break :blk new_hash;
            };

            if (mem.eql(u8, &owner_hash, &child_hash)) {
                if (isInsecureDelegationProof(nsec3.type_bit_maps)) return .insecure;
                // NSEC3 matches but doesn't prove insecure delegation (RFC 6840 §4.4).
                return .secure;
            }
            if (nsec3.flags & nsec3_opt_out != 0) {
                if (nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &child_hash)) {
                    return .insecure;
                }
            }
        }
    }

    // No DS and no valid proof of absence — fail closed to SERVFAIL.
    return .secure;
}

/// Compute the key tag for a DNSKEY record per RFC 4034 Appendix B.
/// The key tag is a checksum over the DNSKEY RDATA wire format.
fn keyTag(dnskey: dns.DnskeyData) u16 {
    var ac: u32 = 0;

    // DNSKEY RDATA wire: flags(2) + protocol(1) + algorithm(1) + public_key
    // Accumulate 16-bit words
    ac += @as(u32, dnskey.flags);
    ac += @as(u32, dnskey.protocol) << 8 | @backingInt(dnskey.algorithm);

    var i: usize = 0;
    while (i < dnskey.public_key.len) : (i += 1) {
        if (i & 1 == 0) {
            ac += @as(u32, dnskey.public_key[i]) << 8;
        } else {
            ac += @as(u32, dnskey.public_key[i]);
        }
    }

    ac += (ac >> 16) & 0xFFFF;
    return @intCast(ac & 0xFFFF);
}

// ── Canonical Name Wire Format (RFC 4034 §6.1) ──────────────────────

fn writeCanonicalNameWire(buf: []u8, name: dns.Name) error{BufferTooSmall}!usize {
    return writeNameWire(buf, name, true);
}

/// Write a name in uncompressed wire format, preserving case. RFC 6840 §5.1
/// exempts exactly one field from case folding — the NSEC `next_domain_name`
/// — so this is not a general-purpose escape hatch. RFC 4034 §6.2's list said
/// to fold it, RFC 3755 said not to, and 6840 settled it against 4034 to match
/// what signers already did.
fn writeNameWirePreservingCase(buf: []u8, name: dns.Name) error{BufferTooSmall}!usize {
    return writeNameWire(buf, name, false);
}

fn writeNameWire(buf: []u8, name: dns.Name, comptime lower: bool) error{BufferTooSmall}!usize {
    var pos: usize = 0;
    for (name.labels) |label| {
        if (pos + 1 + label.len > buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(label.len);
        pos += 1;
        for (label) |c| {
            buf[pos] = if (comptime lower) std.ascii.toLower(c) else c;
            pos += 1;
        }
    }
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = 0; // root label
    pos += 1;
    return pos;
}

fn verifyDs(ds: dns.DsData, dnskey: dns.DnskeyData, owner_name: dns.Name) VerifyError!void {
    var wire_buf: [1024]u8 = undefined;
    const name_len = try writeCanonicalNameWire(&wire_buf, owner_name);

    var pos = name_len;
    if (pos + 4 + dnskey.public_key.len > wire_buf.len) return error.BufferTooSmall;
    mem.writeInt(u16, wire_buf[pos..][0..2], dnskey.flags, .big);
    pos += 2;
    wire_buf[pos] = dnskey.protocol;
    pos += 1;
    wire_buf[pos] = @backingInt(dnskey.algorithm);
    pos += 1;
    @memcpy(wire_buf[pos..][0..dnskey.public_key.len], dnskey.public_key);
    pos += dnskey.public_key.len;

    const data = wire_buf[0..pos];

    const ok = switch (ds.digest_type) {
        .sha1 => verifyDigest(Sha1, data, ds.digest),
        .sha256 => verifyDigest(Sha256, data, ds.digest),
        .sha384 => verifyDigest(Sha384, data, ds.digest),
        _ => return error.UnsupportedAlgorithm,
    };
    if (!ok) return error.InvalidSignature;
}

/// Fixed-shape digest check: the expected length must match the hash and the
/// hash of `data` must equal `expected`. Either mismatch yields false — the
/// caller maps that to InvalidSignature, preserving verifyDs's semantics.
fn verifyDigest(comptime Hash: type, data: []const u8, expected: []const u8) bool {
    if (expected.len != Hash.digest_length) return false;
    var hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(data, &hash, .{});
    return mem.eql(u8, &hash, expected);
}

// ── RRSIG Signed Data Construction (RFC 4034 §5.3) ──────────────────

/// Write the RRSIG header (everything except the signature) in canonical
/// wire form. Used by both RRSIG verification (buildSignedData) and RRSIG
/// canonical serialization (writeCanonicalRData).
fn writeRrsigHeaderWire(buf: []u8, rrsig: dns.RrsigData) error{BufferTooSmall}!usize {
    if (buf.len < 18) return error.BufferTooSmall;
    mem.writeInt(u16, buf[0..2], @backingInt(rrsig.type_covered), .big);
    buf[2] = @backingInt(rrsig.algorithm);
    buf[3] = rrsig.labels;
    mem.writeInt(u32, buf[4..8], rrsig.original_ttl, .big);
    mem.writeInt(u32, buf[8..12], rrsig.sig_expiration, .big);
    mem.writeInt(u32, buf[12..16], rrsig.sig_inception, .big);
    mem.writeInt(u16, buf[16..18], rrsig.key_tag, .big);
    const name_len = try writeCanonicalNameWire(buf[18..], rrsig.signer_name);
    return 18 + name_len;
}

/// Build the signed data for RRSIG verification.
/// Returns a slice of the buffer containing: RRSIG_RDATA(sans signature) || sorted_canonical_RRset
fn buildSignedData(
    buf: []u8,
    rrsig: dns.RrsigData,
    rrset: []const dns.ResourceRecord,
) error{BufferTooSmall}![]const u8 {
    const pos: usize = try writeRrsigHeaderWire(buf, rrsig);

    // 2. Build canonical RRset entries, sorted by RDATA (RFC 4034 §6.3)
    // Each entry: canonical_owner_wire || type(2) || class(2) || original_ttl(4) || rdlength(2) || canonical_rdata
    const SortEntry = struct { wire: []const u8, rdata: []const u8 };
    var entries: [64]SortEntry = undefined;
    if (rrset.len > entries.len) return error.BufferTooSmall;

    var temp_pos = pos;

    for (rrset, 0..) |rr, idx| {
        const rr_start = temp_pos;

        // RFC 4035 §5.3.2: reconstruct wildcard owner if labels < name label count
        // wc_labels must live in the for-loop scope (not the if-block) so the
        // Name slice returned via break :blk remains valid for writeCanonicalNameWire.
        var wc_labels: [dns.max_label_count][]const u8 = undefined;
        const owner_name = if (rrsig.labels < rr.name.labels.len) blk: {
            wc_labels[0] = "*";
            const suffix = rr.name.labels[rr.name.labels.len - rrsig.labels ..];
            for (suffix, 1..) |label, i| {
                wc_labels[i] = label;
            }
            break :blk dns.Name{ .labels = wc_labels[0 .. rrsig.labels + 1] };
        } else rr.name;

        const owner_len = try writeCanonicalNameWire(buf[temp_pos..], owner_name);
        temp_pos += owner_len;

        if (temp_pos + 10 > buf.len) return error.BufferTooSmall;
        mem.writeInt(u16, buf[temp_pos..][0..2], @backingInt(rr.rtype), .big);
        temp_pos += 2;
        mem.writeInt(u16, buf[temp_pos..][0..2], @backingInt(rr.rclass), .big);
        temp_pos += 2;
        // Use RRSIG's original_ttl, not the RR's TTL
        mem.writeInt(u32, buf[temp_pos..][0..4], rrsig.original_ttl, .big);
        temp_pos += 4;

        const rdlen_pos = temp_pos;
        temp_pos += 2;

        const rdata_start = temp_pos;
        temp_pos += try writeCanonicalRData(buf[temp_pos..], rr.rdata);
        const rdata_len = temp_pos - rdata_start;
        mem.writeInt(u16, buf[rdlen_pos..][0..2], @intCast(rdata_len), .big);

        entries[idx] = .{ .wire = buf[rr_start..temp_pos], .rdata = buf[rdata_start..temp_pos] };
    }

    // RFC 4034 §6.3: within an RRset, sort by RDATA (owner/type/class/TTL
    // are identical). Must not include rdlength — it would mis-order records
    // of different sizes (e.g. mixed 1024/2048-bit DNSKEY).
    mem.sortUnstable(SortEntry, entries[0..rrset.len], {}, struct {
        fn lessThan(_: void, a: SortEntry, b: SortEntry) bool {
            return mem.order(u8, a.rdata, b.rdata) == .lt;
        }
    }.lessThan);

    // The sorted entries reference slices of buf[pos..temp_pos].
    // Compacting them in-place would corrupt source data (earlier copies
    // overwrite source positions of later entries). Copy to a temp buffer first.
    var temp_buf: [65536]u8 = undefined;
    var out_pos: usize = 0;
    for (entries[0..rrset.len]) |entry| {
        if (out_pos + entry.wire.len > temp_buf.len) return error.BufferTooSmall;
        @memcpy(temp_buf[out_pos..][0..entry.wire.len], entry.wire);
        out_pos += entry.wire.len;
    }
    if (pos + out_pos > buf.len) return error.BufferTooSmall;
    @memcpy(buf[pos..][0..out_pos], temp_buf[0..out_pos]);

    return buf[0 .. pos + out_pos];
}

/// Write canonical RDATA per RFC 4034 §6.2. Each name-bearing arm carries
/// its own folding rule — most lowercase, NSEC is case-preserving per
/// RFC 6840 §5.1. Types without embedded names are written as-is.
///
/// Separate from `dns.Serializer.writeRData` (canonical/lowercased, not wire).
/// Any new name-bearing RData arm MUST add a lowercasing arm here, or the
/// fallback mis-canonicalizes its embedded name and DNSSEC validation breaks.
fn writeCanonicalRData(buf: []u8, rdata: dns.RData) error{BufferTooSmall}!usize {
    switch (rdata) {
        .ns => |name| return writeCanonicalNameWire(buf, name),
        .cname => |name| return writeCanonicalNameWire(buf, name),
        .dname => |name| return writeCanonicalNameWire(buf, name),
        .ptr => |name| return writeCanonicalNameWire(buf, name),
        .mx => |mx| {
            if (buf.len < 2) return error.BufferTooSmall;
            mem.writeInt(u16, buf[0..2], mx.preference, .big);
            const name_len = try writeCanonicalNameWire(buf[2..], mx.exchange);
            return 2 + name_len;
        },
        .soa => |soa| {
            var pos: usize = 0;
            pos += try writeCanonicalNameWire(buf[pos..], soa.mname);
            pos += try writeCanonicalNameWire(buf[pos..], soa.rname);
            if (pos + 20 > buf.len) return error.BufferTooSmall;
            mem.writeInt(u32, buf[pos..][0..4], soa.serial, .big);
            pos += 4;
            mem.writeInt(u32, buf[pos..][0..4], soa.refresh, .big);
            pos += 4;
            mem.writeInt(u32, buf[pos..][0..4], soa.retry, .big);
            pos += 4;
            mem.writeInt(u32, buf[pos..][0..4], soa.expire, .big);
            pos += 4;
            mem.writeInt(u32, buf[pos..][0..4], soa.minimum, .big);
            pos += 4;
            return pos;
        },
        .rrsig => |rrsig| {
            var pos: usize = try writeRrsigHeaderWire(buf, rrsig);
            if (pos + rrsig.signature.len > buf.len) return error.BufferTooSmall;
            @memcpy(buf[pos..][0..rrsig.signature.len], rrsig.signature);
            pos += rrsig.signature.len;
            return pos;
        },
        .nsec => |nsec_data| {
            var pos: usize = 0;
            // RFC 6840 §5.1: NSEC RDATA names are NOT folded (RRSIG's are —
            // see the signer_name write above, which correctly is).
            pos += try writeNameWirePreservingCase(buf[pos..], nsec_data.next_domain_name);
            if (pos + nsec_data.type_bit_maps.len > buf.len) return error.BufferTooSmall;
            @memcpy(buf[pos..][0..nsec_data.type_bit_maps.len], nsec_data.type_bit_maps);
            pos += nsec_data.type_bit_maps.len;
            return pos;
        },
        else => {
            var ser = dns.Serializer.init(buf);
            ser.writeRData(rdata) catch return error.BufferTooSmall;
            return ser.pos;
        },
    }
}

// RFC 4035 §5.3.1 mandates zero grace; deviate minimally and asymmetrically.
// Inception grace forgives a signer with a slightly-ahead clock (misconfig, no
// replay value). Expiration grace would widen an attacker's replay window for
// a captured RRSIG, so it stays zero.
const inception_skew_tolerance: u32 = 60;

/// Verify an RRSIG, returning true on success, false on non-budget failure.
/// Propagates ValidationBudgetExhausted so callers can bail out of loops.
fn tryVerifyRrsig(
    rrsig: dns.RrsigData,
    dnskey: dns.DnskeyData,
    rrset: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *ValidationBudget,
) error{ValidationBudgetExhausted}!bool {
    verifyRrsig(rrsig, dnskey, rrset, now_u32, budget) catch |e| switch (e) {
        error.ValidationBudgetExhausted => return error.ValidationBudgetExhausted,
        else => return false,
    };
    return true;
}

fn verifyRrsig(
    rrsig: dns.RrsigData,
    dnskey: dns.DnskeyData,
    rrset: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *ValidationBudget,
) VerifyError!void {
    // KeyTrap (CVE-2023-50387) mitigation: charge before any work so attempts
    // count even when the cheap pre-checks below would reject.
    try budget.consumeVerify();

    // RFC 4035 §5.3.1; else an RRSIG naming a weaker algorithm hands the key to that verifier.
    if (rrsig.algorithm != dnskey.algorithm) return error.InvalidSignature;

    // RFC 4034 §3.1.3: signer name MUST be a (non-strict) ancestor of every
    // RRset owner, and `labels` MUST NOT exceed the owner's label count nor
    // fall below the signer's: fewer means the wildcard that signed sits above
    // the zone. Owner-vs-signer is also checked at the resolver layer (bailiwick
    // scrubbing); enforcing here defends future callers from missing it.
    if (rrsig.labels < rrsig.signer_name.labels.len) return error.InvalidSignature;
    for (rrset) |rr| {
        if (!rr.name.isSubdomainOf(rrsig.signer_name)) return error.InvalidSignature;
        if (rrsig.labels > rr.name.labels.len) return error.InvalidSignature;
    }

    // An SOA or NS RRset *defines* the name it sits at: SOA marks an apex, and
    // a signed NS marks a child-side apex, since RFC 4035 §2.2 forbids signing
    // the parent-side delegation NS. Either way the containing zone is the
    // owner itself, so a strictly-higher signer is wrong by definition — no
    // knowledge of where the cuts are required. This is the one case where the
    // §5.3.1 rule "the Signer's Name MUST be the name of the zone that contains
    // the RRset" is decidable from the record alone; everywhere else the signer
    // is an ancestor of the owner for every non-apex record in DNS and the test
    // says nothing. BIND names it "SOA signer mismatch" / "NS signer mismatch"
    // (lib/dns/validator.c:1473-1483); it is the only such check in Unbound or
    // BIND, and hark had no equivalent.
    if (rrsig.type_covered == .soa or rrsig.type_covered == .ns) {
        for (rrset) |rr| {
            if (!rr.name.eql(rrsig.signer_name)) return error.InvalidSignature;
        }
    }

    // RFC 4035 §5.3.1 validity period, with asymmetric clock-skew tolerance.
    const skew_ahead = now_u32 +% inception_skew_tolerance;
    if (dns.serialAfter(rrsig.sig_inception, skew_ahead)) return error.SignatureExpired;
    if (dns.serialAfter(now_u32, rrsig.sig_expiration)) return error.SignatureExpired;

    var signed_data_buf: [65536]u8 = undefined;
    const signed_data = try buildSignedData(&signed_data_buf, rrsig, rrset);

    switch (rrsig.algorithm) {
        .rsasha1, .rsasha1_nsec3 => try verifyRsa(rrsig.signature, signed_data, dnskey.public_key, Sha1),
        .rsasha256 => try verifyRsa(rrsig.signature, signed_data, dnskey.public_key, Sha256),
        .rsasha512 => try verifyRsa(rrsig.signature, signed_data, dnskey.public_key, Sha512),
        .ecdsap256sha256 => try verifyEcdsa(EcdsaP256, 32, rrsig.signature, signed_data, dnskey.public_key),
        .ecdsap384sha384 => try verifyEcdsa(EcdsaP384, 48, rrsig.signature, signed_data, dnskey.public_key),
        .ed25519 => try verifyEd25519(rrsig.signature, signed_data, dnskey.public_key),
        else => return error.UnsupportedAlgorithm,
    }
}

/// Parse an RFC 3110 RSA public key and verify a PKCS#1 v1.5 signature.
fn verifyRsa(signature: []const u8, msg: []const u8, key_data: []const u8, comptime Hash: type) VerifyError!void {
    // RFC 3110: first byte is exponent length (if < 256), then exponent, then modulus
    // If first byte is 0, next 2 bytes are exponent length
    if (key_data.len < 3) return error.InvalidKey;

    var exp_len: usize = key_data[0];
    var offset: usize = 1;
    if (exp_len == 0) {
        exp_len = @as(usize, key_data[1]) << 8 | key_data[2];
        offset = 3;
    }

    if (exp_len == 0) return error.InvalidKey;
    if (offset + exp_len > key_data.len) return error.InvalidKey;
    var exponent = key_data[offset..][0..exp_len];
    const modulus = key_data[offset + exp_len ..];

    // Strip leading zeros: `[00 00 00 01]` would read as e=1 and forge sig=EM.
    while (exponent.len > 1 and exponent[0] == 0) exponent = exponent[1..];
    if (exponent[exponent.len - 1] & 1 == 0) return error.InvalidKey;
    if (exponent.len == 1 and exponent[0] <= 1) return error.InvalidKey;

    // powPublic is square-and-multiply, so its cost is linear in the exponent's
    // bit length. Measured on a 4096-bit modulus: e=65537 costs 0.8 ms and a
    // 511-byte exponent costs 31.6 ms. The KeyTrap budget caps the verify
    // *count* at 96, not the cost of each, so a fat exponent multiplies the
    // whole budget — 96 x 31.6 ms = 3.0 s of CPU for one query, against 4
    // resolution threads per worker. That is under 2 QPS to saturate.
    //
    // 8 bytes is 32x the largest exponent anyone actually publishes and keeps
    // the point of 500285a, which removed the stdlib's 4-byte cap so
    // xelerance.com's 5-byte e = 2^32+1 would validate.
    //
    // The exponent is already bounded below the modulus by RsaFe.fromBytes, so
    // the pre-existing ceiling was 511 bytes rather than the 65535 that RFC
    // 3110's length encoding allows. Bounded, but not nearly enough.
    if (exponent.len > 8) return error.InvalidKey;

    // Require 1024-bit minimum modulus, 8-byte step (1024/2048/3072/4096 are
    // the only sizes generated in practice). RFC 6781 recommends 2048 but
    // 1024-bit ZSKs are still common, including in TLDs like .org.
    if (modulus.len < 128 or modulus.len > 512 or modulus.len % 8 != 0) return error.InvalidKey;
    if (signature.len != modulus.len) return error.InvalidSignature;

    // ff.Modulus is what Certificate.rsa wraps; calling it directly sidesteps
    // the 4-byte exponent cap (Windows-CryptoAPI parity) that would lock out
    // zones like xelerance.com (e = 2^32 + 1).
    const n = RsaModulus.fromBytes(modulus, .big) catch return error.InvalidKey;
    if (n.bits() < 1024) return error.InvalidKey;
    const e = RsaFe.fromBytes(n, exponent, .big) catch return error.InvalidKey;
    const sig_fe = RsaFe.fromBytes(n, signature, .big) catch return error.InvalidSignature;
    const decoded_fe = n.powPublic(sig_fe, e) catch return error.InvalidSignature;

    var em_dec: [512]u8 = undefined;
    decoded_fe.toBytes(em_dec[0..modulus.len], .big) catch return error.InvalidSignature;
    var em_expected: [512]u8 = undefined;
    pkcs1v15Encode(em_expected[0..modulus.len], Hash, msg);

    // Xor-fold compare: no data-dependent branch, so still constant-time —
    // though EM in signature *verification* is public data anyway.
    var diff: u8 = 0;
    for (em_dec[0..modulus.len], em_expected[0..modulus.len]) |a, b| diff |= a ^ b;
    if (diff != 0) return error.InvalidSignature;
}

/// EMSA-PKCS1-v1_5 (RFC 8017 §9.2). Inlined because the stdlib's equivalent
/// in Certificate.rsa is private and we no longer route through it.
fn pkcs1v15Encode(em: []u8, comptime Hash: type, msg: []const u8) void {
    const hash_der: []const u8 = &switch (Hash) {
        Sha1 => .{
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        },
        Sha256 => .{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
        Sha512 => .{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
        else => @compileError("unsupported hash for PKCS#1 v1.5"),
    };
    // RFC 8017 §9.2 step 3: PS ≥ 8 octets, else @memset wraps. Guaranteed
    // by verifyRsa's `modulus.len >= 128` gate — Sha512 needs at most 94.
    std.debug.assert(em.len >= hash_der.len + Hash.digest_length + 11);

    var idx: usize = em.len;
    idx -= Hash.digest_length;
    Hash.hash(msg, em[idx..][0..Hash.digest_length], .{});
    idx -= hash_der.len;
    @memcpy(em[idx..][0..hash_der.len], hash_der);
    idx -= 1;
    em[idx] = 0x00;
    @memset(em[2..idx], 0xff);
    em[1] = 0x01;
    em[0] = 0x00;
}

/// Verify an ECDSA signature (P-256 or P-384) given raw x||y key and r||s signature.
fn verifyEcdsa(comptime Curve: type, comptime coord_len: comptime_int, signature: []const u8, msg: []const u8, key_data: []const u8) VerifyError!void {
    const key_len = coord_len * 2;
    if (key_data.len != key_len) return error.InvalidKey;
    if (signature.len != key_len) return error.InvalidSignature;

    // Prepend 0x04 for SEC1 uncompressed format
    var sec1_key: [1 + key_len]u8 = undefined;
    sec1_key[0] = 0x04;
    @memcpy(sec1_key[1..], key_data);

    const pub_key = Curve.PublicKey.fromSec1(&sec1_key) catch return error.InvalidKey;
    const sig = Curve.Signature.fromBytes(signature[0..key_len].*);
    sig.verify(msg, pub_key) catch return error.InvalidSignature;
}

fn verifyEd25519(signature: []const u8, msg: []const u8, key_data: []const u8) VerifyError!void {
    if (key_data.len != 32) return error.InvalidKey;
    if (signature.len != 64) return error.InvalidSignature;

    const pub_key = Ed25519.PublicKey.fromBytes(key_data[0..32].*) catch return error.InvalidKey;
    const sig = Ed25519.Signature.fromBytes(signature[0..64].*);
    sig.verify(msg, pub_key) catch return error.InvalidSignature;
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
pub fn commonSuffixLabels(a: dns.Name, b: dns.Name) usize {
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
/// shared with either bound, clamped to a PROPER ancestor — an apex-wrap
/// NSEC bound (e.g. ip6.arpa. → 3.0.0.1.0.0.2.ip6.arpa.) contains qname as
/// a strict suffix and would otherwise saturate the CE to qname itself.
/// Null for the root qname. The result aliases qname's labels.
pub fn closestEncloser(qname: dns.Name, bound_a: dns.Name, bound_b: dns.Name) ?dns.Name {
    if (qname.labels.len == 0) return null;
    const depth = @min(@max(
        commonSuffixLabels(qname, bound_a),
        commonSuffixLabels(qname, bound_b),
    ), qname.labels.len - 1);
    return .{ .labels = qname.labels[qname.labels.len - depth ..] };
}

test closestEncloser {
    const t = std.testing;
    const qname = dns.Name{ .labels = &.{ "a", "b", "example", "com" } };
    // Ordinary cover: CE is the deepest shared suffix of either bound.
    const owner = dns.Name{ .labels = &.{ "z", "b", "example", "com" } };
    const next = dns.Name{ .labels = &.{ "example", "com" } };
    try t.expectEqual(@as(usize, 3), closestEncloser(qname, owner, next).?.labels.len);
    // Apex-wrap bound containing qname as a strict suffix must clamp to a
    // proper ancestor, never qname itself.
    const wrap = dns.Name{ .labels = &.{ "x", "a", "b", "example", "com" } };
    try t.expectEqual(@as(usize, 3), closestEncloser(qname, wrap, wrap).?.labels.len);
    // Root qname has no proper ancestor.
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

/// Check if an NSEC record proves that `qname` does not exist.
/// Returns true if qname falls in the range (nsec_owner, nsec_next) AND the
/// record is allowed to speak for qname at all (RFC 6840 §4.1 — see
/// `provesNothingBelowOwner`). `nsec_cache.checkCovering` reaches the §4.1
/// rule through here, which is deliberate: one home for both callers.
pub fn nsecProvesNameNonexistence(
    nsec_owner: dns.Name,
    nsec: dns.NsecData,
    qname: dns.Name,
) bool {
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

/// RFC 4035 §5.4 + RFC 6840 §4.3: a NODATA proof fails if the bitmap
/// asserts qtype — or a CNAME, which would have answered the query —
/// exists at the owner. Also gates nsec_cache's aggressive synthesis.
pub fn bitmapContradictsNodata(type_bit_maps: []const u8, qtype: dns.RType) bool {
    return dns.typeBitmapContains(type_bit_maps, qtype) or
        dns.typeBitmapContains(type_bit_maps, .cname);
}

fn nsecProvesTypeNonexistence(
    nsec_owner: dns.Name,
    nsec: dns.NsecData,
    qname: dns.Name,
    qtype: dns.RType,
) bool {
    if (!nsec_owner.eql(qname)) return false;
    if (wrongSideOfCut(nsec.type_bit_maps, qname, qtype)) return false;
    return !bitmapContradictsNodata(nsec.type_bit_maps, qtype);
}

/// Max NSEC3 iterations per record. >50 → .insecure (fail-open) rather than
/// burning hash budget — the post-CVE-2023-50868 consensus (Knot/BIND/PowerDNS);
/// RFC 9276 recommends 0. Honest signers use 0–20.
const max_nsec3_iterations: u16 = 50;

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

/// Per-proof NSEC3 record ceiling (Knot Resolver 5.7.1). An honest proof needs
/// ≤3 (closest-encloser + next-closer + wildcard); more is the CVE-2023-50868
/// flood shape, refused CLOSED to `.bogus` before any hashing.
const max_nsec3_records_per_proof: usize = 8;

/// True when an authority section holds more NSEC3 records than any honest proof
/// needs — the flood shape. NSEC3-only count, so NSEC proofs are unaffected.
fn nsec3Flood(authorities: []const dns.ResourceRecord) bool {
    var n: usize = 0;
    for (authorities) |rr| {
        if (rr.rtype == .nsec3) n += 1;
    }
    return n > max_nsec3_records_per_proof;
}

fn nsec3Hash(
    name: dns.Name,
    salt: []const u8,
    iterations: u16,
) error{BufferTooSmall}![Sha1.digest_length]u8 {
    var name_wire: [dns.max_name_len + 2]u8 = undefined;
    const name_len = try writeCanonicalNameWire(&name_wire, name);

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
    budget: *ValidationBudget,
) BudgetedHashError![Sha1.digest_length]u8 {
    try budget.consumeNsec3Hash();
    return nsec3Hash(name, salt, iterations) catch return error.HashFailed;
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
/// the same record covers the wildcard). `classifyDelegation` already takes a
/// zone; this function being the odd one out is what made the hole reachable.
///
/// Tests that exercise pure range geometry pass root, which makes the check
/// vacuous by construction.
pub fn validateNegativeProof(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    zone: dns.Name,
    budget: *ValidationBudget,
) SecurityStatus {
    // A proof signed by some other zone says nothing about this name.
    if (!qname.isSubdomainOf(zone)) return .bogus;

    if (hasMixedNsecNsec3(authorities)) return .bogus;

    // One scan for both shapes: matching_nsec (owner == qname) → direct NODATA;
    // covering_nsec (range covers qname) → wildcard-NODATA (§3.1.3.4) or
    // NXDOMAIN-shape-under-NOERROR (§5.4 — proof shape is signed, not rcode).
    var matching_nsec: ?dns.ResourceRecord = null;
    var covering_nsec: ?dns.ResourceRecord = null;
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
    }

    // NODATA arm. Bitmap contradicting NODATA → .bogus (signed, hence forgery).
    if (!is_nxdomain and any_nsec) {
        if (matching_nsec) |rr| {
            if (nsecProvesTypeNonexistence(rr.name, rr.rdata.nsec, qname, qtype))
                return .secure;
            // Answered from the wrong side of its own cut: unusable, not
            // contradictory (RFC 6840 §4.1/§4.4). A parent-side NSEC owed us
            // a referral; a child-side one owed us nothing about DS.
            if (wrongSideOfCut(rr.rdata.nsec.type_bit_maps, qname, qtype))
                return .unchecked;
            return .bogus;
        }

        // Do NOT borrow the NXDOMAIN arm's strict CE-existence check (NSEC
        // owner or next == CE): canonical wildcard NSECs have owner *.CE
        // which sorts AFTER CE, so the strict check fails on the wire shape
        // IANA and real signed zones actually emit. Owner-equality with
        // *.CE plus a verified RRSIG is the binding here.
        if (covering_nsec) |cov| {
            // ENT: a covering NSEC whose next name descends below qname
            // proves qname is an empty non-terminal (RFC 4592 §2.2.2) — it
            // exists, owns no types, and wildcards never apply to existing
            // names, so this alone completes the proof (Unbound
            // nsec_proves_nodata, same ENT-before-wildcard order). The open
            // range excludes next == qname, so isSubdomainOf is strict.
            // ip6.arpa's NSEC-signed nibble tree is mostly ENTs; every qmin
            // step landing between delegations takes this path.
            if (cov.rdata.nsec.next_domain_name.isSubdomainOf(qname))
                return .secure;

            const ce = closestEncloser(qname, cov.name, cov.rdata.nsec.next_domain_name) orelse
                return .unchecked;

            var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
            const wildcard = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unchecked;

            for (authorities) |rr| {
                if (rr.rtype != .nsec or !rr.name.isSubdomainOf(zone)) continue;
                if (rr.name.eql(wildcard)) {
                    // §3.1.3.4: *.CE exists; qtype + CNAME must be absent.
                    if (bitmapContradictsNodata(rr.rdata.nsec.type_bit_maps, qtype))
                        return .bogus;
                    return .secure;
                }
                // §5.4 proof under NOERROR rcode: *.CE denied + qname denied.
                if (nsecProvesNameNonexistence(rr.name, rr.rdata.nsec, wildcard))
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
        // an existing name exists (RFC 4592 §2.2.2). An owner/next == CE
        // equality check here rejected ENT closest-enclosers — ip6.arpa
        // NXDOMAINs SERVFAILed on every query (ENTs never own an NSEC).
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
    if (nsec3Flood(authorities)) return .{ .verdict = .bogus };

    var salt: []const u8 = &.{};
    var iterations: u16 = 0;
    var found_nsec3 = false;
    var saw_unknown_algo = false;
    for (authorities) |rr| {
        if (rr.rtype != .nsec3 or !rr.name.isSubdomainOf(zone)) continue;
        const nsec3 = rr.rdata.nsec3;
        // RFC 5155 §10.2 / RFC 6840 §5.11: skip NSEC3 records using unknown
        // hash algorithms; do not treat as bogus.
        if (nsec3.hash_algorithm != .sha1) {
            saw_unknown_algo = true;
            continue;
        }
        // §8.2: ignored, so not allowed to define the chain's parameters.
        if (nsec3FlagsReserved(nsec3)) continue;
        // RFC 9276 §3.2: treat high-iteration NSEC3 as insecure. Mirrors
        // classifyDelegation — both paths share one policy.
        if (nsec3.iterations > max_nsec3_iterations) return .{ .verdict = .insecure };
        salt = nsec3.salt;
        iterations = nsec3.iterations;
        found_nsec3 = true;
        break;
    }
    if (!found_nsec3) {
        // Only unknown-algorithm NSEC3 records present — validator can't
        // verify; treat as insecure so a future SHA-256/SHA-3 transition
        // doesn't SERVFAIL.
        if (saw_unknown_algo) return .{ .verdict = .insecure };
        return .{ .verdict = .unchecked };
    }

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

/// RFC 4035 §5.3.4: without proof that nothing exists between `qname` and the
/// closest encloser the RRSIG's `labels` names, a captured `*.zone` answer
/// replays as any name in the zone. Cf. Unbound `nsec3_prove_wildcard`.
pub fn proveNoCloserMatch(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    labels: u8,
    zone: dns.Name,
    budget: *ValidationBudget,
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
    var covered = false;
    var optout = false;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
        if (!nsec3HashInRange(&owner_hash, rr.rdata.nsec3.next_hashed_owner, &nc_hash)) continue;
        covered = true;
        if (rr.rdata.nsec3.flags & nsec3_opt_out != 0) optout = true;
    }
    return if (!covered) .bogus else if (optout) .insecure else .secure;
}

/// Validate NSEC3 negative proofs (RFC 5155 §8.4/§8.5/§8.6/§8.7).
fn validateNsec3NegativeProof(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    zone: dns.Name,
    budget: *ValidationBudget,
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
                // NSEC3 is the majority wire form — com/net/org all use it —
                // so omitting it here would leave the rule on the minority case.
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
    var ce_idx: ?usize = null;
    var label_offset: usize = 0;
    while (label_offset < qname.labels.len) : (label_offset += 1) {
        const ancestor_hash: [Sha1.digest_length]u8 = if (label_offset == 0)
            qname_hash
        else blk: {
            const ancestor = dns.Name{ .labels = qname.labels[label_offset..] };
            break :blk budgetedNsec3Hash(ancestor, salt, iterations, budget) catch return .bogus;
        };
        for (authorities) |rr| {
            const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
            if (mem.eql(u8, &owner_hash, &ancestor_hash)) {
                // RFC 6840 §4.1: a closest encloser is by construction a
                // proper ancestor of qname (ce_offset == 0 is rejected just
                // below), so everything this proof goes on to deny lies below
                // it. An ancestor-delegation or DNAME NSEC3 may not serve as
                // that anchor — otherwise any TLD's own genuine delegation
                // NSEC3 becomes the CE for every name in the child zone, and
                // the next-closer and wildcard hashes then fall inside the
                // parent's chain trivially, because those names are not in
                // the parent at all.
                if (provesNothingBelowOwner(rr.rdata.nsec3.type_bit_maps)) return .unchecked;
                ce_idx = label_offset;
                break;
            }
        }
        if (ce_idx != null) break;
    }
    const ce_offset = ce_idx orelse return .unchecked;

    // CE == qname contradicts NXDOMAIN (and wildcard-expansion semantics).
    if (ce_offset == 0) return .bogus;

    const next_closer = dns.Name{ .labels = qname.labels[ce_offset - 1 ..] };
    const nc_hash = budgetedNsec3Hash(next_closer, salt, iterations, budget) catch return .bogus;

    // RFC 5155 §8.6 — NODATA, QTYPE DS. No NSEC3 matched qname, which under
    // Opt-Out is the normal shape for an unsigned delegation. §8.6 wants a
    // closest-*provable*-encloser proof — CE match plus an Opt-Out NSEC3
    // covering the next closer — and no wildcard, a delegation never being
    // wildcard-generated. Demanding §8.7's wildcard step (as the shared path
    // below does) SERVFAILed every DS query into an Opt-Out TLD.
    //
    // `.insecure`, never `.secure`: the span may hold unsigned delegations, so
    // qname's own existence is unproven and §9.2 makes AD a MUST NOT. Unbound's
    // `nsec3_prove_nods` ends on the same verdict.
    if (qtype == .ds and !is_nxdomain) {
        var ds_nc_covered = false;
        var ds_nc_optout = false;
        for (authorities) |rr| {
            const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
            const nsec3 = rr.rdata.nsec3;
            if (!nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &nc_hash)) continue;
            ds_nc_covered = true;
            if (nsec3.flags & nsec3_opt_out != 0) ds_nc_optout = true;
        }
        if (!ds_nc_covered) return .unchecked;
        // Without Opt-Out the coverer proves the name *absent*, contradicting
        // the NOERROR it arrived under — a lie, not a gap.
        return if (ds_nc_optout) .insecure else .bogus;
    }

    var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
    const ce = dns.Name{ .labels = qname.labels[ce_offset..] };
    const wildcard = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unchecked;
    const wc_hash = budgetedNsec3Hash(wildcard, salt, iterations, budget) catch return .bogus;

    // Wildcard step: covered (§8.4) or, under NOERROR only, owner-match lacking
    // qtype and CNAME (§8.6). Any other owner-match means *.CE exists and the
    // answer should have been an expansion or NODATA.
    var nc_covered = false;
    var nc_optout = false;
    var wc_proven = false;
    var wc_contradicted = false;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr, zone) orelse continue;
        const nsec3 = rr.rdata.nsec3;

        if (nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &nc_hash)) {
            nc_covered = true;
            // All coverers, not just the first: an attacker picks the order.
            if (nsec3.flags & nsec3_opt_out != 0) nc_optout = true;
        }
        if (!wc_proven) {
            if (nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &wc_hash)) {
                wc_proven = true;
            } else if (mem.eql(u8, &owner_hash, &wc_hash)) {
                if (is_nxdomain or bitmapContradictsNodata(nsec3.type_bit_maps, qtype)) {
                    wc_contradicted = true;
                } else {
                    wc_proven = true;
                }
            }
        }
    }

    // RFC 5155 §9.2: AD MUST NOT be set when the next-closer coverer has
    // Opt-Out — that span may hold insecure delegations, so the denial is not
    // fully proven. §9.2 is not DS-scoped, which is why it applies here and not
    // only in the §8.6 branch above; Unbound agrees at `val_nsec3.c:1231`
    // and `:1386`.
    if (nc_covered and wc_proven) return if (nc_optout) .insecure else .secure;
    if (wc_contradicted) return .bogus;
    return .unchecked;
}

/// RFC 8624 §3.1: MUST validate RSASHA1/RSASHA1-NSEC3 even though they
/// are NOT RECOMMENDED for signing — signing-not-recommended is not
/// validation-unsupported.
fn isSupportedAlgorithm(algo: dns.DnssecAlgorithm) bool {
    return switch (algo) {
        .rsasha1, .rsasha1_nsec3, .rsasha256, .rsasha512, .ecdsap256sha256, .ecdsap384sha384, .ed25519 => true,
        else => false,
    };
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
        if (!isSupportedAlgorithm(ds.algorithm)) continue;
        switch (ds.digest_type) {
            .sha1, .sha256, .sha384 => return true,
            _ => {},
        }
    }
    return false;
}

fn rrsetVerifiesWithAnyKey(
    rrsig: dns.RrsigData,
    dnskey_records: []const dns.ResourceRecord,
    rrset: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *ValidationBudget,
) error{ValidationBudgetExhausted}!bool {
    for (dnskey_records) |dk_rr| {
        if (dk_rr.rtype != .dnskey) continue;
        const dk = dk_rr.rdata.dnskey;
        if (!isValidZoneKey(dk)) continue;
        if (keyTag(dk) != rrsig.key_tag) continue;
        if (try tryVerifyRrsig(rrsig, dk, rrset, now_u32, budget)) return true;
    }
    return false;
}

/// A message is no better authenticated than its least authenticated RRset.
pub fn weakest(a: SecurityStatus, b: SecurityStatus) SecurityStatus {
    return if (verdictRank(a) <= verdictRank(b)) a else b;
}

fn verdictRank(s: SecurityStatus) u8 {
    return switch (s) {
        .bogus => 0,
        .unchecked => 1,
        .insecure => 2,
        .secure => 3,
    };
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
        const rrsig = rr.rdata.rrsig;
        if (rrsig.type_covered == covered_type and rr.name.eql(owner)) return rrsig;
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
    budget: *ValidationBudget,
) ?dns.RrsigData {
    // Refuse rather than truncate: the caller sets AD on the *unpruned*
    // response, so verifying a signature over records[0..64] while
    // shipping 70 records launders the 6 attacker-appended RRs into an
    // authenticated answer. buildSignedData refuses >64 anyway,
    // so a genuine oversized RRset was already unvalidatable here —
    // this only makes the refusal explicit instead of silent.
    var filtered: [64]dns.ResourceRecord = undefined;
    var count: usize = 0;
    for (records) |rr| {
        if (rr.rtype != covered_type or !rr.name.eql(owner)) continue;
        if (count == filtered.len) return null;
        filtered[count] = rr;
        count += 1;
    }
    if (count == 0) return null;

    for (records) |sig_rr| {
        if (sig_rr.rtype != .rrsig) continue;
        const rrsig = sig_rr.rdata.rrsig;
        if (rrsig.type_covered != covered_type) continue;
        if (!sig_rr.name.eql(owner)) continue;
        if (!isSupportedAlgorithm(rrsig.algorithm)) continue;

        if (rrsetVerifiesWithAnyKey(rrsig, dnskey_records, filtered[0..count], now_u32, budget) catch return null) return rrsig;
    }
    // Nothing verified on a zone already proven secure — bogus, even when
    // every candidate RRSIG used an unsupported algorithm: real supported
    // signatures existed (the zone's DS says so, RFC 4035 §5.2 filtered the
    // all-unsupported case to .insecure at the delegation) and were stripped.
    // A softer verdict here is a keyless downgrade; Unbound and BIND agree.
    return null;
}

/// How long an RRset this signature verified may be held: RFC 4034 §3.1.2
/// Original TTL or RFC 4035 §5.3.3 remaining window, whichever is shorter.
pub fn rrsigTtlCap(rrsig: dns.RrsigData, now_u32: u32) u32 {
    return @min(rrsig.original_ttl, rrsig.secondsUntilExpiry(now_u32));
}

/// Verify that every piece of negative-answer material in the authority
/// section — NSEC/NSEC3 proofs *and* the RFC 2308 SOA — has a valid RRSIG
/// signed by one of the provided DNSKEYs. The SOA is what a `.secure`
/// negative's TTL and a downstream validator's own verdict rest on; leaving
/// it unverified made AD=1 an overclaim (RFC 4035 §3.2.3 covers the whole
/// authority section). NS and glue stay exempt: at a zone cut they are
/// legitimately unsigned delegation data. On `.secure`, `ttl_cap` is lowered
/// to the tightest verified signature's bound — a proof-derived verdict must
/// not be cached past the signatures that justify it.
pub fn verifyAuthorityProofSigs(
    authorities: []const dns.ResourceRecord,
    dnskey_records: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *ValidationBudget,
    ttl_cap: ?*u32,
) SecurityStatus {
    // No proof material at all is `.unchecked` regardless of the SOA: the
    // stripped-everything response already degrades to unauthenticated-and-
    // uncached, and an unsigned bare SOA must not land *harsher* than that —
    // the attacker would simply strip the SOA too.
    for (authorities) |rr| {
        if (rr.rtype == .nsec or rr.rtype == .nsec3) break;
    } else return .unchecked;

    // NSEC/NSEC3 records have unique owners per RFC 4034/5155,
    // so no dedup is needed.
    for (authorities) |rr| {
        if (rr.rtype != .nsec and rr.rtype != .nsec3 and rr.rtype != .soa) continue;

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
            const rrsig = sig_rr.rdata.rrsig;
            if (rrsig.type_covered != rr.rtype or !sig_rr.name.eql(rr.name)) continue;
            if (!isSupportedAlgorithm(rrsig.algorithm)) continue;
            // Proof material is never wildcard-expanded (RFC 4035 §3.1.3.3 serves
            // the `*.CE` NSEC under its own owner), and the proofs read the owner
            // as served: a real `*.zone NSEC` signature would verify under any.
            if (rrsig.labels != rr.name.labels.len) return .bogus;

            if (rrsetVerifiesWithAnyKey(rrsig, dnskey_records, rrset[0..rrset_count], now_u32, budget) catch return .bogus) {
                if (ttl_cap) |cap| cap.* = @min(cap.*, rrsigTtlCap(rrsig, now_u32));
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

test "keyTag computation" {
    // Test with a known DNSKEY. The root KSK-2017 has key tag 20326.
    // We'll use a synthetic key and verify the algorithm matches RFC 4034 Appendix B.
    const dnskey = dns.DnskeyData{
        .flags = 256, // ZSK
        .protocol = 3,
        .algorithm = .rsasha256,
        .public_key = &.{ 0x03, 0x01, 0x00, 0x01 },
    };
    const tag = keyTag(dnskey);
    // Manually compute: ac = 256 + (3<<8|8) + (0x03<<8) + (0x01) + (0x00<<8) + (0x01)
    // = 256 + 776 + 768 + 1 + 0 + 1 = 1802
    // ac += (1802 >> 16) & 0xFFFF = 0
    // tag = 1802 & 0xFFFF = 1802
    try testing.expectEqual(@as(u16, 1802), tag);
}

test "isSupportedAlgorithm covers RFC 8624 MUST-validate set" {
    // RFC 8624 §3.1: validators MUST validate algorithms 5 (RSASHA1),
    // 7 (RSASHA1-NSEC3-SHA1), 8 (RSASHA256), 10 (RSASHA512), 13 and 14
    // (ECDSA), 15 (Ed25519). Marking any of these unsupported silently
    // downgrades signed zones to insecure and lets forged answers through.
    try testing.expect(isSupportedAlgorithm(.rsasha1));
    try testing.expect(isSupportedAlgorithm(.rsasha1_nsec3));
    try testing.expect(isSupportedAlgorithm(.rsasha256));
    try testing.expect(isSupportedAlgorithm(.rsasha512));
    try testing.expect(isSupportedAlgorithm(.ecdsap256sha256));
    try testing.expect(isSupportedAlgorithm(.ecdsap384sha384));
    try testing.expect(isSupportedAlgorithm(.ed25519));
    // Algorithms RFC 8624 declares MUST NOT use for either signing or
    // validation should still register as unsupported.
    try testing.expect(!isSupportedAlgorithm(.rsamd5));
    try testing.expect(!isSupportedAlgorithm(.dsasha1));
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

test "canonical name wire format" {
    var buf: [256]u8 = undefined;

    const name = dns.Name{
        .labels = &.{
            @as([]const u8, "Example"),
            @as([]const u8, "COM"),
        },
    };
    const len = try writeCanonicalNameWire(&buf, name);
    try testing.expectEqualSlices(u8, "\x07example\x03com\x00", buf[0..len]);

    const root = dns.Name{ .labels = &.{} };
    const root_len = try writeCanonicalNameWire(&buf, root);
    try testing.expectEqual(@as(usize, 1), root_len);
    try testing.expectEqual(@as(u8, 0), buf[0]);
}

fn testDsDigest(owner: dns.Name, dnskey: dns.DnskeyData) ![Sha256.digest_length]u8 {
    return testDsDigestWith(Sha256, owner, dnskey);
}

fn testDsDigestWith(comptime Hash: type, owner: dns.Name, dnskey: dns.DnskeyData) ![Hash.digest_length]u8 {
    var wire_buf: [1024]u8 = undefined;
    const name_len = try writeCanonicalNameWire(&wire_buf, owner);
    var pos = name_len;
    mem.writeInt(u16, wire_buf[pos..][0..2], dnskey.flags, .big);
    pos += 2;
    wire_buf[pos] = dnskey.protocol;
    pos += 1;
    wire_buf[pos] = @backingInt(dnskey.algorithm);
    pos += 1;
    @memcpy(wire_buf[pos..][0..dnskey.public_key.len], dnskey.public_key);
    pos += dnskey.public_key.len;
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(wire_buf[0..pos], &digest, .{});
    return digest;
}

const test_dnskey = dns.DnskeyData{
    .flags = 257,
    .protocol = 3,
    .algorithm = .rsasha256,
    .public_key = &.{ 0x03, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD },
};

/// Zone argument for tests that exercise pure range geometry: root makes the
/// qname/owner binding vacuous, so those tests keep testing exactly what they
/// tested before it existed.
const test_root = dns.Name{ .labels = &.{} };

const test_owner = dns.Name{
    .labels = &.{
        @as([]const u8, "example"),
        @as([]const u8, "com"),
    },
};

test "DS hash verification - synthetic" {
    var expected_digest = try testDsDigest(test_owner, test_dnskey);

    const ds = dns.DsData{
        .key_tag = keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &expected_digest,
    };

    try verifyDs(ds, test_dnskey, test_owner);
}

test "DS hash verification - sha1 and sha384 digest types" {
    // verifyDs's three digest arms collapse to one comptime helper; exercise
    // the sha1 and sha384 instantiations (only sha256 was covered above).
    const d1 = try testDsDigestWith(Sha1, test_owner, test_dnskey);
    try verifyDs(.{
        .key_tag = keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha1,
        .digest = &d1,
    }, test_dnskey, test_owner);

    const d384 = try testDsDigestWith(Sha384, test_owner, test_dnskey);
    try verifyDs(.{
        .key_tag = keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha384,
        .digest = &d384,
    }, test_dnskey, test_owner);
}

test "anySupportedDs: unsupported algorithm or digest contributes no path" {
    const zero_digest: [32]u8 = @splat(0);
    const ds_rr = struct {
        fn make(algo: dns.DnssecAlgorithm, digest_type: dns.DigestType) dns.ResourceRecord {
            return .{
                .name = test_owner,
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
}

test "validateDnskeyRrset rejects DNSKEY without RRSIG when DS exists" {
    // RFC 4035 §5.2: stripped RRSIG on DNSKEY must not bypass validation.
    var digest = try testDsDigest(test_owner, test_dnskey);

    const ds = dns.DsData{
        .key_tag = keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };

    // DNSKEY record with NO accompanying RRSIG — this is the attack vector
    const dnskey_records = [_]dns.ResourceRecord{.{
        .name = test_owner,
        .rtype = .dnskey,
        .rclass = .in,
        .ttl = 86400,
        .rdata = .{ .dnskey = test_dnskey },
    }};

    var budget: ValidationBudget = .{};
    try testing.expectError(
        error.InvalidSignature,
        validateDnskeyRrset(&dnskey_records, &.{ds}, test_owner, 1700000000, &budget),
    );
}

test "validateDnskeyRrset refuses more DNSKEYs than the 64-key filter buffer" {
    // A hostile zone can serve >64 DNSKEYs over TCP. Skipping the overflow
    // would let a signature over the first 64 authenticate a set the caller
    // then caches whole — appended forgeries included — so overflow is a
    // hard refusal, not a truncated collect.
    var digest = try testDsDigest(test_owner, test_dnskey);
    const ds = dns.DsData{
        .key_tag = keyTag(test_dnskey),
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
    try testing.expect(keyTag(filler) != ds.key_tag);

    var records: [65]dns.ResourceRecord = undefined;
    for (records[0..64]) |*r| r.* = .{ .name = test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 86400, .rdata = .{ .dnskey = filler } };
    records[64] = .{ .name = test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 86400, .rdata = .{ .dnskey = test_dnskey } };

    var budget: ValidationBudget = .{};
    try testing.expectError(
        error.InvalidKey,
        validateDnskeyRrset(&records, &.{ds}, test_owner, 1700000000, &budget),
    );

    // 64 exactly is still accepted (and rejected on signature grounds, not
    // size) — the boundary is off-by-one sensitive.
    try testing.expectError(
        error.InvalidSignature,
        validateDnskeyRrset(records[0..64], &.{ds}, test_owner, 1700000000, &budget),
    );
}

test "verifyAuthorityProofSigs: oversized owner+type is refused, not truncated" {
    // Honest scope: the old truncating collect ALSO returned .bogus here, so
    // this pins the boundary and the absence of an out-of-bounds write — not a
    // closed hole. The refusal is structural consistency with the other two
    // collects: for the truncated 16 to verify, an attacker would need a valid
    // zone signature over 16 same-owner NSECs, and RFC 4034 §4 puts exactly one
    // NSEC at an owner, so no such signature exists without the zone's key.
    const nsec = dns.NsecData{
        .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
        .type_bit_maps = &.{ 0x00, 0x01, 0x62 },
    };
    var rrs: [17]dns.ResourceRecord = undefined;
    for (&rrs) |*r| r.* = .{
        .name = test_owner,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .nsec = nsec },
    };

    var budget: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityProofSigs(&rrs, &.{}, 1_700_000_000, &budget, null),
    );
    // 16 is within the buffer and fails on the ordinary no-signature path,
    // so the boundary is the size check and not a signature accident.
    var budget2: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityProofSigs(rrs[0..16], &.{}, 1_700_000_000, &budget2, null),
    );
}

test "validateDnskeyRrset: a real signature over 64 keys cannot launder a 65th" {
    // The property the size check exists for, with actual crypto: sign exactly
    // the 64 keys the old truncating collect would have kept, append a forged
    // 65th, and confirm the RRset is refused rather than validated as a
    // prefix. A prefix-verify here would trust every key in the message.
    var recs: [65]dns.ResourceRecord = undefined;
    var pub_bufs: [65][32]u8 = undefined;
    for (&recs, 0..) |*r, i| {
        pub_bufs[i] = @splat(@intCast(i + 1));
        r.* = dnskeyRr(test_owner, .{
            .flags = 256,
            .protocol = 3,
            .algorithm = .ed25519,
            .public_key = &pub_bufs[i],
        });
    }

    var sig_bytes: [64]u8 = undefined;
    var signer_pub: [32]u8 = undefined;
    const signed = try testSignRrset(recs[0..64], .dnskey, test_owner, .ed25519, &sig_bytes, &signer_pub);
    // The signing key must itself be in the RRset and DS-anchored, or the
    // refusal could be blamed on anchoring rather than on size.
    recs[0] = dnskeyRr(test_owner, signed.dnskey);
    var sig2: [64]u8 = undefined;
    const resigned = try testSignRrset(recs[0..64], .dnskey, test_owner, .ed25519, &sig2, &signer_pub);
    recs[0] = dnskeyRr(test_owner, resigned.dnskey);

    var digest = try testDsDigest(test_owner, resigned.dnskey);
    const ds = dns.DsData{
        .key_tag = keyTag(resigned.dnskey),
        .algorithm = .ed25519,
        .digest_type = .sha256,
        .digest = &digest,
    };
    const sig_rr = dns.ResourceRecord{
        .name = test_owner,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .rrsig = resigned.rrsig },
    };

    // Control: the signed 64 plus their RRSIG validate.
    var ok: [65]dns.ResourceRecord = undefined;
    @memcpy(ok[0..64], recs[0..64]);
    ok[64] = sig_rr;
    var budget: ValidationBudget = .{};
    try validateDnskeyRrset(&ok, &.{ds}, test_owner, 1_700_000_000, &budget);

    // The 65th key must not ride in on that signature.
    var laundered: [66]dns.ResourceRecord = undefined;
    @memcpy(laundered[0..65], &recs);
    laundered[65] = sig_rr;
    var budget2: ValidationBudget = .{};
    try testing.expectError(
        error.InvalidKey,
        validateDnskeyRrset(&laundered, &.{ds}, test_owner, 1_700_000_000, &budget2),
    );
}

test "validateDnskeyRrset caps the KeyTrap key×signature cross-product at the budget" {
    // CVE-2023-50387: colliding-tag keys × DNSKEY-covering RRSIGs force an N×M
    // verify cross-product. consumeVerify charges before any crypto, so the walk
    // halts at the ceiling however large N·M grows. Pins that against the walk's
    // next refactor.
    var digest = try testDsDigest(test_owner, test_dnskey);
    const ds = dns.DsData{
        .key_tag = keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };

    // 3 anchored copies of the DS-matching key × 40 tag-matching RRSIGs with
    // unverifiable signatures = 120 candidate attempts; the budget permits 8.
    var records: [43]dns.ResourceRecord = undefined;
    for (records[0..3]) |*r| r.* = .{ .name = test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 86400, .rdata = .{ .dnskey = test_dnskey } };
    for (records[3..43]) |*r| r.* = .{
        .name = test_owner,
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
            .signer_name = test_owner,
            .signature = &.{ 0xDE, 0xAD, 0xBE, 0xEF },
        } },
    };

    const cap: u32 = 8;
    var budget: ValidationBudget = .{ .max_sig_verify = cap };
    try testing.expectError(
        error.ValidationBudgetExhausted,
        validateDnskeyRrset(&records, &.{ds}, test_owner, 1700000000, &budget),
    );
    // cap draws succeed, the next trips exhaustion → spent == cap+1: proof the
    // walk stopped at the ceiling and never touched all 120 attempts.
    try testing.expectEqual(cap + 1, budget.sig_verify_spent.load(.monotonic));
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
    var b: ValidationBudget = .{};
    try testing.expect(validateRrset(&records, owner, .ds, &.{}, 1700000000, &b) == null);
}

test "DS hash verification - wrong digest fails" {
    const dnskey = dns.DnskeyData{
        .flags = 257,
        .protocol = 3,
        .algorithm = .rsasha256,
        .public_key = &.{ 0x03, 0x01, 0x00, 0x01 },
    };

    const owner = dns.Name{
        .labels = &.{
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };

    var bad_digest: [32]u8 = undefined;
    @memset(&bad_digest, 0xFF);

    const ds = dns.DsData{
        .key_tag = keyTag(dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &bad_digest,
    };

    try testing.expectError(error.InvalidSignature, verifyDs(ds, dnskey, owner));
}

test "buildSignedData produces correct header" {
    const signer_name = dns.Name{
        .labels = &.{
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };
    const rrsig = dns.RrsigData{
        .type_covered = .a,
        .algorithm = .ecdsap256sha256,
        .labels = 3,
        .original_ttl = 300,
        .sig_expiration = 1700000000,
        .sig_inception = 1699000000,
        .key_tag = 12345,
        .signer_name = signer_name,
        .signature = &.{},
    };

    const owner_name = dns.Name{
        .labels = &.{
            @as([]const u8, "www"),
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };

    const rrset = [_]dns.ResourceRecord{.{
        .name = owner_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 200, // different from original_ttl — signed data should use original_ttl
        .rdata = .{ .a = .{ 93, 184, 216, 34 } },
    }};

    var buf: [4096]u8 = undefined;
    const signed = try buildSignedData(&buf, rrsig, &rrset);

    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, signed[0..2], .big)); // type_covered = A = 1
    try testing.expectEqual(@as(u8, 13), signed[2]); // algorithm
    try testing.expectEqual(@as(u8, 3), signed[3]); // labels
    try testing.expectEqual(@as(u32, 300), mem.readInt(u32, signed[4..8], .big)); // original_ttl
    try testing.expectEqual(@as(u32, 1700000000), mem.readInt(u32, signed[8..12], .big)); // expiration
    try testing.expectEqual(@as(u32, 1699000000), mem.readInt(u32, signed[12..16], .big)); // inception
    try testing.expectEqual(@as(u16, 12345), mem.readInt(u16, signed[16..18], .big)); // key_tag

    // After the header comes the canonical signer name
    try testing.expectEqualSlices(u8, "\x07example\x03com\x00", signed[18..31]);

    // Then the RR: canonical owner name + type(2) + class(2) + original_ttl(4) + rdlength(2) + rdata
    const rr_start = 31;
    // \x03www\x07example\x03com\x00 = 4+8+4+1 = 17 bytes
    try testing.expectEqualSlices(u8, "\x03www\x07example\x03com\x00", signed[rr_start..][0..17]);
    const after_name = rr_start + 17;
    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, signed[after_name..][0..2], .big)); // type A
    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, signed[after_name + 2 ..][0..2], .big)); // class IN
    try testing.expectEqual(@as(u32, 300), mem.readInt(u32, signed[after_name + 4 ..][0..4], .big)); // original_ttl (not 200)
    try testing.expectEqual(@as(u16, 4), mem.readInt(u16, signed[after_name + 8 ..][0..2], .big)); // rdlength
    try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, signed[after_name + 10 ..][0..4]); // rdata
}

test "buildSignedData reconstructs wildcard owner name" {
    // RFC 4035 §5.3.2: when rrsig.labels < owner label count, reconstruct wildcard
    const signer_name = dns.Name{
        .labels = &.{
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };
    const rrsig = dns.RrsigData{
        .type_covered = .a,
        .algorithm = .ecdsap256sha256,
        .labels = 2, // wildcard: fewer than owner's 3 labels
        .original_ttl = 300,
        .sig_expiration = 1700000000,
        .sig_inception = 1699000000,
        .key_tag = 12345,
        .signer_name = signer_name,
        .signature = &.{},
    };

    // Owner has 3 labels but RRSIG says 2 — wildcard expansion
    const owner_name = dns.Name{
        .labels = &.{
            @as([]const u8, "foo"),
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };

    const rrset = [_]dns.ResourceRecord{.{
        .name = owner_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 200,
        .rdata = .{ .a = .{ 93, 184, 216, 34 } },
    }};

    var buf: [4096]u8 = undefined;
    const signed = try buildSignedData(&buf, rrsig, &rrset);

    // After the RRSIG header (18 bytes) + signer name (13 bytes) = offset 31
    const rr_start = 31;
    // Owner in signed data must be *.example.com = \x01*\x07example\x03com\x00 (16 bytes)
    // NOT \x03foo\x07example\x03com\x00 (17 bytes)
    const expected_wc_owner = "\x01*\x07example\x03com\x00";
    try testing.expectEqualSlices(u8, expected_wc_owner, signed[rr_start..][0..expected_wc_owner.len]);
}

test "ECDSA P-256 signature verification" {
    const key_pair = EcdsaP256.KeyPair.generate(testing.io);
    const pub_bytes = key_pair.public_key.toUncompressedSec1();
    // DNSSEC key is raw 64-byte x||y (without 0x04 prefix)
    const dnssec_key = pub_bytes[1..65];

    const msg = "test DNSSEC signed data";
    const sig = try key_pair.sign(msg, null);
    const sig_bytes = sig.toBytes();

    try verifyEcdsa(EcdsaP256, 32, &sig_bytes, msg, dnssec_key);

    try testing.expectError(error.InvalidSignature, verifyEcdsa(EcdsaP256, 32, &sig_bytes, "wrong data", dnssec_key));
}

test "Ed25519 signature verification" {
    const key_pair = Ed25519.KeyPair.generate(testing.io);
    const pub_bytes = key_pair.public_key.toBytes();

    const msg = "test Ed25519 DNSSEC data";
    const sig = try key_pair.sign(msg, null);
    const sig_bytes = sig.toBytes();

    try verifyEd25519(&sig_bytes, msg, &pub_bytes);
    try testing.expectError(error.InvalidSignature, verifyEd25519(&sig_bytes, "tampered", &pub_bytes));
}

test "invalid key sizes are rejected" {
    const msg = "test";
    const sig64: [64]u8 = @splat(0);
    const sig96: [96]u8 = @splat(0);

    // ECDSA P-256: key must be 64 bytes
    try testing.expectError(error.InvalidKey, verifyEcdsa(EcdsaP256, 32, &sig64, msg, &.{ 0x01, 0x02 }));
    // ECDSA P-384: key must be 96 bytes
    try testing.expectError(error.InvalidKey, verifyEcdsa(EcdsaP384, 48, &sig96, msg, &.{ 0x01, 0x02 }));
    // Ed25519: key must be 32 bytes
    try testing.expectError(error.InvalidKey, verifyEd25519(&sig64, msg, &.{ 0x01, 0x02 }));
}

test "verifyRsa accepts RFC 3110 keys with exponent > 4 bytes (xelerance.com KSK shape)" {
    // KSK 26346 uses e = 2^32 + 1 (5 bytes). RFC 3110: 1-byte exp_len || exp || mod.
    // Synthetic 1024-bit modulus: any odd number with high bit set, so n.bits() == 1024.
    var key_data = [_]u8{ 5, 0x01, 0x00, 0x00, 0x00, 0x01 } ++ @as([128]u8, @splat(0x55));
    key_data[6] = 0x80;
    const signature: [128]u8 = @splat(0xaa);
    try testing.expectError(error.InvalidSignature, verifyRsa(&signature, "x", &key_data, Sha1));
    try testing.expectError(error.InvalidSignature, verifyRsa(&signature, "x", &key_data, Sha256));
}

test "verifyRsa rejects leading-zero-padded e=1 exponent (forgery defense)" {
    // Without the strip, [00 00 00 01] reads as e=1 and any sig == EM verifies.
    var k1 = [_]u8{ 4, 0x00, 0x00, 0x00, 0x01 } ++ @as([128]u8, @splat(0x55));
    k1[5] = 0x80;
    const sig: [128]u8 = @splat(0);
    try testing.expectError(error.InvalidKey, verifyRsa(&sig, "x", &k1, Sha256));

    // 2-byte exp_len encoding with 8-byte padded exponent.
    var k2 = [_]u8{ 0, 0, 8 } ++ @as([7]u8, @splat(0)) ++ [_]u8{0x01} ++ @as([128]u8, @splat(0x55));
    k2[11] = 0x80;
    try testing.expectError(error.InvalidKey, verifyRsa(&sig, "x", &k2, Sha256));
}

test "pkcs1v15Encode produces RFC 8017 §9.2 byte layout (per hash)" {
    // EM = 00 || 01 || PS (0xff..) || 00 || T (DER) || H. Pinning the bytes
    // per hash defends the OID-typo class — a bad byte in a DER prefix would
    // silently SERVFAIL every zone signed with that algorithm.
    const Case = struct {
        Hash: type,
        digest_len: usize,
        der: []const u8,
        hash_abc: []const u8,
    };
    inline for ([_]Case{
        .{
            .Hash = Sha1,
            .digest_len = 20,
            .der = &.{
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
            },
            // SHA-1("abc") — RFC 3174 Appendix A.
            .hash_abc = &.{
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
                0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
                0x9c, 0xd0, 0xd8, 0x9d,
            },
        },
        .{
            .Hash = Sha256,
            .digest_len = 32,
            .der = &.{
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            },
            // NIST SHA-256("abc").
            .hash_abc = &.{
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
            },
        },
        .{
            .Hash = Sha512,
            .digest_len = 64,
            .der = &.{
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                0x00, 0x04, 0x40,
            },
            // NIST SHA-512("abc").
            .hash_abc = &.{
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
                0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
                0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
                0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
                0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
                0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
                0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
            },
        },
    }) |c| {
        var em: [128]u8 = undefined;
        pkcs1v15Encode(&em, c.Hash, "abc");
        try testing.expectEqual(@as(u8, 0x00), em[0]);
        try testing.expectEqual(@as(u8, 0x01), em[1]);
        const sep = 128 - c.digest_len - c.der.len - 1;
        for (em[2..sep]) |b| try testing.expectEqual(@as(u8, 0xff), b);
        try testing.expectEqual(@as(u8, 0x00), em[sep]);
        try testing.expectEqualSlices(u8, c.der, em[sep + 1 .. sep + 1 + c.der.len]);
        try testing.expectEqualSlices(u8, c.hash_abc, em[128 - c.digest_len ..]);
    }
}

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

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, classifyDelegation(&authorities, child_zone, &b));
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

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, classifyDelegation(&authorities, child_zone, &b));
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

    // No DS and no NSEC/NSEC3 proof — indeterminate, fails closed to .secure
    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, classifyDelegation(&authorities, child_zone, &b));
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
        var b: ValidationBudget = .{};
        try testing.expectEqual(SecurityStatus.secure, classifyDelegation(&authorities, child_zone, &b));
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

    try testing.expect(nsecProvesTypeNonexistence(name, nsec_data, name, .aaaa));
    try testing.expect(!nsecProvesTypeNonexistence(name, nsec_data, name, .a));
    const other = dns.Name{ .labels = &.{@as([]const u8, "other")} };
    try testing.expect(!nsecProvesTypeNonexistence(name, nsec_data, other, .aaaa));
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
    // A query for AAAA must NOT be proved nonexistent — the CNAME would chain it.
    try testing.expect(!nsecProvesTypeNonexistence(name, cname_present, name, .aaaa));
    // A query for CNAME itself: the bit IS set, so proof fails (correctly).
    try testing.expect(!nsecProvesTypeNonexistence(name, cname_present, name, .cname));

    // Bitmap with TXT only — no CNAME, no AAAA.
    const cname_absent = dns.NsecData{
        .next_domain_name = dns.Name{ .labels = &.{@as([]const u8, "next")} },
        .type_bit_maps = &[_]u8{ 0x00, 0x03, 0x00, 0x00, 0x80 },
    };
    try testing.expect(nsecProvesTypeNonexistence(name, cname_absent, name, .aaaa));
    try testing.expect(nsecProvesTypeNonexistence(name, cname_absent, name, .cname));
}

test "NSEC3 hash computation - RFC 5155 Appendix B" {
    // RFC 5155 Appendix B test vectors use:
    // Hash algorithm: 1 (SHA-1), iterations: 12, salt: aabbccdd
    // example -> 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
    // The known-answer assertion against that vector lives in the
    // base32hex roundtrip test below; here we check shape and determinism.
    const name = dns.Name{
        .labels = &.{@as([]const u8, "example")},
    };
    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const hash = try nsec3Hash(name, &salt, 12);
    try testing.expectEqual(@as(usize, 20), hash.len);

    const hash2 = try nsec3Hash(name, &salt, 12);
    try testing.expectEqualSlices(u8, &hash, &hash2);

    const other = dns.Name{
        .labels = &.{@as([]const u8, "other")},
    };
    const hash3 = try nsec3Hash(other, &salt, 12);
    try testing.expect(!mem.eql(u8, &hash, &hash3));
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

    var b: ValidationBudget = .{};
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

    var b: ValidationBudget = .{};
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
    var b: ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
}

test "validateNegativeProof NSEC NXDOMAIN without wildcard denial" {
    const alpha = dns.Name{ .labels = &.{ "alpha", "example", "com" } };
    const gamma = dns.Name{ .labels = &.{ "gamma", "example", "com" } };

    const authorities = [_]dns.ResourceRecord{nsecRr(alpha, gamma)};

    const beta = dns.Name{ .labels = &.{ "beta", "example", "com" } };
    var b: ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, status);
}

fn nsecRr(owner: dns.Name, next: dns.Name) dns.ResourceRecord {
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
    var b: ValidationBudget = .{};
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
    var b: ValidationBudget = .{};
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
    var b: ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, qname, .a, true, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, status);
}

test "validateNegativeProof NSEC NODATA at empty non-terminal (live ip6.arpa shape)" {
    // Captured 2026-07-24 from b.ip6-servers.arpa: `A 6.2.ip6.arpa` (a
    // qname-minimization step of a 2600::/12 PTR) answers NOERROR/NODATA
    // with a single NSEC 1.4.2.ip6.arpa -> 0.6.2.ip6.arpa. The next name
    // descends below qname ⇒ qname is an ENT ⇒ complete proof. Regression:
    // this SERVFAILed as "incomplete proof" pre-fix.
    const owner = dns.Name{ .labels = &.{ "1", "4", "2", "ip6", "arpa" } };
    const next = dns.Name{ .labels = &.{ "0", "6", "2", "ip6", "arpa" } };
    const qname = dns.Name{ .labels = &.{ "6", "2", "ip6", "arpa" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(owner, next)};
    var b: ValidationBudget = .{};
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
    var b: ValidationBudget = .{};
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
    var b: ValidationBudget = .{};
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

test "validateNegativeProof NSEC NXDOMAIN apex-NSEC shape (clamped CE)" {
    // IANA ip6.arpa shape under NXDOMAIN rcode: next contains qname as a
    // strict suffix → commonSuffix saturates → clamp must engage.
    const apex = dns.Name{ .labels = &.{ "ip6", "arpa" } };
    const next = dns.Name{ .labels = &.{ "3", "0", "0", "1", "0", "0", "2", "ip6", "arpa" } };
    const qname = dns.Name{ .labels = &.{ "2", "ip6", "arpa" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(apex, next)};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
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

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .https, false, test_root, &b));
    // Same records under NXDOMAIN: *.CE exists, contradiction.
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .https, true, test_root, &b));
}

test "validateNegativeProof NSEC NODATA NXDOMAIN-shape under NOERROR (RFC 4035 §5.4)" {
    // IANA ip6.arpa shape under NOERROR. Single apex NSEC covers qname AND
    // *.CE (canonical: ip6.arpa < *.ip6.arpa < 2.ip6.arpa < 3.0.0.1.0.0.2.ip6.arpa).
    const apex = dns.Name{ .labels = &.{ "ip6", "arpa" } };
    const next = dns.Name{ .labels = &.{ "3", "0", "0", "1", "0", "0", "2", "ip6", "arpa" } };
    const qname = dns.Name{ .labels = &.{ "2", "ip6", "arpa" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(apex, next)};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
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

    var b: ValidationBudget = .{};
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

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
}

test "validateNegativeProof NSEC NODATA owner-match with qtype in bitmap is .bogus" {
    const name = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "com" } };
    const bitmap = [_]u8{ 0x00, 0x04, 0x62, 0x00, 0x00, 0x08 }; // A+NS+SOA+AAAA
    const authorities = [_]dns.ResourceRecord{nsecRrWithBitmap(name, next, &bitmap)};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, name, .aaaa, false, test_root, &b));
}

test "validateNegativeProof NSEC NODATA covering but no wildcard proof is .unchecked" {
    // Covering range starts at aaa.example.com, so *.example.com sorts before
    // the range and isn't covered. No *.CE NSEC either.
    const aaa = dns.Name{ .labels = &.{ "aaa", "example", "com" } };
    const zzz = dns.Name{ .labels = &.{ "zzz", "example", "com" } };
    const qname = dns.Name{ .labels = &.{ "missing", "example", "com" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(aaa, zzz)};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
}

/// Build an NSEC3 owner name by base32hex-encoding a hash and appending zone labels.
/// Returns the label slices and Name referencing them. Caller must keep returned
/// struct alive for as long as the Name is used.
fn makeNsec3OwnerName(
    hash: [Sha1.digest_length]u8,
    zone_labels: []const []const u8,
    encode_buf: []u8,
    labels_buf: [][]const u8,
) dns.Name {
    const encoded = dns.base32HexEncode(encode_buf, &hash);
    labels_buf[0] = encoded;
    for (zone_labels, 0..) |zl, i| {
        labels_buf[1 + i] = zl;
    }
    return dns.Name{ .labels = labels_buf[0 .. 1 + zone_labels.len] };
}

const Nsec3OwnerBufs = struct {
    enc: [32]u8 = undefined,
    labels: [4][]const u8 = undefined,
};

fn makeNsec3Rr(
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
    low: *[Sha1.digest_length]u8,
    high: *[Sha1.digest_length]u8,
) dns.ResourceRecord {
    low.* = target_hash;
    high.* = target_hash;
    low[19] -|= 1;
    high[19] +|= 1;
    const owner = makeNsec3OwnerName(low.*, zone_labels, &bufs.enc, &bufs.labels);
    return makeNsec3Rr(owner, salt, high, &.{});
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

test "base32hex case insensitivity" {
    var buf1: [20]u8 = undefined;
    var buf2: [20]u8 = undefined;
    const n1 = try dns.base32HexDecode(&buf1, "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM");
    const n2 = try dns.base32HexDecode(&buf2, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");
    try testing.expectEqual(n1, n2);
    try testing.expectEqualSlices(u8, buf1[0..n1], buf2[0..n2]);
}

test "base32hex invalid characters" {
    var buf: [20]u8 = undefined;
    try testing.expectError(error.InvalidBase32, dns.base32HexDecode(&buf, "INVALID!CHARS@@@@@@@@@@@@@@@@@@@!"));
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

test "NSEC3 unknown hash algorithm yields .insecure (RFC 6840 §5.11)" {
    // Single NSEC3 record using a hash algorithm we don't support.
    // validateNegativeProof must not return .bogus — that would SERVFAIL
    // legitimate zones during a future SHA3 transition.
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

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&authorities, qname, .aaaa, false, test_root, &b));
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
    const owner_name = makeNsec3OwnerName(hash, zone_labels, &bufs.enc, &bufs.labels);

    // Bitmap: A(bit1=0x40) + NS(bit2=0x20) + SOA(bit6=0x02) = 0x62
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x62 })};

    var b: ValidationBudget = .{};
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
    const cut_owner = makeNsec3OwnerName(cut_hash, zone_labels, &bufs.enc, &bufs.labels);
    const parent_side = [_]u8{ 0x00, 0x01, 0x20 }; // NS only

    // (a) NODATA at the cut for a non-DS type: the parent's bitmap says
    //     nothing about what the child holds.
    var b: ValidationBudget = .{};
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
    const owner = makeNsec3OwnerName(hash, &.{ "example", "com" }, &bufs.enc, &bufs.labels);
    // A NS SOA RRSIG NSEC DNSKEY — no DS.
    const child_apex = [_]u8{ 0x00, 0x07, 0x62, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80 };

    var b: ValidationBudget = .{};
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
    const owner_name = makeNsec3OwnerName(hash, &.{@as([]const u8, "com")}, &bufs.enc, &bufs.labels);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x04 })};

    var b: ValidationBudget = .{};
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
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1.enc, &bufs1.labels);

    var bufs2: Nsec3OwnerBufs = .{};
    var nc_low: [20]u8 = undefined;
    var nc_high: [20]u8 = undefined;
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2, &nc_low, &nc_high);

    var bufs3: Nsec3OwnerBufs = .{};
    var wc_low: [20]u8 = undefined;
    var wc_high: [20]u8 = undefined;
    const wc_rr = makeCoveringNsec3(try nsec3Hash(wc_name, salt, 0), zone_labels, salt, &bufs3, &wc_low, &wc_high);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        wc_rr,
    };

    var b: ValidationBudget = .{};
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
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1.enc, &bufs1.labels);

    var bufs2: Nsec3OwnerBufs = .{};
    var nc_low: [20]u8 = undefined;
    var nc_high: [20]u8 = undefined;
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2, &nc_low, &nc_high);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &.{}),
        nc_rr,
    };

    var b: ValidationBudget = .{};
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
    nc_low: [Sha1.digest_length]u8 = undefined,
    nc_high: [Sha1.digest_length]u8 = undefined,
    rrs: [2]dns.ResourceRecord = undefined,

    /// `opt_out = false` makes the coverer a plain name-denial, which is a
    /// *contradiction* under NOERROR rather than a gap.
    fn init(self: *@This(), qname: dns.Name, opt_out: bool) !void {
        const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
        const salt: []const u8 = &.{};
        const ce = dns.Name{ .labels = zone_labels };
        const ce_hash = try nsec3Hash(ce, salt, 0);
        const ce_owner = makeNsec3OwnerName(
            ce_hash,
            zone_labels,
            &self.ce_bufs.enc,
            &self.ce_bufs.labels,
        );
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
            &self.nc_low,
            &self.nc_high,
        );
        self.rrs[1].rdata.nsec3.type_bit_maps = &com_delegation_bitmap;
        self.rrs[1].rdata.nsec3.flags = if (opt_out) nsec3_opt_out else 0;
    }
};

test "NSEC3 Opt-Out proves no DS, without AD (RFC 5155 §8.6 / §9.2)" {
    // The shared path demanded §8.7's wildcard step → SERVFAIL for every child
    // of every Opt-Out TLD.
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var p: OptOutDsProof = .{};
    try p.init(qname, true);
    var b: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.insecure,
        validateNegativeProof(&p.rrs, qname, .ds, false, test_root, &b),
    );
}

test "NSEC3 DS NODATA needs the Opt-Out flag (RFC 5155 §8.6)" {
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var p: OptOutDsProof = .{};
    try p.init(qname, false);
    var b: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        validateNegativeProof(&p.rrs, qname, .ds, false, test_root, &b),
    );
}

test "NSEC3 Opt-Out authenticates nothing but DS (RFC 5155 §8.6)" {
    // DS-only: for any other qtype the wildcard step must still be required, or
    // Opt-Out's "may exist as an insecure delegation" launders into a NODATA
    // proof for arbitrary types.
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var p: OptOutDsProof = .{};
    try p.init(qname, true);
    var b: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&p.rrs, qname, .a, false, test_root, &b),
    );
    try testing.expectEqual(
        SecurityStatus.unchecked,
        validateNegativeProof(&p.rrs, qname, .ds, true, test_root, &b),
    );
}

test "NSEC3 reserved Flag bits make a record invisible (RFC 5155 §8.2)" {
    const qname = dns.Name{ .labels = &.{ "amazon", "com" } };
    var b: ValidationBudget = .{};
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
    var b: ValidationBudget = .{};
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
    nc_low: [Sha1.digest_length]u8 = undefined,
    nc_high: [Sha1.digest_length]u8 = undefined,
    wc_low: [Sha1.digest_length]u8 = undefined,
    wc_high: [Sha1.digest_length]u8 = undefined,
    rrs: [3]dns.ResourceRecord = undefined,

    fn init(self: *@This(), qname: dns.Name, nc_opt_out: bool) !void {
        const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
        const salt: []const u8 = &.{};
        const ce = dns.Name{ .labels = zone_labels };
        const ce_hash = try nsec3Hash(ce, salt, 0);
        const ce_owner = makeNsec3OwnerName(ce_hash, zone_labels, &self.ce_bufs.enc, &self.ce_bufs.labels);
        self.ce_next = ce_hash;
        self.ce_next[Sha1.digest_length - 1] +|= 1;
        self.rrs[0] = makeNsec3Rr(ce_owner, salt, &self.ce_next, &com_apex_bitmap);
        self.rrs[0].rdata.nsec3.flags = nsec3_opt_out;

        self.rrs[1] = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &self.nc_bufs, &self.nc_low, &self.nc_high);
        self.rrs[1].rdata.nsec3.type_bit_maps = &com_delegation_bitmap;
        self.rrs[1].rdata.nsec3.flags = if (nc_opt_out) nsec3_opt_out else 0;

        var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
        const wildcard = dns.makeWildcardName(&wc_labels_buf, ce).?;
        self.rrs[2] = makeCoveringNsec3(try nsec3Hash(wildcard, salt, 0), zone_labels, salt, &self.wc_bufs, &self.wc_low, &self.wc_high);
    }
};

test "NSEC3 Opt-Out NXDOMAIN must not set AD (RFC 5155 §9.2)" {
    // hark returned `.secure`, so every NXDOMAIN under com, net and org came
    // back AD=1 and was cached that way.
    const qname = dns.Name{ .labels = &.{ "victim", "com" } };
    var b: ValidationBudget = .{};
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

test "NSEC3 Opt-Out NODATA-by-CE-proof must not set AD (RFC 5155 §9.2)" {
    // Same records under NOERROR — the §8.4-shape path, which shares the
    // wildcard step. Unbound's match: `val_nsec3.c:1386`.
    const qname = dns.Name{ .labels = &.{ "victim", "com" } };
    var b: ValidationBudget = .{};
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
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1.enc, &bufs1.labels);
    var bufs2: Nsec3OwnerBufs = .{};
    var nc_low: [20]u8 = undefined;
    var nc_high: [20]u8 = undefined;
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2, &nc_low, &nc_high);
    // *.CE NSEC3 owner-match with bitmap = A(1) only; HTTPS(65) and CNAME(5) absent.
    var bufs3: Nsec3OwnerBufs = .{};
    const wc_owner = makeNsec3OwnerName(try nsec3Hash(wc_name, salt, 0), zone_labels, &bufs3.enc, &bufs3.labels);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        makeNsec3Rr(wc_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
    };

    var b: ValidationBudget = .{};
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
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1.enc, &bufs1.labels);
    var bufs2: Nsec3OwnerBufs = .{};
    var nc_low: [20]u8 = undefined;
    var nc_high: [20]u8 = undefined;
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2, &nc_low, &nc_high);
    var bufs3: Nsec3OwnerBufs = .{};
    var wc_low: [20]u8 = undefined;
    var wc_high: [20]u8 = undefined;
    const wc_rr = makeCoveringNsec3(try nsec3Hash(wc_name, salt, 0), zone_labels, salt, &bufs3, &wc_low, &wc_high);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        wc_rr,
    };

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));
}

test "NSEC3 NXDOMAIN wildcard-match with qtype present is .bogus" {
    // Tightened from prior accept-any-wildcard-match: bitmap claiming the
    // qtype is present at *.CE means the answer should have been wildcard
    // expansion, not NXDOMAIN.
    const qname = dns.Name{ .labels = &.{ "missing", "example", "com" } };
    const ce_name = dns.Name{ .labels = &.{ "example", "com" } };
    const wc_name = dns.Name{ .labels = &.{ "*", "example", "com" } };
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1.enc, &bufs1.labels);
    var bufs2: Nsec3OwnerBufs = .{};
    var nc_low: [20]u8 = undefined;
    var nc_high: [20]u8 = undefined;
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2, &nc_low, &nc_high);
    var bufs3: Nsec3OwnerBufs = .{};
    const wc_owner = makeNsec3OwnerName(try nsec3Hash(wc_name, salt, 0), zone_labels, &bufs3.enc, &bufs3.labels);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        makeNsec3Rr(wc_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
    };

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

test "NSEC3 NXDOMAIN wildcard-match with CNAME present is .bogus" {
    // The wildcard's bitmap asserting a CNAME means the answer should have
    // been wildcard CNAME expansion, not NXDOMAIN.
    const qname = dns.Name{ .labels = &.{ "missing", "example", "com" } };
    const ce_name = dns.Name{ .labels = &.{ "example", "com" } };
    const wc_name = dns.Name{ .labels = &.{ "*", "example", "com" } };
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const salt: []const u8 = &.{};

    var bufs1: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce_name, salt, 0), zone_labels, &bufs1.enc, &bufs1.labels);
    var bufs2: Nsec3OwnerBufs = .{};
    var nc_low: [20]u8 = undefined;
    var nc_high: [20]u8 = undefined;
    const nc_rr = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs2, &nc_low, &nc_high);
    var bufs3: Nsec3OwnerBufs = .{};
    const wc_owner = makeNsec3OwnerName(try nsec3Hash(wc_name, salt, 0), zone_labels, &bufs3.enc, &bufs3.labels);

    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        makeNsec3Rr(wc_owner, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x04 }),
    };

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

test "classifyDelegation NSEC3 match" {
    // NSEC3 owner matches hash(child_zone), DS absent → insecure
    const child_zone = dns.Name{
        .labels = &.{ @as([]const u8, "unsigned"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const zone_labels: []const []const u8 = &.{ @as([]const u8, "example"), @as([]const u8, "com") };
    const salt: []const u8 = &.{};

    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(try nsec3Hash(child_zone, salt, 0), zone_labels, &bufs.enc, &bufs.labels);

    // NS only (no DS)
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0xFF)), &[_]u8{ 0x00, 0x01, 0x20 })};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, classifyDelegation(&authorities, child_zone, &b));
}

test "classifyDelegation NSEC3 owned by a foreign zone proves nothing" {
    const child_zone = dns.Name{ .labels = &.{ "bank", "com" } };
    const salt: []const u8 = &.{ 0xAA, 0xBB };
    var lo = try nsec3Hash(child_zone, salt, 0);
    lo[19] -%= 1;
    var hi = lo;
    hi[19] +%= 2;

    var b: ValidationBudget = .{};
    for ([_]struct { []const []const u8, SecurityStatus }{
        .{ &.{"com"}, .insecure },
        .{ &.{ "evil", "com" }, .secure },
        .{ &.{ "bank", "com" }, .secure },
    }) |case| {
        var bufs: Nsec3OwnerBufs = .{};
        var rr = makeNsec3Rr(makeNsec3OwnerName(lo, case[0], &bufs.enc, &bufs.labels), salt, &hi, &.{});
        rr.rdata.nsec3.flags = nsec3_opt_out;
        try testing.expectEqual(case[1], classifyDelegation(&.{rr}, child_zone, &b));
    }
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
    const owner_name = makeNsec3OwnerName(try nsec3Hash(other_name, salt, 0), zone_labels, &bufs.enc, &bufs.labels);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0)), &[_]u8{ 0x00, 0x01, 0x20 })};

    // NSEC3 doesn't cover the child zone — indeterminate, fails closed to .secure
    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, classifyDelegation(&authorities, child_zone, &b));
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
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_labels, &bufs.enc, &bufs.labels);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0x43)), &.{})};

    var b: ValidationBudget = .{ .max_nsec3_hash = 32 };
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
}

test "NSEC3 high-iteration returns insecure (RFC 9276 §3.2)" {
    // Iterations > 50 → .insecure: validator opts out of expensive proof rather
    // than burning CPU. classifyDelegation and validateNegativeProof both apply
    // this policy uniformly.
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "www"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const salt: []const u8 = &.{};
    var bufs: Nsec3OwnerBufs = .{};
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_labels, &bufs.enc, &bufs.labels);

    const authorities = [_]dns.ResourceRecord{.{
        .name = owner_name,
        .rtype = .nsec3,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .nsec3 = .{
            .hash_algorithm = .sha1,
            .flags = 0,
            .iterations = 200,
            .salt = salt,
            .next_hashed_owner = &@as([20]u8, @splat(0x43)),
            .type_bit_maps = &.{},
        } },
    }};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&authorities, qname, .a, true, test_root, &b));
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&authorities, qname, .a, false, test_root, &b));

    const child_zone = dns.Name{ .labels = zone_labels };
    try testing.expectEqual(SecurityStatus.insecure, classifyDelegation(&authorities, child_zone, &b));
}

test "classifyDelegation salt-cache defeat exhausts NSEC3 budget" {
    // Adversarial, within the per-proof record cap (≤8): NSEC3 records with
    // unique salts each force a fresh nsec3Hash because the single-slot salt
    // cache misses on every transition. With the per-resolution budget,
    // exhausting it fails CLOSED to .bogus once the cap is hit.
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
        const owner = makeNsec3OwnerName(@as([20]u8, @splat(@as(u8, @intCast(i ^ 0xA5)))), zone_labels, &bufs[i].enc, &bufs[i].labels);
        rrs[i] = .{
            .name = owner,
            .rtype = .nsec3,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .nsec3 = .{
                .hash_algorithm = .sha1,
                .flags = 0,
                .iterations = max_nsec3_iterations,
                .salt = &unique_salts[i],
                .next_hashed_owner = &next_owner,
                .type_bit_maps = &.{},
            } },
        };
    }

    var b: ValidationBudget = .{ .max_nsec3_hash = 4 };
    try testing.expectEqual(SecurityStatus.bogus, classifyDelegation(&rrs, child_zone, &b));
    try testing.expect(b.nsec3_hash_spent.load(.monotonic) >= 4);
}

test "refuses NSEC3 floods before hashing (Knot >8-record cap)" {
    // >8 NSEC3 records is the flood shape: refused .bogus before any hashing, on
    // both paths, so the hash budget is untouched (spent == 0).
    const N: usize = max_nsec3_records_per_proof + 1;
    const zone_labels: []const []const u8 = &.{ "example", "com" };
    const salt: []const u8 = &.{};
    const next_owner: [20]u8 = @splat(0xFF);

    var bufs: [N]Nsec3OwnerBufs = undefined;
    var rrs: [N]dns.ResourceRecord = undefined;
    for (0..N) |i| {
        bufs[i] = .{};
        const owner = makeNsec3OwnerName(@as([20]u8, @splat(@as(u8, @intCast(i ^ 0xA5)))), zone_labels, &bufs[i].enc, &bufs[i].labels);
        rrs[i] = makeNsec3Rr(owner, salt, &next_owner, &.{});
    }

    var b: ValidationBudget = .{};
    const child_zone = dns.Name{ .labels = &.{ "victim", "example", "com" } };
    try testing.expectEqual(SecurityStatus.bogus, classifyDelegation(&rrs, child_zone, &b));
    const qname = dns.Name{ .labels = &.{ "absent", "example", "com" } };
    try testing.expectEqual(SecurityStatus.bogus, validateNegativeProof(&rrs, qname, .a, true, test_root, &b));
    try testing.expectEqual(@as(u32, 0), b.nsec3_hash_spent.load(.monotonic));
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
    const owner_name = makeNsec3OwnerName(@as([20]u8, @splat(0x42)), zone_labels, &bufs.enc, &bufs.labels);
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &@as([20]u8, @splat(0x43)), &.{})};

    var b: ValidationBudget = .{ .max_nsec3_hash = 2 };
    const first = validateNegativeProof(&authorities, qname, .a, false, test_root, &b);
    try testing.expectEqual(SecurityStatus.unchecked, first);
    try testing.expectEqual(@as(u32, 2), b.nsec3_hash_spent.load(.monotonic));
    const second = validateNegativeProof(&authorities, qname, .a, false, test_root, &b);
    try testing.expectEqual(SecurityStatus.bogus, second);
}

// Shared fixture for the verifyRrsig time-window tests. Empty key/signature
// means the ECDSA path always returns InvalidSignature — anything before
// it (the time check) is what gates the assertion.
const test_window_rrsig = dns.RrsigData{
    .type_covered = .a,
    .algorithm = .ecdsap256sha256,
    .labels = 2,
    .original_ttl = 300,
    .sig_expiration = 1700000000,
    .sig_inception = 1699000000,
    .key_tag = 12345,
    .signer_name = .{ .labels = &.{ "example", "com" } },
    .signature = &.{},
};
const test_window_dnskey = dns.DnskeyData{
    .flags = 256,
    .protocol = 3,
    .algorithm = .ecdsap256sha256,
    .public_key = &.{},
};
const test_window_empty_rrset: []const dns.ResourceRecord = &.{};

test "verifyRrsig rejects expired signature" {
    var budget: ValidationBudget = .{};
    // Expiration tolerance is 0 — any time strictly past expiration rejects.
    try testing.expectError(error.SignatureExpired, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, 1700000000 + 1, &budget));
}

test "verifyRrsig rejects not-yet-valid signature" {
    var budget: ValidationBudget = .{};
    try testing.expectError(error.SignatureExpired, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, 1699000000 - inception_skew_tolerance - 1, &budget));
}

test "verifyRrsig tolerates clock skew within window" {
    var budget: ValidationBudget = .{};
    inline for (.{
        1700000000, // at expiration boundary
        1699000000 - inception_skew_tolerance, // just before inception, within tolerance
    }) |now| {
        // Time check passes; empty key fails verifyEcdsa's length check first.
        try testing.expectError(error.InvalidKey, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, now, &budget));
    }
}

test "verifyRrsig rejects signer that is not an ancestor of owner (RFC 4034 §3.1.3)" {
    // Cross-zone signer ("example.org" trying to sign "example.com" record):
    // the crypto layer rejects independently of the bailiwick check upstream.
    const cross_signer = dns.Name{ .labels = &.{ "example", "org" } };
    const rrsig = dns.RrsigData{
        .type_covered = .a,
        .algorithm = .ecdsap256sha256,
        .labels = 2,
        .original_ttl = 300,
        .sig_expiration = 1700000000,
        .sig_inception = 1699000000,
        .key_tag = 12345,
        .signer_name = cross_signer,
        .signature = &.{},
    };
    const rrset = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
    };
    var budget: ValidationBudget = .{};
    try testing.expectError(
        error.InvalidSignature,
        verifyRrsig(rrsig, test_window_dnskey, &rrset, 1699500000, &budget),
    );
}

test "verifyRrsig consumes budget on entry (KeyTrap mitigation)" {
    var budget: ValidationBudget = .{ .max_sig_verify = 2 };
    // Each call charges one unit, even when later checks would reject (empty
    // key here trips InvalidKey). Two attempts deplete the budget.
    inline for (0..2) |_| {
        try testing.expectError(error.InvalidKey, verifyRrsig(
            test_window_rrsig,
            test_window_dnskey,
            test_window_empty_rrset,
            1699500000,
            &budget,
        ));
    }
    try testing.expectEqual(@as(u32, 2), budget.sig_verify_spent.load(.monotonic));
    try testing.expectError(error.ValidationBudgetExhausted, verifyRrsig(
        test_window_rrsig,
        test_window_dnskey,
        test_window_empty_rrset,
        1699500000,
        &budget,
    ));
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
    const tag = keyTag(dnskey);
    const rrsig = dns.RrsigData{
        .type_covered = .a,
        .algorithm = .ecdsap256sha256,
        .labels = 2,
        .original_ttl = 300,
        .sig_expiration = 1700000000,
        .sig_inception = 1699000000,
        .key_tag = tag,
        .signer_name = test_owner,
        .signature = &.{},
    };
    const answers = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        .{ .name = test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = rrsig } },
    };
    const dnskeys = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 300, .rdata = .{ .dnskey = dnskey } },
    };
    var budget: ValidationBudget = .{ .max_sig_verify = 0 };
    try testing.expect(validateRrset(&answers, test_owner, .a, &dnskeys, 1699500000, &budget) == null);
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
    const authorities = [_]dns.ResourceRecord{nsecRr(owner, next)};
    // No DNSKEYs needed; iteration fails the find-RRSIG step.
    var budget: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityProofSigs(&authorities, &.{}, 1699500000, &budget, null),
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
        nsecRr(owner1, next1),
        rrsigRr(owner1, .nsec, .dsasha1, 12345, signer), // unsupported algo, won't verify
        nsecRr(owner2, next2),
        // no RRSIG for owner2 — bogus
    };
    var budget: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityProofSigs(&authorities, &.{}, 1699500000, &budget, null),
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
        nsecRr(owner, next),
        rrsigRr(owner, .nsec, .dsasha1, 12345, signer), // unsupported
    };
    var budget: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityProofSigs(&authorities, &.{}, 1699500000, &budget, null),
    );
}

test "verifyAuthorityProofSigs: failing supported + unsupported RRSIG returns bogus" {
    // Laundering guard: a fake unsupported-algo RRSIG must not downgrade
    // a failing supported-algo RRSIG from .bogus to .insecure.
    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "example", "com" } };
    const signer = owner;
    const tag = keyTag(test_ecdsa_dnskey);
    const authorities = [_]dns.ResourceRecord{
        nsecRr(owner, next),
        rrsigRr(owner, .nsec, .dsasha1, 12345, signer), // unsupported
        rrsigRr(owner, .nsec, .ecdsap256sha256, tag, signer), // supported, empty sig → fails
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(signer, test_ecdsa_dnskey)};
    var budget: ValidationBudget = .{};
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityProofSigs(&authorities, &dnskeys, 1699500000, &budget, null),
    );
}

test "validateRrset: an RRSIG at another owner cannot move this RRset's verdict" {
    // A signature at another owner says nothing about this RRset either way:
    // the verdict must be identical with and without the foreign RRSIG.
    const tag = keyTag(test_ecdsa_dnskey);
    const other_owner = dns.Name{ .labels = &.{ "other", "com" } };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(test_owner, test_ecdsa_dnskey)};

    const with_foreign = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(test_owner, .a, .dsasha1, 0, test_owner), // unsupported, this owner
        rrsigRr(other_owner, .a, .ecdsap256sha256, tag, other_owner), // supported, foreign owner
    };
    const without_foreign = with_foreign[0..2];

    var b1: ValidationBudget = .{};
    var b2: ValidationBudget = .{};
    try testing.expect(validateRrset(&with_foreign, test_owner, .a, &dnskeys, 1699500000, &b1) == null);
    try testing.expect(validateRrset(without_foreign, test_owner, .a, &dnskeys, 1699500000, &b2) == null);
}

test "validateRrset: failing supported + unsupported RRSIG returns bogus" {
    // Same-owner laundering on the answer-validation path.
    const tag = keyTag(test_ecdsa_dnskey);
    const answers = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(test_owner, .a, .dsasha1, 0, test_owner),
        rrsigRr(test_owner, .a, .ecdsap256sha256, tag, test_owner), // empty sig → fails
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(test_owner, test_ecdsa_dnskey)};
    var budget: ValidationBudget = .{};
    try testing.expect(validateRrset(&answers, test_owner, .a, &dnskeys, 1699500000, &budget) == null);
}

test "verifyRrsig rejects labels below the signer's label count" {
    // `*.com` cannot sign inside example.com: the wildcard that generated the
    // owner would sit above the zone. Unbound: "RRSIG label count too low for signer".
    const owner = dns.Name{ .labels = &.{ "foo", "example", "com" } };
    const recs = [_]dns.ResourceRecord{
        .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 0, 2, 1 } } },
    };
    var sig_buf: [64]u8 = undefined;
    var pub_buf: [32]u8 = undefined;
    var signed = try testSignRrset(&recs, .a, test_owner, .ed25519, &sig_buf, &pub_buf);
    var budget: ValidationBudget = .{};
    try verifyRrsig(signed.rrsig, signed.dnskey, &recs, 1_700_000_000, &budget);
    signed.rrsig.labels = 1;
    try testing.expectError(error.InvalidSignature, verifyRrsig(signed.rrsig, signed.dnskey, &recs, 1_700_000_000, &budget));
}

test "verifyAuthorityProofSigs refuses a wildcard-expanded NSEC" {
    // The zone's real `*.example.com NSEC a.example.com`, replayed under owner
    // `v.example.com`: labels 2 < 3 reconstructs `*.example.com` for the
    // signature, which verifies. As `v NSEC a` it is an apex wrap covering
    // every name after `v`, including ones that exist.
    const star = dns.Name{ .labels = &.{ "*", "example", "com" } };
    const a = dns.Name{ .labels = &.{ "a", "example", "com" } };
    const v = dns.Name{ .labels = &.{ "v", "example", "com" } };
    const real = [_]dns.ResourceRecord{nsecRr(star, a)};
    var sig_buf: [64]u8 = undefined;
    var pub_buf: [32]u8 = undefined;
    const signed = try testSignRrset(&real, .nsec, test_owner, .ed25519, &sig_buf, &pub_buf);
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(test_owner, signed.dnskey)};
    const sig_rr = dns.ResourceRecord{ .name = v, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } };
    const replayed = [_]dns.ResourceRecord{ nsecRr(v, a), sig_rr };
    var budget: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.bogus, verifyAuthorityProofSigs(&replayed, &dnskeys, 1_700_000_000, &budget, null));

    // Control: under its own owner the same signature is fine.
    const own_sig = dns.ResourceRecord{ .name = star, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } };
    const genuine = [_]dns.ResourceRecord{ real[0], own_sig };
    var budget2: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, verifyAuthorityProofSigs(&genuine, &dnskeys, 1_700_000_000, &budget2, null));
}

test "verifyRrsig rejects NS and SOA signed by a strictly-higher zone" {
    // The signature is genuine and every other rule passes — RFC 4034 §3.1.3
    // is satisfied because the signer *is* an ancestor of the owner, which is
    // true of every non-apex record in DNS. Only the type-specific rule
    // rejects: a signed NS marks a child-side apex (RFC 4035 §2.2 forbids
    // signing the parent-side delegation NS) and an SOA marks an apex, so the
    // containing zone is the owner itself.
    const parent = dns.Name{ .labels = &.{ "example", "com" } };
    const child = dns.Name{ .labels = &.{ "sub", "example", "com" } };
    var budget: ValidationBudget = .{};

    inline for (.{ dns.RType.ns, dns.RType.soa }) |rtype| {
        const rdata: dns.RData = switch (rtype) {
            .ns => .{ .ns = dns.Name{ .labels = &.{ "ns1", "example", "com" } } },
            .soa => .{ .soa = .{
                .mname = parent,
                .rname = parent,
                .serial = 1,
                .refresh = 3600,
                .retry = 600,
                .expire = 604800,
                .minimum = 300,
            } },
            else => unreachable,
        };

        // Owner strictly below the signer: rejected however good the signature.
        var sig_buf: [64]u8 = undefined;
        var pub_buf: [32]u8 = undefined;
        const below = [_]dns.ResourceRecord{
            .{ .name = child, .rtype = rtype, .rclass = .in, .ttl = 300, .rdata = rdata },
        };
        const signed = try testSignRrset(&below, rtype, parent, .ed25519, &sig_buf, &pub_buf);
        try testing.expectError(
            error.InvalidSignature,
            verifyRrsig(signed.rrsig, signed.dnskey, &below, 1_700_000_000, &budget),
        );

        // Owner == signer is the apex shape and must still verify, or the rule
        // would reject every legitimate apex NS/SOA in existence.
        var apex_sig_buf: [64]u8 = undefined;
        var apex_pub_buf: [32]u8 = undefined;
        const at_apex = [_]dns.ResourceRecord{
            .{ .name = parent, .rtype = rtype, .rclass = .in, .ttl = 300, .rdata = rdata },
        };
        const apex = try testSignRrset(&at_apex, rtype, parent, .ed25519, &apex_sig_buf, &apex_pub_buf);
        try verifyRrsig(apex.rrsig, apex.dnskey, &at_apex, 1_700_000_000, &budget);
    }
}

/// Sign `rrset` with a fresh Ed25519 key; returns the RRSIG and the DNSKEY
/// that verifies it. Buffers are caller-owned so the slices outlive the call.
fn testSignRrset(
    rrset: []const dns.ResourceRecord,
    covered: dns.RType,
    signer: dns.Name,
    key_algo: dns.DnssecAlgorithm,
    sig_buf: *[64]u8,
    pub_buf: *[32]u8,
) !struct { rrsig: dns.RrsigData, dnskey: dns.DnskeyData } {
    const kp = Ed25519.KeyPair.generate(testing.io);
    pub_buf.* = kp.public_key.toBytes();
    const dnskey = dns.DnskeyData{
        .flags = 256, // ZONE, not SEP
        .protocol = 3,
        .algorithm = key_algo,
        .public_key = pub_buf,
    };
    var rrsig = dns.RrsigData{
        .type_covered = covered,
        .algorithm = .ed25519,
        .labels = @intCast(rrset[0].name.labels.len),
        .original_ttl = 300,
        .sig_inception = 1_699_000_000,
        .sig_expiration = 1_800_000_000,
        .key_tag = keyTag(dnskey),
        .signer_name = signer,
        .signature = &.{},
    };
    var data_buf: [65536]u8 = undefined;
    sig_buf.* = (try kp.sign(try buildSignedData(&data_buf, rrsig, rrset), null)).toBytes();
    rrsig.signature = sig_buf;
    return .{ .rrsig = rrsig, .dnskey = dnskey };
}

test "validateDnskeyRrset: RRSIG algorithm must match the DS-anchored key's" {
    // Ed25519 key labelled `.rsasha256`; the RRSIG says .ed25519 and carries the
    // key's tag, so only the algorithm comparison can refuse it.
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    // recs[0] aliases pub_bytes, which testSignRrset fills before signing.
    var recs: [2]dns.ResourceRecord = undefined;
    recs[0] = dnskeyRr(test_owner, .{ .flags = 256, .protocol = 3, .algorithm = .rsasha256, .public_key = &pub_bytes });
    const signed = try testSignRrset(recs[0..1], .dnskey, test_owner, .rsasha256, &sig_bytes, &pub_bytes);
    recs[1] = .{ .name = test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } };

    var digest = try testDsDigest(test_owner, signed.dnskey);
    const ds = dns.DsData{
        .key_tag = keyTag(signed.dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };
    var budget: ValidationBudget = .{};
    try testing.expectError(
        error.InvalidSignature,
        validateDnskeyRrset(&recs, &.{ds}, test_owner, 1_700_000_000, &budget),
    );
}

test "validateRrset: the TTL cap comes from the signature that verified" {
    // Regression: the cap used to be derived in the cache by reducing over
    // every RRSIG present in the entry. The cache cannot tell which signature
    // verified, so one unverifiable RRSIG — free to append, since nothing
    // checks it — drove a `.secure` entry's TTL to zero and forced an upstream
    // query per client query. Unbound and Knot both read the bound off the
    // verifying signature at verification time; so does this.
    //
    // `testSignRrset` signs original_ttl 300 / expiration 1_800_000_000, and
    // those fields are inside the signature, so the genuine values cannot be
    // edited after the fact — the junk RRSIG carries the hostile ones instead.
    const now: u32 = 1_700_000_000;
    const recs = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try testSignRrset(&recs, .a, test_owner, .ed25519, &sig_bytes, &pub_bytes);

    // Appended, unverifiable, and expiring in one second. Placed FIRST so a
    // naive scan would reach it before the real one.
    var junk = signed.rrsig;
    junk.key_tag = signed.rrsig.key_tag ^ 0x5555;
    junk.original_ttl = 1;
    junk.sig_expiration = now + 1;

    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(test_owner, signed.dnskey)};
    const answers = [_]dns.ResourceRecord{
        recs[0],
        .{ .name = test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = junk } },
        .{ .name = test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = signed.rrsig } },
    };
    var budget: ValidationBudget = .{};
    const sig = validateRrset(&answers, test_owner, .a, &dnskeys, now, &budget).?;
    // The verifying signature's own bounds: original_ttl 300 against a
    // remaining window of 100_000_000 s. Never the junk record's 1.
    try testing.expectEqual(@as(u32, 300), rrsigTtlCap(sig, now));
}

test "validateRrset: the cap takes the RFC 4035 §5.3.3 window when it is the shorter bound" {
    // Same signature, evaluated close to its expiration: now the remaining
    // window is what binds, not RFC 4034 §3.1.2's original TTL.
    const recs = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try testSignRrset(&recs, .a, test_owner, .ed25519, &sig_bytes, &pub_bytes);
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(test_owner, signed.dnskey)};
    const answers = [_]dns.ResourceRecord{
        recs[0],
        .{ .name = test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = signed.rrsig } },
    };
    // 60 s before the signature dies.
    const now: u32 = 1_800_000_000 - 60;
    var budget: ValidationBudget = .{};
    const sig = validateRrset(&answers, test_owner, .a, &dnskeys, now, &budget).?;
    try testing.expectEqual(@as(u32, 60), rrsigTtlCap(sig, now));
}

test "validateRrset: >64-member RRset is bogus, not a validated prefix" {
    // The caller sets AD on the *unpruned* response, so a signature that
    // verifies over answers[0..64] must not authenticate a 70-record answer
    // section — the 6 appended records would ship authenticated.
    var recs: [70]dns.ResourceRecord = undefined;
    for (&recs, 0..) |*r, i| r.* = .{
        .name = test_owner,
        .rtype = .a,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .a = .{ 10, 0, @intCast(i / 256), @intCast(i % 256) } },
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try testSignRrset(recs[0..64], .a, test_owner, .ed25519, &sig_bytes, &pub_bytes);
    const sig_rr = dns.ResourceRecord{
        .name = test_owner,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .rrsig = signed.rrsig },
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(test_owner, signed.dnskey)};

    var answers: [71]dns.ResourceRecord = undefined;
    @memcpy(answers[0..70], &recs);
    answers[70] = sig_rr;
    var budget: ValidationBudget = .{};
    try testing.expect(validateRrset(&answers, test_owner, .a, &dnskeys, 1_700_000_000, &budget) == null);

    // Control: the signed 64 on their own still validate.
    var exact: [65]dns.ResourceRecord = undefined;
    @memcpy(exact[0..64], recs[0..64]);
    exact[64] = sig_rr;
    var budget2: ValidationBudget = .{};
    try testing.expect(validateRrset(&exact, test_owner, .a, &dnskeys, 1_700_000_000, &budget2) != null);
}

test "validateRrset: all-unsupported algorithms are .bogus, not .secure" {
    // .secure would stamp AD on data no signature verified; .insecure would
    // let an injector swap real RRSIGs for one unsupported-algo signature and
    // get forged data served instead of SERVFAILed (the zone is known secure
    // here — the all-unsupported-zone case goes insecure at the delegation).
    const answers = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(test_owner, .a, .dsasha1, 0, test_owner),
    };
    var budget: ValidationBudget = .{};
    try testing.expect(validateRrset(&answers, test_owner, .a, &.{}, 1699500000, &budget) == null);
}

test "verifyRsa accepts 1024-bit (128-byte) modulus key parsing" {
    // Build a minimal RSA key with 128-byte modulus (1024-bit)
    // Many TLDs still use RSA-1024 ZSKs — validators must accept them
    var key_data: [1 + 3 + 128]u8 = undefined;
    key_data[0] = 3;
    key_data[1] = 0x01; // exponent = 65537 (0x010001)
    key_data[2] = 0x00;
    key_data[3] = 0x01;
    @memset(key_data[4..], 0xAA);

    var sig: [128]u8 = undefined;
    @memset(&sig, 0xBB);
    // Should get InvalidSignature (key valid, sig doesn't verify) or InvalidKey from crypto
    const result = verifyRsa(&sig, "test", &key_data, Sha256);
    try testing.expect(result == error.InvalidSignature or result == error.InvalidKey);
}

test "verifyRsa accepts 2048-bit (256-byte) modulus key parsing" {
    // Build a key with 256-byte modulus — should pass key parsing
    // (will fail at signature verification, not key validation)
    var key_data: [1 + 3 + 256]u8 = undefined;
    key_data[0] = 3;
    key_data[1] = 0x01; // exponent = 65537
    key_data[2] = 0x00;
    key_data[3] = 0x01;
    @memset(key_data[4..], 0xAA);

    var sig: [256]u8 = undefined;
    @memset(&sig, 0xBB);
    // Should get InvalidSignature (key is valid but sig doesn't verify)
    // or InvalidKey from the crypto library — either is fine, not a key size error
    const result = verifyRsa(&sig, "test", &key_data, Sha256);
    // The point: it doesn't reject at the key-size check
    try testing.expect(result == error.InvalidSignature or result == error.InvalidKey);
}

fn expectVerifyRsaInvalidKey(exp: []const u8) !void {
    var key_data: [1 + 16 + 256]u8 = undefined;
    key_data[0] = @intCast(exp.len);
    @memcpy(key_data[1 .. 1 + exp.len], exp);
    @memset(key_data[1 + exp.len ..], 0xAA);
    const sig: [256]u8 = @splat(0);
    try testing.expectError(error.InvalidKey, verifyRsa(&sig, "test", key_data[0 .. 1 + exp.len + 256], Sha256));
}

test "verifyRsa rejects even exponent" {
    try expectVerifyRsaInvalidKey(&.{ 0x01, 0x00, 0x02 }); // 65538, even
}

test "verifyRsa rejects exponent 0" {
    try expectVerifyRsaInvalidKey(&.{0});
}

test "verifyRsa rejects exponent 1" {
    try expectVerifyRsaInvalidKey(&.{1});
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

test "verifyRsa bounds the public exponent (RFC 3110 allows absurd ones)" {
    // powPublic is linear in exponent bits and the KeyTrap budget caps only the
    // verify count, so an oversized exponent multiplies the entire per-query
    // budget. RsaFe.fromBytes already forces e < n, but with a 4096-bit modulus
    // that still left 511 bytes -- 31.6 ms a verify, 3.0 s a query.
    //
    // Both directions matter: 8 bytes must still be accepted, or this breaks
    // xelerance.com's 5-byte e = 2^32+1, which is the whole reason 500285a
    // dropped the stdlib's 4-byte cap.
    var buf: [1024]u8 = undefined;
    var sig: [256]u8 = undefined;
    @memset(&sig, 0xAB);

    inline for (.{ .{ 8, false }, .{ 9, true } }) |cfg| {
        const elen: usize = cfg[0];
        const want_rejected: bool = cfg[1];
        buf[0] = @intCast(elen);
        @memset(buf[1..][0..elen], 0xFF);
        @memset(buf[1 + elen ..][0..256], 0xFF);
        const key_data = buf[0 .. 1 + elen + 256];
        const res = verifyRsa(&sig, "hello", key_data, Sha256);
        if (want_rejected) {
            // Rejected on the key, before any modular arithmetic runs.
            try testing.expectError(error.InvalidKey, res);
        } else {
            // Got past every key check and died on the signature instead.
            try testing.expectError(error.InvalidSignature, res);
        }
    }
}

test "proveNoCloserMatch NSEC" {
    // `*.example.com` (labels=2) answered `foo.example.com`.
    const foo = dns.Name{ .labels = &.{ "foo", "example", "com" } };
    const zone = dns.Name{ .labels = &.{ "example", "com" } };
    const cover = [_]dns.ResourceRecord{nsecRr(.{ .labels = &.{ "bar", "example", "com" } }, .{ .labels = &.{ "zzz", "example", "com" } })};
    const elsewhere = [_]dns.ResourceRecord{nsecRr(.{ .labels = &.{ "aaa", "example", "com" } }, .{ .labels = &.{ "bbb", "example", "com" } })};
    var b: ValidationBudget = .{};
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
    var lo: [20]u8 = undefined;
    var hi: [20]u8 = undefined;
    var nc = makeCoveringNsec3(try nsec3Hash(qname, salt, 0), zone_labels, salt, &bufs, &lo, &hi);
    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, proveNoCloserMatch(&.{nc}, qname, 2, ce, &b));
    nc.rdata.nsec3.flags = nsec3_opt_out;
    try testing.expectEqual(SecurityStatus.insecure, proveNoCloserMatch(&.{nc}, qname, 2, ce, &b));
    // The CE's own record names the wildcard's parent and denies nothing.
    var ce_bufs: Nsec3OwnerBufs = .{};
    const ce_owner = makeNsec3OwnerName(try nsec3Hash(ce, salt, 0), zone_labels, &ce_bufs.enc, &ce_bufs.labels);
    const ce_only = [_]dns.ResourceRecord{makeNsec3Rr(ce_owner, salt, &@as([20]u8, @splat(0xFF)), &.{})};
    try testing.expectEqual(SecurityStatus.bogus, proveNoCloserMatch(&ce_only, qname, 2, ce, &b));
}
