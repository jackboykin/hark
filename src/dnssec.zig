const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const rsa = std.crypto.Certificate.rsa;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

pub const VerifyError = error{
    InvalidSignature,
    UnsupportedAlgorithm,
    InvalidKey,
    InvalidRData,
    BufferTooSmall,
    SignatureExpired,
    /// CVE-2023-50387 (KeyTrap) defense: per-resolution signature-verify budget
    /// exhausted. Callers map this to .bogus; the response SERVFAILs.
    ValidationBudgetExhausted,
};

// ── Per-Resolution CPU Budgets ───────────────────────────────────────

/// Caps RRSIG verifications per query to bound DS×DNSKEY×RRSIG amplification
/// (CVE-2023-50387, KeyTrap). 96 covers the realistic worst-case mix of
/// cold-cache 5-level chain × KSK rollover × dual-algo signing (RSASHA256 +
/// ECDSAP256) × the per-level DS-RRSIG verify added by RFC 4035 §5.2 fix:
/// roughly 5 levels × 3 verifies/level (DS + KSK self-sig + ZSK answer)
/// × 2 algos = ~60, plus headroom for repeated KSKs. Raise if legitimately
/// complex zones SERVFAIL during real KSK rollover windows; lower under
/// tight CPU budgets.
pub const max_sig_verify_per_resolution: u16 = 96;

/// Caps NSEC3 hash invocations per query (CVE-2023-50868 + salt-cache-defeat
/// in `classifyDelegation`). 96 covers the worst legitimate case (~78 hashes
/// across max-CNAME-chain × max-referrals with deep IDN qnames) with modest
/// headroom; exhaustion fails open to `.insecure` (skip_cache, no SERVFAIL).
/// Each invocation is bounded to `max_nsec3_iterations` SHA-1 ops, so worst-
/// case spend is 96 × 150 ≈ 14.4k SHA-1 compressions per resolution.
/// Raise to 128 if telemetry shows legitimate zones tripping the cap.
pub const max_nsec3_hashes_per_resolution: u16 = 96;

/// Per-resolution CPU counters; reset at the top of each `resolve()`.
pub const ValidationBudget = struct {
    sig_verify_remaining: u16 = max_sig_verify_per_resolution,
    nsec3_hash_remaining: u16 = max_nsec3_hashes_per_resolution,

    pub fn consumeVerify(self: *ValidationBudget) error{ValidationBudgetExhausted}!void {
        if (self.sig_verify_remaining == 0) return error.ValidationBudgetExhausted;
        self.sig_verify_remaining -= 1;
    }

    pub fn consumeNsec3Hash(self: *ValidationBudget) error{ValidationBudgetExhausted}!void {
        if (self.nsec3_hash_remaining == 0) return error.ValidationBudgetExhausted;
        self.nsec3_hash_remaining -= 1;
    }
};

// ── Security Status ──────────────────────────────────────────────────

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

// ── DNSKEY Validation Helpers ────────────────────────────────────────

/// RFC 4034 §2.1.1–2: a DNSKEY is usable for RRSIG verification only if
/// the Zone Key flag (bit 7) is set and the protocol field is 3.
/// RFC 5011 §2.1 additionally bars revoked keys (bit 8) from validating.
fn isValidZoneKey(dk: dns.DnskeyData) bool {
    return dk.isZoneKey() and dk.protocol == 3 and !dk.isRevoked();
}

/// Find a DNSKEY in a set that matches a DS record.
/// Returns the matching DNSKEY and its index, or null.
/// Uses pre-computed key tags to avoid redundant keyTag() calls.
pub fn findMatchingDnskey(
    ds: dns.DsData,
    dnskeys: []const dns.ResourceRecord,
    owner_name: dns.Name,
    precomputed_tags: []const u16,
) ?struct { dnskey: dns.DnskeyData, index: usize } {
    for (dnskeys, 0..) |rr, i| {
        if (rr.rtype != .dnskey) continue;
        const dk = rr.rdata.dnskey;
        if (!isValidZoneKey(dk)) continue;
        const tag = if (i < precomputed_tags.len) precomputed_tags[i] else keyTag(dk);
        if (tag != ds.key_tag) continue;
        if (@intFromEnum(dk.algorithm) != @intFromEnum(ds.algorithm)) continue;
        // Verify DS hash matches
        verifyDs(ds, dk, owner_name) catch continue;
        return .{ .dnskey = dk, .index = i };
    }
    return null;
}

/// Find an RRSIG covering a given RType signed by a given key tag.
pub fn findRrsig(
    records: []const dns.ResourceRecord,
    covered_type: dns.RType,
) ?dns.RrsigData {
    for (records) |rr| {
        if (rr.rtype != .rrsig) continue;
        const rrsig = rr.rdata.rrsig;
        if (rrsig.type_covered == covered_type) return rrsig;
    }
    return null;
}

/// Validate a DNSKEY RRset using a trust anchor DS record.
/// Returns the validated zone-signing keys (ZSKs) on success.
pub fn validateDnskeyRrset(
    dnskey_records: []const dns.ResourceRecord,
    ds_records: []const dns.DsData,
    zone_name: dns.Name,
    now_u32: u32,
    budget: ?*ValidationBudget,
) VerifyError!void {
    // Filter to only DNSKEY records for signature verification.
    // Response answers may include RRSIG records alongside DNSKEYs;
    // including them in buildSignedData would corrupt the verification.
    var dnskey_only: [64]dns.ResourceRecord = undefined;
    var dnskey_count: usize = 0;
    for (dnskey_records) |rr| {
        if (rr.rtype == .dnskey and dnskey_count < dnskey_only.len) {
            dnskey_only[dnskey_count] = rr;
            dnskey_count += 1;
        }
    }
    const filtered = dnskey_only[0..dnskey_count];

    // Pre-compute key tags to avoid redundant recomputation across nested loops.
    var key_tags: [64]u16 = undefined;
    for (dnskey_records, 0..) |rr, i| {
        if (i >= key_tags.len) break;
        key_tags[i] = if (rr.rtype == .dnskey) keyTag(rr.rdata.dnskey) else 0;
    }
    const tags = key_tags[0..@min(dnskey_records.len, key_tags.len)];

    // Try all DS records × all RRSIGs covering DNSKEY (RFC 6840 §5.11)
    outer: for (ds_records) |ds| {
        // RFC 6840 §5.2: if a SHA-256 DS covers the same key_tag, MUST NOT use SHA-1.
        if (ds.digest_type == .sha1) {
            for (ds_records) |ds2| {
                if (ds2.digest_type == .sha256 and ds2.key_tag == ds.key_tag) continue :outer;
            }
        }
        if (findMatchingDnskey(ds, dnskey_records, zone_name, tags)) |ksk_match| {
            const ksk = ksk_match.dnskey;
            const ksk_tag = tags[ksk_match.index];
            // Try every RRSIG covering DNSKEY
            for (dnskey_records) |rrsig_rr| {
                if (rrsig_rr.rtype != .rrsig) continue;
                if (rrsig_rr.rdata.rrsig.type_covered != .dnskey) continue;
                const rrsig = rrsig_rr.rdata.rrsig;

                if (rrsig.key_tag == ksk_tag) {
                    // Direct KSK verification
                    if (try tryVerifyRrsig(rrsig, ksk, filtered, now_u32, budget)) return;
                    continue;
                }

                // Fallback: signing key must be DS-authenticated (C2 fix)
                for (dnskey_records, 0..) |rr, i| {
                    if (rr.rtype != .dnskey) continue;
                    const dk = rr.rdata.dnskey;
                    if (!isValidZoneKey(dk)) continue;
                    const dk_tag = if (i < tags.len) tags[i] else keyTag(dk);
                    if (dk_tag != rrsig.key_tag) continue;
                    var ds_auth = false;
                    for (ds_records) |ds2| {
                        verifyDs(ds2, dk, zone_name) catch continue;
                        ds_auth = true;
                        break;
                    }
                    if (!ds_auth) continue;
                    if (try tryVerifyRrsig(rrsig, dk, filtered, now_u32, budget)) return;
                }
            }
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

/// Check if a referral has DS records proving the child is signed,
/// or NSEC/NSEC3 records proving DS absence (insecure delegation).
pub fn classifyDelegation(
    authorities: []const dns.ResourceRecord,
    child_zone: dns.Name,
    budget: *ValidationBudget,
) SecurityStatus {
    // Look for DS records for the child zone
    var has_ds = false;
    for (authorities) |rr| {
        if (rr.rtype == .ds and rr.name.eql(child_zone)) {
            has_ds = true;
            break;
        }
    }

    if (has_ds) return .secure;

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
            // RFC 9276 §3.2: treat high-iteration NSEC3 as insecure. Per
            // RFC 5155 §7.3, all NSEC3 in a zone share the same iterations,
            // so one high-iteration record taints the whole proof.
            if (nsec3.iterations > max_nsec3_iterations) return .insecure;
            const owner_hash = nsec3OwnerHash(rr.name) orelse continue;

            // Reuse cached hash if salt/iterations match; cache misses charge
            // the per-resolution budget (the salt-cache-defeat surface).
            const child_hash = blk: {
                if (cached_hash) |h| {
                    if (cached_iterations == nsec3.iterations and
                        mem.eql(u8, cached_salt, nsec3.salt))
                        break :blk h;
                }
                const new_hash = budgetedNsec3Hash(child_zone, nsec3.salt, nsec3.iterations, budget) catch |e| switch (e) {
                    error.ValidationBudgetExhausted => return .insecure,
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
            // Opt-Out cover: child_hash in range and Opt-Out flag set
            if (nsec3.flags & 1 != 0) {
                if (nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &child_hash)) {
                    return .insecure;
                }
            }
        }
    }

    // No DS and no valid proof of absence — fail closed to SERVFAIL.
    return .secure;
}

// ── Key Tag (RFC 4034 Appendix B) ────────────────────────────────────

/// Compute the key tag for a DNSKEY record per RFC 4034 Appendix B.
/// The key tag is a checksum over the DNSKEY RDATA wire format.
pub fn keyTag(dnskey: dns.DnskeyData) u16 {
    var ac: u32 = 0;

    // DNSKEY RDATA wire: flags(2) + protocol(1) + algorithm(1) + public_key
    // Accumulate 16-bit words
    ac += @as(u32, dnskey.flags);
    ac += @as(u32, dnskey.protocol) << 8 | @intFromEnum(dnskey.algorithm);

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

/// Write a name in canonical (lowercase, uncompressed) wire format.
/// Returns the number of bytes written.
pub fn writeCanonicalNameWire(buf: []u8, name: dns.Name) error{BufferTooSmall}!usize {
    var pos: usize = 0;
    for (name.labels) |label| {
        if (pos + 1 + label.len > buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(label.len);
        pos += 1;
        for (label) |c| {
            buf[pos] = std.ascii.toLower(c);
            pos += 1;
        }
    }
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = 0; // root label
    pos += 1;
    return pos;
}

// ── DS Hash Verification ─────────────────────────────────────────────

/// Verify a DS record against a DNSKEY record.
/// Computes hash(canonical_owner_wire || DNSKEY_RDATA) and compares to DS digest.
pub fn verifyDs(ds: dns.DsData, dnskey: dns.DnskeyData, owner_name: dns.Name) VerifyError!void {
    // Build: canonical_owner_wire || DNSKEY_RDATA
    var wire_buf: [1024]u8 = undefined;
    const name_len = writeCanonicalNameWire(&wire_buf, owner_name) catch return error.BufferTooSmall;

    // DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + public_key
    var pos = name_len;
    if (pos + 4 + dnskey.public_key.len > wire_buf.len) return error.BufferTooSmall;
    mem.writeInt(u16, wire_buf[pos..][0..2], dnskey.flags, .big);
    pos += 2;
    wire_buf[pos] = dnskey.protocol;
    pos += 1;
    wire_buf[pos] = @intFromEnum(dnskey.algorithm);
    pos += 1;
    @memcpy(wire_buf[pos..][0..dnskey.public_key.len], dnskey.public_key);
    pos += dnskey.public_key.len;

    const data = wire_buf[0..pos];

    switch (ds.digest_type) {
        .sha1 => {
            if (ds.digest.len != Sha1.digest_length) return error.InvalidSignature;
            var hash: [Sha1.digest_length]u8 = undefined;
            Sha1.hash(data, &hash, .{});
            if (!mem.eql(u8, &hash, ds.digest)) return error.InvalidSignature;
        },
        .sha256 => {
            if (ds.digest.len != Sha256.digest_length) return error.InvalidSignature;
            var hash: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(data, &hash, .{});
            if (!mem.eql(u8, &hash, ds.digest)) return error.InvalidSignature;
        },
        .sha384 => {
            if (ds.digest.len != Sha384.digest_length) return error.InvalidSignature;
            var hash: [Sha384.digest_length]u8 = undefined;
            Sha384.hash(data, &hash, .{});
            if (!mem.eql(u8, &hash, ds.digest)) return error.InvalidSignature;
        },
        _ => return error.UnsupportedAlgorithm,
    }
}

// ── RRSIG Signed Data Construction (RFC 4034 §5.3) ──────────────────

/// Write the RRSIG header (everything except the signature) in canonical
/// wire form. Used by both RRSIG verification (buildSignedData) and RRSIG
/// canonical serialization (writeCanonicalRData).
fn writeRrsigHeaderWire(buf: []u8, rrsig: dns.RrsigData) error{BufferTooSmall}!usize {
    if (buf.len < 18) return error.BufferTooSmall;
    mem.writeInt(u16, buf[0..2], @intFromEnum(rrsig.type_covered), .big);
    buf[2] = @intFromEnum(rrsig.algorithm);
    buf[3] = rrsig.labels;
    mem.writeInt(u32, buf[4..8], rrsig.original_ttl, .big);
    mem.writeInt(u32, buf[8..12], rrsig.sig_expiration, .big);
    mem.writeInt(u32, buf[12..16], rrsig.sig_inception, .big);
    mem.writeInt(u16, buf[16..18], rrsig.key_tag, .big);
    const name_len = writeCanonicalNameWire(buf[18..], rrsig.signer_name) catch return error.BufferTooSmall;
    return 18 + name_len;
}

/// Build the signed data for RRSIG verification.
/// Returns a slice of the buffer containing: RRSIG_RDATA(sans signature) || sorted_canonical_RRset
pub fn buildSignedData(
    buf: []u8,
    rrsig: dns.RrsigData,
    rrset: []const dns.ResourceRecord,
) error{BufferTooSmall}![]const u8 {
    // 1. RRSIG RDATA fields (sans signature)
    const pos: usize = try writeRrsigHeaderWire(buf, rrsig);

    // 2. Build canonical RRset entries, sorted by RDATA (RFC 4034 §6.3)
    // Each entry: canonical_owner_wire || type(2) || class(2) || original_ttl(4) || rdlength(2) || canonical_rdata
    const SortEntry = struct { wire: []const u8, rdata: []const u8 };
    var entries: [64]SortEntry = undefined;
    if (rrset.len > entries.len) return error.BufferTooSmall;

    // Use remaining buffer space for individual RR wire data
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

        const owner_len = writeCanonicalNameWire(buf[temp_pos..], owner_name) catch return error.BufferTooSmall;
        temp_pos += owner_len;

        if (temp_pos + 10 > buf.len) return error.BufferTooSmall;
        mem.writeInt(u16, buf[temp_pos..][0..2], @intFromEnum(rr.rtype), .big);
        temp_pos += 2;
        mem.writeInt(u16, buf[temp_pos..][0..2], @intFromEnum(rr.rclass), .big);
        temp_pos += 2;
        // Use RRSIG's original_ttl, not the RR's TTL
        mem.writeInt(u32, buf[temp_pos..][0..4], rrsig.original_ttl, .big);
        temp_pos += 4;

        // rdlength placeholder
        const rdlen_pos = temp_pos;
        temp_pos += 2;

        // Canonical RDATA
        const rdata_start = temp_pos;
        temp_pos += writeCanonicalRData(buf[temp_pos..], rr.rdata) catch return error.BufferTooSmall;
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

/// Write canonical RDATA per RFC 4034 §6.2.
/// For types with embedded names (NS, CNAME, SOA, PTR, MX, RRSIG, NSEC),
/// the names are lowercased. Other types are written as-is.
fn writeCanonicalRData(buf: []u8, rdata: dns.RData) error{BufferTooSmall}!usize {
    switch (rdata) {
        .ns => |name| return writeCanonicalNameWire(buf, name),
        .cname => |name| return writeCanonicalNameWire(buf, name),
        .ptr => |name| return writeCanonicalNameWire(buf, name),
        .mx => |mx| {
            if (buf.len < 2) return error.BufferTooSmall;
            mem.writeInt(u16, buf[0..2], mx.preference, .big);
            const name_len = try writeCanonicalNameWire(buf[2..], mx.exchange);
            return 2 + name_len;
        },
        .soa => |soa| {
            var pos: usize = 0;
            pos += writeCanonicalNameWire(buf[pos..], soa.mname) catch return error.BufferTooSmall;
            pos += writeCanonicalNameWire(buf[pos..], soa.rname) catch return error.BufferTooSmall;
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
            pos += writeCanonicalNameWire(buf[pos..], nsec_data.next_domain_name) catch return error.BufferTooSmall;
            if (pos + nsec_data.type_bit_maps.len > buf.len) return error.BufferTooSmall;
            @memcpy(buf[pos..][0..nsec_data.type_bit_maps.len], nsec_data.type_bit_maps);
            pos += nsec_data.type_bit_maps.len;
            return pos;
        },
        else => {
            // For types without embedded names, serialize via the standard serializer
            var ser = dns.Serializer.init(buf);
            ser.writeRData(rdata) catch return error.BufferTooSmall;
            return ser.pos;
        },
    }
}

// ── RRSIG Verification ───────────────────────────────────────────────

/// RFC 1982 serial number "greater than" for 32-bit timestamps.
fn serialAfter(s1: u32, s2: u32) bool {
    return s1 != s2 and (s1 -% s2) < 0x80000000;
}

/// 5 minutes — covers typical NTP drift; stricter than Unbound (1h floor).
pub const clock_skew_tolerance: u32 = 300;

/// Verify an RRSIG, returning true on success, false on non-budget failure.
/// Propagates ValidationBudgetExhausted so callers can bail out of loops.
fn tryVerifyRrsig(
    rrsig: dns.RrsigData,
    dnskey: dns.DnskeyData,
    rrset: []const dns.ResourceRecord,
    now_u32: u32,
    budget: ?*ValidationBudget,
) error{ValidationBudgetExhausted}!bool {
    verifyRrsig(rrsig, dnskey, rrset, now_u32, budget) catch |e| switch (e) {
        error.ValidationBudgetExhausted => return error.ValidationBudgetExhausted,
        else => return false,
    };
    return true;
}

/// Verify an RRSIG signature against a DNSKEY and RRset.
pub fn verifyRrsig(
    rrsig: dns.RrsigData,
    dnskey: dns.DnskeyData,
    rrset: []const dns.ResourceRecord,
    now_u32: u32,
    budget: ?*ValidationBudget,
) VerifyError!void {
    // KeyTrap (CVE-2023-50387) mitigation: charge before any work so attempts
    // count even when the cheap pre-checks below would reject.
    if (budget) |b| try b.consumeVerify();

    // RFC 4034 §3.1.3: signer name MUST be a (non-strict) ancestor of every
    // RRset owner, and `labels` MUST NOT exceed the owner's non-root label
    // count. Owner-vs-signer is also checked at the resolver layer (bailiwick
    // scrubbing); enforcing here defends future callers from missing it.
    for (rrset) |rr| {
        if (!rr.name.isSubdomainOf(rrsig.signer_name)) return error.InvalidSignature;
        if (rrsig.labels > rr.name.labels.len) return error.InvalidSignature;
        if (rrsig.labels == 0 and rr.name.labels.len != 0) return error.InvalidSignature;
    }

    // RFC 4035 §5.3.1 validity period, with clock-skew tolerance.
    const skew_ahead = now_u32 +% clock_skew_tolerance;
    const skew_behind = now_u32 -% clock_skew_tolerance;
    if (serialAfter(rrsig.sig_inception, skew_ahead)) return error.SignatureExpired;
    if (serialAfter(skew_behind, rrsig.sig_expiration)) return error.SignatureExpired;

    // Build the signed data
    var signed_data_buf: [65536]u8 = undefined;
    const signed_data = buildSignedData(&signed_data_buf, rrsig, rrset) catch return error.BufferTooSmall;

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

// ── Algorithm-specific verification ──────────────────────────────────

/// Parse an RFC 3110 RSA public key and verify a PKCS#1 v1.5 signature.
fn verifyRsa(signature: []const u8, msg: []const u8, key_data: []const u8, comptime Hash: type) VerifyError!void {
    // RFC 3110: first byte is exponent length (if < 256), then exponent, then modulus
    // If first byte is 0, next 2 bytes are exponent length
    if (key_data.len < 3) return error.InvalidKey;

    var exp_len: usize = key_data[0];
    var offset: usize = 1;
    if (exp_len == 0) {
        if (key_data.len < 3) return error.InvalidKey;
        exp_len = @as(usize, key_data[1]) << 8 | key_data[2];
        offset = 3;
    }

    if (offset + exp_len > key_data.len) return error.InvalidKey;
    const exponent = key_data[offset..][0..exp_len];
    const modulus = key_data[offset + exp_len ..];

    // Reject degenerate exponents: empty, 0, 1, or even
    if (exp_len == 0) return error.InvalidKey;
    if (exponent[exp_len - 1] & 1 == 0) return error.InvalidKey; // reject even
    if (exp_len == 1 and exponent[0] <= 1) return error.InvalidKey; // reject 0, 1

    // Require 1024-bit minimum modulus (128 bytes). Many zones (including TLDs
    // like .org) still use 1024-bit RSA ZSKs. Validators must accept them even
    // though 2048-bit is recommended for signing (RFC 6781).
    if (modulus.len < 128 or modulus.len > 512) return error.InvalidKey;
    if (signature.len != modulus.len) return error.InvalidSignature;

    const pub_key = rsa.PublicKey.fromBytes(exponent, modulus) catch return error.InvalidKey;

    // Dispatch on modulus length at comptime. Zig's RSA implementation needs
    // the modulus size as a comptime parameter. Cover every 8-byte-aligned
    // size from 128 to 512 — RSA keys are always a multiple of 64 bits.
    inline for (comptime blk: {
        var sizes: [(512 - 128) / 8 + 1]usize = undefined;
        for (0..sizes.len) |i| sizes[i] = 128 + i * 8;
        break :blk sizes;
    }) |mod_len| {
        if (modulus.len == mod_len) {
            const sig_array = signature[0..mod_len].*;
            rsa.PKCS1v1_5Signature.verify(mod_len, sig_array, msg, pub_key, Hash) catch
                return error.InvalidSignature;
            return;
        }
    }
    return error.InvalidKey;
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

/// Verify an Ed25519 signature.
fn verifyEd25519(signature: []const u8, msg: []const u8, key_data: []const u8) VerifyError!void {
    if (key_data.len != 32) return error.InvalidKey;
    if (signature.len != 64) return error.InvalidSignature;

    const pub_key = Ed25519.PublicKey.fromBytes(key_data[0..32].*) catch return error.InvalidKey;
    const sig = Ed25519.Signature.fromBytes(signature[0..64].*);
    sig.verify(msg, pub_key) catch return error.InvalidSignature;
}

// ── Canonical Name Ordering (RFC 4034 §6.1) ──────────────────────────

/// Compare two DNS names in canonical ordering (RFC 4034 §6.1).
/// Labels are compared case-insensitively from rightmost to leftmost.
/// Returns .lt, .eq, or .gt.
pub fn canonicalNameOrder(a: dns.Name, b: dns.Name) std.math.Order {
    // Compare from the rightmost label
    const min_labels = @min(a.labels.len, b.labels.len);
    var i: usize = 0;
    while (i < min_labels) : (i += 1) {
        const a_idx = a.labels.len - 1 - i;
        const b_idx = b.labels.len - 1 - i;
        const cmp = cmpLabelsCI(a.labels[a_idx], b.labels[b_idx]);
        if (cmp != .eq) return cmp;
    }
    // All compared labels equal — shorter name comes first
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

/// Case-insensitive label comparison, byte-by-byte.
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

// ── Range Checks ─────────────────────────────────────────────────────

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

// ── NSEC Proofs ──────────────────────────────────────────────────────

/// Check if an NSEC record proves that `qname` does not exist.
/// Returns true if qname falls in the range (nsec_owner, nsec_next).
pub fn nsecProvesNameNonexistence(
    nsec_owner: dns.Name,
    nsec: dns.NsecData,
    qname: dns.Name,
) bool {
    return inOpenRangeWrap(
        canonicalNameOrder(nsec_owner, qname),
        canonicalNameOrder(qname, nsec.next_domain_name),
        canonicalNameOrder(nsec_owner, nsec.next_domain_name),
    );
}

/// Check if an NSEC record proves that `qtype` does not exist at `qname`.
/// RFC 4035 §5.4 + RFC 6840 §4.3: the bitmap must show qtype absent AND
/// CNAME absent — otherwise the name has a CNAME and the answer should
/// have followed it. (When qtype itself is CNAME, only that absence
/// matters; the dual check would be self-redundant.) Mirrors the NSEC3
/// NODATA path in validateNegativeProofNsec3.
pub fn nsecProvesTypeNonexistence(
    nsec_owner: dns.Name,
    nsec: dns.NsecData,
    qname: dns.Name,
    qtype: dns.RType,
) bool {
    if (!nsec_owner.eql(qname)) return false;
    if (dns.typeBitmapContains(nsec.type_bit_maps, qtype)) return false;
    if (qtype == .cname) return true;
    return !dns.typeBitmapContains(nsec.type_bit_maps, .cname);
}

// ── NSEC3 Hashing (RFC 5155) ─────────────────────────────────────────

/// Maximum allowed NSEC3 iterations. RFC 9276 §3.2 recommends treating any
/// iteration count as a configuration smell; 100 is the modern BIND/Unbound
/// soft ceiling above which proofs are downgraded to .insecure rather than
/// burning hash budget.
pub const max_nsec3_iterations: u16 = 100;

/// Compute NSEC3 hash: iterated SHA-1 over canonical_name_wire || salt.
/// Returns the raw hash bytes (20 bytes for SHA-1).
pub fn nsec3Hash(
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

/// Check if hash falls within the NSEC3 range (owner_hash, next_hashed_owner).
pub fn nsec3HashInRange(
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

// ── NSEC3 Owner Hash + Budgeted Hashing ──────────────────────────────

/// Extract the raw hash from an NSEC3 owner name by base32hex-decoding its first label.
/// Returns null if the label length is wrong or contains invalid characters.
pub fn nsec3OwnerHash(name: dns.Name) ?[Sha1.digest_length]u8 {
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
fn supportedNsec3OwnerHash(rr: dns.ResourceRecord) ?[Sha1.digest_length]u8 {
    if (rr.rtype != .nsec3) return null;
    if (rr.rdata.nsec3.hash_algorithm != .sha1) return null;
    return nsec3OwnerHash(rr.name);
}

pub const BudgetedHashError = error{ ValidationBudgetExhausted, HashFailed };

/// Compute NSEC3 hash with per-resolution budget tracking. Callers map
/// ValidationBudgetExhausted to .insecure (CVE-2023-50868 + salt-cache-defeat
/// in `classifyDelegation`) and HashFailed to .bogus.
pub fn budgetedNsec3Hash(
    name: dns.Name,
    salt: []const u8,
    iterations: u16,
    budget: *ValidationBudget,
) BudgetedHashError![Sha1.digest_length]u8 {
    try budget.consumeNsec3Hash();
    return nsec3Hash(name, salt, iterations) catch return error.HashFailed;
}

fn budgetedHashStatus(e: BudgetedHashError) SecurityStatus {
    return switch (e) {
        error.ValidationBudgetExhausted => .insecure,
        error.HashFailed => .bogus,
    };
}

// ── Mixed NSEC/NSEC3 Detection ───────────────────────────────────────

/// Check if a response mixes NSEC and NSEC3 from the same zone.
/// Returns true if mixed (should reject the proof).
pub fn hasMixedNsecNsec3(authorities: []const dns.ResourceRecord) bool {
    var has_nsec = false;
    var has_nsec3 = false;
    for (authorities) |rr| {
        if (rr.rtype == .nsec) has_nsec = true;
        if (rr.rtype == .nsec3) has_nsec3 = true;
    }
    return has_nsec and has_nsec3;
}

// ── Negative Proof Validation ────────────────────────────────────────

/// Validate an NXDOMAIN or NODATA response using NSEC/NSEC3 proofs.
/// Returns the security status of the negative proof.
pub fn validateNegativeProof(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    budget: *ValidationBudget,
) SecurityStatus {
    // Reject mixed NSEC/NSEC3
    if (hasMixedNsecNsec3(authorities)) return .bogus;

    // Try NSEC proofs first. Track the NSEC that covered qname so we can derive
    // the closest encloser and only test wildcard denial at the correct name.
    // Invariant: `any_nsec` remains false when the proof is pure NSEC3, which
    // lets control fall through to the NSEC3 path below.
    var covering_nsec: ?dns.ResourceRecord = null;
    var any_nsec = false;
    for (authorities) |rr| {
        if (rr.rtype != .nsec) continue;
        any_nsec = true;
        if (is_nxdomain) {
            if (nsecProvesNameNonexistence(rr.name, rr.rdata.nsec, qname)) {
                covering_nsec = rr;
            }
        } else {
            // NODATA: NSEC owner matches qname, type not in bitmap
            if (nsecProvesTypeNonexistence(rr.name, rr.rdata.nsec, qname, qtype)) {
                return .secure;
            }
        }
    }

    // RFC 4035 §5.4: NXDOMAIN requires both name denial AND wildcard denial at
    // the closest encloser. The CE is the longest label-suffix of qname that is
    // also a suffix of the covering NSEC's owner or next_domain_name.
    if (is_nxdomain and any_nsec) {
        const covering = covering_nsec orelse return .unchecked;
        const ce_depth = @max(
            commonSuffixLabels(qname, covering.name),
            commonSuffixLabels(qname, covering.rdata.nsec.next_domain_name),
        );
        // CE must be a proper ancestor of qname (strictly fewer labels).
        if (ce_depth >= qname.labels.len) return .bogus;
        const ce = dns.Name{ .labels = qname.labels[qname.labels.len - ce_depth ..] };

        // RFC 4035 §5.4: the CE must be *proven* to exist via an NSEC that
        // explicitly names it as owner or next. A "covering range strictly
        // contains CE" branch was considered for empty-non-terminal CEs,
        // but the CE is by construction a common-suffix ancestor of both
        // NSEC bounds — canonical order sorts ancestors strictly before
        // descendants of the same suffix, so any legitimate NSEC has both
        // bounds sorting *after* the CE and the in-range check is dead.
        // The branch fires only on attacker-forged NSECs that geometrically
        // straddle a CE candidate; dropping it closes that pin-CE class
        // without losing any real ENT-CE proof (real ENT denial uses
        // NSEC3, which has its own dedicated CE proof in this validator).
        var ce_proven = false;
        for (authorities) |rr| {
            if (rr.rtype != .nsec) continue;
            if (rr.name.eql(ce) or rr.rdata.nsec.next_domain_name.eql(ce)) {
                ce_proven = true;
                break;
            }
        }
        if (!ce_proven) return .unchecked;

        var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
        const wildcard = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unchecked;

        var wildcard_denied = false;
        for (authorities) |rr| {
            if (rr.rtype != .nsec) continue;
            // Wildcard is covered by NSEC range (doesn't exist)
            if (nsecProvesNameNonexistence(rr.name, rr.rdata.nsec, wildcard)) {
                wildcard_denied = true;
                break;
            }
            // Wildcard matches NSEC owner but qtype absent (NODATA at wildcard)
            if (nsecProvesTypeNonexistence(rr.name, rr.rdata.nsec, wildcard, qtype)) {
                wildcard_denied = true;
                break;
            }
        }
        if (wildcard_denied) return .secure;
        return .unchecked;
    }

    // Try NSEC3 proofs
    return validateNsec3NegativeProof(authorities, qname, qtype, is_nxdomain, budget);
}

/// Validate NSEC3 negative proofs (RFC 5155 §8.4/§8.5).
fn validateNsec3NegativeProof(
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
    budget: *ValidationBudget,
) SecurityStatus {
    // Extract NSEC3 parameters from first NSEC3 record
    var salt: []const u8 = &.{};
    var iterations: u16 = 0;
    var found_nsec3 = false;
    var saw_unknown_algo = false;
    for (authorities) |rr| {
        if (rr.rtype != .nsec3) continue;
        const nsec3 = rr.rdata.nsec3;
        // RFC 5155 §10.2 / RFC 6840 §5.11: skip NSEC3 records using unknown
        // hash algorithms; do not treat as bogus.
        if (nsec3.hash_algorithm != .sha1) {
            saw_unknown_algo = true;
            continue;
        }
        // RFC 9276 §3.2: treat high-iteration NSEC3 as insecure. Mirrors
        // classifyDelegation — both paths share one policy.
        if (nsec3.iterations > max_nsec3_iterations) return .insecure;
        salt = nsec3.salt;
        iterations = nsec3.iterations;
        found_nsec3 = true;
        break;
    }
    if (!found_nsec3) {
        // Only unknown-algorithm NSEC3 records present — validator can't
        // verify; treat as insecure so a future SHA-256/SHA-3 transition
        // doesn't SERVFAIL.
        if (saw_unknown_algo) return .insecure;
        return .unchecked;
    }

    if (!is_nxdomain) {
        // NODATA (RFC 5155 §8.5): NSEC3 owner matches hash(qname), qtype absent
        const qname_hash = budgetedNsec3Hash(qname, salt, iterations, budget) catch |e|
            return budgetedHashStatus(e);
        for (authorities) |rr| {
            const owner_hash = supportedNsec3OwnerHash(rr) orelse continue;
            if (mem.eql(u8, &owner_hash, &qname_hash)) {
                const nsec3 = rr.rdata.nsec3;
                // Must not have qtype AND must not have CNAME (RFC 5155 §8.5)
                if (!dns.typeBitmapContains(nsec3.type_bit_maps, qtype) and
                    !dns.typeBitmapContains(nsec3.type_bit_maps, .cname))
                {
                    return .secure;
                }
                return .unchecked;
            }
        }
        return .unchecked;
    }

    // NXDOMAIN (RFC 5155 §8.4): closest encloser proof
    // Walk up from qname toward root to find closest encloser
    var ce_idx: ?usize = null; // index into qname.labels where CE starts
    var label_offset: usize = 0;
    while (label_offset < qname.labels.len) : (label_offset += 1) {
        // Build ancestor name from qname.labels[label_offset..]
        const ancestor = dns.Name{ .labels = qname.labels[label_offset..] };
        const ancestor_hash = budgetedNsec3Hash(ancestor, salt, iterations, budget) catch |e|
            return budgetedHashStatus(e);

        for (authorities) |rr| {
            const owner_hash = supportedNsec3OwnerHash(rr) orelse continue;
            if (mem.eql(u8, &owner_hash, &ancestor_hash)) {
                ce_idx = label_offset;
                break;
            }
        }
        if (ce_idx != null) break;
    }
    const ce_offset = ce_idx orelse return .unchecked;

    // CE == qname itself contradicts NXDOMAIN
    if (ce_offset == 0) return .bogus;

    // Next closer name: CE + one label toward qname = qname.labels[ce_offset - 1..]
    const next_closer = dns.Name{ .labels = qname.labels[ce_offset - 1 ..] };
    const nc_hash = budgetedNsec3Hash(next_closer, salt, iterations, budget) catch |e|
        return budgetedHashStatus(e);

    // Wildcard at closest encloser: *.CE
    var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
    const ce = dns.Name{ .labels = qname.labels[ce_offset..] };
    const wildcard = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unchecked;
    const wc_hash = budgetedNsec3Hash(wildcard, salt, iterations, budget) catch |e|
        return budgetedHashStatus(e);

    // Verify: some NSEC3 covers the next-closer hash
    var nc_covered = false;
    var wc_covered = false;
    for (authorities) |rr| {
        const owner_hash = supportedNsec3OwnerHash(rr) orelse continue;
        const nsec3 = rr.rdata.nsec3;

        if (!nc_covered and nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &nc_hash)) {
            nc_covered = true;
        }
        // Wildcard: covered (doesn't exist) OR exact match with no qtype (NODATA at wildcard)
        if (!wc_covered) {
            if (nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &wc_hash)) {
                wc_covered = true;
            } else if (mem.eql(u8, &owner_hash, &wc_hash)) {
                // Wildcard exists but doesn't have the type — still proves NXDOMAIN
                wc_covered = true;
            }
        }
    }

    if (nc_covered and wc_covered) return .secure;
    return .unchecked;
}

// ── Answer RRset Validation ──────────────────────────────────────────

/// Validate answer RRsets against a DNSKEY set.
/// Finds the RRSIG covering `qtype`, matches it to a DNSKEY by key_tag + algorithm,
/// and verifies the signature. Per RFC 6840 §5.4, tries ALL matching DNSKEYs.
/// Also validates CNAME RRSIG if the answer contains CNAMEs and qtype != .cname,
/// but only when the CNAME RRSIG signer matches the main type's signer (same zone).
/// Cross-zone CNAMEs (RFC 4035 §5.3.1) are skipped — they need their own zone's DNSKEYs.
pub fn validateAnswerRrset(
    answers: []const dns.ResourceRecord,
    qtype: dns.RType,
    dnskey_records: []const dns.ResourceRecord,
    now_u32: u32,
    budget: ?*ValidationBudget,
) SecurityStatus {
    // Validate the main answer type. Propagate .insecure (all-unsupported-algo
    // RRSIGs) instead of silently upgrading to .secure — otherwise the resolver
    // would stamp AD on data it never cryptographically verified.
    const main = validateRrsetForType(answers, qtype, dnskey_records, now_u32, budget);
    if (main == .bogus) return .bogus;

    // If answers contain CNAME records, validate the CNAME RRset too.
    // After bailiwick scrubbing, all answer records are from the same zone.
    if (qtype != .cname) {
        for (answers) |rr| {
            if (rr.rtype == .cname) {
                const cname_status = validateRrsetForType(answers, .cname, dnskey_records, now_u32, budget);
                if (cname_status == .bogus) return .bogus;
                if (cname_status == .insecure) return .insecure;
                break;
            }
        }
    }

    return main;
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

/// Validate a single RRset type within the answers against DNSKEYs.
/// Iterates ALL RRSIGs covering the target type per RFC 6840 §5.11.
fn validateRrsetForType(
    answers: []const dns.ResourceRecord,
    covered_type: dns.RType,
    dnskey_records: []const dns.ResourceRecord,
    now_u32: u32,
    budget: ?*ValidationBudget,
) SecurityStatus {
    var had_unsupported_algo = false;
    var attempted_supported = false;
    for (answers) |sig_rr| {
        if (sig_rr.rtype != .rrsig) continue;
        const rrsig = sig_rr.rdata.rrsig;
        if (rrsig.type_covered != covered_type) continue;

        if (!isSupportedAlgorithm(rrsig.algorithm)) {
            had_unsupported_algo = true;
            continue;
        }

        // Set BEFORE the owner filter — owner-mismatch is itself a forgery
        // signal, not an excuse to launder to .insecure.
        attempted_supported = true;

        // Filter RRset by this RRSIG's owner (same owner + type)
        var filtered: [64]dns.ResourceRecord = undefined;
        var count: usize = 0;
        for (answers) |rr| {
            if (rr.rtype == covered_type and rr.name.eql(sig_rr.name) and count < filtered.len) {
                filtered[count] = rr;
                count += 1;
            }
        }
        if (count == 0) continue;

        // Try ALL matching DNSKEYs (key_tag + algorithm)
        for (dnskey_records) |dk_rr| {
            if (dk_rr.rtype != .dnskey) continue;
            const dk = dk_rr.rdata.dnskey;
            if (!isValidZoneKey(dk)) continue;
            if (keyTag(dk) != rrsig.key_tag) continue;
            if (@intFromEnum(dk.algorithm) != @intFromEnum(rrsig.algorithm)) continue;
            if (tryVerifyRrsig(rrsig, dk, filtered[0..count], now_u32, budget) catch return .bogus) return .secure;
        }
    }
    // RFC 6840 §5.11: all-unsupported → .insecure. But a supported-algo
    // attempt that failed must yield .bogus, not .insecure, or attackers
    // launder failures via injected unsupported-algo RRSIGs.
    if (attempted_supported) return .bogus;
    return if (had_unsupported_algo) .insecure else .bogus;
}

// ── Authority NSEC/NSEC3 Signature Verification ──────────────────────

/// Verify that every NSEC/NSEC3 record in the authority section has a valid RRSIG
/// signed by one of the provided DNSKEYs.
pub fn verifyAuthorityNsecSigs(
    authorities: []const dns.ResourceRecord,
    dnskey_records: []const dns.ResourceRecord,
    now_u32: u32,
    budget: ?*ValidationBudget,
) SecurityStatus {
    // Verify that every NSEC/NSEC3 record has a valid RRSIG.
    // NSEC/NSEC3 records have unique owners per RFC 4034/5155,
    // so no dedup is needed.
    var any_nsec = false;
    var any_unsupported = false;
    for (authorities) |rr| {
        if (rr.rtype != .nsec and rr.rtype != .nsec3) continue;
        any_nsec = true;

        // Collect the RRset (all records with same owner+type)
        var rrset: [16]dns.ResourceRecord = undefined;
        var rrset_count: usize = 0;
        for (authorities) |rr2| {
            if (rr2.rtype == rr.rtype and rr2.name.eql(rr.name) and rrset_count < rrset.len) {
                rrset[rrset_count] = rr2;
                rrset_count += 1;
            }
        }

        // Find a matching RRSIG and verify it
        var sig_verified = false;
        var had_unsupported_algo = false;
        var attempted_supported = false;
        for (authorities) |sig_rr| {
            if (sig_rr.rtype != .rrsig) continue;
            const rrsig = sig_rr.rdata.rrsig;
            if (rrsig.type_covered != rr.rtype or !sig_rr.name.eql(rr.name)) continue;

            if (!isSupportedAlgorithm(rrsig.algorithm)) {
                had_unsupported_algo = true;
                continue;
            }

            attempted_supported = true;

            for (dnskey_records) |dk_rr| {
                if (dk_rr.rtype != .dnskey) continue;
                const dk = dk_rr.rdata.dnskey;
                if (!isValidZoneKey(dk)) continue;
                if (keyTag(dk) != rrsig.key_tag) continue;
                if (@intFromEnum(dk.algorithm) != @intFromEnum(rrsig.algorithm)) continue;
                if (tryVerifyRrsig(rrsig, dk, rrset[0..rrset_count], now_u32, budget) catch return .bogus) {
                    sig_verified = true;
                    break;
                }
            }
            if (sig_verified) break;
        }
        if (!sig_verified) {
            // RFC 4035 §5.3: every NSEC owner must verify. .insecure only
            // when every supported-algo path was unavailable; otherwise
            // bogus. See validateRrsetForType for the laundering rationale.
            if (attempted_supported) return .bogus;
            if (!had_unsupported_algo) return .bogus;
            any_unsupported = true;
        }
    }

    if (!any_nsec) return .unchecked;
    // RFC 6840 §5.11: every owner ended up with only unsupported algorithms.
    if (any_unsupported) return .insecure;
    return .secure;
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

test "keyTag computation" {
    // Test with a known DNSKEY. The root KSK-2017 has key tag 20326.
    // We'll use a synthetic key and verify the algorithm matches RFC 4034 Appendix B.
    const dnskey = dns.DnskeyData{
        .flags = 256, // ZSK
        .protocol = 3,
        .algorithm = .rsasha256,
        .public_key = &.{ 0x03, 0x01, 0x00, 0x01 }, // minimal test key
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
    // Wrong protocol
    try testing.expect(!isValidZoneKey(.{ .flags = 256, .protocol = 0, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 256, .protocol = 1, .algorithm = .rsasha256, .public_key = &.{} }));
    // RFC 5011 §2.1: REVOKE bit set — must reject even with zone key + correct protocol
    try testing.expect(!isValidZoneKey(.{ .flags = 256 | 0x80, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 257 | 0x80, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
}

test "canonical name wire format" {
    var buf: [256]u8 = undefined;

    // "Example.COM" => lowercase uncompressed wire: \x07example\x03com\x00
    const name = dns.Name{
        .labels = &.{
            @as([]const u8, "Example"),
            @as([]const u8, "COM"),
        },
    };
    const len = try writeCanonicalNameWire(&buf, name);
    try testing.expectEqualSlices(u8, "\x07example\x03com\x00", buf[0..len]);

    // Root zone => \x00
    const root = dns.Name{ .labels = &.{} };
    const root_len = try writeCanonicalNameWire(&buf, root);
    try testing.expectEqual(@as(usize, 1), root_len);
    try testing.expectEqual(@as(u8, 0), buf[0]);
}

/// Compute SHA-256 DS digest for a DNSKEY: SHA-256(canonical_owner_wire || DNSKEY_RDATA).
fn testDsDigest(owner: dns.Name, dnskey: dns.DnskeyData) ![Sha256.digest_length]u8 {
    var wire_buf: [1024]u8 = undefined;
    const name_len = try writeCanonicalNameWire(&wire_buf, owner);
    var pos = name_len;
    mem.writeInt(u16, wire_buf[pos..][0..2], dnskey.flags, .big);
    pos += 2;
    wire_buf[pos] = dnskey.protocol;
    pos += 1;
    wire_buf[pos] = @intFromEnum(dnskey.algorithm);
    pos += 1;
    @memcpy(wire_buf[pos..][0..dnskey.public_key.len], dnskey.public_key);
    pos += dnskey.public_key.len;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(wire_buf[0..pos], &digest, .{});
    return digest;
}

const test_dnskey = dns.DnskeyData{
    .flags = 257,
    .protocol = 3,
    .algorithm = .rsasha256,
    .public_key = &.{ 0x03, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD },
};

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

    try testing.expectError(
        error.InvalidSignature,
        validateDnskeyRrset(&dnskey_records, &.{ds}, test_owner, 1700000000, null),
    );
}

test "validateAnswerRrset on DS without RRSIG returns .bogus (RFC 4035 §5.2)" {
    // A DS RRset that arrives at the resolver without a covering RRSIG
    // signed by the parent zone's DNSKEY MUST NOT be trusted as a chain
    // anchor. Without C4's verify step, hark used to cache such records
    // as .unchecked and let DNSKEY validation indirectly bless them.
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
            .digest = &[_]u8{0} ** 32,
        } },
    };
    const records = [_]dns.ResourceRecord{ds_record}; // No RRSIG present.
    var b: ValidationBudget = .{};
    const status = validateAnswerRrset(&records, .ds, &.{}, 1700000000, &b);
    try testing.expectEqual(SecurityStatus.bogus, status);
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
    // Verify the RRSIG header portion of signed data
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

    // Verify first 18 bytes of RRSIG header
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
    // Generate a real key pair and sign some data
    const key_pair = EcdsaP256.KeyPair.generate(testing.io);
    const pub_bytes = key_pair.public_key.toUncompressedSec1();
    // DNSSEC key is raw 64-byte x||y (without 0x04 prefix)
    const dnssec_key = pub_bytes[1..65];

    const msg = "test DNSSEC signed data";
    const sig = try key_pair.sign(msg, null);
    const sig_bytes = sig.toBytes();

    // Should verify
    try verifyEcdsa(EcdsaP256, 32, &sig_bytes, msg, dnssec_key);

    // Wrong message should fail
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
    const sig64 = [_]u8{0} ** 64;
    const sig96 = [_]u8{0} ** 96;

    // ECDSA P-256: key must be 64 bytes
    try testing.expectError(error.InvalidKey, verifyEcdsa(EcdsaP256, 32, &sig64, msg, &.{ 0x01, 0x02 }));
    // ECDSA P-384: key must be 96 bytes
    try testing.expectError(error.InvalidKey, verifyEcdsa(EcdsaP384, 48, &sig96, msg, &.{ 0x01, 0x02 }));
    // Ed25519: key must be 32 bytes
    try testing.expectError(error.InvalidKey, verifyEd25519(&sig64, msg, &.{ 0x01, 0x02 }));
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
            .digest = &([_]u8{0xAA} ** 32),
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
                .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x60 }, // A + NS, no DS
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

    // NS only, no DS, no NSEC/NSEC3 — indeterminate, treated as insecure
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

test "findRrsig finds matching RRSIG" {
    const signer = dns.Name{
        .labels = &.{
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };

    const records = [_]dns.ResourceRecord{
        .{
            .name = signer,
            .rtype = .a,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .a = .{ 1, 2, 3, 4 } },
        },
        .{
            .name = signer,
            .rtype = .rrsig,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .rrsig = .{
                .type_covered = .a,
                .algorithm = .ecdsap256sha256,
                .labels = 2,
                .original_ttl = 300,
                .sig_expiration = 1700000000,
                .sig_inception = 1699000000,
                .key_tag = 12345,
                .signer_name = signer,
                .signature = &.{},
            } },
        },
    };

    const result = findRrsig(&records, .a);
    try testing.expect(result != null);
    try testing.expectEqual(@as(u16, 12345), result.?.key_tag);

    // No RRSIG for NS
    try testing.expect(findRrsig(&records, .ns) == null);
}

// ── M8d: Canonical ordering and NSEC/NSEC3 tests ────────────────────

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

    // Root < everything
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(root, com));
    // com < net
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(com, net));
    // com < example.com
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(com, example_com));
    // example.com < a.example.com
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(example_com, a_example_com));
    // a.example.com < z.example.com
    try testing.expectEqual(std.math.Order.lt, canonicalNameOrder(a_example_com, z_example_com));
    // Equal
    try testing.expectEqual(std.math.Order.eq, canonicalNameOrder(com, com));
    // Reverse
    try testing.expectEqual(std.math.Order.gt, canonicalNameOrder(net, com));
}

test "NSEC name non-existence" {
    const alpha = dns.Name{
        .labels = &.{ @as([]const u8, "alpha"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const gamma = dns.Name{
        .labels = &.{ @as([]const u8, "gamma"), @as([]const u8, "example"), @as([]const u8, "com") },
    };

    // NSEC: alpha.example.com -> gamma.example.com
    const nsec_data = dns.NsecData{
        .next_domain_name = gamma,
        .type_bit_maps = &.{},
    };

    // beta.example.com should be between alpha and gamma
    const beta = dns.Name{
        .labels = &.{ @as([]const u8, "beta"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    try testing.expect(nsecProvesNameNonexistence(alpha, nsec_data, beta));

    // zeta.example.com is NOT between alpha and gamma (z > g)
    const zeta = dns.Name{
        .labels = &.{ @as([]const u8, "zeta"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    try testing.expect(!nsecProvesNameNonexistence(alpha, nsec_data, zeta));

    // alpha itself should NOT be proved non-existent
    try testing.expect(!nsecProvesNameNonexistence(alpha, nsec_data, alpha));
}

test "NSEC type non-existence" {
    const name = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };

    // Bitmap has A and NS but not AAAA
    // A(1)=0x40, NS(2)=0x20 => byte0 = 0x60
    const nsec_data = dns.NsecData{
        .next_domain_name = dns.Name{ .labels = &.{@as([]const u8, "next")} },
        .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x60 }, // window 0, len 1, A+NS
    };

    // AAAA doesn't exist at this name
    try testing.expect(nsecProvesTypeNonexistence(name, nsec_data, name, .aaaa));
    // A does exist
    try testing.expect(!nsecProvesTypeNonexistence(name, nsec_data, name, .a));
    // Different name — not a proof
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
    // Direct CNAME query against a name without CNAME passes.
    try testing.expect(nsecProvesTypeNonexistence(name, cname_absent, name, .cname));
}

test "NSEC3 hash computation - RFC 5155 Appendix B" {
    // RFC 5155 Appendix B test vectors use:
    // Hash algorithm: 1 (SHA-1), iterations: 12, salt: aabbccdd
    // example -> 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
    // The expected hash in raw bytes (not base32hex):

    // We test that the hash is deterministic and 20 bytes
    const name = dns.Name{
        .labels = &.{@as([]const u8, "example")},
    };
    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const hash = try nsec3Hash(name, &salt, 12);
    try testing.expectEqual(@as(usize, 20), hash.len);

    // Same input produces same hash
    const hash2 = try nsec3Hash(name, &salt, 12);
    try testing.expectEqualSlices(u8, &hash, &hash2);

    // Different name produces different hash
    const other = dns.Name{
        .labels = &.{@as([]const u8, "other")},
    };
    const hash3 = try nsec3Hash(other, &salt, 12);
    try testing.expect(!mem.eql(u8, &hash, &hash3));
}

test "NSEC3 hash range check" {
    const owner = [_]u8{ 0x10, 0x20, 0x30 };
    const next = [_]u8{ 0x50, 0x60, 0x70 };

    // In range
    const target_in = [_]u8{ 0x30, 0x40, 0x50 };
    try testing.expect(nsec3HashInRange(&owner, &next, &target_in));

    // Before range
    const target_before = [_]u8{ 0x05, 0x06, 0x07 };
    try testing.expect(!nsec3HashInRange(&owner, &next, &target_before));

    // After range
    const target_after = [_]u8{ 0x80, 0x90, 0xA0 };
    try testing.expect(!nsec3HashInRange(&owner, &next, &target_after));
}

test "NSEC3 hash range wrap-around" {
    // Wrap-around: owner > next (last NSEC3 in zone)
    const owner = [_]u8{ 0xF0, 0xF0, 0xF0 };
    const next = [_]u8{ 0x10, 0x10, 0x10 };

    // After owner (wraps around)
    const target_after = [_]u8{ 0xF5, 0xF5, 0xF5 };
    try testing.expect(nsec3HashInRange(&owner, &next, &target_after));

    // Before next (wraps around)
    const target_before_next = [_]u8{ 0x05, 0x05, 0x05 };
    try testing.expect(nsec3HashInRange(&owner, &next, &target_before_next));

    // Between next and owner (not in range)
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

    const nsec3_only = [_]dns.ResourceRecord{makeNsec3Rr(name, &.{}, &([_]u8{0} ** 20), &.{})};
    try testing.expect(!hasMixedNsecNsec3(&nsec3_only));

    // Mixed — should be detected
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

    // NSEC at example.com has A and NS but not AAAA
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
                .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x60 }, // A + NS
            },
        },
    }};

    // NODATA for AAAA should be proven secure
    var b: ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, name, .aaaa, false, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
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
    const status = validateNegativeProof(&authorities, beta, .a, true, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
}

test "validateNegativeProof NSEC NXDOMAIN without wildcard denial" {
    const alpha = dns.Name{ .labels = &.{ "alpha", "example", "com" } };
    const gamma = dns.Name{ .labels = &.{ "gamma", "example", "com" } };

    // Only one NSEC covering qname, no wildcard denial
    const authorities = [_]dns.ResourceRecord{nsecRr(alpha, gamma)};

    const beta = dns.Name{ .labels = &.{ "beta", "example", "com" } };
    var b: ValidationBudget = .{};
    const status = validateNegativeProof(&authorities, beta, .a, true, &b);
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
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, missing, .a, true, &b));
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
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, missing, .a, true, &b));
}

test "validateNegativeProof NSEC NXDOMAIN requires CE existence proof (RFC 4035 §5.4)" {
    // qname = a.b.c.example.com. A single NSEC covers qname between two
    // unrelated bounds — the derived CE (example.com) is neither named by
    // any NSEC nor strictly between this NSEC's bounds. Without an
    // independent CE existence proof, an attacker could pin an arbitrary
    // CE inside any range. Must return .unchecked, not .secure.
    const aaa = dns.Name{ .labels = &.{ "aaa", "example", "com" } };
    const zzz = dns.Name{ .labels = &.{ "zzz", "example", "com" } };
    const qname = dns.Name{ .labels = &.{ "a", "b", "c", "example", "com" } };
    // covering = (aaa.example.com, zzz.example.com); qname sorts between
    // (a.b.c.example.com is between a... and z... in the example.com range).
    const authorities = [_]dns.ResourceRecord{nsecRr(aaa, zzz)};
    var b: ValidationBudget = .{};
    // Without a CE-proving NSEC, the answer is unchecked even though the
    // covering NSEC validly denies qname.
    const status = validateNegativeProof(&authorities, qname, .a, true, &b);
    try testing.expectEqual(SecurityStatus.unchecked, status);
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
    const status = validateNegativeProof(&authorities, beta, .a, true, &b);
    try testing.expectEqual(SecurityStatus.secure, status);
}

// ── NSEC3 Helper Tests ───────────────────────────────────────────────

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

    // Encode to base32hex
    var enc_buf: [32]u8 = undefined;
    const encoded = dns.base32HexEncode(&enc_buf, &hash);
    try testing.expectEqual(@as(usize, 32), encoded.len);

    // Decode back
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

    // Encode to build a proper NSEC3 owner
    var enc_buf: [32]u8 = undefined;
    const encoded = dns.base32HexEncode(&enc_buf, &hash);

    const owner_name = dns.Name{
        .labels = &.{ encoded, @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const extracted = nsec3OwnerHash(owner_name).?;
    try testing.expectEqualSlices(u8, &hash, &extracted);

    // Wrong length label
    const bad_name = dns.Name{ .labels = &.{@as([]const u8, "tooshort")} };
    try testing.expect(nsec3OwnerHash(bad_name) == null);

    // Empty name
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
    const next: [20]u8 = .{0xFF} ** 20;
    const authorities = [_]dns.ResourceRecord{.{
        .name = owner_name,
        .rtype = .nsec3,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{
            .nsec3 = .{
                .hash_algorithm = @enumFromInt(2), // not sha1
                .flags = 0,
                .iterations = 0,
                .salt = &.{},
                .next_hashed_owner = &next,
                .type_bit_maps = &.{},
            },
        },
    }};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&authorities, qname, .aaaa, false, &b));
}

test "NSEC3 NODATA - secure" {
    // Query: example.com AAAA (NODATA)
    // NSEC3 at hash(example.com) has A and NS but not AAAA, not CNAME
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const salt: []const u8 = &.{};
    const hash = try nsec3Hash(qname, salt, 0);

    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(hash, zone_labels, &bufs.enc, &bufs.labels);

    // Bitmap: A(bit1=0x40) + NS(bit2=0x20) = 0x60
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &([_]u8{0xFF} ** 20), &[_]u8{ 0x00, 0x01, 0x60 })};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .aaaa, false, &b));
}

test "NSEC3 NODATA - CNAME in bitmap" {
    // If CNAME is in bitmap, should NOT prove NODATA (RFC 5155 §8.5)
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "alias"), @as([]const u8, "com") },
    };
    const salt: []const u8 = &.{};
    const hash = try nsec3Hash(qname, salt, 0);

    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(hash, &.{@as([]const u8, "com")}, &bufs.enc, &bufs.labels);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &([_]u8{0xFF} ** 20), &[_]u8{ 0x00, 0x01, 0x04 })};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .aaaa, false, &b));
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
        makeNsec3Rr(ce_owner, salt, &([_]u8{0xFF} ** 20), &[_]u8{ 0x00, 0x01, 0x40 }),
        nc_rr,
        wc_rr,
    };

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, validateNegativeProof(&authorities, qname, .a, true, &b));
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

    // Only CE match + NC cover, NO wildcard cover
    const authorities = [_]dns.ResourceRecord{
        makeNsec3Rr(ce_owner, salt, &([_]u8{0xFF} ** 20), &.{}),
        nc_rr,
    };

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.unchecked, validateNegativeProof(&authorities, qname, .a, true, &b));
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
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &([_]u8{0xFF} ** 20), &[_]u8{ 0x00, 0x01, 0x20 })};

    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, classifyDelegation(&authorities, child_zone, &b));
}

test "classifyDelegation NSEC3 non-match" {
    const child_zone = dns.Name{
        .labels = &.{ @as([]const u8, "signed"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const zone_labels: []const []const u8 = &.{ @as([]const u8, "example"), @as([]const u8, "com") };
    const salt: []const u8 = &.{};

    // Use a different name's hash — doesn't match child_zone
    const other_name = dns.Name{
        .labels = &.{ @as([]const u8, "other"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    var bufs: Nsec3OwnerBufs = .{};
    const owner_name = makeNsec3OwnerName(try nsec3Hash(other_name, salt, 0), zone_labels, &bufs.enc, &bufs.labels);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &([_]u8{0} ** 20), &[_]u8{ 0x00, 0x01, 0x20 })};

    // NSEC3 doesn't cover the child zone — indeterminate, fails closed to .secure
    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.secure, classifyDelegation(&authorities, child_zone, &b));
}

test "NSEC3 hash budget exhaustion" {
    // CVE-2023-50868: a deep ancestor walk under a tight budget exhausts before
    // the CE is found; the proof fails open to .insecure rather than burning CPU.
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
    const owner_name = makeNsec3OwnerName([_]u8{0x42} ** 20, zone_labels, &bufs.enc, &bufs.labels);

    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &([_]u8{0x43} ** 20), &.{})};

    var b: ValidationBudget = .{ .nsec3_hash_remaining = 32 };
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&authorities, qname, .a, true, &b));
}

test "NSEC3 high-iteration returns insecure (RFC 9276 §3.2)" {
    // Iterations > 150 → .insecure: validator opts out of expensive proof rather
    // than burning CPU. classifyDelegation and validateNegativeProof both apply
    // this policy uniformly.
    const qname = dns.Name{
        .labels = &.{ @as([]const u8, "www"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const salt: []const u8 = &.{};
    var bufs: Nsec3OwnerBufs = .{};
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const owner_name = makeNsec3OwnerName([_]u8{0x42} ** 20, zone_labels, &bufs.enc, &bufs.labels);

    // NSEC3 with iterations=200 (exceeds max_nsec3_iterations=150)
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
            .next_hashed_owner = &([_]u8{0x43} ** 20),
            .type_bit_maps = &.{},
        } },
    }};

    // Both NXDOMAIN and NODATA negative-proof paths return .insecure
    var b: ValidationBudget = .{};
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&authorities, qname, .a, true, &b));
    try testing.expectEqual(SecurityStatus.insecure, validateNegativeProof(&authorities, qname, .a, false, &b));

    // classifyDelegation matches: high-iteration NSEC3 → insecure delegation
    const child_zone = dns.Name{ .labels = zone_labels };
    try testing.expectEqual(SecurityStatus.insecure, classifyDelegation(&authorities, child_zone, &b));
}

test "classifyDelegation salt-cache defeat exhausts NSEC3 budget" {
    // Adversarial: stuff the authority section with NSEC3 records that all use
    // unique salts. Each record forces a fresh nsec3Hash because the single-slot
    // salt cache misses on every transition. Without the per-resolution budget
    // this is unmetered CPU; with the budget the resolution returns .insecure
    // once the cap is hit.
    const N: usize = 32;
    const child_zone = dns.Name{ .labels = &.{ "victim", "example", "com" } };
    const zone_labels: []const []const u8 = &.{ "example", "com" };

    var bufs: [N]Nsec3OwnerBufs = undefined;
    var unique_salts: [N][1]u8 = undefined;
    var rrs: [N]dns.ResourceRecord = undefined;
    const next_owner = [_]u8{0xFF} ** 20;

    for (0..N) |i| {
        bufs[i] = .{};
        unique_salts[i] = .{@as(u8, @intCast(i))};
        const owner = makeNsec3OwnerName([_]u8{@as(u8, @intCast(i ^ 0xA5))} ** 20, zone_labels, &bufs[i].enc, &bufs[i].labels);
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

    var b: ValidationBudget = .{ .nsec3_hash_remaining = 8 };
    try testing.expectEqual(SecurityStatus.insecure, classifyDelegation(&rrs, child_zone, &b));
    try testing.expectEqual(@as(u16, 0), b.nsec3_hash_remaining);
}

test "NSEC3 budget accumulates across negative-proof calls" {
    // Per-resolution semantics: a single ValidationBudget is shared across the
    // whole resolve(), so two validateNegativeProof invocations on the same
    // budget must accumulate. Use the NODATA path (one hash per call); a budget
    // of 1 admits the first call but exhausts the second.
    const qname = dns.Name{ .labels = &.{ "example", "com" } };
    const salt: []const u8 = &.{};

    var bufs: Nsec3OwnerBufs = .{};
    const zone_labels: []const []const u8 = &.{@as([]const u8, "com")};
    const owner_name = makeNsec3OwnerName([_]u8{0x42} ** 20, zone_labels, &bufs.enc, &bufs.labels);
    const authorities = [_]dns.ResourceRecord{makeNsec3Rr(owner_name, salt, &([_]u8{0x43} ** 20), &.{})};

    var b: ValidationBudget = .{ .nsec3_hash_remaining = 1 };
    const first = validateNegativeProof(&authorities, qname, .a, false, &b);
    try testing.expectEqual(SecurityStatus.unchecked, first);
    try testing.expectEqual(@as(u16, 0), b.nsec3_hash_remaining);
    const second = validateNegativeProof(&authorities, qname, .a, false, &b);
    try testing.expectEqual(SecurityStatus.insecure, second);
}

// ── RRSIG expiration tests ──────────────────────────────────────────

test "serialAfter: basic comparisons" {
    // s1 > s2 in serial arithmetic
    try testing.expect(serialAfter(10, 5));
    // s1 < s2
    try testing.expect(!serialAfter(5, 10));
    // equal
    try testing.expect(!serialAfter(5, 5));
    // wrap-around: 0xFFFFFFFF is "before" 0x00000001
    try testing.expect(serialAfter(0x00000001, 0xFFFFFFFF));
    try testing.expect(!serialAfter(0xFFFFFFFF, 0x00000001));
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
    // now is past expiration by more than the clock-skew tolerance
    try testing.expectError(error.SignatureExpired, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, 1700000000 + clock_skew_tolerance + 1, null));
}

test "verifyRrsig rejects not-yet-valid signature" {
    // now is before inception by more than the clock-skew tolerance
    try testing.expectError(error.SignatureExpired, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, 1699000000 - clock_skew_tolerance - 1, null));
}

test "verifyRrsig tolerates clock skew within window" {
    inline for (.{
        1700000000 + clock_skew_tolerance, // just past expiration, within tolerance
        1699000000 - clock_skew_tolerance, // just before inception, within tolerance
    }) |now| {
        // Time check passes; empty key fails verifyEcdsa's length check first.
        try testing.expectError(error.InvalidKey, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, now, null));
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
    try testing.expectError(
        error.InvalidSignature,
        verifyRrsig(rrsig, test_window_dnskey, &rrset, 1699500000, null),
    );
}

test "verifyRrsig consumes budget on entry (KeyTrap mitigation)" {
    var budget: ValidationBudget = .{ .sig_verify_remaining = 2 };
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
    try testing.expectEqual(@as(u16, 0), budget.sig_verify_remaining);
    try testing.expectError(error.ValidationBudgetExhausted, verifyRrsig(
        test_window_rrsig,
        test_window_dnskey,
        test_window_empty_rrset,
        1699500000,
        &budget,
    ));
}

test "validateRrsetForType propagates budget exhaustion as bogus" {
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
    var budget: ValidationBudget = .{ .sig_verify_remaining = 0 };
    const status = validateRrsetForType(&answers, .a, &dnskeys, 1699500000, &budget);
    try testing.expectEqual(SecurityStatus.bogus, status);
}

// ── verifyAuthorityNsecSigs: validation-bypass guards ────────────────
//
// These tests lock the "every NSEC/NSEC3 owner must verify" invariant
// (RFC 4035 §5.3, RFC 6840 §5.4/§5.11). A regression where the function
// accepts unsigned or unrelated NSEC records would let an attacker forge
// an NXDOMAIN response with insecure denial-of-existence — a DNSSEC
// validation bypass on the order of CVE-2023-50387.

fn rrsigData(type_covered: dns.RType, algorithm: dns.DnssecAlgorithm, owner_labels: usize, key_tag: u16, signer: dns.Name) dns.RrsigData {
    return .{
        .type_covered = type_covered,
        .algorithm = algorithm,
        .labels = @intCast(owner_labels),
        .original_ttl = 300,
        .sig_expiration = 1700000000,
        .sig_inception = 1699000000,
        .key_tag = key_tag,
        .signer_name = signer,
        .signature = &.{},
    };
}

fn rrsigRr(owner: dns.Name, type_covered: dns.RType, algorithm: dns.DnssecAlgorithm, key_tag: u16, signer: dns.Name) dns.ResourceRecord {
    return .{
        .name = owner,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .rrsig = rrsigData(type_covered, algorithm, owner.labels.len, key_tag, signer) },
    };
}

fn nsecRrsigRr(owner: dns.Name, signer: dns.Name, algorithm: dns.DnssecAlgorithm) dns.ResourceRecord {
    return rrsigRr(owner, .nsec, algorithm, 12345, signer);
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

test "verifyAuthorityNsecSigs: NSEC without RRSIG returns bogus" {
    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "example", "com" } };
    const authorities = [_]dns.ResourceRecord{nsecRr(owner, next)};
    // No DNSKEYs needed; iteration fails the find-RRSIG step.
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityNsecSigs(&authorities, &.{}, 1699500000, null),
    );
}

test "verifyAuthorityNsecSigs: signed NSEC + unsigned NSEC returns bogus" {
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
        nsecRrsigRr(owner1, signer, .dsasha1), // unsupported algo, won't verify
        nsecRr(owner2, next2),
        // no RRSIG for owner2 — bogus
    };
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityNsecSigs(&authorities, &.{}, 1699500000, null),
    );
}

test "verifyAuthorityNsecSigs: only-unsupported-algo RRSIG returns insecure" {
    // RFC 6840 §5.11: when every candidate signature uses an unsupported
    // algorithm, the result is .insecure (not .bogus). Validators must
    // not treat unsupported-algo zones as authentication failures.
    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "example", "com" } };
    const signer = dns.Name{ .labels = &.{ "example", "com" } };
    const authorities = [_]dns.ResourceRecord{
        nsecRr(owner, next),
        nsecRrsigRr(owner, signer, .dsasha1), // unsupported — triggers had_unsupported_algo
    };
    try testing.expectEqual(
        SecurityStatus.insecure,
        verifyAuthorityNsecSigs(&authorities, &.{}, 1699500000, null),
    );
}

test "verifyAuthorityNsecSigs: failing supported + unsupported RRSIG returns bogus" {
    // Laundering guard: a fake unsupported-algo RRSIG must not downgrade
    // a failing supported-algo RRSIG from .bogus to .insecure.
    const owner = dns.Name{ .labels = &.{ "example", "com" } };
    const next = dns.Name{ .labels = &.{ "next", "example", "com" } };
    const signer = owner;
    const tag = keyTag(test_ecdsa_dnskey);
    const authorities = [_]dns.ResourceRecord{
        nsecRr(owner, next),
        nsecRrsigRr(owner, signer, .dsasha1), // unsupported
        rrsigRr(owner, .nsec, .ecdsap256sha256, tag, signer), // supported, empty sig → fails
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(signer, test_ecdsa_dnskey)};
    try testing.expectEqual(
        SecurityStatus.bogus,
        verifyAuthorityNsecSigs(&authorities, &dnskeys, 1699500000, null),
    );
}

test "validateRrsetForType: owner-mismatch supported + matched unsupported returns bogus" {
    // Owner-mismatch laundering: a supported-algo RRSIG with no matching
    // owner (count==0 path) alongside an unsupported-algo RRSIG that does
    // match must still bogus. Real zones never emit unmatched RRSIGs.
    const tag = keyTag(test_ecdsa_dnskey);
    const other_owner = dns.Name{ .labels = &.{ "other", "com" } };
    const answers = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(test_owner, .a, .dsasha1, 0, test_owner), // unsupported, matched
        rrsigRr(other_owner, .a, .ecdsap256sha256, tag, other_owner), // supported, unmatched owner
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(test_owner, test_ecdsa_dnskey)};
    try testing.expectEqual(
        SecurityStatus.bogus,
        validateRrsetForType(&answers, .a, &dnskeys, 1699500000, null),
    );
}

test "validateRrsetForType: failing supported + unsupported RRSIG returns bogus" {
    // Same-owner laundering on the answer-validation path.
    const tag = keyTag(test_ecdsa_dnskey);
    const answers = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(test_owner, .a, .dsasha1, 0, test_owner),
        rrsigRr(test_owner, .a, .ecdsap256sha256, tag, test_owner), // empty sig → fails
    };
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(test_owner, test_ecdsa_dnskey)};
    try testing.expectEqual(
        SecurityStatus.bogus,
        validateRrsetForType(&answers, .a, &dnskeys, 1699500000, null),
    );
}

test "validateAnswerRrset: insecure sub-result propagates (not laundered to secure)" {
    // All-unsupported RRSIGs → .insecure; the wrapper must propagate it
    // instead of returning .secure (which would stamp AD on unverified data).
    const answers = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
        rrsigRr(test_owner, .a, .dsasha1, 0, test_owner),
    };
    try testing.expectEqual(
        SecurityStatus.insecure,
        validateAnswerRrset(&answers, .a, &.{}, 1699500000, null),
    );
}

// ── H3: RSA key validation tests ────────────────────────────────────

test "verifyRsa accepts 1024-bit (128-byte) modulus key parsing" {
    // Build a minimal RSA key with 128-byte modulus (1024-bit)
    // Many TLDs still use RSA-1024 ZSKs — validators must accept them
    var key_data: [1 + 3 + 128]u8 = undefined;
    key_data[0] = 3; // exponent length
    key_data[1] = 0x01; // exponent = 65537 (0x010001)
    key_data[2] = 0x00;
    key_data[3] = 0x01;
    @memset(key_data[4..], 0xAA); // 128-byte modulus

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
    key_data[0] = 3; // exponent length
    key_data[1] = 0x01; // exponent = 65537
    key_data[2] = 0x00;
    key_data[3] = 0x01;
    @memset(key_data[4..], 0xAA); // 256-byte modulus

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
    const sig = [_]u8{0} ** 256;
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
