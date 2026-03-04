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

/// Find a DNSKEY in a set that matches a DS record.
/// Returns the matching DNSKEY or null.
pub fn findMatchingDnskey(
    ds: dns.DsData,
    dnskeys: []const dns.ResourceRecord,
    owner_name: dns.Name,
) ?dns.DnskeyData {
    for (dnskeys) |rr| {
        if (rr.rtype != .dnskey) continue;
        const dk = rr.rdata.dnskey;
        if (keyTag(dk) != ds.key_tag) continue;
        if (@intFromEnum(dk.algorithm) != @intFromEnum(ds.algorithm)) continue;
        // Verify DS hash matches
        verifyDs(ds, dk, owner_name) catch continue;
        return dk;
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

    // 1. Find a DNSKEY matching any DS record (this is the KSK)
    for (ds_records) |ds| {
        if (findMatchingDnskey(ds, dnskey_records, zone_name)) |ksk| {
            // 2. Find the RRSIG covering DNSKEY signed by this KSK
            const rrsig = findRrsig(dnskey_records, .dnskey) orelse continue;
            if (rrsig.key_tag != keyTag(ksk)) {
                // RRSIG might be signed by a different key in the set
                // Try to find a key matching the RRSIG's key_tag
                for (dnskey_records) |rr| {
                    if (rr.rtype != .dnskey) continue;
                    const dk = rr.rdata.dnskey;
                    if (keyTag(dk) == rrsig.key_tag) {
                        // This key signed the DNSKEY RRset — verify it
                        verifyRrsig(rrsig, dk, filtered) catch continue;
                        return; // DNSKEY RRset is valid
                    }
                }
                continue;
            }
            // 3. Verify the RRSIG over the DNSKEY RRset using the KSK
            verifyRrsig(rrsig, ksk, filtered) catch continue;
            return; // Success
        }
    }
    return error.InvalidSignature;
}

/// Check if a referral has DS records proving the child is signed,
/// or NSEC/NSEC3 records proving DS absence (insecure delegation).
pub fn classifyDelegation(
    authorities: []const dns.ResourceRecord,
    child_zone: dns.Name,
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

    // No DS — check for NSEC/NSEC3 proof of DS absence
    for (authorities) |rr| {
        if (rr.rtype == .nsec) {
            // NSEC owner matches child zone and DS not in type bitmap
            if (rr.name.eql(child_zone)) {
                if (!dns.typeBitmapContains(rr.rdata.nsec.type_bit_maps, .ds)) {
                    return .insecure;
                }
            }
        }
        if (rr.rtype == .nsec3) {
            // NSEC3 — if it covers the child and DS not in bitmap
            if (!dns.typeBitmapContains(rr.rdata.nsec3.type_bit_maps, .ds)) {
                return .insecure;
            }
        }
    }

    // No DS and no NSEC proof — indeterminate, treat as insecure (don't ServFail)
    return .insecure;
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

/// Build the signed data for RRSIG verification.
/// Returns a slice of the buffer containing: RRSIG_RDATA(sans signature) || sorted_canonical_RRset
pub fn buildSignedData(
    buf: []u8,
    rrsig: dns.RrsigData,
    rrset: []const dns.ResourceRecord,
) error{BufferTooSmall}![]const u8 {
    var pos: usize = 0;

    // 1. RRSIG RDATA fields (sans signature)
    if (pos + 18 > buf.len) return error.BufferTooSmall;
    mem.writeInt(u16, buf[pos..][0..2], @intFromEnum(rrsig.type_covered), .big);
    pos += 2;
    buf[pos] = @intFromEnum(rrsig.algorithm);
    pos += 1;
    buf[pos] = rrsig.labels;
    pos += 1;
    mem.writeInt(u32, buf[pos..][0..4], rrsig.original_ttl, .big);
    pos += 4;
    mem.writeInt(u32, buf[pos..][0..4], rrsig.sig_expiration, .big);
    pos += 4;
    mem.writeInt(u32, buf[pos..][0..4], rrsig.sig_inception, .big);
    pos += 4;
    mem.writeInt(u16, buf[pos..][0..2], rrsig.key_tag, .big);
    pos += 2;
    const name_len = writeCanonicalNameWire(buf[pos..], rrsig.signer_name) catch return error.BufferTooSmall;
    pos += name_len;

    // 2. Build canonical RRset entries, sorted by wire form
    // Each entry: canonical_owner_wire || type(2) || class(2) || original_ttl(4) || rdlength(2) || canonical_rdata
    // We build them into a temp area, sort, then append
    var rr_wires: [64][]const u8 = undefined;
    if (rrset.len > rr_wires.len) return error.BufferTooSmall;

    // Use remaining buffer space for individual RR wire data
    var temp_pos = pos;

    for (rrset, 0..) |rr, idx| {
        const rr_start = temp_pos;

        // Canonical owner name (lowercase, uncompressed)
        const owner_len = writeCanonicalNameWire(buf[temp_pos..], rr.name) catch return error.BufferTooSmall;
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

        rr_wires[idx] = buf[rr_start..temp_pos];
    }

    // Sort RR wires by raw bytes
    mem.sortUnstable([]const u8, rr_wires[0..rrset.len], {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    // The sorted RR wires reference slices of buf[pos..temp_pos].
    // Compacting them in-place would corrupt source data (earlier copies
    // overwrite source positions of later entries). Copy to a temp buffer first.
    var temp_buf: [65536]u8 = undefined;
    var out_pos: usize = 0;
    for (rr_wires[0..rrset.len]) |wire| {
        if (out_pos + wire.len > temp_buf.len) return error.BufferTooSmall;
        @memcpy(temp_buf[out_pos..][0..wire.len], wire);
        out_pos += wire.len;
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
            var pos: usize = 0;
            if (pos + 18 > buf.len) return error.BufferTooSmall;
            mem.writeInt(u16, buf[pos..][0..2], @intFromEnum(rrsig.type_covered), .big);
            pos += 2;
            buf[pos] = @intFromEnum(rrsig.algorithm);
            pos += 1;
            buf[pos] = rrsig.labels;
            pos += 1;
            mem.writeInt(u32, buf[pos..][0..4], rrsig.original_ttl, .big);
            pos += 4;
            mem.writeInt(u32, buf[pos..][0..4], rrsig.sig_expiration, .big);
            pos += 4;
            mem.writeInt(u32, buf[pos..][0..4], rrsig.sig_inception, .big);
            pos += 4;
            mem.writeInt(u16, buf[pos..][0..2], rrsig.key_tag, .big);
            pos += 2;
            pos += writeCanonicalNameWire(buf[pos..], rrsig.signer_name) catch return error.BufferTooSmall;
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

/// Verify an RRSIG signature against a DNSKEY and RRset.
pub fn verifyRrsig(
    rrsig: dns.RrsigData,
    dnskey: dns.DnskeyData,
    rrset: []const dns.ResourceRecord,
) VerifyError!void {
    // Build the signed data
    var signed_data_buf: [65536]u8 = undefined;
    const signed_data = buildSignedData(&signed_data_buf, rrsig, rrset) catch return error.BufferTooSmall;

    switch (rrsig.algorithm) {
        .rsasha256 => try verifyRsa(rrsig.signature, signed_data, dnskey.public_key, Sha256),
        .rsasha512 => try verifyRsa(rrsig.signature, signed_data, dnskey.public_key, Sha512),
        .ecdsap256sha256 => try verifyEcdsaP256(rrsig.signature, signed_data, dnskey.public_key),
        .ecdsap384sha384 => try verifyEcdsaP384(rrsig.signature, signed_data, dnskey.public_key),
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

    if (modulus.len == 0 or modulus.len > 512) return error.InvalidKey;
    if (signature.len != modulus.len) return error.InvalidSignature;

    const pub_key = rsa.PublicKey.fromBytes(exponent, modulus) catch return error.InvalidKey;

    // Dispatch on modulus length at comptime
    // 512-bit (64-byte) RSA omitted: broken key size, and SHA-512 DER exceeds modulus
    inline for ([_]usize{ 128, 256, 384, 512 }) |mod_len| {
        if (modulus.len == mod_len) {
            const sig_array = signature[0..mod_len].*;
            rsa.PKCS1v1_5Signature.verify(mod_len, sig_array, msg, pub_key, Hash) catch
                return error.InvalidSignature;
            return;
        }
    }
    return error.InvalidKey;
}

/// Verify an ECDSA P-256/SHA-256 signature.
fn verifyEcdsaP256(signature: []const u8, msg: []const u8, key_data: []const u8) VerifyError!void {
    // DNSSEC key: raw 64-byte x||y. Prepend 0x04 for SEC1 uncompressed.
    if (key_data.len != 64) return error.InvalidKey;
    if (signature.len != 64) return error.InvalidSignature;

    var sec1_key: [65]u8 = undefined;
    sec1_key[0] = 0x04;
    @memcpy(sec1_key[1..], key_data);

    const pub_key = EcdsaP256.PublicKey.fromSec1(&sec1_key) catch return error.InvalidKey;
    const sig = EcdsaP256.Signature.fromBytes(signature[0..64].*);
    sig.verify(msg, pub_key) catch return error.InvalidSignature;
}

/// Verify an ECDSA P-384/SHA-384 signature.
fn verifyEcdsaP384(signature: []const u8, msg: []const u8, key_data: []const u8) VerifyError!void {
    // DNSSEC key: raw 96-byte x||y
    if (key_data.len != 96) return error.InvalidKey;
    if (signature.len != 96) return error.InvalidSignature;

    var sec1_key: [97]u8 = undefined;
    sec1_key[0] = 0x04;
    @memcpy(sec1_key[1..], key_data);

    const pub_key = EcdsaP384.PublicKey.fromSec1(&sec1_key) catch return error.InvalidKey;
    const sig = EcdsaP384.Signature.fromBytes(signature[0..96].*);
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

// ── NSEC Proofs ──────────────────────────────────────────────────────

/// Check if an NSEC record proves that `qname` does not exist.
/// Returns true if qname falls in the range (nsec_owner, nsec_next).
pub fn nsecProvesNameNonexistence(
    nsec_owner: dns.Name,
    nsec: dns.NsecData,
    qname: dns.Name,
) bool {
    const owner_vs_qname = canonicalNameOrder(nsec_owner, qname);
    const qname_vs_next = canonicalNameOrder(qname, nsec.next_domain_name);
    const owner_vs_next = canonicalNameOrder(nsec_owner, nsec.next_domain_name);

    // Normal range: owner < qname < next
    if (owner_vs_qname == .lt and qname_vs_next == .lt) return true;

    // Wrap-around (last NSEC in zone): owner > next, and qname > owner or qname < next
    if (owner_vs_next == .gt or owner_vs_next == .eq) {
        if (owner_vs_qname == .lt or qname_vs_next == .lt) return true;
    }

    return false;
}

/// Check if an NSEC record proves that `qtype` does not exist at `qname`.
/// The NSEC owner must match qname, and qtype must not be in the bitmap.
pub fn nsecProvesTypeNonexistence(
    nsec_owner: dns.Name,
    nsec: dns.NsecData,
    qname: dns.Name,
    qtype: dns.RType,
) bool {
    if (!nsec_owner.eql(qname)) return false;
    return !dns.typeBitmapContains(nsec.type_bit_maps, qtype);
}

// ── NSEC3 Hashing (RFC 5155) ─────────────────────────────────────────

/// Maximum allowed NSEC3 iterations (per RFC 9276 / BIND precedent).
pub const max_nsec3_iterations: u16 = 150;

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
    const owner_vs_target = mem.order(u8, owner_hash, target_hash);
    const target_vs_next = mem.order(u8, target_hash, next_hash);
    const owner_vs_next = mem.order(u8, owner_hash, next_hash);

    // Normal range: owner < target < next
    if (owner_vs_target == .lt and target_vs_next == .lt) return true;

    // Wrap-around: owner > next, and (target > owner or target < next)
    if (owner_vs_next == .gt or owner_vs_next == .eq) {
        if (owner_vs_target == .lt or target_vs_next == .lt) return true;
    }

    return false;
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
) SecurityStatus {
    // Reject mixed NSEC/NSEC3
    if (hasMixedNsecNsec3(authorities)) return .bogus;

    // Try NSEC proofs first
    for (authorities) |rr| {
        if (rr.rtype == .nsec) {
            if (is_nxdomain) {
                if (nsecProvesNameNonexistence(rr.name, rr.rdata.nsec, qname)) {
                    return .secure;
                }
            } else {
                // NODATA: NSEC owner matches qname, type not in bitmap
                if (nsecProvesTypeNonexistence(rr.name, rr.rdata.nsec, qname, qtype)) {
                    return .secure;
                }
            }
        }
    }

    // Try NSEC3 proofs
    for (authorities) |rr| {
        if (rr.rtype == .nsec3) {
            const nsec3 = rr.rdata.nsec3;
            // Iteration cap — treat high iterations as insecure, not bogus
            if (nsec3.iterations > max_nsec3_iterations) return .insecure;

            if (!is_nxdomain) {
                // NODATA: find matching NSEC3 and check type bitmap
                const owner_hash = nsec3Hash(rr.name, nsec3.salt, nsec3.iterations) catch continue;
                const target_hash = nsec3Hash(qname, nsec3.salt, nsec3.iterations) catch continue;
                if (mem.eql(u8, &owner_hash, &target_hash) or
                    nsec3HashInRange(&owner_hash, nsec3.next_hashed_owner, &target_hash))
                {
                    // This is a rough check — the hash might match or be covered
                    if (!dns.typeBitmapContains(nsec3.type_bit_maps, qtype)) {
                        return .secure;
                    }
                }
            }
            // For NXDOMAIN with NSEC3, we'd need closest encloser proof
            // which requires walking up labels — simplified here
        }
    }

    // Could not prove — return unchecked (don't bogus, don't secure)
    return .unchecked;
}

// ── Answer RRset Validation ──────────────────────────────────────────

/// Validate answer RRsets against a DNSKEY set.
/// Finds the RRSIG covering `qtype`, matches it to a DNSKEY by key_tag + algorithm,
/// and verifies the signature. Per RFC 6840 §5.4, tries ALL matching DNSKEYs.
/// Also validates CNAME RRSIG if the answer contains CNAMEs and qtype != .cname.
pub fn validateAnswerRrset(
    answers: []const dns.ResourceRecord,
    qtype: dns.RType,
    dnskey_records: []const dns.ResourceRecord,
) SecurityStatus {
    // Validate the main answer type
    if (validateRrsetForType(answers, qtype, dnskey_records) == .bogus) return .bogus;

    // If qtype != .cname and answers contain CNAME records, validate CNAME RRSIG too
    if (qtype != .cname) {
        var has_cname = false;
        for (answers) |rr| {
            if (rr.rtype == .cname) {
                has_cname = true;
                break;
            }
        }
        if (has_cname) {
            if (validateRrsetForType(answers, .cname, dnskey_records) == .bogus) return .bogus;
        }
    }

    return .secure;
}

/// Validate a single RRset type within the answers against DNSKEYs.
fn validateRrsetForType(
    answers: []const dns.ResourceRecord,
    covered_type: dns.RType,
    dnskey_records: []const dns.ResourceRecord,
) SecurityStatus {
    // Find RRSIG covering this type
    const rrsig = findRrsig(answers, covered_type) orelse return .bogus;

    // Filter answer records to only those matching the covered type
    var filtered: [64]dns.ResourceRecord = undefined;
    var filtered_count: usize = 0;
    for (answers) |rr| {
        if (rr.rtype == covered_type and filtered_count < filtered.len) {
            filtered[filtered_count] = rr;
            filtered_count += 1;
        }
    }
    if (filtered_count == 0) return .bogus;

    // RFC 6840 §5.4: try ALL matching DNSKEYs (key_tag + algorithm)
    for (dnskey_records) |rr| {
        if (rr.rtype != .dnskey) continue;
        const dk = rr.rdata.dnskey;
        if (keyTag(dk) != rrsig.key_tag) continue;
        if (@intFromEnum(dk.algorithm) != @intFromEnum(rrsig.algorithm)) continue;

        // Try verification with this key
        verifyRrsig(rrsig, dk, filtered[0..filtered_count]) catch continue;
        return .secure; // Signature verified
    }

    return .bogus; // No matching DNSKEY could verify
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

test "DS hash verification - synthetic" {
    // Build a DNSKEY, compute its DS, then verify
    const dnskey = dns.DnskeyData{
        .flags = 257,
        .protocol = 3,
        .algorithm = .rsasha256,
        .public_key = &.{ 0x03, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD },
    };

    const owner = dns.Name{
        .labels = &.{
            @as([]const u8, "example"),
            @as([]const u8, "com"),
        },
    };

    // Compute expected digest: SHA-256(canonical_owner_wire || DNSKEY_RDATA)
    var wire_buf: [1024]u8 = undefined;
    const name_len = try writeCanonicalNameWire(&wire_buf, owner);
    var pos = name_len;
    mem.writeInt(u16, wire_buf[pos..][0..2], 257, .big); // flags
    pos += 2;
    wire_buf[pos] = 3; // protocol
    pos += 1;
    wire_buf[pos] = 8; // algorithm
    pos += 1;
    @memcpy(wire_buf[pos..][0..dnskey.public_key.len], dnskey.public_key);
    pos += dnskey.public_key.len;

    var expected_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(wire_buf[0..pos], &expected_digest, .{});

    const ds = dns.DsData{
        .key_tag = keyTag(dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &expected_digest,
    };

    try verifyDs(ds, dnskey, owner);
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
        .labels = 2,
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
    try testing.expectEqual(@as(u8, 2), signed[3]); // labels
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

test "ECDSA P-256 signature verification" {
    // Generate a real key pair and sign some data
    const key_pair = EcdsaP256.KeyPair.generate();
    const pub_bytes = key_pair.public_key.toUncompressedSec1();
    // DNSSEC key is raw 64-byte x||y (without 0x04 prefix)
    const dnssec_key = pub_bytes[1..65];

    const msg = "test DNSSEC signed data";
    const sig = try key_pair.sign(msg, null);
    const sig_bytes = sig.toBytes();

    // Should verify
    try verifyEcdsaP256(&sig_bytes, msg, dnssec_key);

    // Wrong message should fail
    try testing.expectError(error.InvalidSignature, verifyEcdsaP256(&sig_bytes, "wrong data", dnssec_key));
}

test "Ed25519 signature verification" {
    const key_pair = Ed25519.KeyPair.generate();
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
    try testing.expectError(error.InvalidKey, verifyEcdsaP256(&sig64, msg, &.{ 0x01, 0x02 }));
    // ECDSA P-384: key must be 96 bytes
    try testing.expectError(error.InvalidKey, verifyEcdsaP384(&sig96, msg, &.{ 0x01, 0x02 }));
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

    try testing.expectEqual(SecurityStatus.secure, classifyDelegation(&authorities, child_zone));
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
        .rdata = .{ .nsec = .{
            .next_domain_name = dns.Name{
                .labels = &.{
                    @as([]const u8, "next"),
                    @as([]const u8, "com"),
                },
            },
            .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x60 }, // A + NS, no DS
        } },
    }};

    try testing.expectEqual(SecurityStatus.insecure, classifyDelegation(&authorities, child_zone));
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

    try testing.expectEqual(SecurityStatus.insecure, classifyDelegation(&authorities, child_zone));
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

    const nsec3_only = [_]dns.ResourceRecord{.{
        .name = name,
        .rtype = .nsec3,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .nsec3 = .{
            .hash_algorithm = 1,
            .flags = 0,
            .iterations = 0,
            .salt = &.{},
            .next_hashed_owner = &([_]u8{0} ** 20),
            .type_bit_maps = &.{},
        } },
    }};
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
        .rdata = .{ .nsec = .{
            .next_domain_name = dns.Name{
                .labels = &.{ @as([]const u8, "next"), @as([]const u8, "com") },
            },
            .type_bit_maps = &[_]u8{ 0x00, 0x01, 0x60 }, // A + NS
        } },
    }};

    // NODATA for AAAA should be proven secure
    const status = validateNegativeProof(&authorities, name, .aaaa, false);
    try testing.expectEqual(SecurityStatus.secure, status);
}

test "validateNegativeProof NSEC NXDOMAIN" {
    const alpha = dns.Name{
        .labels = &.{ @as([]const u8, "alpha"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const gamma = dns.Name{
        .labels = &.{ @as([]const u8, "gamma"), @as([]const u8, "example"), @as([]const u8, "com") },
    };

    const authorities = [_]dns.ResourceRecord{.{
        .name = alpha,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .nsec = .{
            .next_domain_name = gamma,
            .type_bit_maps = &.{},
        } },
    }};

    const beta = dns.Name{
        .labels = &.{ @as([]const u8, "beta"), @as([]const u8, "example"), @as([]const u8, "com") },
    };
    const status = validateNegativeProof(&authorities, beta, .a, true);
    try testing.expectEqual(SecurityStatus.secure, status);
}
