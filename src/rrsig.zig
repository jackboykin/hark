//! RRSIG verification: the canonical signed data (RFC 4034 §3.1.8.1, §6.2),
//! each algorithm's math, the memo of what verified, and the KeyTrap budget
//! bounding the work.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Blake3 = std.crypto.hash.Blake3;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

// See verifyRsa for why we drive std.crypto.ff directly.
const RsaModulus = std.crypto.ff.Modulus(4096);
const RsaFe = RsaModulus.Fe;

pub const VerifyError = error{
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

const max_nsec3_blocks_per_resolution: u32 = 8192;

/// Per-resolution DNSSEC CPU budget, shared by every cell a client question
/// demands (`graph.Budget`). Exactly `max` draws succeed; the rest refuse.
pub const ValidationBudget = struct {
    sig_verify_spent: u32 = 0,
    max_sig_verify: u32 = max_sig_verify_per_resolution,
    nsec3_blocks_spent: u32 = 0,
    max_nsec3_blocks: u32 = max_nsec3_blocks_per_resolution,

    fn consumeVerify(self: *ValidationBudget) error{ValidationBudgetExhausted}!void {
        if (self.sig_verify_spent >= self.max_sig_verify) return error.ValidationBudgetExhausted;
        self.sig_verify_spent += 1;
    }

    pub fn exhausted(self: *const ValidationBudget) bool {
        return self.sig_verify_spent >= self.max_sig_verify or self.nsec3Exhausted();
    }

    pub fn nsec3Exhausted(self: *const ValidationBudget) bool {
        return self.nsec3_blocks_spent >= self.max_nsec3_blocks;
    }

    pub fn consumeNsec3(self: *ValidationBudget, blocks: u32) error{ValidationBudgetExhausted}!void {
        if (blocks > self.max_nsec3_blocks - @min(self.nsec3_blocks_spent, self.max_nsec3_blocks)) {
            self.nsec3_blocks_spent = self.max_nsec3_blocks;
            return error.ValidationBudgetExhausted;
        }
        self.nsec3_blocks_spent += blocks;
    }
};

/// Signatures that verified, remembered by what the math saw: algorithm,
/// key, signature and the digest of the signed data (RFC 4034 §3.1.8.1).
/// The RRSIG header is in that data, so an entry for an expired signature
/// is unreachable once `verifyRrsig` refuses the window; nothing expires or
/// invalidates. A hit decides nothing the math wouldn't: every check before
/// the crypto still runs, and the budget is charged first.
pub const VerifyMemo = struct {
    /// Empty remembers nothing.
    sets: []Set = &.{},
    hits: u64 = 0,
    misses: u64 = 0,

    /// 256 bits: an attacker plants tags with their own zone's valid
    /// signatures, so a forgery is a birthday search over the tag width.
    const Tag = [32]u8;
    /// One cache line; way 0 is the more recent.
    const Set = extern struct { ways: [2]Tag align(64) };
    const bytes = 256 * 1024;

    pub fn init(gpa: mem.Allocator) !VerifyMemo {
        const sets = try gpa.alloc(Set, bytes / @sizeOf(Set));
        // Tags are public: reused memory holding one would be a forgery.
        @memset(sets, .{ .ways = @splat(@splat(0)) });
        return .{ .sets = sets };
    }

    pub fn deinit(m: *VerifyMemo, gpa: mem.Allocator) void {
        gpa.free(m.sets);
    }

    /// Lengths framed: an RSA key and signature are both variable, and
    /// bytes moved across their boundary must not name the same entry.
    fn tag(algorithm: dns.DnssecAlgorithm, key: []const u8, signature: []const u8, digest: []const u8) Tag {
        var frame: [5]u8 = undefined;
        frame[0] = @backingInt(algorithm);
        mem.writeInt(u16, frame[1..3], @intCast(key.len), .big);
        mem.writeInt(u16, frame[3..5], @intCast(signature.len), .big);
        var h = Blake3.init(.{});
        h.update(&frame);
        h.update(key);
        h.update(signature);
        h.update(digest);
        var t: Tag = undefined;
        h.final(&t);
        return t;
    }

    fn set(m: *VerifyMemo, t: *const Tag) *Set {
        return &m.sets[mem.readInt(u32, t[0..4], .little) & (m.sets.len - 1)];
    }

    /// A miss is counted even when empty: the math runs either way.
    fn recall(m: *VerifyMemo, t: *const Tag) bool {
        if (m.sets.len != 0) {
            const s = m.set(t);
            if (mem.eql(u8, &s.ways[0], t)) {
                m.hits += 1;
                return true;
            }
            if (mem.eql(u8, &s.ways[1], t)) {
                s.ways = .{ t.*, s.ways[0] };
                m.hits += 1;
                return true;
            }
        }
        m.misses += 1;
        return false;
    }

    fn remember(m: *VerifyMemo, t: *const Tag) void {
        if (m.sets.len == 0) return;
        const s = m.set(t);
        s.ways = .{ t.*, s.ways[0] };
    }
};

/// Compute the key tag for a DNSKEY record per RFC 4034 Appendix B.
/// The key tag is a checksum over the DNSKEY RDATA wire format.
pub fn keyTag(dnskey: dns.DnskeyData) u16 {
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

pub fn writeCanonicalNameWire(buf: []u8, name: dns.Name) error{BufferTooSmall}!usize {
    return writeNameWire(buf, name, true);
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

/// RFC 4034 §3.1.8.1 signed data: RRSIG_RDATA (sans signature) followed by
/// the RRset in canonical form sorted by RDATA. Held as parts so verifiers
/// stream it into their hash; nothing needs it contiguous.
pub const SignedData = struct {
    const Entry = struct { wire: []const u8, rdata: []const u8 };
    pub const max_entries = 64;

    header: []const u8,
    entries: [max_entries]Entry = undefined,
    len: usize = 0,

    fn raw(bytes: []const u8) SignedData {
        return .{ .header = bytes };
    }

    pub fn feed(self: *const SignedData, hasher: anytype) void {
        hasher.update(self.header);
        for (self.entries[0..self.len]) |e| hasher.update(e.wire);
    }
};

/// Canonical entries are written into `buf` in RRset order and sorted by
/// slice, so the buffer only ever holds one copy.
pub fn buildSignedData(
    buf: []u8,
    rrsig: dns.RrsigData,
    rrset: []const dns.ResourceRecord,
) error{BufferTooSmall}!SignedData {
    const pos: usize = try writeRrsigHeaderWire(buf, rrsig);
    var out = SignedData{ .header = buf[0..pos], .len = rrset.len };
    if (rrset.len > out.entries.len) return error.BufferTooSmall;
    const entries = &out.entries;

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
    mem.sortUnstable(SignedData.Entry, entries[0..rrset.len], {}, struct {
        fn lessThan(_: void, a: SignedData.Entry, b: SignedData.Entry) bool {
            return mem.order(u8, a.rdata, b.rdata) == .lt;
        }
    }.lessThan);
    return out;
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
            // RFC 6840 §5.1: NSEC next_domain_name is the one field never folded.
            pos += try writeNameWire(buf[pos..], nsec_data.next_domain_name, false);
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
pub fn tryVerifyRrsig(
    rrsig: dns.RrsigData,
    dnskey: dns.DnskeyData,
    rrset: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *ValidationBudget,
    memo: *VerifyMemo,
) error{ValidationBudgetExhausted}!bool {
    verifyRrsig(rrsig, dnskey, rrset, now_u32, budget, memo) catch |e| switch (e) {
        error.ValidationBudgetExhausted => return error.ValidationBudgetExhausted,
        else => return false,
    };
    return true;
}

pub fn verifyRrsig(
    rrsig: dns.RrsigData,
    dnskey: dns.DnskeyData,
    rrset: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *ValidationBudget,
    memo: *VerifyMemo,
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
    // BIND.
    if (rrsig.type_covered == .soa or rrsig.type_covered == .ns) {
        for (rrset) |rr| {
            if (!rr.name.eql(rrsig.signer_name)) return error.InvalidSignature;
        }
    }

    // RFC 4035 §5.3.1 validity period, with asymmetric clock-skew tolerance.
    const skew_ahead = now_u32 +% inception_skew_tolerance;
    if (dns.serialAfter(rrsig.sig_inception, skew_ahead)) return error.SignatureExpired;
    if (dns.serialAfter(now_u32, rrsig.sig_expiration)) return error.SignatureExpired;

    // A cold burst's largest signed data was 4.3 KiB (RSA DNSKEY rollover);
    // spilling only TCP-sized sets keeps 64 KiB off every validating stack.
    var canonical_buf: [8192]u8 = undefined;
    var spill: []u8 = &.{};
    defer std.heap.page_allocator.free(spill);
    const data = buildSignedData(&canonical_buf, rrsig, rrset) catch data: {
        spill = std.heap.page_allocator.alloc(u8, 65536) catch return error.BufferTooSmall;
        break :data try buildSignedData(spill, rrsig, rrset);
    };

    switch (rrsig.algorithm) {
        inline .rsasha1, .rsasha1_nsec3, .rsasha256, .rsasha512, .ecdsap256sha256, .ecdsap384sha384, .ed25519, .mldsa44 => |alg| {
            var digest: [Digest(alg).digest_length]u8 = undefined;
            var hash = Digest(alg).init(.{});
            data.feed(&hash);
            hash.final(&digest);
            const t = VerifyMemo.tag(alg, dnskey.public_key, rrsig.signature, &digest);
            if (memo.recall(&t)) {
                // The gate runs Debug: every hit in every scenario is re-proven.
                if (builtin.mode == .debug) verifyMath(alg, rrsig.signature, &data, &digest, dnskey.public_key) catch unreachable;
                return;
            }
            try verifyMath(alg, rrsig.signature, &data, &digest, dnskey.public_key);
            memo.remember(&t);
        },
        else => return error.UnsupportedAlgorithm,
    }
}

/// What an algorithm signs: RSA and ECDSA sign this digest of the data, so
/// the memo assumes nothing the algorithm doesn't. Ed25519 and ML-DSA hash
/// the data themselves; SHA-256 only names their entries.
fn Digest(comptime algorithm: dns.DnssecAlgorithm) type {
    return switch (algorithm) {
        .rsasha1, .rsasha1_nsec3 => Sha1,
        .rsasha256, .ecdsap256sha256, .ed25519, .mldsa44 => Sha256,
        .ecdsap384sha384 => Sha384,
        .rsasha512 => Sha512,
        else => @compileError("no verifier for " ++ @tagName(algorithm)),
    };
}

/// RFC 8624 §3.1: MUST validate RSASHA1/RSASHA1-NSEC3 even though they
/// are NOT RECOMMENDED for signing — signing-not-recommended is not
/// validation-unsupported. The same set as `verifyRrsig`'s prongs.
pub fn isSupportedAlgorithm(algo: dns.DnssecAlgorithm) bool {
    return switch (algo) {
        .rsasha1, .rsasha1_nsec3, .rsasha256, .rsasha512, .ecdsap256sha256, .ecdsap384sha384, .ed25519, .mldsa44 => true,
        else => false,
    };
}

/// A function of its arguments alone, or remembered hits would bypass the
/// change: policy (distrusting an algorithm, a key-size floor) runs before.
fn verifyMath(
    comptime algorithm: dns.DnssecAlgorithm,
    signature: []const u8,
    data: *const SignedData,
    digest: *const [Digest(algorithm).digest_length]u8,
    key: []const u8,
) VerifyError!void {
    return switch (algorithm) {
        .rsasha1, .rsasha1_nsec3, .rsasha256, .rsasha512 => verifyRsa(Digest(algorithm), signature, digest, key),
        .ecdsap256sha256 => verifyEcdsa(EcdsaP256, signature, digest, key),
        .ecdsap384sha384 => verifyEcdsa(EcdsaP384, signature, digest, key),
        .ed25519 => verifyEd25519(signature, data, key),
        .mldsa44 => verifyMlDsa(signature, data, key),
        else => comptime unreachable,
    };
}

/// Parse an RFC 3110 RSA public key and verify a PKCS#1 v1.5 signature.
fn verifyRsa(comptime Hash: type, signature: []const u8, digest: *const [Hash.digest_length]u8, key_data: []const u8) VerifyError!void {
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
    // whole budget — 96 x 31.6 ms = 3.0 s of CPU for one query on the one
    // graph thread.
    //
    // 8 bytes admits xelerance.com's 5-byte e = 2^32+1 with room;
    // RsaFe.fromBytes alone only bounds it below the modulus (511 bytes).
    if (exponent.len > 8) return error.InvalidKey;

    // 1024-bit minimum (RFC 6781 recommends 2048, but 1024-bit ZSKs are still
    // common, TLDs included). No step: RFC 3110 fixes no size and the wild
    // has odd ones (gob.cl's KSK is 2024 bits; an 8-byte step SERVFAILed it).
    if (modulus.len < 128 or modulus.len > 512) return error.InvalidKey;
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
    pkcs1v15Encode(em_expected[0..modulus.len], Hash, digest);

    // Xor-fold compare: no data-dependent branch, so still constant-time —
    // though EM in signature *verification* is public data anyway.
    var diff: u8 = 0;
    for (em_dec[0..modulus.len], em_expected[0..modulus.len]) |a, b| diff |= a ^ b;
    if (diff != 0) return error.InvalidSignature;
}

/// EMSA-PKCS1-v1_5 (RFC 8017 §9.2); the stdlib's is private.
fn pkcs1v15Encode(em: []u8, comptime Hash: type, digest: *const [Hash.digest_length]u8) void {
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
    @memcpy(em[idx..][0..Hash.digest_length], digest);
    idx -= hash_der.len;
    @memcpy(em[idx..][0..hash_der.len], hash_der);
    idx -= 1;
    em[idx] = 0x00;
    @memset(em[2..idx], 0xff);
    em[1] = 0x01;
    em[0] = 0x00;
}

/// Verify an ECDSA signature (RFC 6605: raw x||y key, r||s signature) per
/// FIPS 186-5 §6.4.2. std's Verifier computes u1·G and u2·Q separately and
/// normalises the sum to affine; one double-base multiplication shares the
/// doublings, and comparing r·Z against the projective X skips the inversion.
fn verifyEcdsa(comptime Ecdsa: type, signature: []const u8, digest: *const [Ecdsa.Hash.digest_length]u8, key_data: []const u8) VerifyError!void {
    const Curve = Ecdsa.Curve;
    const Scalar = Curve.scalar.Scalar;
    const len = Curve.scalar.encoded_length;
    if (key_data.len != 2 * len) return error.InvalidKey;
    if (signature.len != 2 * len) return error.InvalidSignature;

    var sec1: [1 + 2 * len]u8 = undefined;
    sec1[0] = 0x04;
    @memcpy(sec1[1..], key_data);
    const q = Curve.fromSec1(&sec1) catch return error.InvalidKey;

    const r_bytes = signature[0..len].*;
    const r = Scalar.fromBytes(r_bytes, .big) catch return error.InvalidSignature;
    const s = Scalar.fromBytes(signature[len..][0..len].*, .big) catch return error.InvalidSignature;
    if (r.isZero() or s.isZero()) return error.InvalidSignature;

    var wide: [64]u8 = @splat(0);
    wide[64 - digest.len ..].* = digest.*;
    const e = Scalar.fromBytes64(wide, .big);

    const w = s.invert();
    const point = Curve.mulDoubleBasePublic(Curve.basePoint, e.mul(w).toBytes(.little), q, r.mul(w).toBytes(.little), .little) catch
        return error.InvalidSignature;

    // x = X/Z lies in [0, p) and must equal r mod n: x is r, or r + n when that is below p.
    const r_fe = Curve.Fe.fromBytes(r_bytes, .big) catch unreachable; // r < n < p
    if (point.x.equivalent(r_fe.mul(point.z))) return;
    const Int = @Int(.unsigned, 8 * len);
    const n = Curve.scalar.field_order;
    if (mem.readInt(Int, &r_bytes, .big) < Curve.Fe.field_order - n) {
        const n_fe = comptime Curve.Fe.fromInt(n) catch unreachable;
        if (point.x.equivalent(r_fe.add(n_fe).mul(point.z))) return;
    }
    return error.InvalidSignature;
}

fn verifyEd25519(signature: []const u8, data: *const SignedData, key_data: []const u8) VerifyError!void {
    if (key_data.len != 32) return error.InvalidKey;
    if (signature.len != 64) return error.InvalidSignature;

    const pub_key = Ed25519.PublicKey.fromBytes(key_data[0..32].*) catch return error.InvalidKey;
    const sig = Ed25519.Signature.fromBytes(signature[0..64].*);
    var verifier = sig.verifier(pub_key) catch return error.InvalidSignature;
    data.feed(&verifier);
    verifier.verify() catch return error.InvalidSignature;
}

/// draft-westerbaan-dnssec-mldsa §3-4: raw FIPS 204 encodings, pure
/// (non-prehash) ML-DSA-44 with an empty context string.
fn verifyMlDsa(signature: []const u8, data: *const SignedData, key_data: []const u8) VerifyError!void {
    if (key_data.len != MlDsa44.PublicKey.encoded_length) return error.InvalidKey;
    if (signature.len != MlDsa44.Signature.encoded_length) return error.InvalidSignature;

    const pub_key = MlDsa44.PublicKey.fromBytes(key_data[0..MlDsa44.PublicKey.encoded_length].*) catch return error.InvalidKey;
    const sig = MlDsa44.Signature.fromBytes(signature[0..MlDsa44.Signature.encoded_length].*) catch return error.InvalidSignature;
    var verifier = sig.verifier(pub_key) catch return error.InvalidSignature;
    data.feed(&verifier);
    verifier.verify() catch return error.InvalidSignature;
}

/// How long an RRset this signature verified may be held: RFC 4034 §3.1.2
/// Original TTL or RFC 4035 §5.3.3 remaining window, whichever is shorter.
pub fn ttlCap(sig: dns.RrsigData, now_u32: u32) u32 {
    return @min(sig.original_ttl, dns.secondsUntil(sig.sig_expiration, now_u32));
}

/// RFC 4034 §3.1.3: RRSIG labels exclude a leading `*`.
pub fn signedLabels(name: dns.Name) usize {
    const star = name.labels.len > 0 and mem.eql(u8, name.labels[0], "*");
    return name.labels.len - @intFromBool(star);
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
    try testing.expect(isSupportedAlgorithm(.mldsa44));
    // Algorithms RFC 8624 declares MUST NOT use for either signing or
    // validation should still register as unsupported.
    try testing.expect(!isSupportedAlgorithm(.rsamd5));
    try testing.expect(!isSupportedAlgorithm(.dsasha1));
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

pub const test_owner = dns.Name{
    .labels = &.{
        @as([]const u8, "example"),
        @as([]const u8, "com"),
    },
};

const TestFlatten = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,
    fn update(self: *TestFlatten, b: []const u8) void {
        @memcpy(self.buf[self.len..][0..b.len], b);
        self.len += b.len;
    }
};

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
    var flat = TestFlatten{};
    (try buildSignedData(&buf, rrsig, &rrset)).feed(&flat);
    const signed = flat.buf[0..flat.len];

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
    var flat = TestFlatten{};
    (try buildSignedData(&buf, rrsig, &rrset)).feed(&flat);
    const signed = flat.buf[0..flat.len];

    // After the RRSIG header (18 bytes) + signer name (13 bytes) = offset 31
    const rr_start = 31;
    // Owner in signed data must be *.example.com = \x01*\x07example\x03com\x00 (16 bytes)
    // NOT \x03foo\x07example\x03com\x00 (17 bytes)
    const expected_wc_owner = "\x01*\x07example\x03com\x00";
    try testing.expectEqualSlices(u8, expected_wc_owner, signed[rr_start..][0..expected_wc_owner.len]);
}

test "ECDSA P-384 signature verification" {
    // The sim signs only P-256; this is P-384's one gate.
    const key_pair = EcdsaP384.KeyPair.generate(testing.io);
    const dnssec_key = key_pair.public_key.toUncompressedSec1()[1..];
    const msg = "test DNSSEC signed data";
    const sig = (try key_pair.sign(msg, null)).toBytes();

    try verifyEcdsa(EcdsaP384, &sig, &testDigest(EcdsaP384.Hash, msg), dnssec_key);
    try testing.expectError(error.InvalidSignature, verifyEcdsa(EcdsaP384, &sig, &testDigest(EcdsaP384.Hash, "wrong data"), dnssec_key));
}

test "Ed25519 signature verification" {
    const key_pair = Ed25519.KeyPair.generate(testing.io);
    const pub_bytes = key_pair.public_key.toBytes();

    const msg = "test Ed25519 DNSSEC data";
    const sig = try key_pair.sign(msg, null);
    const sig_bytes = sig.toBytes();

    try verifyEd25519(&sig_bytes, &SignedData.raw(msg), &pub_bytes);
    try testing.expectError(error.InvalidSignature, verifyEd25519(&sig_bytes, &SignedData.raw("tampered"), &pub_bytes));
}

test "ECDSA P-256 accepts x(R) at or above the group order" {
    // Wycheproof ecdsa_secp256r1_sha256 "minimal R length": x(R) = r + n,
    // a branch honest signers reach about once in 2^129.
    var key: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "0ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e");
    var sig: [64]u8 = @splat(0);
    _ = try std.fmt.hexToBytes(sig[16..32], "4319055358e8617b0c46353d039cdaab");
    _ = try std.fmt.hexToBytes(sig[32..], "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e");

    try verifyEcdsa(EcdsaP256, &sig, &testDigest(Sha256, "123400"), &key);
    try testing.expectError(error.InvalidSignature, verifyEcdsa(EcdsaP256, &sig, &testDigest(Sha256, "123401"), &key));
}

test "VerifyMemo: a remembered signature binds its key and still expires" {
    const recs = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 1, 2, 3, 4 } } },
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try testSignRrset(&recs, .a, test_owner, .ed25519, &sig_bytes, &pub_bytes);
    var other_sig: [64]u8 = undefined;
    var other_pub: [32]u8 = undefined;
    const other = try testSignRrset(&recs, .a, test_owner, .ed25519, &other_sig, &other_pub);

    var memo: VerifyMemo = try .init(testing.allocator);
    defer memo.deinit(testing.allocator);
    var budget: ValidationBudget = .{};
    const now: u32 = 1_700_000_000;

    try verifyRrsig(signed.rrsig, signed.dnskey, &recs, now, &budget, &memo);
    try verifyRrsig(signed.rrsig, signed.dnskey, &recs, now, &budget, &memo);
    try testing.expectEqual(1, memo.hits);
    // Same signature and data under another key of the same algorithm.
    try testing.expectError(error.InvalidSignature, verifyRrsig(signed.rrsig, other.dnskey, &recs, now, &budget, &memo));
    try testing.expectError(error.SignatureExpired, verifyRrsig(signed.rrsig, signed.dnskey, &recs, signed.rrsig.sig_expiration + 1, &budget, &memo));
    try testing.expectEqual(1, memo.hits);
}

test "invalid key sizes are rejected" {
    const msg = "test";
    const sig64: [64]u8 = @splat(0);
    const sig96: [96]u8 = @splat(0);

    // ECDSA P-256: key must be 64 bytes
    try testing.expectError(error.InvalidKey, verifyEcdsa(EcdsaP256, &sig64, &testDigest(EcdsaP256.Hash, msg), &.{ 0x01, 0x02 }));
    // ECDSA P-384: key must be 96 bytes
    try testing.expectError(error.InvalidKey, verifyEcdsa(EcdsaP384, &sig96, &testDigest(EcdsaP384.Hash, msg), &.{ 0x01, 0x02 }));
    // Ed25519: key must be 32 bytes
    try testing.expectError(error.InvalidKey, verifyEd25519(&sig64, &SignedData.raw(msg), &.{ 0x01, 0x02 }));
    // ML-DSA-44: key 1312 bytes, signature 2420 bytes
    const pq_sig: [MlDsa44.Signature.encoded_length]u8 = @splat(0);
    try testing.expectError(error.InvalidKey, verifyMlDsa(&pq_sig, &SignedData.raw(msg), &.{ 0x01, 0x02 }));
    try testing.expectError(error.InvalidSignature, verifyMlDsa(&sig64, &SignedData.raw(msg), &@as([MlDsa44.PublicKey.encoded_length]u8, @splat(0))));
}

test "verifyRsa accepts RFC 3110 keys with exponent > 4 bytes (xelerance.com KSK shape)" {
    // KSK 26346 uses e = 2^32 + 1 (5 bytes). RFC 3110: 1-byte exp_len || exp || mod.
    // Synthetic 1024-bit modulus: any odd number with high bit set, so n.bits() == 1024.
    var key_data = [_]u8{ 5, 0x01, 0x00, 0x00, 0x00, 0x01 } ++ @as([128]u8, @splat(0x55));
    key_data[6] = 0x80;
    const signature: [128]u8 = @splat(0xaa);
    try testing.expectError(error.InvalidSignature, verifyRsa(Sha1, &signature, &testDigest(Sha1, "x"), &key_data));
    try testing.expectError(error.InvalidSignature, verifyRsa(Sha256, &signature, &testDigest(Sha256, "x"), &key_data));
}

test "verifyRsa rejects leading-zero-padded e=1 exponent (forgery defense)" {
    // Without the strip, [00 00 00 01] reads as e=1 and any sig == EM verifies.
    var k1 = [_]u8{ 4, 0x00, 0x00, 0x00, 0x01 } ++ @as([128]u8, @splat(0x55));
    k1[5] = 0x80;
    const sig: [128]u8 = @splat(0);
    try testing.expectError(error.InvalidKey, verifyRsa(Sha256, &sig, &testDigest(Sha256, "x"), &k1));

    // 2-byte exp_len encoding with 8-byte padded exponent.
    var k2 = [_]u8{ 0, 0, 8 } ++ @as([7]u8, @splat(0)) ++ [_]u8{0x01} ++ @as([128]u8, @splat(0x55));
    k2[11] = 0x80;
    try testing.expectError(error.InvalidKey, verifyRsa(Sha256, &sig, &testDigest(Sha256, "x"), &k2));
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
        pkcs1v15Encode(&em, c.Hash, c.hash_abc[0..c.Hash.digest_length]);
        try testing.expectEqual(@as(u8, 0x00), em[0]);
        try testing.expectEqual(@as(u8, 0x01), em[1]);
        const sep = 128 - c.digest_len - c.der.len - 1;
        for (em[2..sep]) |b| try testing.expectEqual(@as(u8, 0xff), b);
        try testing.expectEqual(@as(u8, 0x00), em[sep]);
        try testing.expectEqualSlices(u8, c.der, em[sep + 1 .. sep + 1 + c.der.len]);
        try testing.expectEqualSlices(u8, c.hash_abc, em[128 - c.digest_len ..]);
    }
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
    try testing.expectError(error.SignatureExpired, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, 1700000000 + 1, &budget, &test_memo));
}

test "verifyRrsig rejects not-yet-valid signature" {
    var budget: ValidationBudget = .{};
    try testing.expectError(error.SignatureExpired, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, 1699000000 - inception_skew_tolerance - 1, &budget, &test_memo));
}

test "verifyRrsig tolerates clock skew within window" {
    var budget: ValidationBudget = .{};
    inline for (.{
        1700000000, // at expiration boundary
        1699000000 - inception_skew_tolerance, // just before inception, within tolerance
    }) |now| {
        // Time check passes; empty key fails verifyEcdsa's length check first.
        try testing.expectError(error.InvalidKey, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_rrset, now, &budget, &test_memo));
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
        verifyRrsig(rrsig, test_window_dnskey, &rrset, 1699500000, &budget, &test_memo),
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
            &test_memo,
        ));
    }
    try testing.expectEqual(@as(u32, 2), budget.sig_verify_spent);
    try testing.expectError(error.ValidationBudgetExhausted, verifyRrsig(
        test_window_rrsig,
        test_window_dnskey,
        test_window_empty_rrset,
        1699500000,
        &budget,
        &test_memo,
    ));
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
    try verifyRrsig(signed.rrsig, signed.dnskey, &recs, 1_700_000_000, &budget, &test_memo);
    signed.rrsig.labels = 1;
    try testing.expectError(error.InvalidSignature, verifyRrsig(signed.rrsig, signed.dnskey, &recs, 1_700_000_000, &budget, &test_memo));
}

test "verifyRrsig verifies signed data past its stack buffer" {
    const chunk: [255]u8 = @splat('x');
    const strings: [40][]const u8 = @splat(&chunk);
    var recs = [_]dns.ResourceRecord{
        .{ .name = test_owner, .rtype = .txt, .rclass = .in, .ttl = 300, .rdata = .{ .txt = .{ .strings = &strings } } },
    };
    var sig_buf: [64]u8 = undefined;
    var pub_buf: [32]u8 = undefined;
    const signed = try testSignRrset(&recs, .txt, test_owner, .ed25519, &sig_buf, &pub_buf);
    var budget: ValidationBudget = .{};
    try verifyRrsig(signed.rrsig, signed.dnskey, &recs, 1_700_000_000, &budget, &test_memo);
    recs[0].rdata.txt.strings = strings[1..];
    try testing.expectError(error.InvalidSignature, verifyRrsig(signed.rrsig, signed.dnskey, &recs, 1_700_000_000, &budget, &test_memo));
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
            verifyRrsig(signed.rrsig, signed.dnskey, &below, 1_700_000_000, &budget, &test_memo),
        );

        // Owner == signer is the apex shape and must still verify, or the rule
        // would reject every legitimate apex NS/SOA in existence.
        var apex_sig_buf: [64]u8 = undefined;
        var apex_pub_buf: [32]u8 = undefined;
        const at_apex = [_]dns.ResourceRecord{
            .{ .name = parent, .rtype = rtype, .rclass = .in, .ttl = 300, .rdata = rdata },
        };
        const apex = try testSignRrset(&at_apex, rtype, parent, .ed25519, &apex_sig_buf, &apex_pub_buf);
        try verifyRrsig(apex.rrsig, apex.dnskey, &at_apex, 1_700_000_000, &budget, &test_memo);
    }
}

/// Remembers nothing; unit tests exercise the math alone.
var test_memo: VerifyMemo = .{};

fn testDigest(comptime Hash: type, msg: []const u8) [Hash.digest_length]u8 {
    var d: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &d, .{});
    return d;
}

/// Sign `rrset` with a fresh Ed25519 key; returns the RRSIG and the DNSKEY
/// that verifies it. Buffers are caller-owned so the slices outlive the call.
pub fn testSignRrset(
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
        .labels = @intCast(signedLabels(rrset[0].name)),
        .original_ttl = 300,
        .sig_inception = 1_699_000_000,
        .sig_expiration = 1_800_000_000,
        .key_tag = keyTag(dnskey),
        .signer_name = signer,
        .signature = &.{},
    };
    var canonical_buf: [65536]u8 = undefined;
    const data = try buildSignedData(&canonical_buf, rrsig, rrset);
    var sig = try kp.signer(null, testing.io);
    data.feed(&sig);
    sig_buf.* = sig.finalize().toBytes();
    rrsig.signature = sig_buf;
    return .{ .rrsig = rrsig, .dnskey = dnskey };
}

test "verifyRsa rejects exponents 0, 1 and even" {
    const sig: [256]u8 = @splat(0);
    inline for (.{ &[_]u8{0}, &[_]u8{1}, &[_]u8{ 0x01, 0x00, 0x02 } }) |exp| {
        var key_data: [1 + exp.len + 256]u8 = undefined;
        key_data[0] = exp.len;
        @memcpy(key_data[1..][0..exp.len], exp);
        @memset(key_data[1 + exp.len ..], 0xAA);
        try testing.expectError(error.InvalidKey, verifyRsa(Sha256, &sig, &testDigest(Sha256, "test"), &key_data));
    }
}

test "verifyRsa bounds the public exponent (RFC 3110 allows absurd ones)" {
    // powPublic is linear in exponent bits and the KeyTrap budget caps only the
    // verify count, so an oversized exponent multiplies the entire per-query
    // budget. RsaFe.fromBytes already forces e < n, but with a 4096-bit modulus
    // that still left 511 bytes -- 31.6 ms a verify, 3.0 s a query.
    //
    // 8 bytes must still pass: xelerance.com's e = 2^32+1.
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
        const res = verifyRsa(Sha256, &sig, &testDigest(Sha256, "hello"), key_data);
        if (want_rejected) {
            // Rejected on the key, before any modular arithmetic runs.
            try testing.expectError(error.InvalidKey, res);
        } else {
            // Got past every key check and died on the signature instead.
            try testing.expectError(error.InvalidSignature, res);
        }
    }
}
