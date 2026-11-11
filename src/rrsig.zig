//! RRSIG verification: the canonical signed data (RFC 4034 §3.1.8.1, §6.2),
//! each algorithm's math, the memo of what verified, and the KeyTrap budget
//! bounding the work.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Blake3 = std.crypto.hash.Blake3;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

const RsaModulus = std.crypto.ff.Modulus(4096);
const RsaFe = RsaModulus.Fe;

pub const VerifyError = error{
    InvalidSignature,
    UnsupportedAlgorithm,
    InvalidKey,
    SignatureExpired,
    ValidationBudgetExhausted,
};

/// KeyTrap (CVE-2023-50387) cap. Sized for a cold five-level chain with
/// two algorithms mid key rollover.
const max_sig_verify_per_resolution: u32 = 96;

const max_nsec3_blocks_per_resolution: u32 = 8192;

pub const ValidationBudget = struct {
    sig_verify_spent: u32 = 0,
    max_sig_verify: u32 = max_sig_verify_per_resolution,
    nsec3_blocks_spent: u32 = 0,
    max_nsec3_blocks: u32 = max_nsec3_blocks_per_resolution,
    /// Set only when a draw was refused. A budget filled exactly refused
    /// none, so the data, not the limit, decided.
    stopped: ?enum { verify, nsec3 } = null,

    fn consumeVerify(self: *ValidationBudget) error{ValidationBudgetExhausted}!void {
        if (self.sig_verify_spent >= self.max_sig_verify) {
            self.stopped = self.stopped orelse .verify;
            return error.ValidationBudgetExhausted;
        }
        self.sig_verify_spent += 1;
    }

    pub fn exhausted(self: *const ValidationBudget) bool {
        return self.sig_verify_spent >= self.max_sig_verify or self.nsec3_blocks_spent >= self.max_nsec3_blocks;
    }

    pub fn consumeNsec3(self: *ValidationBudget, blocks: u32) error{ValidationBudgetExhausted}!void {
        if (blocks > self.max_nsec3_blocks - @min(self.nsec3_blocks_spent, self.max_nsec3_blocks)) {
            self.nsec3_blocks_spent = self.max_nsec3_blocks;
            self.stopped = .nsec3;
            return error.ValidationBudgetExhausted;
        }
        self.nsec3_blocks_spent += blocks;
    }
};

/// Lengths are hashed in: RSA keys and signatures both vary in size, and
/// bytes shifted across their boundary must not produce the same tag.
fn framed(algorithm: dns.DnssecAlgorithm, key: []const u8, signature: []const u8) Blake3 {
    var frame: [5]u8 = undefined;
    frame[0] = @backingInt(algorithm);
    mem.writeInt(u16, frame[1..3], @intCast(key.len), .big);
    mem.writeInt(u16, frame[3..5], @intCast(signature.len), .big);
    var h = Blake3.init(.{});
    h.update(&frame);
    h.update(key);
    h.update(signature);
    return h;
}

/// Remembers signatures that verified, keyed by what the math saw. It holds
/// no clock and needs none: every check in `verifyRrsig` before the crypto,
/// the validity window included, still runs on a hit.
pub const VerifyMemo = struct {
    sets: []Set = &.{},
    hits: u64 = 0,
    misses: u64 = 0,

    /// Full width on purpose: anyone can plant tags with their own zone's
    /// valid signatures, so a forgery is a birthday search over the tag.
    const Tag = [32]u8;
    const Set = extern struct { ways: [2]Tag align(64) };
    /// The set count must stay a power of two: `set` masks the index.
    const bytes = 256 * 1024;

    pub fn init(gpa: mem.Allocator) !VerifyMemo {
        const sets = try gpa.alloc(Set, bytes / @sizeOf(Set));
        // Leftover memory that happened to hold a tag would be a forgery.
        @memset(sets, .{ .ways = @splat(@splat(0)) });
        return .{ .sets = sets };
    }

    pub fn deinit(m: *VerifyMemo, gpa: mem.Allocator) void {
        gpa.free(m.sets);
    }

    fn tag(algorithm: dns.DnssecAlgorithm, key: []const u8, signature: []const u8, digest: []const u8) Tag {
        var h = framed(algorithm, key, signature);
        h.update(digest);
        var t: Tag = undefined;
        h.final(&t);
        return t;
    }

    fn set(m: *VerifyMemo, t: *const Tag) *Set {
        return &m.sets[mem.readInt(u32, t[0..4], .little) & (m.sets.len - 1)];
    }

    fn recall(m: *VerifyMemo, t: *const Tag) bool {
        if (m.sets.len != 0) {
            const s = m.set(t);
            if (mem.eql(u8, &s.ways[0], t)) {
                m.hits += 1;
                return true;
            }
            if (mem.eql(u8, &s.ways[1], t)) {
                mem.swap(Tag, &s.ways[0], &s.ways[1]);
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
        s.ways[1] = s.ways[0];
        s.ways[0] = t.*;
    }
};

pub fn keyTag(dnskey: dns.DnskeyData) u16 {
    var ac: u32 = dnskey.flags;
    ac += @as(u32, dnskey.protocol) << 8 | @backingInt(dnskey.algorithm);
    for (dnskey.public_key, 0..) |b, i| ac += if (i & 1 == 0) @as(u32, b) << 8 else b;
    ac += (ac >> 16) & 0xFFFF;
    return @truncate(ac);
}

pub const Canonical = struct {
    records: []const dns.ResourceRecord,

    /// RFC 4034 §6.3 order, by RDATA alone: RDLENGTH must not take part, or
    /// records of different sizes sort wrong. Relies on stored rdata already
    /// being in canonical form.
    pub fn sort(records: []dns.ResourceRecord) Canonical {
        mem.sortUnstable(dns.ResourceRecord, records, {}, struct {
            fn lessThan(_: void, a: dns.ResourceRecord, b: dns.ResourceRecord) bool {
                return mem.order(u8, a.rdata, b.rdata) == .lt;
            }
        }.lessThan);
        return .{ .records = records };
    }
};

const SignedData = struct {
    header: [18 + dns.max_name_wire_len]u8 = undefined,
    header_len: usize,
    labels: u8 = 0,
    original_ttl: u32 = 0,
    set: Canonical = .{ .records = &.{} },

    pub fn feed(self: *const SignedData, hasher: anytype) void {
        hasher.update(self.header[0..self.header_len]);
        for (self.set.records) |rr| {
            var wc: dns.Name.Buf = undefined;
            const owner = if (self.labels < rr.name.depth()) dns.Name.child(&wc, "*", rr.name.ancestor(self.labels)).? else rr.name;
            var signed = rr;
            signed.ttl = self.original_ttl;
            hasher.update(owner.wire);
            hasher.update(&(signed.fixed() catch unreachable));
            hasher.update(rr.rdata);
        }
    }
};

pub fn buildSignedData(rrsig: dns.RrsigData, set: Canonical) SignedData {
    var out: SignedData = .{ .header_len = 18 + rrsig.signer_name.wire.len, .labels = rrsig.labels, .original_ttl = rrsig.original_ttl, .set = set };
    const h = &out.header;
    mem.writeInt(u16, h[0..2], @backingInt(rrsig.type_covered), .big);
    h[2] = @backingInt(rrsig.algorithm);
    h[3] = rrsig.labels;
    mem.writeInt(u32, h[4..8], rrsig.original_ttl, .big);
    mem.writeInt(u32, h[8..12], rrsig.sig_expiration, .big);
    mem.writeInt(u32, h[12..16], rrsig.sig_inception, .big);
    mem.writeInt(u16, h[16..18], rrsig.key_tag, .big);
    @memcpy(h[18..out.header_len], rrsig.signer_name.wire);
    return out;
}

/// Seconds. RFC 4035 §5.3.1 allows no grace. Inception gets some, for a
/// signer whose clock runs ahead; expiration gets none, since that would
/// widen the replay window of a captured signature.
const inception_skew_tolerance: u32 = 60;

/// When a signature is checked, at whose cost, and what is known to verify.
pub const Verifier = struct { now: u32, budget: *ValidationBudget, memo: *VerifyMemo };

pub fn verifyRrsig(
    rrsig: dns.RrsigData,
    dnskey: dns.DnskeyData,
    set: Canonical,
    at: Verifier,
) VerifyError!void {
    // Charged before any check, so attempts the cheap checks reject count
    // too (KeyTrap).
    try at.budget.consumeVerify();

    // Else an RRSIG naming a weaker algorithm hands the key to that verifier.
    if (rrsig.algorithm != dnskey.algorithm) return error.InvalidSignature;

    for (set.records) |rr| {
        if (!rr.name.isSubdomainOf(rrsig.signer_name)) return error.InvalidSignature;
        if (rrsig.labels > rr.name.depth()) return error.InvalidSignature;
        // The wildcard an expansion came from must sit inside the signer's zone.
        if (rrsig.labels < signedLabels(rr.name) and rrsig.labels < rrsig.signer_name.depth()) return error.InvalidSignature;
    }

    // A signed SOA or NS sits at an apex (RFC 4035 §2.2 leaves the parent's
    // delegation NS unsigned), so its signer must be its owner. A parent's
    // key must not sign these for a child.
    if (rrsig.type_covered == .soa or rrsig.type_covered == .ns) {
        for (set.records) |rr| {
            if (!rr.name.eql(rrsig.signer_name)) return error.InvalidSignature;
        }
    }

    if (!inWindow(rrsig, at.now)) return error.SignatureExpired;

    const data = buildSignedData(rrsig, set);

    switch (rrsig.algorithm) {
        inline .rsasha256, .rsasha512, .ecdsap256sha256, .ecdsap384sha384, .ed25519, .mldsa44 => |alg| {
            var digest: [Digest(alg).digest_length]u8 = undefined;
            var hash = Digest(alg).init(.{});
            data.feed(&hash);
            hash.final(&digest);
            const t = VerifyMemo.tag(alg, dnskey.public_key, rrsig.signature, &digest);
            if (at.memo.recall(&t)) {
                if (builtin.mode == .debug) proveMath(alg, rrsig.signature, &data, &digest, dnskey.public_key) catch unreachable;
                return;
            }
            try proveMath(alg, rrsig.signature, &data, &digest, dnskey.public_key);
            at.memo.remember(&t);
        },
        else => return error.UnsupportedAlgorithm,
    }
}

/// RSA and ECDSA sign this digest. Ed25519 and ML-DSA hash the data
/// themselves; for them it only names the memo entry.
fn Digest(comptime algorithm: dns.DnssecAlgorithm) type {
    return switch (algorithm) {
        .rsasha256, .ecdsap256sha256, .ed25519, .mldsa44 => Sha256,
        .ecdsap384sha384 => Sha384,
        .rsasha512 => Sha512,
        else => @compileError("no verifier for " ++ @tagName(algorithm)),
    };
}

pub fn inWindow(rrsig: dns.RrsigData, now_u32: u32) bool {
    const skew_ahead = now_u32 +% inception_skew_tolerance;
    return !dns.serialAfter(rrsig.sig_inception, skew_ahead) and !dns.serialAfter(now_u32, rrsig.sig_expiration);
}

pub fn isSupportedAlgorithm(algo: dns.DnssecAlgorithm) bool {
    return switch (algo) {
        .rsasha256, .rsasha512, .ecdsap256sha256, .ecdsap384sha384, .ed25519, .mldsa44 => true,
        else => false,
    };
}

/// Debug test builds only: each thread runs the math for a signature once,
/// so Debug's re-check of every memo hit stays cheap. Keyed by the signed
/// data, not the memo's tag, so a wrong memo hit is still caught.
threadlocal var proven: std.AutoHashMapUnmanaged([32]u8, void) = .empty;

fn proveMath(
    comptime algorithm: dns.DnssecAlgorithm,
    signature: []const u8,
    data: *const SignedData,
    digest: *const [Digest(algorithm).digest_length]u8,
    key: []const u8,
) VerifyError!void {
    if (!builtin.is_test or builtin.mode != .debug) return verifyMath(algorithm, signature, data, digest, key);
    var h = framed(algorithm, key, signature);
    data.feed(&h);
    var t: [32]u8 = undefined;
    h.final(&t);
    if (proven.contains(t)) return;
    try verifyMath(algorithm, signature, data, digest, key);
    proven.put(std.heap.smp_allocator, t, {}) catch {};
}

/// Must stay a pure function of its arguments, or memo hits bypass the
/// change. Policy (distrusting an algorithm, a key-size floor) goes before
/// the memo lookup.
fn verifyMath(
    comptime algorithm: dns.DnssecAlgorithm,
    signature: []const u8,
    data: *const SignedData,
    digest: *const [Digest(algorithm).digest_length]u8,
    key: []const u8,
) VerifyError!void {
    return switch (algorithm) {
        .rsasha256, .rsasha512 => verifyRsa(Digest(algorithm), signature, digest, key),
        .ecdsap256sha256 => verifyEcdsa(EcdsaP256, signature, digest, key),
        .ecdsap384sha384 => verifyEcdsa(EcdsaP384, signature, digest, key),
        .ed25519 => verifyEd25519(signature, data, key),
        .mldsa44 => verifyMlDsa(signature, data, key),
        else => comptime unreachable,
    };
}

fn verifyRsa(comptime Hash: type, signature: []const u8, digest: *const [Hash.digest_length]u8, key_data: []const u8) VerifyError!void {
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

    // Strip leading zeros first: `00 00 00 01` is e=1, which accepts sig == EM.
    while (exponent.len > 1 and exponent[0] == 0) exponent = exponent[1..];
    if (exponent[exponent.len - 1] & 1 == 0) return error.InvalidKey;
    if (exponent.len == 1 and exponent[0] <= 1) return error.InvalidKey;

    // Verify cost is linear in exponent bits and the budget caps only the
    // count: a 511-byte exponent costs about 40 times e=65537. Eight bytes
    // still admits the 5-byte e = 2^32+1 seen in the wild.
    if (exponent.len > 8) return error.InvalidKey;

    if (modulus.len < 128 or modulus.len > 512) return error.InvalidKey;
    if (signature.len != modulus.len) return error.InvalidSignature;

    // `ff` directly, not std's RSA wrapper, whose 4-byte exponent cap would
    // refuse those keys.
    const n = RsaModulus.fromBytes(modulus, .big) catch return error.InvalidKey;
    if (n.bits() < 1024) return error.InvalidKey;
    const e = RsaFe.fromBytes(n, exponent, .big) catch return error.InvalidKey;
    const sig_fe = RsaFe.fromBytes(n, signature, .big) catch return error.InvalidSignature;
    const decoded_fe = n.powPublic(sig_fe, e) catch return error.InvalidSignature;

    var em_dec: [512]u8 = undefined;
    decoded_fe.toBytes(em_dec[0..modulus.len], .big) catch return error.InvalidSignature;
    var em_expected: [512]u8 = undefined;
    pkcs1v15Encode(em_expected[0..modulus.len], Hash, digest);

    var diff: u8 = 0;
    for (em_dec[0..modulus.len], em_expected[0..modulus.len]) |a, b| diff |= a ^ b;
    if (diff != 0) return error.InvalidSignature;
}

fn pkcs1v15Encode(em: []u8, comptime Hash: type, digest: *const [Hash.digest_length]u8) void {
    const hash_der: []const u8 = &switch (Hash) {
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

fn verifyEcdsa(comptime Ecdsa: type, signature: []const u8, digest: *const [Ecdsa.Hash.digest_length]u8, key_data: []const u8) VerifyError!void {
    const len = Ecdsa.Curve.scalar.encoded_length;
    if (key_data.len != 2 * len) return error.InvalidKey;
    if (signature.len != 2 * len) return error.InvalidSignature;
    const key: Ecdsa.PublicKey = .{ .p = Ecdsa.Curve.fromSerializedAffineCoordinates(key_data[0..len].*, key_data[len..][0..len].*, .big) catch return error.InvalidKey };
    Ecdsa.Signature.fromBytes(signature[0 .. 2 * len].*).verifyPrehashed(digest.*, key) catch return error.InvalidSignature;
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

fn verifyMlDsa(signature: []const u8, data: *const SignedData, key_data: []const u8) VerifyError!void {
    if (key_data.len != MlDsa44.PublicKey.encoded_length) return error.InvalidKey;
    if (signature.len != MlDsa44.Signature.encoded_length) return error.InvalidSignature;

    const pub_key = MlDsa44.PublicKey.fromBytes(key_data[0..MlDsa44.PublicKey.encoded_length].*) catch return error.InvalidKey;
    const sig = MlDsa44.Signature.fromBytes(signature[0..MlDsa44.Signature.encoded_length].*) catch return error.InvalidSignature;
    var verifier = sig.verifier(pub_key) catch return error.InvalidSignature;
    data.feed(&verifier);
    verifier.verify() catch return error.InvalidSignature;
}

/// RFC 4035 §5.3.3. Two clocks: `original_ttl` ages from when the set was
/// received, `window_s` is seconds from now until the signature expires.
pub const Cap = struct {
    original_ttl: u32,
    window_s: u32,

    pub const none: Cap = .{ .original_ttl = std.math.maxInt(u32), .window_s = std.math.maxInt(u32) };

    pub fn of(sig: dns.RrsigData, now_u32: u32) Cap {
        return .{ .original_ttl = sig.original_ttl, .window_s = dns.secondsUntil(sig.sig_expiration, now_u32) };
    }

    pub fn meet(a: Cap, b: Cap) Cap {
        return .{ .original_ttl = @min(a.original_ttl, b.original_ttl), .window_s = @min(a.window_s, b.window_s) };
    }
};

pub fn signedLabels(name: dns.Name) u8 {
    const star = !name.isRoot() and mem.eql(u8, name.leaf(), "*");
    return name.depth() - @intFromBool(star);
}

pub const test_owner = dns.Name.lit("example.com");

const TestFlatten = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,
    fn update(self: *TestFlatten, b: []const u8) void {
        @memcpy(self.buf[self.len..][0..b.len], b);
        self.len += b.len;
    }
};

test "buildSignedData produces correct header" {
    const signer_name = dns.Name.lit("example.com");
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

    const owner_name = dns.Name.lit("www.example.com");

    var rrset = [_]dns.ResourceRecord{.fixture(.{
        .name = owner_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 200, // different from original_ttl — signed data should use original_ttl
        .rdata = .{ .a = .{ 93, 184, 216, 34 } },
    })};

    var flat = TestFlatten{};
    buildSignedData(rrsig, .sort(&rrset)).feed(&flat);
    const signed = flat.buf[0..flat.len];

    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, signed[0..2], .big));
    try testing.expectEqual(@as(u8, 13), signed[2]);
    try testing.expectEqual(@as(u8, 3), signed[3]);
    try testing.expectEqual(@as(u32, 300), mem.readInt(u32, signed[4..8], .big));
    try testing.expectEqual(@as(u32, 1700000000), mem.readInt(u32, signed[8..12], .big));
    try testing.expectEqual(@as(u32, 1699000000), mem.readInt(u32, signed[12..16], .big));
    try testing.expectEqual(@as(u16, 12345), mem.readInt(u16, signed[16..18], .big));

    try testing.expectEqualSlices(u8, "\x07example\x03com\x00", signed[18..31]);

    const rr_start = 31;
    try testing.expectEqualSlices(u8, "\x03www\x07example\x03com\x00", signed[rr_start..][0..17]);
    const after_name = rr_start + 17;
    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, signed[after_name..][0..2], .big));
    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, signed[after_name + 2 ..][0..2], .big));
    try testing.expectEqual(@as(u32, 300), mem.readInt(u32, signed[after_name + 4 ..][0..4], .big));
    try testing.expectEqual(@as(u16, 4), mem.readInt(u16, signed[after_name + 8 ..][0..2], .big));
    try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, signed[after_name + 10 ..][0..4]);
}

test "buildSignedData reconstructs wildcard owner name" {
    const signer_name = dns.Name.lit("example.com");
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

    const owner_name = dns.Name.lit("foo.example.com");

    var rrset = [_]dns.ResourceRecord{.fixture(.{
        .name = owner_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 200,
        .rdata = .{ .a = .{ 93, 184, 216, 34 } },
    })};

    var flat = TestFlatten{};
    buildSignedData(rrsig, .sort(&rrset)).feed(&flat);
    const signed = flat.buf[0..flat.len];

    const rr_start = 31;
    const expected_wc_owner = "\x01*\x07example\x03com\x00";
    try testing.expectEqualSlices(u8, expected_wc_owner, signed[rr_start..][0..expected_wc_owner.len]);
}

test "verifyRrsig takes an SRV target that arrived compressed and mixed case" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const wire = "\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x04_sip\x04_tcp\x07Example\x00\x00\x21\x00\x01" ++
        "\xc0\x0c\x00\x21\x00\x01\x00\x00\x01\x2c\x00\x0c" ++
        "\x00\x0a\x00\x14\x13\xc4\x03SIP\xc0\x16";
    const msg = try dns.parseMessage(a, wire);
    const answers = try a.dupe(dns.ResourceRecord, msg.answers);
    const b64 = std.base64.standard.Decoder;
    var key: [32]u8 = undefined;
    try b64.decode(&key, "pN1ZplRgxmic0CryiKUUNeppeKGaijf6hL5+N3QVvM4=");
    var sig: [64]u8 = undefined;
    try b64.decode(&sig, "90H7Oz/xTne6mQrj0HA4f59/p3hGTc4GS1j+p5QY19Mkda7NqlosTLVN0ewALvovWJXG9FpbnzIhjBvdGNCQCQ==");
    const rrsig: dns.RrsigData = .{
        .type_covered = .srv,
        .algorithm = .ed25519,
        .labels = 3,
        .original_ttl = 300,
        .sig_expiration = 2114380800, // 20370101000000
        .sig_inception = 1767225600, // 20260101000000
        .key_tag = 60260,
        .signer_name = try dns.parseDottedName(a, "example"),
        .signature = &sig,
    };
    const dnskey: dns.DnskeyData = .{ .flags = 257, .protocol = 3, .algorithm = .ed25519, .public_key = &key };
    var budget: ValidationBudget = .{};
    var memo: VerifyMemo = .{};
    try verifyRrsig(rrsig, dnskey, .sort(answers), .{ .now = 1_800_000_000, .budget = &budget, .memo = &memo });
}

test "ECDSA P-384 signature verification" {
    const key_pair = EcdsaP384.KeyPair.generate(testing.io);
    const dnssec_key = key_pair.public_key.toUncompressedSec1()[1..];
    const msg = "test DNSSEC signed data";
    const sig = (try key_pair.sign(msg, null)).toBytes();

    try verifyEcdsa(EcdsaP384, &sig, &testDigest(EcdsaP384.Hash, msg), dnssec_key);
    try testing.expectError(error.InvalidSignature, verifyEcdsa(EcdsaP384, &sig, &testDigest(EcdsaP384.Hash, "wrong data"), dnssec_key));
}

test "VerifyMemo: a remembered signature binds its key and still expires" {
    var recs = [_]dns.ResourceRecord{
        .fixture(.{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 1, 2, 3, 4 } } }),
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

    try verifyRrsig(signed.rrsig, signed.dnskey, .sort(&recs), .{ .now = now, .budget = &budget, .memo = &memo });
    try verifyRrsig(signed.rrsig, signed.dnskey, .sort(&recs), .{ .now = now, .budget = &budget, .memo = &memo });
    try testing.expectEqual(1, memo.hits);
    try testing.expectError(error.InvalidSignature, verifyRrsig(signed.rrsig, other.dnskey, .sort(&recs), .{ .now = now, .budget = &budget, .memo = &memo }));
    try testing.expectError(error.SignatureExpired, verifyRrsig(signed.rrsig, signed.dnskey, .sort(&recs), .{ .now = signed.rrsig.sig_expiration + 1, .budget = &budget, .memo = &memo }));
    try testing.expectEqual(1, memo.hits);
}

test "VerifyMemo: a set holds its two newest tags" {
    var memo: VerifyMemo = try .init(testing.allocator);
    defer memo.deinit(testing.allocator);
    const a: VerifyMemo.Tag = @splat(1);
    var b = a;
    b[31] = 2;
    memo.remember(&a);
    memo.remember(&b);
    try testing.expect(memo.recall(&a));
    try testing.expect(memo.recall(&b));
}

test "invalid key sizes are rejected" {
    const msg = "test";
    const signed = buildSignedData(test_window_rrsig, test_window_empty_set);
    const sig64: [64]u8 = @splat(0);
    const sig96: [96]u8 = @splat(0);

    try testing.expectError(error.InvalidKey, verifyEcdsa(EcdsaP256, &sig64, &testDigest(EcdsaP256.Hash, msg), &.{ 0x01, 0x02 }));
    try testing.expectError(error.InvalidKey, verifyEcdsa(EcdsaP384, &sig96, &testDigest(EcdsaP384.Hash, msg), &.{ 0x01, 0x02 }));
    try testing.expectError(error.InvalidKey, verifyEd25519(&sig64, &signed, &.{ 0x01, 0x02 }));
    const pq_sig: [MlDsa44.Signature.encoded_length]u8 = @splat(0);
    try testing.expectError(error.InvalidKey, verifyMlDsa(&pq_sig, &signed, &.{ 0x01, 0x02 }));
    try testing.expectError(error.InvalidSignature, verifyMlDsa(&sig64, &signed, &@as([MlDsa44.PublicKey.encoded_length]u8, @splat(0))));
}

test "verifyRsa accepts RFC 3110 keys with exponent > 4 bytes (xelerance.com KSK shape)" {
    var key_data = [_]u8{ 5, 0x01, 0x00, 0x00, 0x00, 0x01 } ++ @as([128]u8, @splat(0x55));
    key_data[6] = 0x80;
    const signature: [128]u8 = @splat(0xaa);
    try testing.expectError(error.InvalidSignature, verifyRsa(Sha256, &signature, &testDigest(Sha256, "x"), &key_data));
}

test "verifyRsa rejects leading-zero-padded e=1 exponent (forgery defense)" {
    var k1 = [_]u8{ 4, 0x00, 0x00, 0x00, 0x01 } ++ @as([128]u8, @splat(0x55));
    k1[5] = 0x80;
    const sig: [128]u8 = @splat(0);
    try testing.expectError(error.InvalidKey, verifyRsa(Sha256, &sig, &testDigest(Sha256, "x"), &k1));

    var k2 = [_]u8{ 0, 0, 8 } ++ @as([7]u8, @splat(0)) ++ [_]u8{0x01} ++ @as([128]u8, @splat(0x55));
    k2[11] = 0x80;
    try testing.expectError(error.InvalidKey, verifyRsa(Sha256, &sig, &testDigest(Sha256, "x"), &k2));
}

test "pkcs1v15Encode produces RFC 8017 §9.2 byte layout (per hash)" {
    const Case = struct {
        Hash: type,
        digest_len: usize,
        der: []const u8,
        hash_abc: []const u8,
    };
    inline for ([_]Case{
        .{
            .Hash = Sha256,
            .digest_len = 32,
            .der = &.{
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            },
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

const test_window_rrsig = dns.RrsigData{
    .type_covered = .a,
    .algorithm = .ecdsap256sha256,
    .labels = 2,
    .original_ttl = 300,
    .sig_expiration = 1700000000,
    .sig_inception = 1699000000,
    .key_tag = 12345,
    .signer_name = .lit("example.com"),
    .signature = &.{},
};
const test_window_dnskey = dns.DnskeyData{
    .flags = 256,
    .protocol = 3,
    .algorithm = .ecdsap256sha256,
    .public_key = &.{},
};
const test_window_empty_set: Canonical = .{ .records = &.{} };

test "verifyRrsig rejects expired signature" {
    var budget: ValidationBudget = .{};
    try testing.expectError(error.SignatureExpired, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_set, .{ .now = 1700000000 + 1, .budget = &budget, .memo = &test_memo }));
}

test "verifyRrsig rejects not-yet-valid signature" {
    var budget: ValidationBudget = .{};
    try testing.expectError(error.SignatureExpired, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_set, .{ .now = 1699000000 - inception_skew_tolerance - 1, .budget = &budget, .memo = &test_memo }));
}

test "verifyRrsig tolerates clock skew within window" {
    var budget: ValidationBudget = .{};
    inline for (.{
        1700000000, // at expiration boundary
        1699000000 - inception_skew_tolerance, // just before inception, within tolerance
    }) |now| {
        try testing.expectError(error.InvalidKey, verifyRrsig(test_window_rrsig, test_window_dnskey, test_window_empty_set, .{ .now = now, .budget = &budget, .memo = &test_memo }));
    }
}

test "verifyRrsig rejects signer that is not an ancestor of owner (RFC 4034 §3.1.3)" {
    const cross_signer = dns.Name.lit("example.org");
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
    var rrset = [_]dns.ResourceRecord{
        .fixture(.{ .name = test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } }),
    };
    var budget: ValidationBudget = .{};
    try testing.expectError(
        error.InvalidSignature,
        verifyRrsig(rrsig, test_window_dnskey, .sort(&rrset), .{ .now = 1699500000, .budget = &budget, .memo = &test_memo }),
    );
}

test "verifyRrsig consumes budget on entry (KeyTrap mitigation)" {
    var budget: ValidationBudget = .{ .max_sig_verify = 2 };
    inline for (0..2) |_| {
        try testing.expectError(error.InvalidKey, verifyRrsig(
            test_window_rrsig,
            test_window_dnskey,
            test_window_empty_set,
            .{ .now = 1699500000, .budget = &budget, .memo = &test_memo },
        ));
    }
    try testing.expectEqual(@as(u32, 2), budget.sig_verify_spent);
    try testing.expect(budget.stopped == null);
    try testing.expectError(error.ValidationBudgetExhausted, verifyRrsig(
        test_window_rrsig,
        test_window_dnskey,
        test_window_empty_set,
        .{ .now = 1699500000, .budget = &budget, .memo = &test_memo },
    ));
    try testing.expect(budget.stopped == .verify);
}

test "verifyRrsig takes an expansion only from a wildcard inside the signer's zone" {
    const Case = struct { owner: []const u8, signer: []const u8, labels: u8, ok: bool };
    const cases = [_]Case{
        .{ .owner = "foo.example.com", .signer = "example.com", .labels = 2, .ok = true },
        .{ .owner = "foo.example.com", .signer = "example.com", .labels = 1, .ok = false },
        .{ .owner = "foo.example.com", .signer = "example.com", .labels = 0, .ok = false },
        .{ .owner = "*.example", .signer = "*.example", .labels = 1, .ok = true },
        .{ .owner = "x.*.example", .signer = "*.example", .labels = 1, .ok = false },
        .{ .owner = "x.*.example", .signer = "*.example", .labels = 2, .ok = true },
    };
    const kp = Ed25519.KeyPair.generate(testing.io);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    for (cases) |c| {
        const owner = try dns.parseDottedName(arena.allocator(), c.owner);
        const signer = try dns.parseDottedName(arena.allocator(), c.signer);
        var recs = [_]dns.ResourceRecord{
            .fixture(.{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 0, 2, 1 } } }),
        };
        var sig_buf: [64]u8 = undefined;
        var pub_buf: [32]u8 = undefined;
        var signed = try testSignRrsetBy(kp, &recs, .a, signer, .ed25519, &sig_buf, &pub_buf);
        signed.rrsig.labels = c.labels;
        const data = buildSignedData(signed.rrsig, .sort(&recs));
        var sig = try kp.signer(null, testing.io);
        data.feed(&sig);
        sig_buf = sig.finalize().toBytes();
        var budget: ValidationBudget = .{};
        const got = verifyRrsig(signed.rrsig, signed.dnskey, .sort(&recs), .{ .now = 1_700_000_000, .budget = &budget, .memo = &test_memo });
        if (c.ok) try got else try testing.expectError(error.InvalidSignature, got);
    }
}

test "verifyRrsig rejects NS and SOA signed by a strictly-higher zone" {
    const parent = dns.Name.lit("example.com");
    const child = dns.Name.lit("sub.example.com");
    var budget: ValidationBudget = .{};

    inline for (.{ dns.RType.ns, dns.RType.soa }) |rtype| {
        const rdata: dns.RData = switch (rtype) {
            .ns => .{ .ns = dns.Name.lit("ns1.example.com") },
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

        var sig_buf: [64]u8 = undefined;
        var pub_buf: [32]u8 = undefined;
        var below = [_]dns.ResourceRecord{
            .fixture(.{ .name = child, .rtype = rtype, .rclass = .in, .ttl = 300, .rdata = rdata }),
        };
        const signed = try testSignRrset(&below, rtype, parent, .ed25519, &sig_buf, &pub_buf);
        try testing.expectError(
            error.InvalidSignature,
            verifyRrsig(signed.rrsig, signed.dnskey, .sort(&below), .{ .now = 1_700_000_000, .budget = &budget, .memo = &test_memo }),
        );

        var apex_sig_buf: [64]u8 = undefined;
        var apex_pub_buf: [32]u8 = undefined;
        var at_apex = [_]dns.ResourceRecord{
            .fixture(.{ .name = parent, .rtype = rtype, .rclass = .in, .ttl = 300, .rdata = rdata }),
        };
        const apex = try testSignRrset(&at_apex, rtype, parent, .ed25519, &apex_sig_buf, &apex_pub_buf);
        try verifyRrsig(apex.rrsig, apex.dnskey, .sort(&at_apex), .{ .now = 1_700_000_000, .budget = &budget, .memo = &test_memo });
    }
}

pub var test_memo: VerifyMemo = .{};

fn testDigest(comptime Hash: type, msg: []const u8) [Hash.digest_length]u8 {
    var d: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &d, .{});
    return d;
}

const TestSigned = struct { rrsig: dns.RrsigData, dnskey: dns.DnskeyData };

pub fn testSignRrset(
    rrset: []const dns.ResourceRecord,
    covered: dns.RType,
    signer: dns.Name,
    key_algo: dns.DnssecAlgorithm,
    sig_buf: *[64]u8,
    pub_buf: *[32]u8,
) !TestSigned {
    return testSignRrsetBy(Ed25519.KeyPair.generate(testing.io), rrset, covered, signer, key_algo, sig_buf, pub_buf);
}

/// `key_algo` labels the DNSKEY only. The RRSIG always says Ed25519, so a
/// test can make the two disagree.
pub fn testSignRrsetBy(
    kp: Ed25519.KeyPair,
    rrset: []const dns.ResourceRecord,
    covered: dns.RType,
    signer: dns.Name,
    key_algo: dns.DnssecAlgorithm,
    sig_buf: *[64]u8,
    pub_buf: *[32]u8,
) !TestSigned {
    pub_buf.* = kp.public_key.toBytes();
    const dnskey = dns.DnskeyData{
        .flags = dns.DnskeyData.zone_flag,
        .protocol = 3,
        .algorithm = key_algo,
        .public_key = pub_buf,
    };
    var rrsig = dns.RrsigData{
        .type_covered = covered,
        .algorithm = .ed25519,
        .labels = signedLabels(rrset[0].name),
        .original_ttl = 300,
        .sig_inception = 1_699_000_000,
        .sig_expiration = 1_800_000_000,
        .key_tag = keyTag(dnskey),
        .signer_name = signer,
        .signature = &.{},
    };
    const set = try testing.allocator.dupe(dns.ResourceRecord, rrset);
    defer testing.allocator.free(set);
    const data = buildSignedData(rrsig, .sort(set));
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
            try testing.expectError(error.InvalidKey, res);
        } else {
            try testing.expectError(error.InvalidSignature, res);
        }
    }
}
