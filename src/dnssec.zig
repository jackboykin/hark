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

pub const root_ds_records = [_]dns.DsData{
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

fn isValidZoneKey(dk: dns.DnskeyData) bool {
    return dk.isZoneKey() and dk.protocol == 3 and !dk.isRevoked();
}

/// RFC 4509 §3: a SHA-1 DS is ignored when the set has a SHA-256 one. Only
/// a usable one counts: a SHA-256 DS for an unsupported key algorithm
/// anchors nothing and must not silence the SHA-1 that does.
fn dsEligible(ds: dns.DsData, ds_records: []const dns.DsData) bool {
    if (ds.digest_type != .sha1) return true;
    for (ds_records) |ds2| if (ds2.digest_type == .sha256 and rrsig.isSupportedAlgorithm(ds2.algorithm)) return false;
    return true;
}

const test_memo = &rrsig.test_memo;
var test_scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);

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
    scratch: mem.Allocator,
    dnskey_records: []const dns.ResourceRecord,
    ds_records: []const dns.DsData,
    zone_name: dns.Name,
    now_u32: u32,
    budget: *rrsig.ValidationBudget,
    memo: *rrsig.VerifyMemo,
) !?dns.RrsigData {
    const filtered = try collect(scratch, dnskey_records, null, .dnskey);
    var anchored: Keyset = try .init(scratch, dnskey_records);
    var n: usize = 0;
    for (anchored.keys, anchored.tags) |dk, tag| {
        for (ds_records) |ds| {
            if (ds.key_tag != tag or ds.algorithm != dk.algorithm or !dsEligible(ds, ds_records)) continue;
            verifyDs(ds, dk, zone_name) catch continue;
            anchored.keys[n] = dk;
            anchored.tags[n] = tag;
            n += 1;
            break;
        }
    }
    anchored.keys = anchored.keys[0..n];
    anchored.tags = anchored.tags[0..n];

    // A DS advertising ML-DSA-44 makes its RRSIG the only one that counts
    // (draft-westerbaan-dnssec-mldsa §7.2), or stripping it is a downgrade.
    const pq = hasMlDsaDs(ds_records);
    var tried: usize = 0;
    for (dnskey_records) |rrsig_rr| {
        if (rrsig_rr.rtype != .rrsig) continue;
        const sig = rrsig_rr.rrsig();
        if (sig.type_covered != .dnskey) continue;
        if (pq and sig.algorithm != .mldsa44) continue;
        if (!sig.signer_name.eql(zone_name) or !usable(sig, now_u32)) continue;
        if (tried == max_sigs_per_set) break;
        tried += 1;
        if (rrsetVerifiesWithAnyKey(sig, &anchored, filtered, now_u32, budget, memo) catch return null) return sig;
    }
    return null;
}

fn hasMlDsaDs(ds_records: []const dns.DsData) bool {
    for (ds_records) |ds| if (ds.algorithm == .mldsa44 and digestSupported(ds.digest_type) and dsEligible(ds, ds_records)) return true;
    return false;
}

/// ML-DSA-44 signatures (2420 B) do not fit a 1232 B UDP payload.
pub fn dsExceedsUdp(rrs: []const dns.ResourceRecord) bool {
    for (rrs) |rr| if (rr.rtype == .ds and rr.ds().algorithm == .mldsa44) return true;
    return false;
}

fn digestSupported(digest_type: dns.DigestType) bool {
    return switch (digest_type) {
        .sha1, .sha256, .sha384 => true,
        _ => false,
    };
}

/// Under an ML-DSA-44 DS only those keys validate below the apex, so no
/// classical RRSIG finds a key. The result borrows `records` or lives in
/// `allocator`.
pub fn usableKeys(allocator: mem.Allocator, records: []const dns.ResourceRecord, ds_records: []const dns.DsData) ![]const dns.ResourceRecord {
    if (!hasMlDsaDs(ds_records)) return records;
    var kept: std.ArrayList(dns.ResourceRecord) = .empty;
    for (records) |rr| if (rr.rtype == .dnskey and rr.dnskey().algorithm == .mldsa44) try kept.append(allocator, rr);
    return kept.items;
}

pub fn dsDigest(comptime Hash: type, owner: dns.Name, dnskey: dns.DnskeyData) [Hash.digest_length]u8 {
    var h = Hash.init(.{});
    h.update(owner.wire);
    h.update(&mem.toBytes(mem.nativeToBig(u16, dnskey.flags)));
    h.update(&.{ dnskey.protocol, @backingInt(dnskey.algorithm) });
    h.update(dnskey.public_key);
    return h.finalResult();
}

fn verifyDs(ds: dns.DsData, dnskey: dns.DnskeyData, owner_name: dns.Name) rrsig.VerifyError!void {
    const ok = switch (ds.digest_type) {
        .sha1 => mem.eql(u8, &dsDigest(Sha1, owner_name, dnskey), ds.digest),
        .sha256 => mem.eql(u8, &dsDigest(Sha256, owner_name, dnskey), ds.digest),
        .sha384 => mem.eql(u8, &dsDigest(Sha384, owner_name, dnskey), ds.digest),
        _ => return error.UnsupportedAlgorithm,
    };
    if (!ok) return error.InvalidSignature;
}

/// RFC 4035 §5.2: a verified DS set with no supported algorithm and digest
/// pair means insecure, not bogus, or every Ed448-only zone fails.
pub fn anySupportedDs(records: []const dns.ResourceRecord) bool {
    for (records) |rr| {
        if (rr.rtype != .ds) continue;
        const ds = rr.ds();
        if (rrsig.isSupportedAlgorithm(ds.algorithm) and digestSupported(ds.digest_type)) return true;
    }
    return false;
}

const Keyset = struct {
    keys: []dns.DnskeyData,
    tags: []u16,
    zone: ?dns.Name = null,

    fn init(scratch: mem.Allocator, records: []const dns.ResourceRecord) !Keyset {
        var n: usize = 0;
        for (records) |rr| n += @intFromBool(rr.rtype == .dnskey);
        var k: Keyset = .{ .keys = try scratch.alloc(dns.DnskeyData, n), .tags = try scratch.alloc(u16, n) };
        n = 0;
        for (records) |rr| {
            if (rr.rtype != .dnskey) continue;
            k.zone = k.zone orelse rr.name;
            const dk = rr.dnskey();
            if (!isValidZoneKey(dk)) continue;
            k.keys[n] = dk;
            k.tags[n] = rrsig.keyTag(dk);
            n += 1;
        }
        k.keys = k.keys[0..n];
        k.tags = k.tags[0..n];
        return k;
    }
};

/// The whole set, however large: verifying part of it would vouch for the
/// rest.
fn collect(scratch: mem.Allocator, rrs: []const dns.ResourceRecord, owner: ?dns.Name, rtype: dns.RType) !rrsig.Canonical {
    var n: usize = 0;
    for (rrs) |rr| n += @intFromBool(rr.rtype == rtype and (owner == null or rr.name.eql(owner.?)));
    const set = try scratch.alloc(dns.ResourceRecord, n);
    n = 0;
    for (rrs) |rr| if (rr.rtype == rtype and (owner == null or rr.name.eql(owner.?))) {
        set[n] = rr;
        n += 1;
    };
    return .sort(set);
}

fn rrsetVerifiesWithAnyKey(
    sig: dns.RrsigData,
    keyset: *const Keyset,
    set: rrsig.Canonical,
    now_u32: u32,
    budget: *rrsig.ValidationBudget,
    memo: *rrsig.VerifyMemo,
) error{ValidationBudgetExhausted}!bool {
    for (keyset.keys, keyset.tags) |dk, tag| {
        if (tag != sig.key_tag) continue;
        rrsig.verifyRrsig(sig, dk, set, now_u32, budget, memo) catch |e| switch (e) {
            error.ValidationBudgetExhausted => return error.ValidationBudgetExhausted,
            else => continue,
        };
        return true;
    }
    return false;
}

/// Depth alone picks the signer: `bindSets` keeps only signatures whose
/// signer is on the owner's path to the root.
pub fn signerBelow(rrs: []const dns.ResourceRecord, owner: dns.Name, rtype: dns.RType, below: usize) ?dns.Name {
    var best: ?dns.Name = null;
    for (rrs) |rr| {
        if (rr.rtype != .rrsig or rr.rrsig().type_covered != rtype or !rr.name.eql(owner)) continue;
        const z = rr.rrsig().signer_name;
        if (z.depth() < below and (best == null or z.depth() > best.?.depth())) best = z;
    }
    return best;
}

pub fn signedBy(rrs: []const dns.ResourceRecord, owner: dns.Name, rtype: dns.RType, signer: dns.Name) bool {
    for (rrs) |rr| {
        if (rr.rtype == .rrsig and rr.rrsig().type_covered == rtype and rr.name.eql(owner) and rr.rrsig().signer_name.eql(signer)) return true;
    }
    return false;
}

const max_sigs_per_set = 8;

fn usable(sig: dns.RrsigData, now: u32) bool {
    return rrsig.isSupportedAlgorithm(sig.algorithm) and rrsig.inWindow(sig, now);
}

/// Iterates the signatures worth a verify: the zone's own, usable now, at
/// most `max_sigs_per_set`. `passed` records that some covering one was
/// skipped.
pub const Weighed = struct {
    rrs: []const dns.ResourceRecord,
    owner: dns.Name,
    rtype: dns.RType,
    zone: dns.Name,
    now: u32,
    /// For proof records, which are never wildcard-expanded (RFC 4035
    /// §3.1.3.3). Else a real `*.zone NSEC` signature verifies under any
    /// owner, and the proof reads the owner as served.
    unexpanded: bool = false,
    at: usize = 0,
    n: usize = 0,
    passed: bool = false,

    pub inline fn next(w: *Weighed) ?usize {
        while (w.at < w.rrs.len) {
            const i = w.at;
            w.at += 1;
            const rr = w.rrs[i];
            if (rr.rtype != .rrsig) continue;
            const sig = rr.rrsig();
            if (sig.type_covered != w.rtype or !rr.name.eql(w.owner)) continue;
            if (w.n == max_sigs_per_set or !sig.signer_name.eql(w.zone) or !usable(sig, w.now) or
                (w.unexpanded and sig.labels != rrsig.signedLabels(w.owner)))
            {
                w.passed = true;
                continue;
            }
            w.n += 1;
            return i;
        }
        return null;
    }
};

const Verified = struct { sig: dns.RrsigData, unweighed: bool };

/// Regroups a section in place into sets (RFC 2181 §5): each set where it
/// first appears, followed by its signatures, all at their lowest TTL. A
/// signature stays only if its signer could hold the set. Signatures over
/// no set are dropped unless `bare_sigs` (an RRSIG query's data).
pub fn bindSets(scratch: mem.Allocator, rrs: []dns.ResourceRecord, bare_sigs: bool) ![]dns.ResourceRecord {
    if (rrs.len < 2) return if (rrs.len == 1 and rrs[0].rtype == .rrsig and !bare_sigs) rrs[0..0] else rrs;
    const By = struct {
        rrs: []const dns.ResourceRecord,

        fn order(c: @This(), x: u32, y: u32) std.math.Order {
            const p = c.rrs[x];
            const q = c.rrs[y];
            const t = std.math.order(@backingInt(covers(p)), @backingInt(covers(q)));
            return if (t != .eq) t else p.name.order(q.name);
        }

        fn lessThan(c: @This(), x: u32, y: u32) bool {
            const o = c.order(x, y);
            return if (o != .eq) o == .lt else @intFromBool(c.rrs[x].rtype == .rrsig) < @intFromBool(c.rrs[y].rtype == .rrsig);
        }
    };
    const src = try scratch.dupe(dns.ResourceRecord, rrs);
    const by: By = .{ .rrs = src };
    const at = try scratch.alloc(u32, rrs.len);
    for (at, 0..) |*x, i| x.* = @intCast(i);
    // Must be stable: a set keeps the order it arrived in.
    std.mem.sort(u32, at, by, By.lessThan);
    const Kept = struct { lo: u32 = 0, hi: u32 = 0 };
    const kept = try scratch.alloc(Kept, rrs.len);
    @memset(kept, .{});
    var i: usize = 0;
    while (i < at.len) {
        var j = i + 1;
        while (j < at.len and by.order(at[i], at[j]) == .eq) j += 1;
        var hi = i;
        if (src[at[i]].rtype == .rrsig) {
            if (bare_sigs) hi = j;
        } else {
            const apex = proof.deepestApex(src[at[i]].name, covers(src[at[i]]));
            var ttl: u32 = std.math.maxInt(u32);
            for (at[i..j]) |k| {
                if (src[k].rtype == .rrsig and !apex.isSubdomainOf(src[k].rrsig().signer_name)) continue;
                ttl = @min(ttl, src[k].ttl);
                at[hi] = k;
                hi += 1;
            }
            for (at[i..hi]) |k| src[k].ttl = ttl;
        }
        for (at[i..hi]) |k| kept[k] = .{ .lo = @intCast(i), .hi = @intCast(hi) };
        i = j;
    }
    var n: usize = 0;
    for (0..rrs.len) |r| {
        const group = kept[r];
        for (at[group.lo..group.hi]) |k| {
            rrs[n] = src[k];
            n += 1;
            kept[k] = .{};
        }
    }
    return rrs[0..n];
}

/// Only valid on `bindSets` output, where a set and its signatures are
/// contiguous.
pub fn setFrom(rrs: []const dns.ResourceRecord, i: usize) []const dns.ResourceRecord {
    const t = covers(rrs[i]);
    var j = i + 1;
    while (j < rrs.len and covers(rrs[j]) == t and rrs[j].name.eql(rrs[i].name)) j += 1;
    return rrs[i..j];
}

pub fn setAt(rrs: []const dns.ResourceRecord, owner: dns.Name, rtype: dns.RType) []const dns.ResourceRecord {
    for (rrs, 0..) |rr, i| if (rr.rtype == rtype and rr.name.eql(owner)) return setFrom(rrs, i);
    return &.{};
}

pub fn covers(rr: dns.ResourceRecord) dns.RType {
    return if (rr.rtype == .rrsig) rr.rrsig().type_covered else rr.rtype;
}

/// `dnskey_records` must be the keyset of this set's signer. Callers read
/// TTL and wildcard facts from the returned signature only: an appended
/// unverifiable RRSIG must not drive them.
pub fn validateRrset(
    scratch: mem.Allocator,
    records: []const dns.ResourceRecord,
    owner: dns.Name,
    covered_type: dns.RType,
    unexpanded: bool,
    dnskey_records: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *rrsig.ValidationBudget,
    memo: *rrsig.VerifyMemo,
) !?Verified {
    const set = try collect(scratch, records, owner, covered_type);
    if (set.records.len == 0) return null;
    const keyset: Keyset = try .init(scratch, dnskey_records);

    var it: Weighed = .{ .rrs = records, .owner = owner, .rtype = covered_type, .zone = keyset.zone orelse return null, .now = now_u32, .unexpanded = unexpanded };
    while (it.next()) |i| {
        const sig = records[i].rrsig();
        if (rrsetVerifiesWithAnyKey(sig, &keyset, set, now_u32, budget, memo) catch return null) {
            // Drain so `passed` covers the signatures after the one that verified.
            while (it.next()) |_| {}
            return .{ .sig = sig, .unweighed = it.passed };
        }
    }
    return null;
}

/// Null is bogus, including a section with no NSEC or NSEC3 at all. NS and
/// glue are unsigned delegation data and are not checked.
pub fn verifyAuthorityProofSigs(
    scratch: mem.Allocator,
    authorities: []const dns.ResourceRecord,
    dnskey_records: []const dns.ResourceRecord,
    now_u32: u32,
    budget: *rrsig.ValidationBudget,
    memo: *rrsig.VerifyMemo,
) !?rrsig.Cap {
    for (authorities) |rr| {
        if (rr.rtype == .nsec or rr.rtype == .nsec3) break;
    } else return null;
    if (proof.proofFlood(authorities)) return null;
    const keyset: Keyset = try .init(scratch, dnskey_records);
    const zone = keyset.zone orelse return null;

    var cap: rrsig.Cap = .none;
    for (authorities, 0..) |rr, i| {
        if (rr.rtype != .nsec and rr.rtype != .nsec3 and rr.rtype != .soa) continue;
        const seen = for (authorities[0..i]) |prev| {
            if (prev.rtype == rr.rtype and prev.name.eql(rr.name)) break true;
        } else false;
        if (seen) continue;

        const set = try collect(scratch, authorities, rr.name, rr.rtype);
        var it: Weighed = .{ .rrs = authorities, .owner = rr.name, .rtype = rr.rtype, .zone = zone, .now = now_u32, .unexpanded = true };
        const sig = while (it.next()) |j| {
            const sig = authorities[j].rrsig();
            if (rrsetVerifiesWithAnyKey(sig, &keyset, set, now_u32, budget, memo) catch return null) break sig;
        } else return null;
        cap = cap.meet(.of(sig, now_u32));
    }
    return cap;
}

test "isValidZoneKey (RFC 4034 §2.1.1–2)" {
    try testing.expect(isValidZoneKey(.{ .flags = 256, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(isValidZoneKey(.{ .flags = 257, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 0, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 1, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 256, .protocol = 0, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 256, .protocol = 1, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 256 | 0x80, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
    try testing.expect(!isValidZoneKey(.{ .flags = 257 | 0x80, .protocol = 3, .algorithm = .rsasha256, .public_key = &.{} }));
}

const test_dnskey = dns.DnskeyData{
    .flags = 257,
    .protocol = 3,
    .algorithm = .rsasha256,
    .public_key = &.{ 0x03, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD },
};

test "DS: RFC 4034 §5.4 (SHA-1) and RFC 6605 §6.2 (SHA-384) examples verify, and a flipped bit does not" {
    const Case = struct { owner: dns.Name, flags: u16, algorithm: dns.DnssecAlgorithm, key_b64: []const u8, tag: u16, digest_type: dns.DigestType, digest_hex: []const u8 };
    for ([_]Case{ .{
        .owner = .lit("dskey.example.com"),
        .flags = 256,
        .algorithm = .rsasha1,
        .key_b64 = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ" ++
            "DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc" ++
            "nOf+EPbtG9DMBmADjFDc2w/rljwvFw==",
        .tag = 60485,
        .digest_type = .sha1,
        .digest_hex = "2BB183AF5F22588179A53B0A98631FAD1A292118",
    }, .{
        .owner = .lit("example.net"),
        .flags = 257,
        .algorithm = .ecdsap384sha384,
        .key_b64 = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X" ++
            "1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
        .tag = 10771,
        .digest_type = .sha384,
        .digest_hex = "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0" ++
            "563a9b5f4d288405c3008a946df983d6",
    } }) |c| {
        var key: [130]u8 = undefined;
        const key_len = try std.base64.standard.Decoder.calcSizeForSlice(c.key_b64);
        try std.base64.standard.Decoder.decode(key[0..key_len], c.key_b64);
        var digest: [48]u8 = undefined;
        const d = try std.fmt.hexToBytes(&digest, c.digest_hex);
        const dnskey: dns.DnskeyData = .{ .flags = c.flags, .protocol = 3, .algorithm = c.algorithm, .public_key = key[0..key_len] };
        try testing.expectEqual(c.tag, rrsig.keyTag(dnskey));
        try verifyDs(.{ .key_tag = c.tag, .algorithm = c.algorithm, .digest_type = c.digest_type, .digest = d }, dnskey, c.owner);
        d[0] ^= 1;
        try testing.expectError(error.InvalidSignature, verifyDs(.{ .key_tag = c.tag, .algorithm = c.algorithm, .digest_type = c.digest_type, .digest = d }, dnskey, c.owner));
    }
}

test "anySupportedDs: unsupported algorithm or digest contributes no path" {
    const zero_digest: [32]u8 = @splat(0);
    const ds_rr = struct {
        fn make(algo: dns.DnssecAlgorithm, digest_type: dns.DigestType) dns.ResourceRecord {
            return .fixture(.{
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
            });
        }
    }.make;

    try testing.expect(!anySupportedDs(&.{ds_rr(.ed448, .sha256)}));
    try testing.expect(!anySupportedDs(&.{ds_rr(.ecdsap256sha256, @fromBackingInt(3))}));
    try testing.expect(!anySupportedDs(&.{}));
    try testing.expect(anySupportedDs(&.{ ds_rr(.ed448, .sha256), ds_rr(.ecdsap256sha256, .sha256) }));
    try testing.expect(anySupportedDs(&.{ds_rr(.mldsa44, .sha256)}));
}

test "validateDnskeyRrset: 65 keys verify whole, and a signature over 64 launders no 65th" {
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

    const kp = std.crypto.sign.Ed25519.KeyPair.generate(testing.io);
    var signer_pub = kp.public_key.toBytes();
    recs[0] = dnskeyRr(rrsig.test_owner, .{ .flags = 256, .protocol = 3, .algorithm = .ed25519, .public_key = &signer_pub });
    var part_sig: [64]u8 = undefined;
    const part = try rrsig.testSignRrsetBy(kp, recs[0..64], .dnskey, rrsig.test_owner, .ed25519, &part_sig, &signer_pub);
    var whole_sig: [64]u8 = undefined;
    const whole = try rrsig.testSignRrsetBy(kp, &recs, .dnskey, rrsig.test_owner, .ed25519, &whole_sig, &signer_pub);

    var digest = dsDigest(Sha256, rrsig.test_owner, whole.dnskey);
    const ds = dns.DsData{
        .key_tag = rrsig.keyTag(whole.dnskey),
        .algorithm = .ed25519,
        .digest_type = .sha256,
        .digest = &digest,
    };

    var set: [66]dns.ResourceRecord = undefined;
    @memcpy(set[0..65], &recs);
    set[65] = rrsigRr(rrsig.test_owner, whole.rrsig);
    var budget: rrsig.ValidationBudget = .{};
    _ = (try validateDnskeyRrset(test_scratch.allocator(), &set, &.{ds}, rrsig.test_owner, 1_700_000_000, &budget, test_memo)).?;

    set[65] = rrsigRr(rrsig.test_owner, part.rrsig);
    var budget2: rrsig.ValidationBudget = .{};
    try testing.expect(try validateDnskeyRrset(test_scratch.allocator(), &set, &.{ds}, rrsig.test_owner, 1_700_000_000, &budget2, test_memo) == null);
}

test "validateDnskeyRrset caps the KeyTrap key×signature cross-product at the budget" {
    var digest = dsDigest(Sha256, rrsig.test_owner, test_dnskey);
    const ds = dns.DsData{
        .key_tag = rrsig.keyTag(test_dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };

    var records: [43]dns.ResourceRecord = undefined;
    for (records[0..3]) |*r| r.* = .fixture(.{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 86400, .rdata = .{ .dnskey = test_dnskey } });
    for (records[3..43]) |*r| r.* = .fixture(.{
        .name = rrsig.test_owner,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 86400,
        .rdata = .{ .rrsig = .{
            .type_covered = .dnskey,
            .algorithm = .rsasha256,
            .labels = 2,
            .original_ttl = 86400,
            .sig_expiration = 1700086400,
            .sig_inception = 0,
            .key_tag = ds.key_tag,
            .signer_name = rrsig.test_owner,
            .signature = &.{ 0xDE, 0xAD, 0xBE, 0xEF },
        } },
    });

    const cap: u32 = 8;
    var budget: rrsig.ValidationBudget = .{ .max_sig_verify = cap };
    try testing.expect(try validateDnskeyRrset(test_scratch.allocator(), &records, &.{ds}, rrsig.test_owner, 1700000000, &budget, test_memo) == null);
    try testing.expectEqual(cap, budget.sig_verify_spent);
    try testing.expect(budget.stopped != null);
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

    var mx = [_]dns.ResourceRecord{.fixture(.{
        .name = rrsig.test_owner,
        .rtype = .mx,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .mx = .{ .preference = 10, .exchange = .lit("mail.example.com") } },
    })};
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
    try rrsig.verifyRrsig(sig, dnskey, .sort(&mx), 1439000000, &budget, test_memo);

    signature[100] ^= 1;
    try testing.expectError(error.InvalidSignature, rrsig.verifyRrsig(sig, dnskey, .sort(&mx), 1439000000, &budget, test_memo));
    signature[100] ^= 1;
    sig.signer_name = .lit("com");
    try testing.expectError(error.InvalidSignature, rrsig.verifyRrsig(sig, dnskey, .sort(&mx), 1439000000, &budget, test_memo));
}

test "NsecTrap: a proof flood is refused before any RRSIG is tried" {
    const zone: dns.Name = .lit("example.com");
    const next_owner: [20]u8 = @splat(0xFF);
    const key: dns.ResourceRecord = .fixture(.{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 300, .rdata = .{ .dnskey = test_dnskey } });
    var bufs: [2 * (proof.max_proof_records + 1)]proof.Nsec3OwnerBufs = undefined;
    var rrs: [2 * (proof.max_proof_records + 1)]dns.ResourceRecord = undefined;
    for (0..proof.max_proof_records + 1) |i| {
        bufs[i] = .{};
        const owner = proof.makeNsec3OwnerName(@as([20]u8, @splat(@as(u8, @intCast(i ^ 0xA5)))), zone, &bufs[i]);
        rrs[2 * i] = proof.makeNsec3Rr(owner, &.{}, &next_owner, &.{});
        rrs[2 * i + 1] = .fixture(.{ .name = owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = .{
            .type_covered = .nsec3,
            .algorithm = .rsasha256,
            .labels = 3,
            .original_ttl = 300,
            .sig_expiration = 1700086400,
            .sig_inception = 0,
            .key_tag = rrsig.keyTag(test_dnskey),
            .signer_name = rrsig.test_owner,
            .signature = &.{ 0xDE, 0xAD },
        } } });
    }
    var at_cap: rrsig.ValidationBudget = .{};
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), rrs[0 .. 2 * proof.max_proof_records], &.{key}, 1700000000, &at_cap, test_memo) == null);
    try testing.expect(at_cap.sig_verify_spent > 0);
    var past: rrsig.ValidationBudget = .{};
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), &rrs, &.{key}, 1700000000, &past, test_memo) == null);
    try testing.expectEqual(@as(u32, 0), past.sig_verify_spent);
}

fn dnskeyRr(owner: dns.Name, dnskey: dns.DnskeyData) dns.ResourceRecord {
    return .fixture(.{ .name = owner, .rtype = .dnskey, .rclass = .in, .ttl = 300, .rdata = .{ .dnskey = dnskey } });
}

fn rrsigRr(owner: dns.Name, sig: dns.RrsigData) dns.ResourceRecord {
    return .fixture(.{ .name = owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = sig } });
}

test "verifyAuthorityProofSigs: every proof owner must verify (RFC 4035 §5.3)" {
    const alpha = dns.Name.lit("alpha.example.com");
    const gamma = dns.Name.lit("gamma.example.com");
    const nsecs = [_]dns.ResourceRecord{
        proof.nsecRr(alpha, .lit("beta.example.com")),
        proof.nsecRr(gamma, .lit("delta.example.com")),
    };
    var sig_bufs: [2][64]u8 = undefined;
    var pub_bufs: [2][32]u8 = undefined;
    const a = try rrsig.testSignRrset(nsecs[0..1], .nsec, rrsig.test_owner, .ed25519, &sig_bufs[0], &pub_bufs[0]);
    const g = try rrsig.testSignRrset(nsecs[1..2], .nsec, rrsig.test_owner, .ed25519, &sig_bufs[1], &pub_bufs[1]);
    const dnskeys = [_]dns.ResourceRecord{ dnskeyRr(rrsig.test_owner, a.dnskey), dnskeyRr(rrsig.test_owner, g.dnskey) };
    const signed = [_]dns.ResourceRecord{ nsecs[0], rrsigRr(alpha, a.rrsig), nsecs[1], rrsigRr(gamma, g.rrsig) };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), &signed, &dnskeys, 1_700_000_000, &budget, test_memo) != null);
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), signed[0..3], &dnskeys, 1_700_000_000, &budget, test_memo) == null);
}

test "verifyAuthorityProofSigs: a signature over part of a set verifies none of it" {
    const nsec = [_]dns.ResourceRecord{proof.nsecRr(rrsig.test_owner, .lit("a.example.com"))};
    var soas: [17]dns.ResourceRecord = undefined;
    for (&soas, 0..) |*r, i| r.* = .fixture(.{ .name = rrsig.test_owner, .rtype = .soa, .rclass = .in, .ttl = 300, .rdata = .{ .soa = .{
        .mname = rrsig.test_owner,
        .rname = rrsig.test_owner,
        .serial = @intCast(i),
        .refresh = 0,
        .retry = 0,
        .expire = 0,
        .minimum = 300,
    } } });
    var sig_bufs: [2][64]u8 = undefined;
    var pub_bufs: [2][32]u8 = undefined;
    const n = try rrsig.testSignRrset(&nsec, .nsec, rrsig.test_owner, .ed25519, &sig_bufs[0], &pub_bufs[0]);
    const s = try rrsig.testSignRrset(soas[0..16], .soa, rrsig.test_owner, .ed25519, &sig_bufs[1], &pub_bufs[1]);
    const dnskeys = [_]dns.ResourceRecord{ dnskeyRr(rrsig.test_owner, n.dnskey), dnskeyRr(rrsig.test_owner, s.dnskey) };
    const sigs = [_]dns.ResourceRecord{ nsec[0], rrsigRr(rrsig.test_owner, n.rrsig), rrsigRr(rrsig.test_owner, s.rrsig) };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), &(sigs ++ soas[0..16].*), &dnskeys, 1_700_000_000, &budget, test_memo) != null);
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), &(sigs ++ soas), &dnskeys, 1_700_000_000, &budget, test_memo) == null);
}

test "validateRrset: a genuine RRSIG under another owner does not sign this RRset" {
    const now: u32 = 1_700_000_000;
    const recs = [_]dns.ResourceRecord{
        .fixture(.{ .name = rrsig.test_owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } }),
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try rrsig.testSignRrset(&recs, .a, rrsig.test_owner, .ed25519, &sig_bytes, &pub_bytes);
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, signed.dnskey)};
    const sig_at = struct {
        fn f(owner: dns.Name, sig: dns.RrsigData) dns.ResourceRecord {
            return .fixture(.{ .name = owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = sig } });
        }
    }.f;

    var budget: rrsig.ValidationBudget = .{};
    const moved = [_]dns.ResourceRecord{ recs[0], sig_at(.lit("other.com"), signed.rrsig) };
    try testing.expect(try validateRrset(test_scratch.allocator(), &moved, rrsig.test_owner, .a, false, &dnskeys, now, &budget, test_memo) == null);
    const home = [_]dns.ResourceRecord{ recs[0], sig_at(rrsig.test_owner, signed.rrsig) };
    try testing.expect(try validateRrset(test_scratch.allocator(), &home, rrsig.test_owner, .a, false, &dnskeys, now, &budget, test_memo) != null);
}

test "verifyAuthorityProofSigs refuses a wildcard-expanded NSEC" {
    const star = dns.Name.lit("*.example.com");
    const a = dns.Name.lit("a.example.com");
    const v = dns.Name.lit("v.example.com");
    const real = [_]dns.ResourceRecord{proof.nsecRr(star, a)};
    var sig_buf: [64]u8 = undefined;
    var pub_buf: [32]u8 = undefined;
    const signed = try rrsig.testSignRrset(&real, .nsec, rrsig.test_owner, .ed25519, &sig_buf, &pub_buf);
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, signed.dnskey)};
    const sig_rr = dns.ResourceRecord.fixture(.{ .name = v, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } });
    const replayed = [_]dns.ResourceRecord{ proof.nsecRr(v, a), sig_rr };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), &replayed, &dnskeys, 1_700_000_000, &budget, test_memo) == null);

    const own_sig = dns.ResourceRecord.fixture(.{ .name = star, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } });
    const genuine = [_]dns.ResourceRecord{ real[0], own_sig };
    var budget2: rrsig.ValidationBudget = .{};
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), &genuine, &dnskeys, 1_700_000_000, &budget2, test_memo) != null);

    var fewer = signed.rrsig;
    fewer.labels -= 1;
    const stray = dns.ResourceRecord.fixture(.{ .name = star, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = fewer } });
    const strayed = [_]dns.ResourceRecord{ real[0], stray, own_sig };
    var budget3: rrsig.ValidationBudget = .{};
    try testing.expect(try verifyAuthorityProofSigs(test_scratch.allocator(), &strayed, &dnskeys, 1_700_000_000, &budget3, test_memo) != null);
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
        .labels = rrsig.signedLabels(rrset[0].name),
        .original_ttl = 300,
        .sig_inception = 1_699_000_000,
        .sig_expiration = 1_800_000_000,
        .key_tag = rrsig.keyTag(dnskey),
        .signer_name = signer,
        .signature = &.{},
    };
    const set = try testing.allocator.dupe(dns.ResourceRecord, rrset);
    defer testing.allocator.free(set);
    const data = rrsig.buildSignedData(sig, .sort(set));
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
    const ed_kp = std.crypto.sign.Ed25519.KeyPair.generate(testing.io);
    var ed_pub = ed_kp.public_key.toBytes();
    var ed_sig: [64]u8 = undefined;
    const ed_key = dns.DnskeyData{ .flags = 256, .protocol = 3, .algorithm = .ed25519, .public_key = &ed_pub };
    const key = struct {
        fn rr(dk: dns.DnskeyData) dns.ResourceRecord {
            return .fixture(.{ .name = rrsig.test_owner, .rtype = .dnskey, .rclass = .in, .ttl = 300, .rdata = .{ .dnskey = dk } });
        }
        fn sig(s: dns.RrsigData) dns.ResourceRecord {
            return .fixture(.{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = s } });
        }
    };
    const keys = [_]dns.ResourceRecord{ key.rr(ed_key), key.rr(pq_key) };
    const ed = try rrsig.testSignRrsetBy(ed_kp, &keys, .dnskey, rrsig.test_owner, .ed25519, &ed_sig, &ed_pub);
    var pq_sig: [MlDsa44.Signature.encoded_length]u8 = undefined;
    const pq = try testSignMlDsa(&keys, .dnskey, rrsig.test_owner, pq_key, &pq_kp, &pq_sig);
    var ed_digest = dsDigest(Sha256, rrsig.test_owner, ed_key);
    var pq_digest = dsDigest(Sha256, rrsig.test_owner, pq_key);
    const ed_ds = dns.DsData{ .key_tag = rrsig.keyTag(ed_key), .algorithm = .ed25519, .digest_type = .sha256, .digest = &ed_digest };
    const pq_ds = dns.DsData{ .key_tag = rrsig.keyTag(pq_key), .algorithm = .mldsa44, .digest_type = .sha256, .digest = &pq_digest };

    const stripped = keys ++ [_]dns.ResourceRecord{key.sig(ed.rrsig)};
    var b1: rrsig.ValidationBudget = .{};
    try testing.expect(try validateDnskeyRrset(test_scratch.allocator(), &stripped, &.{ ed_ds, pq_ds }, rrsig.test_owner, 1_700_000_000, &b1, test_memo) == null);

    const dual = keys ++ [_]dns.ResourceRecord{ key.sig(ed.rrsig), key.sig(pq) };
    var b2: rrsig.ValidationBudget = .{};
    try testing.expectEqual(dns.DnssecAlgorithm.mldsa44, (try validateDnskeyRrset(test_scratch.allocator(), &dual, &.{ ed_ds, pq_ds }, rrsig.test_owner, 1_700_000_000, &b2, test_memo)).?.algorithm);
    const dual_rev = keys ++ [_]dns.ResourceRecord{ key.sig(pq), key.sig(ed.rrsig) };
    try testing.expectEqual(dns.DnssecAlgorithm.mldsa44, (try validateDnskeyRrset(test_scratch.allocator(), &dual_rev, &.{ pq_ds, ed_ds }, rrsig.test_owner, 1_700_000_000, &b2, test_memo)).?.algorithm);

    const odd_ds = dns.DsData{ .key_tag = rrsig.keyTag(pq_key), .algorithm = .mldsa44, .digest_type = @fromBackingInt(9), .digest = &pq_digest };
    var b4: rrsig.ValidationBudget = .{};
    try testing.expectEqual(dns.DnssecAlgorithm.ed25519, (try validateDnskeyRrset(test_scratch.allocator(), &stripped, &.{ ed_ds, odd_ds }, rrsig.test_owner, 1_700_000_000, &b4, test_memo)).?.algorithm);
    var pq_sha1 = dsDigest(Sha1, rrsig.test_owner, pq_key);
    const sha1_ds = dns.DsData{ .key_tag = rrsig.keyTag(pq_key), .algorithm = .mldsa44, .digest_type = .sha1, .digest = &pq_sha1 };
    try testing.expectEqual(dns.DnssecAlgorithm.ed25519, (try validateDnskeyRrset(test_scratch.allocator(), &stripped, &.{ ed_ds, sha1_ds }, rrsig.test_owner, 1_700_000_000, &b4, test_memo)).?.algorithm);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(dual.len, (try usableKeys(arena.allocator(), &dual, &.{ed_ds})).len);
    const kept = try usableKeys(arena.allocator(), &dual, &.{ ed_ds, pq_ds });
    try testing.expectEqual(@as(usize, 1), kept.len);
    try testing.expectEqual(dns.DnssecAlgorithm.mldsa44, kept[0].dnskey().algorithm);

    var b3: rrsig.ValidationBudget = .{};
    try testing.expectEqual(dns.DnssecAlgorithm.ed25519, (try validateDnskeyRrset(test_scratch.allocator(), &stripped, &.{ed_ds}, rrsig.test_owner, 1_700_000_000, &b3, test_memo)).?.algorithm);
}

test "validateDnskeyRrset: RRSIG algorithm must match the DS-anchored key's" {
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    var recs: [2]dns.ResourceRecord = undefined;
    recs[0] = dnskeyRr(rrsig.test_owner, .{ .flags = 256, .protocol = 3, .algorithm = .rsasha256, .public_key = &pub_bytes });
    const signed = try rrsig.testSignRrset(recs[0..1], .dnskey, rrsig.test_owner, .rsasha256, &sig_bytes, &pub_bytes);
    recs[1] = .fixture(.{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = signed.rrsig } });

    var digest = dsDigest(Sha256, rrsig.test_owner, signed.dnskey);
    const ds = dns.DsData{
        .key_tag = rrsig.keyTag(signed.dnskey),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .digest = &digest,
    };
    var budget: rrsig.ValidationBudget = .{};
    try testing.expect(try validateDnskeyRrset(test_scratch.allocator(), &recs, &.{ds}, rrsig.test_owner, 1_700_000_000, &budget, test_memo) == null);
}

test "validateRrset: the TTL cap comes from the signature that verified" {
    const now: u32 = 1_700_000_000;
    const recs = [_]dns.ResourceRecord{
        .fixture(.{ .name = rrsig.test_owner, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 1, 2, 3, 4 } } }),
    };
    var sig_bytes: [64]u8 = undefined;
    var pub_bytes: [32]u8 = undefined;
    const signed = try rrsig.testSignRrset(&recs, .a, rrsig.test_owner, .ed25519, &sig_bytes, &pub_bytes);

    var junk = signed.rrsig;
    junk.key_tag = signed.rrsig.key_tag ^ 0x5555;
    junk.original_ttl = 1;
    junk.sig_expiration = now + 1;

    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, signed.dnskey)};
    const answers = [_]dns.ResourceRecord{
        recs[0],
        .fixture(.{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = junk } }),
        .fixture(.{ .name = rrsig.test_owner, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = signed.rrsig } }),
    };
    var budget: rrsig.ValidationBudget = .{};
    const sig = (try validateRrset(test_scratch.allocator(), &answers, rrsig.test_owner, .a, false, &dnskeys, now, &budget, test_memo)).?.sig;
    try testing.expectEqual(@as(u32, 300), rrsig.Cap.of(sig, now).original_ttl);
}

test "validateRrset: 70 records verify whole, and a signature over 64 launders no other 6" {
    var recs: [70]dns.ResourceRecord = undefined;
    for (&recs, 0..) |*r, i| r.* = .fixture(.{
        .name = rrsig.test_owner,
        .rtype = .a,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .a = .{ 10, 0, @intCast(i / 256), @intCast(i % 256) } },
    });
    const kp = std.crypto.sign.Ed25519.KeyPair.generate(testing.io);
    var pub_bytes: [32]u8 = undefined;
    var part_sig: [64]u8 = undefined;
    const part = try rrsig.testSignRrsetBy(kp, recs[0..64], .a, rrsig.test_owner, .ed25519, &part_sig, &pub_bytes);
    var whole_sig: [64]u8 = undefined;
    const whole = try rrsig.testSignRrsetBy(kp, &recs, .a, rrsig.test_owner, .ed25519, &whole_sig, &pub_bytes);
    const dnskeys = [_]dns.ResourceRecord{dnskeyRr(rrsig.test_owner, whole.dnskey)};

    var answers: [71]dns.ResourceRecord = undefined;
    @memcpy(answers[0..70], &recs);
    answers[70] = rrsigRr(rrsig.test_owner, whole.rrsig);
    var budget: rrsig.ValidationBudget = .{};
    try testing.expect(try validateRrset(test_scratch.allocator(), &answers, rrsig.test_owner, .a, false, &dnskeys, 1_700_000_000, &budget, test_memo) != null);

    answers[70] = rrsigRr(rrsig.test_owner, part.rrsig);
    var budget2: rrsig.ValidationBudget = .{};
    try testing.expect(try validateRrset(test_scratch.allocator(), &answers, rrsig.test_owner, .a, false, &dnskeys, 1_700_000_000, &budget2, test_memo) == null);
}
