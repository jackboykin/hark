//! RFC 6147 DNS64, on when `dns64-prefix` is set; applied by answer.zig.
//! AAAA NODATA → resolve A and embed. PTR under
//! the prefix → the in-addr.arpa PTRs re-owned (Unbound's rename, not the
//! §5.3.1 CNAME). CD=1 disables it. A SERVFAILed AAAA stays SERVFAIL: §5.1.2
//! says treat as empty, §5.5 forbids laundering a bogus one, and bogus is
//! indistinguishable from lame here. Mixed real+`::ffff` sets pass through
//! untouched; stripping members would orphan the RRSIG.
const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const acl = @import("acl.zig");
const dns = @import("dns.zig");
const na = @import("net_address.zig");

pub const Prefix = struct {
    bytes: [16]u8,
    /// RFC 6052 §2.2: 32, 40, 48, 56, 64 or 96.
    len: u8,

    pub const well_known: Prefix = .{ .bytes = .{ 0, 0x64, 0xff, 0x9b } ++ @as([12]u8, @splat(0)), .len = 96 };

    pub fn parse(s: []const u8) ?Prefix {
        const cidr = acl.parse(s) orelse return null;
        if (cidr.address != .ip6) return null;
        return switch (cidr.prefix) {
            32, 40, 48, 56, 64, 96 => .{ .bytes = cidr.address.ip6.bytes, .len = cidr.prefix },
            else => null,
        };
    }

    pub fn contains(p: Prefix, v6: *const [16]u8) bool {
        return mem.eql(u8, v6[0 .. p.len / 8], p.bytes[0 .. p.len / 8]);
    }

    /// RFC 6052 §2.2: byte of the i-th IPv4 octet; the u-octet at 8 is skipped.
    fn slot(p: Prefix, i: usize) usize {
        const k = p.len / 8 + i;
        return if (p.len < 96 and k >= 8) k + 1 else k;
    }

    pub fn embed(p: Prefix, v4: [4]u8) [16]u8 {
        var out = p.bytes;
        for (v4, 0..) |b, i| out[p.slot(i)] = b;
        return out;
    }

    pub fn extract(p: Prefix, v6: *const [16]u8) [4]u8 {
        var out: [4]u8 = undefined;
        for (&out, 0..) |*b, i| b.* = v6[p.slot(i)];
        return out;
    }
};

/// §5.1.2, §5.1.4: NOERROR with no AAAA beyond `::ffff:0:0/96`.
pub fn wantsSynthesis(rcode: dns.RCode, answers: []const dns.ResourceRecord) bool {
    if (rcode != .no_error) return false;
    for (answers) |rr| if (rr.rtype == .aaaa and !na.isIp4Mapped(rr.rdata)) return false;
    return true;
}

/// The A reply's answers with each A embedded under `p` and the A RRSIG
/// dropped; null when there is no A to embed. §5.1.7: TTL capped by the
/// negative's SOA, else 600 s. AD is the caller's to clear.
pub fn synthesizeAaaa(alloc: mem.Allocator, p: Prefix, a: []const dns.ResourceRecord, negative_authorities: []const dns.ResourceRecord) !?[]dns.ResourceRecord {
    for (a) |rr| {
        if (rr.rtype == .a) break;
    } else return null;
    const cap = for (negative_authorities) |rr| {
        if (rr.rtype == .soa) break rr.ttl;
    } else 600;
    const out = try alloc.alloc(dns.ResourceRecord, a.len);
    var n: usize = 0;
    for (a) |rr| {
        if (rr.covers() == .a) continue;
        out[n] = if (rr.rtype != .a) rr else blk: {
            const addr = try alloc.create([16]u8);
            addr.* = p.embed(rr.a());
            break :blk .{ .name = rr.name, .rtype = .aaaa, .rclass = rr.rclass, .ttl = @min(rr.ttl, cap), .rdata = addr };
        };
        n += 1;
    }
    return out[0..n];
}

pub fn parseIp6Arpa(name: dns.Name) ?[16]u8 {
    const w = name.wire;
    const suffix = "\x03ip6\x04arpa\x00";
    if (w.len != 2 * 32 + suffix.len or !mem.endsWith(u8, w, suffix)) return null;
    var out: [16]u8 = undefined;
    for (0..32) |i| {
        if (w[2 * i] != 1) return null;
        const nib = std.fmt.charToDigit(w[2 * i + 1], 16) catch return null;
        const byte = &out[15 - i / 2];
        if (i % 2 == 0) byte.* = nib else byte.* |= nib << 4;
    }
    return out;
}

/// CNAMEs (RFC 2317) and RRSIGs are untrue under the new owner.
pub fn renamePtr(alloc: mem.Allocator, answers: []const dns.ResourceRecord, qname: dns.Name) ![]dns.ResourceRecord {
    const owner = try qname.clone(alloc);
    const out = try alloc.alloc(dns.ResourceRecord, answers.len);
    var n: usize = 0;
    for (answers) |rr| {
        if (rr.rtype != .ptr) continue;
        out[n] = rr;
        out[n].name = owner;
        n += 1;
    }
    return out[0..n];
}

/// RFC 6052 §2.4.
const rfc6052_examples = [_]struct { len: u8, text: []const u8 }{
    .{ .len = 32, .text = "2001:db8:c000:221::" },
    .{ .len = 40, .text = "2001:db8:1c0:2:21::" },
    .{ .len = 48, .text = "2001:db8:122:c000:2:2100::" },
    .{ .len = 56, .text = "2001:db8:122:3c0:0:221::" },
    .{ .len = 64, .text = "2001:db8:122:344:c0:2:2100::" },
    .{ .len = 96, .text = "2001:db8:122:344::c000:221" },
};

test "embed/extract match every RFC 6052 §2.4 example" {
    const v4 = [4]u8{ 192, 0, 2, 33 };
    for (rfc6052_examples) |ex| {
        const want = (try std.Io.net.Ip6Address.parse(ex.text, 0)).bytes;
        var pbytes = want;
        @memset(pbytes[ex.len / 8 ..], 0);
        const p: Prefix = .{ .bytes = pbytes, .len = ex.len };
        try testing.expectEqualSlices(u8, &want, &p.embed(v4));
        try testing.expectEqualSlices(u8, &v4, &p.extract(&want));
        try testing.expect(p.contains(&want));
    }
}

test "parseIp6Arpa round-trips through the nibble order" {
    const addr = Prefix.well_known.embed(.{ 192, 0, 2, 1 });
    const name: dns.Name = .lit("1.0.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa.");
    try testing.expectEqualSlices(u8, &addr, &parseIp6Arpa(name).?);
    try testing.expectEqual(@as(?[16]u8, null), parseIp6Arpa(.lit("1.0.0.127.in-addr.arpa.")));
    try testing.expectEqual(@as(?[16]u8, null), parseIp6Arpa(name.parent().?));
    // As long as 32 nibbles, but one label holds three.
    try testing.expectEqual(@as(?[16]u8, null), parseIp6Arpa(.lit("abc.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")));
}

test "synthesizeAaaa embeds every A, drops its RRSIG and caps TTL by the SOA" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const al = arena.allocator();
    const host = try dns.parseDottedName(al, "host.example.com.");
    const sig: dns.RrsigData = .{ .type_covered = .a, .algorithm = .ecdsap256sha256, .labels = 3, .original_ttl = 0, .sig_expiration = 0, .sig_inception = 0, .key_tag = 0, .signer_name = host, .signature = "" };
    const a = [_]dns.ResourceRecord{
        .fixture(.{ .name = host, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 192, 0, 2, 1 } } }),
        .fixture(.{ .name = host, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = sig } }),
    };
    const soa = [_]dns.ResourceRecord{.fixture(.{ .name = host, .rtype = .soa, .rclass = .in, .ttl = 300, .rdata = .{ .unknown = "" } })};
    try testing.expect(wantsSynthesis(.no_error, &.{}));
    const out = (try synthesizeAaaa(al, Prefix.well_known, &a, &soa)).?;
    try testing.expectEqual(@as(usize, 1), out.len);
    try testing.expectEqual(dns.RType.aaaa, out[0].rtype);
    try testing.expectEqual(@as(u32, 300), out[0].ttl);
    try testing.expectEqualSlices(u8, &Prefix.well_known.embed(.{ 192, 0, 2, 1 }), out[0].rdata);
    try testing.expect(!wantsSynthesis(.no_error, out));
    try testing.expectEqual(@as(?[]dns.ResourceRecord, null), try synthesizeAaaa(al, Prefix.well_known, &.{}, &soa));
}

test "renamePtr re-owns PTRs to the ip6.arpa qname and drops the RFC 2317 CNAME hop" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const in_addr = try dns.parseDottedName(a, "1.2.0.192.in-addr.arpa.");
    const classless = try dns.parseDottedName(a, "1.0-25.2.0.192.in-addr.arpa.");
    const host = try dns.parseDottedName(a, "host.example.com.");
    const answers = [_]dns.ResourceRecord{
        .fixture(.{ .name = in_addr, .rtype = .cname, .rclass = .in, .ttl = 3600, .rdata = .{ .cname = classless } }),
        .fixture(.{ .name = classless, .rtype = .ptr, .rclass = .in, .ttl = 300, .rdata = .{ .ptr = host } }),
    };
    const qname = try dns.parseDottedName(a, "1.0.2.0.0.0.0.C.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.B.9.F.F.4.6.0.0.ip6.arpa.");
    const out = try renamePtr(a, &answers, qname);
    try testing.expectEqual(@as(usize, 1), out.len);
    try testing.expect(out[0].name.eql(qname));
    try testing.expectEqualSlices(u8, answers[1].rdata, out[0].rdata);
}
