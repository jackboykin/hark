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
pub fn wantsSynthesis(rcode: dns.RCode, answers: []const dns.WireRecord) bool {
    if (rcode != .no_error) return false;
    for (answers) |rr| if (rr.rtype() == .aaaa and !na.isIp4Mapped(rr.rdata())) return false;
    return true;
}

/// The A reply's answers with each A embedded under `p` and the A RRSIG
/// dropped; null when there is no A to embed. §5.1.7: TTL capped by the
/// negative's SOA, else 600 s. AD is the caller's to clear.
pub fn synthesizeAaaa(alloc: mem.Allocator, p: Prefix, a: []const dns.WireRecord, negative_authorities: []const dns.WireRecord) !?[]dns.WireRecord {
    for (a) |rr| {
        if (rr.rtype() == .a) break;
    } else return null;
    const cap = for (negative_authorities) |rr| {
        if (rr.rtype() == .soa) break rr.ttl;
    } else 600;
    const out = try alloc.alloc(dns.WireRecord, a.len);
    var n: usize = 0;
    for (a) |rr| {
        if (rr.covers() == .a) continue;
        out[n] = if (rr.rtype() != .a) rr else blk: {
            const rest = try alloc.alloc(u8, 10 + 16);
            const ttl = @min(rr.ttl, cap);
            mem.writeInt(u16, rest[0..2], @backingInt(dns.RType.aaaa), .big);
            @memcpy(rest[2..4], rr.rest[2..4]);
            mem.writeInt(u32, rest[4..8], ttl, .big);
            mem.writeInt(u16, rest[8..10], 16, .big);
            rest[10..26].* = p.embed(rr.rdata()[0..4].*);
            break :blk .{ .owner = rr.owner, .rest = rest, .ttl = ttl };
        };
        n += 1;
    }
    return out[0..n];
}

pub fn parseIp6Arpa(name: []const u8) ?[16]u8 {
    const s = dns.stripTrailingDot(name);
    const suffix = ".ip6.arpa";
    if (s.len != 2 * 32 - 1 + suffix.len or !std.ascii.endsWithIgnoreCase(s, suffix)) return null;
    var out: [16]u8 = undefined;
    for (0..32) |i| {
        if (s[2 * i + 1] != '.') return null;
        const nib = std.fmt.charToDigit(s[2 * i], 16) catch return null;
        const byte = &out[15 - i / 2];
        if (i % 2 == 0) byte.* = nib else byte.* |= nib << 4;
    }
    return out;
}

/// The PTRs re-owned to `qname`, lowercased; CNAMEs (RFC 2317) and
/// RRSIGs are untrue under the new owner.
pub fn renamePtr(alloc: mem.Allocator, answers: []const dns.WireRecord, qname: dns.Name) ![]dns.WireRecord {
    var buf: [dns.max_name_len + 2]u8 = undefined;
    const owner = try alloc.dupe(u8, buf[0..try dns.writeNameWire(&buf, qname)]);
    // Length bytes are below 'A': lowering the whole name lowers its labels.
    for (owner) |*c| c.* = std.ascii.toLower(c.*);
    const out = try alloc.alloc(dns.WireRecord, answers.len);
    var n: usize = 0;
    for (answers) |rr| {
        if (rr.rtype() != .ptr) continue;
        out[n] = .{ .owner = owner, .rest = rr.rest, .ttl = rr.ttl };
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
    const name = "1.0.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa.";
    try testing.expectEqualSlices(u8, &addr, &parseIp6Arpa(name).?);
    try testing.expectEqualSlices(u8, &addr, &parseIp6Arpa(name[0 .. name.len - 1]).?);
    try testing.expectEqual(@as(?[16]u8, null), parseIp6Arpa("1.0.0.127.in-addr.arpa."));
    try testing.expectEqual(@as(?[16]u8, null), parseIp6Arpa(name[2..]));
    var upper: [name.len]u8 = undefined;
    try testing.expectEqualSlices(u8, &addr, &parseIp6Arpa(std.ascii.upperString(&upper, name)).?);
}

test "synthesizeAaaa embeds every A, drops its RRSIG and caps TTL by the SOA" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const al = arena.allocator();
    const host = try dns.parseDottedName(al, "host.example.com.");
    const sig: dns.RrsigData = .{ .type_covered = .a, .algorithm = .ecdsap256sha256, .labels = 3, .original_ttl = 0, .sig_expiration = 0, .sig_inception = 0, .key_tag = 0, .signer_name = host, .signature = "" };
    const a = [_]dns.WireRecord{
        try .from(al, .{ .name = host, .rtype = .a, .rclass = .in, .ttl = 3600, .rdata = .{ .a = .{ 192, 0, 2, 1 } } }),
        try .from(al, .{ .name = host, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = sig } }),
    };
    const soa = [_]dns.WireRecord{try .from(al, .{ .name = host, .rtype = .soa, .rclass = .in, .ttl = 300, .rdata = .{ .unknown = "" } })};
    try testing.expect(wantsSynthesis(.no_error, &.{}));
    const out = (try synthesizeAaaa(al, Prefix.well_known, &a, &soa)).?;
    try testing.expectEqual(@as(usize, 1), out.len);
    try testing.expectEqual(dns.RType.aaaa, out[0].rtype());
    try testing.expectEqual(@as(u32, 300), out[0].ttl);
    try testing.expectEqualSlices(u8, &Prefix.well_known.embed(.{ 192, 0, 2, 1 }), out[0].rdata());
    try testing.expect(!wantsSynthesis(.no_error, out));
    try testing.expectEqual(@as(?[]dns.WireRecord, null), try synthesizeAaaa(al, Prefix.well_known, &.{}, &soa));
}

test "renamePtr re-owns PTRs to the ip6.arpa qname and drops the RFC 2317 CNAME hop" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const in_addr = try dns.parseDottedName(a, "1.2.0.192.in-addr.arpa.");
    const classless = try dns.parseDottedName(a, "1.0-25.2.0.192.in-addr.arpa.");
    const host = try dns.parseDottedName(a, "host.example.com.");
    const answers = [_]dns.WireRecord{
        try .from(a, .{ .name = in_addr, .rtype = .cname, .rclass = .in, .ttl = 3600, .rdata = .{ .cname = classless } }),
        try .from(a, .{ .name = classless, .rtype = .ptr, .rclass = .in, .ttl = 300, .rdata = .{ .ptr = host } }),
    };
    const qname = try dns.parseDottedName(a, "1.0.2.0.0.0.0.C.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.B.9.F.F.4.6.0.0.ip6.arpa.");
    const out = try renamePtr(a, &answers, qname);
    try testing.expectEqual(@as(usize, 1), out.len);
    var lower: [dns.max_name_len + 2]u8 = undefined;
    const want = lower[0..try dns.writeNameWire(&lower, try dns.cloneNameLower(a, qname))];
    try testing.expectEqualSlices(u8, want, out[0].owner);
    try testing.expectEqualSlices(u8, answers[1].rest, out[0].rest);
}
