//! The DNS wire format (RFC 1035 §4): names in canonical wire form, and
//! messages with their records and EDNS (RFC 6891) parsed and serialized.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

/// A wire enum for `{f}`: its name, or its number where it has none. `{t}`
/// is `@tagName`, which panics on an unnamed value.
pub fn tag(val: anytype) Tag(@TypeOf(val)) {
    return .{ .val = val };
}

fn Tag(comptime E: type) type {
    return struct {
        val: E,
        pub fn format(t: @This(), w: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (t.val) {
                _ => try w.print("{d}", .{@backingInt(t.val)}),
                else => try w.writeAll(@tagName(t.val)),
            }
        }
    };
}

pub const max_label_len = 63;
pub const max_label_count = 127; // (255 wire octets - 1 root byte) / 2 octets per single-char label = 127
pub const max_name_len = 253;
/// RFC 1035 §3.1, the root's length octet included.
pub const max_name_wire_len = 255;
/// Presentation-format ceiling: every content byte can escape to `\DDD`
/// (4 chars), separators are free relative to the wire length budget.
pub const max_dotted_len = 4 * max_name_len;
const header_len = 12;
pub const max_udp_payload = 512;
/// A week (BIND's max-cache-ttl): a chosen 0xFFFFFFFF would outlive its delegation.
const max_ttl: u32 = 604_800;
/// A negative, NSEC and NSEC3 included, is trusted three hours at most
/// (RFC 2308 §5, RFC 9077 §3.4).
pub const max_negative_ttl: u32 = 10_800;
pub const edns_udp_payload: u16 = 1232;
/// RFC 1035 §4.2.2: DNS-over-TCP uses a 2-byte length prefix, so a single
/// message can be at most 65535 bytes. Also the ceiling for any DNS
/// response buffer we might parse.
pub const max_message_len: u16 = 65535;

pub const OpCode = enum(u4) {
    query = 0,
    _,
};

pub const RCode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3,
    not_implemented = 4,
    refused = 5,
    yx_domain = 6,
    _,
};

pub const RType = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    hinfo = 13,
    mx = 15,
    txt = 16,
    rp = 17,
    afsdb = 18,
    rt = 21,
    /// May sit beside a CNAME (RFC 4035 §2.5).
    key = 25,
    px = 26,
    aaaa = 28,
    srv = 33,
    naptr = 35,
    kx = 36,
    /// RFC 6672. RFC 6840 §4.1 also requires recognizing the bit in an
    /// NSEC/NSEC3 bitmap: names beneath a DNAME owner are synthesized,
    /// not absent.
    dname = 39,
    opt = 41,
    ds = 43,
    rrsig = 46,
    nsec = 47,
    dnskey = 48,
    nsec3 = 50,
    nsec3param = 51,
    svcb = 64,
    https = 65,
    any = 255,
    _,
};

pub const RClass = enum(u16) {
    in = 1,
    _,
};

pub const Error = error{
    EndOfData,
    LabelTooLong,
    NameTooLong,
    CompressionPointerLoop,
    FormatError,
    InvalidLabelType,
    InvalidRDataLength,
    MultipleOptRecords,
    OutOfMemory,
};

pub const Header = struct {
    id: u16,
    flags: Flags,
    qd_count: u16 = 0,
    an_count: u16 = 0,
    ns_count: u16 = 0,
    ar_count: u16 = 0,

    /// Wire-format flag bits (RFC 1035 §4.1.1 + RFC 2535 §6.1 for AD/CD).
    /// Packed LSB→MSB so a host-order u16 (post `mem.readInt(.big)`) bitcasts
    /// directly to the wire bit layout: QR is the MSB, RCODE the low nibble.
    pub const Flags = packed struct(u16) {
        rcode: RCode,
        cd: bool,
        ad: bool,
        z: u1,
        ra: bool,
        rd: bool,
        tc: bool,
        aa: bool,
        opcode: OpCode,
        qr: bool,
    };

    pub fn parse(bytes: *const [12]u8) Header {
        return .{
            .id = mem.readInt(u16, bytes[0..2], .big),
            .flags = @bitCast(mem.readInt(u16, bytes[2..4], .big)),
            .qd_count = mem.readInt(u16, bytes[4..6], .big),
            .an_count = mem.readInt(u16, bytes[6..8], .big),
            .ns_count = mem.readInt(u16, bytes[8..10], .big),
            .ar_count = mem.readInt(u16, bytes[10..12], .big),
        };
    }

    pub fn serialize(self: Header, out: *[12]u8) void {
        mem.writeInt(u16, out[0..2], self.id, .big);
        mem.writeInt(u16, out[2..4], @bitCast(self.flags), .big);
        mem.writeInt(u16, out[4..6], self.qd_count, .big);
        mem.writeInt(u16, out[6..8], self.an_count, .big);
        mem.writeInt(u16, out[8..10], self.ns_count, .big);
        mem.writeInt(u16, out[10..12], self.ar_count, .big);
    }
};

/// RFC 4034 §6.2 canonical form: uncompressed wire labels, lowercase,
/// at most 255 octets. Case someone wrote lives in `Question.spelled`
/// and an NSEC's rdata, never here.
pub const Name = struct {
    wire: []const u8,

    pub const root: Name = .{ .wire = "\x00" };

    pub const Buf = [max_name_wire_len]u8;

    pub fn lit(comptime dotted: []const u8) Name {
        const wire = comptime blk: {
            @setEvalBranchQuota(20_000);
            var buf: Buf = undefined;
            const w = wireOfDotted(&buf, dotted, false) catch |err| @compileError(@errorName(err) ++ ": " ++ dotted);
            for (w) |b| if (std.ascii.isUpper(b)) @compileError("not lowercase: " ++ dotted);
            break :blk w[0..w.len].*;
        };
        return .{ .wire = &wire };
    }

    pub fn of(wire: []const u8) Name {
        if (builtin.mode.runtimeSafety()) std.debug.assert(canonical(wire));
        return .{ .wire = wire };
    }

    fn canonical(wire: []const u8) bool {
        if (wire.len == 0 or wire.len > max_name_wire_len) return false;
        var i: usize = 0;
        while (i < wire.len and wire[i] != 0) : (i += 1 + wire[i]) {
            if (wire[i] > max_label_len or i + 1 + wire[i] >= wire.len) return false;
            for (wire[i + 1 ..][0..wire[i]]) |b| if (std.ascii.isUpper(b)) return false;
        }
        return i == wire.len - 1;
    }

    pub fn clone(n: Name, allocator: Allocator) Allocator.Error!Name {
        return .{ .wire = try allocator.dupe(u8, n.wire) };
    }

    pub fn isRoot(n: Name) bool {
        return n.wire[0] == 0;
    }

    pub fn depth(n: Name) u8 {
        var d: u8 = 0;
        var i: usize = 0;
        while (n.wire[i] != 0) : (i += 1 + n.wire[i]) d += 1;
        return d;
    }

    pub fn leaf(n: Name) []const u8 {
        return n.wire[1..][0..n.wire[0]];
    }

    pub fn parent(n: Name) ?Name {
        return if (n.isRoot()) null else .{ .wire = n.wire[1 + n.wire[0] ..] };
    }

    pub fn ancestor(n: Name, d: u8) Name {
        var i: usize = 0;
        for (0..n.depth() - d) |_| i += 1 + n.wire[i];
        return .{ .wire = n.wire[i..] };
    }

    fn starts(n: Name, out: *[max_label_count]u8) []const u8 {
        var k: usize = 0;
        var i: usize = 0;
        while (n.wire[i] != 0) : (i += 1 + n.wire[i]) {
            out[k] = @intCast(i);
            k += 1;
        }
        return out[0..k];
    }

    fn labelAt(n: Name, at: u8) []const u8 {
        return n.wire[at + 1 ..][0..n.wire[at]];
    }

    pub fn shared(a: Name, b: Name) Name {
        var ab: [max_label_count]u8 = undefined;
        var bb: [max_label_count]u8 = undefined;
        const sa = a.starts(&ab);
        const sb = b.starts(&bb);
        var i = sa.len;
        var j = sb.len;
        while (i > 0 and j > 0 and mem.eql(u8, a.labelAt(sa[i - 1]), b.labelAt(sb[j - 1]))) {
            i -= 1;
            j -= 1;
        }
        return .{ .wire = a.wire[if (i == sa.len) a.wire.len - 1 else sa[i]..] };
    }

    /// RFC 4034 §6.1 canonical order.
    pub fn order(a: Name, b: Name) std.math.Order {
        var ab: [max_label_count]u8 = undefined;
        var bb: [max_label_count]u8 = undefined;
        const sa = a.starts(&ab);
        const sb = b.starts(&bb);
        var i = sa.len;
        var j = sb.len;
        while (i > 0 and j > 0) {
            i -= 1;
            j -= 1;
            const o = mem.order(u8, a.labelAt(sa[i]), b.labelAt(sb[j]));
            if (o != .eq) return o;
        }
        return std.math.order(sa.len, sb.len);
    }

    pub fn child(buf: *Buf, label: []const u8, above: Name) ?Name {
        const len = 1 + label.len + above.wire.len;
        if (len > max_name_wire_len) return null;
        buf[0] = @intCast(label.len);
        @memcpy(buf[1..][0..label.len], label);
        @memcpy(buf[1 + label.len ..][0..above.wire.len], above.wire);
        return .of(buf[0..len]);
    }

    /// RFC 4343 §2.1 presentation form, which `parseDottedName` reads back.
    pub fn formatInto(self: Name, buf: *[max_dotted_len + 1]u8) []const u8 {
        var pos: usize = 0;
        var i: usize = 0;
        while (self.wire[i] != 0) : (i += 1 + self.wire[i]) {
            if (pos > 0) {
                buf[pos] = '.';
                pos += 1;
            }
            for (self.wire[i + 1 ..][0..self.wire[i]]) |byte| switch (byte) {
                '.', '\\' => {
                    buf[pos] = '\\';
                    buf[pos + 1] = byte;
                    pos += 2;
                },
                0x21...0x2d, 0x2f...0x5b, 0x5d...0x7e => {
                    buf[pos] = byte;
                    pos += 1;
                },
                else => {
                    buf[pos] = '\\';
                    buf[pos + 1] = '0' + byte / 100;
                    buf[pos + 2] = '0' + (byte / 10) % 10;
                    buf[pos + 3] = '0' + byte % 10;
                    pos += 4;
                },
            };
        }
        return buf[0..pos];
    }

    pub fn eql(a: Name, b: Name) bool {
        return mem.eql(u8, a.wire, b.wire);
    }

    /// Its tail is `zone`'s bytes, starting on one of its labels: matching
    /// bytes alone can start mid-label.
    pub fn isSubdomainOf(self: Name, zone: Name) bool {
        if (zone.wire.len > self.wire.len) return false;
        const at = self.wire.len - zone.wire.len;
        if (!mem.eql(u8, self.wire[at..], zone.wire)) return false;
        var i: usize = 0;
        while (i < at) i += 1 + self.wire[i];
        return i == at;
    }
};

pub const MxData = struct {
    preference: u16,
    exchange: Name,
};

pub const SoaData = struct {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

pub const TxtData = struct {
    strings: []const []const u8,

    pub const Strings = struct {
        rdata: []const u8,
        at: usize = 0,

        pub fn next(s: *Strings) ?[]const u8 {
            if (s.at == s.rdata.len) return null;
            const len = s.rdata[s.at];
            defer s.at += 1 + len;
            return s.rdata[s.at + 1 ..][0..len];
        }
    };
};

// ── DNSSEC types (RFC 4034, 5155) ──────────────────────────────────

pub const DnssecAlgorithm = enum(u8) {
    rsamd5 = 1,
    dh = 2,
    dsasha1 = 3,
    rsasha1 = 5,
    dsasha1_nsec3 = 6,
    rsasha1_nsec3 = 7,
    rsasha256 = 8,
    rsasha512 = 10,
    ecdsap256sha256 = 13,
    ecdsap384sha384 = 14,
    ed25519 = 15,
    ed448 = 16,
    mldsa44 = 18,
    _,
};

pub const DigestType = enum(u8) {
    sha1 = 1,
    sha256 = 2,
    sha384 = 4,
    _,
};

/// RFC 5155 §8.1: the only NSEC3 hash algorithm defined is SHA-1.
pub const Nsec3HashAlgorithm = enum(u8) {
    sha1 = 1,
    _,
};

pub const RrsigData = struct {
    type_covered: RType,
    algorithm: DnssecAlgorithm,
    labels: u8,
    original_ttl: u32,
    sig_expiration: u32,
    sig_inception: u32,
    key_tag: u16,
    signer_name: Name,
    signature: []const u8,
};

/// Seconds from `now` to an RRSIG timestamp, saturating at 0. For the RFC
/// 4035 §5.3.3 TTL ceiling, not the validator's freshness check, which
/// needs the clock-skew-tolerant comparison in dnssec.zig.
pub fn secondsUntil(expiration: u32, now: u32) u32 {
    return if (serialAfter(expiration, now)) expiration -% now else 0;
}

/// RFC 1982 serial comparison. RRSIG timestamps are mod-2^32 serials (RFC
/// 4034 §3.1.5) and must never be compared or subtracted directly.
pub fn serialAfter(s1: u32, s2: u32) bool {
    return s1 != s2 and (s1 -% s2) < 0x80000000;
}

test "serialAfter: basic comparisons" {
    try testing.expect(serialAfter(10, 5));
    try testing.expect(!serialAfter(5, 10));
    try testing.expect(!serialAfter(5, 5));
    // Wrap: 0xFFFFFFFF is "before" 0x00000001.
    try testing.expect(serialAfter(0x00000001, 0xFFFFFFFF));
    try testing.expect(!serialAfter(0xFFFFFFFF, 0x00000001));
}

test "secondsUntil: saturates at zero and wraps as a serial" {
    try testing.expectEqual(@as(u32, 400), secondsUntil(1000, 600));
    try testing.expectEqual(@as(u32, 0), secondsUntil(1000, 1000));
    try testing.expectEqual(@as(u32, 0), secondsUntil(1000, 1001));
    // Expiration just past the 2^32 wrap is still in the future.
    try testing.expectEqual(@as(u32, 10), secondsUntil(5, 0xFFFFFFFB));
}

pub const DnskeyData = struct {
    flags: u16,
    protocol: u8,
    algorithm: DnssecAlgorithm,
    public_key: []const u8,

    pub fn isZoneKey(self: DnskeyData) bool {
        return (self.flags & 0x100) != 0; // bit 7 (ZONE flag)
    }

    /// RFC 5011 §2.1: bit 8 (REVOKE). A revoked key MUST NOT be used to
    /// validate RRSIGs. keyTag() still includes the revoke bit per
    /// RFC 4034 Appendix B, so do not change tag computation.
    pub fn isRevoked(self: DnskeyData) bool {
        return (self.flags & 0x80) != 0;
    }
};

pub const DsData = struct {
    key_tag: u16,
    algorithm: DnssecAlgorithm,
    digest_type: DigestType,
    digest: []const u8,
};

pub const NsecData = struct {
    next_domain_name: Name,
    type_bit_maps: []const u8,
};

pub const Nsec3Data = struct {
    hash_algorithm: Nsec3HashAlgorithm,
    flags: u8,
    iterations: u16,
    salt: []const u8,
    next_hashed_owner: []const u8,
    type_bit_maps: []const u8,
};

/// A record's rdata in its parts, for building one.
pub const RData = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    ns: Name,
    cname: Name,
    dname: Name,
    ptr: Name,
    mx: MxData,
    soa: SoaData,
    txt: TxtData,
    rrsig: RrsigData,
    dnskey: DnskeyData,
    ds: DsData,
    nsec: NsecData,
    nsec3: Nsec3Data,
    /// Already wire.
    unknown: []const u8,

    pub const Error = Allocator.Error || error{InvalidRDataLength};

    fn encode(rdata: RData, gpa: Allocator) RData.Error![]const u8 {
        switch (rdata) {
            .ns, .cname, .dname, .ptr => |n| return n.wire,
            .unknown => |bytes| return bytes,
            .a, .aaaa, .mx, .soa, .txt, .rrsig, .dnskey, .ds, .nsec, .nsec3 => {},
        }
        var w: std.Io.Writer.Allocating = .init(gpa);
        errdefer w.deinit();
        rdata.write(&w.writer) catch |err| return switch (err) {
            error.WriteFailed => error.OutOfMemory,
            else => |e| e,
        };
        return try w.toOwnedSlice();
    }

    fn write(rdata: RData, w: *std.Io.Writer) (std.Io.Writer.Error || RData.Error)!void {
        switch (rdata) {
            .a => |addr| try w.writeAll(&addr),
            .aaaa => |addr| try w.writeAll(&addr),
            .ns, .cname, .ptr, .dname => |name| try w.writeAll(name.wire),
            .mx => |mx| {
                try w.writeInt(u16, mx.preference, .big);
                try w.writeAll(mx.exchange.wire);
            },
            .soa => |soa| {
                try w.writeAll(soa.mname.wire);
                try w.writeAll(soa.rname.wire);
                for ([_]u32{ soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum }) |v| try w.writeInt(u32, v, .big);
            },
            .txt => |txt| for (txt.strings) |str| {
                try w.writeByte(std.math.cast(u8, str.len) orelse return error.InvalidRDataLength);
                try w.writeAll(str);
            },
            .rrsig => |sig| {
                try w.writeInt(u16, @backingInt(sig.type_covered), .big);
                try w.writeByte(@backingInt(sig.algorithm));
                try w.writeByte(sig.labels);
                try w.writeInt(u32, sig.original_ttl, .big);
                try w.writeInt(u32, sig.sig_expiration, .big);
                try w.writeInt(u32, sig.sig_inception, .big);
                try w.writeInt(u16, sig.key_tag, .big);
                try w.writeAll(sig.signer_name.wire);
                try w.writeAll(sig.signature);
            },
            .dnskey => |key| {
                try w.writeInt(u16, key.flags, .big);
                try w.writeByte(key.protocol);
                try w.writeByte(@backingInt(key.algorithm));
                try w.writeAll(key.public_key);
            },
            .ds => |ds| {
                try w.writeInt(u16, ds.key_tag, .big);
                try w.writeByte(@backingInt(ds.algorithm));
                try w.writeByte(@backingInt(ds.digest_type));
                try w.writeAll(ds.digest);
            },
            .nsec => |nsec| {
                try w.writeAll(nsec.next_domain_name.wire);
                try w.writeAll(nsec.type_bit_maps);
            },
            .nsec3 => |nsec3| {
                try w.writeByte(@backingInt(nsec3.hash_algorithm));
                try w.writeByte(nsec3.flags);
                try w.writeInt(u16, nsec3.iterations, .big);
                try w.writeByte(std.math.cast(u8, nsec3.salt.len) orelse return error.InvalidRDataLength);
                try w.writeAll(nsec3.salt);
                try w.writeByte(std.math.cast(u8, nsec3.next_hashed_owner.len) orelse return error.InvalidRDataLength);
                try w.writeAll(nsec3.next_hashed_owner);
                try w.writeAll(nsec3.type_bit_maps);
            },
            .unknown => |bytes| try w.writeAll(bytes),
        }
    }
};

// Each type's layout, stated once: the parser checks records with these,
// and the accessors read records the parser or `init` proved.

fn nameLen(d: []const u8) Error!usize {
    var i: usize = 0;
    while (i < d.len) : (i += 1 + d[i]) if (d[i] == 0) return i + 1;
    return error.InvalidRDataLength;
}

fn readMx(d: []const u8) Error!MxData {
    if (d.len < 2) return error.InvalidRDataLength;
    return .{ .preference = mem.readInt(u16, d[0..2], .big), .exchange = .of(d[2..]) };
}

fn readSoa(d: []const u8) Error!SoaData {
    const m = try nameLen(d);
    const r = m + try nameLen(d[m..]);
    if (d.len != r + 20) return error.FormatError;
    const n = d[r..][0..20];
    return .{
        .mname = .of(d[0..m]),
        .rname = .of(d[m..r]),
        .serial = mem.readInt(u32, n[0..4], .big),
        .refresh = mem.readInt(u32, n[4..8], .big),
        .retry = mem.readInt(u32, n[8..12], .big),
        .expire = mem.readInt(u32, n[12..16], .big),
        .minimum = mem.readInt(u32, n[16..20], .big),
    };
}

fn checkTxt(d: []const u8) Error!void {
    var at: usize = 0;
    while (at < d.len) at += 1 + @as(usize, d[at]);
    if (at != d.len) return error.FormatError;
}

fn readRrsig(d: []const u8) Error!RrsigData {
    if (d.len < 18) return error.InvalidRDataLength;
    const n = 18 + try nameLen(d[18..]);
    return .{
        .type_covered = @fromBackingInt(mem.readInt(u16, d[0..2], .big)),
        .algorithm = @fromBackingInt(d[2]),
        .labels = d[3],
        .original_ttl = mem.readInt(u32, d[4..8], .big),
        .sig_expiration = mem.readInt(u32, d[8..12], .big),
        .sig_inception = mem.readInt(u32, d[12..16], .big),
        .key_tag = mem.readInt(u16, d[16..18], .big),
        .signer_name = .of(d[18..n]),
        .signature = d[n..],
    };
}

fn readDnskey(d: []const u8) Error!DnskeyData {
    if (d.len < 4) return error.InvalidRDataLength;
    return .{ .flags = mem.readInt(u16, d[0..2], .big), .protocol = d[2], .algorithm = @fromBackingInt(d[3]), .public_key = d[4..] };
}

fn readDs(d: []const u8) Error!DsData {
    if (d.len < 4) return error.InvalidRDataLength;
    return .{ .key_tag = mem.readInt(u16, d[0..2], .big), .algorithm = @fromBackingInt(d[2]), .digest_type = @fromBackingInt(d[3]), .digest = d[4..] };
}

fn readNsec(d: []const u8, buf: *Name.Buf) Error!NsecData {
    const n = try nameLen(d);
    // A length octet is at most 63, never a capital.
    const spelled = d[0..n];
    const folded = for (spelled) |c| {
        if (std.ascii.isUpper(c)) break std.ascii.lowerString(buf[0..n], spelled);
    } else spelled;
    return .{ .next_domain_name = .of(folded), .type_bit_maps = d[n..] };
}

fn readNsec3(d: []const u8) Error!Nsec3Data {
    if (d.len < 6) return error.InvalidRDataLength;
    const salt_len: usize = d[4];
    if (5 + salt_len + 1 > d.len) return error.InvalidRDataLength;
    const hash_len: usize = d[5 + salt_len];
    const consumed = 6 + salt_len + hash_len;
    if (consumed > d.len) return error.InvalidRDataLength;
    return .{
        .hash_algorithm = @fromBackingInt(d[0]),
        .flags = d[1],
        .iterations = mem.readInt(u16, d[2..4], .big),
        .salt = d[5..][0..salt_len],
        .next_hashed_owner = d[6 + salt_len .. consumed],
        .type_bit_maps = d[consumed..],
    };
}

/// Names were checked as they were read; these are the rest.
fn checkRdata(rtype: RType, d: []const u8) Error!void {
    switch (rtype) {
        .a => if (d.len != 4) return error.InvalidRDataLength,
        .aaaa => if (d.len != 16) return error.InvalidRDataLength,
        .txt => try checkTxt(d),
        .dnskey => _ = try readDnskey(d),
        .ds => _ = try readDs(d),
        .nsec3 => _ = try readNsec3(d),
        else => {},
    }
}

/// Check if an RType is present in a type bitmap (RFC 4034 §4.1.2).
/// Used by NSEC and NSEC3 records.
pub fn typeBitmapContains(bitmap: []const u8, rtype: RType) bool {
    const type_num = @backingInt(rtype);
    const window = type_num >> 8; // high byte = window number
    const bit_offset: u8 = @intCast(type_num & 0xFF); // low byte = offset within window
    const byte_in_window = bit_offset >> 3;
    const bit_in_byte: u3 = @intCast(bit_offset & 0x07);

    var pos: usize = 0;
    while (pos + 2 <= bitmap.len) {
        const win = bitmap[pos];
        const win_len = bitmap[pos + 1];
        pos += 2;
        if (pos + win_len > bitmap.len) return false;
        if (win == window) {
            if (byte_in_window >= win_len) return false;
            return (bitmap[pos + byte_in_window] & (@as(u8, 0x80) >> bit_in_byte)) != 0;
        }
        pos += win_len;
    }
    return false;
}

// ── EDNS0 (RFC 6891) ──────────────────────────────────────────────────

pub const edns_opt_tcp_keepalive: u16 = 11; // RFC 7828

pub const edns_opt_ede: u16 = 15; // RFC 8914

/// RFC 8914 Extended DNS Error.
pub const Ede = struct {
    code: Code,
    text: []const u8 = "",

    pub const Code = enum(u16) {
        other = 0,
        stale_answer = 3,
        dnssec_bogus = 6,
        cached_error = 13,
        blocked = 15,
        stale_nxdomain_answer = 19,
        not_supported = 21,
        no_reachable_authority = 22,
        unsupported_nsec3_iterations = 27,
        synthesized = 29,
        /// draft-muks-dns-ede-rate-limited.
        over_quota = 32,
    };

    pub fn option(self: Ede, buf: *[64]u8) EdnsOption {
        mem.writeInt(u16, buf[0..2], @backingInt(self.code), .big);
        const n = @min(self.text.len, buf.len - 2);
        @memcpy(buf[2..][0..n], self.text[0..n]);
        return .{ .code = edns_opt_ede, .data = buf[0 .. 2 + n] };
    }
};

pub const EdnsOption = struct {
    code: u16,
    data: []const u8,
};

pub const OptRecord = struct {
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    do_bit: bool,
    options: []const EdnsOption,
};

pub const Edns = struct {
    udp_payload_size: u16,
    version: u8,
    do_bit: bool,
};

pub const Question = struct {
    name: Name,
    qtype: RType,
    qclass: RClass,
    /// The name as its asker wrote it, for the echo and the 0x20 check.
    /// Null when that is `name`.
    spelled: ?[]const u8 = null,
};

var fixtures: std.heap.ArenaAllocator = .init(std.heap.page_allocator);

pub const ResourceRecord = struct {
    name: Name,
    rtype: RType,
    rclass: RClass,
    ttl: u32,
    /// Canonical wire (RFC 4034 §6.2): names uncompressed and lowercase,
    /// but an NSEC's next name, kept as signed (RFC 6840 §5.1).
    rdata: []const u8,

    pub const Parts = struct {
        name: Name,
        rtype: RType,
        rclass: RClass,
        ttl: u32,
        rdata: RData,
    };

    pub fn init(gpa: Allocator, p: Parts) RData.Error!ResourceRecord {
        return .{ .name = p.name, .rtype = p.rtype, .rclass = p.rclass, .ttl = p.ttl, .rdata = try p.rdata.encode(gpa) };
    }

    /// For tests: memory the test binary never frees.
    pub fn fixture(p: Parts) ResourceRecord {
        return init(fixtures.allocator(), p) catch @panic("bad fixture");
    }

    pub fn a(rr: ResourceRecord) [4]u8 {
        std.debug.assert(rr.rtype == .a);
        return rr.rdata[0..4].*;
    }

    pub fn aaaa(rr: ResourceRecord) [16]u8 {
        std.debug.assert(rr.rtype == .aaaa);
        return rr.rdata[0..16].*;
    }

    pub fn ns(rr: ResourceRecord) Name {
        std.debug.assert(rr.rtype == .ns);
        return .of(rr.rdata);
    }

    pub fn cname(rr: ResourceRecord) Name {
        std.debug.assert(rr.rtype == .cname);
        return .of(rr.rdata);
    }

    pub fn dname(rr: ResourceRecord) Name {
        std.debug.assert(rr.rtype == .dname);
        return .of(rr.rdata);
    }

    pub fn ptr(rr: ResourceRecord) Name {
        std.debug.assert(rr.rtype == .ptr);
        return .of(rr.rdata);
    }

    pub fn mx(rr: ResourceRecord) MxData {
        std.debug.assert(rr.rtype == .mx);
        return readMx(rr.rdata) catch unreachable;
    }

    pub fn soa(rr: ResourceRecord) SoaData {
        std.debug.assert(rr.rtype == .soa);
        return readSoa(rr.rdata) catch unreachable;
    }

    pub fn txt(rr: ResourceRecord) TxtData.Strings {
        std.debug.assert(rr.rtype == .txt);
        return .{ .rdata = rr.rdata };
    }

    pub fn rrsig(rr: ResourceRecord) RrsigData {
        std.debug.assert(rr.rtype == .rrsig);
        return readRrsig(rr.rdata) catch unreachable;
    }

    pub fn dnskey(rr: ResourceRecord) DnskeyData {
        std.debug.assert(rr.rtype == .dnskey);
        return readDnskey(rr.rdata) catch unreachable;
    }

    pub fn ds(rr: ResourceRecord) DsData {
        std.debug.assert(rr.rtype == .ds);
        return readDs(rr.rdata) catch unreachable;
    }

    /// The next name folded, into `buf` when it was signed with capitals.
    pub fn nsec(rr: ResourceRecord, buf: *Name.Buf) NsecData {
        std.debug.assert(rr.rtype == .nsec);
        return readNsec(rr.rdata, buf) catch unreachable;
    }

    pub fn nsec3(rr: ResourceRecord) Nsec3Data {
        std.debug.assert(rr.rtype == .nsec3);
        return readNsec3(rr.rdata) catch unreachable;
    }

    /// TYPE, CLASS, TTL and RDLENGTH as on the wire.
    pub fn fixed(rr: ResourceRecord) error{InvalidRDataLength}![10]u8 {
        var f: [10]u8 = undefined;
        mem.writeInt(u16, f[0..2], @backingInt(rr.rtype), .big);
        mem.writeInt(u16, f[2..4], @backingInt(rr.rclass), .big);
        mem.writeInt(u32, f[4..8], rr.ttl, .big);
        mem.writeInt(u16, f[8..10], std.math.cast(u16, rr.rdata.len) orelse return error.InvalidRDataLength, .big);
        return f;
    }

    pub fn covers(rr: ResourceRecord) ?RType {
        return if (rr.rtype == .rrsig) @fromBackingInt(mem.readInt(u16, rr.rdata[0..2], .big)) else null;
    }
};

pub fn wireNameLen(wire: []const u8) usize {
    var i: usize = 0;
    while (wire[i] != 0) i += 1 + wire[i];
    return i + 1;
}

/// Where an rdata's names lie. `tail` is the octets after them, null for any.
const Embedded = struct {
    skip: u8 = 0,
    strings: u8 = 0,
    names: u8,
    spelling: Spelling,
    tail: ?u8 = 0,

    const Spelling = enum {
        /// Compressed both ways (RFC 3597 §4).
        rfc1035,
        /// Read through pointers, written flat (RFC 3597 §4).
        read_compressed,
        /// Never a pointer (RFC 4034 §3.1.7).
        flat,
        /// Never a pointer nor folded (RFC 4034 §4.1.1, RFC 6840 §5.1).
        signed,
    };
};

fn embedded(rtype: RType) ?Embedded {
    return switch (rtype) {
        .ns, .cname, .ptr => .{ .names = 1, .spelling = .rfc1035 },
        .mx => .{ .skip = 2, .names = 1, .spelling = .rfc1035 },
        .soa => .{ .names = 2, .spelling = .rfc1035, .tail = 20 },
        .dname => .{ .names = 1, .spelling = .read_compressed },
        .rrsig => .{ .skip = 18, .names = 1, .spelling = .flat, .tail = null },
        .nsec => .{ .names = 1, .spelling = .signed, .tail = null },
        .rp => .{ .names = 2, .spelling = .read_compressed },
        .afsdb, .rt, .kx => .{ .skip = 2, .names = 1, .spelling = .read_compressed },
        .px => .{ .skip = 2, .names = 2, .spelling = .read_compressed },
        .srv => .{ .skip = 6, .names = 1, .spelling = .read_compressed },
        .naptr => .{ .skip = 4, .strings = 3, .names = 1, .spelling = .read_compressed },
        else => null,
    };
}

pub const Message = struct {
    header: Header,
    question: ?Question,
    answers: []const ResourceRecord = &.{},
    authorities: []const ResourceRecord = &.{},
    additionals: []const ResourceRecord = &.{},
    opt: ?OptRecord = null,
};

/// Index of the first label-separating `.` at or after `start`, skipping
/// escaped bytes. Works on any well-formed presentation string; `\DDD`
/// digits can never be `.` so skipping one byte after `\` suffices.
fn indexOfUnescapedDot(s: []const u8, start: usize) ?usize {
    var i = start;
    while (i < s.len) : (i += 1) switch (s[i]) {
        '\\' => i += 1,
        '.' => return i,
        else => {},
    };
    return null;
}

fn isEscapedAt(s: []const u8, i: usize) bool {
    var n: usize = 0;
    while (n < i and s[i - 1 - n] == '\\') n += 1;
    return n % 2 == 1;
}

pub fn stripTrailingDot(s: []const u8) []const u8 {
    if (s.len > 0 and s[s.len - 1] == '.' and !isEscapedAt(s, s.len - 1))
        return s[0 .. s.len - 1];
    return s;
}

/// Decode one presentation-format label (`\.`, `\\`, `\DDD`, `\X` literal)
/// into `out`. Returns the decoded length.
fn unescapeLabel(label: []const u8, out: *[max_label_len]u8) Error!usize {
    var len: usize = 0;
    var i: usize = 0;
    while (i < label.len) {
        var byte = label[i];
        i += 1;
        if (byte == '\\') {
            if (i >= label.len) return error.FormatError;
            byte = label[i];
            i += 1;
            if (std.ascii.isDigit(byte)) {
                if (i + 1 >= label.len or !std.ascii.isDigit(label[i]) or !std.ascii.isDigit(label[i + 1]))
                    return error.FormatError;
                const value = @as(u16, byte - '0') * 100 + @as(u16, label[i] - '0') * 10 + (label[i + 1] - '0');
                if (value > 255) return error.FormatError;
                byte = @intCast(value);
                i += 2;
            }
        }
        if (len >= max_label_len) return error.LabelTooLong;
        out[len] = byte;
        len += 1;
    }
    return len;
}

pub fn parseDottedName(allocator: Allocator, dotted: []const u8) Error!Name {
    var buf: Name.Buf = undefined;
    const wire = try wireOfDotted(&buf, dotted, true);
    if (wire.len == 1) return .root;
    return .{ .wire = try allocator.dupe(u8, wire) };
}

fn wireOfDotted(buf: *Name.Buf, dotted: []const u8, comptime lower: bool) Error![]u8 {
    const name_str = stripTrailingDot(dotted);
    var n: usize = 0;
    var start: usize = 0;
    while (start < name_str.len) {
        const end = indexOfUnescapedDot(name_str, start) orelse name_str.len;
        var scratch: [max_label_len]u8 = undefined;
        const len = try unescapeLabel(name_str[start..end], &scratch);
        if (len == 0) return error.InvalidLabelType;
        if (n + 1 + len >= max_name_wire_len) return error.NameTooLong;
        buf[n] = @intCast(len);
        for (buf[n + 1 ..][0..len], scratch[0..len]) |*d, c| d.* = if (lower) std.ascii.toLower(c) else c;
        n += 1 + len;
        if (end == name_str.len) break;
        start = end + 1;
    }
    buf[n] = 0;
    return buf[0 .. n + 1];
}

/// Length octets sit below 'A', so only label bytes flip. RFC draft
/// Vixie/Dagon.
fn applyCase0x20(rng: std.Random, wire: []u8) void {
    var pool: u64 = 0;
    var bits_left: u8 = 0;
    for (wire) |*b| {
        if (!std.ascii.isAlphabetic(b.*)) continue;
        if (bits_left == 0) {
            pool = rng.int(u64);
            bits_left = 64;
        }
        if (pool & 1 == 1) b.* ^= 0x20;
        pool >>= 1;
        bits_left -= 1;
    }
}

const EdnsConfig = struct {
    udp_payload_size: u16 = edns_udp_payload,
    do_bit: bool = false,
};

const QueryOptions = struct {
    rd: bool = true,
    edns: ?EdnsConfig = null,
    /// RFC draft Vixie/Dagon "Use of Bit 0x20 in DNS Labels": when non-null,
    /// randomize ASCII letter case in QNAME using this RNG. Caller verifies
    /// the response echoes byte-for-byte.
    case_rng: ?std.Random = null,
};

/// Borrows `qname`; its spelling is `allocator`'s.
pub fn buildQuery(allocator: Allocator, id: u16, qname: Name, qtype: RType, options: QueryOptions) Allocator.Error!Message {
    const spelled = try allocator.dupe(u8, qname.wire);
    if (options.case_rng) |rng| applyCase0x20(rng, spelled);

    return .{
        .header = .{
            .id = id,
            .flags = .{
                .qr = false,
                .opcode = .query,
                .aa = false,
                .tc = false,
                .rd = options.rd,
                .ra = false,
                .z = 0,
                .ad = false,
                .cd = false,
                .rcode = .no_error,
            },
        },
        .question = .{ .name = qname, .qtype = qtype, .qclass = .in, .spelled = spelled },
        .opt = if (options.edns) |edns| .{
            .udp_payload_size = edns.udp_payload_size,
            .extended_rcode = 0,
            .version = 0,
            .do_bit = edns.do_bit,
            .options = &.{},
        } else null,
    };
}

const Parser = struct {
    msg: []const u8,
    pos: usize,

    fn readU8(self: *Parser) Error!u8 {
        if (self.pos >= self.msg.len) return error.EndOfData;
        const val = self.msg[self.pos];
        self.pos += 1;
        return val;
    }

    fn readU16(self: *Parser) Error!u16 {
        if (self.pos + 2 > self.msg.len) return error.EndOfData;
        const val = mem.readInt(u16, self.msg[self.pos..][0..2], .big);
        self.pos += 2;
        return val;
    }

    fn readU32(self: *Parser) Error!u32 {
        if (self.pos + 4 > self.msg.len) return error.EndOfData;
        const val = mem.readInt(u32, self.msg[self.pos..][0..4], .big);
        self.pos += 4;
        return val;
    }

    fn readSlice(self: *Parser, len: usize) Error![]const u8 {
        if (self.pos + len > self.msg.len) return error.EndOfData;
        const slice = self.msg[self.pos..][0..len];
        self.pos += len;
        return slice;
    }

    const Form = enum { compressed, uncompressed };

    /// Read in place when it lies whole in the message, lowercase; else one
    /// lowercase copy, 255 octets at most however few the message spent.
    fn parseName(self: *Parser, allocator: Allocator, comptime form: Form) Error!Name {
        var buf: Name.Buf = undefined;
        const name = try self.readName(&buf, form);
        return if (name.wire.ptr == &buf) .{ .wire = try allocator.dupe(u8, name.wire) } else name;
    }

    fn readName(self: *Parser, buf: *Name.Buf, comptime form: Form) Error!Name {
        // Where the name lies whole: no label before a pointer.
        var whole: ?usize = self.pos;
        var upper = false;
        var len: usize = 0;
        var jumps: usize = 0;
        const max_jumps = 32;
        var cursor = self.pos;
        var resume_at: ?usize = null;

        while (true) {
            if (cursor >= self.msg.len) return error.EndOfData;
            const len_byte = self.msg[cursor];
            switch (len_byte & 0xC0) {
                0x00 => {
                    const label_len: usize = len_byte;
                    if (len + 1 + label_len > max_name_wire_len) return error.NameTooLong;
                    if (cursor + 1 + label_len > self.msg.len) return error.EndOfData;
                    buf[len] = len_byte;
                    for (buf[len + 1 ..][0..label_len], self.msg[cursor + 1 ..][0..label_len]) |*d, c| {
                        upper = upper or std.ascii.isUpper(c);
                        d.* = std.ascii.toLower(c);
                    }
                    len += 1 + label_len;
                    cursor += 1 + label_len;
                    if (label_len == 0) break;
                },
                0xC0 => {
                    if (form == .uncompressed) return error.FormatError;
                    if (cursor + 1 >= self.msg.len) return error.EndOfData;
                    jumps += 1;
                    if (jumps > max_jumps) return error.CompressionPointerLoop;
                    if (resume_at == null) resume_at = cursor + 2;
                    const offset = (@as(u16, len_byte & 0x3F) << 8) | @as(u16, self.msg[cursor + 1]);
                    // RFC 1035 §4.1.4: pointers must reference prior occurrences
                    if (offset >= cursor) return error.FormatError;
                    whole = if (len == 0) offset else null;
                    cursor = offset;
                },
                else => return error.InvalidLabelType,
            }
        }
        self.pos = resume_at orelse cursor;
        if (len == 1) return .root;
        if (whole) |at| if (!upper) return .{ .wire = self.msg[at..cursor] };
        return .{ .wire = buf[0..len] };
    }

    fn skipName(self: *Parser) Error!void {
        while (true) {
            const len = try self.readU8();
            switch (len & 0xC0) {
                0x00 => if (len == 0) return else {
                    _ = try self.readSlice(len);
                },
                0xC0 => {
                    _ = try self.readU8();
                    return;
                },
                else => return error.InvalidLabelType,
            }
        }
    }

    /// An RRSIG keeps the week: binding levels it to its set (`dnssec.bindSets`).
    fn ttlCeiling(rtype: RType) u32 {
        return switch (rtype) {
            .nsec, .nsec3 => max_negative_ttl,
            else => max_ttl,
        };
    }

    /// The first name in a message has no earlier name to point at.
    fn parseQuestion(self: *Parser, allocator: Allocator) Error!Question {
        const start = self.pos;
        const name = try self.parseName(allocator, .uncompressed);
        const spelled = self.msg[start..self.pos];
        const qtype: RType = @fromBackingInt(@intCast(try self.readU16()));
        const qclass: RClass = @fromBackingInt(@intCast(try self.readU16()));
        return .{ .name = name, .qtype = qtype, .qclass = qclass, .spelled = spelled };
    }

    fn parseResourceRecord(self: *Parser, allocator: Allocator) Error!ResourceRecord {
        const name = try self.parseName(allocator, .compressed);
        const rtype: RType = @fromBackingInt(@intCast(try self.readU16()));
        const rclass: RClass = @fromBackingInt(@intCast(try self.readU16()));
        // RFC 2181 §8: top bit set is zero. OPT's field is not a TTL (RFC 6891 §6.1.3).
        const raw_ttl = try self.readU32();
        const ttl = if (rtype == .opt) raw_ttl else if (raw_ttl > std.math.maxInt(i32)) 0 else @min(raw_ttl, ttlCeiling(rtype));
        const rdlength: usize = try self.readU16();
        const rdata = try self.readRdata(allocator, rtype, rdlength);
        try checkRdata(rtype, rdata);
        return .{ .name = name, .rtype = rtype, .rclass = rclass, .ttl = ttl, .rdata = rdata };
    }

    fn readRdata(self: *Parser, allocator: Allocator, rtype: RType, rdlength: usize) Error![]const u8 {
        const start = self.pos;
        const end = start + rdlength;
        if (end > self.msg.len) return error.EndOfData;
        const e = embedded(rtype) orelse return self.readSlice(rdlength);
        var at = start + e.skip;
        for (0..e.strings) |_| {
            if (at >= end) return error.InvalidRDataLength;
            at += 1 + @as(usize, self.msg[at]);
        }
        if (at > end) return error.InvalidRDataLength;
        self.pos = at;
        var bufs: [2]Name.Buf = undefined;
        var names: [2][]const u8 = undefined;
        var in_place = true;
        for (names[0..e.names], bufs[0..e.names]) |*n, *buf| {
            const from = self.pos;
            n.* = switch (e.spelling) {
                .rfc1035, .read_compressed => (try self.readName(buf, .compressed)).wire,
                .flat => (try self.readName(buf, .uncompressed)).wire,
                .signed => blk: {
                    _ = try self.readName(buf, .uncompressed);
                    break :blk self.msg[from..self.pos];
                },
            };
            in_place = in_place and mem.eql(u8, n.*, self.msg[from..self.pos]);
        }
        if (self.pos > end) return if (e.tail == null) error.InvalidRDataLength else error.FormatError;
        if (e.tail) |t| if (end - self.pos != t) return error.FormatError;
        const head = self.msg[start..at];
        const tail = self.msg[self.pos..end];
        self.pos = end;
        if (in_place) return self.msg[start..end];
        var len = head.len + tail.len;
        for (names[0..e.names]) |n| len += n.len;
        const out = try allocator.alloc(u8, len);
        @memcpy(out[0..head.len], head);
        var w = head.len;
        for (names[0..e.names]) |n| {
            @memcpy(out[w..][0..n.len], n);
            w += n.len;
        }
        @memcpy(out[w..], tail);
        return out;
    }
};

fn parseEdnsOptions(allocator: Allocator, rdata: []const u8) Error![]const EdnsOption {
    if (rdata.len == 0) return &.{};

    var options: ArrayList(EdnsOption) = .empty;
    var pos: usize = 0;
    while (pos + 4 <= rdata.len) {
        const code = mem.readInt(u16, rdata[pos..][0..2], .big);
        const length = mem.readInt(u16, rdata[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + length > rdata.len) return error.FormatError;
        const data = rdata[pos..][0..length];
        try options.append(allocator, .{ .code = code, .data = data });
        pos += length;
    }
    if (pos != rdata.len) return error.FormatError;
    return try options.toOwnedSlice(allocator);
}

/// `opt_out` non-null marks the additional section: OPT records are
/// extracted into it (RFC 6891) instead of appended. Null (answer /
/// authority) keeps any OPT as an ordinary record.
fn parseRRSection(allocator: Allocator, parser: *Parser, count: u16, max_rrs: usize, opt_out: ?*?OptRecord) Error![]ResourceRecord {
    var list: ArrayList(ResourceRecord) = try .initCapacity(allocator, @min(count, max_rrs));
    for (0..count) |_| {
        const rr = try parser.parseResourceRecord(allocator);
        if (opt_out) |opt| if (rr.rtype == .opt) {
            // RFC 6891 §6.1.1: a query with more than one OPT MUST get FORMERR.
            if (opt.* != null) return error.MultipleOptRecords;
            // RFC 6891 §6.1.2: OPT owner name MUST be root.
            if (!rr.name.isRoot()) return error.FormatError;
            const options = try parseEdnsOptions(allocator, rr.rdata);
            opt.* = .{
                .udp_payload_size = @backingInt(rr.rclass),
                .extended_rcode = @intCast(rr.ttl >> 24),
                .version = @intCast((rr.ttl >> 16) & 0xFF),
                .do_bit = (rr.ttl & 0x8000) != 0,
                .options = options,
            };
            continue;
        };
        try list.append(allocator, rr);
    }
    return list.items;
}

/// Parse a DNS wire message. Names and rdata alias `bytes`, which must
/// outlive the Message.
///
/// `allocator` must be an arena: nothing in the Message can be freed
/// piece by piece, on success or on error.
pub fn parseMessage(allocator: Allocator, bytes: []const u8) Error!Message {
    const hdr, var parser, const question = try readHead(allocator, bytes);

    // Cap pre-allocation against what the wire can physically contain.
    // Prevents a small packet with inflated header counts from triggering
    // a large allocation (counts are attacker-controlled u16, max 65535).
    const max_rrs = (bytes.len - header_len) / 11; // min RR: 1 name + 2 type + 2 class + 4 TTL + 2 rdlength
    const answers = try parseRRSection(allocator, &parser, hdr.an_count, max_rrs, null);
    const authorities = try parseRRSection(allocator, &parser, hdr.ns_count, max_rrs, null);
    var opt: ?OptRecord = null;
    const additionals = try parseRRSection(allocator, &parser, hdr.ar_count, max_rrs, &opt);

    return .{
        .header = hdr,
        .question = question,
        .answers = answers,
        .authorities = authorities,
        .additionals = additionals,
        .opt = opt,
    };
}

/// RFC 9619 §4: a second question is malformed, so none is read. Every
/// pointer question would decompress into a name of its own.
fn readHead(allocator: Allocator, bytes: []const u8) Error!struct { Header, Parser, ?Question } {
    if (bytes.len < header_len) return error.EndOfData;
    const hdr = Header.parse(bytes[0..12]);
    var parser = Parser{ .msg = bytes, .pos = 12 };
    if (hdr.qd_count > 1) return error.FormatError;
    const question = if (hdr.qd_count == 1) try parser.parseQuestion(allocator) else null;
    return .{ hdr, parser, question };
}

pub const Query = struct {
    header: Header,
    question: ?Question,
    edns: ?Edns,
};

/// The question may alias `bytes`. Records are framed, not read, but
/// for the additional section's OPT: a pointer or rdata nothing reads
/// is no error.
pub fn readQuery(allocator: Allocator, bytes: []const u8) Error!Query {
    const hdr, var parser, const question = try readHead(allocator, bytes);

    const before_additional = @as(usize, hdr.an_count) + hdr.ns_count;
    var edns: ?Edns = null;
    var opts: usize = 0;
    for (0..before_additional + hdr.ar_count) |i| {
        const owner = parser.pos;
        try parser.skipName();
        const rtype: RType = @fromBackingInt(try parser.readU16());
        const class = try parser.readU16();
        const ttl = try parser.readU32();
        const rdata = try parser.readSlice(try parser.readU16());
        if (rtype != .opt) continue;
        // RFC 6891 §6.1.1: one OPT per message, whichever section holds it.
        opts += 1;
        if (opts > 1) return error.MultipleOptRecords;
        if (i < before_additional) continue;
        // §6.1.2: owned by the root.
        var at = Parser{ .msg = bytes, .pos = owner };
        if (!(try at.parseName(allocator, .compressed)).isRoot()) return error.FormatError;
        try frameEdnsOptions(rdata);
        edns = .{ .udp_payload_size = class, .version = @intCast(ttl >> 16 & 0xFF), .do_bit = ttl & 0x8000 != 0 };
    }
    return .{ .header = hdr, .question = question, .edns = edns };
}

fn frameEdnsOptions(rdata: []const u8) Error!void {
    var pos: usize = 0;
    while (pos + 4 <= rdata.len) pos += 4 + @as(usize, mem.readInt(u16, rdata[pos + 2 ..][0..2], .big));
    if (pos != rdata.len) return error.FormatError;
}

fn castOrRDataErr(comptime T: type, val: anytype) Error!T {
    return std.math.cast(T, val) orelse error.InvalidRDataLength;
}

/// RFC 1035 §4.1.4 targets. Byte-exact: a pointer must not change a name's case.
/// A candidate entry spends its label count from `work`; once gone, names go
/// out whole (Unbound CVE-2024-8508: labels² × entries per name).
pub const NameTable = struct {
    /// A name written at `offset`, `labels` long.
    const Entry = struct { offset: u16, labels: u8 };
    entries: [64]Entry = undefined,
    len: usize = 0,
    work: u32 = 1 << 16,

    /// `suffix` is an uncompressed wire name `labels` long; `out` holds
    /// every entry's name.
    fn find(self: *NameTable, out: []const u8, suffix: []const u8, labels: u8) ?u16 {
        for (self.entries[0..self.len]) |e| {
            if (e.labels != labels) continue;
            if (self.work < labels) return null;
            self.work -= labels;
            if (sameWireName(out, e.offset, suffix)) return e.offset;
        }
        return null;
    }

    fn add(self: *NameTable, offset: usize, labels: u8) void {
        if (self.len == self.entries.len or offset >= 0x4000) return;
        self.entries[self.len] = .{ .offset = @intCast(offset), .labels = labels };
        self.len += 1;
    }
};

/// The name at `out[at..]`, its pointers followed, is `wire` to the byte.
/// Pointers the serializer wrote only reach back, so the walk ends.
fn sameWireName(out: []const u8, at: u16, wire: []const u8) bool {
    var p: usize = at;
    var q: usize = 0;
    while (true) {
        const len = out[p];
        if (len & 0xC0 == 0xC0) {
            p = @as(usize, len & 0x3F) << 8 | out[p + 1];
            continue;
        }
        if (len != wire[q]) return false;
        if (len == 0) return true;
        if (!mem.eql(u8, out[p + 1 ..][0..len], wire[q + 1 ..][0..len])) return false;
        p += 1 + len;
        q += 1 + len;
    }
}

pub const Serializer = struct {
    buf: []u8,
    pos: usize = 0,
    names: ?*NameTable = null,

    fn ensureSpace(self: *Serializer, n: usize) Error!void {
        if (self.pos + n > self.buf.len) return error.EndOfData;
    }

    fn writeU8(self: *Serializer, val: u8) Error!void {
        try self.ensureSpace(1);
        self.buf[self.pos] = val;
        self.pos += 1;
    }

    fn writeU16(self: *Serializer, val: u16) Error!void {
        try self.ensureSpace(2);
        mem.writeInt(u16, self.buf[self.pos..][0..2], val, .big);
        self.pos += 2;
    }

    fn writeU32(self: *Serializer, val: u32) Error!void {
        try self.ensureSpace(4);
        mem.writeInt(u32, self.buf[self.pos..][0..4], val, .big);
        self.pos += 4;
    }

    fn writeSlice(self: *Serializer, data: []const u8) Error!void {
        try self.ensureSpace(data.len);
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    /// `compress` only for owner names and RFC 1035 rdata (RFC 3597 §4).
    fn writeName(self: *Serializer, wire: []const u8, compress: bool) Error!void {
        if (compress and self.names != null) return self.writeWireName(wire);
        try self.writeSlice(wire);
    }

    /// An uncompressed wire name, compressed against what is written.
    fn writeWireName(self: *Serializer, wire: []const u8) Error!void {
        const t = self.names.?;
        var labels: u8 = 0;
        var i: usize = 0;
        while (wire[i] != 0) : (i += 1 + wire[i]) labels += 1;
        i = 0;
        while (wire[i] != 0) : ({
            i += 1 + wire[i];
            labels -= 1;
        }) {
            if (t.find(self.buf, wire[i..], labels)) |off| {
                try self.writeSlice(wire[0..i]);
                return self.writeU16(0xC000 | off);
            }
            t.add(self.pos + i, labels);
        }
        try self.writeSlice(wire);
    }

    fn writeQuestion(self: *Serializer, q: Question) Error!void {
        try self.writeName(q.spelled orelse q.name.wire, true);
        try self.writeU16(@backingInt(q.qtype));
        try self.writeU16(@backingInt(q.qclass));
    }

    fn writeResourceRecord(self: *Serializer, rr: ResourceRecord) Error!void {
        try self.writeName(rr.name.wire, true);
        const at = self.pos;
        try self.writeSlice(&try rr.fixed());
        const e = (if (self.names != null) embedded(rr.rtype) else null) orelse return self.writeSlice(rr.rdata);
        if (e.spelling != .rfc1035) return self.writeSlice(rr.rdata);
        try self.writeSlice(rr.rdata[0..e.skip]);
        var p: usize = e.skip;
        for (0..e.names) |_| {
            const n = wireNameLen(rr.rdata[p..]);
            try self.writeWireName(rr.rdata[p..][0..n]);
            p += n;
        }
        try self.writeSlice(rr.rdata[p..]);
        mem.writeInt(u16, self.buf[at + 8 ..][0..2], try castOrRDataErr(u16, self.pos - at - 10), .big);
    }

    pub fn writeOpt(self: *Serializer, opt: OptRecord) Error!void {
        try self.writeU8(0); // root name
        try self.writeU16(41); // type OPT
        try self.writeU16(opt.udp_payload_size); // class = UDP payload size
        // TTL = extended_rcode(8) | version(8) | DO(1) | Z(15)
        const ttl: u32 = (@as(u32, opt.extended_rcode) << 24) |
            (@as(u32, opt.version) << 16) |
            (@as(u32, @intFromBool(opt.do_bit)) << 15);
        try self.writeU32(ttl);

        var rdlength: u16 = 0;
        for (opt.options) |o| rdlength += 4 + (try castOrRDataErr(u16, o.data.len));
        try self.writeU16(rdlength);
        for (opt.options) |o| {
            try self.writeU16(o.code);
            try self.writeU16(@intCast(o.data.len));
            try self.writeSlice(o.data);
        }
    }
};

/// Where each section ended, filled progressively by `serializeEnds`
/// so a caller can rewind to a completed boundary after an overflow.
/// 0 = never reached.
pub const SectionEnds = struct { question: usize = 0, answers: usize = 0, authorities: usize = 0 };

pub fn serializeMessage(buf: []u8, msg: Message) Error![]const u8 {
    var ends: SectionEnds = .{};
    const sections: Sections = .{ .answers = msg.answers, .authorities = msg.authorities, .additionals = msg.additionals };
    return serializeEnds(buf, msg.header, msg.question, sections, msg.opt, &ends);
}

pub const Sections = struct {
    answers: []const ResourceRecord = &.{},
    authorities: []const ResourceRecord = &.{},
    additionals: []const ResourceRecord = &.{},

    pub fn header(s: Sections, hdr: Header, question: bool, opt: bool) Header {
        var out = hdr;
        out.qd_count = @intFromBool(question);
        out.an_count = @intCast(s.answers.len);
        out.ns_count = @intCast(s.authorities.len);
        out.ar_count = @intCast(s.additionals.len + @intFromBool(opt));
        return out;
    }
};

/// The header goes last and counts only records that fit in one message,
/// so each count fits a u16.
pub fn serializeEnds(buf: []u8, hdr: Header, question: ?Question, sections: Sections, opt: ?OptRecord, ends: *SectionEnds) Error![]const u8 {
    var names: NameTable = .{};
    var ser: Serializer = .{ .buf = buf[0..@min(buf.len, max_message_len)], .names = &names };

    try ser.ensureSpace(12);
    ser.pos = 12;
    if (question) |q| try ser.writeQuestion(q);
    ends.question = ser.pos;
    for (sections.answers) |rr| try ser.writeResourceRecord(rr);
    ends.answers = ser.pos;
    for (sections.authorities) |rr| try ser.writeResourceRecord(rr);
    ends.authorities = ser.pos;
    for (sections.additionals) |rr| try ser.writeResourceRecord(rr);
    if (opt) |o| try ser.writeOpt(o);

    sections.header(hdr, question != null, opt != null).serialize(buf[0..12]);
    return buf[0..ser.pos];
}

test "header parse known bytes" {
    // Hand-crafted: id=0x1234, QR=1, opcode=0, AA=0, TC=0, RD=1, RA=1, rcode=0
    // flags = 1_0000_0_0_1_1_000_0000 = 0x8180
    const bytes = [12]u8{
        0x12, 0x34, // id
        0x81, 0x80, // flags: QR=1, RD=1, RA=1
        0x00, 0x01, // qdcount=1
        0x00, 0x02, // ancount=2
        0x00, 0x00, // nscount=0
        0x00, 0x00, // arcount=0
    };
    const hdr = Header.parse(&bytes);
    try testing.expectEqual(@as(u16, 0x1234), hdr.id);
    try testing.expect(hdr.flags.qr);
    try testing.expectEqual(OpCode.query, hdr.flags.opcode);
    try testing.expect(!hdr.flags.aa);
    try testing.expect(!hdr.flags.tc);
    try testing.expect(hdr.flags.rd);
    try testing.expect(hdr.flags.ra);
    try testing.expectEqual(@as(u16, 1), hdr.qd_count);
    try testing.expectEqual(@as(u16, 2), hdr.an_count);
}

test "name parsing - compressed" {
    // Build a message where offset 0 has "example.com" and then a pointer back
    // Offset 0: \x07example\x03com\x00  (13 bytes)
    // Offset 13: \x03foo\xC0\x00       (pointer to offset 0 = "example.com")
    // So "foo.example.com"
    const data = "\x07example\x03com\x00\x03foo\xC0\x00";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var parser = Parser{ .msg = data, .pos = 13 };
    const name = try parser.parseName(arena.allocator(), .compressed);

    try testing.expect(name.eql(.lit("foo.example.com")));
    // pos should advance past the pointer (13 + 3+1 + 2 = 19)
    try testing.expectEqual(@as(usize, 19), parser.pos);
}

test "name parsing - forward pointer rejection" {
    // Forward pointer at position 0 pointing to offset 2 — rejected per RFC 1035 §4.1.4
    const data = [_]u8{ 0xC0, 0x02, 0xC0, 0x00 };
    var parser = Parser{ .msg = &data, .pos = 0 };
    try testing.expectError(error.FormatError, parser.parseName(testing.allocator, .compressed));
}

test "name parsing - self pointer rejection" {
    // Self-pointer: offset == cursor, rejected as non-backward
    const data = [_]u8{ 0xC0, 0x00 };
    var parser = Parser{ .msg = &data, .pos = 0 };
    try testing.expectError(error.FormatError, parser.parseName(testing.allocator, .compressed));
}

test "full query packet parse" {
    const pkt = "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt);

    try testing.expectEqual(@as(u16, 0x0001), msg.header.id);
    try testing.expect(msg.header.flags.rd);
    const q = msg.question.?;
    try testing.expect(q.name.eql(.lit("example.com")));
    try testing.expectEqual(RType.a, q.qtype);
    try testing.expectEqual(RClass.in, q.qclass);
}

test "A record parsing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkt: [max_udp_payload]u8 = undefined;
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .a, &.{ 93, 184, 216, 34 }, 4));

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const rr = msg.answers[0];
    try testing.expectEqual(RType.a, rr.rtype);
    try testing.expectEqual(@as(u32, 300), rr.ttl);
    try testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &rr.a());
}

test "SOA record parsing" {
    var rd = TestRdata{};
    rd.putBytes("\x02ns\x07example\x03com\x00");
    rd.putBytes("\x05admin\x07example\x03com\x00");
    for ([_]u32{ 2023010101, 3600, 900, 604800, 86400 }) |v| rd.put(u32, v);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkt: [max_udp_payload]u8 = undefined;
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .soa, rd.slice(), rd.pos));

    const soa = msg.answers[0].soa();
    try testing.expect(soa.mname.eql(.lit("ns.example.com")));
    try testing.expect(soa.rname.eql(.lit("admin.example.com")));
    try testing.expectEqual(@as(u32, 2023010101), soa.serial);
    try testing.expectEqual(@as(u32, 3600), soa.refresh);
    try testing.expectEqual(@as(u32, 900), soa.retry);
    try testing.expectEqual(@as(u32, 604800), soa.expire);
    try testing.expectEqual(@as(u32, 86400), soa.minimum);
}

test "MX record parsing" {
    var rd = TestRdata{};
    rd.put(u16, 10);
    rd.putBytes("\x04mail\x07example\x03com\x00");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkt: [max_udp_payload]u8 = undefined;
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .mx, rd.slice(), rd.pos));

    const mx = msg.answers[0].mx();
    try testing.expectEqual(@as(u16, 10), mx.preference);
    try testing.expect(mx.exchange.eql(.lit("mail.example.com")));
}

test "TXT record parsing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkt: [max_udp_payload]u8 = undefined;
    const rdata = "\x1av=spf1 include:example.com\x05hello";
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .txt, rdata, rdata.len));

    var txt = msg.answers[0].txt();
    try testing.expectEqualStrings("v=spf1 include:example.com", txt.next().?);
    try testing.expectEqualStrings("hello", txt.next().?);
    try testing.expectEqual(null, txt.next());
}

test "name compression: owner and RFC 1035 rdata share suffixes, DNSSEC names stay flat" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const owner = try parseDottedName(a, "www.example.com");
    const ns1 = try parseDottedName(a, "ns1.example.com");
    const rrsig = RrsigData{
        .type_covered = .a,
        .algorithm = .ecdsap256sha256,
        .labels = 3,
        .original_ttl = 60,
        .sig_expiration = 2,
        .sig_inception = 1,
        .key_tag = 7,
        .signer_name = try parseDottedName(a, "example.com"),
        .signature = "sig",
    };
    const msg = Message{
        .header = mem.zeroes(Header),
        .question = .{ .name = owner, .qtype = .a, .qclass = .in },
        .answers = &.{
            .fixture(.{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 1, 2, 3, 4 } } }),
            .fixture(.{ .name = owner, .rtype = .rrsig, .rclass = .in, .ttl = 60, .rdata = .{ .rrsig = rrsig } }),
        },
        .authorities = &.{.fixture(.{ .name = try parseDottedName(a, "example.com"), .rtype = .ns, .rclass = .in, .ttl = 60, .rdata = .{ .ns = ns1 } })},
    };

    var buf: [512]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);
    // Question 21 + A(2+10+4) + RRSIG(2+10+18+13+3) + NS(2+10+4+2).
    try testing.expectEqual(@as(usize, 12 + 21 + 16 + 46 + 18), wire.len);
    try testing.expectEqualSlices(u8, "\x07example\x03com\x00", wire[12 + 21 + 16 + 30 ..][0..13]);

    const parsed = try parseMessage(a, wire);
    try testing.expect(parsed.answers[0].name.eql(owner));
    try testing.expect(parsed.answers[1].rrsig().signer_name.eql(rrsig.signer_name));
    try testing.expect(parsed.authorities[0].ns().eql(ns1));
}

test "name compression follows a pointer inside an earlier name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const www = try parseDottedName(a, "www.example.com");
    const mail = try parseDottedName(a, "mail.example.com");
    const rr: ResourceRecord = .fixture(.{ .name = mail, .rtype = .a, .rclass = .in, .ttl = 1, .rdata = .{ .a = .{ 1, 2, 3, 4 } } });
    var buf: [512]u8 = undefined;
    const wire = try serializeMessage(&buf, .{ .header = mem.zeroes(Header), .question = .{ .name = www, .qtype = .a, .qclass = .in }, .answers = &.{ rr, rr } });
    // The second owner is one pointer to "mail" + a pointer, itself.
    try testing.expectEqual(@as(usize, 12 + 21 + (7 + 14) + (2 + 14)), wire.len);
    const back = try parseMessage(a, wire);
    for (back.answers) |got| try testing.expect(got.name.eql(mail));
}

test "edge case: empty message (too short)" {
    try testing.expectError(error.EndOfData, parseMessage(testing.allocator, ""));
    try testing.expectError(error.EndOfData, parseMessage(testing.allocator, &@as([11]u8, @splat(0))));
}

test "edge case: truncated question" {
    // A three-byte label with one byte left.
    const pkt = "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03a";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.EndOfData, parseMessage(arena.allocator(), pkt));
}

test "RFC 9619 §4: two questions are malformed before either is read" {
    const q = "\x01a\x00\x00\x01\x00\x01";
    const pkt = "\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00" ++ q ++ q;
    try testing.expectError(error.FormatError, parseMessage(testing.failing_allocator, pkt));
}

test "RFC 1035 §4.1.4: a question's name holds no pointer, even one that would decode" {
    const header = "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    // A label of bytes 01 62 00, then a pointer into it: "\001b\000.b."
    const into_label = header ++ "\x03\x01b\x00\xc0\x0d\x00\x01\x00\x01";
    // Offset 4 is QDCOUNT's high byte, 00: the root.
    const into_header = header ++ "\xc0\x04\x00\x01\x00\x01";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.FormatError, parseMessage(arena.allocator(), into_label));
    try testing.expectError(error.FormatError, parseMessage(arena.allocator(), into_header));
}

test "edge case: a 63-byte label parses, a 64-byte one is no label type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const header = "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00";

    const max = header ++ "\x3f" ++ @as([63]u8, @splat('a')) ++ "\x00\x00\x01\x00\x01";
    const msg = try parseMessage(arena.allocator(), max);
    try testing.expectEqual(@as(usize, 63), msg.question.?.name.leaf().len);

    // 64 is 0x40: top bits 01, a label type RFC 1035 never defined.
    const over = header ++ "\x40" ++ @as([64]u8, @splat('a'));
    try testing.expectError(error.InvalidLabelType, parseMessage(arena.allocator(), over));
}

test "EDNS0: reserializing a parsed OPT response counts it once" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wire = [_]u8{ 0, 1, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0 };
    var buf: [64]u8 = undefined;
    const out = try serializeMessage(&buf, try parseMessage(arena.allocator(), &wire));
    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, out[10..12], .big));
    _ = try parseMessage(arena.allocator(), out);
}

test "EDNS0: serialized OPT has correct wire format" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const msg = try buildQuery(alloc, 0xABCD, .lit("x.com"), .a, .{ .rd = true, .edns = .{ .do_bit = true, .udp_payload_size = 4096 } });

    var buf: [max_udp_payload]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);

    try testing.expectEqual(@as(u16, 1), mem.readInt(u16, wire[10..12], .big));
    // After the 11-byte question: root owner, type 41, class 4096, a TTL
    // holding only DO, no rdata.
    try testing.expectEqualSlices(u8, "\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00", wire[12 + 11 ..]);
}

test "EDNS0: OPT with non-root owner is FORMERR (RFC 6891 §6.1.2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // example.com A, then an OPT owned by "x.".
    const wire = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01" ++
        "\x01x\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00";
    try testing.expectError(error.FormatError, parseMessage(arena.allocator(), wire));
}

test "RFC 6891 §6.1.1: a query's OPT is the only one in the message, whatever section holds the other" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const opt = "\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00";
    const header = "\x12\x34\x01\x00\x00\x01\x00\x01\x00\x00\x00\x01";
    const wire = header ++ "\x07example\x03com\x00\x00\x01\x00\x01" ++ opt ++ opt;
    try testing.expectError(error.MultipleOptRecords, readQuery(arena.allocator(), wire));
}

test "names are read lowercase, and the question as it was spelled" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // A reply to WwW.eXaMpLe whose answer's owner points at the question.
    const wire = "\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x03WwW\x07eXaMpLe\x00\x00\x01\x00\x01" ++
        "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04";
    const msg = try parseMessage(arena.allocator(), wire);
    try testing.expect(msg.question.?.name.eql(.lit("www.example")));
    try testing.expectEqualSlices(u8, "\x03WwW\x07eXaMpLe\x00", msg.question.?.spelled.?);
    try testing.expect(msg.answers[0].name.eql(.lit("www.example")));
}

test "a name lying whole in the message, lowercase, is read in place" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a_rr = "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04";
    const wire = "\x00\x01\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00" ++
        "\x07example\x03com\x00\x00\x01\x00\x01" ++
        "\xc0\x0c" ++ a_rr ++ "\x03www\xc0\x0c" ++ a_rr ++ "\x03WWW\x07example\x03com\x00" ++ a_rr;
    const msg = try parseMessage(arena.allocator(), wire);
    const in = struct {
        fn place(n: Name, bytes: []const u8) bool {
            return @intFromPtr(n.wire.ptr) >= @intFromPtr(bytes.ptr) and @intFromPtr(n.wire.ptr) < @intFromPtr(bytes.ptr) + bytes.len;
        }
    }.place;
    try testing.expect(in(msg.question.?.name, wire));
    try testing.expect(in(msg.answers[0].name, wire));
    try testing.expect(!in(msg.answers[1].name, wire));
    try testing.expect(!in(msg.answers[2].name, wire));
    try testing.expect(msg.answers[1].name.eql(.lit("www.example.com")));
    try testing.expect(msg.answers[2].name.eql(.lit("www.example.com")));
}

test "a pointer flood costs each name its 255 octets, no more" {
    // A 126-label question, then answers whose owner and rdata are each a
    // label and a pointer to it: 18 wire octets for two names of 255.
    var buf: [max_message_len]u8 = undefined;
    var n: usize = 12;
    for (0..max_label_count - 1) |_| {
        @memcpy(buf[n..][0..2], "\x01a");
        n += 2;
    }
    @memcpy(buf[n..][0..5], "\x00\x00\x0c\x00\x01");
    n += 5;
    const rr = "\x01b\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c\x00\x04\x01b\xc0\x0c";
    var answers: u16 = 0;
    while (n + rr.len <= buf.len) : (answers += 1) {
        @memcpy(buf[n..][0..rr.len], rr);
        n += rr.len;
    }
    (Header{ .id = 1, .flags = mem.zeroes(Header.Flags), .qd_count = 1, .an_count = answers }).serialize(buf[0..12]);
    const room = try testing.allocator.alloc(u8, 4 << 20);
    defer testing.allocator.free(room);
    var fixed = std.heap.FixedBufferAllocator.init(room);
    const msg = try parseMessage(fixed.allocator(), buf[0..n]);
    try testing.expectEqual(answers, msg.answers.len);
}

test "a TXT of empty strings costs its record, not a slice a string" {
    var buf: [max_message_len]u8 = undefined;
    const head = "\x00\x01\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x10\x00\x01\x00\x00\x01\x2c";
    @memcpy(buf[0..head.len], head);
    const rdlength = buf.len - head.len - 2;
    mem.writeInt(u16, buf[head.len..][0..2], rdlength, .big);
    @memset(buf[head.len + 2 ..], 0);
    var room: [4096]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&room);
    const msg = try parseMessage(fixed.allocator(), &buf);
    var strings = msg.answers[0].txt();
    var n: usize = 0;
    while (strings.next()) |str| : (n += 1) try testing.expectEqual(0, str.len);
    try testing.expectEqual(rdlength, n);
}

test "an NSEC's next name goes back out as signed (RFC 6840 §5.1)" {
    const rdata = "\x04HoSt\x07example\x00\x00\x01\x40";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkt: [max_udp_payload]u8 = undefined;
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .nsec, rdata, rdata.len));
    var next: Name.Buf = undefined;
    try testing.expect(msg.answers[0].nsec(&next).next_domain_name.eql(.lit("host.example")));
    var out: [max_udp_payload]u8 = undefined;
    try testing.expect(mem.endsWith(u8, try serializeMessage(&out, msg), rdata));
}

test "a query's other records are stepped, never built" {
    // A 127-label question, then answers whose owner and rdata both point at it.
    var buf: [max_message_len]u8 = undefined;
    var n: usize = 12;
    for (0..max_label_count) |_| {
        @memcpy(buf[n..][0..2], "\x01a");
        n += 2;
    }
    @memcpy(buf[n..][0..5], "\x00\x00\x0c\x00\x01");
    n += 5;
    const rr = "\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x0c";
    var answers: u16 = 0;
    while (n + rr.len <= buf.len) : (answers += 1) {
        @memcpy(buf[n..][0..rr.len], rr);
        n += rr.len;
    }
    (Header{ .id = 1, .flags = mem.zeroes(Header.Flags), .qd_count = 1, .an_count = answers }).serialize(buf[0..12]);
    var room: [4096]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&room);
    const query = try readQuery(fixed.allocator(), buf[0..n]);
    try testing.expectEqual(max_label_count, query.question.?.name.depth());
}

/// RFC 6672 §2.2: `owner` with its `suffix` replaced by `target`. Null
/// past 255 octets, where no name from the wire could match it.
pub fn substituteSuffix(allocator: Allocator, owner: Name, suffix: Name, target: Name) Allocator.Error!?Name {
    std.debug.assert(owner.isSubdomainOf(suffix));
    const prefix = owner.wire[0 .. owner.wire.len - suffix.wire.len];
    if (prefix.len + target.wire.len > max_name_wire_len) return null;
    const wire = try allocator.alloc(u8, prefix.len + target.wire.len);
    @memcpy(wire[0..prefix.len], prefix);
    @memcpy(wire[prefix.len..], target.wire);
    return .of(wire);
}

/// RFC 5452 §9.1: the one question sent, at any rcode, its spelling byte
/// for byte when `cased`. RFC 9619 lets a message carry none, but then
/// nothing matches.
pub fn validateResponse(response: Message, sent: []const u8, qtype: RType, cased: bool) error{Mismatch}!void {
    const f = response.header.flags;
    if (!f.qr or f.opcode != .query) return error.Mismatch;
    const q = response.question orelse return error.Mismatch;
    const got = q.spelled orelse return error.Mismatch;
    // Length octets sit below 'A', so only label bytes fold.
    const same = if (cased) mem.eql(u8, got, sent) else std.ascii.eqlIgnoreCase(got, sent);
    if (!same or q.qtype != qtype or q.qclass != .in) return error.Mismatch;
}

test "validateResponse: only the one question sent, at any rcode" {
    const sent = "\x07eXaMpLe\x03cOm\x00";
    const lower = "\x07example\x03com\x00";
    const other = "\x05other\x03net\x00";
    const reply = struct {
        fn make(spelled: ?[]const u8, rcode: RCode) Message {
            const f = Header.Flags{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = false, .ra = false, .z = 0, .ad = false, .cd = false, .rcode = rcode };
            const q: ?Question = if (spelled) |s| .{ .name = .root, .qtype = .a, .qclass = .in, .spelled = s } else null;
            return .{ .header = .{ .id = 0, .flags = f }, .question = q };
        }
    }.make;
    const bad = error.Mismatch;

    try validateResponse(reply(sent, .no_error), sent, .a, true);
    try validateResponse(reply(lower, .no_error), sent, .a, false);
    try std.testing.expectError(bad, validateResponse(reply(lower, .refused), sent, .a, true));
    try std.testing.expectError(bad, validateResponse(reply(other, .refused), sent, .a, false));
    try std.testing.expectError(bad, validateResponse(reply(null, .format_error), sent, .a, false));
    var notify = reply(sent, .no_error);
    notify.header.flags.opcode = @fromBackingInt(4);
    try std.testing.expectError(bad, validateResponse(notify, sent, .a, true));
}

test "wire TTLs: top bit set reads as zero (RFC 2181 §8), the rest cap at a week, NSEC and NSEC3 at three hours" {
    const a = [_]u8{ 192, 0, 2, 1 };
    // Next name the root; window 0 holds A.
    const nsec = [_]u8{ 0, 0, 1, 0x40 };
    // SHA-1, no salt, a one-byte hash, no types.
    const nsec3 = [_]u8{ 1, 0, 0, 0, 0, 1, 0xab };
    const Row = struct { rtype: RType, rdata: []const u8, ttl: u32, want: u32 };
    const rows = [_]Row{
        .{ .rtype = .a, .rdata = &a, .ttl = 300, .want = 300 },
        .{ .rtype = .a, .rdata = &a, .ttl = max_ttl, .want = max_ttl },
        .{ .rtype = .a, .rdata = &a, .ttl = max_ttl + 1, .want = max_ttl },
        .{ .rtype = .a, .rdata = &a, .ttl = 0x7FFFFFFF, .want = max_ttl },
        .{ .rtype = .a, .rdata = &a, .ttl = 0x80000000, .want = 0 },
        .{ .rtype = .a, .rdata = &a, .ttl = 0xFFFFFFFF, .want = 0 },
        .{ .rtype = .nsec, .rdata = &nsec, .ttl = 86400, .want = max_negative_ttl },
        .{ .rtype = .nsec3, .rdata = &nsec3, .ttl = 86400, .want = max_negative_ttl },
    };
    var pkt: [512]u8 = undefined;
    @memcpy(pkt[0..12], &[_]u8{ 0, 1, 0x81, 0x80, 0, 0, 0, rows.len, 0, 0, 0, 0 });
    var pos: usize = 12;
    for (rows) |row| {
        pkt[pos] = 0;
        mem.writeInt(u16, pkt[pos + 1 ..][0..2], @backingInt(row.rtype), .big);
        mem.writeInt(u16, pkt[pos + 3 ..][0..2], 1, .big);
        mem.writeInt(u32, pkt[pos + 5 ..][0..4], row.ttl, .big);
        mem.writeInt(u16, pkt[pos + 9 ..][0..2], @intCast(row.rdata.len), .big);
        @memcpy(pkt[pos + 11 ..][0..row.rdata.len], row.rdata);
        pos += 11 + row.rdata.len;
    }
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);
    try testing.expectEqual(rows.len, msg.answers.len);
    for (msg.answers, rows) |rr, row| try testing.expectEqual(row.want, rr.ttl);
}

test "compression past its work budget writes names whole, and they read back" {
    // 126-label names differing only nearest the root: a compare per suffix per entry.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var rrs: [60]ResourceRecord = undefined;
    const owner: Name = .lit("x");
    for (&rrs, 0..) |*rr, i| {
        var w: std.ArrayList(u8) = .empty;
        for (0..125) |_| try w.appendSlice(a, "\x01a");
        const last = try a.print("b{d}", .{i});
        try w.append(a, @intCast(last.len));
        try w.appendSlice(a, last);
        try w.append(a, 0);
        rr.* = .fixture(.{ .name = owner, .rtype = .ptr, .rclass = .in, .ttl = 60, .rdata = .{ .ptr = .of(w.items) } });
    }
    const q: Question = .{ .name = owner, .qtype = .ptr, .qclass = .in };
    var buf: [max_message_len]u8 = undefined;
    const wire = try serializeMessage(&buf, .{ .header = mem.zeroes(Header), .question = q, .answers = &rrs });
    const back = try parseMessage(a, wire);
    try testing.expectEqual(rrs.len, back.answers.len);
    for (rrs, back.answers) |want, got| try testing.expect(want.ptr().eql(got.ptr()));
}

test "parseDottedName: trailing dot optional, root is empty, bad labels refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = Name.lit("example.com");
    try testing.expect(want.eql(try parseDottedName(a, "example.com")));
    try testing.expect(want.eql(try parseDottedName(a, "example.com.")));
    try testing.expect((try parseDottedName(a, ".")).isRoot());
    try testing.expect((try parseDottedName(a, "")).isRoot());
    try testing.expectError(error.InvalidLabelType, parseDottedName(a, "example..com"));
    const long_label = @as([64]u8, @splat('a')) ++ ".com".*;
    try testing.expectError(error.LabelTooLong, parseDottedName(a, &long_label));
}

test "substituteSuffix declines a substitution that overflows a legal name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const long_label = @as([63]u8, @splat('x')) ++ ".";
    // Four 63-octet labels is 257 wire octets — past the 255 limit.
    const owner: Name = .lit(long_label ++ long_label ++ "short");
    const suffix: Name = .lit("short");
    const target: Name = .lit(long_label ++ long_label);
    try testing.expect(try substituteSuffix(a, owner, suffix, target) == null);

    const fits = try substituteSuffix(a, owner, suffix, .lit("net"));
    try testing.expect(fits.?.eql(.lit(long_label ++ long_label ++ "net")));
}

test "a name walks up to the root, label by label" {
    const name = Name.lit("www.example.com.");
    try testing.expectEqual(@as(u8, 3), name.depth());
    try testing.expectEqualStrings("www", name.leaf());
    try testing.expect(name.ancestor(2).eql(.lit("example.com")));
    try testing.expect(name.ancestor(3).eql(name));
    try testing.expect(name.ancestor(0).isRoot());
    var up: ?Name = name;
    var seen: usize = 0;
    while (up) |n| : (up = n.parent()) seen += 1;
    try testing.expectEqual(@as(usize, 4), seen);
}

test "RFC 4034 §6.1: names in canonical order" {
    const sorted = [_]Name{
        .lit("example"),
        .lit("a.example"),
        .lit("yljkjljk.a.example"),
        .lit("z.a.example"),
        .lit("zabc.a.example"),
        .lit("z.example"),
        .lit("\\001.z.example"),
        .lit("*.z.example"),
        .lit("\\200.z.example"),
    };
    for (sorted, 0..) |a, i| for (sorted, 0..) |b, j| {
        try testing.expectEqual(std.math.order(i, j), a.order(b));
    };
}

test "shared ancestors, and a child that would pass 255 octets is none" {
    const q = Name.lit("a.b.example.com");
    try testing.expect(q.shared(.lit("z.b.example.com")).eql(.lit("b.example.com")));
    try testing.expect(q.shared(.lit("example.net")).isRoot());
    try testing.expect(q.shared(.lit("x.a.b.example.com")).eql(q));

    var buf: Name.Buf = undefined;
    try testing.expect(Name.child(&buf, "*", q.parent().?).?.eql(.lit("*.b.example.com")));
    const label: [63]u8 = @splat('a');
    const three = label ++ "." ++ label ++ "." ++ label ++ ".";
    const full = Name.lit(three ++ @as([61]u8, @splat('a')));
    const room = Name.lit(three ++ @as([59]u8, @splat('a')));
    try testing.expectEqual(@as(usize, 255), full.wire.len);
    try testing.expectEqual(null, Name.child(&buf, "*", full));
    try testing.expectEqual(@as(usize, 255), Name.child(&buf, "*", room).?.wire.len);
}

test "isSubdomainOf: self, descendants and the root; never a sibling, nor a label's tail" {
    const name = Name.lit("example.com");
    try testing.expect(name.isSubdomainOf(name));
    try testing.expect((Name.lit("www.example.com")).isSubdomainOf(name));
    // Bytes `\x07example\x03com\x00` end this name inside its first label.
    try testing.expect(!(Name.lit("a\\007example.com")).isSubdomainOf(name));
    try testing.expect(name.isSubdomainOf(.root));
    try testing.expect(!(Name.lit("a.example.com")).isSubdomainOf(.lit("b.example.com")));
}

const TestRdata = struct {
    buf: [256]u8 = undefined,
    pos: u16 = 0,

    fn put(self: *TestRdata, comptime T: type, v: T) void {
        mem.writeInt(T, self.buf[self.pos..][0..@sizeOf(T)], v, .big);
        self.pos += @sizeOf(T);
    }
    fn putBytes(self: *TestRdata, v: []const u8) void {
        @memcpy(self.buf[self.pos..][0..v.len], v);
        self.pos += @intCast(v.len);
    }
    fn slice(self: *const TestRdata) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// A response holding one answer, example.com IN 300, whose RDLENGTH
/// says `rdlength` whatever `rdata` holds.
fn testAnswer(pkt: *[max_udp_payload]u8, rtype: RType, rdata: []const u8, rdlength: u16) []const u8 {
    const head = "\x00\x01\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x07example\x03com\x00";
    @memcpy(pkt[0..head.len], head);
    const at = head.len;
    mem.writeInt(u16, pkt[at..][0..2], @backingInt(rtype), .big);
    mem.writeInt(u16, pkt[at + 2 ..][0..2], 1, .big);
    mem.writeInt(u32, pkt[at + 4 ..][0..4], 300, .big);
    mem.writeInt(u16, pkt[at + 8 ..][0..2], rdlength, .big);
    @memcpy(pkt[at + 10 ..][0..rdata.len], rdata);
    return pkt[0 .. at + 10 + rdata.len];
}

test "DNSKEY record parsing" {
    // RDATA: flags=257 (KSK), protocol=3, algorithm=8 (RSA/SHA-256), key=16 bytes
    const key_data = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var rd = TestRdata{};
    rd.put(u16, 257);
    rd.put(u8, 3);
    rd.put(u8, 8);
    rd.putBytes(&key_data);

    var pkt: [max_udp_payload]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .dnskey, rd.slice(), rd.pos));

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const dnskey = msg.answers[0].dnskey();
    try testing.expectEqual(@as(u16, 257), dnskey.flags);
    try testing.expectEqual(@as(u8, 3), dnskey.protocol);
    try testing.expectEqual(DnssecAlgorithm.rsasha256, dnskey.algorithm);
    try testing.expect(dnskey.isZoneKey());
    try testing.expectEqualSlices(u8, &key_data, dnskey.public_key);
}

test "DS record parsing" {
    // RDATA: key_tag=20326, alg=8, digest_type=2 (SHA-256), digest=32 bytes
    const digest = [32]u8{ 0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84, 0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D };
    var rd = TestRdata{};
    rd.put(u16, 20326);
    rd.put(u8, 8);
    rd.put(u8, 2);
    rd.putBytes(&digest);

    var pkt: [max_udp_payload]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .ds, rd.slice(), rd.pos));

    const ds = msg.answers[0].ds();
    try testing.expectEqual(@as(u16, 20326), ds.key_tag);
    try testing.expectEqual(DnssecAlgorithm.rsasha256, ds.algorithm);
    try testing.expectEqual(DigestType.sha256, ds.digest_type);
    try testing.expectEqualSlices(u8, &digest, ds.digest);
}

test "RRSIG record parsing" {
    const signer_wire = "\x07example\x03com\x00";
    const fake_sig = [8]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    var rd = TestRdata{};
    rd.put(u16, 1); // type_covered = A
    rd.put(u8, 13); // algorithm = ECDSAP256SHA256
    rd.put(u8, 2); // labels
    rd.put(u32, 300); // original_ttl
    rd.put(u32, 1700000000); // sig_expiration
    rd.put(u32, 1699000000); // sig_inception
    rd.put(u16, 12345); // key_tag
    rd.putBytes(signer_wire);
    rd.putBytes(&fake_sig);

    var pkt: [max_udp_payload]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .rrsig, rd.slice(), rd.pos));

    const rrsig = msg.answers[0].rrsig();
    try testing.expectEqual(RType.a, rrsig.type_covered);
    try testing.expectEqual(DnssecAlgorithm.ecdsap256sha256, rrsig.algorithm);
    try testing.expectEqual(@as(u8, 2), rrsig.labels);
    try testing.expectEqual(@as(u32, 300), rrsig.original_ttl);
    try testing.expectEqual(@as(u32, 1700000000), rrsig.sig_expiration);
    try testing.expectEqual(@as(u32, 1699000000), rrsig.sig_inception);
    try testing.expectEqual(@as(u16, 12345), rrsig.key_tag);
    try testing.expect(rrsig.signer_name.eql(.lit("example.com")));
    try testing.expectEqualSlices(u8, &fake_sig, rrsig.signature);
}

test "NSEC record parsing" {
    const next_name = "\x04host\x07example\x03com\x00";
    const bitmap = "\x00\x07\x62\x01\x00\x00\x00\x03\x80";
    var rd = TestRdata{};
    rd.putBytes(next_name);
    rd.putBytes(bitmap);

    var pkt: [max_udp_payload]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .nsec, rd.slice(), rd.pos));

    var next: Name.Buf = undefined;
    const nsec = msg.answers[0].nsec(&next);
    try testing.expectEqualStrings("host", nsec.next_domain_name.leaf());
    try testing.expectEqualSlices(u8, bitmap, nsec.type_bit_maps);
}

test "NSEC3 record parsing" {
    const salt = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const next_hash = [20]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 };
    const bitmap = [_]u8{ 0x00, 0x01, 0x40 }; // window 0, len 1, A bit set
    var rd = TestRdata{};
    rd.put(u8, 1); // hash_algorithm (SHA-1)
    rd.put(u8, 0); // flags
    rd.put(u16, 10); // iterations
    rd.put(u8, @intCast(salt.len));
    rd.putBytes(&salt);
    rd.put(u8, @intCast(next_hash.len));
    rd.putBytes(&next_hash);
    rd.putBytes(&bitmap);

    var pkt: [max_udp_payload]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), testAnswer(&pkt, .nsec3, rd.slice(), rd.pos));

    const nsec3 = msg.answers[0].nsec3();
    try testing.expectEqual(Nsec3HashAlgorithm.sha1, nsec3.hash_algorithm);
    try testing.expectEqual(@as(u8, 0), nsec3.flags);
    try testing.expectEqual(@as(u16, 10), nsec3.iterations);
    try testing.expectEqualSlices(u8, &salt, nsec3.salt);
    try testing.expectEqualSlices(u8, &next_hash, nsec3.next_hashed_owner);
    try testing.expectEqualSlices(u8, &bitmap, nsec3.type_bit_maps);
}

test "typeBitmapContains" {
    const bitmap = [_]u8{
        0x00, 0x07, // window 0, length 7
        0x62, // byte 0: A(1), NS(2), SOA(6)
        0x00, // byte 1: empty
        0x00, // byte 2: empty
        0x00, // byte 3: empty
        0x00, // byte 4: empty
        0x03, // byte 5: RRSIG(46), NSEC(47)
        0x80, // byte 6: DNSKEY(48)
    };

    try testing.expect(typeBitmapContains(&bitmap, .a));
    try testing.expect(typeBitmapContains(&bitmap, .ns));
    try testing.expect(typeBitmapContains(&bitmap, .soa));
    try testing.expect(typeBitmapContains(&bitmap, .rrsig));
    try testing.expect(typeBitmapContains(&bitmap, .nsec));
    try testing.expect(typeBitmapContains(&bitmap, .dnskey));
    try testing.expect(!typeBitmapContains(&bitmap, .aaaa));
    try testing.expect(!typeBitmapContains(&bitmap, .mx));
    try testing.expect(!typeBitmapContains(&bitmap, .txt));
    try testing.expect(!typeBitmapContains(&bitmap, .cname));

    try testing.expect(!typeBitmapContains(&.{}, .a));
}

test "an unnamed wire value prints as its number" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("aaaa", try std.mem.print(&buf, "{f}", .{tag(RType.aaaa)}));
    try testing.expectEqualStrings("999", try std.mem.print(&buf, "{f}", .{tag(@as(RType, @fromBackingInt(999)))}));
    try testing.expectEqualStrings("9", try std.mem.print(&buf, "{f}", .{tag(@as(RCode, @fromBackingInt(9)))}));
}

test "RRSIG with signer name exceeding rdlength returns InvalidRDataLength" {
    var rd = TestRdata{};
    rd.put(u16, 1); // type covered
    rd.put(u8, 13); // algorithm
    rd.put(u8, 2); // labels
    for ([_]u32{ 300, 1700000000, 1699000000 }) |v| rd.put(u32, v);
    rd.put(u16, 12345); // key tag
    rd.putBytes("\x07example\x03com\x00");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkt: [max_udp_payload]u8 = undefined;
    // 18 fixed bytes and a 13-byte signer: 20 ends inside the signer.
    try testing.expectError(error.InvalidRDataLength, parseMessage(arena.allocator(), testAnswer(&pkt, .rrsig, rd.slice(), 20)));
}

test "NSEC with next domain name exceeding rdlength returns InvalidRDataLength" {
    const next = "\x04host\x07example\x03com\x00";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkt: [max_udp_payload]u8 = undefined;
    try testing.expectError(error.InvalidRDataLength, parseMessage(arena.allocator(), testAnswer(&pkt, .nsec, next, 5)));
}

test "RFC 4034 §3.1.7, §4.1.1: an RRSIG's signer and an NSEC's next name hold no pointer" {
    var rd = TestRdata{};
    rd.put(u16, 1); // type covered
    rd.put(u8, 13); // algorithm
    rd.put(u8, 2); // labels
    for ([_]u32{ 300, 1700000000, 1699000000 }) |v| rd.put(u32, v);
    rd.put(u16, 12345); // key tag
    rd.putBytes("\xc0\x0csig"); // the owner, example.com, by pointer
    const nsec = "\xc0\x0c\x00\x01\x40";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkt: [max_udp_payload]u8 = undefined;
    try testing.expectError(error.FormatError, parseMessage(arena.allocator(), testAnswer(&pkt, .rrsig, rd.slice(), @intCast(rd.slice().len))));
    try testing.expectError(error.FormatError, parseMessage(arena.allocator(), testAnswer(&pkt, .nsec, nsec, nsec.len)));
}

test "applyCase0x20 only flips ASCII letters" {
    var prng: std.Random.DefaultPrng = .init(0x20);
    const original = "\x03Foo\x0aBar123-baz\x03com\x00";
    var randomized = original.*;
    applyCase0x20(prng.random(), &randomized);
    for (randomized, original) |rb, ob| {
        if (std.ascii.isAlphabetic(ob)) {
            try testing.expectEqual(std.ascii.toLower(ob), std.ascii.toLower(rb));
        } else {
            try testing.expectEqual(ob, rb);
        }
    }
}

test "applyCase0x20 distribution: each letter flips ~50% over many runs" {
    var prng: std.Random.DefaultPrng = .init(0x20);
    const iterations: usize = 10_000;
    const letters = "\x1aabcdefghijklmnopqrstuvwxyz\x00";
    var upper_counts: [26]u32 = @splat(0);

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var n = letters.*;
        applyCase0x20(prng.random(), &n);
        for (n[1..27], 0..) |b, idx| {
            if (std.ascii.isUpper(b)) upper_counts[idx] += 1;
        }
    }

    for (upper_counts) |c| {
        const ratio = @as(f64, @floatFromInt(c)) / @as(f64, @floatFromInt(iterations));
        try testing.expect(ratio > 0.45 and ratio < 0.55);
    }
}

test "formatInto is injective over hostile labels" {
    var buf: [max_dotted_len + 1]u8 = undefined;

    // The two wire names that motivated RFC 4343 §2.1 escaping: a literal
    // 0x2e inside a label must not render like the separator.
    try testing.expectEqualStrings("e\\.d.com", (Name.lit("e\\.d.com")).formatInto(&buf));
    try testing.expectEqualStrings("e.d.com", (Name.lit("e.d.com")).formatInto(&buf));

    // Non-printables render as \DDD, so 0x07 no longer collides with '?'.
    try testing.expectEqualStrings("\\007foo.com", (Name.lit("\\007foo.com")).formatInto(&buf));
    try testing.expectEqualStrings("?foo.com", (Name.lit("?foo.com")).formatInto(&buf));

    try testing.expectEqualStrings("a\\\\b", (Name.lit("a\\\\b")).formatInto(&buf));
    try testing.expectEqualStrings("\\032.\\255", (Name.lit("\\032.\\255")).formatInto(&buf));
}

test "formatInto/parseDottedName round-trip every label byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var b: usize = 0;
    while (b < 256) : (b += 1) {
        var wire = "\x03a?z\x07example\x03com\x00".*;
        wire[2] = std.ascii.toLower(@intCast(b));
        const original: Name = .of(&wire);
        var buf: [max_dotted_len + 1]u8 = undefined;
        const parsed = try parseDottedName(alloc, original.formatInto(&buf));
        try testing.expect(original.eql(parsed));
    }

    // Worst case: a wire-maximal name of pure \DDD content (253 bytes over
    // four labels) renders to 4·250+3 = 1003 chars and still round-trips.
    const wide = [_]u8{max_label_len} ++ @as([max_label_len]u8, @splat(0));
    const last = [_]u8{61} ++ @as([61]u8, @splat(0));
    const original: Name = .of(&(wide ++ wide ++ wide ++ last ++ [_]u8{0}));
    var buf: [max_dotted_len + 1]u8 = undefined;
    const parsed = try parseDottedName(alloc, original.formatInto(&buf));
    try testing.expect(original.eql(parsed));
}

test "parseDottedName decodes presentation escapes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const escaped_dot = try parseDottedName(alloc, "e\\.d.com");
    try testing.expect(escaped_dot.eql(.lit("e\\.d.com")));

    // \DDD is a decimal byte, \X a literal, and a trailing escaped dot is
    // content rather than a stripped separator.
    try testing.expect((try parseDottedName(alloc, "\\068")).eql(.lit("d")));
    try testing.expect((try parseDottedName(alloc, "ex\\ample.com")).eql(.lit("example.com")));
    try testing.expect((try parseDottedName(alloc, "a\\.")).eql(.lit("a\\.")));

    try testing.expectError(error.FormatError, parseDottedName(alloc, "a\\"));
    try testing.expectError(error.FormatError, parseDottedName(alloc, "a\\12"));
    try testing.expectError(error.FormatError, parseDottedName(alloc, "a\\1x2"));
    try testing.expectError(error.FormatError, parseDottedName(alloc, "a\\999"));
}
