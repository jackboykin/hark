const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

// ── Helpers ──────────────────────────────────────────────────────────

/// Safe replacement for `@tagName` on non-exhaustive enums.
/// Returns the field name for known values, or the numeric string for unknown ones.
pub fn safeTagName(comptime E: type, val: E, buf: *[24]u8) []const u8 {
    const info = @typeInfo(E).@"enum";
    inline for (info.field_names, info.field_values) |name, value| {
        if (@backingInt(val) == value) return name;
    }
    return std.fmt.bufPrint(buf, "{d}", .{@backingInt(val)}) catch "?";
}

/// Check the TC (truncation) bit on raw wire data without full parsing.
/// Used to detect truncated UDP responses before attempting parseMessage,
/// which may fail with EndOfData on mid-record truncation (RFC 2181).
pub fn hasTcBit(bytes: []const u8) bool {
    if (bytes.len < header_len) return false;
    const flags: Header.Flags = @bitCast(mem.readInt(u16, bytes[2..4], .big));
    return flags.tc;
}

// ── Constants ──────────────────────────────────────────────────────────

pub const max_label_len = 63;
pub const max_label_count = 127; // (255 wire octets - 1 root byte) / 2 octets per single-char label = 127
pub const max_name_len = 253;
pub const header_len = 12;
pub const max_udp_payload = 512;
pub const edns_udp_payload: u16 = 1232;
/// RFC 1035 §4.2.2: DNS-over-TCP uses a 2-byte length prefix, so a single
/// message can be at most 65535 bytes. Also the ceiling for any DNS
/// response buffer we might parse.
pub const max_message_len: u16 = 65535;

/// Stage `wire_query` into `buf` as a 2-byte big-endian length prefix
/// followed by the query bytes. Returns the populated slice. Used by
/// DNS-over-TCP and DNS-over-TLS callers; both bound queries to
/// `edns_udp_payload`.
pub fn stageLengthPrefixed(buf: *[2 + edns_udp_payload]u8, wire_query: []const u8) ![]const u8 {
    if (wire_query.len > edns_udp_payload) return error.QueryTooLarge;
    std.mem.writeInt(u16, buf[0..2], @intCast(wire_query.len), .big);
    @memcpy(buf[2..][0..wire_query.len], wire_query);
    return buf[0 .. 2 + wire_query.len];
}

// ── Enums ──────────────────────────────────────────────────────────────

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
    _,

    /// Server-side error (SERVFAIL/REFUSED) — the server received the query
    /// but couldn't or wouldn't answer. Used for lame detection (RFC 4697).
    pub fn isServerError(self: RCode) bool {
        return self == .server_failure or self == .refused;
    }

    /// Should the iterative resolver abandon this NS's answer and try a
    /// sibling? Broader than isServerError: a FORMERR usually means *this*
    /// server can't interpret the query (EDNS-hostile auth, COOKIE-mangling
    /// middlebox), but a sibling NS for the zone may still answer (RFC 1034
    /// §4.3.5). Both fallthrough sites deliberately score FORMERR as
    /// .server_error too — hark always sends EDNS and never retries without
    /// it, so a FORMERR-ing NS can't serve the zone. Only the DoT guard
    /// keeps isServerError's narrower SERVFAIL/REFUSED meaning.
    pub fn shouldTrySiblingNs(self: RCode) bool {
        return self.isServerError() or self == .format_error;
    }
};

pub const RType = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    mx = 15,
    txt = 16,
    aaaa = 28,
    /// RFC 6672. hark does not synthesize DNAMEs (RDATA parses as `.unknown`),
    /// but RFC 6840 §4.1 requires recognizing the bit in an NSEC/NSEC3 bitmap:
    /// names beneath a DNAME owner are synthesized, not absent.
    dname = 39,
    opt = 41,
    ds = 43,
    rrsig = 46,
    nsec = 47,
    dnskey = 48,
    nsec3 = 50,
    nsec3param = 51,
    any = 255,
    _,
};

pub const RClass = enum(u16) {
    in = 1,
    _,
};

// ── Error Set ──────────────────────────────────────────────────────────

pub const Error = error{
    EndOfData,
    LabelTooLong,
    NameTooLong,
    TooManyLabels,
    CompressionPointerLoop,
    FormatError,
    InvalidLabelType,
    InvalidRDataLength,
    MultipleOptRecords,
    OutOfMemory,
};

// ── Header ─────────────────────────────────────────────────────────────

pub const Header = struct {
    id: u16,
    flags: Flags,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,

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

// ── Name ───────────────────────────────────────────────────────────────

pub const Name = struct {
    labels: []const []const u8,

    /// Format `self` into `buf` as a dotted string. Returns the written slice so
    /// callers don't need to re-scan for the null terminator.
    ///
    /// Display-lossy (non-printables render as `?`); for logging only, not
    /// byte-exact comparison — use `eqlExact` for that.
    pub fn formatInto(self: Name, buf: *[max_name_len + 1]u8) []const u8 {
        var pos: usize = 0;
        for (self.labels) |label| {
            if (pos > 0) {
                buf[pos] = '.';
                pos += 1;
            }
            for (label) |byte| {
                buf[pos] = if (byte >= 0x21 and byte <= 0x7e) byte else '?';
                pos += 1;
            }
        }
        return buf[0..pos];
    }

    /// Like `formatInto` but lowercased (DNS is case-insensitive).
    pub fn formatLower(self: Name, buf: *[max_name_len + 1]u8) []const u8 {
        const dotted = self.formatInto(buf);
        for (buf[0..dotted.len]) |*b| b.* = std.ascii.toLower(b.*);
        return buf[0..dotted.len];
    }

    pub fn eql(a: Name, b: Name) bool {
        if (a.labels.len != b.labels.len) return false;
        for (a.labels, b.labels) |la, lb| {
            if (!std.ascii.eqlIgnoreCase(la, lb)) return false;
        }
        return true;
    }

    /// Strict byte-exact comparison — used to verify 0x20 echo
    /// (RFC draft Vixie/Dagon "Use of Bit 0x20").
    pub fn eqlExact(a: Name, b: Name) bool {
        if (a.labels.len != b.labels.len) return false;
        for (a.labels, b.labels) |la, lb| {
            if (!mem.eql(u8, la, lb)) return false;
        }
        return true;
    }

    /// Returns true if self is equal to or a subdomain of parent.
    /// E.g. "www.example.com".isSubdomainOf("example.com") == true
    pub fn isSubdomainOf(self: Name, parent: Name) bool {
        if (parent.labels.len == 0) return true; // everything is under root
        if (self.labels.len < parent.labels.len) return false;
        const offset = self.labels.len - parent.labels.len;
        for (parent.labels, 0..) |p_label, i| {
            if (!std.ascii.eqlIgnoreCase(self.labels[offset + i], p_label)) return false;
        }
        return true;
    }
};

// ── RData types ────────────────────────────────────────────────────────

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

    /// Seconds until this signature expires at `now`, saturating at 0. For
    /// the RFC 4035 §5.3.3 TTL ceiling, not the validator's freshness check,
    /// which needs the clock-skew-tolerant comparison in dnssec.zig.
    pub fn secondsUntilExpiry(self: RrsigData, now: u32) u32 {
        return if (serialAfter(self.sig_expiration, now)) self.sig_expiration -% now else 0;
    }
};

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

test "secondsUntilExpiry: saturates at zero and wraps as a serial" {
    var sig: RrsigData = .{
        .type_covered = .a,
        .algorithm = .ecdsap256sha256,
        .labels = 2,
        .original_ttl = 3600,
        .sig_expiration = 1000,
        .sig_inception = 0,
        .key_tag = 0,
        .signer_name = .{ .labels = &.{} },
        .signature = "",
    };
    try testing.expectEqual(@as(u32, 400), sig.secondsUntilExpiry(600));
    try testing.expectEqual(@as(u32, 0), sig.secondsUntilExpiry(1000));
    try testing.expectEqual(@as(u32, 0), sig.secondsUntilExpiry(1001));
    // Expiration just past the 2^32 wrap is still in the future.
    sig.sig_expiration = 5;
    try testing.expectEqual(@as(u32, 10), sig.secondsUntilExpiry(0xFFFFFFFB));
}

/// Returns the rtype an RRSIG record covers, or null if `rr` isn't an RRSIG.
/// Centralised because RFC 4035 RRSIG-vs-covered-RRset bookkeeping recurs
/// across the cache, shaper, and validator paths.
pub fn rrsigCovers(rr: ResourceRecord) ?RType {
    if (rr.rtype != .rrsig) return null;
    return rr.rdata.rrsig.type_covered;
}

/// Wildcard-expansion / negative-existence DNSSEC proof material per
/// RFC 4035 §3.1.3. True for NSEC, NSEC3, and RRSIGs covering either.
/// Used by the CNAME-chain aggregator and the cache's wildcard / negative
/// proof capture — same predicate, multiple call sites.
pub fn isNsecProofMaterial(rr: ResourceRecord) bool {
    return switch (rr.rtype) {
        .nsec, .nsec3 => true,
        .rrsig => switch (rrsigCovers(rr) orelse return false) {
            .nsec, .nsec3 => true,
            else => false,
        },
        else => false,
    };
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

pub const Nsec3ParamData = struct {
    hash_algorithm: Nsec3HashAlgorithm,
    flags: u8,
    iterations: u16,
    salt: []const u8,
};

pub const RData = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    ns: Name,
    cname: Name,
    ptr: Name,
    mx: MxData,
    soa: SoaData,
    txt: TxtData,
    rrsig: RrsigData,
    dnskey: DnskeyData,
    ds: DsData,
    nsec: NsecData,
    nsec3: Nsec3Data,
    nsec3param: Nsec3ParamData,
    unknown: []const u8,
};

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

// ── Base32hex (RFC 4648 §7) ───────────────────────────────────────────

/// Decode base32hex (RFC 4648 §7) without padding.
/// Returns the number of bytes written to `dest`.
pub fn base32HexDecode(dest: []u8, encoded: []const u8) error{InvalidBase32}!usize {
    var bits: u32 = 0;
    var bit_count: u4 = 0;
    var out: usize = 0;

    for (encoded) |c| {
        const val: u5 = switch (c) {
            '0'...'9' => @intCast(c - '0'),
            'A'...'V' => @intCast(c - 'A' + 10),
            'a'...'v' => @intCast(c - 'a' + 10),
            else => return error.InvalidBase32,
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if (bit_count >= 8) {
            bit_count -= 8;
            if (out >= dest.len) return error.InvalidBase32;
            dest[out] = @intCast((bits >> bit_count) & 0xFF);
            out += 1;
        }
    }
    return out;
}

/// Encode bytes to base32hex (RFC 4648 §7) without padding.
/// Returns a slice into `dest` with the encoded string.
pub fn base32HexEncode(dest: []u8, data: []const u8) []const u8 {
    const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    var bits: u32 = 0;
    var bit_count: u4 = 0;
    var out: usize = 0;

    for (data) |b| {
        bits = (bits << 8) | b;
        bit_count += 8;
        while (bit_count >= 5) {
            bit_count -= 5;
            dest[out] = alphabet[@intCast((bits >> bit_count) & 0x1F)];
            out += 1;
        }
    }
    // Emit trailing bits (if any)
    if (bit_count > 0) {
        dest[out] = alphabet[@intCast((bits << (5 - bit_count)) & 0x1F)];
        out += 1;
    }
    return dest[0..out];
}

// ── EDNS0 (RFC 6891) ──────────────────────────────────────────────────

/// Well-known EDNS option codes consumed/emitted by hark.
pub const edns_opt_tcp_keepalive: u16 = 11; // RFC 7828
const edns_opt_padding: u16 = 12; // RFC 7830

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
    /// If non-zero, serializeMessage adds an EDNS0 padding option (code 12)
    /// so the total message reaches this size. Set by buildQuery.
    padding_target: u16 = 0,
};

// ── Question ───────────────────────────────────────────────────────────

pub const Question = struct {
    name: Name,
    qtype: RType,
    qclass: RClass,
};

// ── ResourceRecord ─────────────────────────────────────────────────────

pub const ResourceRecord = struct {
    name: Name,
    rtype: RType,
    rclass: RClass,
    ttl: u32,
    rdata: RData,
    /// When set, serializer memcpys these bytes and patches the 4 TTL bytes
    /// at `wire_ttl_offset` from `.ttl` — the blob's own TTL is a placeholder.
    wire: ?[]const u8 = null,
    wire_ttl_offset: u16 = 0,
};

// ── Message ────────────────────────────────────────────────────────────

pub const Message = struct {
    header: Header,
    questions: []const Question,
    answers: []const ResourceRecord = &.{},
    authorities: []const ResourceRecord = &.{},
    additionals: []const ResourceRecord = &.{},
    opt: ?OptRecord = null,
};

// ── Name / Query builders ──────────────────────────────────────────────

pub fn parseDottedName(allocator: Allocator, dotted: []const u8) Error!Name {
    // Handle root zone
    if (dotted.len == 0 or (dotted.len == 1 and dotted[0] == '.')) {
        const labels = try allocator.alloc([]const u8, 0);
        return .{ .labels = labels };
    }

    // Strip optional trailing dot
    const name_str = if (dotted[dotted.len - 1] == '.') dotted[0 .. dotted.len - 1] else dotted;

    // Validate first (no allocations, so no cleanup needed on error)
    var total_len: usize = 0;
    var label_count: usize = 0;
    {
        var iter = mem.splitScalar(u8, name_str, '.');
        while (iter.next()) |label| {
            if (label.len == 0) return error.InvalidLabelType;
            if (label.len > max_label_len) return error.LabelTooLong;
            total_len += label.len + 1;
            if (total_len > max_name_len + 1) return error.NameTooLong;
            label_count += 1;
        }
    }

    // Allocate and populate. errdefer unwinds a partial fill on dupe-OOM.
    const labels = try allocator.alloc([]const u8, label_count);
    errdefer allocator.free(labels);
    var i: usize = 0;
    errdefer for (labels[0..i]) |l| allocator.free(l);
    var iter = mem.splitScalar(u8, name_str, '.');
    while (iter.next()) |label| {
        labels[i] = try allocator.dupe(u8, label);
        i += 1;
    }

    return .{ .labels = labels };
}

/// Randomly flip the 0x20 (case) bit of ASCII letters in `name`'s labels.
/// `@constCast` is sound because `parseDottedName` `dupe`s each label, so
/// the underlying storage is mutable. RFC draft Vixie/Dagon.
pub fn applyCase0x20(io: std.Io, name: Name) void {
    var pool: u64 = 0;
    var bits_left: u8 = 0;
    for (name.labels) |label| {
        const bytes = @constCast(label);
        for (bytes) |*b| {
            if (!std.ascii.isAlphabetic(b.*)) continue;
            if (bits_left == 0) {
                var buf: [8]u8 = undefined;
                io.random(&buf);
                pool = mem.readInt(u64, &buf, .little);
                bits_left = 64;
            }
            if (pool & 1 == 1) b.* ^= 0x20;
            pool >>= 1;
            bits_left -= 1;
        }
    }
}

/// RFC 8467 §4.1 recommended block-size for DoT query padding.
pub const dot_padding_target: u16 = 468;

const EdnsConfig = struct {
    udp_payload_size: u16 = edns_udp_payload,
    do_bit: bool = false,
    /// If non-zero, add EDNS0 padding (option code 12, RFC 7830) to reach
    /// this total message size. See `dot_padding_target` for DoT.
    padding_target: u16 = 0,
};

const QueryOptions = struct {
    rd: bool = true,
    edns: ?EdnsConfig = null,
    /// RFC draft Vixie/Dagon "Use of Bit 0x20 in DNS Labels": when non-null,
    /// randomize ASCII letter case in QNAME using this RNG. Caller verifies
    /// the response echoes byte-for-byte.
    case_rng: ?std.Io = null,
};

pub fn buildQuery(allocator: Allocator, id: u16, name_str: []const u8, qtype: RType, options: QueryOptions) Error!Message {
    const name = try parseDottedName(allocator, name_str);
    if (options.case_rng) |io| applyCase0x20(io, name);
    const questions = try allocator.alloc(Question, 1);
    questions[0] = .{ .name = name, .qtype = qtype, .qclass = .in };

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
            .qd_count = 1,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = questions,
        .opt = if (options.edns) |edns| .{
            .udp_payload_size = edns.udp_payload_size,
            .extended_rcode = 0,
            .version = 0,
            .do_bit = edns.do_bit,
            .options = &.{},
            .padding_target = edns.padding_target,
        } else null,
    };
}

// ── Parser ─────────────────────────────────────────────────────────────

pub const Parser = struct {
    msg: []const u8,
    pos: usize,

    pub fn init(msg: []const u8) Parser {
        return .{ .msg = msg, .pos = 0 };
    }

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

    /// Parse a wire-format Name. Labels alias the wire buffer directly —
    /// the returned `Name.labels` outer slice is `allocator`-owned, but
    /// each `labels[i]` byte slice points into `self.msg`. Caller must
    /// keep the wire buffer alive for the lifetime of the parsed Name.
    pub fn parseName(self: *Parser, allocator: Allocator) Error!Name {
        // Collect on the stack and dupe once at the end — N ArrayList grow
        // allocs per name (4-5 typical) showed up at ~0.5% of CPU on miss.
        var labels_buf: [max_label_count][]const u8 = undefined;
        var labels_len: usize = 0;
        var total_len: usize = 0;
        var jumps: usize = 0;
        const max_jumps = 32;
        var cursor = self.pos;
        var saved_pos: ?usize = null;

        while (true) {
            if (cursor >= self.msg.len) return error.EndOfData;
            const len_byte = self.msg[cursor];

            if (len_byte == 0) {
                // End of name
                cursor += 1;
                if (saved_pos == null) self.pos = cursor;
                break;
            }

            const label_type = len_byte & 0xC0;
            if (label_type == 0xC0) {
                // Compression pointer
                if (cursor + 1 >= self.msg.len) return error.EndOfData;
                jumps += 1;
                if (jumps > max_jumps) return error.CompressionPointerLoop;
                if (saved_pos == null) saved_pos = cursor + 2;
                const offset = (@as(u16, len_byte & 0x3F) << 8) | @as(u16, self.msg[cursor + 1]);
                // RFC 1035 §4.1.4: pointers must reference prior occurrences
                if (offset >= cursor) return error.FormatError;
                cursor = offset;
            } else if (label_type == 0x00) {
                // Normal label
                const label_len: usize = len_byte;
                if (label_len > max_label_len) return error.LabelTooLong;
                if (labels_len >= max_label_count) return error.TooManyLabels;
                cursor += 1;
                if (cursor + label_len > self.msg.len) return error.EndOfData;
                labels_buf[labels_len] = self.msg[cursor..][0..label_len];
                labels_len += 1;
                cursor += label_len;
                total_len += label_len + 1; // +1 for the dot separator
                if (total_len > max_name_len + 1) return error.NameTooLong;
                if (saved_pos == null) self.pos = cursor;
            } else {
                return error.InvalidLabelType;
            }
        }

        if (saved_pos) |sp| self.pos = sp;

        const labels = try allocator.dupe([]const u8, labels_buf[0..labels_len]);
        return .{ .labels = labels };
    }

    pub fn parseQuestion(self: *Parser, allocator: Allocator) Error!Question {
        const name = try self.parseName(allocator);
        const qtype: RType = @fromBackingInt(@intCast(try self.readU16()));
        const qclass: RClass = @fromBackingInt(@intCast(try self.readU16()));
        return .{ .name = name, .qtype = qtype, .qclass = qclass };
    }

    pub fn parseResourceRecord(self: *Parser, allocator: Allocator) Error!ResourceRecord {
        const name = try self.parseName(allocator);
        // parseName's outer label slice is the only heap touched so far; on
        // any subsequent failure (header reads or parseRData OOM) we must
        // release it so non-arena callers don't leak. See freeWireParsedName.
        errdefer freeWireParsedName(allocator, name);
        const rtype: RType = @fromBackingInt(@intCast(try self.readU16()));
        const rclass: RClass = @fromBackingInt(@intCast(try self.readU16()));
        const ttl = try self.readU32();
        const rdlength: usize = try self.readU16();

        if (self.pos + rdlength > self.msg.len) return error.EndOfData;
        const rdata_end = self.pos + rdlength;

        const rdata = try self.parseRData(rtype, rdlength, allocator);
        self.pos = rdata_end;

        return .{
            .name = name,
            .rtype = rtype,
            .rclass = rclass,
            .ttl = ttl,
            .rdata = rdata,
        };
    }

    fn parseRData(self: *Parser, rtype: RType, rdlength: usize, allocator: Allocator) Error!RData {
        switch (rtype) {
            .a => {
                if (rdlength != 4) return error.InvalidRDataLength;
                const data = try self.readSlice(4);
                return .{ .a = data[0..4].* };
            },
            .aaaa => {
                if (rdlength != 16) return error.InvalidRDataLength;
                const data = try self.readSlice(16);
                return .{ .aaaa = data[0..16].* };
            },
            .ns => return .{ .ns = try self.parseNameRdata(allocator, rdlength) },
            .cname => return .{ .cname = try self.parseNameRdata(allocator, rdlength) },
            .ptr => return .{ .ptr = try self.parseNameRdata(allocator, rdlength) },
            .mx => {
                const rdata_end = self.pos + rdlength;
                const preference = try self.readU16();
                const exchange = try self.parseName(allocator);
                errdefer freeWireParsedName(allocator, exchange);
                if (self.pos != rdata_end) return error.FormatError;
                return .{ .mx = .{ .preference = preference, .exchange = exchange } };
            },
            .soa => {
                const rdata_end = self.pos + rdlength;
                const mname = try self.parseName(allocator);
                errdefer freeWireParsedName(allocator, mname);
                const rname = try self.parseName(allocator);
                errdefer freeWireParsedName(allocator, rname);
                const serial = try self.readU32();
                const refresh = try self.readU32();
                const retry = try self.readU32();
                const expire = try self.readU32();
                const minimum = try self.readU32();
                if (self.pos != rdata_end) return error.FormatError;
                return .{ .soa = .{
                    .mname = mname,
                    .rname = rname,
                    .serial = serial,
                    .refresh = refresh,
                    .retry = retry,
                    .expire = expire,
                    .minimum = minimum,
                } };
            },
            .txt => {
                const rdata_end = self.pos + rdlength;
                var strings: ArrayList([]const u8) = .empty;
                errdefer strings.deinit(allocator);
                while (self.pos < rdata_end) {
                    const str_len: usize = try self.readU8();
                    if (self.pos + str_len > rdata_end) return error.FormatError;
                    const str_data = try self.readSlice(str_len);
                    try strings.append(allocator, str_data);
                }
                return .{ .txt = .{
                    .strings = try strings.toOwnedSlice(allocator),
                } };
            },
            .rrsig => {
                if (rdlength < 18) return error.InvalidRDataLength;
                const type_covered: RType = @fromBackingInt(@intCast(try self.readU16()));
                const algorithm: DnssecAlgorithm = @fromBackingInt(@intCast(try self.readU8()));
                const label_count = try self.readU8();
                const original_ttl = try self.readU32();
                const sig_expiration = try self.readU32();
                const sig_inception = try self.readU32();
                const key_tag = try self.readU16();
                const name_start = self.pos;
                const signer_name = try self.parseName(allocator);
                errdefer freeWireParsedName(allocator, signer_name);
                const name_len = self.pos - name_start;
                if (18 + name_len > rdlength) return error.InvalidRDataLength;
                const sig_len = rdlength - 18 - name_len;
                const signature = try self.readSlice(sig_len);
                return .{ .rrsig = .{
                    .type_covered = type_covered,
                    .algorithm = algorithm,
                    .labels = label_count,
                    .original_ttl = original_ttl,
                    .sig_expiration = sig_expiration,
                    .sig_inception = sig_inception,
                    .key_tag = key_tag,
                    .signer_name = signer_name,
                    .signature = signature,
                } };
            },
            .dnskey => {
                if (rdlength < 4) return error.InvalidRDataLength;
                const flags = try self.readU16();
                const protocol = try self.readU8();
                const algorithm: DnssecAlgorithm = @fromBackingInt(@intCast(try self.readU8()));
                const public_key = try self.readSlice(rdlength - 4);
                return .{ .dnskey = .{
                    .flags = flags,
                    .protocol = protocol,
                    .algorithm = algorithm,
                    .public_key = public_key,
                } };
            },
            .ds => {
                if (rdlength < 4) return error.InvalidRDataLength;
                const key_tag = try self.readU16();
                const algorithm: DnssecAlgorithm = @fromBackingInt(@intCast(try self.readU8()));
                const digest_type: DigestType = @fromBackingInt(@intCast(try self.readU8()));
                const digest = try self.readSlice(rdlength - 4);
                return .{ .ds = .{
                    .key_tag = key_tag,
                    .algorithm = algorithm,
                    .digest_type = digest_type,
                    .digest = digest,
                } };
            },
            .nsec => {
                if (rdlength < 1) return error.InvalidRDataLength;
                const name_start = self.pos;
                const next_domain_name = try self.parseName(allocator);
                errdefer freeWireParsedName(allocator, next_domain_name);
                const name_len = self.pos - name_start;
                if (name_len > rdlength) return error.InvalidRDataLength;
                return .{ .nsec = .{
                    .next_domain_name = next_domain_name,
                    .type_bit_maps = try self.readSlice(rdlength - name_len),
                } };
            },
            .nsec3 => {
                if (rdlength < 6) return error.InvalidRDataLength;
                const hash_algorithm: Nsec3HashAlgorithm = @fromBackingInt(@intCast(try self.readU8()));
                const flags = try self.readU8();
                const iterations = try self.readU16();
                const salt_len: usize = try self.readU8();
                // Validate salt + hash_len byte fit within rdlength
                if (5 + salt_len + 1 > rdlength) return error.InvalidRDataLength;
                const salt = try self.readSlice(salt_len);
                const hash_len: usize = try self.readU8();
                const consumed = 6 + salt_len + hash_len;
                if (consumed > rdlength) return error.InvalidRDataLength;
                const next_hashed_owner = try self.readSlice(hash_len);
                const bitmap_len = rdlength - consumed;
                return .{ .nsec3 = .{
                    .hash_algorithm = hash_algorithm,
                    .flags = flags,
                    .iterations = iterations,
                    .salt = salt,
                    .next_hashed_owner = next_hashed_owner,
                    .type_bit_maps = try self.readSlice(bitmap_len),
                } };
            },
            .nsec3param => {
                if (rdlength < 5) return error.InvalidRDataLength;
                const hash_algorithm: Nsec3HashAlgorithm = @fromBackingInt(@intCast(try self.readU8()));
                const flags = try self.readU8();
                const iterations = try self.readU16();
                const salt_len: usize = try self.readU8();
                if (5 + salt_len > rdlength) return error.InvalidRDataLength;
                return .{ .nsec3param = .{
                    .hash_algorithm = hash_algorithm,
                    .flags = flags,
                    .iterations = iterations,
                    .salt = try self.readSlice(salt_len),
                } };
            },
            .opt, .any, .dname, _ => {
                const data = try self.readSlice(rdlength);
                return .{ .unknown = data };
            },
        }
    }

    /// Parse a single-name RDATA (NS, CNAME, PTR) with rdlength validation.
    fn parseNameRdata(self: *Parser, allocator: Allocator, rdlength: usize) Error!Name {
        const rdata_end = self.pos + rdlength;
        const name = try self.parseName(allocator);
        errdefer freeWireParsedName(allocator, name);
        if (self.pos != rdata_end) return error.FormatError;
        return name;
    }
};

// ── EDNS option parsing ────────────────────────────────────────────────

/// Advance past one wire-format name starting at `start`. Names are either
/// a chain of length-prefixed labels terminated by a zero byte, or a 2-byte
/// compression pointer (top two bits set). Returns the position one past
/// the name, or null if the wire is malformed.
fn skipWireName(wire: []const u8, start: usize) ?usize {
    var p = start;
    while (p < wire.len) {
        const b = wire[p];
        if (b == 0) return p + 1;
        if (b & 0xC0 == 0xC0) {
            if (p + 1 >= wire.len) return null;
            return p + 2;
        }
        if (b & 0xC0 != 0) return null; // reserved label types
        p += 1 + b;
    }
    return null;
}

/// Convert an RFC 7828 TIMEOUT (100-ms units) into whole seconds. Sub-second
/// non-zero values round up so a 100-ms hint doesn't evict the connection on
/// the same tick. TIMEOUT=0 ("close ASAP" per RFC 7828 §3.3) passes through
/// as 0; callers that pool a connection must clamp against weaponized 0
/// before applying — see `connection_pool.applyKeepaliveHint`.
pub fn keepaliveToSeconds(timeout_100ms: u16) i64 {
    return @divFloor(@as(i64, @intCast(timeout_100ms)) + 9, 10);
}

/// RFC 7828 §3.3: read the edns-tcp-keepalive TIMEOUT (option 11) advertised
/// in a TCP/DoT response. Returns the value in 100-ms units, or null if no
/// OPT record carries it. Cheap wire scan — does not allocate, does not
/// touch rdata bodies beyond OPT's option list.
pub fn extractKeepaliveTimeout(wire: []const u8) ?u16 {
    if (wire.len < header_len) return null;
    const ar = mem.readInt(u16, wire[10..][0..2], .big);
    if (ar == 0) return null;
    const qd = mem.readInt(u16, wire[4..][0..2], .big);
    const an = mem.readInt(u16, wire[6..][0..2], .big);
    const ns = mem.readInt(u16, wire[8..][0..2], .big);

    var pos: usize = header_len;
    for (0..qd) |_| {
        pos = skipWireName(wire, pos) orelse return null;
        if (pos + 4 > wire.len) return null;
        pos += 4;
    }
    const rr_no_opt = @as(usize, an) + @as(usize, ns);
    for (0..rr_no_opt) |_| {
        pos = skipWireName(wire, pos) orelse return null;
        if (pos + 10 > wire.len) return null;
        const rdlen = mem.readInt(u16, wire[pos + 8 ..][0..2], .big);
        pos += 10 + @as(usize, rdlen);
        if (pos > wire.len) return null;
    }
    for (0..ar) |_| {
        const name_start = pos;
        pos = skipWireName(wire, pos) orelse return null;
        if (pos + 10 > wire.len) return null;
        const rtype = mem.readInt(u16, wire[pos..][0..2], .big);
        const rdlen = mem.readInt(u16, wire[pos + 8 ..][0..2], .big);
        if (pos + 10 + @as(usize, rdlen) > wire.len) return null;
        if (rtype == @backingInt(RType.opt)) {
            // RFC 6891 §6.1.2: OPT owner MUST be root (single zero byte).
            if (wire[name_start] != 0) return null;
            const opt_rdata = wire[pos + 10 .. pos + 10 + rdlen];
            var op: usize = 0;
            while (op + 4 <= opt_rdata.len) {
                const code = mem.readInt(u16, opt_rdata[op..][0..2], .big);
                const length = mem.readInt(u16, opt_rdata[op + 2 ..][0..2], .big);
                op += 4;
                if (op + length > opt_rdata.len) return null;
                if (code == edns_opt_tcp_keepalive) {
                    // RFC 7828 §3.2: 0 octets is the client form; the
                    // server-to-client TIMEOUT form is always 2 octets.
                    if (length == 2) return mem.readInt(u16, opt_rdata[op..][0..2], .big);
                    return null;
                }
                op += length;
            }
            return null;
        }
        pos += 10 + @as(usize, rdlen);
    }
    return null;
}

fn parseEdnsOptions(allocator: Allocator, rdata: []const u8) Error![]const EdnsOption {
    if (rdata.len == 0) return &.{};

    var options: ArrayList(EdnsOption) = .empty;
    errdefer options.deinit(allocator);
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

// ── Top-level parse ────────────────────────────────────────────────────

/// Free a slice of wire-parsed RRs and its backing (error-path cleanup
/// for `parseRRSection` results; success paths hand off to the Message).
fn freeWireParsedRRSlice(allocator: Allocator, rrs: []const ResourceRecord) void {
    for (rrs) |rr| freeWireParsedRR(allocator, rr);
    allocator.free(rrs);
}

/// Parse `count` questions into an owned slice. On error, everything
/// parsed so far (including backing) is freed.
fn parseQuestionSection(allocator: Allocator, parser: *Parser, count: u16, max_questions: usize) Error![]Question {
    var list: ArrayList(Question) = .empty;
    try list.ensureTotalCapacity(allocator, @min(count, max_questions));
    errdefer {
        for (list.items) |q| freeWireParsedName(allocator, q.name);
        list.deinit(allocator);
    }
    for (0..count) |_| {
        const q = try parser.parseQuestion(allocator);
        list.append(allocator, q) catch {
            freeWireParsedName(allocator, q.name);
            return error.OutOfMemory;
        };
    }
    return try list.toOwnedSlice(allocator);
}

/// Parse `count` resource records into an owned slice. On error,
/// everything parsed so far (including backing) is freed; a previously
/// written `opt_out.*` is the caller's errdefer to release.
///
/// `opt_out` non-null marks the additional section: OPT records are
/// extracted into it (RFC 6891) instead of appended. Null (answer /
/// authority) keeps any OPT as an ordinary record — question-section
/// placement rules don't apply there.
fn parseRRSection(allocator: Allocator, parser: *Parser, count: u16, max_rrs: usize, opt_out: ?*?OptRecord) Error![]ResourceRecord {
    var list: ArrayList(ResourceRecord) = .empty;
    try list.ensureTotalCapacity(allocator, @min(count, max_rrs));
    errdefer {
        for (list.items) |rr| freeWireParsedRR(allocator, rr);
        list.deinit(allocator);
    }
    for (0..count) |_| {
        const rr = try parser.parseResourceRecord(allocator);
        if (opt_out) |opt| if (rr.rtype == .opt) {
            // RFC 6891 §6.1.1: a query with more than one OPT MUST get FORMERR.
            if (opt.* != null) {
                freeWireParsedRR(allocator, rr);
                return error.MultipleOptRecords;
            }
            // RFC 6891 §6.1.2: OPT owner name MUST be root ("."). Non-root
            // OPT is malformed; treat as FormatError so the server replies
            // FORMERR rather than silently absorbing whatever owner appears.
            if (rr.name.labels.len != 0) {
                freeWireParsedRR(allocator, rr);
                return error.FormatError;
            }
            // Parse options into a local first; assigning into the optional
            // `opt` before this point would let Zig write the tag (Some) with
            // the payload still undefined — the caller's opt errdefer would
            // then dereference garbage on a later failure.
            const opt_options = parseEdnsOptions(allocator, rr.rdata.unknown) catch |err| {
                freeWireParsedRR(allocator, rr);
                return err;
            };
            opt.* = .{
                .udp_payload_size = @backingInt(rr.rclass),
                .extended_rcode = @intCast(rr.ttl >> 24),
                .version = @intCast((rr.ttl >> 16) & 0xFF),
                .do_bit = (rr.ttl & 0x8000) != 0,
                .options = opt_options,
            };
            // OPT rr's name (root) and rdata (.unknown alias) carry no heap;
            // freeing the wire-parsed OPT rr is a no-op since rr.name.labels.len == 0.
            continue;
        };
        list.append(allocator, rr) catch {
            freeWireParsedRR(allocator, rr);
            return error.OutOfMemory;
        };
    }
    return try list.toOwnedSlice(allocator);
}

/// Parse a DNS wire message.
///
/// Lifetime contract: parsed `Name.labels[i]` byte slices and rdata byte
/// slices (RRSIG signature, DNSKEY public_key, DS digest, NSEC bitmap,
/// NSEC3 salt/hash/bitmap, NSEC3PARAM salt, unknown, EDNS option data)
/// alias `bytes` — the wire buffer. Caller must keep `bytes` alive for
/// the lifetime of the returned Message.
///
/// `allocator` must be an arena on success: the returned Message's
/// aliased slices point into `bytes`, so `freeMessage` is only sound
/// when `allocator.free` is a no-op. On error, per-item cleanup is
/// skipped for the same reason — only ArrayList backing buffers are
/// deinit'd, which is safe under any allocator. Production uses a
/// per-query arena; tests wrap `testing.allocator` in an `ArenaAllocator`
/// for successful-parse paths.
pub fn parseMessage(allocator: Allocator, bytes: []const u8) Error!Message {
    if (bytes.len < header_len) return error.EndOfData;

    const hdr = Header.parse(bytes[0..12]);
    var parser = Parser{ .msg = bytes, .pos = 12 };

    // Cap pre-allocation against what the wire can physically contain.
    // Prevents a small packet with inflated header counts from triggering
    // a large allocation (counts are attacker-controlled u16, max 65535).
    const payload = bytes.len - header_len;
    const max_questions = payload / 5; // min question: 1 name + 2 type + 2 class
    const max_rrs = payload / 11; // min RR: 1 name + 2 type + 2 class + 4 TTL + 2 rdlength

    // Each section arrives as a completed owned slice before the next
    // parses, so error cleanup is one errdefer per section — no partial
    // ArrayList/toOwnedSlice interleaving to reason about.
    const questions = try parseQuestionSection(allocator, &parser, hdr.qd_count, max_questions);
    errdefer {
        for (questions) |q| freeWireParsedName(allocator, q.name);
        allocator.free(questions);
    }
    const answers = try parseRRSection(allocator, &parser, hdr.an_count, max_rrs, null);
    errdefer freeWireParsedRRSlice(allocator, answers);
    const authorities = try parseRRSection(allocator, &parser, hdr.ns_count, max_rrs, null);
    errdefer freeWireParsedRRSlice(allocator, authorities);
    var opt: ?OptRecord = null;
    errdefer if (opt) |o| if (o.options.len > 0) allocator.free(o.options);
    const additionals = try parseRRSection(allocator, &parser, hdr.ar_count, max_rrs, &opt);

    return .{
        .header = hdr,
        .questions = questions,
        .answers = answers,
        .authorities = authorities,
        .additionals = additionals,
        .opt = opt,
    };
}

// ── Serializer ─────────────────────────────────────────────────────────

fn castOrRDataErr(comptime T: type, val: anytype) Error!T {
    return std.math.cast(T, val) orelse error.InvalidRDataLength;
}

pub const Serializer = struct {
    buf: []u8,
    pos: usize,

    pub fn init(buf: []u8) Serializer {
        return .{ .buf = buf, .pos = 0 };
    }

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

    pub fn writeHeader(self: *Serializer, hdr: Header) Error!void {
        try self.ensureSpace(12);
        hdr.serialize(self.buf[self.pos..][0..12]);
        self.pos += 12;
    }

    pub fn writeName(self: *Serializer, name: Name) Error!void {
        for (name.labels) |label| {
            if (label.len > max_label_len) return error.LabelTooLong;
            try self.writeU8(@intCast(label.len));
            try self.writeSlice(label);
        }
        try self.writeU8(0); // Root label terminator
    }

    pub fn writeQuestion(self: *Serializer, q: Question) Error!void {
        try self.writeName(q.name);
        try self.writeU16(@backingInt(q.qtype));
        try self.writeU16(@backingInt(q.qclass));
    }

    pub fn writeResourceRecord(self: *Serializer, rr: ResourceRecord) Error!void {
        if (rr.wire) |blob| {
            const start = self.pos;
            try self.writeSlice(blob);
            mem.writeInt(u32, self.buf[start + rr.wire_ttl_offset ..][0..4], rr.ttl, .big);
            return;
        }
        _ = try self.writeRecordFields(rr);
    }

    /// Ignores `rr.wire`. Returns the TTL byte offset for later patching.
    fn writeRecordFields(self: *Serializer, rr: ResourceRecord) Error!u16 {
        try self.writeName(rr.name);
        try self.writeU16(@backingInt(rr.rtype));
        try self.writeU16(@backingInt(rr.rclass));
        const ttl_offset: u16 = try castOrRDataErr(u16, self.pos);
        try self.writeU32(rr.ttl);

        const rdlength_pos = self.pos;
        try self.writeU16(0); // placeholder
        const rdata_start = self.pos;
        try self.writeRData(rr.rdata);
        const rdata_len = self.pos - rdata_start;
        mem.writeInt(u16, self.buf[rdlength_pos..][0..2], try castOrRDataErr(u16, rdata_len), .big);
        return ttl_offset;
    }

    pub fn writeRData(self: *Serializer, rdata: RData) Error!void {
        switch (rdata) {
            .a => |addr| try self.writeSlice(&addr),
            .aaaa => |addr| try self.writeSlice(&addr),
            .ns, .cname, .ptr => |name| try self.writeName(name),
            .mx => |mx| {
                try self.writeU16(mx.preference);
                try self.writeName(mx.exchange);
            },
            .soa => |soa| {
                try self.writeName(soa.mname);
                try self.writeName(soa.rname);
                try self.writeU32(soa.serial);
                try self.writeU32(soa.refresh);
                try self.writeU32(soa.retry);
                try self.writeU32(soa.expire);
                try self.writeU32(soa.minimum);
            },
            .txt => |txt| {
                for (txt.strings) |s| {
                    try self.writeU8(try castOrRDataErr(u8, s.len));
                    try self.writeSlice(s);
                }
            },
            .rrsig => |rrsig| {
                try self.writeU16(@backingInt(rrsig.type_covered));
                try self.writeU8(@backingInt(rrsig.algorithm));
                try self.writeU8(rrsig.labels);
                try self.writeU32(rrsig.original_ttl);
                try self.writeU32(rrsig.sig_expiration);
                try self.writeU32(rrsig.sig_inception);
                try self.writeU16(rrsig.key_tag);
                try self.writeName(rrsig.signer_name);
                try self.writeSlice(rrsig.signature);
            },
            .dnskey => |dnskey| {
                try self.writeU16(dnskey.flags);
                try self.writeU8(dnskey.protocol);
                try self.writeU8(@backingInt(dnskey.algorithm));
                try self.writeSlice(dnskey.public_key);
            },
            .ds => |ds_data| {
                try self.writeU16(ds_data.key_tag);
                try self.writeU8(@backingInt(ds_data.algorithm));
                try self.writeU8(@backingInt(ds_data.digest_type));
                try self.writeSlice(ds_data.digest);
            },
            .nsec => |nsec_data| {
                try self.writeName(nsec_data.next_domain_name);
                try self.writeSlice(nsec_data.type_bit_maps);
            },
            .nsec3 => |nsec3| {
                try self.writeU8(@backingInt(nsec3.hash_algorithm));
                try self.writeU8(nsec3.flags);
                try self.writeU16(nsec3.iterations);
                try self.writeU8(try castOrRDataErr(u8, nsec3.salt.len));
                try self.writeSlice(nsec3.salt);
                try self.writeU8(try castOrRDataErr(u8, nsec3.next_hashed_owner.len));
                try self.writeSlice(nsec3.next_hashed_owner);
                try self.writeSlice(nsec3.type_bit_maps);
            },
            .nsec3param => |nsec3p| {
                try self.writeU8(@backingInt(nsec3p.hash_algorithm));
                try self.writeU8(nsec3p.flags);
                try self.writeU16(nsec3p.iterations);
                try self.writeU8(try castOrRDataErr(u8, nsec3p.salt.len));
                try self.writeSlice(nsec3p.salt);
            },
            .unknown => |data| try self.writeSlice(data),
        }
    }
};

/// Overwrite the 2-byte query id in a serialized DNS message. Used by
/// failover/staggered paths that build and serialize once, then rotate
/// per-attempt query-id entropy (RFC 5452 §9.1).
pub fn patchQueryId(wire: []u8, id: u16) void {
    std.debug.assert(wire.len >= 2);
    std.mem.writeInt(u16, wire[0..2], id, .big);
}

pub const BuiltRR = struct {
    bytes: []const u8,
    ttl_offset: u16,
};

pub fn buildResourceRecordWire(buf: []u8, rr: ResourceRecord) Error!BuiltRR {
    var ser = Serializer.init(buf);
    const ttl_offset = try ser.writeRecordFields(rr);
    return .{ .bytes = ser.buf[0..ser.pos], .ttl_offset = ttl_offset };
}

pub fn serializeMessage(buf: []u8, msg: Message) Error![]const u8 {
    var ser = Serializer.init(buf);

    // Write header with adjusted ar_count for OPT
    var hdr = msg.header;
    if (msg.opt != null) hdr.ar_count += 1;
    try ser.writeHeader(hdr);

    for (msg.questions) |q| try ser.writeQuestion(q);
    for (msg.answers) |rr| try ser.writeResourceRecord(rr);
    for (msg.authorities) |rr| try ser.writeResourceRecord(rr);
    for (msg.additionals) |rr| try ser.writeResourceRecord(rr);

    // Append OPT pseudo-record
    if (msg.opt) |opt| {
        try ser.writeU8(0); // root name
        try ser.writeU16(41); // type OPT
        try ser.writeU16(opt.udp_payload_size); // class = UDP payload size
        // TTL = extended_rcode(8) | version(8) | DO(1) | Z(15)
        const ttl: u32 = (@as(u32, opt.extended_rcode) << 24) |
            (@as(u32, opt.version) << 16) |
            (@as(u32, @intFromBool(opt.do_bit)) << 15);
        try ser.writeU32(ttl);

        // Compute RDLENGTH: existing options + optional padding
        var rdlength: u16 = 0;
        for (opt.options) |o| rdlength += 4 + (try castOrRDataErr(u16, o.data.len));

        // EDNS0 padding (RFC 7830, option code 12): pad total message to padding_target
        var padding_len: u16 = 0;
        if (opt.padding_target > 0) {
            // ser.pos already includes name(1) + type(2) + class(2) + ttl(4) = 9
            // bytes of OPT. Only the rdlength (2) and the padding option header
            // (4) remain unwritten, so the predicted final size is ser.pos + 6
            // + rdlength + padding_len.
            const msg_size_before_padding = ser.pos + 2 + rdlength + 4;
            if (opt.padding_target > msg_size_before_padding) {
                padding_len = @intCast(opt.padding_target - msg_size_before_padding);
            }
            rdlength += 4 + padding_len; // code(2) + length(2) + padding data
        }

        try ser.writeU16(rdlength);
        for (opt.options) |o| {
            try ser.writeU16(o.code);
            try ser.writeU16(@intCast(o.data.len));
            try ser.writeSlice(o.data);
        }

        // Write padding option if needed
        if (opt.padding_target > 0) {
            try ser.writeU16(edns_opt_padding);
            try ser.writeU16(padding_len);
            // Write zero-filled padding
            try ser.ensureSpace(padding_len);
            @memset(ser.buf[ser.pos..][0..padding_len], 0);
            ser.pos += padding_len;
        }
    }

    return buf[0..ser.pos];
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

test "header roundtrip" {
    const original = Header{
        .id = 0xABCD,
        .flags = .{
            .qr = true,
            .opcode = .query,
            .aa = true,
            .tc = false,
            .rd = true,
            .ra = true,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = .no_error,
        },
        .qd_count = 1,
        .an_count = 2,
        .ns_count = 0,
        .ar_count = 1,
    };

    var buf: [12]u8 = undefined;
    original.serialize(&buf);
    const parsed = Header.parse(&buf);

    try testing.expectEqual(original.id, parsed.id);
    try testing.expectEqual(original.flags, parsed.flags);
    try testing.expectEqual(original.qd_count, parsed.qd_count);
    try testing.expectEqual(original.an_count, parsed.an_count);
    try testing.expectEqual(original.ns_count, parsed.ns_count);
    try testing.expectEqual(original.ar_count, parsed.ar_count);

    // Re-serialize and compare bytes
    var buf2: [12]u8 = undefined;
    parsed.serialize(&buf2);
    try testing.expectEqualSlices(u8, &buf, &buf2);
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

test "name parsing - uncompressed" {
    // "example.com" = \x07example\x03com\x00
    const data = "\x07example\x03com\x00";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var parser = Parser{ .msg = data, .pos = 0 };
    const name = try parser.parseName(arena.allocator());

    try testing.expectEqual(@as(usize, 2), name.labels.len);
    try testing.expectEqualStrings("example", name.labels[0]);
    try testing.expectEqualStrings("com", name.labels[1]);
    try testing.expectEqual(data.len, parser.pos);
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
    const name = try parser.parseName(arena.allocator());

    try testing.expectEqual(@as(usize, 3), name.labels.len);
    try testing.expectEqualStrings("foo", name.labels[0]);
    try testing.expectEqualStrings("example", name.labels[1]);
    try testing.expectEqualStrings("com", name.labels[2]);
    // pos should advance past the pointer (13 + 3+1 + 2 = 19)
    try testing.expectEqual(@as(usize, 19), parser.pos);
}

test "name parsing - forward pointer rejection" {
    // Forward pointer at position 0 pointing to offset 2 — rejected per RFC 1035 §4.1.4
    const data = [_]u8{ 0xC0, 0x02, 0xC0, 0x00 };
    var parser = Parser{ .msg = &data, .pos = 0 };
    try testing.expectError(error.FormatError, parser.parseName(testing.allocator));
}

test "name parsing - self pointer rejection" {
    // Self-pointer: offset == cursor, rejected as non-backward
    const data = [_]u8{ 0xC0, 0x00 };
    var parser = Parser{ .msg = &data, .pos = 0 };
    try testing.expectError(error.FormatError, parser.parseName(testing.allocator));
}

test "full query packet parse" {
    // A DNS query for "example.com" type A class IN
    var pkt: [max_udp_payload]u8 = undefined;
    // Header: id=0x0001, RD=1, qdcount=1
    mem.writeInt(u16, pkt[0..2], 0x0001, .big);
    mem.writeInt(u16, pkt[2..4], 0x0100, .big); // RD=1
    mem.writeInt(u16, pkt[4..6], 1, .big); // qdcount
    mem.writeInt(u16, pkt[6..8], 0, .big);
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);
    // Question: example.com A IN
    const qname = "\x07example\x03com\x00";
    @memcpy(pkt[12..][0..qname.len], qname);
    var pos: usize = 12 + qname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // A
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

    try testing.expectEqual(@as(u16, 0x0001), msg.header.id);
    try testing.expect(msg.header.flags.rd);
    try testing.expectEqual(@as(usize, 1), msg.questions.len);
    try testing.expectEqualStrings("example", msg.questions[0].name.labels[0]);
    try testing.expectEqualStrings("com", msg.questions[0].name.labels[1]);
    try testing.expectEqual(RType.a, msg.questions[0].qtype);
    try testing.expectEqual(RClass.in, msg.questions[0].qclass);
}

test "response with A records" {
    // Build a response with 1 question + 1 A answer
    var pkt: [max_udp_payload]u8 = undefined;
    // Header: id=0x1234, QR=1, RD=1, RA=1, qdcount=1, ancount=1
    mem.writeInt(u16, pkt[0..2], 0x1234, .big);
    mem.writeInt(u16, pkt[2..4], 0x8180, .big);
    mem.writeInt(u16, pkt[4..6], 1, .big);
    mem.writeInt(u16, pkt[6..8], 1, .big);
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);

    // Question
    const qname = "\x07example\x03com\x00";
    @memcpy(pkt[12..][0..qname.len], qname);
    var pos: usize = 12 + qname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // A
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;

    // Answer: example.com (via pointer to offset 12), A, IN, TTL=300, 93.184.216.34
    pkt[pos] = 0xC0;
    pkt[pos + 1] = 0x0C; // pointer to offset 12
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // A
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 300, .big); // TTL
    pos += 4;
    mem.writeInt(u16, pkt[pos..][0..2], 4, .big); // rdlength
    pos += 2;
    pkt[pos] = 93;
    pkt[pos + 1] = 184;
    pkt[pos + 2] = 216;
    pkt[pos + 3] = 34;
    pos += 4;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const rr = msg.answers[0];
    try testing.expectEqual(RType.a, rr.rtype);
    try testing.expectEqual(@as(u32, 300), rr.ttl);
    try testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &rr.rdata.a);
}

test "SOA record parsing" {
    var pkt: [max_udp_payload]u8 = undefined;
    // Header: ancount=1
    mem.writeInt(u16, pkt[0..2], 0x0001, .big);
    mem.writeInt(u16, pkt[2..4], 0x8000, .big); // QR=1
    mem.writeInt(u16, pkt[4..6], 0, .big);
    mem.writeInt(u16, pkt[6..8], 1, .big); // 1 answer
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);

    var pos: usize = 12;
    // RR name: example.com
    const rrname = "\x07example\x03com\x00";
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 6, .big); // SOA
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 3600, .big); // TTL
    pos += 4;

    // Build rdata
    const mname = "\x02ns\x07example\x03com\x00";
    const rname_data = "\x05admin\x07example\x03com\x00";
    const rdlen = mname.len + rname_data.len + 20; // 5 x u32
    mem.writeInt(u16, pkt[pos..][0..2], @intCast(rdlen), .big);
    pos += 2;
    @memcpy(pkt[pos..][0..mname.len], mname);
    pos += mname.len;
    @memcpy(pkt[pos..][0..rname_data.len], rname_data);
    pos += rname_data.len;
    mem.writeInt(u32, pkt[pos..][0..4], 2023010101, .big); // serial
    pos += 4;
    mem.writeInt(u32, pkt[pos..][0..4], 3600, .big); // refresh
    pos += 4;
    mem.writeInt(u32, pkt[pos..][0..4], 900, .big); // retry
    pos += 4;
    mem.writeInt(u32, pkt[pos..][0..4], 604800, .big); // expire
    pos += 4;
    mem.writeInt(u32, pkt[pos..][0..4], 86400, .big); // minimum
    pos += 4;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const soa = msg.answers[0].rdata.soa;
    try testing.expectEqualStrings("ns", soa.mname.labels[0]);
    try testing.expectEqualStrings("admin", soa.rname.labels[0]);
    try testing.expectEqual(@as(u32, 2023010101), soa.serial);
    try testing.expectEqual(@as(u32, 3600), soa.refresh);
    try testing.expectEqual(@as(u32, 900), soa.retry);
    try testing.expectEqual(@as(u32, 604800), soa.expire);
    try testing.expectEqual(@as(u32, 86400), soa.minimum);
}

test "MX record parsing" {
    var pkt: [max_udp_payload]u8 = undefined;
    mem.writeInt(u16, pkt[0..2], 0x0001, .big);
    mem.writeInt(u16, pkt[2..4], 0x8000, .big);
    mem.writeInt(u16, pkt[4..6], 0, .big);
    mem.writeInt(u16, pkt[6..8], 1, .big);
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);

    var pos: usize = 12;
    const rrname = "\x07example\x03com\x00";
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 15, .big); // MX
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 300, .big);
    pos += 4;

    const exchange = "\x04mail\x07example\x03com\x00";
    mem.writeInt(u16, pkt[pos..][0..2], @intCast(2 + exchange.len), .big); // rdlength
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 10, .big); // preference
    pos += 2;
    @memcpy(pkt[pos..][0..exchange.len], exchange);
    pos += exchange.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

    const mx = msg.answers[0].rdata.mx;
    try testing.expectEqual(@as(u16, 10), mx.preference);
    try testing.expectEqualStrings("mail", mx.exchange.labels[0]);
}

test "TXT record parsing" {
    var pkt: [max_udp_payload]u8 = undefined;
    mem.writeInt(u16, pkt[0..2], 0x0001, .big);
    mem.writeInt(u16, pkt[2..4], 0x8000, .big);
    mem.writeInt(u16, pkt[4..6], 0, .big);
    mem.writeInt(u16, pkt[6..8], 1, .big);
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);

    var pos: usize = 12;
    const rrname = "\x07example\x03com\x00";
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 16, .big); // TXT
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 300, .big);
    pos += 4;

    const txt1 = "v=spf1 include:example.com";
    const txt2 = "hello";
    const rdlen = 1 + txt1.len + 1 + txt2.len;
    mem.writeInt(u16, pkt[pos..][0..2], @intCast(rdlen), .big);
    pos += 2;
    pkt[pos] = @intCast(txt1.len);
    pos += 1;
    @memcpy(pkt[pos..][0..txt1.len], txt1);
    pos += txt1.len;
    pkt[pos] = @intCast(txt2.len);
    pos += 1;
    @memcpy(pkt[pos..][0..txt2.len], txt2);
    pos += txt2.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

    const txt = msg.answers[0].rdata.txt;
    try testing.expectEqual(@as(usize, 2), txt.strings.len);
    try testing.expectEqualStrings("v=spf1 include:example.com", txt.strings[0]);
    try testing.expectEqualStrings("hello", txt.strings[1]);
}

test "roundtrip: parse -> serialize -> parse -> compare" {
    // Build a query packet
    var original_pkt: [max_udp_payload]u8 = undefined;
    mem.writeInt(u16, original_pkt[0..2], 0xABCD, .big);
    mem.writeInt(u16, original_pkt[2..4], 0x0100, .big); // RD=1
    mem.writeInt(u16, original_pkt[4..6], 1, .big);
    mem.writeInt(u16, original_pkt[6..8], 1, .big);
    mem.writeInt(u16, original_pkt[8..10], 0, .big);
    mem.writeInt(u16, original_pkt[10..12], 0, .big);

    var pos: usize = 12;
    const qname = "\x07example\x03com\x00";
    @memcpy(original_pkt[pos..][0..qname.len], qname);
    pos += qname.len;
    mem.writeInt(u16, original_pkt[pos..][0..2], 1, .big); // A
    pos += 2;
    mem.writeInt(u16, original_pkt[pos..][0..2], 1, .big); // IN
    pos += 2;

    // Answer: A record (no compression for roundtrip test)
    const aname = "\x07example\x03com\x00";
    @memcpy(original_pkt[pos..][0..aname.len], aname);
    pos += aname.len;
    mem.writeInt(u16, original_pkt[pos..][0..2], 1, .big); // A
    pos += 2;
    mem.writeInt(u16, original_pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, original_pkt[pos..][0..4], 300, .big);
    pos += 4;
    mem.writeInt(u16, original_pkt[pos..][0..2], 4, .big);
    pos += 2;
    original_pkt[pos] = 1;
    original_pkt[pos + 1] = 2;
    original_pkt[pos + 2] = 3;
    original_pkt[pos + 3] = 4;
    pos += 4;

    // Parse
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg1 = try parseMessage(arena.allocator(), original_pkt[0..pos]);

    // Serialize
    var ser_buf: [max_udp_payload]u8 = undefined;
    const serialized = try serializeMessage(&ser_buf, msg1);

    // Parse again
    const msg2 = try parseMessage(arena.allocator(), serialized);

    // Compare
    try testing.expectEqual(msg1.header.id, msg2.header.id);
    try testing.expectEqual(msg1.header.flags.rd, msg2.header.flags.rd);
    try testing.expectEqual(msg1.questions.len, msg2.questions.len);
    try testing.expectEqual(msg1.answers.len, msg2.answers.len);
    try testing.expect(msg1.questions[0].name.eql(msg2.questions[0].name));
    try testing.expect(msg1.answers[0].name.eql(msg2.answers[0].name));
    try testing.expectEqualSlices(u8, &msg1.answers[0].rdata.a, &msg2.answers[0].rdata.a);
}

test "writeResourceRecord fast-path matches field path with TTL patch" {
    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try parseDottedName(a, "example.com");
    const base = ResourceRecord{ .name = name, .rtype = .a, .rclass = .in, .ttl = 500, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    // Pre-build the wire blob (stored in cache with placeholder TTL 500).
    var stage: [128]u8 = undefined;
    const built = try buildResourceRecordWire(&stage, base);

    // Slow path with remaining TTL = 100.
    var slow: [128]u8 = undefined;
    var ser_slow = Serializer.init(&slow);
    try ser_slow.writeResourceRecord(.{ .name = name, .rtype = .a, .rclass = .in, .ttl = 100, .rdata = .{ .a = .{ 1, 2, 3, 4 } } });

    // Fast path: same RR but wire blob carries TTL=500, rr.ttl=100 triggers a patch.
    var fast: [128]u8 = undefined;
    var ser_fast = Serializer.init(&fast);
    try ser_fast.writeResourceRecord(.{
        .name = name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 100,
        .rdata = .{ .a = .{ 1, 2, 3, 4 } },
        .wire = built.bytes,
        .wire_ttl_offset = built.ttl_offset,
    });

    try testing.expectEqualSlices(u8, slow[0..ser_slow.pos], fast[0..ser_fast.pos]);
}

test "edge case: empty message (too short)" {
    try testing.expectError(error.EndOfData, parseMessage(testing.allocator, ""));
    try testing.expectError(error.EndOfData, parseMessage(testing.allocator, &@as([11]u8, @splat(0))));
}

test "edge case: truncated question" {
    var pkt: [14]u8 = undefined;
    mem.writeInt(u16, pkt[0..2], 1, .big);
    mem.writeInt(u16, pkt[2..4], 0, .big);
    mem.writeInt(u16, pkt[4..6], 1, .big); // qdcount=1
    mem.writeInt(u16, pkt[6..8], 0, .big);
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);
    pkt[12] = 0x03; // label length 3
    pkt[13] = 'a'; // but only 1 byte of data

    try testing.expectError(error.EndOfData, parseMessage(testing.allocator, &pkt));
}

test "hasTcBit detects truncation on mid-record truncated response" {
    // Regression: a TC=1 UDP response truncated mid-record causes parseMessage
    // to fail with EndOfData. hasTcBit must detect TC on the raw wire data so
    // the resolver can fall back to TCP before attempting to parse.

    // Build a response with qdcount=1, ancount=1, TC=1, but truncate the
    // answer record mid-way so parseMessage cannot succeed.
    var pkt: [32]u8 = undefined;
    mem.writeInt(u16, pkt[0..2], 0x1234, .big); // id
    mem.writeInt(u16, pkt[2..4], 0x8200, .big); // QR=1, TC=1
    mem.writeInt(u16, pkt[4..6], 1, .big); // qdcount=1
    mem.writeInt(u16, pkt[6..8], 1, .big); // ancount=1
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);

    // Question: \x07example\x03com\x00, type A, class IN
    const qname = "\x07example\x03com\x00";
    @memcpy(pkt[12..][0..qname.len], qname);
    const qend = 12 + qname.len;
    mem.writeInt(u16, pkt[qend..][0..2], 1, .big); // qtype=A
    mem.writeInt(u16, pkt[qend + 2 ..][0..2], 1, .big); // qclass=IN

    // Answer record starts but is truncated — only 2 bytes of a name pointer
    const ans_start = qend + 4;
    pkt[ans_start] = 0xC0; // compressed name pointer...
    pkt[ans_start + 1] = 0x0C; // ...to offset 12

    // Slice to just past the pointer — no type/class/ttl/rdlength/rdata
    const truncated = pkt[0 .. ans_start + 2];

    // hasTcBit works on the truncated wire data
    try testing.expect(hasTcBit(truncated));

    // parseMessage fails — this is the bug we're guarding against.
    // Use an arena because parseMessage leaks partial allocations on error.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.EndOfData, parseMessage(arena.allocator(), truncated));

    // Without TC bit, hasTcBit returns false
    mem.writeInt(u16, pkt[2..4], 0x8000, .big); // QR=1, TC=0
    try testing.expect(!hasTcBit(truncated));

    // Too short for header → false
    try testing.expect(!hasTcBit(pkt[0..4]));
    try testing.expect(!hasTcBit(&[_]u8{}));
}

test "edge case: max-length label" {
    var pkt: [max_udp_payload]u8 = undefined;
    mem.writeInt(u16, pkt[0..2], 1, .big);
    mem.writeInt(u16, pkt[2..4], 0, .big);
    mem.writeInt(u16, pkt[4..6], 1, .big);
    mem.writeInt(u16, pkt[6..8], 0, .big);
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);

    // 63-byte label (max allowed)
    pkt[12] = 63;
    @memset(pkt[13..][0..63], 'a');
    pkt[76] = 0; // root
    mem.writeInt(u16, pkt[77..79], 1, .big); // A
    mem.writeInt(u16, pkt[79..81], 1, .big); // IN

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..81]);

    try testing.expectEqual(@as(usize, 1), msg.questions.len);
    try testing.expectEqual(@as(usize, 63), msg.questions[0].name.labels[0].len);
}

test "edge case: oversized label" {
    var pkt: [max_udp_payload]u8 = undefined;
    mem.writeInt(u16, pkt[0..2], 1, .big);
    mem.writeInt(u16, pkt[2..4], 0, .big);
    mem.writeInt(u16, pkt[4..6], 1, .big);
    mem.writeInt(u16, pkt[6..8], 0, .big);
    mem.writeInt(u16, pkt[8..10], 0, .big);
    mem.writeInt(u16, pkt[10..12], 0, .big);

    // 64-byte label (exceeds max)
    pkt[12] = 64;
    @memset(pkt[13..][0..64], 'a');

    // 64 = 0x40, top 2 bits = 01 → invalid label type per RFC 1035
    try testing.expectError(error.InvalidLabelType, parseMessage(testing.allocator, pkt[0..78]));
}

test "fuzz: random bytes must not panic" {
    const Context = struct {
        fn testOne(context: @This(), smith: *testing.Smith) anyerror!void {
            _ = context;
            var buf: [4096]u8 = undefined;
            const len = smith.slice(&buf);
            const input = buf[0..len];
            // parseMessage should either return a valid result or an error, never panic
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            if (parseMessage(arena.allocator(), input)) |_| {} else |_| {
                // Any error is fine — just must not panic
            }
        }
    };
    try testing.fuzz(Context{}, Context.testOne, .{});
}

test "EDNS0 roundtrip: build query with EDNS, serialize, parse, verify opt" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const msg = try buildQuery(alloc, 0x1234, "example.com", .a, .{ .rd = true, .edns = .{ .do_bit = true } });

    // Verify opt was set on the built message
    try testing.expect(msg.opt != null);
    const opt = msg.opt.?;
    try testing.expectEqual(edns_udp_payload, opt.udp_payload_size);
    try testing.expect(opt.do_bit);
    try testing.expectEqual(@as(u8, 0), opt.version);

    // Serialize
    var buf: [edns_udp_payload]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);

    // Parse back
    const parsed = try parseMessage(alloc, wire);

    // Verify the opt record survives the roundtrip
    try testing.expect(parsed.opt != null);
    const parsed_opt = parsed.opt.?;
    try testing.expectEqual(edns_udp_payload, parsed_opt.udp_payload_size);
    try testing.expect(parsed_opt.do_bit);
    try testing.expectEqual(@as(u8, 0), parsed_opt.version);
    try testing.expectEqual(@as(u8, 0), parsed_opt.extended_rcode);

    // OPT should not appear in additionals
    try testing.expectEqual(@as(usize, 0), parsed.additionals.len);
}

test "EDNS0: parse non-EDNS response has null opt" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Build a query without EDNS
    const msg = try buildQuery(alloc, 0x5678, "example.com", .a, .{});
    try testing.expect(msg.opt == null);

    // Serialize and parse
    var buf: [max_udp_payload]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);
    const parsed = try parseMessage(alloc, wire);

    try testing.expect(parsed.opt == null);
    try testing.expectEqual(@as(usize, 0), parsed.additionals.len);
}

test "EDNS0: serialized OPT has correct wire format" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const msg = try buildQuery(alloc, 0xABCD, "x.com", .a, .{ .rd = true, .edns = .{ .do_bit = true, .udp_payload_size = 4096 } });

    var buf: [max_udp_payload]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);

    // ar_count in header should be 1 (the OPT record)
    const ar_count = mem.readInt(u16, wire[10..12], .big);
    try testing.expectEqual(@as(u16, 1), ar_count);

    // Find the OPT record at the end: after header(12) + question section
    // Question: \x01x\x03com\x00 (7 bytes) + qtype(2) + qclass(2) = 11 bytes
    const opt_start = 12 + 11;

    // root name
    try testing.expectEqual(@as(u8, 0x00), wire[opt_start]);
    // type 41
    try testing.expectEqual(@as(u16, 41), mem.readInt(u16, wire[opt_start + 1 ..][0..2], .big));
    // class = 4096
    try testing.expectEqual(@as(u16, 4096), mem.readInt(u16, wire[opt_start + 3 ..][0..2], .big));
    // TTL: DO bit set = 0x00008000
    const ttl = mem.readInt(u32, wire[opt_start + 5 ..][0..4], .big);
    try testing.expectEqual(@as(u32, 0x00008000), ttl);
    // RDLENGTH = 0
    try testing.expectEqual(@as(u16, 0), mem.readInt(u16, wire[opt_start + 9 ..][0..2], .big));
}

test "EDNS0: padding_target produces wire of exactly that size" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const msg = try buildQuery(alloc, 0xBEEF, "example.com", .a, .{
        .rd = true,
        .edns = .{ .do_bit = false, .udp_payload_size = 4096, .padding_target = dot_padding_target },
    });

    var buf: [max_udp_payload]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);

    try testing.expectEqual(@as(usize, dot_padding_target), wire.len);

    // And it should still parse cleanly with the OPT carrying a padding option.
    const parsed = try parseMessage(alloc, wire);
    try testing.expect(parsed.opt != null);
}

test "EDNS0: buildQuery without edns has no opt" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const msg = try buildQuery(alloc, 0x1111, "test.com", .aaaa, .{ .rd = false });
    try testing.expect(msg.opt == null);

    var buf: [max_udp_payload]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);

    // ar_count should be 0
    const ar_count = mem.readInt(u16, wire[10..12], .big);
    try testing.expectEqual(@as(u16, 0), ar_count);
}

test "EDNS0: OPT with non-root owner is FORMERR (RFC 6891 §6.1.2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Header: id=0x1234, flags=0x0100 (RD), qdcount=1, arcount=1
    // Question: example.com A IN
    // Additional: OPT with owner = "x." (NOT root) — RFC 6891 §6.1.2 violation.
    const wire = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // QNAME example.com.
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00,
        // QTYPE=A, QCLASS=IN
        0x00, 0x01, 0x00, 0x01,
        // OPT owner "x." (label "x" then root)
        0x01, 'x',  0x00,
        // TYPE=OPT (41), CLASS=4096 (UDP payload)
        0x00, 0x29, 0x10, 0x00,
        // TTL: ext_rcode=0, version=0, flags=0
        0x00, 0x00, 0x00, 0x00,
        // RDLENGTH=0
        0x00, 0x00,
    };

    try testing.expectError(error.FormatError, parseMessage(alloc, &wire));
}

// ── Name helpers ──────────────────────────────────────────────────────

/// Lowercase a DNS name string into a caller-provided buffer.
/// Asserts name.len <= buf.len (caller must ensure sufficient space).
pub fn lowerNameIntoBuf(buf: []u8, name: []const u8) []const u8 {
    std.debug.assert(name.len <= buf.len);
    for (name, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..name.len];
}

// ── Name memory management ─────────────────────────────────────────────

pub fn cloneName(allocator: Allocator, name: Name) !Name {
    const labels = try allocator.alloc([]const u8, name.labels.len);
    errdefer allocator.free(labels);
    var initialized: usize = 0;
    errdefer for (labels[0..initialized]) |l| allocator.free(l);
    for (name.labels, 0..) |label, i| {
        labels[i] = try allocator.dupe(u8, label);
        initialized += 1;
    }
    return .{ .labels = labels };
}

/// Arena-only DNS name: labels slice and every label byte share one
/// contiguous buffer. Distinct from `Name` by type so the compiler
/// rejects `freeName(NameFlat)` — that call would invoke `allocator.free`
/// on each mid-buffer label pointer (UAF). Produced by `cloneNameFlat`,
/// consumed by `.toUnownedName()` when handing off to a `ResourceRecord`
/// (whose surrounding arena owns the lifetime).
pub const NameFlat = struct {
    labels: []const []const u8,

    /// Reinterpret as a plain `Name` for placement in fields whose source
    /// is mixed (e.g. `ResourceRecord.name`). The caller asserts the
    /// surrounding arena will outlive every consumer — `freeName` MUST
    /// NOT be called on the result.
    pub fn toUnownedName(self: NameFlat) Name {
        return .{ .labels = self.labels };
    }
};

/// Owner-backing pair for `cloneNameFlatOwned`: caller frees `backing`
/// when ready (root names allocate nothing, so the slice can be empty).
pub const OwnedFlatName = struct {
    backing: []align(@alignOf([]const u8)) u8,
    name: Name,
};

/// Single-allocation variant of cloneName: the returned `NameFlat`'s
/// labels slice and every label byte live in one contiguous buffer. Use
/// only with arena allocators. Designed for the cache read path where
/// the caller's arena owns lifetime.
pub fn cloneNameFlat(allocator: Allocator, name: Name) !NameFlat {
    const owned = try cloneNameFlatImpl(allocator, name, false);
    return .{ .labels = owned.name.labels };
}

/// Like `cloneNameFlat` but also returns the raw backing slice so the
/// caller can free it later. Used by callers that own the allocation
/// across a non-arena boundary (e.g. the cache, which frees a single
/// shared-owner buffer when evicting an RRset).
pub fn cloneNameFlatOwned(allocator: Allocator, name: Name) !OwnedFlatName {
    return cloneNameFlatImpl(allocator, name, false);
}

/// Like `cloneNameFlat` but lowercases ASCII letters in-flight. Used to
/// scrub 0x20-randomized case off upstream RR owner names.
pub fn cloneNameFlatLower(allocator: Allocator, name: Name) !NameFlat {
    const owned = try cloneNameFlatImpl(allocator, name, true);
    return .{ .labels = owned.name.labels };
}

/// `cloneNameFlatLower` + `toUnownedName` — for scrub sites that don't keep the owned form.
pub fn cloneNameLower(allocator: Allocator, name: Name) !Name {
    return (try cloneNameFlatLower(allocator, name)).toUnownedName();
}

fn cloneNameFlatImpl(allocator: Allocator, name: Name, comptime lower: bool) !OwnedFlatName {
    const n = name.labels.len;
    if (n == 0) return .{ .backing = &.{}, .name = .{ .labels = &.{} } };
    const slice_bytes = @sizeOf([]const u8) * n;
    var total_bytes: usize = 0;
    for (name.labels) |label| total_bytes += label.len;

    const alignment: std.mem.Alignment = comptime .fromByteUnits(@alignOf([]const u8));
    const buf = try allocator.alignedAlloc(u8, alignment, slice_bytes + total_bytes);
    const labels_ptr: [*]([]const u8) = @ptrCast(buf.ptr);
    const labels: [][]const u8 = labels_ptr[0..n];
    var offset: usize = slice_bytes;
    for (name.labels, 0..) |label, i| {
        if (comptime lower) {
            for (label, 0..) |b, j| buf[offset + j] = std.ascii.toLower(b);
        } else {
            @memcpy(buf[offset..][0..label.len], label);
        }
        labels[i] = buf[offset..][0..label.len];
        offset += label.len;
    }
    return .{ .backing = buf, .name = .{ .labels = labels } };
}

/// Build a wildcard name (*.closest-encloser) from a closest encloser name
/// into a caller-provided label buffer. Returns null if CE has too many labels.
pub fn makeWildcardName(buf: *[max_label_count + 1][]const u8, closest_encloser: Name) ?Name {
    if (closest_encloser.labels.len >= buf.len) return null;
    buf[0] = "*";
    for (closest_encloser.labels, 0..) |label, i| {
        buf[1 + i] = label;
    }
    return Name{ .labels = buf[0 .. closest_encloser.labels.len + 1] };
}

/// RFC 5452 §9.1 / RFC 9619: verify response question section echoes the
/// original query. QDCOUNT must be exactly 1 for standard queries (OPCODE=0).
pub fn validateQuestionMatch(response: Message, expected_name: Name, expected_type: RType) bool {
    if (response.questions.len != 1) return false;
    const q = response.questions[0];
    return q.qtype == expected_type and q.qclass == .in and q.name.eql(expected_name);
}

/// RFC 9619 / Unbound model: error responses (FORMERR, SERVFAIL, REFUSED)
/// may omit the question section. Reject NOERROR/NXDOMAIN with missing
/// questions (suspicious — nothing legitimate to poison into cache).
pub fn validateResponse(msg: Message, expected_name: Name, qtype: RType) error{FormatError}!void {
    if (!msg.header.flags.qr) return error.FormatError;
    if (!validateQuestionMatch(msg, expected_name, qtype)) {
        if (msg.header.flags.rcode == .no_error or msg.header.flags.rcode == .name_error) return error.FormatError;
    }
}

test "validateResponse accepts a question-less error reply but rejects question-less NOERROR" {
    // RFC 9619: error rcodes may omit the question; NOERROR may not. An error
    // reply with QDCOUNT=0 thus passes here with empty questions — recursive.zig's
    // 0x20-echo checks must gate on questions.len==1 before indexing questions[0].
    const qname = Name{ .labels = &.{ "example", "com" } };
    const base_flags = Header.Flags{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = false, .ra = true, .z = 0, .ad = false, .cd = false, .rcode = .refused };

    const refused_no_question = Message{
        .header = .{ .id = 0, .flags = base_flags, .qd_count = 0, .an_count = 0, .ns_count = 0, .ar_count = 0 },
        .questions = &.{},
    };
    try validateResponse(refused_no_question, qname, .a);
    try std.testing.expectEqual(@as(usize, 0), refused_no_question.questions.len);

    var noerror_no_question = refused_no_question;
    noerror_no_question.header.flags.rcode = .no_error;
    try std.testing.expectError(error.FormatError, validateResponse(noerror_no_question, qname, .a));
}

pub fn freeName(allocator: Allocator, name: Name) void {
    for (name.labels) |l| allocator.free(l);
    allocator.free(name.labels);
}

/// Free a slice that may be empty (parsed data can alias the wire buffer with
/// zero-length slices that were never heap-allocated).
pub fn freeIfOwned(allocator: Allocator, slice: []const u8) void {
    if (slice.len > 0) allocator.free(slice);
}

/// Duplicate a slice, returning an unallocated empty slice for empty inputs.
/// Mirrors `freeIfOwned` so clone/free symmetry is preserved.
pub fn dupeOrEmpty(allocator: Allocator, slice: []const u8) ![]const u8 {
    if (slice.len == 0) return &.{};
    return allocator.dupe(u8, slice);
}

pub fn freeRData(allocator: Allocator, rdata: RData) void {
    switch (rdata) {
        .a, .aaaa => {},
        .ns, .cname, .ptr => |name| freeName(allocator, name),
        .mx => |mx| freeName(allocator, mx.exchange),
        .soa => |soa| {
            freeName(allocator, soa.mname);
            freeName(allocator, soa.rname);
        },
        .txt => |txt| {
            for (txt.strings) |s| allocator.free(s);
            allocator.free(txt.strings);
        },
        .rrsig => |rrsig| {
            freeName(allocator, rrsig.signer_name);
            freeIfOwned(allocator, rrsig.signature);
        },
        .dnskey => |dnskey| freeIfOwned(allocator, dnskey.public_key),
        .ds => |ds_data| freeIfOwned(allocator, ds_data.digest),
        .nsec => |nsec_data| {
            freeName(allocator, nsec_data.next_domain_name);
            freeIfOwned(allocator, nsec_data.type_bit_maps);
        },
        .nsec3 => |nsec3| {
            freeIfOwned(allocator, nsec3.salt);
            freeIfOwned(allocator, nsec3.next_hashed_owner);
            freeIfOwned(allocator, nsec3.type_bit_maps);
        },
        .nsec3param => |nsec3p| freeIfOwned(allocator, nsec3p.salt),
        .unknown => |data| allocator.free(data),
    }
}

/// Deep-copy an `RData`, allocating owned copies of every heap-backed field.
/// The clone counterpart to `freeRData`.
pub fn cloneRData(allocator: Allocator, rdata: RData) !RData {
    return switch (rdata) {
        .a => |v| .{ .a = v },
        .aaaa => |v| .{ .aaaa = v },
        .ns => |name| .{ .ns = try cloneName(allocator, name) },
        .cname => |name| .{ .cname = try cloneName(allocator, name) },
        .ptr => |name| .{ .ptr = try cloneName(allocator, name) },
        .mx => |mx| .{ .mx = .{
            .preference = mx.preference,
            .exchange = try cloneName(allocator, mx.exchange),
        } },
        .soa => |soa| blk: {
            const mname = try cloneName(allocator, soa.mname);
            errdefer freeName(allocator, mname);
            const rname = try cloneName(allocator, soa.rname);
            break :blk .{ .soa = .{
                .mname = mname,
                .rname = rname,
                .serial = soa.serial,
                .refresh = soa.refresh,
                .retry = soa.retry,
                .expire = soa.expire,
                .minimum = soa.minimum,
            } };
        },
        .txt => |txt| blk: {
            const strings = try allocator.alloc([]const u8, txt.strings.len);
            errdefer allocator.free(strings);
            var init_count: usize = 0;
            errdefer for (strings[0..init_count]) |s| allocator.free(s);
            for (txt.strings, 0..) |s, i| {
                strings[i] = try allocator.dupe(u8, s);
                init_count += 1;
            }
            break :blk .{ .txt = .{ .strings = strings } };
        },
        .rrsig => |rrsig| blk: {
            const signer = try cloneName(allocator, rrsig.signer_name);
            errdefer freeName(allocator, signer);
            const sig = try allocator.dupe(u8, rrsig.signature);
            break :blk .{ .rrsig = .{
                .type_covered = rrsig.type_covered,
                .algorithm = rrsig.algorithm,
                .labels = rrsig.labels,
                .original_ttl = rrsig.original_ttl,
                .sig_expiration = rrsig.sig_expiration,
                .sig_inception = rrsig.sig_inception,
                .key_tag = rrsig.key_tag,
                .signer_name = signer,
                .signature = sig,
            } };
        },
        .dnskey => |dnskey| .{ .dnskey = .{
            .flags = dnskey.flags,
            .protocol = dnskey.protocol,
            .algorithm = dnskey.algorithm,
            .public_key = try allocator.dupe(u8, dnskey.public_key),
        } },
        .ds => |ds_data| .{ .ds = .{
            .key_tag = ds_data.key_tag,
            .algorithm = ds_data.algorithm,
            .digest_type = ds_data.digest_type,
            .digest = try allocator.dupe(u8, ds_data.digest),
        } },
        .nsec => |nsec_data| blk: {
            const next_name = try cloneName(allocator, nsec_data.next_domain_name);
            errdefer freeName(allocator, next_name);
            break :blk .{ .nsec = .{
                .next_domain_name = next_name,
                .type_bit_maps = try dupeOrEmpty(allocator, nsec_data.type_bit_maps),
            } };
        },
        .nsec3 => |nsec3| blk: {
            const salt = try dupeOrEmpty(allocator, nsec3.salt);
            errdefer freeIfOwned(allocator, salt);
            const next_hash = try dupeOrEmpty(allocator, nsec3.next_hashed_owner);
            errdefer freeIfOwned(allocator, next_hash);
            break :blk .{ .nsec3 = .{
                .hash_algorithm = nsec3.hash_algorithm,
                .flags = nsec3.flags,
                .iterations = nsec3.iterations,
                .salt = salt,
                .next_hashed_owner = next_hash,
                .type_bit_maps = try dupeOrEmpty(allocator, nsec3.type_bit_maps),
            } };
        },
        .nsec3param => |nsec3p| .{ .nsec3param = .{
            .hash_algorithm = nsec3p.hash_algorithm,
            .flags = nsec3p.flags,
            .iterations = nsec3p.iterations,
            .salt = try dupeOrEmpty(allocator, nsec3p.salt),
        } },
        .unknown => |data| .{ .unknown = try allocator.dupe(u8, data) },
    };
}

fn freeOpt(allocator: Allocator, opt: OptRecord) void {
    for (opt.options) |o| allocator.free(o.data);
    if (opt.options.len > 0) allocator.free(opt.options);
}

/// Free only the heap-allocated outer slice of a `Name` parsed from a wire
/// buffer. Inner labels alias the wire (`parseName` collects them into a
/// stack buffer and `dupe`s only the outer slice); calling `freeName` on a
/// wire-parsed name would invoke `allocator.free` on those wire-pointing
/// slices, which is only sound under an arena. Used on parseMessage error
/// paths to drain per-record interiors without touching wire-aliased data.
fn freeWireParsedName(allocator: Allocator, name: Name) void {
    allocator.free(name.labels);
}

/// Free the heap-allocated outer slices inside a wire-parsed `RData`.
/// See `freeWireParsedName` for the rationale — variants whose payload
/// consists of `readSlice` results (DNSKEY public_key, DS digest, NSEC
/// bitmap, NSEC3 salt/hash/bitmap, NSEC3PARAM salt, unknown) reference
/// the wire directly and are skipped.
fn freeWireParsedRData(allocator: Allocator, rdata: RData) void {
    switch (rdata) {
        .a, .aaaa, .dnskey, .ds, .nsec3, .nsec3param, .unknown => {},
        .ns, .cname, .ptr => |n| freeWireParsedName(allocator, n),
        .mx => |mx| freeWireParsedName(allocator, mx.exchange),
        .soa => |s| {
            freeWireParsedName(allocator, s.mname);
            freeWireParsedName(allocator, s.rname);
        },
        .txt => |t| allocator.free(t.strings),
        .rrsig => |r| freeWireParsedName(allocator, r.signer_name),
        .nsec => |n| freeWireParsedName(allocator, n.next_domain_name),
    }
}

/// Lowercase every embedded `Name` in `rdata` in place. Mirrors the
/// name-bearing variants of `freeWireParsedRData` (differs only on
/// `.txt`, which has no names). Pre-scrub label bytes are abandoned,
/// not freed; only safe under an arena.
pub fn lowercaseRDataNames(allocator: Allocator, rdata: *RData) !void {
    switch (rdata.*) {
        .a, .aaaa, .txt, .dnskey, .ds, .nsec3, .nsec3param, .unknown => {},
        .ns, .cname, .ptr => |*n| n.* = try cloneNameLower(allocator, n.*),
        .mx => |*m| m.exchange = try cloneNameLower(allocator, m.exchange),
        .soa => |*s| {
            s.mname = try cloneNameLower(allocator, s.mname);
            s.rname = try cloneNameLower(allocator, s.rname);
        },
        .rrsig => |*r| r.signer_name = try cloneNameLower(allocator, r.signer_name),
        // RFC 6840 §5.1: names in NSEC RDATA are *not* case-folded when
        // canonicalizing, while names in RRSIG RDATA are — hark used to do the
        // exact inverse of both halves. Downcasing here changed the bytes that
        // later go into the signed data, so any signer preserving case in its
        // chain failed verification and every NXDOMAIN and NODATA in the zone
        // came back bogus.
        //
        // Still cloned, just not folded: the scrub is also what re-anchors
        // label bytes off the upstream wire buffer, so skipping it entirely
        // would leave the name aliasing storage the message does not own.
        //
        // The 0x20 motive that justifies the folding elsewhere does not reach
        // here — case randomization affects the echoed QNAME and owner names,
        // never a signer-chosen next_domain — and range comparisons go through
        // case-insensitive cmpLabelsCI regardless.
        // `cloneNameFlat`, not `cloneName`: same single-allocation shape as the
        // `cloneNameLower` it replaced. The per-label variant would turn one
        // allocation into N+1 for every NSEC on the parse path.
        .nsec => |*n| n.next_domain_name = (try cloneNameFlat(allocator, n.next_domain_name)).toUnownedName(),
    }
}

fn freeWireParsedRR(allocator: Allocator, rr: ResourceRecord) void {
    freeWireParsedName(allocator, rr.name);
    freeWireParsedRData(allocator, rr.rdata);
}

fn freeResourceRecordContents(allocator: Allocator, rrs: []const ResourceRecord) void {
    for (rrs) |rr| {
        freeName(allocator, rr.name);
        freeRData(allocator, rr.rdata);
    }
}

fn freeResourceRecords(allocator: Allocator, rrs: []const ResourceRecord) void {
    freeResourceRecordContents(allocator, rrs);
    allocator.free(rrs);
}

/// Free a Message and all owned contents. For Messages returned from
/// `parseMessage`, `allocator` must be the arena the Message was parsed
/// into — Name labels and all rdata byte slices (TXT strings included)
/// alias the wire buffer, so `allocator.free` on them is only sound when
/// it is a no-op. For manually-built or `cloneRData`'d Messages (e.g.
/// cache-owned records), any allocator that owns the contents works.
pub fn freeMessage(allocator: Allocator, msg: Message) void {
    for (msg.questions) |q| freeName(allocator, q.name);
    allocator.free(msg.questions);
    freeResourceRecords(allocator, msg.answers);
    freeResourceRecords(allocator, msg.authorities);
    freeResourceRecords(allocator, msg.additionals);
    if (msg.opt) |opt| freeOpt(allocator, opt);
}

test "cloneNameFlat returns NameFlat; freeName(NameFlat) does not compile" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = Name{ .labels = &.{ "example", "com" } };
    const flat: NameFlat = try cloneNameFlat(alloc, src);
    try testing.expectEqual(@as(usize, 2), flat.labels.len);
    try testing.expectEqualStrings("example", flat.labels[0]);
    try testing.expectEqualStrings("com", flat.labels[1]);

    // Compile-error proof (uncomment to verify): `freeName` takes `Name`,
    // not `NameFlat`, so the next line fails to compile.
    //   freeName(alloc, flat);

    // The intentional bridge: explicit conversion when the surrounding
    // arena owns lifetime. Result is a plain `Name` — must NOT be freed.
    const as_name = flat.toUnownedName();
    try testing.expect(as_name.eql(src));
}

test "parseDottedName basic" {
    const name = try parseDottedName(testing.allocator, "example.com");
    defer freeName(testing.allocator, name);
    try testing.expectEqual(@as(usize, 2), name.labels.len);
    try testing.expectEqualStrings("example", name.labels[0]);
    try testing.expectEqualStrings("com", name.labels[1]);
}

test "parseDottedName trailing dot" {
    const name = try parseDottedName(testing.allocator, "example.com.");
    defer freeName(testing.allocator, name);
    try testing.expectEqual(@as(usize, 2), name.labels.len);
    try testing.expectEqualStrings("example", name.labels[0]);
    try testing.expectEqualStrings("com", name.labels[1]);
}

test "parseDottedName root zone" {
    const name = try parseDottedName(testing.allocator, ".");
    defer testing.allocator.free(name.labels);
    try testing.expectEqual(@as(usize, 0), name.labels.len);

    const name2 = try parseDottedName(testing.allocator, "");
    defer testing.allocator.free(name2.labels);
    try testing.expectEqual(@as(usize, 0), name2.labels.len);
}

test "parseDottedName empty label" {
    try testing.expectError(error.InvalidLabelType, parseDottedName(testing.allocator, "example..com"));
}

test "parseDottedName too-long label" {
    const long_label = @as([64]u8, @splat('a')) ++ ".com".*;
    try testing.expectError(error.LabelTooLong, parseDottedName(testing.allocator, &long_label));
}

test "isSubdomainOf equal names" {
    const name = Name{ .labels = &.{ "example", "com" } };
    try testing.expect(name.isSubdomainOf(name));
}

test "isSubdomainOf child of parent" {
    const child = Name{ .labels = &.{ "www", "example", "com" } };
    const parent = Name{ .labels = &.{ "example", "com" } };
    try testing.expect(child.isSubdomainOf(parent));
}

test "isSubdomainOf sibling returns false" {
    const a = Name{ .labels = &.{ "a", "example", "com" } };
    const b = Name{ .labels = &.{ "b", "example", "com" } };
    try testing.expect(!a.isSubdomainOf(b));
}

test "isSubdomainOf root parent" {
    const name = Name{ .labels = &.{ "example", "com" } };
    const root = Name{ .labels = &.{} };
    try testing.expect(name.isSubdomainOf(root));
}

test "isSubdomainOf case insensitive" {
    const child = Name{ .labels = &.{ "WWW", "EXAMPLE", "COM" } };
    const parent = Name{ .labels = &.{ "example", "com" } };
    try testing.expect(child.isSubdomainOf(parent));
}

test "buildQuery roundtrip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try buildQuery(arena.allocator(), 0x1234, "example.com", .a, .{});

    try testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try testing.expect(!msg.header.flags.qr);
    try testing.expect(msg.header.flags.rd);
    try testing.expectEqual(@as(u16, 1), msg.header.qd_count);
    try testing.expectEqual(@as(usize, 1), msg.questions.len);
    try testing.expectEqual(RType.a, msg.questions[0].qtype);
    try testing.expectEqual(RClass.in, msg.questions[0].qclass);

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    try testing.expectEqual(msg.header.id, msg2.header.id);
    try testing.expectEqual(msg.header.flags.rd, msg2.header.flags.rd);
    try testing.expect(msg.questions[0].name.eql(msg2.questions[0].name));
    try testing.expectEqual(msg.questions[0].qtype, msg2.questions[0].qtype);
}

test "buildQuery rd=false roundtrip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try buildQuery(arena.allocator(), 0x5678, "example.com", .a, .{ .rd = false });

    try testing.expect(!msg.header.flags.rd);
    try testing.expectEqual(@as(u16, 0x5678), msg.header.id);

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    try testing.expect(!msg2.header.flags.rd);
    try testing.expectEqual(@as(u16, 0x5678), msg2.header.id);
    try testing.expect(msg.questions[0].name.eql(msg2.questions[0].name));
}

// ── Test helpers ────────────────────────────────────────────────────

fn testHeader(pkt: *[max_udp_payload]u8, opts: struct {
    id: u16 = 0x0001,
    flags: u16 = 0x8000,
    qd: u16 = 0,
    an: u16 = 1,
    ns: u16 = 0,
    ar: u16 = 0,
}) void {
    mem.writeInt(u16, pkt[0..2], opts.id, .big);
    mem.writeInt(u16, pkt[2..4], opts.flags, .big);
    mem.writeInt(u16, pkt[4..6], opts.qd, .big);
    mem.writeInt(u16, pkt[6..8], opts.an, .big);
    mem.writeInt(u16, pkt[8..10], opts.ns, .big);
    mem.writeInt(u16, pkt[10..12], opts.ar, .big);
}

fn testRoundtrip(allocator: Allocator, wire_buf: []u8, msg: Message) Error!Message {
    const wire = try serializeMessage(wire_buf, msg);
    return parseMessage(allocator, wire);
}

const TestRdata = struct {
    buf: [256]u8 = undefined,
    pos: usize = 0,

    fn putU8(self: *TestRdata, v: u8) void {
        if (self.pos + 1 > self.buf.len) @panic("TestRdata overflow");
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn putU16(self: *TestRdata, v: u16) void {
        if (self.pos + 2 > self.buf.len) @panic("TestRdata overflow");
        mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }
    fn putU32(self: *TestRdata, v: u32) void {
        if (self.pos + 4 > self.buf.len) @panic("TestRdata overflow");
        mem.writeInt(u32, self.buf[self.pos..][0..4], v, .big);
        self.pos += 4;
    }
    fn putBytes(self: *TestRdata, v: []const u8) void {
        if (self.pos + v.len > self.buf.len) @panic("TestRdata overflow");
        @memcpy(self.buf[self.pos..][0..v.len], v);
        self.pos += v.len;
    }
    fn slice(self: *const TestRdata) []const u8 {
        return self.buf[0..self.pos];
    }
};

fn testBuildAnswer(pkt: *[max_udp_payload]u8, rrname: []const u8, rtype_int: u16, ttl: u32, rdata: []const u8) usize {
    testHeader(pkt, .{});
    var pos: usize = 12;
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], rtype_int, .big);
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // class IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], ttl, .big);
    pos += 4;
    mem.writeInt(u16, pkt[pos..][0..2], @intCast(rdata.len), .big);
    pos += 2;
    @memcpy(pkt[pos..][0..rdata.len], rdata);
    pos += rdata.len;
    return pos;
}

// ── DNSSEC record type tests ────────────────────────────────────────

test "DNSKEY record parse/serialize roundtrip" {
    // RDATA: flags=257 (KSK), protocol=3, algorithm=8 (RSA/SHA-256), key=16 bytes
    const key_data = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var rd = TestRdata{};
    rd.putU16(257);
    rd.putU8(3);
    rd.putU8(8);
    rd.putBytes(&key_data);

    var pkt: [max_udp_payload]u8 = undefined;
    const pkt_len = testBuildAnswer(&pkt, "\x00", 48, 172800, rd.slice());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pkt_len]);

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const dnskey = msg.answers[0].rdata.dnskey;
    try testing.expectEqual(@as(u16, 257), dnskey.flags);
    try testing.expectEqual(@as(u8, 3), dnskey.protocol);
    try testing.expectEqual(DnssecAlgorithm.rsasha256, dnskey.algorithm);
    try testing.expect(dnskey.isZoneKey());
    try testing.expectEqualSlices(u8, &key_data, dnskey.public_key);

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    const dk2 = msg2.answers[0].rdata.dnskey;
    try testing.expectEqual(dnskey.flags, dk2.flags);
    try testing.expectEqual(dnskey.protocol, dk2.protocol);
    try testing.expectEqual(dnskey.algorithm, dk2.algorithm);
    try testing.expectEqualSlices(u8, dnskey.public_key, dk2.public_key);
}

test "DS record parse/serialize roundtrip" {
    // RDATA: key_tag=20326, alg=8, digest_type=2 (SHA-256), digest=32 bytes
    const digest = [32]u8{ 0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84, 0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D };
    var rd = TestRdata{};
    rd.putU16(20326);
    rd.putU8(8);
    rd.putU8(2);
    rd.putBytes(&digest);

    var pkt: [max_udp_payload]u8 = undefined;
    const pkt_len = testBuildAnswer(&pkt, "\x07example\x03com\x00", 43, 86400, rd.slice());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pkt_len]);

    const ds = msg.answers[0].rdata.ds;
    try testing.expectEqual(@as(u16, 20326), ds.key_tag);
    try testing.expectEqual(DnssecAlgorithm.rsasha256, ds.algorithm);
    try testing.expectEqual(DigestType.sha256, ds.digest_type);
    try testing.expectEqualSlices(u8, &digest, ds.digest);

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    const ds2 = msg2.answers[0].rdata.ds;
    try testing.expectEqual(ds.key_tag, ds2.key_tag);
    try testing.expectEqualSlices(u8, ds.digest, ds2.digest);
}

test "RRSIG record parse/serialize roundtrip" {
    const signer_wire = "\x07example\x03com\x00"; // example.com
    const fake_sig = [8]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    var rd = TestRdata{};
    rd.putU16(1); // type_covered = A
    rd.putU8(13); // algorithm = ECDSAP256SHA256
    rd.putU8(2); // labels
    rd.putU32(300); // original_ttl
    rd.putU32(1700000000); // sig_expiration
    rd.putU32(1699000000); // sig_inception
    rd.putU16(12345); // key_tag
    rd.putBytes(signer_wire);
    rd.putBytes(&fake_sig);

    var pkt: [max_udp_payload]u8 = undefined;
    const pkt_len = testBuildAnswer(&pkt, "\x07example\x03com\x00", 46, 300, rd.slice());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pkt_len]);

    const rrsig = msg.answers[0].rdata.rrsig;
    try testing.expectEqual(RType.a, rrsig.type_covered);
    try testing.expectEqual(DnssecAlgorithm.ecdsap256sha256, rrsig.algorithm);
    try testing.expectEqual(@as(u8, 2), rrsig.labels);
    try testing.expectEqual(@as(u32, 300), rrsig.original_ttl);
    try testing.expectEqual(@as(u32, 1700000000), rrsig.sig_expiration);
    try testing.expectEqual(@as(u32, 1699000000), rrsig.sig_inception);
    try testing.expectEqual(@as(u16, 12345), rrsig.key_tag);
    try testing.expectEqualStrings("example", rrsig.signer_name.labels[0]);
    try testing.expectEqualSlices(u8, &fake_sig, rrsig.signature);

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    const rrsig2 = msg2.answers[0].rdata.rrsig;
    try testing.expectEqual(rrsig.type_covered, rrsig2.type_covered);
    try testing.expectEqual(rrsig.key_tag, rrsig2.key_tag);
    try testing.expect(rrsig.signer_name.eql(rrsig2.signer_name));
    try testing.expectEqualSlices(u8, rrsig.signature, rrsig2.signature);
}

test "NSEC record parse/serialize roundtrip" {
    const next_name = "\x04host\x07example\x03com\x00";
    // Type bitmap: window 0, length 7 bytes
    // A(1): byte 0, bit 1 => 0x40
    // NS(2): byte 0, bit 2 => 0x20
    // SOA(6): byte 0, bit 6 => 0x02
    // => byte 0 = 0x62
    // MX(15): byte 1, bit 7 => 0x01
    // RRSIG(46): byte 5, bit 6 => 0x02
    // NSEC(47): byte 5, bit 7 => 0x01
    // => byte 5 = 0x03
    // DNSKEY(48): byte 6, bit 0 => 0x80
    const bitmap = [_]u8{ 0x00, 0x07, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    var rd = TestRdata{};
    rd.putBytes(next_name);
    rd.putBytes(&bitmap);

    var pkt: [max_udp_payload]u8 = undefined;
    const pkt_len = testBuildAnswer(&pkt, "\x07example\x03com\x00", 47, 3600, rd.slice());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pkt_len]);

    const nsec = msg.answers[0].rdata.nsec;
    try testing.expectEqualStrings("host", nsec.next_domain_name.labels[0]);
    try testing.expect(typeBitmapContains(nsec.type_bit_maps, .a));
    try testing.expect(typeBitmapContains(nsec.type_bit_maps, .ns));
    try testing.expect(typeBitmapContains(nsec.type_bit_maps, .soa));
    try testing.expect(typeBitmapContains(nsec.type_bit_maps, .mx));
    try testing.expect(typeBitmapContains(nsec.type_bit_maps, .rrsig));
    try testing.expect(typeBitmapContains(nsec.type_bit_maps, .nsec));
    try testing.expect(typeBitmapContains(nsec.type_bit_maps, .dnskey));
    try testing.expect(!typeBitmapContains(nsec.type_bit_maps, .aaaa));
    try testing.expect(!typeBitmapContains(nsec.type_bit_maps, .txt));

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    const nsec2 = msg2.answers[0].rdata.nsec;
    try testing.expect(nsec.next_domain_name.eql(nsec2.next_domain_name));
    try testing.expectEqualSlices(u8, nsec.type_bit_maps, nsec2.type_bit_maps);
}

test "NSEC3 record parse/serialize roundtrip" {
    const salt = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const next_hash = [20]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 };
    const bitmap = [_]u8{ 0x00, 0x01, 0x40 }; // window 0, len 1, A bit set
    var rd = TestRdata{};
    rd.putU8(1); // hash_algorithm (SHA-1)
    rd.putU8(0); // flags
    rd.putU16(10); // iterations
    rd.putU8(@intCast(salt.len));
    rd.putBytes(&salt);
    rd.putU8(@intCast(next_hash.len));
    rd.putBytes(&next_hash);
    rd.putBytes(&bitmap);

    var pkt: [max_udp_payload]u8 = undefined;
    const pkt_len = testBuildAnswer(&pkt, "\x07example\x03com\x00", 50, 3600, rd.slice());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pkt_len]);

    const nsec3 = msg.answers[0].rdata.nsec3;
    try testing.expectEqual(Nsec3HashAlgorithm.sha1, nsec3.hash_algorithm);
    try testing.expectEqual(@as(u8, 0), nsec3.flags);
    try testing.expectEqual(@as(u16, 10), nsec3.iterations);
    try testing.expectEqualSlices(u8, &salt, nsec3.salt);
    try testing.expectEqualSlices(u8, &next_hash, nsec3.next_hashed_owner);
    try testing.expect(typeBitmapContains(nsec3.type_bit_maps, .a));
    try testing.expect(!typeBitmapContains(nsec3.type_bit_maps, .aaaa));

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    const n3_2 = msg2.answers[0].rdata.nsec3;
    try testing.expectEqual(nsec3.hash_algorithm, n3_2.hash_algorithm);
    try testing.expectEqual(nsec3.iterations, n3_2.iterations);
    try testing.expectEqualSlices(u8, nsec3.salt, n3_2.salt);
    try testing.expectEqualSlices(u8, nsec3.next_hashed_owner, n3_2.next_hashed_owner);
    try testing.expectEqualSlices(u8, nsec3.type_bit_maps, n3_2.type_bit_maps);
}

test "NSEC3PARAM record parse/serialize roundtrip" {
    const salt = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var rd = TestRdata{};
    rd.putU8(1); // hash_algorithm
    rd.putU8(0); // flags
    rd.putU16(0); // iterations
    rd.putU8(@intCast(salt.len));
    rd.putBytes(&salt);

    var pkt: [max_udp_payload]u8 = undefined;
    const pkt_len = testBuildAnswer(&pkt, "\x07example\x03com\x00", 51, 0, rd.slice());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pkt_len]);

    const nsec3p = msg.answers[0].rdata.nsec3param;
    try testing.expectEqual(Nsec3HashAlgorithm.sha1, nsec3p.hash_algorithm);
    try testing.expectEqual(@as(u16, 0), nsec3p.iterations);
    try testing.expectEqualSlices(u8, &salt, nsec3p.salt);

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    const np2 = msg2.answers[0].rdata.nsec3param;
    try testing.expectEqual(nsec3p.hash_algorithm, np2.hash_algorithm);
    try testing.expectEqualSlices(u8, nsec3p.salt, np2.salt);
}

test "typeBitmapContains" {
    // Type A = 1: byte 0, bit 1, mask = 0x80>>1 = 0x40
    // Type NS = 2: byte 0, bit 2, mask = 0x80>>2 = 0x20
    // Type SOA = 6: byte 0, bit 6, mask = 0x80>>6 = 0x02
    // => byte 0 = 0x62
    // Type RRSIG = 46: byte 5, bit 6, mask = 0x80>>6 = 0x02
    // Type NSEC = 47: byte 5, bit 7, mask = 0x80>>7 = 0x01
    // => byte 5 = 0x03
    // Type DNSKEY = 48: byte 6, bit 0, mask = 0x80>>0 = 0x80
    // => byte 6 = 0x80
    // Need window 0, length 7 (bytes 0-6)
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

    // Empty bitmap
    try testing.expect(!typeBitmapContains(&.{}, .a));
}

test "safeTagName handles known and unknown enum values" {
    var buf: [24]u8 = undefined;
    try testing.expectEqualStrings("a", safeTagName(RType, .a, &buf));
    try testing.expectEqualStrings("aaaa", safeTagName(RType, .aaaa, &buf));
    try testing.expectEqualStrings("no_error", safeTagName(RCode, .no_error, &buf));

    // Unknown values — HTTPS (65), SVCB (64), CAA (257)
    const https: RType = @fromBackingInt(@intCast(65));
    try testing.expectEqualStrings("65", safeTagName(RType, https, &buf));
    const svcb: RType = @fromBackingInt(@intCast(64));
    try testing.expectEqualStrings("64", safeTagName(RType, svcb, &buf));
    const caa: RType = @fromBackingInt(@intCast(257));
    try testing.expectEqualStrings("257", safeTagName(RType, caa, &buf));

    // Unknown RCode
    const rcode7: RCode = @fromBackingInt(@intCast(7));
    try testing.expectEqualStrings("7", safeTagName(RCode, rcode7, &buf));
}

test "RRSIG with signer name exceeding rdlength returns InvalidRDataLength" {
    // Craft a packet where the RRSIG signer name extends past the declared rdlength.
    // Before the fix this would cause an unsigned integer underflow (panic/UB).
    var pkt: [max_udp_payload]u8 = undefined;
    testHeader(&pkt, .{});

    var pos: usize = 12;
    const rrname = "\x07example\x03com\x00";
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 46, .big); // RRSIG
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 300, .big); // TTL
    pos += 4;

    // Signer name "example.com." = 13 bytes on wire. 18 + 13 = 31, but set rdlength = 20.
    const signer_wire = "\x07example\x03com\x00";
    const rdlen: u16 = 20; // too small: 18 + signer_wire.len = 31
    mem.writeInt(u16, pkt[pos..][0..2], rdlen, .big);
    pos += 2;
    // Write the 18-byte fixed fields
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // type_covered = A
    pos += 2;
    pkt[pos] = 13; // algorithm
    pos += 1;
    pkt[pos] = 2; // labels
    pos += 1;
    mem.writeInt(u32, pkt[pos..][0..4], 300, .big); // original_ttl
    pos += 4;
    mem.writeInt(u32, pkt[pos..][0..4], 1700000000, .big); // sig_expiration
    pos += 4;
    mem.writeInt(u32, pkt[pos..][0..4], 1699000000, .big); // sig_inception
    pos += 4;
    mem.writeInt(u16, pkt[pos..][0..2], 12345, .big); // key_tag
    pos += 2;
    // Signer name extends past rdlength boundary
    @memcpy(pkt[pos..][0..signer_wire.len], signer_wire);
    pos += signer_wire.len;

    // Use arena to avoid leak detection on partial-parse error paths
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = parseMessage(arena.allocator(), pkt[0..pos]);
    try testing.expectError(error.InvalidRDataLength, result);
}

test "NSEC with next domain name exceeding rdlength returns InvalidRDataLength" {
    // Craft a packet where the NSEC next domain name extends past the declared rdlength.
    var pkt: [max_udp_payload]u8 = undefined;
    testHeader(&pkt, .{});

    var pos: usize = 12;
    const rrname = "\x07example\x03com\x00";
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 47, .big); // NSEC
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 300, .big); // TTL
    pos += 4;

    // next domain "host.example.com." = 22 bytes, but set rdlength = 5
    const next_domain_wire = "\x04host\x07example\x03com\x00";
    const rdlen: u16 = 5; // too small for the domain name
    mem.writeInt(u16, pkt[pos..][0..2], rdlen, .big);
    pos += 2;
    @memcpy(pkt[pos..][0..next_domain_wire.len], next_domain_wire);
    pos += next_domain_wire.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = parseMessage(arena.allocator(), pkt[0..pos]);
    try testing.expectError(error.InvalidRDataLength, result);
}

// ── 0x20 case randomization ───────────────────────────────────────────

test "applyCase0x20 only flips ASCII letters; round-trips eql" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = try parseDottedName(alloc, "Foo.Bar123-baz.com");
    const randomized = try parseDottedName(alloc, "Foo.Bar123-baz.com");

    applyCase0x20(testing.io, randomized);

    for (randomized.labels, original.labels) |rl, ol| {
        try testing.expectEqual(rl.len, ol.len);
        for (rl, ol) |rb, ob| {
            if (std.ascii.isAlphabetic(ob)) {
                try testing.expectEqual(std.ascii.toLower(ob), std.ascii.toLower(rb));
            } else {
                try testing.expectEqual(ob, rb);
            }
        }
    }

    try testing.expect(original.eql(randomized));
}

test "eqlExact rejects case-flipped name; eql accepts" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const a = try parseDottedName(alloc, "example.com");
    const b = try parseDottedName(alloc, "ExAmPlE.com");

    try testing.expect(a.eql(b));
    try testing.expect(!a.eqlExact(b));
    try testing.expect(a.eqlExact(a));
}

test "applyCase0x20 distribution: each letter flips ~50% over many runs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const iterations: usize = 10_000;
    const letters = "abcdefghijklmnopqrstuvwxyz";
    var upper_counts: [26]u32 = @splat(0);

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const n = try parseDottedName(alloc, letters);
        applyCase0x20(testing.io, n);
        for (n.labels[0], 0..) |b, idx| {
            if (std.ascii.isUpper(b)) upper_counts[idx] += 1;
        }
    }

    for (upper_counts) |c| {
        const ratio = @as(f64, @floatFromInt(c)) / @as(f64, @floatFromInt(iterations));
        try testing.expect(ratio > 0.45 and ratio < 0.55);
    }
}

test "applyCase0x20 on root and all-numeric is a no-op" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const root = try parseDottedName(alloc, ".");
    applyCase0x20(testing.io, root);
    try testing.expectEqual(@as(usize, 0), root.labels.len);

    const numeric = try parseDottedName(alloc, "12345.com");
    const numeric_copy = try parseDottedName(alloc, "12345.com");
    applyCase0x20(testing.io, numeric);
    try testing.expect(mem.eql(u8, numeric.labels[0], numeric_copy.labels[0]));
}

test "buildQuery with case_randomize" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const lower = try buildQuery(alloc, 0x1234, "example.com", .a, .{});
    const randomized = try buildQuery(alloc, 0x1234, "example.com", .a, .{
        .case_rng = testing.io,
    });

    try testing.expect(lower.questions[0].name.eql(randomized.questions[0].name));
}

/// Serialize a minimal "1-question, optional A answer, OPT-with-one-option"
/// response for `extractKeepaliveTimeout` tests.
pub fn serializeOptOptionResponse(
    arena: Allocator,
    buf: []u8,
    qname: []const u8,
    include_answer: bool,
    opt_code: u16,
    opt_data: []const u8,
) ![]const u8 {
    const name = try parseDottedName(arena, qname);
    const questions = try arena.alloc(Question, 1);
    questions[0] = .{ .name = name, .qtype = .a, .qclass = .in };

    var answers: []ResourceRecord = &.{};
    if (include_answer) {
        answers = try arena.alloc(ResourceRecord, 1);
        answers[0] = .{
            .name = name,
            .rtype = .a,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .a = .{ 192, 0, 2, 1 } },
        };
    }

    const options = try arena.alloc(EdnsOption, 1);
    options[0] = .{ .code = opt_code, .data = opt_data };

    const msg: Message = .{
        .header = .{
            .id = 0x1234,
            .flags = .{
                .qr = true,
                .opcode = .query,
                .aa = false,
                .tc = false,
                .rd = true,
                .ra = true,
                .z = 0,
                .ad = false,
                .cd = false,
                .rcode = .no_error,
            },
            .qd_count = 1,
            .an_count = if (include_answer) 1 else 0,
            .ns_count = 0,
            .ar_count = 1,
        },
        .questions = questions,
        .answers = answers,
        .opt = .{
            .udp_payload_size = edns_udp_payload,
            .extended_rcode = 0,
            .version = 0,
            .do_bit = false,
            .options = options,
        },
    };
    return serializeMessage(buf, msg);
}

test "extractKeepaliveTimeout reads RFC 7828 option 11" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [256]u8 = undefined;
    const ka_data = [_]u8{ 0x00, 0x64 }; // 100 * 100ms = 10s
    const wire = try serializeOptOptionResponse(arena.allocator(), &buf, "example.com", true, edns_opt_tcp_keepalive, &ka_data);
    try testing.expectEqual(@as(?u16, 100), extractKeepaliveTimeout(wire));
}

test "extractKeepaliveTimeout returns null when option absent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [256]u8 = undefined;
    const padding = [_]u8{ 0, 0, 0, 0 };
    const wire = try serializeOptOptionResponse(arena.allocator(), &buf, "example.com", false, 12, &padding);
    try testing.expectEqual(@as(?u16, null), extractKeepaliveTimeout(wire));
}

test "extractKeepaliveTimeout returns null on zero-length client form" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [256]u8 = undefined;
    const empty = [_]u8{};
    const wire = try serializeOptOptionResponse(arena.allocator(), &buf, "example.com", false, edns_opt_tcp_keepalive, &empty);
    try testing.expectEqual(@as(?u16, null), extractKeepaliveTimeout(wire));
}

test "extractKeepaliveTimeout rejects malformed wire" {
    // Header-only buffer claiming 1 question but zero bytes follow.
    var buf: [12]u8 = .{ 0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0 };
    try testing.expectEqual(@as(?u16, null), extractKeepaliveTimeout(&buf));
}

test "keepaliveToSeconds rounds up" {
    try testing.expectEqual(@as(i64, 0), keepaliveToSeconds(0));
    try testing.expectEqual(@as(i64, 1), keepaliveToSeconds(1)); // 100ms → ≥1s
    try testing.expectEqual(@as(i64, 1), keepaliveToSeconds(9));
    try testing.expectEqual(@as(i64, 1), keepaliveToSeconds(10)); // exactly 1s
    try testing.expectEqual(@as(i64, 2), keepaliveToSeconds(11)); // 1.1s → 2s
    try testing.expectEqual(@as(i64, 10), keepaliveToSeconds(100)); // 10s
}

fn parseMessageOomProbe(allocator: Allocator, wire: []const u8) !void {
    const msg = try parseMessage(allocator, wire);
    // Wire-safe teardown: parseMessage's lifetime contract says inner labels
    // and rdata byte slices alias `wire`, so a normal `freeMessage` would
    // call `allocator.free` on wire-pointing slices. Drain only the heap
    // material the parser actually allocates from `allocator`.
    for (msg.questions) |q| freeWireParsedName(allocator, q.name);
    allocator.free(msg.questions);
    for (msg.answers) |rr| freeWireParsedRR(allocator, rr);
    allocator.free(msg.answers);
    for (msg.authorities) |rr| freeWireParsedRR(allocator, rr);
    allocator.free(msg.authorities);
    for (msg.additionals) |rr| freeWireParsedRR(allocator, rr);
    allocator.free(msg.additionals);
    if (msg.opt) |o| if (o.options.len > 0) allocator.free(o.options);
}

test "parseMessage handles OOM at every allocation without leaking" {
    // Question + two A answers + one NS authority + OPT — exercises per-record
    // parseName, parseRData branches, parseEdnsOptions, and the four section
    // ArrayList spines.
    const example_com = Name{ .labels = &.{ "example", "com" } };
    const ns_target = Name{ .labels = &.{ "ns", "example", "com" } };
    const msg: Message = .{
        .header = .{
            .id = 0x4242,
            .flags = .{
                .qr = true,
                .opcode = .query,
                .aa = true,
                .tc = false,
                .rd = false,
                .ra = false,
                .z = 0,
                .ad = false,
                .cd = false,
                .rcode = .no_error,
            },
            .qd_count = 1,
            .an_count = 2,
            .ns_count = 1,
            .ar_count = 0, // serializeMessage adds 1 for the OPT below
        },
        .questions = &.{
            .{ .name = example_com, .qtype = .a, .qclass = .in },
        },
        .answers = &.{
            .{ .name = example_com, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 192, 0, 2, 1 } } },
            .{ .name = example_com, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 192, 0, 2, 2 } } },
        },
        .authorities = &.{
            .{ .name = example_com, .rtype = .ns, .rclass = .in, .ttl = 3600, .rdata = .{ .ns = ns_target } },
        },
        .additionals = &.{},
        .opt = .{
            .udp_payload_size = 1232,
            .extended_rcode = 0,
            .version = 0,
            .do_bit = false,
            .options = &.{.{ .code = 3, .data = &.{} }}, // NSID, empty data
        },
    };

    var wire_buf: [max_udp_payload]u8 = undefined;
    const wire = try serializeMessage(&wire_buf, msg);

    // Sanity: the wire parses successfully under an arena.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const parsed = try parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 2), parsed.header.an_count);
    try testing.expectEqual(@as(u16, 1), parsed.header.ns_count);
    try testing.expect(parsed.opt != null);

    try testing.checkAllAllocationFailures(testing.allocator, parseMessageOomProbe, .{wire});
}
