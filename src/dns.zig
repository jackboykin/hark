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
    inline for (info.fields) |field| {
        if (@intFromEnum(val) == field.value) return field.name;
    }
    return std.fmt.bufPrint(buf, "{d}", .{@intFromEnum(val)}) catch "?";
}

/// Check the TC (truncation) bit on raw wire data without full parsing.
/// Used to detect truncated UDP responses before attempting parseMessage,
/// which may fail with EndOfData on mid-record truncation (RFC 2181).
pub fn hasTcBit(bytes: []const u8) bool {
    if (bytes.len < header_len) return false;
    const flags = mem.readInt(u16, bytes[2..4], .big);
    return (flags >> 9) & 1 == 1;
}

// ── Constants ──────────────────────────────────────────────────────────

pub const max_label_len = 63;
pub const max_label_count = 127; // max_name_len / (1 label byte + 1 char) = 127
pub const max_name_len = 253;
pub const header_len = 12;
pub const max_udp_payload = 512;
pub const edns_udp_payload: u16 = 1232;
/// RFC 1035 §4.2.2: DNS-over-TCP uses a 2-byte length prefix, so a single
/// message can be at most 65535 bytes. Also the ceiling for any DNS
/// response buffer we might parse.
pub const max_message_len: u16 = 65535;

// ── Enums ──────────────────────────────────────────────────────────────

pub const OpCode = enum(u4) {
    query = 0,
    iquery = 1,
    status = 2,
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
    opt = 41,
    ds = 43,
    rrsig = 46,
    nsec = 47,
    dnskey = 48,
    nsec3 = 50,
    nsec3param = 51,
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
    OutOfMemory,
};

// ── Header ─────────────────────────────────────────────────────────────

pub const Header = struct {
    id: u16,
    qr: bool,
    opcode: OpCode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u1,
    ad: bool,
    cd: bool,
    rcode: RCode,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,

    pub fn parse(bytes: *const [12]u8) Header {
        const id = mem.readInt(u16, bytes[0..2], .big);
        const flags = mem.readInt(u16, bytes[2..4], .big);
        const qd_count = mem.readInt(u16, bytes[4..6], .big);
        const an_count = mem.readInt(u16, bytes[6..8], .big);
        const ns_count = mem.readInt(u16, bytes[8..10], .big);
        const ar_count = mem.readInt(u16, bytes[10..12], .big);

        return .{
            .id = id,
            .qr = (flags >> 15) & 1 == 1,
            .opcode = @enumFromInt(@as(u4, @truncate(flags >> 11))),
            .aa = (flags >> 10) & 1 == 1,
            .tc = (flags >> 9) & 1 == 1,
            .rd = (flags >> 8) & 1 == 1,
            .ra = (flags >> 7) & 1 == 1,
            .z = @truncate(flags >> 6),
            .ad = (flags >> 5) & 1 == 1,
            .cd = (flags >> 4) & 1 == 1,
            .rcode = @enumFromInt(@as(u4, @truncate(flags))),
            .qd_count = qd_count,
            .an_count = an_count,
            .ns_count = ns_count,
            .ar_count = ar_count,
        };
    }

    pub fn serialize(self: Header, out: *[12]u8) void {
        mem.writeInt(u16, out[0..2], self.id, .big);

        var flags: u16 = 0;
        flags |= @as(u16, @intFromBool(self.qr)) << 15;
        flags |= @as(u16, @intFromEnum(self.opcode)) << 11;
        flags |= @as(u16, @intFromBool(self.aa)) << 10;
        flags |= @as(u16, @intFromBool(self.tc)) << 9;
        flags |= @as(u16, @intFromBool(self.rd)) << 8;
        flags |= @as(u16, @intFromBool(self.ra)) << 7;
        flags |= @as(u16, self.z) << 6;
        flags |= @as(u16, @intFromBool(self.ad)) << 5;
        flags |= @as(u16, @intFromBool(self.cd)) << 4;
        flags |= @as(u16, @intFromEnum(self.rcode));
        mem.writeInt(u16, out[2..4], flags, .big);

        mem.writeInt(u16, out[4..6], self.qd_count, .big);
        mem.writeInt(u16, out[6..8], self.an_count, .big);
        mem.writeInt(u16, out[8..10], self.ns_count, .big);
        mem.writeInt(u16, out[10..12], self.ar_count, .big);
    }
};

// ── Name ───────────────────────────────────────────────────────────────

pub const Name = struct {
    labels: []const []const u8,

    pub fn format(self: Name) [max_name_len + 1]u8 {
        var buf: [max_name_len + 1]u8 = undefined;
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
        buf[pos] = 0;
        return buf;
    }

    /// Format `self` into `buf` as a dotted string. Returns the written slice so
    /// callers don't need to re-scan for the null terminator.
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
};

pub const DnskeyData = struct {
    flags: u16,
    protocol: u8,
    algorithm: DnssecAlgorithm,
    public_key: []const u8,

    pub fn isZoneKey(self: DnskeyData) bool {
        return (self.flags & 0x100) != 0; // bit 7 (ZONE flag)
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
    const type_num = @intFromEnum(rtype);
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
    /// so the total message reaches this size. Set by buildQueryWithOptions.
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
        const labels = allocator.alloc([]const u8, 0) catch return error.OutOfMemory;
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

    // Allocate and populate
    const labels = allocator.alloc([]const u8, label_count) catch return error.OutOfMemory;
    var i: usize = 0;
    var iter = mem.splitScalar(u8, name_str, '.');
    while (iter.next()) |label| {
        labels[i] = allocator.dupe(u8, label) catch return error.OutOfMemory;
        i += 1;
    }

    return .{ .labels = labels };
}

pub const EdnsConfig = struct {
    udp_payload_size: u16 = edns_udp_payload,
    do_bit: bool = false,
    /// If non-zero, add EDNS0 padding (option code 12, RFC 7830) to reach
    /// this total message size. RFC 8467 §4.1 recommends 468 for DoT.
    padding_target: u16 = 0,
};

pub const QueryOptions = struct {
    rd: bool = true,
    edns: ?EdnsConfig = null,
};

pub fn buildQuery(allocator: Allocator, id: u16, name_str: []const u8, qtype: RType) Error!Message {
    return buildQueryWithOptions(allocator, id, name_str, qtype, .{});
}

pub fn buildQueryWithOptions(allocator: Allocator, id: u16, name_str: []const u8, qtype: RType, options: QueryOptions) Error!Message {
    const name = try parseDottedName(allocator, name_str);
    const questions = allocator.alloc(Question, 1) catch return error.OutOfMemory;
    questions[0] = .{ .name = name, .qtype = qtype, .qclass = .in };

    return .{
        .header = .{
            .id = id,
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
        var labels: ArrayList([]const u8) = .empty;
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
                if (labels.items.len >= max_label_count) return error.TooManyLabels;
                cursor += 1;
                if (cursor + label_len > self.msg.len) return error.EndOfData;
                const label_data = self.msg[cursor..][0..label_len];
                labels.append(allocator, label_data) catch return error.OutOfMemory;
                cursor += label_len;
                total_len += label_len + 1; // +1 for the dot separator
                if (total_len > max_name_len + 1) return error.NameTooLong;
                if (saved_pos == null) self.pos = cursor;
            } else {
                return error.InvalidLabelType;
            }
        }

        if (saved_pos) |sp| self.pos = sp;

        return .{ .labels = labels.toOwnedSlice(allocator) catch return error.OutOfMemory };
    }

    pub fn parseQuestion(self: *Parser, allocator: Allocator) Error!Question {
        const name = try self.parseName(allocator);
        const qtype: RType = @enumFromInt(try self.readU16());
        const qclass: RClass = @enumFromInt(try self.readU16());
        return .{ .name = name, .qtype = qtype, .qclass = qclass };
    }

    pub fn parseResourceRecord(self: *Parser, allocator: Allocator) Error!ResourceRecord {
        const name = try self.parseName(allocator);
        const rtype: RType = @enumFromInt(try self.readU16());
        const rclass: RClass = @enumFromInt(try self.readU16());
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
                if (self.pos != rdata_end) return error.FormatError;
                return .{ .mx = .{ .preference = preference, .exchange = exchange } };
            },
            .soa => {
                const rdata_end = self.pos + rdlength;
                const mname = try self.parseName(allocator);
                const rname = try self.parseName(allocator);
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
                while (self.pos < rdata_end) {
                    const str_len: usize = try self.readU8();
                    if (self.pos + str_len > rdata_end) return error.FormatError;
                    const str_data = try self.readSlice(str_len);
                    strings.append(allocator, str_data) catch return error.OutOfMemory;
                }
                return .{ .txt = .{
                    .strings = strings.toOwnedSlice(allocator) catch return error.OutOfMemory,
                } };
            },
            .rrsig => {
                if (rdlength < 18) return error.InvalidRDataLength;
                const type_covered: RType = @enumFromInt(try self.readU16());
                const algorithm: DnssecAlgorithm = @enumFromInt(try self.readU8());
                const label_count = try self.readU8();
                const original_ttl = try self.readU32();
                const sig_expiration = try self.readU32();
                const sig_inception = try self.readU32();
                const key_tag = try self.readU16();
                const name_start = self.pos;
                const signer_name = try self.parseName(allocator);
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
                const algorithm: DnssecAlgorithm = @enumFromInt(try self.readU8());
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
                const algorithm: DnssecAlgorithm = @enumFromInt(try self.readU8());
                const digest_type: DigestType = @enumFromInt(try self.readU8());
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
                const name_len = self.pos - name_start;
                if (name_len > rdlength) return error.InvalidRDataLength;
                return .{ .nsec = .{
                    .next_domain_name = next_domain_name,
                    .type_bit_maps = try self.readSlice(rdlength - name_len),
                } };
            },
            .nsec3 => {
                if (rdlength < 6) return error.InvalidRDataLength;
                const hash_algorithm: Nsec3HashAlgorithm = @enumFromInt(try self.readU8());
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
                const hash_algorithm: Nsec3HashAlgorithm = @enumFromInt(try self.readU8());
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
            .opt, _ => {
                const data = try self.readSlice(rdlength);
                return .{ .unknown = data };
            },
        }
    }

    /// Parse a single-name RDATA (NS, CNAME, PTR) with rdlength validation.
    fn parseNameRdata(self: *Parser, allocator: Allocator, rdlength: usize) Error!Name {
        const rdata_end = self.pos + rdlength;
        const name = try self.parseName(allocator);
        if (self.pos != rdata_end) return error.FormatError;
        return name;
    }
};

// ── EDNS option parsing ────────────────────────────────────────────────

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
        options.append(allocator, .{ .code = code, .data = data }) catch return error.OutOfMemory;
        pos += length;
    }
    if (pos != rdata.len) return error.FormatError;
    return options.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

// ── Top-level parse ────────────────────────────────────────────────────

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

    var questions: ArrayList(Question) = .empty;
    questions.ensureTotalCapacity(allocator, @min(hdr.qd_count, max_questions)) catch return error.OutOfMemory;
    errdefer questions.deinit(allocator);
    for (0..hdr.qd_count) |_| {
        const q = try parser.parseQuestion(allocator);
        questions.append(allocator, q) catch return error.OutOfMemory;
    }

    var answers: ArrayList(ResourceRecord) = .empty;
    answers.ensureTotalCapacity(allocator, @min(hdr.an_count, max_rrs)) catch return error.OutOfMemory;
    errdefer answers.deinit(allocator);
    for (0..hdr.an_count) |_| {
        const rr = try parser.parseResourceRecord(allocator);
        answers.append(allocator, rr) catch return error.OutOfMemory;
    }

    var authorities: ArrayList(ResourceRecord) = .empty;
    authorities.ensureTotalCapacity(allocator, @min(hdr.ns_count, max_rrs)) catch return error.OutOfMemory;
    errdefer authorities.deinit(allocator);
    for (0..hdr.ns_count) |_| {
        const rr = try parser.parseResourceRecord(allocator);
        authorities.append(allocator, rr) catch return error.OutOfMemory;
    }

    var additionals: ArrayList(ResourceRecord) = .empty;
    additionals.ensureTotalCapacity(allocator, @min(hdr.ar_count, max_rrs)) catch return error.OutOfMemory;
    errdefer additionals.deinit(allocator);
    var opt: ?OptRecord = null;
    for (0..hdr.ar_count) |_| {
        const rr = try parser.parseResourceRecord(allocator);
        if (rr.rtype == .opt and opt == null) {
            // OPT pseudo-record: extract fields and discard the shell.
            opt = .{
                .udp_payload_size = @intFromEnum(rr.rclass),
                .extended_rcode = @intCast(rr.ttl >> 24),
                .version = @intCast((rr.ttl >> 16) & 0xFF),
                .do_bit = (rr.ttl & 0x8000) != 0,
                .options = try parseEdnsOptions(allocator, rr.rdata.unknown),
            };
        } else {
            additionals.append(allocator, rr) catch return error.OutOfMemory;
        }
    }

    return .{
        .header = hdr,
        .questions = questions.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .answers = answers.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .authorities = authorities.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .additionals = additionals.toOwnedSlice(allocator) catch return error.OutOfMemory,
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
        try self.writeU16(@intFromEnum(q.qtype));
        try self.writeU16(@intFromEnum(q.qclass));
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

    /// Serialize an RR via the field-by-field path (ignoring `rr.wire`).
    /// Returns the byte offset of the TTL field, used by store-time callers
    /// that want to patch TTL later.
    fn writeRecordFields(self: *Serializer, rr: ResourceRecord) Error!u16 {
        try self.writeName(rr.name);
        try self.writeU16(@intFromEnum(rr.rtype));
        try self.writeU16(@intFromEnum(rr.rclass));
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
            .ns => |name| try self.writeName(name),
            .cname => |name| try self.writeName(name),
            .ptr => |name| try self.writeName(name),
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
                try self.writeU16(@intFromEnum(rrsig.type_covered));
                try self.writeU8(@intFromEnum(rrsig.algorithm));
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
                try self.writeU8(@intFromEnum(dnskey.algorithm));
                try self.writeSlice(dnskey.public_key);
            },
            .ds => |ds_data| {
                try self.writeU16(ds_data.key_tag);
                try self.writeU8(@intFromEnum(ds_data.algorithm));
                try self.writeU8(@intFromEnum(ds_data.digest_type));
                try self.writeSlice(ds_data.digest);
            },
            .nsec => |nsec_data| {
                try self.writeName(nsec_data.next_domain_name);
                try self.writeSlice(nsec_data.type_bit_maps);
            },
            .nsec3 => |nsec3| {
                try self.writeU8(@intFromEnum(nsec3.hash_algorithm));
                try self.writeU8(nsec3.flags);
                try self.writeU16(nsec3.iterations);
                try self.writeU8(try castOrRDataErr(u8, nsec3.salt.len));
                try self.writeSlice(nsec3.salt);
                try self.writeU8(try castOrRDataErr(u8, nsec3.next_hashed_owner.len));
                try self.writeSlice(nsec3.next_hashed_owner);
                try self.writeSlice(nsec3.type_bit_maps);
            },
            .nsec3param => |nsec3p| {
                try self.writeU8(@intFromEnum(nsec3p.hash_algorithm));
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
            // OPT fixed overhead: 1(name) + 2(type) + 2(class) + 4(ttl) + 2(rdlength) = 11
            const msg_size_before_padding = ser.pos + 11 + rdlength + 4; // +4 for padding option header
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
            try ser.writeU16(12); // EDNS0 Padding option code (RFC 7830)
            try ser.writeU16(padding_len);
            // Write zero-filled padding
            try ser.ensureSpace(padding_len);
            @memset(ser.buf[ser.pos..][0..padding_len], 0);
            ser.pos += padding_len;
        }
    }

    return buf[0..ser.pos];
}

// ── Pretty printing (for CLI) ──────────────────────────────────────────

pub fn printMessage(msg: Message, writer: anytype) !void {
    const hdr = msg.header;
    var opcode_buf: [24]u8 = undefined;
    var rcode_buf: [24]u8 = undefined;
    try writer.print(";; ->>HEADER<<- opcode: {s}, status: {s}, id: {d}\n", .{
        safeTagName(OpCode, hdr.opcode, &opcode_buf), safeTagName(RCode, hdr.rcode, &rcode_buf), hdr.id,
    });
    try writer.print(";; flags:", .{});
    if (hdr.qr) try writer.print(" qr", .{});
    if (hdr.aa) try writer.print(" aa", .{});
    if (hdr.tc) try writer.print(" tc", .{});
    if (hdr.rd) try writer.print(" rd", .{});
    if (hdr.ra) try writer.print(" ra", .{});
    if (hdr.ad) try writer.print(" ad", .{});
    if (hdr.cd) try writer.print(" cd", .{});
    try writer.print("; QUERY: {d}, ANSWER: {d}, AUTHORITY: {d}, ADDITIONAL: {d}\n\n", .{
        hdr.qd_count, hdr.an_count, hdr.ns_count, hdr.ar_count,
    });

    if (msg.opt) |opt| {
        try writer.print(";; OPT PSEUDOSECTION:\n", .{});
        try writer.print("; EDNS: version: {d}, flags:", .{opt.version});
        if (opt.do_bit) try writer.print(" do", .{});
        try writer.print("; udp: {d}\n", .{opt.udp_payload_size});
        if (opt.options.len > 0) {
            try writer.print("; OPTIONS: {d}\n", .{opt.options.len});
        }
        try writer.print("\n", .{});
    }

    if (msg.questions.len > 0) {
        try writer.print(";; QUESTION SECTION:\n", .{});
        for (msg.questions) |q| {
            try printName(q.name, writer);
            var qclass_buf: [24]u8 = undefined;
            var qtype_buf: [24]u8 = undefined;
            try writer.print("\t\t{s}\t{s}\n", .{ safeTagName(RClass, q.qclass, &qclass_buf), safeTagName(RType, q.qtype, &qtype_buf) });
        }
        try writer.print("\n", .{});
    }

    if (msg.answers.len > 0) {
        try writer.print(";; ANSWER SECTION:\n", .{});
        for (msg.answers) |rr| try printResourceRecord(rr, writer);
        try writer.print("\n", .{});
    }

    if (msg.authorities.len > 0) {
        try writer.print(";; AUTHORITY SECTION:\n", .{});
        for (msg.authorities) |rr| try printResourceRecord(rr, writer);
        try writer.print("\n", .{});
    }

    if (msg.additionals.len > 0) {
        try writer.print(";; ADDITIONAL SECTION:\n", .{});
        for (msg.additionals) |rr| try printResourceRecord(rr, writer);
        try writer.print("\n", .{});
    }
}

fn printName(name: Name, writer: anytype) !void {
    if (name.labels.len == 0) {
        try writer.print(".", .{});
        return;
    }
    for (name.labels) |label| {
        try writer.print("{s}.", .{label});
    }
}

fn printResourceRecord(rr: ResourceRecord, writer: anytype) !void {
    try printName(rr.name, writer);
    var rclass_buf: [24]u8 = undefined;
    var rtype_buf: [24]u8 = undefined;
    try writer.print("\t{d}\t{s}\t{s}\t", .{ rr.ttl, safeTagName(RClass, rr.rclass, &rclass_buf), safeTagName(RType, rr.rtype, &rtype_buf) });
    switch (rr.rdata) {
        .a => |addr| try writer.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }),
        .aaaa => |addr| {
            // Print as colon-separated hex pairs
            for (0..8) |i| {
                if (i > 0) try writer.print(":", .{});
                try writer.print("{x:0>2}{x:0>2}", .{ addr[i * 2], addr[i * 2 + 1] });
            }
        },
        .ns => |name| try printName(name, writer),
        .cname => |name| try printName(name, writer),
        .ptr => |name| try printName(name, writer),
        .mx => |mx| {
            try writer.print("{d} ", .{mx.preference});
            try printName(mx.exchange, writer);
        },
        .soa => |soa| {
            try printName(soa.mname, writer);
            try writer.print(" ", .{});
            try printName(soa.rname, writer);
            try writer.print(" {d} {d} {d} {d} {d}", .{
                soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum,
            });
        },
        .txt => |txt| {
            for (txt.strings) |s| {
                try writer.print("\"{s}\" ", .{s});
            }
        },
        .rrsig => |rrsig| {
            var tc_buf: [24]u8 = undefined;
            var algo_buf: [24]u8 = undefined;
            try writer.print("{s} {d} {s} {d} {d} {d} {d} ", .{
                safeTagName(RType, rrsig.type_covered, &tc_buf),
                rrsig.labels,
                safeTagName(DnssecAlgorithm, rrsig.algorithm, &algo_buf),
                rrsig.original_ttl,
                rrsig.sig_expiration,
                rrsig.sig_inception,
                rrsig.key_tag,
            });
            try printName(rrsig.signer_name, writer);
        },
        .dnskey => |dnskey| {
            var dkalgo_buf: [24]u8 = undefined;
            try writer.print("{d} {d} {s}", .{
                dnskey.flags,
                dnskey.protocol,
                safeTagName(DnssecAlgorithm, dnskey.algorithm, &dkalgo_buf),
            });
        },
        .ds => |ds_data| {
            var dsalgo_buf: [24]u8 = undefined;
            var digest_buf: [24]u8 = undefined;
            try writer.print("{d} {s} {s} ", .{
                ds_data.key_tag,
                safeTagName(DnssecAlgorithm, ds_data.algorithm, &dsalgo_buf),
                safeTagName(DigestType, ds_data.digest_type, &digest_buf),
            });
            for (ds_data.digest) |b| {
                try writer.print("{X:0>2}", .{b});
            }
        },
        .nsec => |nsec_data| {
            try printName(nsec_data.next_domain_name, writer);
            try printTypeBitmap(nsec_data.type_bit_maps, writer);
        },
        .nsec3 => |nsec3| {
            try writer.print("{d} {d} {d} ", .{
                @intFromEnum(nsec3.hash_algorithm),
                nsec3.flags,
                nsec3.iterations,
            });
            if (nsec3.salt.len == 0) {
                try writer.print("- ", .{});
            } else {
                for (nsec3.salt) |b| try writer.print("{X:0>2}", .{b});
                try writer.print(" ", .{});
            }
            for (nsec3.next_hashed_owner) |b| {
                try writer.print("{X:0>2}", .{b});
            }
            try printTypeBitmap(nsec3.type_bit_maps, writer);
        },
        .nsec3param => |nsec3p| {
            try writer.print("{d} {d} {d} ", .{
                @intFromEnum(nsec3p.hash_algorithm),
                nsec3p.flags,
                nsec3p.iterations,
            });
            if (nsec3p.salt.len == 0) {
                try writer.print("-", .{});
            } else {
                for (nsec3p.salt) |b| try writer.print("{X:0>2}", .{b});
            }
        },
        .unknown => |data| try writer.print("<{d} bytes>", .{data.len}),
    }
    try writer.print("\n", .{});
}

fn printTypeBitmap(bitmap: []const u8, writer: anytype) !void {
    var pos: usize = 0;
    while (pos + 2 <= bitmap.len) {
        const window = bitmap[pos];
        const win_len = bitmap[pos + 1];
        pos += 2;
        if (pos + win_len > bitmap.len) break;
        for (0..win_len) |byte_idx| {
            const byte = bitmap[pos + byte_idx];
            if (byte == 0) continue;
            for (0..8) |bit_idx| {
                if (byte & (@as(u8, 0x80) >> @intCast(bit_idx)) != 0) {
                    const type_num = @as(u16, window) * 256 + @as(u16, @intCast(byte_idx)) * 8 + @as(u16, @intCast(bit_idx));
                    const rtype: RType = @enumFromInt(type_num);
                    var tbm_buf: [24]u8 = undefined;
                    try writer.print(" {s}", .{safeTagName(RType, rtype, &tbm_buf)});
                }
            }
        }
        pos += win_len;
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

test "header roundtrip" {
    const original = Header{
        .id = 0xABCD,
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
        .qd_count = 1,
        .an_count = 2,
        .ns_count = 0,
        .ar_count = 1,
    };

    var buf: [12]u8 = undefined;
    original.serialize(&buf);
    const parsed = Header.parse(&buf);

    try testing.expectEqual(original.id, parsed.id);
    try testing.expectEqual(original.qr, parsed.qr);
    try testing.expectEqual(original.opcode, parsed.opcode);
    try testing.expectEqual(original.aa, parsed.aa);
    try testing.expectEqual(original.tc, parsed.tc);
    try testing.expectEqual(original.rd, parsed.rd);
    try testing.expectEqual(original.ra, parsed.ra);
    try testing.expectEqual(original.z, parsed.z);
    try testing.expectEqual(original.ad, parsed.ad);
    try testing.expectEqual(original.cd, parsed.cd);
    try testing.expectEqual(original.rcode, parsed.rcode);
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
    try testing.expect(hdr.qr);
    try testing.expectEqual(OpCode.query, hdr.opcode);
    try testing.expect(!hdr.aa);
    try testing.expect(!hdr.tc);
    try testing.expect(hdr.rd);
    try testing.expect(hdr.ra);
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
    try testing.expect(msg.header.rd);
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
    try testing.expectEqual(msg1.header.rd, msg2.header.rd);
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
    try testing.expectError(error.EndOfData, parseMessage(testing.allocator, &[_]u8{0} ** 11));
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

    const msg = try buildQueryWithOptions(alloc, 0x1234, "example.com", .a, .{ .rd = true, .edns = .{ .do_bit = true } });

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
    const msg = try buildQuery(alloc, 0x5678, "example.com", .a);
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

    const msg = try buildQueryWithOptions(alloc, 0xABCD, "x.com", .a, .{ .rd = true, .edns = .{ .do_bit = true, .udp_payload_size = 4096 } });

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

test "EDNS0: buildQuery without edns has no opt" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const msg = try buildQueryWithOptions(alloc, 0x1111, "test.com", .aaaa, .{ .rd = false });
    try testing.expect(msg.opt == null);

    var buf: [max_udp_payload]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);

    // ar_count should be 0
    const ar_count = mem.readInt(u16, wire[10..12], .big);
    try testing.expectEqual(@as(u16, 0), ar_count);
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

/// Single-allocation variant of cloneName: the returned Name's labels slice
/// and every label byte live in one contiguous buffer. Use only with arena
/// allocators — the result must NOT be passed to `freeName` (which frees
/// each label individually). Designed for the cache read path where the
/// caller's arena owns lifetime.
pub fn cloneNameFlat(allocator: Allocator, name: Name) !Name {
    const n = name.labels.len;
    if (n == 0) return .{ .labels = &.{} };
    const slice_bytes = @sizeOf([]const u8) * n;
    var total_bytes: usize = 0;
    for (name.labels) |label| total_bytes += label.len;

    const alignment: std.mem.Alignment = comptime .fromByteUnits(@alignOf([]const u8));
    const buf = try allocator.alignedAlloc(u8, alignment, slice_bytes + total_bytes);
    const labels_ptr: [*]([]const u8) = @ptrCast(buf.ptr);
    const labels: [][]const u8 = labels_ptr[0..n];
    var offset: usize = slice_bytes;
    for (name.labels, 0..) |label, i| {
        @memcpy(buf[offset..][0..label.len], label);
        labels[i] = buf[offset..][0..label.len];
        offset += label.len;
    }
    return .{ .labels = labels };
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
    if (!msg.header.qr) return error.FormatError;
    if (!validateQuestionMatch(msg, expected_name, qtype)) {
        if (msg.header.rcode == .no_error or msg.header.rcode == .name_error) return error.FormatError;
    }
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
        .ns => |name| freeName(allocator, name),
        .cname => |name| freeName(allocator, name),
        .ptr => |name| freeName(allocator, name),
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

pub fn freeOpt(allocator: Allocator, opt: OptRecord) void {
    for (opt.options) |o| allocator.free(o.data);
    if (opt.options.len > 0) allocator.free(opt.options);
}

pub fn freeResourceRecordContents(allocator: Allocator, rrs: []const ResourceRecord) void {
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
    const long_label = "a" ** 64 ++ ".com";
    try testing.expectError(error.LabelTooLong, parseDottedName(testing.allocator, long_label));
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
    const msg = try buildQuery(arena.allocator(), 0x1234, "example.com", .a);

    try testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try testing.expect(!msg.header.qr);
    try testing.expect(msg.header.rd);
    try testing.expectEqual(@as(u16, 1), msg.header.qd_count);
    try testing.expectEqual(@as(usize, 1), msg.questions.len);
    try testing.expectEqual(RType.a, msg.questions[0].qtype);
    try testing.expectEqual(RClass.in, msg.questions[0].qclass);

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    try testing.expectEqual(msg.header.id, msg2.header.id);
    try testing.expectEqual(msg.header.rd, msg2.header.rd);
    try testing.expect(msg.questions[0].name.eql(msg2.questions[0].name));
    try testing.expectEqual(msg.questions[0].qtype, msg2.questions[0].qtype);
}

test "buildQueryWithOptions rd=false roundtrip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try buildQueryWithOptions(arena.allocator(), 0x5678, "example.com", .a, .{ .rd = false });

    try testing.expect(!msg.header.rd);
    try testing.expectEqual(@as(u16, 0x5678), msg.header.id);

    var rt_buf: [max_udp_payload]u8 = undefined;
    const msg2 = try testRoundtrip(arena.allocator(), &rt_buf, msg);

    try testing.expect(!msg2.header.rd);
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

// ── DNSSEC record type tests ────────────────────────────────────────

test "DNSKEY record parse/serialize roundtrip" {
    var pkt: [max_udp_payload]u8 = undefined;
    testHeader(&pkt, .{});

    var pos: usize = 12;
    // Name: "." (root)
    pkt[pos] = 0;
    pos += 1;
    mem.writeInt(u16, pkt[pos..][0..2], 48, .big); // DNSKEY
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 172800, .big); // TTL
    pos += 4;
    // RDATA: flags=257 (KSK), protocol=3, algorithm=8 (RSA/SHA-256), key=16 bytes
    const key_data = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const rdlen: u16 = 4 + key_data.len;
    mem.writeInt(u16, pkt[pos..][0..2], rdlen, .big);
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 257, .big); // flags
    pos += 2;
    pkt[pos] = 3; // protocol
    pos += 1;
    pkt[pos] = 8; // algorithm
    pos += 1;
    @memcpy(pkt[pos..][0..key_data.len], &key_data);
    pos += key_data.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

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
    var pkt: [max_udp_payload]u8 = undefined;
    testHeader(&pkt, .{});

    var pos: usize = 12;
    const rrname = "\x07example\x03com\x00";
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 43, .big); // DS
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 86400, .big);
    pos += 4;
    // RDATA: key_tag=20326, alg=8, digest_type=2 (SHA-256), digest=32 bytes
    const digest = [32]u8{ 0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84, 0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D };
    mem.writeInt(u16, pkt[pos..][0..2], @intCast(4 + digest.len), .big);
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 20326, .big); // key_tag
    pos += 2;
    pkt[pos] = 8; // algorithm
    pos += 1;
    pkt[pos] = 2; // digest_type (SHA-256)
    pos += 1;
    @memcpy(pkt[pos..][0..digest.len], &digest);
    pos += digest.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

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
    mem.writeInt(u32, pkt[pos..][0..4], 300, .big);
    pos += 4;

    const signer_wire = "\x07example\x03com\x00"; // example.com
    const fake_sig = [8]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    const rdlen: u16 = 18 + @as(u16, signer_wire.len) + fake_sig.len;
    mem.writeInt(u16, pkt[pos..][0..2], rdlen, .big);
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // type_covered = A
    pos += 2;
    pkt[pos] = 13; // algorithm = ECDSAP256SHA256
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
    @memcpy(pkt[pos..][0..signer_wire.len], signer_wire);
    pos += signer_wire.len;
    @memcpy(pkt[pos..][0..fake_sig.len], &fake_sig);
    pos += fake_sig.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

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
    mem.writeInt(u32, pkt[pos..][0..4], 3600, .big);
    pos += 4;

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
    const rdlen: u16 = @intCast(next_name.len + bitmap.len);
    mem.writeInt(u16, pkt[pos..][0..2], rdlen, .big);
    pos += 2;
    @memcpy(pkt[pos..][0..next_name.len], next_name);
    pos += next_name.len;
    @memcpy(pkt[pos..][0..bitmap.len], &bitmap);
    pos += bitmap.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

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
    var pkt: [max_udp_payload]u8 = undefined;
    testHeader(&pkt, .{});

    var pos: usize = 12;
    // Owner: some base32 hash label under example.com (simplified for test)
    const rrname = "\x07example\x03com\x00";
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 50, .big); // NSEC3
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 3600, .big);
    pos += 4;

    const salt = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const next_hash = [20]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 };
    const bitmap = [_]u8{ 0x00, 0x01, 0x40 }; // window 0, len 1, A bit set
    // hash_alg(1) + flags(1) + iterations(2) + salt_len(1) + salt(4) + hash_len(1) + hash(20) + bitmap(3)
    const rdlen: u16 = 1 + 1 + 2 + 1 + salt.len + 1 + next_hash.len + bitmap.len;
    mem.writeInt(u16, pkt[pos..][0..2], rdlen, .big);
    pos += 2;
    pkt[pos] = 1; // hash_algorithm (SHA-1)
    pos += 1;
    pkt[pos] = 0; // flags
    pos += 1;
    mem.writeInt(u16, pkt[pos..][0..2], 10, .big); // iterations
    pos += 2;
    pkt[pos] = @intCast(salt.len); // salt_len
    pos += 1;
    @memcpy(pkt[pos..][0..salt.len], &salt);
    pos += salt.len;
    pkt[pos] = @intCast(next_hash.len); // hash_len
    pos += 1;
    @memcpy(pkt[pos..][0..next_hash.len], &next_hash);
    pos += next_hash.len;
    @memcpy(pkt[pos..][0..bitmap.len], &bitmap);
    pos += bitmap.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

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
    var pkt: [max_udp_payload]u8 = undefined;
    testHeader(&pkt, .{});

    var pos: usize = 12;
    const rrname = "\x07example\x03com\x00";
    @memcpy(pkt[pos..][0..rrname.len], rrname);
    pos += rrname.len;
    mem.writeInt(u16, pkt[pos..][0..2], 51, .big); // NSEC3PARAM
    pos += 2;
    mem.writeInt(u16, pkt[pos..][0..2], 1, .big); // IN
    pos += 2;
    mem.writeInt(u32, pkt[pos..][0..4], 0, .big); // TTL=0 per RFC 5155
    pos += 4;

    const salt = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    mem.writeInt(u16, pkt[pos..][0..2], @intCast(5 + salt.len), .big);
    pos += 2;
    pkt[pos] = 1; // hash_algorithm
    pos += 1;
    pkt[pos] = 0; // flags
    pos += 1;
    mem.writeInt(u16, pkt[pos..][0..2], 0, .big); // iterations
    pos += 2;
    pkt[pos] = @intCast(salt.len);
    pos += 1;
    @memcpy(pkt[pos..][0..salt.len], &salt);
    pos += salt.len;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const msg = try parseMessage(arena.allocator(), pkt[0..pos]);

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
    const https: RType = @enumFromInt(65);
    try testing.expectEqualStrings("65", safeTagName(RType, https, &buf));
    const svcb: RType = @enumFromInt(64);
    try testing.expectEqualStrings("64", safeTagName(RType, svcb, &buf));
    const caa: RType = @enumFromInt(257);
    try testing.expectEqualStrings("257", safeTagName(RType, caa, &buf));

    // Unknown RCode
    const rcode7: RCode = @enumFromInt(7);
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
