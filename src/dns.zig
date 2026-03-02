const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

// ── Constants ──────────────────────────────────────────────────────────

pub const max_label_len = 63;
pub const max_name_len = 253;
pub const header_len = 12;
pub const max_udp_payload = 512;

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
    _,
};

pub const RClass = enum(u16) {
    in = 1,
    cs = 2,
    ch = 3,
    hs = 4,
    _,
};

// ── Error Set ──────────────────────────────────────────────────────────

pub const Error = error{
    EndOfData,
    LabelTooLong,
    NameTooLong,
    CompressionPointerLoop,
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
    z: u3,
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
            .z = @truncate(flags >> 4),
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
        flags |= @as(u16, self.z) << 4;
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
            @memcpy(buf[pos..][0..label.len], label);
            pos += label.len;
        }
        buf[pos] = 0;
        return buf;
    }

    pub fn toStr(self: Name) []const u8 {
        // Returns a formatted representation; caller should use format() for stack buffer
        _ = self;
        return "<Name>";
    }

    pub fn eql(a: Name, b: Name) bool {
        if (a.labels.len != b.labels.len) return false;
        for (a.labels, b.labels) |la, lb| {
            if (!std.ascii.eqlIgnoreCase(la, lb)) return false;
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

pub const RData = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    ns: Name,
    cname: Name,
    ptr: Name,
    mx: MxData,
    soa: SoaData,
    txt: TxtData,
    unknown: []const u8,
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
};

// ── Message ────────────────────────────────────────────────────────────

pub const Message = struct {
    header: Header,
    questions: []const Question,
    answers: []const ResourceRecord,
    authorities: []const ResourceRecord,
    additionals: []const ResourceRecord,
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

pub const QueryOptions = struct {
    rd: bool = true,
};

pub fn buildQuery(allocator: Allocator, id: u16, name_str: []const u8, qtype: RType) Error!Message {
    return buildQueryWithOptions(allocator, id, name_str, qtype, .{});
}

pub fn buildQueryWithOptions(allocator: Allocator, id: u16, name_str: []const u8, qtype: RType, options: QueryOptions) Error!Message {
    const name = try parseDottedName(allocator, name_str);
    const questions = allocator.alloc(Question, 1) catch return error.OutOfMemory;
    questions[0] = .{ .name = name, .qtype = qtype, .qclass = .in };

    const empty_rr = allocator.alloc(ResourceRecord, 0) catch return error.OutOfMemory;
    const empty_rr2 = allocator.alloc(ResourceRecord, 0) catch return error.OutOfMemory;
    const empty_rr3 = allocator.alloc(ResourceRecord, 0) catch return error.OutOfMemory;

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
            .rcode = .no_error,
            .qd_count = 1,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = questions,
        .answers = empty_rr,
        .authorities = empty_rr2,
        .additionals = empty_rr3,
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

    pub fn parseName(self: *Parser, allocator: Allocator) Error!Name {
        var labels: ArrayList([]const u8) = .empty;
        var total_len: usize = 0;
        var jumps: usize = 0;
        const max_jumps = 128;
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
                cursor = offset;
            } else if (label_type == 0x00) {
                // Normal label
                const label_len: usize = len_byte;
                if (label_len > max_label_len) return error.LabelTooLong;
                cursor += 1;
                if (cursor + label_len > self.msg.len) return error.EndOfData;
                const label_data = self.msg[cursor..][0..label_len];
                const duped = allocator.dupe(u8, label_data) catch return error.OutOfMemory;
                labels.append(allocator, duped) catch return error.OutOfMemory;
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
            .ns => return .{ .ns = try self.parseName(allocator) },
            .cname => return .{ .cname = try self.parseName(allocator) },
            .ptr => return .{ .ptr = try self.parseName(allocator) },
            .mx => {
                const preference = try self.readU16();
                const exchange = try self.parseName(allocator);
                return .{ .mx = .{ .preference = preference, .exchange = exchange } };
            },
            .soa => {
                const mname = try self.parseName(allocator);
                const rname = try self.parseName(allocator);
                const serial = try self.readU32();
                const refresh = try self.readU32();
                const retry = try self.readU32();
                const expire = try self.readU32();
                const minimum = try self.readU32();
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
                    const str_data = try self.readSlice(str_len);
                    const duped = allocator.dupe(u8, str_data) catch return error.OutOfMemory;
                    strings.append(allocator, duped) catch return error.OutOfMemory;
                }
                return .{ .txt = .{
                    .strings = strings.toOwnedSlice(allocator) catch return error.OutOfMemory,
                } };
            },
            _ => {
                const data = try self.readSlice(rdlength);
                const duped = allocator.dupe(u8, data) catch return error.OutOfMemory;
                return .{ .unknown = duped };
            },
        }
    }
};

// ── Top-level parse ────────────────────────────────────────────────────

pub fn parseMessage(allocator: Allocator, bytes: []const u8) Error!Message {
    if (bytes.len < header_len) return error.EndOfData;

    const hdr = Header.parse(bytes[0..12]);
    var parser = Parser{ .msg = bytes, .pos = 12 };

    var questions: ArrayList(Question) = .empty;
    for (0..hdr.qd_count) |_| {
        questions.append(allocator, try parser.parseQuestion(allocator)) catch return error.OutOfMemory;
    }

    var answers: ArrayList(ResourceRecord) = .empty;
    for (0..hdr.an_count) |_| {
        answers.append(allocator, try parser.parseResourceRecord(allocator)) catch return error.OutOfMemory;
    }

    var authorities: ArrayList(ResourceRecord) = .empty;
    for (0..hdr.ns_count) |_| {
        authorities.append(allocator, try parser.parseResourceRecord(allocator)) catch return error.OutOfMemory;
    }

    var additionals: ArrayList(ResourceRecord) = .empty;
    for (0..hdr.ar_count) |_| {
        additionals.append(allocator, try parser.parseResourceRecord(allocator)) catch return error.OutOfMemory;
    }

    return .{
        .header = hdr,
        .questions = questions.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .answers = answers.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .authorities = authorities.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .additionals = additionals.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

// ── Serializer ─────────────────────────────────────────────────────────

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
        try self.writeName(rr.name);
        try self.writeU16(@intFromEnum(rr.rtype));
        try self.writeU16(@intFromEnum(rr.rclass));
        try self.writeU32(rr.ttl);

        // Serialize rdata to a temporary position to measure length
        const rdlength_pos = self.pos;
        try self.writeU16(0); // placeholder
        const rdata_start = self.pos;
        try self.writeRData(rr.rdata);
        const rdata_len = self.pos - rdata_start;

        // Patch rdlength
        mem.writeInt(u16, self.buf[rdlength_pos..][0..2], @intCast(rdata_len), .big);
    }

    fn writeRData(self: *Serializer, rdata: RData) Error!void {
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
                    try self.writeU8(@intCast(s.len));
                    try self.writeSlice(s);
                }
            },
            .unknown => |data| try self.writeSlice(data),
        }
    }
};

pub fn serializeMessage(buf: []u8, msg: Message) Error![]const u8 {
    var ser = Serializer.init(buf);
    try ser.writeHeader(msg.header);
    for (msg.questions) |q| try ser.writeQuestion(q);
    for (msg.answers) |rr| try ser.writeResourceRecord(rr);
    for (msg.authorities) |rr| try ser.writeResourceRecord(rr);
    for (msg.additionals) |rr| try ser.writeResourceRecord(rr);
    return buf[0..ser.pos];
}

// ── Pretty printing (for CLI) ──────────────────────────────────────────

pub fn printMessage(msg: Message, writer: anytype) !void {
    const hdr = msg.header;
    try writer.print(";; ->>HEADER<<- opcode: {s}, status: {s}, id: {d}\n", .{
        @tagName(hdr.opcode), @tagName(hdr.rcode), hdr.id,
    });
    try writer.print(";; flags:", .{});
    if (hdr.qr) try writer.print(" qr", .{});
    if (hdr.aa) try writer.print(" aa", .{});
    if (hdr.tc) try writer.print(" tc", .{});
    if (hdr.rd) try writer.print(" rd", .{});
    if (hdr.ra) try writer.print(" ra", .{});
    try writer.print("; QUERY: {d}, ANSWER: {d}, AUTHORITY: {d}, ADDITIONAL: {d}\n\n", .{
        hdr.qd_count, hdr.an_count, hdr.ns_count, hdr.ar_count,
    });

    if (msg.questions.len > 0) {
        try writer.print(";; QUESTION SECTION:\n", .{});
        for (msg.questions) |q| {
            try printName(q.name, writer);
            try writer.print("\t\t{s}\t{s}\n", .{ @tagName(q.qclass), @tagName(q.qtype) });
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
    try writer.print("\t{d}\t{s}\t{s}\t", .{ rr.ttl, @tagName(rr.rclass), @tagName(rr.rtype) });
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
        .unknown => |data| try writer.print("<{d} bytes>", .{data.len}),
    }
    try writer.print("\n", .{});
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
    var parser = Parser{ .msg = data, .pos = 0 };
    const name = try parser.parseName(testing.allocator);
    defer testing.allocator.free(name.labels);
    defer for (name.labels) |l| testing.allocator.free(l);

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
    var parser = Parser{ .msg = data, .pos = 13 };
    const name = try parser.parseName(testing.allocator);
    defer testing.allocator.free(name.labels);
    defer for (name.labels) |l| testing.allocator.free(l);

    try testing.expectEqual(@as(usize, 3), name.labels.len);
    try testing.expectEqualStrings("foo", name.labels[0]);
    try testing.expectEqualStrings("example", name.labels[1]);
    try testing.expectEqualStrings("com", name.labels[2]);
    // pos should advance past the pointer (13 + 3+1 + 2 = 19)
    try testing.expectEqual(@as(usize, 19), parser.pos);
}

test "name parsing - pointer loop detection" {
    // Two pointers pointing at each other
    const data = [_]u8{ 0xC0, 0x02, 0xC0, 0x00 };
    var parser = Parser{ .msg = &data, .pos = 0 };
    try testing.expectError(error.CompressionPointerLoop, parser.parseName(testing.allocator));
}

test "full query packet parse" {
    // A DNS query for "example.com" type A class IN
    var pkt: [512]u8 = undefined;
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

    const msg = try parseMessage(testing.allocator, pkt[0..pos]);
    defer {
        for (msg.questions) |q| {
            for (q.name.labels) |l| testing.allocator.free(l);
            testing.allocator.free(q.name.labels);
        }
        testing.allocator.free(msg.questions);
        testing.allocator.free(msg.answers);
        testing.allocator.free(msg.authorities);
        testing.allocator.free(msg.additionals);
    }

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
    var pkt: [512]u8 = undefined;
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

    const msg = try parseMessage(testing.allocator, pkt[0..pos]);
    defer freeMessage(testing.allocator, msg);

    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    const rr = msg.answers[0];
    try testing.expectEqual(RType.a, rr.rtype);
    try testing.expectEqual(@as(u32, 300), rr.ttl);
    try testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &rr.rdata.a);
}

test "SOA record parsing" {
    var pkt: [512]u8 = undefined;
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

    const msg = try parseMessage(testing.allocator, pkt[0..pos]);
    defer freeMessage(testing.allocator, msg);

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
    var pkt: [512]u8 = undefined;
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

    const msg = try parseMessage(testing.allocator, pkt[0..pos]);
    defer freeMessage(testing.allocator, msg);

    const mx = msg.answers[0].rdata.mx;
    try testing.expectEqual(@as(u16, 10), mx.preference);
    try testing.expectEqualStrings("mail", mx.exchange.labels[0]);
}

test "TXT record parsing" {
    var pkt: [512]u8 = undefined;
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

    const msg = try parseMessage(testing.allocator, pkt[0..pos]);
    defer freeMessage(testing.allocator, msg);

    const txt = msg.answers[0].rdata.txt;
    try testing.expectEqual(@as(usize, 2), txt.strings.len);
    try testing.expectEqualStrings("v=spf1 include:example.com", txt.strings[0]);
    try testing.expectEqualStrings("hello", txt.strings[1]);
}

test "roundtrip: parse -> serialize -> parse -> compare" {
    // Build a query packet
    var original_pkt: [512]u8 = undefined;
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
    const msg1 = try parseMessage(testing.allocator, original_pkt[0..pos]);
    defer freeMessage(testing.allocator, msg1);

    // Serialize
    var ser_buf: [512]u8 = undefined;
    const serialized = try serializeMessage(&ser_buf, msg1);

    // Parse again
    const msg2 = try parseMessage(testing.allocator, serialized);
    defer freeMessage(testing.allocator, msg2);

    // Compare
    try testing.expectEqual(msg1.header.id, msg2.header.id);
    try testing.expectEqual(msg1.header.rd, msg2.header.rd);
    try testing.expectEqual(msg1.questions.len, msg2.questions.len);
    try testing.expectEqual(msg1.answers.len, msg2.answers.len);
    try testing.expect(msg1.questions[0].name.eql(msg2.questions[0].name));
    try testing.expect(msg1.answers[0].name.eql(msg2.answers[0].name));
    try testing.expectEqualSlices(u8, &msg1.answers[0].rdata.a, &msg2.answers[0].rdata.a);
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

test "edge case: max-length label" {
    var pkt: [512]u8 = undefined;
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

    const msg = try parseMessage(testing.allocator, pkt[0..81]);
    defer freeMessage(testing.allocator, msg);

    try testing.expectEqual(@as(usize, 1), msg.questions.len);
    try testing.expectEqual(@as(usize, 63), msg.questions[0].name.labels[0].len);
}

test "edge case: oversized label" {
    var pkt: [512]u8 = undefined;
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
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // parseMessage should either return a valid result or an error, never panic
            if (parseMessage(testing.allocator, input)) |msg| {
                freeMessage(testing.allocator, msg);
            } else |_| {
                // Any error is fine — just must not panic
            }
        }
    };
    try testing.fuzz(Context{}, Context.testOne, .{});
}

// ── Test helper: free all allocations from a parsed message ────────────

fn freeName(allocator: Allocator, name: Name) void {
    for (name.labels) |l| allocator.free(l);
    allocator.free(name.labels);
}

fn freeRData(allocator: Allocator, rdata: RData) void {
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
        .unknown => |data| allocator.free(data),
    }
}

pub fn freeMessage(allocator: Allocator, msg: Message) void {
    for (msg.questions) |q| freeName(allocator, q.name);
    allocator.free(msg.questions);
    for (msg.answers) |rr| {
        freeName(allocator, rr.name);
        freeRData(allocator, rr.rdata);
    }
    allocator.free(msg.answers);
    for (msg.authorities) |rr| {
        freeName(allocator, rr.name);
        freeRData(allocator, rr.rdata);
    }
    allocator.free(msg.authorities);
    for (msg.additionals) |rr| {
        freeName(allocator, rr.name);
        freeRData(allocator, rr.rdata);
    }
    allocator.free(msg.additionals);
}

test "parseDottedName basic" {
    const name = try parseDottedName(testing.allocator, "example.com");
    defer {
        for (name.labels) |l| testing.allocator.free(l);
        testing.allocator.free(name.labels);
    }
    try testing.expectEqual(@as(usize, 2), name.labels.len);
    try testing.expectEqualStrings("example", name.labels[0]);
    try testing.expectEqualStrings("com", name.labels[1]);
}

test "parseDottedName trailing dot" {
    const name = try parseDottedName(testing.allocator, "example.com.");
    defer {
        for (name.labels) |l| testing.allocator.free(l);
        testing.allocator.free(name.labels);
    }
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

test "buildQuery roundtrip" {
    const msg = try buildQuery(testing.allocator, 0x1234, "example.com", .a);
    defer freeMessage(testing.allocator, msg);

    try testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try testing.expect(!msg.header.qr);
    try testing.expect(msg.header.rd);
    try testing.expectEqual(@as(u16, 1), msg.header.qd_count);
    try testing.expectEqual(@as(usize, 1), msg.questions.len);
    try testing.expectEqual(RType.a, msg.questions[0].qtype);
    try testing.expectEqual(RClass.in, msg.questions[0].qclass);

    // Serialize and re-parse
    var buf: [512]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);
    const msg2 = try parseMessage(testing.allocator, wire);
    defer freeMessage(testing.allocator, msg2);

    try testing.expectEqual(msg.header.id, msg2.header.id);
    try testing.expectEqual(msg.header.rd, msg2.header.rd);
    try testing.expect(msg.questions[0].name.eql(msg2.questions[0].name));
    try testing.expectEqual(msg.questions[0].qtype, msg2.questions[0].qtype);
}

test "buildQueryWithOptions rd=false roundtrip" {
    const msg = try buildQueryWithOptions(testing.allocator, 0x5678, "example.com", .a, .{ .rd = false });
    defer freeMessage(testing.allocator, msg);

    try testing.expect(!msg.header.rd);
    try testing.expectEqual(@as(u16, 0x5678), msg.header.id);

    // Serialize and re-parse to verify rd bit survives wire format
    var buf: [512]u8 = undefined;
    const wire = try serializeMessage(&buf, msg);
    const msg2 = try parseMessage(testing.allocator, wire);
    defer freeMessage(testing.allocator, msg2);

    try testing.expect(!msg2.header.rd);
    try testing.expectEqual(@as(u16, 0x5678), msg2.header.id);
    try testing.expect(msg.questions[0].name.eql(msg2.questions[0].name));
}
