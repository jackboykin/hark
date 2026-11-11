//! The client's reply on the wire: header, EDNS0 OPT, the rebinding
//! scrub, the truncation cascade, error responses, and per-RFC query
//! validation. Pure (no I/O); serve.zig does the I/O. Which records a
//! client is owed is answer.zig's (`Keep`); this only writes them.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const rebinding = @import("rebinding.zig");

pub const Reply = struct {
    rcode: dns.RCode,
    ad: bool = false,
    ede: ?dns.Ede = null,
    /// Not the public DNS's answer, so never scrubbed for rebinding.
    local: bool = false,
    aa: bool = false,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
    additionals: []const dns.ResourceRecord = &.{},
};

pub const ResponseContext = struct {
    query_id: u16,
    opcode: dns.OpCode,
    rd: bool,
    cd: bool,
    question: dns.Question,
    client_edns: bool,
    client_do: bool,
    max_udp_payload: u16,
    tcp_keepalive: ?u16 = null,
    rebinding: *const rebinding.Config = &rebinding.Config.off,

    pub fn fromQuery(query: dns.Query, max_udp_payload: u16) ResponseContext {
        return .{
            .query_id = query.header.id,
            .opcode = query.header.flags.opcode,
            .rd = query.header.flags.rd,
            .cd = query.header.flags.cd,
            .question = query.question.?,
            .client_edns = query.edns != null,
            .client_do = query.edns != null and query.edns.?.do_bit,
            .max_udp_payload = max_udp_payload,
        };
    }
};

pub fn buildResponseWire(
    wire_buf: []u8,
    ctx: ResponseContext,
    reply: Reply,
    alloc: mem.Allocator,
) ?[]const u8 {
    const rb = (if (reply.local) &rebinding.Config.off else ctx.rebinding).*;

    // Scrubbed here, at the wire, so fresh answers and cache hits pass alike.
    // Every section: RFC 9460 §4.2 has clients use addresses from additional.
    // Out of memory returns null, never an unscrubbed reply.
    const answers = rebinding.scrub(alloc, reply.answers, rb) catch return null;
    const authorities = rebinding.scrub(alloc, reply.authorities, rb) catch return null;
    const additionals = rebinding.scrub(alloc, reply.additionals, rb) catch return null;
    const scrubbed = answers.len != reply.answers.len or authorities.len != reply.authorities.len;

    var options_buf: [3]dns.EdnsOption = undefined;
    var options: std.ArrayList(dns.EdnsOption) = .initBuffer(&options_buf);
    var keepalive_data: [2]u8 = undefined;
    if (ctx.tcp_keepalive) |timeout| {
        std.mem.writeInt(u16, &keepalive_data, timeout, .big);
        options.appendAssumeCapacity(.{ .code = dns.edns_opt_tcp_keepalive, .data = &keepalive_data });
    }
    var ede_bufs: [2][64]u8 = undefined;
    if (reply.ede) |e| options.appendAssumeCapacity(e.option(&ede_bufs[0]));
    // A scrubbed reply goes out with what is left, never as REFUSED or
    // SERVFAIL: those send a stub on to its next resolver, which may not
    // scrub.
    if (scrubbed) options.appendAssumeCapacity((dns.Ede{ .code = .blocked, .text = "rebinding" }).option(&ede_bufs[1]));
    const opt: ?dns.OptRecord = if (ctx.client_edns) .{
        .udp_payload_size = dns.edns_udp_payload,
        .extended_rcode = 0,
        .version = 0,
        .do_bit = ctx.client_do,
        .options = options.items,
    } else null;

    const hdr: dns.Header = .{
        .id = ctx.query_id,
        .flags = .{
            .qr = true,
            .opcode = ctx.opcode,
            .aa = reply.aa,
            .rd = ctx.rd,
            .ra = true,
            .ad = reply.ad and !scrubbed,
            .cd = ctx.cd,
            .rcode = reply.rcode,
        },
    };
    const sections: dns.Sections = .{ .answers = answers, .authorities = authorities, .additionals = additionals };

    var ends: dns.SectionEnds = .{};
    if (dns.serializeEnds(wire_buf[0..@min(wire_buf.len, ctx.max_udp_payload)], hdr, ctx.question, sections, opt, &ends) catch null) |wire| return wire;

    // Pointers only reach back, so the message up to a section's end plus a
    // fresh OPT is a valid message: rewind instead of serializing again.
    // Dropping additionals alone sets no TC; dropping authority or answers
    // does (RFC 2181 §9). The last step also clips to the payload.
    for ([_]usize{ ends.authorities, ends.answers, ends.question }, 1..) |end, dropped| {
        if (end == 0) continue;
        var ser = dns.Serializer{ .buf = wire_buf, .pos = end };
        if (opt) |o| ser.writeOpt(o) catch continue;
        const kept: dns.Sections = .{
            .answers = if (dropped < 3) answers else &.{},
            .authorities = if (dropped < 2) authorities else &.{},
        };
        var cut = kept.header(hdr, true, opt != null);
        cut.flags.tc = dropped >= 2;
        cut.serialize(wire_buf[0..12]);
        if (ser.pos <= ctx.max_udp_payload or dropped == 3) return wire_buf[0..@min(ser.pos, ctx.max_udp_payload)];
    }
    return null;
}

/// A reply that carries only an rcode, to a query that may not have parsed.
pub const Refusal = struct {
    id: u16,
    opcode: dns.OpCode = .query,
    rcode: dns.RCode,
    extended_rcode: u8 = 0,
    rd: bool,
    question: ?dns.Question = null,
    client: ?dns.Edns = null,
};

pub fn serializeErrorResponse(wire_buf: *[dns.max_udp_payload]u8, e: Refusal) []const u8 {
    const opt: ?dns.OptRecord = if (e.client) |o| .{
        .udp_payload_size = dns.edns_udp_payload,
        .extended_rcode = e.extended_rcode,
        .version = 0,
        .do_bit = o.do_bit,
        .options = &.{},
    } else null;
    const msg = dns.Message{
        .header = .{
            .id = e.id,
            .flags = .{
                .qr = true,
                .opcode = e.opcode,
                .rd = e.rd,
                .ra = true,
                .rcode = e.rcode,
            },
        },
        .question = e.question,
        .opt = opt,
    };
    // At most one question, so 12 + 259 + 11 octets: it fits.
    return dns.serializeMessage(wire_buf, msg) catch unreachable;
}

pub fn validateQuery(query: dns.Query) ?struct { rcode: dns.RCode, extended_rcode: u8 = 0 } {
    if (query.header.flags.qr) return .{ .rcode = .format_error };
    if (query.header.flags.opcode != .query) return .{ .rcode = .not_implemented };
    const question = query.question orelse return .{ .rcode = .format_error };
    // RFC 6891 §6.1.3: BADVERS is 16, split as header RCODE 0 and extended
    // RCODE 1.
    if (query.edns) |edns| if (edns.version != 0) return .{ .rcode = .no_error, .extended_rcode = 1 };
    if (question.qclass != .in) return .{ .rcode = .refused };
    return null;
}

fn testCtx(question: dns.Question, over: anytype) ResponseContext {
    var ctx: ResponseContext = .{
        .query_id = 0,
        .opcode = .query,
        .rd = true,
        .cd = false,
        .question = question,
        .client_edns = false,
        .client_do = false,
        .max_udp_payload = dns.max_udp_payload,
    };
    inline for (@typeInfo(@TypeOf(over)).@"struct".field_names) |f| @field(ctx, f) = @field(over, f);
    return ctx;
}

test "buildResponseWire carries EDE only to an EDNS client" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const question: dns.Question = .{ .name = try dns.parseDottedName(a, "example.com"), .qtype = .a, .qclass = .in };
    const servfail: Reply = .{ .rcode = .server_failure, .ede = .{ .code = .dnssec_bogus, .text = "rrsig failed to verify" } };
    var ctx = testCtx(question, .{ .client_edns = true });

    var buf: [dns.max_udp_payload]u8 = undefined;
    const opt = (try dns.parseMessage(a, buildResponseWire(&buf, ctx, servfail, a).?)).opt.?;
    try testing.expectEqual(@as(usize, 1), opt.options.len);
    try testing.expectEqual(dns.edns_opt_ede, opt.options[0].code);
    try testing.expectEqualSlices(u8, "\x00\x06rrsig failed to verify", opt.options[0].data);

    ctx.client_edns = false;
    try testing.expectEqual(null, (try dns.parseMessage(a, buildResponseWire(&buf, ctx, servfail, a).?)).opt);
}

test "buildResponseWire returns null on OOM rather than an unscrubbed reply" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const question: dns.Question = .{ .name = name, .qtype = .a, .qclass = .in };
    const answers = [_]dns.ResourceRecord{
        .fixture(.{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 192, 168, 0, 1 } } }),
        .fixture(.{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 93, 184, 216, 34 } } }),
    };
    const scrub_on = rebinding.Config{ .enabled = true };

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var buf: [dns.max_udp_payload]u8 = undefined;
    const result = buildResponseWire(&buf, testCtx(question, .{ .rebinding = &scrub_on }), .{ .rcode = .no_error, .answers = &answers }, failing.allocator());

    try testing.expect(result == null);
}

test "serializeErrorResponse produces valid DNS message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, .{ .id = 0xABCD, .rcode = .refused, .rd = true, .question = .{ .name = name, .qtype = .a, .qclass = .in } });

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0xABCD), parsed.header.id);
    try testing.expectEqual(dns.RCode.refused, parsed.header.flags.rcode);
    try testing.expectEqual(true, parsed.header.flags.rd);
    try testing.expectEqual(true, parsed.header.flags.ra);
    try testing.expectEqual(true, parsed.header.flags.qr);
    try testing.expectEqual(@as(u16, 1), parsed.header.qd_count);
}

const test_query: dns.Query = .{
    .header = .{ .id = 0, .flags = std.mem.zeroes(dns.Header.Flags), .qd_count = 1 },
    .question = .{ .name = .lit("example.com"), .qtype = .a, .qclass = .in },
    .edns = null,
};

test "validateQuery rejects QR=1 (response posing as query)" {
    var spoofed = test_query;
    spoofed.header.flags.qr = true;

    try testing.expectEqual(dns.RCode.format_error, validateQuery(spoofed).?.rcode);
}

test "validateQuery returns BADVERS for unsupported EDNS version" {
    var query = test_query;
    query.edns = .{ .udp_payload_size = 4096, .version = 1, .do_bit = false };

    const fail = validateQuery(query).?;
    try testing.expectEqual(dns.RCode.no_error, fail.rcode);
    try testing.expectEqual(@as(u8, 1), fail.extended_rcode);
}

test "serializeErrorResponse echoes client OPCODE (RFC 1035 §4.1.1)" {
    const opcode_update: dns.OpCode = @fromBackingInt(@intCast(5));
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, .{ .id = 0x9999, .opcode = opcode_update, .rcode = .not_implemented, .rd = false });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u4, 5), @backingInt(parsed.header.flags.opcode));
    try testing.expectEqual(dns.RCode.not_implemented, parsed.header.flags.rcode);
}

test "buildResponseWire truncation cascade: additionals drop silently, authority/answers drop with TC=1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const question: dns.Question = .{ .name = name, .qtype = .a, .qclass = .in };

    var ns_authorities: [12]dns.ResourceRecord = undefined;
    for (&ns_authorities, 0..) |*rr, i| {
        const ns_label = try a.print("ns{d}.long.example.com.", .{i});
        const ns_name = try dns.parseDottedName(a, ns_label);
        rr.* = .fixture(.{
            .name = name,
            .rtype = .ns,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .ns = ns_name },
        });
    }
    const a_record: dns.ResourceRecord = .fixture(.{
        .name = name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 60,
        .rdata = .{ .a = .{ 192, 0, 2, 1 } },
    });

    const reply: Reply = .{
        .rcode = .no_error,
        .answers = &.{a_record},
        .authorities = &ns_authorities,
        .additionals = &.{ a_record, a_record, a_record },
    };

    const rows = [_]struct { max: u16, tc: bool, an: u16, ns: u16 }{
        .{ .max = 300, .tc = false, .an = 1, .ns = 12 },
        .{ .max = 100, .tc = true, .an = 1, .ns = 0 },
        .{ .max = 40, .tc = true, .an = 0, .ns = 0 },
    };
    var buf: [1024]u8 = undefined;
    for ([_]usize{ 300, 1024 }) |cap| for (rows) |row| {
        const wire = buildResponseWire(buf[0..cap], testCtx(question, .{ .rd = false, .client_edns = true, .max_udp_payload = row.max }), reply, a).?;
        try testing.expect(wire.len <= row.max);
        const parsed = try dns.parseMessage(a, wire);
        try testing.expectEqual(row.tc, parsed.header.flags.tc);
        try testing.expectEqual(row.an, parsed.header.an_count);
        try testing.expectEqual(row.ns, parsed.header.ns_count);
        try testing.expectEqual(@as(u16, 1), parsed.header.ar_count);
        try testing.expectEqual(@as(usize, 0), parsed.additionals.len);
        try testing.expectEqual(dns.edns_udp_payload, parsed.opt.?.udp_payload_size);
    };
}

test "buildResponseWire: an authority section past a u16 of records truncates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const nsec: dns.ResourceRecord = .fixture(.{ .name = name, .rtype = .nsec, .rclass = .in, .ttl = 300, .rdata = .{ .nsec = .{ .next_domain_name = name, .type_bit_maps = "" } } });
    const authorities = try a.alloc(dns.ResourceRecord, 1 << 16);
    @memset(authorities, nsec);

    var buf: [dns.max_message_len]u8 = undefined;
    const wire = buildResponseWire(&buf, testCtx(.{ .name = name, .qtype = .a, .qclass = .in }, .{ .client_do = true, .max_udp_payload = dns.max_message_len }), .{ .rcode = .name_error, .authorities = authorities }, a).?;
    const parsed = try dns.parseMessage(a, wire);
    try testing.expect(parsed.header.flags.tc);
    try testing.expectEqual(@as(u16, 0), parsed.header.ns_count);
}

test "serializeErrorResponse answers an EDNS query with OPT (RFC 6891 §6.1.1)" {
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, .{ .id = 0x1234, .rcode = .no_error, .extended_rcode = 1, .rd = false, .client = .{ .udp_payload_size = 512, .version = 1, .do_bit = true } });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(dns.RCode.no_error, parsed.header.flags.rcode);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u8, 1), parsed.opt.?.extended_rcode);
    try testing.expectEqual(dns.edns_udp_payload, parsed.opt.?.udp_payload_size);
    try testing.expect(parsed.opt.?.do_bit);
}

test "buildResponseWire: the rebinding scrub reaches additionals" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const zone = try dns.parseDottedName(a, "example.com");
    const glue = try dns.parseDottedName(a, "ns.example.com");
    const reply: Reply = .{
        .rcode = .no_error,
        .additionals = &.{.fixture(.{ .name = glue, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 168, 1, 1 } } })},
    };
    const scrub_on = rebinding.Config{ .enabled = true };
    for ([_]*const rebinding.Config{ &rebinding.Config.off, &scrub_on }, [_]u16{ 1, 0 }) |rb, kept| {
        var buf: [dns.max_udp_payload]u8 = undefined;
        const wire = buildResponseWire(&buf, testCtx(.{ .name = zone, .qtype = .a, .qclass = .in }, .{ .rebinding = rb }), reply, a).?;
        try testing.expectEqual(kept, (try dns.parseMessage(a, wire)).header.ar_count);
    }
}

test "buildResponseWire: a local answer bypasses the rebinding scrub; any other does not" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const scrub_on = rebinding.Config{ .enabled = true };
    const localhost = try dns.parseDottedName(a, "localhost");
    const loopback: dns.ResourceRecord = .fixture(.{ .name = localhost, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 127, 0, 0, 1 } } });
    for ([_]bool{ true, false }) |local| {
        var buf: [dns.max_udp_payload]u8 = undefined;
        const wire = buildResponseWire(&buf, testCtx(.{ .name = localhost, .qtype = .a, .qclass = .in }, .{ .rebinding = &scrub_on }), .{ .rcode = .no_error, .local = local, .answers = &.{loopback} }, a).?;
        try testing.expectEqual(@intFromBool(local), (try dns.parseMessage(a, wire)).header.an_count);
    }
}

test "buildResponseWire: a rebinding scrub clears AD" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const scrub_on = rebinding.Config{ .enabled = true };
    for ([_][4]u8{ .{ 93, 184, 216, 34 }, .{ 192, 168, 1, 1 } }, [_]bool{ true, false }) |ip, ad| {
        const answers = [_]dns.ResourceRecord{.fixture(.{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = ip } })};
        var buf: [dns.max_udp_payload]u8 = undefined;
        const wire = buildResponseWire(&buf, testCtx(.{ .name = name, .qtype = .a, .qclass = .in }, .{ .client_edns = true, .client_do = true, .rebinding = &scrub_on }), .{ .rcode = .no_error, .ad = true, .answers = &answers }, a).?;
        try testing.expectEqual(ad, (try dns.parseMessage(a, wire)).header.flags.ad);
    }
}
