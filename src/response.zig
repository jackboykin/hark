/// The client's reply on the wire: header, EDNS0 OPT, the rebinding
/// scrub, the truncation cascade, error responses, and per-RFC query
/// validation. Pure (no I/O); serve.zig does the I/O. Which records a
/// client is owed is answer.zig's (`Keep`); this only writes them.
const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const rebinding = @import("rebinding.zig");
const special_use = @import("special_use.zig");

/// What is sent: the rcode, AD as the shaper judged it, and the records.
pub const Reply = struct {
    rcode: dns.RCode,
    ad: bool = false,
    answers: []const dns.WireRecord = &.{},
    authorities: []const dns.WireRecord = &.{},
    additionals: []const dns.WireRecord = &.{},
};

pub const ResponseContext = struct {
    query_id: u16,
    opcode: dns.OpCode,
    rd: bool,
    cd: bool,
    questions: []const dns.Question,
    client_edns: bool,
    client_do: bool,
    client_wants_ad: bool,
    max_udp_payload: u16,
    /// RFC 7828 edns-tcp-keepalive TIMEOUT (100-ms units). Emitted only
    /// when non-null AND the client sent EDNS — null on UDP, or when
    /// the operator disabled the option. Servers MUST only advertise
    /// this on stream transports.
    tcp_keepalive: ?u16 = null,
    rebinding: *const rebinding.Config = &rebinding.Config.off,
    ede: ?dns.Ede = null,

    pub fn fromQuery(query: dns.Message, max_udp_payload: u16) ResponseContext {
        const client_do = query.opt != null and query.opt.?.do_bit;
        return .{
            .query_id = query.header.id,
            .opcode = query.header.flags.opcode,
            .rd = query.header.flags.rd,
            .cd = query.header.flags.cd,
            .questions = query.questions,
            .client_edns = query.opt != null,
            .client_do = client_do,
            // RFC 6840 §5.8: set AD only if client signalled DO or AD
            .client_wants_ad = client_do or query.header.flags.ad,
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
    const qtype = if (ctx.questions.len > 0) ctx.questions[0].qtype else .a;

    // Special-use answers are hark's own. Keyed on qname, so a CNAME
    // into localhost still scrubs.
    var qname_buf: [dns.max_dotted_len + 1]u8 = undefined;
    const rb = (if (ctx.rebinding.enabled and ctx.questions.len > 0 and
        special_use.classify(ctx.questions[0].name.formatInto(&qname_buf), qtype) != .none)
        &rebinding.Config.off
    else
        ctx.rebinding).*;

    // Every section: negatives pass authority and additional through, and
    // RFC 9460 §4.2 steers clients to Additional-section SVCB/A/AAAA. OOM
    // is null, which the caller sends as SERVFAIL, never an unscrubbed reply.
    const answers = rebinding.scrub(alloc, reply.answers, rb) catch return null;
    const authorities = rebinding.scrub(alloc, reply.authorities, rb) catch return null;
    const additionals = rebinding.scrub(alloc, reply.additionals, rb) catch return null;
    const scrubbed = answers.len != reply.answers.len or authorities.len != reply.authorities.len;

    var options_buf: [3]dns.EdnsOption = undefined;
    var options: std.ArrayList(dns.EdnsOption) = .initBuffer(&options_buf);
    // RFC 7828: never over UDP.
    var keepalive_data: [2]u8 = undefined;
    if (ctx.tcp_keepalive) |timeout| {
        std.mem.writeInt(u16, &keepalive_data, timeout, .big);
        options.appendAssumeCapacity(.{ .code = dns.edns_opt_tcp_keepalive, .data = &keepalive_data });
    }
    var ede_bufs: [2][64]u8 = undefined;
    if (ctx.ede) |e| options.appendAssumeCapacity(e.option(&ede_bufs[0]));
    if (scrubbed) options.appendAssumeCapacity((dns.Ede{ .code = .blocked, .text = "rebinding" }).option(&ede_bufs[1]));
    const opt: ?dns.OptRecord = if (ctx.client_edns) .{
        // RFC 6891 §6.2.3: our own receive limit, not the send budget.
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
            .aa = false,
            .tc = false,
            .rd = ctx.rd,
            .ra = true,
            .z = 0,
            .ad = reply.ad and ctx.client_wants_ad and !scrubbed,
            .cd = ctx.cd,
            .rcode = reply.rcode,
        },
    };
    const sections: dns.Sections(dns.WireRecord) = .{ .answers = answers, .authorities = authorities, .additionals = additionals };

    // Nothing past the client's payload is sent, so none is built; the rewind drops an overrun.
    var ends: dns.SectionEnds = .{};
    if (dns.serializeEnds(wire_buf[0..@min(wire_buf.len, ctx.max_udp_payload)], hdr, ctx.questions, dns.WireRecord, sections, opt, &ends) catch null) |wire| return wire;

    // Sections are laid down in order and a name pointer only reaches
    // backward (RFC 1035 §4.1.4), so a response minus its tail sections is a
    // prefix of the full wire plus a fresh OPT: rewind to a section boundary
    // instead of re-serializing. Dropping additionals alone needs no TC
    // (RFC 1035 §4.2.1: advisory); dropping authority (negative SOA, referral
    // NS) sets TC=1 so the client retries over TCP (RFC 1035 §4.2.1, RFC 2181
    // §9). Last resort drops answers too and hard-clips the bytes.
    for ([_]usize{ ends.authorities, ends.answers, ends.questions }, 1..) |end, dropped| {
        if (end == 0) continue;
        var ser = dns.Serializer{ .buf = wire_buf, .pos = end };
        if (opt) |o| ser.writeOpt(o) catch continue;
        var cut = sections.header(hdr, ctx.questions.len, opt != null);
        cut.flags.tc = dropped >= 2;
        cut.ar_count = @intFromBool(opt != null);
        if (dropped >= 2) cut.ns_count = 0;
        if (dropped >= 3) cut.an_count = 0;
        cut.serialize(wire_buf[0..12]);
        if (ser.pos <= ctx.max_udp_payload or dropped == 3) return wire_buf[0..@min(ser.pos, ctx.max_udp_payload)];
    }
    return null;
}

pub fn serializeErrorResponse(
    wire_buf: []u8,
    query_id: u16,
    opcode: dns.OpCode,
    rcode: dns.RCode,
    extended_rcode: u8,
    rd: bool,
    questions: []const dns.Question,
    client_opt: ?dns.OptRecord,
) ?[]const u8 {
    // RFC 6891 §6.1.1: an OPT in the query obliges one in the response.
    const opt: ?dns.OptRecord = if (client_opt) |o| .{
        .udp_payload_size = dns.edns_udp_payload,
        .extended_rcode = extended_rcode,
        .version = 0,
        .do_bit = o.do_bit,
        .options = &.{},
    } else null;
    const msg = dns.Message{
        .header = .{
            .id = query_id,
            .flags = .{
                .qr = true,
                // RFC 1035 §4.1.1: response OPCODE echoes the query's OPCODE.
                // Hardcoding .query here would mislabel NOTIMP responses to
                // OPCODE=4/5 (Notify/Update) as ordinary QUERY replies.
                .opcode = opcode,
                .aa = false,
                .tc = false,
                .rd = rd,
                .ra = true,
                .z = 0,
                .ad = false,
                .cd = false,
                .rcode = rcode,
            },
        },
        .questions = questions,
        .opt = opt,
    };
    return dns.serializeMessage(wire_buf, msg) catch null;
}

/// Build a `dns.Message` value for a cached or synthesized response. The
/// header is the canonical recursive-resolver shape: aa=false (we are not
/// authoritative for any zone), ra=true (recursion available), no question
/// section (the wire builder copies questions from `ResponseContext`).
/// Used by the cache-hit fast path, the RFC 6761 special-use short-circuit,
/// and the RFC 8482 ANY/HINFO synthesizer — anywhere a response is built
/// without going through actual recursion.
pub fn synthesizedMessage(
    answers: []const dns.ResourceRecord,
    authorities: []const dns.ResourceRecord,
    rcode: dns.RCode,
    authenticated: bool,
) dns.Message {
    return .{
        .header = .{
            .id = 0,
            .flags = .{
                .qr = true,
                .opcode = .query,
                .aa = false,
                .tc = false,
                .rd = false,
                .ra = true,
                .z = 0,
                .ad = authenticated,
                .cd = false,
                .rcode = rcode,
            },
        },
        .questions = &.{},
        .answers = answers,
        .authorities = authorities,
    };
}

pub fn validateQuery(query: dns.Message) ?struct { rcode: dns.RCode, extended_rcode: u8 = 0 } {
    // RFC 1035 §4.1.1: a QR=1 packet is a response, not a query. Don't
    // resolve it. Returning format_error keeps the TCP connection useful
    // (UDP path drops silently before parse).
    if (query.header.flags.qr) return .{ .rcode = .format_error };
    if (query.header.flags.opcode != .query) return .{ .rcode = .not_implemented };
    if (query.questions.len != 1) return .{ .rcode = .format_error };
    // RFC 6891 §6.1.3: BADVERS (extended RCODE 16) for unsupported EDNS
    // version. Header RCODE bits = 0; OPT extended_rcode field = 1.
    if (query.opt) |opt| if (opt.version != 0) return .{ .rcode = .no_error, .extended_rcode = 1 };
    if (query.questions[0].qclass != .in) return .{ .rcode = .refused };
    return null;
}

test "buildResponseWire sets correct header fields" {
    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = try a.alloc(dns.Question, 1);
    const name = try dns.parseDottedName(a, "example.com");
    questions[0] = .{ .name = name, .qtype = .a, .qclass = .in };

    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x1234,
        .opcode = .query,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = false,
        .client_do = false,
        .client_wants_ad = false,
        .max_udp_payload = dns.max_udp_payload,
    }, .{ .rcode = .server_failure }, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(true, parsed.header.flags.qr);
    try testing.expectEqual(true, parsed.header.flags.rd);
    try testing.expectEqual(true, parsed.header.flags.ra);
    try testing.expectEqual(dns.RCode.server_failure, parsed.header.flags.rcode);
    try testing.expectEqual(@as(u16, 1), parsed.header.qd_count);
}

test "buildResponseWire carries EDE only to an EDNS client" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = [_]dns.Question{.{ .name = try dns.parseDottedName(a, "example.com"), .qtype = .a, .qclass = .in }};
    const servfail: Reply = .{ .rcode = .server_failure };
    var ctx: ResponseContext = .{
        .query_id = 1,
        .opcode = .query,
        .rd = true,
        .cd = false,
        .questions = &questions,
        .client_edns = true,
        .client_do = false,
        .client_wants_ad = false,
        .max_udp_payload = dns.max_udp_payload,
        .ede = .{ .code = .dnssec_bogus, .text = "rrsig failed to verify" },
    };

    var buf: [dns.max_udp_payload]u8 = undefined;
    const opt = (try dns.parseMessage(a, buildResponseWire(&buf, ctx, servfail, a).?)).opt.?;
    try testing.expectEqual(@as(usize, 1), opt.options.len);
    try testing.expectEqual(dns.edns_opt_ede, opt.options[0].code);
    try testing.expectEqualSlices(u8, "\x00\x06rrsig failed to verify", opt.options[0].data);

    ctx.client_edns = false;
    try testing.expectEqual(null, (try dns.parseMessage(a, buildResponseWire(&buf, ctx, servfail, a).?)).opt);
}

test "buildResponseWire with EDNS0" {
    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = try a.alloc(dns.Question, 1);
    const name = try dns.parseDottedName(a, "example.com");
    questions[0] = .{ .name = name, .qtype = .a, .qclass = .in };

    var buf: [dns.edns_udp_payload]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x5678,
        .opcode = .query,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = true,
        .client_do = false,
        .client_wants_ad = false,
        .max_udp_payload = dns.edns_udp_payload,
    }, .{ .rcode = .no_error }, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u16, dns.edns_udp_payload), parsed.opt.?.udp_payload_size);
}

test "buildResponseWire returns null on OOM rather than an unscrubbed reply" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const questions: []const dns.Question = &.{.{ .name = name, .qtype = .a, .qclass = .in }};
    const answers = [_]dns.WireRecord{
        try .from(a, .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 192, 168, 0, 1 } } }),
        try .from(a, .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 93, 184, 216, 34 } } }),
    };
    const scrub_on = rebinding.Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };

    // Every allocation fails: the scrub cannot keep the public A without
    // the private one, so nothing is sent rather than both.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var buf: [dns.max_udp_payload]u8 = undefined;
    const result = buildResponseWire(&buf, .{
        .query_id = 0x1234,
        .opcode = .query,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = false,
        .client_do = false,
        .client_wants_ad = false,
        .max_udp_payload = dns.max_udp_payload,
        .rebinding = &scrub_on,
    }, .{ .rcode = .no_error, .answers = &answers }, failing.allocator());

    try testing.expect(result == null);
}

test "serializeErrorResponse produces valid DNS message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const questions: []const dns.Question = &.{.{ .name = name, .qtype = .a, .qclass = .in }};

    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0xABCD, .query, .refused, 0, true, questions, null).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0xABCD), parsed.header.id);
    try testing.expectEqual(dns.RCode.refused, parsed.header.flags.rcode);
    try testing.expectEqual(true, parsed.header.flags.rd);
    try testing.expectEqual(true, parsed.header.flags.ra);
    try testing.expectEqual(true, parsed.header.flags.qr);
    try testing.expectEqual(@as(u16, 1), parsed.header.qd_count);
}

test "serializeErrorResponse with no question (parse failure)" {
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x1234, .query, .format_error, 0, false, &.{}, null).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(dns.RCode.format_error, parsed.header.flags.rcode);
    try testing.expectEqual(@as(u16, 0), parsed.header.qd_count);
}

test "validateQuery rejects QR=1 (response posing as query)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var spoofed = try dns.buildQuery(arena.allocator(), 0, "example.com", .a, .{});
    spoofed.header.flags.qr = true;

    try testing.expectEqual(dns.RCode.format_error, validateQuery(spoofed).?.rcode);
}

test "validateQuery returns BADVERS for unsupported EDNS version" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var query = try dns.buildQuery(arena.allocator(), 0, "example.com", .a, .{});
    query.opt = .{
        .udp_payload_size = 4096,
        .extended_rcode = 0,
        .version = 1,
        .do_bit = false,
        .options = &.{},
    };

    const fail = validateQuery(query).?;
    try testing.expectEqual(dns.RCode.no_error, fail.rcode);
    try testing.expectEqual(@as(u8, 1), fail.extended_rcode);
}

test "serializeErrorResponse echoes client OPCODE (RFC 1035 §4.1.1)" {
    // OPCODE 5 (Update — not in the named enum, use @enumFromInt). A server
    // replying NOTIMP must echo the OPCODE so the client can match the
    // response to its request.
    const opcode_update: dns.OpCode = @fromBackingInt(@intCast(5));
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x9999, opcode_update, .not_implemented, 0, false, &.{}, null).?;

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
    const questions: []const dns.Question = &.{.{ .name = name, .qtype = .a, .qclass = .in }};

    var ns_authorities: [12]dns.WireRecord = undefined;
    for (&ns_authorities, 0..) |*rr, i| {
        const ns_label = try std.fmt.allocPrint(a, "ns{d}.long.example.com.", .{i});
        const ns_name = try dns.parseDottedName(a, ns_label);
        rr.* = try .from(a, .{
            .name = name,
            .rtype = .ns,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .ns = ns_name },
        });
    }
    const a_record: dns.WireRecord = try .from(a, .{
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

    // Compressed: header+question+OPT is 40 bytes; answer 16; authorities
    // 223; additionals 48.
    const rows = [_]struct { max: u16, tc: bool, an: u16, ns: u16 }{
        .{ .max = 300, .tc = false, .an = 1, .ns = 12 },
        .{ .max = 100, .tc = true, .an = 1, .ns = 0 },
        .{ .max = 40, .tc = true, .an = 0, .ns = 0 },
    };
    // 300 overflows the buffer mid-additionals; 1024 serializes whole but over max.
    var buf: [1024]u8 = undefined;
    for ([_]usize{ 300, 1024 }) |cap| for (rows) |row| {
        const wire = buildResponseWire(buf[0..cap], .{
            .query_id = 0x4242,
            .opcode = .query,
            .rd = false,
            .cd = false,
            .questions = questions,
            .client_edns = true,
            .client_do = false,
            .client_wants_ad = false,
            .max_udp_payload = row.max,
        }, reply, a).?;
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

test "serializeErrorResponse answers an EDNS query with OPT (RFC 6891 §6.1.1)" {
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x1234, .query, .no_error, 1, false, &.{}, .{ .udp_payload_size = 512, .extended_rcode = 0, .version = 1, .do_bit = true, .options = &.{} }).?;

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
        .additionals = &.{try .from(a, .{ .name = glue, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 168, 1, 1 } } })},
    };
    const scrub_on = rebinding.Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };
    for ([_]*const rebinding.Config{ &rebinding.Config.off, &scrub_on }, [_]u16{ 1, 0 }) |rb, kept| {
        var buf: [dns.max_udp_payload]u8 = undefined;
        const wire = buildResponseWire(&buf, .{
            .query_id = 0,
            .opcode = .query,
            .rd = true,
            .cd = false,
            .questions = &.{.{ .name = zone, .qtype = .a, .qclass = .in }},
            .client_edns = false,
            .client_do = false,
            .client_wants_ad = false,
            .max_udp_payload = dns.max_udp_payload,
            .rebinding = rb,
        }, reply, a).?;
        try testing.expectEqual(kept, (try dns.parseMessage(a, wire)).header.ar_count);
    }
}

test "buildResponseWire: special-use qname bypasses the rebinding scrub; a CNAME into it does not" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const scrub_on = rebinding.Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };
    const localhost = try dns.parseDottedName(a, "localhost");
    const attacker = try dns.parseDottedName(a, "attacker.com");
    const loopback: dns.WireRecord = try .from(a, .{ .name = localhost, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 127, 0, 0, 1 } } });
    const alias: dns.WireRecord = try .from(a, .{ .name = attacker, .rtype = .cname, .rclass = .in, .ttl = 60, .rdata = .{ .cname = localhost } });

    const cases = [_]struct { qname: dns.Name, answers: []const dns.WireRecord }{
        .{ .qname = localhost, .answers = &.{loopback} },
        .{ .qname = attacker, .answers = &.{ alias, loopback } },
    };
    for (cases) |c| {
        var buf: [dns.max_udp_payload]u8 = undefined;
        const wire = buildResponseWire(&buf, .{
            .query_id = 0,
            .opcode = .query,
            .rd = true,
            .cd = false,
            .questions = &.{.{ .name = c.qname, .qtype = .a, .qclass = .in }},
            .client_edns = false,
            .client_do = false,
            .client_wants_ad = false,
            .max_udp_payload = dns.max_udp_payload,
            .rebinding = &scrub_on,
        }, .{ .rcode = .no_error, .answers = c.answers }, a).?;
        const parsed = try dns.parseMessage(a, wire);
        try testing.expectEqual(@as(u16, 1), parsed.header.an_count);
        try testing.expectEqual(c.answers[0].rtype(), parsed.answers[0].rtype);
    }
}

test "buildResponseWire: a rebinding scrub clears AD" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const scrub_on = rebinding.Config{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };
    for ([_][4]u8{ .{ 93, 184, 216, 34 }, .{ 192, 168, 1, 1 } }, [_]bool{ true, false }) |ip, ad| {
        const answers = [_]dns.WireRecord{try .from(a, .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = ip } })};
        var buf: [dns.max_udp_payload]u8 = undefined;
        const wire = buildResponseWire(&buf, .{
            .query_id = 0,
            .opcode = .query,
            .rd = true,
            .cd = false,
            .questions = &.{.{ .name = name, .qtype = .a, .qclass = .in }},
            .client_edns = true,
            .client_do = true,
            .client_wants_ad = true,
            .max_udp_payload = dns.max_udp_payload,
            .rebinding = &scrub_on,
        }, .{ .rcode = .no_error, .ad = true, .answers = &answers }, a).?;
        try testing.expectEqual(ad, (try dns.parseMessage(a, wire)).header.flags.ad);
    }
}
