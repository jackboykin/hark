/// Wire-shaping for client-facing responses: header construction, EDNS0 OPT,
/// truncation cascade, error responses, and per-RFC validation. Pure (no
/// I/O); the I/O orchestrator lives in server.zig.
const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");

// ── Stripping authenticating DNSSEC RRs ────────────────────────────────

/// RFC 4035 §3.2.1: strip authenticating DNSSEC RRs (RRSIG, NSEC, NSEC3) when
/// client didn't set the DO bit. Records whose type matches the QTYPE are kept
/// in the answer section (explicit query for that type).
fn stripDnssecRRs(alloc: mem.Allocator, records: []const dns.ResourceRecord, qtype: dns.RType, is_answer: bool) []const dns.ResourceRecord {
    var count: usize = 0;
    for (records) |rr| {
        if (isDnssecAuthRR(rr.rtype) and !(is_answer and rr.rtype == qtype)) continue;
        count += 1;
    }
    if (count == records.len) return records;

    const filtered = alloc.alloc(dns.ResourceRecord, count) catch return records;
    var i: usize = 0;
    for (records) |rr| {
        if (isDnssecAuthRR(rr.rtype) and !(is_answer and rr.rtype == qtype)) continue;
        filtered[i] = rr;
        i += 1;
    }
    return filtered;
}

fn isDnssecAuthRR(rtype: dns.RType) bool {
    return switch (rtype) {
        .rrsig, .nsec, .nsec3 => true,
        else => false,
    };
}

// ── Response building ──────────────────────────────────────────────────

pub const ResponseContext = struct {
    query_id: u16,
    rd: bool,
    cd: bool,
    questions: []const dns.Question,
    client_edns: bool,
    client_do: bool,
    client_wants_ad: bool,
    max_payload: u16,

    pub fn fromQuery(query: dns.Message, max_payload: u16) ResponseContext {
        const client_do = query.opt != null and query.opt.?.do_bit;
        return .{
            .query_id = query.header.id,
            .rd = query.header.rd,
            .cd = query.header.cd,
            .questions = query.questions,
            .client_edns = query.opt != null,
            .client_do = client_do,
            // RFC 6840 §5.8: set AD only if client signalled DO or AD
            .client_wants_ad = client_do or query.header.ad,
            .max_payload = max_payload,
        };
    }
};

pub fn buildResponseWire(
    wire_buf: []u8,
    ctx: ResponseContext,
    response: dns.Message,
    alloc: mem.Allocator,
) ?[]const u8 {
    const opt: ?dns.OptRecord = if (ctx.client_edns) .{
        // Echo back the per-request budget so a client knows our willingness
        // to accept large queries — matches what we're willing to emit.
        .udp_payload_size = ctx.max_payload,
        .extended_rcode = 0,
        .version = 0,
        .do_bit = ctx.client_do,
        .options = &.{},
    } else null;

    const qtype = if (ctx.questions.len > 0) ctx.questions[0].qtype else .a;

    // RFC 4035 §3.2.1: strip authenticating DNSSEC RRs when client didn't set DO
    const answers = if (!ctx.client_do) stripDnssecRRs(alloc, response.answers, qtype, true) else response.answers;
    const authorities = if (!ctx.client_do) stripDnssecRRs(alloc, response.authorities, qtype, false) else response.authorities;
    const additionals = if (!ctx.client_do) stripDnssecRRs(alloc, response.additionals, qtype, false) else response.additionals;

    var msg = dns.Message{
        .header = .{
            .id = ctx.query_id,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = ctx.rd,
            .ra = true,
            .z = 0,
            .ad = response.header.ad and ctx.client_wants_ad,
            .cd = ctx.cd,
            .rcode = response.header.rcode,
            .qd_count = @intCast(ctx.questions.len),
            .an_count = @intCast(answers.len),
            .ns_count = @intCast(authorities.len),
            .ar_count = @intCast(additionals.len),
        },
        .questions = ctx.questions,
        .answers = answers,
        .authorities = authorities,
        .additionals = additionals,
        .opt = opt,
    };

    // Try full response
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_payload) return wire;
    } else |_| {}

    // Drop additionals
    msg.additionals = &.{};
    msg.header.ar_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_payload) return wire;
    } else |_| {}

    // Drop authorities
    msg.authorities = &.{};
    msg.header.ns_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_payload) return wire;
    } else |_| {}

    // TC bit with answers
    msg.header.tc = true;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_payload) return wire;
    } else |_| {}

    // TC with no answers
    msg.answers = &.{};
    msg.header.an_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        return wire[0..@min(wire.len, ctx.max_payload)];
    } else |_| {}

    return null;
}

pub fn serializeErrorResponse(
    wire_buf: []u8,
    query_id: u16,
    rcode: dns.RCode,
    extended_rcode: u8,
    rd: bool,
    questions: []const dns.Question,
) ?[]const u8 {
    const opt: ?dns.OptRecord = if (extended_rcode != 0) .{
        .udp_payload_size = dns.edns_udp_payload,
        .extended_rcode = extended_rcode,
        .version = 0,
        .do_bit = false,
        .options = &.{},
    } else null;
    const msg = dns.Message{
        .header = .{
            .id = query_id,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = rd,
            .ra = true,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = rcode,
            .qd_count = @intCast(questions.len),
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = questions,
        .opt = opt,
    };
    return dns.serializeMessage(wire_buf, msg) catch null;
}

// ── Query validation ───────────────────────────────────────────────────

const ValidationFailure = struct {
    rcode: dns.RCode,
    extended_rcode: u8 = 0,
};

pub fn validateQuery(query: dns.Message) ?ValidationFailure {
    // RFC 1035 §4.1.1: a QR=1 packet is a response, not a query. Don't
    // resolve it. Returning format_error keeps the TCP connection useful
    // (UDP path drops silently before parse).
    if (query.header.qr) return .{ .rcode = .format_error };
    if (query.header.opcode != .query) return .{ .rcode = .not_implemented };
    if (query.questions.len != 1) return .{ .rcode = .format_error };
    if (query.questions[0].qclass != .in) return .{ .rcode = .refused };
    // RFC 6891 §6.1.3: BADVERS (extended RCODE 16) for unsupported EDNS
    // version. Header RCODE bits = 0; OPT extended_rcode field = 1.
    if (query.opt) |opt| if (opt.version != 0) return .{ .rcode = .no_error, .extended_rcode = 1 };
    return null;
}

// ── Tests ──────────────────────────────────────────────────────────────

test "buildResponseWire sets correct header fields" {
    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = try a.alloc(dns.Question, 1);
    const name = try dns.parseDottedName(a, "example.com");
    questions[0] = .{ .name = name, .qtype = .a, .qclass = .in };

    const response = dns.Message{
        .header = .{
            .id = 0,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = true,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = .server_failure,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
    };

    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x1234,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = false,
        .client_do = false,
        .client_wants_ad = false,
        .max_payload = dns.max_udp_payload,
    }, response, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(true, parsed.header.qr);
    try testing.expectEqual(true, parsed.header.rd);
    try testing.expectEqual(true, parsed.header.ra);
    try testing.expectEqual(dns.RCode.server_failure, parsed.header.rcode);
    try testing.expectEqual(@as(u16, 1), parsed.header.qd_count);
}

test "buildResponseWire with EDNS0" {
    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = try a.alloc(dns.Question, 1);
    const name = try dns.parseDottedName(a, "example.com");
    questions[0] = .{ .name = name, .qtype = .a, .qclass = .in };

    const response = dns.Message{
        .header = .{
            .id = 0,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = true,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
    };

    var buf: [dns.edns_udp_payload]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x5678,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = true,
        .client_do = false,
        .client_wants_ad = false,
        .max_payload = dns.edns_udp_payload,
    }, response, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u16, dns.edns_udp_payload), parsed.opt.?.udp_payload_size);
}

test "serializeErrorResponse produces valid DNS message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const questions: []const dns.Question = &.{.{ .name = name, .qtype = .a, .qclass = .in }};

    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0xABCD, .refused, 0, true, questions).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0xABCD), parsed.header.id);
    try testing.expectEqual(dns.RCode.refused, parsed.header.rcode);
    try testing.expectEqual(true, parsed.header.rd);
    try testing.expectEqual(true, parsed.header.ra);
    try testing.expectEqual(true, parsed.header.qr);
    try testing.expectEqual(@as(u16, 1), parsed.header.qd_count);
}

test "serializeErrorResponse with no question (parse failure)" {
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x1234, .format_error, 0, false, &.{}).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(dns.RCode.format_error, parsed.header.rcode);
    try testing.expectEqual(@as(u16, 0), parsed.header.qd_count);
}

test "validateQuery rejects QR=1 (response posing as query)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var spoofed = try dns.buildQuery(arena.allocator(), 0, "example.com", .a);
    spoofed.header.qr = true;

    try testing.expectEqual(dns.RCode.format_error, validateQuery(spoofed).?.rcode);
}

test "validateQuery returns BADVERS for unsupported EDNS version" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var query = try dns.buildQuery(arena.allocator(), 0, "example.com", .a);
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

test "serializeErrorResponse emits BADVERS OPT when extended_rcode != 0" {
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x1234, .no_error, 1, false, &.{}).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(dns.RCode.no_error, parsed.header.rcode);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u8, 1), parsed.opt.?.extended_rcode);
}
