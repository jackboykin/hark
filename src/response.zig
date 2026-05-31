/// Wire-shaping for client-facing responses: header construction, EDNS0 OPT,
/// truncation cascade, error responses, and per-RFC validation. Pure (no
/// I/O); the I/O orchestrator lives in server.zig.
///
/// Response shaping policy is captured in `shapeResponse`: a per-section
/// keep/strip matrix over (qtype, DO bit, rcode, answer-present). The cells
/// are documented inline at each branch of `shapeResponse` below.
const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const rebinding = @import("rebinding.zig");

// ── Response shaping ───────────────────────────────────────────────────
//
// What a recursive resolver owes its client:
//   1. Use the answer (or know there isn't one).
//   2. Negatively cache the absence (RFC 2308 — SOA in authority).
//   3. Independently validate, if DO=1 / CD=1 (RFC 4035 §3.2.3).
//
// Everything else — delegation NS in authority, glue in additional — is
// decoration for clients that aren't recursive resolvers. Stubs don't
// follow referrals; forwarding them invites CVE-2025-11411-class
// section-confusion poisoning (child auth records overriding the
// resolver's view of parent delegation).
//
// `shapeResponse` is the single choke point for this policy. All
// client-bound responses flow through it via `buildResponseWire`.

/// Result of shaping: section slices owned by the supplied allocator
/// (or borrowed from `response` when no allocation was needed).
const ShapedSections = struct {
    answers: []const dns.ResourceRecord,
    authorities: []const dns.ResourceRecord,
    additionals: []const dns.ResourceRecord,
};

/// Pure shaper: applies the per-section keep/strip matrix to `response`
/// and returns new slices. Each matrix cell is spelled out at the branch
/// that implements it; the `shapeResponse` tests below exercise them
/// one-to-one.
///
/// On OOM returns the error so the caller can surface SERVFAIL —
/// silently returning a partially-shaped response would leak records
/// the matrix says to strip.
fn shapeResponse(
    alloc: mem.Allocator,
    response: dns.Message,
    qtype: dns.RType,
    do_bit: bool,
    cd_bit: bool,
    minimal_responses: bool,
    rebind_cfg: *const rebinding.Config,
) mem.Allocator.Error!ShapedSections {
    // CD=1 means the client is doing its own validation; it MUST receive
    // the full proof set (RFC 4035 §3.2.2). Treat the keep set as
    // DO=1-equivalent regardless of the DO bit.
    const keep_dnssec = do_bit or cd_bit;

    // qtype=NS suppresses the minimal-responses strip — for RFC 8109 root
    // priming, the NS records *are* the answer and their glue is load-
    // bearing. Mirrors Unbound's positive_answer() carve-out (msgencode.c:660).
    const apply_minimal = minimal_responses and qtype != .ns;
    // Positives shed delegation NS + glue; negatives retain SOA + proofs.
    const positive = response.header.flags.rcode == .no_error and response.answers.len > 0;

    const answers = try shapeAnswers(alloc, response.answers, qtype, keep_dnssec, rebind_cfg);
    const authorities = try shapeAuthority(alloc, response.authorities, keep_dnssec, apply_minimal, positive);
    const additionals = try shapeAdditional(alloc, response.additionals, keep_dnssec, apply_minimal, positive);

    return .{
        .answers = answers,
        .authorities = authorities,
        .additionals = additionals,
    };
}

/// Answer section: keep qtype, CNAME, DNAME unconditionally (the
/// client's primary payload). Keep RRSIG iff the client wants DNSSEC.
/// Strip orphan DNSSEC records when DO=0 (already covered by the
/// keep_dnssec gate). The rebinding scrub runs first; its semantics
/// live in `src/rebinding.zig`.
fn shapeAnswers(
    alloc: mem.Allocator,
    answers: []const dns.ResourceRecord,
    qtype: dns.RType,
    keep_dnssec: bool,
    rebind_cfg: *const rebinding.Config,
) mem.Allocator.Error![]const dns.ResourceRecord {
    const post_scrub = try rebinding.scrub(alloc, answers, rebind_cfg.*);
    return filterRecords(alloc, post_scrub, struct {
        qtype: dns.RType,
        keep_dnssec: bool,
        pub fn keep(self: @This(), rr: dns.ResourceRecord) bool {
            // Explicit-qtype query for an authenticating record: keep
            // the answer's own type even when the client didn't set DO.
            if (rr.rtype == self.qtype) return true;
            return switch (rr.rtype) {
                .rrsig, .nsec, .nsec3 => self.keep_dnssec,
                else => true, // CNAME, DNAME, qtype payload, etc.
            };
        }
    }{ .qtype = qtype, .keep_dnssec = keep_dnssec });
}

/// Authority section: keep SOA (RFC 2308 negative caching) and
/// NSEC/NSEC3 (RFC 4035 wildcard / negative-existence proofs) when DO=1.
/// Keep RRSIGs whose covered rtype is also kept. Strip delegation NS
/// (CVE-2025-11411 class) and DS (internal-to-recursion). The
/// minimal-responses gate allows operators to disable the NS strip
/// (passthrough mode); the DNSSEC-on-DO=0 strip is mandatory regardless.
fn shapeAuthority(
    alloc: mem.Allocator,
    authorities: []const dns.ResourceRecord,
    keep_dnssec: bool,
    apply_minimal: bool,
    positive: bool,
) mem.Allocator.Error![]const dns.ResourceRecord {
    return filterRecords(alloc, authorities, struct {
        keep_dnssec: bool,
        apply_minimal: bool,
        positive: bool,

        pub fn keep(self: @This(), rr: dns.ResourceRecord) bool {
            return switch (rr.rtype) {
                .soa => true, // negative-cache material; always keep
                .nsec, .nsec3 => self.keep_dnssec, // proof material
                .ns => !(self.apply_minimal and self.positive),
                .ds => false, // delegation chain info; not for stubs
                .rrsig => self.keep_dnssec and self.shouldKeepRRSIG(rr),
                else => !self.apply_minimal,
            };
        }

        /// Drop RRSIGs whose covered rtype is one we're stripping.
        /// Stub: cover NS/DS/A/AAAA → drop; cover SOA/NSEC/NSEC3 → keep.
        fn shouldKeepRRSIG(self: @This(), rr: dns.ResourceRecord) bool {
            const covered = dns.rrsigCovers(rr) orelse return false;
            return switch (covered) {
                .soa => true,
                .nsec, .nsec3 => true,
                .ns => !(self.apply_minimal and self.positive),
                else => !self.apply_minimal,
            };
        }
    }{
        .keep_dnssec = keep_dnssec,
        .apply_minimal = apply_minimal,
        .positive = positive,
    });
}

/// Additional section: under minimal-responses, strip all non-DNSSEC
/// content on positive answers. A/AAAA glue is orphaned the moment its
/// owning NS is stripped from authority; with no NS in authority, glue
/// has nowhere to point. Keep RRSIG if it covers something we kept
/// (in practice, almost never applies to additional under minimal).
fn shapeAdditional(
    alloc: mem.Allocator,
    additionals: []const dns.ResourceRecord,
    keep_dnssec: bool,
    apply_minimal: bool,
    positive: bool,
) mem.Allocator.Error![]const dns.ResourceRecord {
    return filterRecords(alloc, additionals, struct {
        keep_dnssec: bool,
        apply_minimal: bool,
        positive: bool,

        pub fn keep(self: @This(), rr: dns.ResourceRecord) bool {
            if (self.apply_minimal and self.positive) {
                // Strip everything except validation material the
                // client explicitly opted into.
                return switch (rr.rtype) {
                    .nsec, .nsec3 => self.keep_dnssec,
                    else => false,
                };
            }
            // Passthrough mode (or negative response): DO=0 still strips
            // orphan DNSSEC records per RFC 4035 §3.2.3.
            return switch (rr.rtype) {
                .rrsig, .nsec, .nsec3 => self.keep_dnssec,
                else => true,
            };
        }
    }{
        .keep_dnssec = keep_dnssec,
        .apply_minimal = apply_minimal,
        .positive = positive,
    });
}

/// Two-pass filter over a record slice using a `Predicate` with a
/// `pub fn keep(self, rr) bool`. Returns the input slice unchanged
/// when no records would be filtered (zero-alloc fast path).
fn filterRecords(
    alloc: mem.Allocator,
    records: []const dns.ResourceRecord,
    predicate: anytype,
) mem.Allocator.Error![]const dns.ResourceRecord {
    var keep_count: usize = 0;
    for (records) |rr| {
        if (predicate.keep(rr)) keep_count += 1;
    }
    if (keep_count == records.len) return records;

    const out = try alloc.alloc(dns.ResourceRecord, keep_count);
    var i: usize = 0;
    for (records) |rr| {
        if (!predicate.keep(rr)) continue;
        out[i] = rr;
        i += 1;
    }
    return out;
}

// ── Response building ──────────────────────────────────────────────────

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
    /// Operator policy: when true (default) `shapeResponse` applies the
    /// Unbound-equivalent minimal-responses strip (no delegation NS in
    /// authority on positive answers, no glue in additional). When
    /// false, only the RFC-mandated DO=0 DNSSEC strip runs; the rest
    /// of the upstream's authority/additional pass through. The DO=0
    /// strip is mandatory regardless of this knob (RFC 4035 §3.2.3).
    minimal_responses: bool = true,
    /// RFC 7828 edns-tcp-keepalive TIMEOUT (100-ms units). Emitted only
    /// when non-null AND the client sent EDNS — null on UDP, or when
    /// the operator disabled the option. Servers MUST only advertise
    /// this on stream transports.
    tcp_keepalive: ?u16 = null,
    /// DNS rebinding scrub policy. `enabled=true` activates the egress
    /// filter that strips private-IP A/AAAA from public-zone answers.
    /// Defaults to `&Config.off` (a static no-op sentinel) so tests and
    /// synthesised responses needn't wire it; the worker overrides to
    /// `&self.config.rebinding` so the scrub applies uniformly to
    /// cache-served and freshly-resolved responses (both flow through
    /// `buildResponseWire`).
    rebinding: *const rebinding.Config = &rebinding.Config.off,

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
    response: dns.Message,
    alloc: mem.Allocator,
) ?[]const u8 {
    // RFC 7828: emit the keepalive option (code 11) on TCP/DoT responses
    // only — servers MUST NOT include it on UDP. Caller signals stream
    // transport via ctx.tcp_keepalive being non-null.
    var opt_options_buf: [1]dns.EdnsOption = undefined;
    var keepalive_data: [2]u8 = undefined;
    const opt_options: []const dns.EdnsOption = blk: {
        if (ctx.tcp_keepalive) |timeout| {
            std.mem.writeInt(u16, &keepalive_data, timeout, .big);
            opt_options_buf[0] = .{ .code = dns.edns_opt_tcp_keepalive, .data = &keepalive_data };
            break :blk opt_options_buf[0..1];
        }
        break :blk &.{};
    };
    const opt: ?dns.OptRecord = if (ctx.client_edns) .{
        // Echo back the per-request budget so a client knows our willingness
        // to accept large queries — matches what we're willing to emit.
        .udp_payload_size = ctx.max_udp_payload,
        .extended_rcode = 0,
        .version = 0,
        .do_bit = ctx.client_do,
        .options = opt_options,
    } else null;

    const qtype = if (ctx.questions.len > 0) ctx.questions[0].qtype else .a;

    // Apply the unified response-shaping matrix. See `shapeResponse` for the
    // per-section keep/strip rules. OOM returns null — the I/O caller
    // surfaces it as SERVFAIL rather than emitting a half-shaped response.
    const shaped = shapeResponse(
        alloc,
        response,
        qtype,
        ctx.client_do,
        ctx.cd,
        ctx.minimal_responses,
        ctx.rebinding,
    ) catch return null;
    const answers = shaped.answers;
    const authorities = shaped.authorities;
    const additionals = shaped.additionals;

    var msg = dns.Message{
        .header = .{
            .id = ctx.query_id,
            .flags = .{
                .qr = true,
                .opcode = ctx.opcode,
                .aa = false,
                .tc = false,
                .rd = ctx.rd,
                .ra = true,
                .z = 0,
                .ad = response.header.flags.ad and ctx.client_wants_ad,
                .cd = ctx.cd,
                .rcode = response.header.flags.rcode,
            },
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
        if (wire.len <= ctx.max_udp_payload) return wire;
    } else |_| {}

    // Drop additionals (RFC 1035 §4.2.1: additionals are advisory; their
    // omission alone does not require TC=1).
    msg.additionals = &.{};
    msg.header.ar_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_udp_payload) return wire;
    } else |_| {}

    // Drop authorities — TC=1 from this point on. RFC 1035 §4.2.1 / 2181 §9:
    // when an authoritative section that the client may need (negative SOA,
    // referral NS) is omitted, the truncation flag MUST be set so the client
    // knows to retry over TCP.
    msg.header.flags.tc = true;
    msg.authorities = &.{};
    msg.header.ns_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_udp_payload) return wire;
    } else |_| {}

    // Last resort: drop answers, keep TC=1.
    msg.answers = &.{};
    msg.header.an_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        return wire[0..@min(wire.len, ctx.max_udp_payload)];
    } else |_| {}

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

// ── Synthesized messages ───────────────────────────────────────────────

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
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = @intCast(authorities.len),
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
        .authorities = authorities,
    };
}

// ── Query validation ───────────────────────────────────────────────────

pub fn validateQuery(query: dns.Message) ?struct { rcode: dns.RCode, extended_rcode: u8 = 0 } {
    // RFC 1035 §4.1.1: a QR=1 packet is a response, not a query. Don't
    // resolve it. Returning format_error keeps the TCP connection useful
    // (UDP path drops silently before parse).
    if (query.header.flags.qr) return .{ .rcode = .format_error };
    if (query.header.flags.opcode != .query) return .{ .rcode = .not_implemented };
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
            .flags = .{
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
            },
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
        .opcode = .query,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = false,
        .client_do = false,
        .client_wants_ad = false,
        .max_udp_payload = dns.max_udp_payload,
    }, response, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(true, parsed.header.flags.qr);
    try testing.expectEqual(true, parsed.header.flags.rd);
    try testing.expectEqual(true, parsed.header.flags.ra);
    try testing.expectEqual(dns.RCode.server_failure, parsed.header.flags.rcode);
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
            .flags = .{
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
            },
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
        .opcode = .query,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = true,
        .client_do = false,
        .client_wants_ad = false,
        .max_udp_payload = dns.edns_udp_payload,
    }, response, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u16, dns.edns_udp_payload), parsed.opt.?.udp_payload_size);
}

test "buildResponseWire returns null on OOM rather than leaking DNSSEC RRs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const questions: []const dns.Question = &.{.{ .name = name, .qtype = .a, .qclass = .in }};

    // Build an answer section that includes RRSIG — would need stripping for
    // a non-DO client, which forces stripDnssecRRs to allocate.
    const a_rdata = dns.RData{ .a = .{ 192, 0, 2, 1 } };
    const rrsig_rdata = dns.RData{ .rrsig = .{
        .type_covered = .a,
        .algorithm = .ecdsap256sha256,
        .labels = 2,
        .original_ttl = 60,
        .sig_expiration = 0,
        .sig_inception = 0,
        .key_tag = 0,
        .signer_name = name,
        .signature = &.{},
    } };
    const answers: []const dns.ResourceRecord = &.{
        .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = a_rdata },
        .{ .name = name, .rtype = .rrsig, .rclass = .in, .ttl = 60, .rdata = rrsig_rdata },
    };

    const response = dns.Message{
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
                .ad = false,
                .cd = false,
                .rcode = .no_error,
            },
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
    };

    // FailingAllocator with budget 0 fails every allocation; stripDnssecRRs
    // must surface OOM as a null response, not return the unfiltered slice.
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
    }, response, failing.allocator());

    try testing.expect(result == null);
}

test "serializeErrorResponse produces valid DNS message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const questions: []const dns.Question = &.{.{ .name = name, .qtype = .a, .qclass = .in }};

    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0xABCD, .query, .refused, 0, true, questions).?;

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
    const wire = serializeErrorResponse(&buf, 0x1234, .query, .format_error, 0, false, &.{}).?;

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
    const opcode_update: dns.OpCode = @enumFromInt(5);
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x9999, opcode_update, .not_implemented, 0, false, &.{}).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u4, 5), @intFromEnum(parsed.header.flags.opcode));
    try testing.expectEqual(dns.RCode.not_implemented, parsed.header.flags.rcode);
}

test "buildResponseWire sets TC=1 when dropping authority section (RFC 1035 §4.2.1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const questions: []const dns.Question = &.{.{ .name = name, .qtype = .a, .qclass = .in }};

    // Build a response whose authority section forces a payload between
    // (additionals-dropped fits) and (answers fits but authorities don't).
    // 12 NS records overflow the small payload but the answers alone fit.
    var ns_authorities: [12]dns.ResourceRecord = undefined;
    for (&ns_authorities, 0..) |*rr, i| {
        const ns_label = try std.fmt.allocPrint(a, "ns{d}.long.example.com.", .{i});
        const ns_name = try dns.parseDottedName(a, ns_label);
        rr.* = .{
            .name = name,
            .rtype = .ns,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .ns = ns_name },
        };
    }
    const a_record = dns.ResourceRecord{
        .name = name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 60,
        .rdata = .{ .a = .{ 192, 0, 2, 1 } },
    };

    const response = dns.Message{
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
                .ad = false,
                .cd = false,
                .rcode = .no_error,
            },
            .qd_count = 0,
            .an_count = 1,
            .ns_count = ns_authorities.len,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = &.{a_record},
        .authorities = &ns_authorities,
    };

    // Tight payload — answers fit, authorities don't. `minimal_responses
    // = false` keeps the authority NS records through shaping so the
    // truncation cascade is what actually drops them.
    var buf: [120]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x4242,
        .opcode = .query,
        .rd = false,
        .cd = false,
        .questions = questions,
        .client_edns = false,
        .client_do = false,
        .client_wants_ad = false,
        .max_udp_payload = buf.len,
        .minimal_responses = false,
    }, response, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(true, parsed.header.flags.tc);
    try testing.expectEqual(@as(u16, 0), parsed.header.ns_count);
    try testing.expectEqual(@as(u16, 1), parsed.header.an_count);
}

test "serializeErrorResponse emits BADVERS OPT when extended_rcode != 0" {
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x1234, .query, .no_error, 1, false, &.{}).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(dns.RCode.no_error, parsed.header.flags.rcode);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u8, 1), parsed.opt.?.extended_rcode);
}

// ── shapeResponse tests ────────────────────────────────────────────────
//
// Each test exercises one (or a tightly-coupled pair) of cells in the
// keep/strip matrix implemented by `shapeResponse` above.
// The shaper is a pure function on `dns.Message`; we build messages
// directly and inspect the shaped sections without going through wire
// encode/decode (the wire layer is tested elsewhere).

// Test helpers shared across shape-* tests. Names are formed from
// static byte slices so no allocation is needed.
const shape_test_name = dns.Name{ .labels = &.{ "example", "com" } };
const shape_test_ns_name = dns.Name{ .labels = &.{ "ns", "example", "com" } };

fn shapeARecord(ip: [4]u8) dns.ResourceRecord {
    return .{ .name = shape_test_name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = ip } };
}

fn shapeNsRecord() dns.ResourceRecord {
    return .{ .name = shape_test_name, .rtype = .ns, .rclass = .in, .ttl = 300, .rdata = .{ .ns = shape_test_ns_name } };
}

fn shapeGlueRecord(ip: [4]u8) dns.ResourceRecord {
    return .{ .name = shape_test_ns_name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = ip } };
}

fn shapeSoaRecord() dns.ResourceRecord {
    return .{
        .name = shape_test_name,
        .rtype = .soa,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .soa = .{
            .mname = shape_test_ns_name,
            .rname = shape_test_ns_name,
            .serial = 1,
            .refresh = 7200,
            .retry = 3600,
            .expire = 1209600,
            .minimum = 3600,
        } },
    };
}

fn shapeNsecRecord() dns.ResourceRecord {
    return .{
        .name = shape_test_name,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .nsec = .{ .next_domain_name = shape_test_ns_name, .type_bit_maps = &.{} } },
    };
}

fn shapeRrsigRecord(covered: dns.RType) dns.ResourceRecord {
    return .{
        .name = shape_test_name,
        .rtype = .rrsig,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .rrsig = .{
            .type_covered = covered,
            .algorithm = .ecdsap256sha256,
            .labels = 2,
            .original_ttl = 60,
            .sig_expiration = 0,
            .sig_inception = 0,
            .key_tag = 0,
            .signer_name = shape_test_name,
            .signature = &.{},
        } },
    };
}

fn shapePositiveMessage(
    answers: []const dns.ResourceRecord,
    authorities: []const dns.ResourceRecord,
    additionals: []const dns.ResourceRecord,
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
                .ad = false,
                .cd = false,
                .rcode = .no_error,
            },
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = @intCast(authorities.len),
            .ar_count = @intCast(additionals.len),
        },
        .questions = &.{},
        .answers = answers,
        .authorities = authorities,
        .additionals = additionals,
    };
}

fn shapeNxdomainMessage(authorities: []const dns.ResourceRecord) dns.Message {
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
                .ad = false,
                .cd = false,
                .rcode = .name_error,
            },
            .qd_count = 0,
            .an_count = 0,
            .ns_count = @intCast(authorities.len),
            .ar_count = 0,
        },
        .questions = &.{},
        .authorities = authorities,
    };
}

fn countByType(records: []const dns.ResourceRecord, rtype: dns.RType) usize {
    var c: usize = 0;
    for (records) |rr| {
        if (rr.rtype == rtype) c += 1;
    }
    return c;
}

test "shape: positive DO=0 strips NS from authority, glue from additional, RRSIG everywhere" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const answers: []const dns.ResourceRecord = &.{ shapeARecord(.{ 192, 0, 2, 1 }), shapeRrsigRecord(.a) };
    const authorities: []const dns.ResourceRecord = &.{ shapeNsRecord(), shapeRrsigRecord(.ns) };
    const additionals: []const dns.ResourceRecord = &.{shapeGlueRecord(.{ 1, 2, 3, 4 })};
    const msg = shapePositiveMessage(answers, authorities, additionals);

    const shaped = try shapeResponse(a, msg, .a, false, false, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 1), shaped.answers.len);
    try testing.expectEqual(dns.RType.a, shaped.answers[0].rtype);
    try testing.expectEqual(@as(usize, 0), shaped.authorities.len);
    try testing.expectEqual(@as(usize, 0), shaped.additionals.len);
}

test "shape: positive DO=1 keeps NSEC + RRSIG-over-NSEC in authority (wildcard proof preserved)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const answers: []const dns.ResourceRecord = &.{
        shapeARecord(.{ 192, 0, 2, 1 }),
        shapeRrsigRecord(.a),
    };
    const authorities: []const dns.ResourceRecord = &.{
        shapeNsRecord(),
        shapeRrsigRecord(.ns),
        shapeNsecRecord(),
        shapeRrsigRecord(.nsec),
    };
    const msg = shapePositiveMessage(answers, authorities, &.{});

    const shaped = try shapeResponse(a, msg, .a, true, false, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 2), shaped.answers.len);
    try testing.expectEqual(@as(usize, 2), shaped.authorities.len);
    try testing.expectEqual(@as(usize, 1), countByType(shaped.authorities, .nsec));
    try testing.expectEqual(@as(usize, 1), countByType(shaped.authorities, .rrsig));
    try testing.expectEqual(dns.RType.nsec, shaped.authorities[1].rdata.rrsig.type_covered);
}

test "shape: qtype=NS preserves authority NS + additional glue (root priming carve-out)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const answers: []const dns.ResourceRecord = &.{shapeNsRecord()};
    const authorities: []const dns.ResourceRecord = &.{shapeNsRecord()};
    const additionals: []const dns.ResourceRecord = &.{shapeGlueRecord(.{ 1, 2, 3, 4 })};
    const msg = shapePositiveMessage(answers, authorities, additionals);

    const shaped = try shapeResponse(a, msg, .ns, false, false, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 1), shaped.answers.len);
    try testing.expectEqual(@as(usize, 1), shaped.authorities.len);
    try testing.expectEqual(@as(usize, 1), shaped.additionals.len);
}

test "shape: minimal_responses=false on positive answer preserves authority + additional" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const answers: []const dns.ResourceRecord = &.{shapeARecord(.{ 192, 0, 2, 1 })};
    const authorities: []const dns.ResourceRecord = &.{shapeNsRecord()};
    const additionals: []const dns.ResourceRecord = &.{shapeGlueRecord(.{ 1, 2, 3, 4 })};
    const msg = shapePositiveMessage(answers, authorities, additionals);

    const shaped = try shapeResponse(a, msg, .a, false, false, false, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 1), shaped.authorities.len);
    try testing.expectEqual(@as(usize, 1), shaped.additionals.len);
}

test "shape: NXDOMAIN keeps SOA, keeps NSEC + RRSIG on DO=1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const authorities: []const dns.ResourceRecord = &.{
        shapeSoaRecord(),
        shapeRrsigRecord(.soa),
        shapeNsecRecord(),
        shapeRrsigRecord(.nsec),
    };
    const msg = shapeNxdomainMessage(authorities);

    const shaped = try shapeResponse(a, msg, .a, true, false, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 4), shaped.authorities.len);
    try testing.expectEqual(@as(usize, 1), countByType(shaped.authorities, .soa));
    try testing.expectEqual(@as(usize, 1), countByType(shaped.authorities, .nsec));
    try testing.expectEqual(@as(usize, 2), countByType(shaped.authorities, .rrsig));
}

test "shape: NXDOMAIN keeps SOA on DO=0 (RFC 2308 negative cache), strips NSEC/RRSIG" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const authorities: []const dns.ResourceRecord = &.{
        shapeSoaRecord(),
        shapeRrsigRecord(.soa),
        shapeNsecRecord(),
        shapeRrsigRecord(.nsec),
    };
    const msg = shapeNxdomainMessage(authorities);

    const shaped = try shapeResponse(a, msg, .a, false, false, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 1), shaped.authorities.len);
    try testing.expectEqual(dns.RType.soa, shaped.authorities[0].rtype);
}

test "shape: CD=1 with DO=0 still preserves validation material (RFC 4035 §3.2.2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const answers: []const dns.ResourceRecord = &.{ shapeARecord(.{ 192, 0, 2, 1 }), shapeRrsigRecord(.a) };
    const authorities: []const dns.ResourceRecord = &.{ shapeNsecRecord(), shapeRrsigRecord(.nsec) };
    const msg = shapePositiveMessage(answers, authorities, &.{});

    const shaped = try shapeResponse(a, msg, .a, false, true, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 2), shaped.answers.len);
    try testing.expectEqual(@as(usize, 2), shaped.authorities.len);
}

test "shape: orphan RRSIG covering stripped NS is removed (no covered-record leak)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const answers: []const dns.ResourceRecord = &.{shapeARecord(.{ 192, 0, 2, 1 })};
    const authorities: []const dns.ResourceRecord = &.{ shapeNsRecord(), shapeRrsigRecord(.ns) };
    const msg = shapePositiveMessage(answers, authorities, &.{});

    const shaped = try shapeResponse(a, msg, .a, true, false, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 0), shaped.authorities.len);
}

test "shape: explicit qtype=NSEC keeps NSEC in answer even with DO=0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const answers: []const dns.ResourceRecord = &.{shapeNsecRecord()};
    const msg = shapePositiveMessage(answers, &.{}, &.{});

    const shaped = try shapeResponse(a, msg, .nsec, false, false, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 1), shaped.answers.len);
    try testing.expectEqual(dns.RType.nsec, shaped.answers[0].rtype);
}

test "shape: cname-chain answer authority NSEC kept on DO=1 (the wildcard-chain case)" {
    // The original concern from the adversarial reviewer: a CNAME chain
    // terminating in a wildcard-expanded answer carries the wildcard's
    // NSEC proof in authority. Stripping it breaks downstream validators.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cname_target = dns.Name{ .labels = &.{ "target", "example", "com" } };
    const cname_rr = dns.ResourceRecord{
        .name = shape_test_name,
        .rtype = .cname,
        .rclass = .in,
        .ttl = 60,
        .rdata = .{ .cname = cname_target },
    };
    const answers: []const dns.ResourceRecord = &.{ cname_rr, shapeARecord(.{ 192, 0, 2, 1 }) };
    const authorities: []const dns.ResourceRecord = &.{ shapeNsecRecord(), shapeRrsigRecord(.nsec) };
    const msg = shapePositiveMessage(answers, authorities, &.{});

    const shaped = try shapeResponse(a, msg, .a, true, false, true, &rebinding.Config.off);

    try testing.expectEqual(@as(usize, 2), shaped.answers.len);
    try testing.expectEqual(@as(usize, 2), shaped.authorities.len);
}

test "shape: fast path returns input slice unmodified when nothing would be filtered" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const answers: []const dns.ResourceRecord = &.{shapeARecord(.{ 192, 0, 2, 1 })};
    const msg = shapePositiveMessage(answers, &.{}, &.{});

    const shaped = try shapeResponse(a, msg, .a, true, false, true, &rebinding.Config.off);

    try testing.expectEqual(answers.ptr, shaped.answers.ptr);
}
