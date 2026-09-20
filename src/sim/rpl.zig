//! Loader for `.rpl` scenarios: the hark dialect of Unbound's testbound
//! format plus the vendored corpus. Mirrors test/harness/rpl.py; whatever
//! the Python parser accepts, this must too.
//!
//! Everything is allocated from the caller's arena, never freed piecemeal.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("../dns.zig");
const na = @import("../net_address.zig");
const dns64 = @import("../dns64.zig");

/// testbound's default; corpus RRs mostly omit the TTL, and hark refuses
/// to cache TTL 0.
pub const default_ttl: u32 = 3600;

/// MATCH flags from every context; which ones a context honours is the
/// runner's business. An unknown flag is a parse error, as in Python.
pub const Match = packed struct {
    opcode: bool = false,
    qname: bool = false,
    qtype: bool = false,
    qclass: bool = false,
    question: bool = false,
    subdomain: bool = false,
    tcp: bool = false,
    udp: bool = false,
    all: bool = false,
    answer: bool = false,
    authority: bool = false,
    additional: bool = false,
    flags: bool = false,
    rcode: bool = false,
    ttl: bool = false,
    order: bool = false,

    pub fn isEmpty(m: Match) bool {
        return @as(u16, @bitCast(m)) == 0;
    }
};

pub const QueryLogRow = struct {
    qname: dns.Name,
    qtype: dns.RType,
    dest: ?na.Address,
};

/// `DS PLACEHOLDER [<zone>]`: the digest of a key minted at run time;
/// `zone` plants another zone's digest at this owner.
pub const DsFrom = struct { owner: dns.Name, zone: dns.Name };

pub const Entry = struct {
    match: Match = .{},
    /// REPLY flags and rcode; the responder forces QR regardless.
    flags: dns.Header.Flags = no_flags,
    /// REPLY DO on a STEP QUERY; no-op on responder entries.
    do_bit: bool = false,
    /// REPLY EDNS: send an OPT without DO.
    edns: bool = false,
    /// MATCH ede=<code> on CHECK_ANSWER.
    ede: ?u16 = null,
    /// ADJUST drop: a blackholed authority.
    drop: bool = false,
    /// ADJUST force_lower_qname: the responder lowercases the echoed question.
    force_lower_qname: bool = false,
    /// ADJUST unsigned: the signer leaves the entry alone (an unsigned zone
    /// served from a signed zone's address).
    unsigned: bool = false,
    sign_as: ?dns.Name = null,
    wildcard: ?dns.Name = null,
    ds_from: []const DsFrom = &.{},
    questions: []const dns.Question = &.{},
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
    additionals: []const dns.ResourceRecord = &.{},
    query_log: []const QueryLogRow = &.{},
};

pub const Range = struct {
    start: u32,
    end: u32,
    address: na.Address,
    entries: []const Entry,
};

pub const Step = struct {
    n: u32,
    kind: Kind,
    entry: ?Entry = null,
    /// TIME_PASSES: seconds to advance.
    seconds: u32 = 0,
    /// CHECK_MAX_QUERIES: bound on upstream queries so far.
    max_queries: u32 = 0,

    pub const Kind = enum {
        query,
        check_answer,
        check_query_log,
        check_out_query,
        check_max_queries,
        /// Drop the next upstream query as if the authority timed out.
        timeout,
        time_passes,
    };
};

pub const Scenario = struct {
    name: []const u8 = "",
    root_hints: []const na.Address = &.{},
    ranges: []const Range = &.{},
    steps: []const Step = &.{},
    /// `; hark:` directives and Unbound-prelude equivalents; null is the
    /// harness default.
    qmin: ?bool = null,
    minimal_responses: ?bool = null,
    rebinding_enabled: ?bool = null,
    rebinding_allow_zones: []const []const u8 = &.{},
    rebinding_extra_block: []const []const u8 = &.{},
    rebinding_extra_allow: []const []const u8 = &.{},
    stagger_ms: ?u32 = null,
    dns64_prefix: ?dns64.Prefix = null,
    serve_stale_ttl: ?u32 = null,
    min_ttl: ?u32 = null,
    prefetch: ?bool = null,
    client_timeout_ms: u32 = 5000,
    /// Zones the harness signs; the first must be the root.
    dnssec_zones: []const []const u8 = &.{},
};

pub const no_flags: dns.Header.Flags = .{
    .rcode = .no_error,
    .cd = false,
    .ad = false,
    .z = 0,
    .ra = false,
    .rd = false,
    .tc = false,
    .aa = false,
    .opcode = .query,
    .qr = false,
};

pub const Diag = struct {
    line: usize = 0,
    msg: []const u8 = "",
};

pub const Error = error{ Parse, UnsupportedRType } || dns.Error;

/// Not in the RType enum; the resolver synthesises it as an unknown type.
pub const hinfo: dns.RType = @fromBackingInt(13);

/// Unbound's `server:` … `CONFIG_END` prelude is lifted as the Python
/// harness does: stripped, qmin and minimal-responses honoured, the first
/// RANGE's ADDRESS the root hint. No address remapping: nothing here binds
/// a socket.
pub fn parse(arena: Allocator, text: []const u8, diag: *Diag) Error!Scenario {
    var p: Parser = .{ .arena = arena, .diag = diag, .lines = mem.splitScalar(u8, text, '\n') };
    return p.parse(text);
}

const Parser = struct {
    arena: Allocator,
    diag: *Diag,
    lines: mem.SplitIterator(u8, .scalar),
    lineno: usize = 0,
    /// The current significant line, held until `advance`.
    cur: ?[]const u8 = null,
    /// The lifted corpus's root hint and the default for an ADDRESS-less
    /// RANGE, as in the Python lifter.
    first_address: ?na.Address = null,
    scenario: Scenario = .{},

    fn fail(p: *Parser, msg: []const u8) Error {
        p.diag.* = .{ .line = p.lineno, .msg = msg };
        return error.Parse;
    }

    /// The next significant line, unconsumed. Applies `; hark:` directives
    /// from the comments it skips.
    fn peek(p: *Parser) Error!?[]const u8 {
        if (p.cur) |c| return c;
        while (p.lines.next()) |raw| {
            p.lineno += 1;
            const line = mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            if (line[0] == ';') {
                try p.directive(line[1..]);
                continue;
            }
            p.cur = line;
            return line;
        }
        return null;
    }

    fn advance(p: *Parser) void {
        p.cur = null;
    }

    fn next(p: *Parser) Error![]const u8 {
        const line = try p.peek() orelse return p.fail("unexpected end of file");
        p.advance();
        return line;
    }

    fn directive(p: *Parser, comment: []const u8) Error!void {
        var rest = mem.trimStart(u8, comment, " \t");
        if (!mem.startsWith(u8, rest, "hark")) return;
        rest = mem.trimStart(u8, rest[4..], " \t");
        if (rest.len == 0 or rest[0] != ':') return;
        const eq = mem.indexOfScalar(u8, rest, '=') orelse return p.fail("hark directive without '='");
        const key = mem.trim(u8, rest[1..eq], " \t");
        const val = mem.trim(u8, rest[eq + 1 ..], " \t");
        try p.applyDirective(key, val);
    }

    fn applyDirective(p: *Parser, key: []const u8, val: []const u8) Error!void {
        const s = &p.scenario;
        if (mem.eql(u8, key, "root-hints")) {
            var list: std.ArrayList(na.Address) = .empty;
            var it = mem.splitScalar(u8, val, ',');
            while (it.next()) |tok| {
                const t = mem.trim(u8, tok, " \t");
                if (t.len == 0) continue;
                try list.append(p.arena, try p.parseAddr(t));
            }
            s.root_hints = list.items;
        } else if (mem.eql(u8, key, "qname-minimisation") or mem.eql(u8, key, "qname-minimization")) {
            s.qmin = yes(val);
        } else if (mem.eql(u8, key, "minimal-responses")) {
            s.minimal_responses = yes(val);
        } else if (mem.eql(u8, key, "rebinding-enabled")) {
            s.rebinding_enabled = yes(val);
        } else if (mem.eql(u8, key, "rebinding-allow-zone")) {
            s.rebinding_allow_zones = try appendStr(p.arena, s.rebinding_allow_zones, val);
        } else if (mem.eql(u8, key, "rebinding-extra-block")) {
            s.rebinding_extra_block = try appendStr(p.arena, s.rebinding_extra_block, val);
        } else if (mem.eql(u8, key, "rebinding-extra-allow")) {
            s.rebinding_extra_allow = try appendStr(p.arena, s.rebinding_extra_allow, val);
        } else if (mem.eql(u8, key, "stagger-ms")) {
            s.stagger_ms = try p.int(u32, val);
        } else if (mem.eql(u8, key, "dns64-prefix")) {
            s.dns64_prefix = dns64.Prefix.parse(val) orelse return p.fail("dns64-prefix: not an RFC 6052 prefix");
        } else if (mem.eql(u8, key, "serve-stale-ttl")) {
            s.serve_stale_ttl = try p.int(u32, val);
        } else if (mem.eql(u8, key, "min-ttl")) {
            s.min_ttl = try p.int(u32, val);
        } else if (mem.eql(u8, key, "prefetch")) {
            s.prefetch = yes(val);
        } else if (mem.eql(u8, key, "client-timeout")) {
            const secs = std.fmt.parseFloat(f64, val) catch return p.fail("client-timeout: not a number");
            s.client_timeout_ms = @intFromFloat(secs * 1000);
        } else if (mem.eql(u8, key, "dnssec-zone")) {
            const lowered = try std.ascii.allocLowerString(p.arena, dns.stripTrailingDot(val));
            const canon = if (lowered.len == 0) "." else lowered;
            if (s.dnssec_zones.len == 0 and !mem.eql(u8, canon, "."))
                return p.fail("first dnssec-zone must be `.`");
            for (s.dnssec_zones) |z| if (mem.eql(u8, z, canon)) return;
            s.dnssec_zones = try appendStr(p.arena, s.dnssec_zones, canon);
        } else return p.fail("unknown hark directive");
    }

    fn parse(p: *Parser, text: []const u8) Error!Scenario {
        try p.lift(text);
        const head = try p.next();
        if (!mem.startsWith(u8, head, "SCENARIO_BEGIN")) return p.fail("expected SCENARIO_BEGIN");
        p.scenario.name = mem.trim(u8, head["SCENARIO_BEGIN".len..], " \t");

        var ranges: std.ArrayList(Range) = .empty;
        var steps: std.ArrayList(Step) = .empty;
        while (try p.peek()) |line| {
            if (mem.eql(u8, line, "SCENARIO_END")) {
                p.advance();
                p.scenario.ranges = ranges.items;
                p.scenario.steps = steps.items;
                if (p.scenario.root_hints.len == 0) {
                    const first = p.first_address orelse return p.fail("no root-hints and no ADDRESS to default to");
                    p.scenario.root_hints = try p.arena.dupe(na.Address, &.{first});
                }
                return p.scenario;
            }
            if (mem.startsWith(u8, line, "RANGE_BEGIN")) {
                try ranges.append(p.arena, try p.range(line));
            } else if (mem.startsWith(u8, line, "STEP")) {
                const step = try p.parseStep(line);
                for (steps.items) |s| if (s.n == step.n) return p.fail("duplicate STEP number");
                try steps.append(p.arena, step);
            } else return p.fail("unexpected directive at scenario level");
        }
        return p.fail("missing SCENARIO_END");
    }

    /// Skip the corpus prelude to CONFIG_END, reading the two knobs the
    /// lifter translates.
    fn lift(p: *Parser, text: []const u8) Error!void {
        const end = mem.indexOf(u8, text, "CONFIG_END") orelse return;
        const prelude = text[0..end];
        if (mem.indexOf(u8, prelude, "server:") == null) return;
        if (findKnob(prelude, "qname-minimisation:")) |v| p.scenario.qmin = yes(v);
        if (findKnob(prelude, "minimal-responses:")) |v| p.scenario.minimal_responses = yes(v);
        while (p.lines.next()) |raw| {
            p.lineno += 1;
            if (mem.startsWith(u8, mem.trimStart(u8, raw, " \t"), "CONFIG_END")) return;
        }
    }

    fn range(p: *Parser, head: []const u8) Error!Range {
        p.advance();
        var toks = mem.tokenizeAny(u8, head, " \t");
        _ = toks.next();
        const start = try p.int(u32, toks.next() orelse return p.fail("RANGE_BEGIN takes <start> <end>"));
        const end = try p.int(u32, toks.next() orelse return p.fail("RANGE_BEGIN takes <start> <end>"));
        if (toks.next() != null) return p.fail("RANGE_BEGIN takes <start> <end>");

        var addr_seen: ?na.Address = null;
        var entries: std.ArrayList(Entry) = .empty;
        while (try p.peek()) |line| {
            if (mem.startsWith(u8, line, "ADDRESS")) {
                p.advance();
                var t = mem.tokenizeAny(u8, line, " \t");
                _ = t.next();
                addr_seen = try p.parseAddr(t.next() orelse return p.fail("ADDRESS takes one IP"));
                if (t.next() != null) return p.fail("ADDRESS takes one IP");
                if (p.first_address == null) p.first_address = addr_seen;
            } else if (mem.eql(u8, line, "ENTRY_BEGIN")) {
                p.advance();
                try entries.append(p.arena, try p.entry());
            } else if (mem.eql(u8, line, "RANGE_END")) {
                p.advance();
                // Unbound's corpus omits ADDRESS for the default server.
                const addr = addr_seen orelse if (p.scenario.root_hints.len > 0) p.scenario.root_hints[0] else p.first_address orelse
                    return p.fail("RANGE without ADDRESS and no root-hints to default to");
                return .{ .start = start, .end = end, .address = addr, .entries = entries.items };
            } else return p.fail("unexpected line in RANGE");
        }
        return p.fail("missing RANGE_END");
    }

    fn parseStep(p: *Parser, head: []const u8) Error!Step {
        p.advance();
        var toks = mem.tokenizeAny(u8, head, " \t");
        _ = toks.next();
        const n = try p.int(u32, toks.next() orelse return p.fail("STEP takes <n> <KIND>"));
        const kind_str = toks.next() orelse return p.fail("STEP takes <n> <KIND>");
        const kind = enumIgnoreCase(Step.Kind, kind_str) orelse return p.fail("unknown STEP kind");
        switch (kind) {
            .time_passes => {
                // `ELAPSE <n>` (corpus) or `EVAL "<n>"` (docs). A bare
                // TIME_PASSES would advance by 0 and launder every check.
                while (toks.next()) |t| {
                    if (mem.eql(u8, t, "ELAPSE") or mem.eql(u8, t, "EVAL")) {
                        const v = mem.trim(u8, toks.next() orelse break, "\"");
                        return .{ .n = n, .kind = kind, .seconds = try p.int(u32, v) };
                    }
                }
                return p.fail("TIME_PASSES needs `ELAPSE <n>` or `EVAL \"<n>\"`");
            },
            .timeout => return .{ .n = n, .kind = kind },
            .check_max_queries => {
                const bound = try p.int(u32, toks.next() orelse return p.fail("CHECK_MAX_QUERIES takes one integer"));
                if (toks.next() != null) return p.fail("CHECK_MAX_QUERIES takes one integer");
                return .{ .n = n, .kind = kind, .max_queries = bound };
            },
            else => {
                const line = try p.next();
                if (!mem.eql(u8, line, "ENTRY_BEGIN")) return p.fail("STEP requires an ENTRY block");
                return .{ .n = n, .kind = kind, .entry = try p.entry() };
            },
        }
    }

    const Section = enum { question, answer, authority, additional, query_log };

    fn entry(p: *Parser) Error!Entry {
        var e: Entry = .{};
        var section: ?Section = null;
        var questions: std.ArrayList(dns.Question) = .empty;
        var answers: std.ArrayList(dns.ResourceRecord) = .empty;
        var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
        var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
        var query_log: std.ArrayList(QueryLogRow) = .empty;
        var ds_from: std.ArrayList(DsFrom) = .empty;
        while (try p.peek()) |line| {
            p.advance();
            if (mem.eql(u8, line, "ENTRY_END")) {
                e.questions = questions.items;
                e.answers = answers.items;
                e.authorities = authorities.items;
                e.additionals = additionals.items;
                e.query_log = query_log.items;
                e.ds_from = ds_from.items;
                return e;
            }
            var toks = mem.tokenizeAny(u8, line, " \t");
            const head = toks.next().?;
            if (mem.eql(u8, head, "MATCH")) {
                while (toks.next()) |t| try p.matchFlag(&e, t);
            } else if (mem.eql(u8, head, "ADJUST")) {
                while (toks.next()) |t| {
                    if (eqlLower(t, "drop")) {
                        e.drop = true;
                    } else if (eqlLower(t, "force_lower_qname")) {
                        e.force_lower_qname = true;
                    } else if (eqlLower(t, "unsigned")) {
                        e.unsigned = true;
                    } else if (!eqlLower(t, "copy_id") and !eqlLower(t, "copy_query")) {
                        return p.fail("unknown ADJUST flag");
                    }
                }
            } else if (mem.eql(u8, head, "SIGN_AS")) {
                e.sign_as = try p.name(toks.next() orelse return p.fail("SIGN_AS takes one zone"));
                if (toks.next() != null) return p.fail("SIGN_AS takes one zone");
            } else if (mem.eql(u8, head, "WILDCARD")) {
                const owner = toks.next() orelse return p.fail("WILDCARD takes one owner");
                if (!mem.startsWith(u8, owner, "*.") or toks.next() != null) return p.fail("WILDCARD takes one wildcard owner");
                e.wildcard = try p.name(owner);
            } else if (mem.eql(u8, head, "REPLY")) {
                while (toks.next()) |t| try p.replyToken(&e, t);
            } else if (mem.eql(u8, head, "SECTION")) {
                const s = toks.next() orelse return p.fail("bad SECTION");
                if (toks.next() != null) return p.fail("bad SECTION");
                section = enumIgnoreCase(Section, s) orelse return p.fail("bad SECTION");
            } else switch (section orelse return p.fail("RR outside SECTION")) {
                .question => try questions.append(p.arena, try p.question(line)),
                .query_log => try query_log.append(p.arena, try p.queryLogRow(line)),
                .answer => try p.addRr(&answers, &ds_from, line),
                .authority => try p.addRr(&authorities, &ds_from, line),
                .additional => try p.addRr(&additionals, &ds_from, line),
            }
        }
        return p.fail("missing ENTRY_END");
    }

    fn matchFlag(p: *Parser, e: *Entry, flag: []const u8) Error!void {
        var buf: [16]u8 = undefined;
        if (flag.len > buf.len) return p.fail("unknown MATCH flag");
        const t = std.ascii.lowerString(&buf, flag);
        if (mem.startsWith(u8, t, "ede=")) {
            e.ede = try p.int(u16, t[4..]);
            return;
        }
        inline for (@typeInfo(Match).@"struct".field_names) |field_name| {
            if (mem.eql(u8, t, field_name)) {
                @field(e.match, field_name) = true;
                return;
            }
        }
        return p.fail("unknown MATCH flag");
    }

    fn replyToken(p: *Parser, e: *Entry, t: []const u8) Error!void {
        const flags = &e.flags;
        if (mem.eql(u8, t, "QR")) {
            flags.qr = true;
        } else if (mem.eql(u8, t, "AA")) {
            flags.aa = true;
        } else if (mem.eql(u8, t, "TC")) {
            flags.tc = true;
        } else if (mem.eql(u8, t, "RD")) {
            flags.rd = true;
        } else if (mem.eql(u8, t, "RA")) {
            flags.ra = true;
        } else if (mem.eql(u8, t, "AD")) {
            flags.ad = true;
        } else if (mem.eql(u8, t, "CD")) {
            flags.cd = true;
        } else if (mem.eql(u8, t, "DO")) {
            e.do_bit = true;
        } else if (mem.eql(u8, t, "EDNS")) {
            e.edns = true;
        } else if (mem.eql(u8, t, "QUERY")) {
            flags.opcode = .query;
        } else if (mem.eql(u8, t, "NOTIFY")) {
            flags.opcode = @fromBackingInt(4);
        } else if (mem.eql(u8, t, "UPDATE")) {
            flags.opcode = @fromBackingInt(5);
        } else if (rcodeFromText(t)) |rc| {
            flags.rcode = rc;
        } else return p.fail("unknown REPLY token");
    }

    fn question(p: *Parser, line: []const u8) Error!dns.Question {
        var toks = mem.tokenizeAny(u8, line, " \t");
        const owner = toks.next().?;
        const a = toks.next() orelse return p.fail("bad QUESTION line");
        const b = toks.next();
        if (toks.next() != null) return p.fail("bad QUESTION line");
        const type_tok = b orelse a;
        if (b != null and !eqlLower(a, "in")) return p.fail("only class IN is supported");
        return .{
            .name = try p.name(owner),
            .qtype = rtypeFromText(type_tok) orelse return p.fail("bad QUESTION type"),
            .qclass = .in,
        };
    }

    fn queryLogRow(p: *Parser, line: []const u8) Error!QueryLogRow {
        var toks = mem.tokenizeAny(u8, line, " \t");
        const owner = toks.next().?;
        const qtype = toks.next() orelse return p.fail("bad QUERY_LOG line (want `qname qtype [dest]`)");
        const dest = toks.next();
        if (toks.next() != null) return p.fail("bad QUERY_LOG line (want `qname qtype [dest]`)");
        return .{
            .qname = try p.name(owner),
            .qtype = rtypeFromText(qtype) orelse return p.fail("bad QUERY_LOG qtype"),
            .dest = if (dest) |d| try p.parseAddr(d) else null,
        };
    }

    /// Same-(owner, type) RRs stay adjacent in first-seen order, so an
    /// RRset asserts as one unit.
    fn addRr(p: *Parser, list: *std.ArrayList(dns.ResourceRecord), ds_from: *std.ArrayList(DsFrom), line: []const u8) Error!void {
        var record = try p.parseRr(line, ds_from);
        for (list.items, 0..) |existing, i| {
            if (existing.rtype == record.rtype and existing.name.eql(record.name)) {
                var j = i + 1;
                while (j < list.items.len and list.items[j].rtype == record.rtype and list.items[j].name.eql(record.name)) j += 1;
                record.ttl = existing.ttl;
                try list.insert(p.arena, j, record);
                return;
            }
        }
        try list.append(p.arena, record);
    }

    /// `name [ttl] [class] type rdata…` in any of testbound's orders.
    fn parseRr(p: *Parser, raw: []const u8, ds_from: *std.ArrayList(DsFrom)) Error!dns.ResourceRecord {
        // `;` ends the record unless quoted (`;{id = 2854}`).
        var line = raw;
        var quoted = false;
        for (raw, 0..) |c, i| {
            quoted = quoted != (c == '"');
            if (c == ';' and !quoted) {
                line = raw[0..i];
                break;
            }
        }
        var toks = mem.tokenizeAny(u8, line, " \t");
        const owner = try p.name(toks.next().?);
        var ttl: u32 = default_ttl;
        var t = toks.next() orelse return p.fail("RR needs a type");
        if (isDigits(t)) {
            ttl = try p.int(u32, t);
            t = toks.next() orelse return p.fail("RR needs a type");
        }
        if (eqlLower(t, "in")) {
            t = toks.next() orelse return p.fail("RR needs a type");
        } else if (eqlLower(t, "ch") or eqlLower(t, "hs")) return p.fail("only class IN is supported");
        if (isDigits(t)) {
            ttl = try p.int(u32, t);
            t = toks.next() orelse return p.fail("RR needs a type");
        }
        const rtype = rtypeFromText(t) orelse return p.fail("unknown RR type");
        return .{ .name = owner, .rtype = rtype, .rclass = .in, .ttl = ttl, .rdata = try p.rdata(rtype, owner, &toks, ds_from) };
    }

    fn rdata(p: *Parser, rtype: dns.RType, owner: dns.Name, toks: *mem.TokenIterator(u8, .any), ds_from: *std.ArrayList(DsFrom)) Error!dns.RData {
        const arena = p.arena;
        switch (rtype) {
            .a => {
                const addr = try p.parseAddr(try p.word(toks));
                if (addr != .ip4) return p.fail("A rdata is not IPv4");
                return .{ .a = addr.ip4.bytes };
            },
            .aaaa => {
                const addr = try p.parseAddr(try p.word(toks));
                if (addr != .ip6) return p.fail("AAAA rdata is not IPv6");
                return .{ .aaaa = addr.ip6.bytes };
            },
            .ns => return .{ .ns = try p.name(try p.word(toks)) },
            .cname => return .{ .cname = try p.name(try p.word(toks)) },
            .dname => return .{ .dname = try p.name(try p.word(toks)) },
            .ptr => return .{ .ptr = try p.name(try p.word(toks)) },
            .mx => return .{ .mx = .{
                .preference = try p.int(u16, try p.word(toks)),
                .exchange = try p.name(try p.word(toks)),
            } },
            .soa => return .{ .soa = .{
                .mname = try p.name(try p.word(toks)),
                .rname = try p.name(try p.word(toks)),
                .serial = try p.int(u32, try p.word(toks)),
                .refresh = try p.int(u32, try p.word(toks)),
                .retry = try p.int(u32, try p.word(toks)),
                .expire = try p.int(u32, try p.word(toks)),
                .minimum = try p.int(u32, try p.word(toks)),
            } },
            .txt => return .{ .txt = .{ .strings = try p.charStrings(toks) } },
            .ds => {
                const first = try p.word(toks);
                if (eqlLower(first, "placeholder")) {
                    // Key tag 0 marks it; the signer fills in the digest.
                    const zone = if (toks.next()) |z| try p.name(z) else owner;
                    try ds_from.append(arena, .{ .owner = owner, .zone = zone });
                    return .{ .ds = .{
                        .key_tag = 0,
                        .algorithm = .ecdsap256sha256,
                        .digest_type = @fromBackingInt(2),
                        .digest = try arena.alloc(u8, 32),
                    } };
                }
                return .{ .ds = .{
                    .key_tag = try p.int(u16, first),
                    .algorithm = @fromBackingInt(try p.int(u8, try p.word(toks))),
                    .digest_type = @fromBackingInt(try p.int(u8, try p.word(toks))),
                    .digest = try p.hex(toks),
                } };
            },
            .dnskey => return .{ .dnskey = .{
                .flags = try p.int(u16, try p.word(toks)),
                .protocol = try p.int(u8, try p.word(toks)),
                .algorithm = try p.algorithm(try p.word(toks)),
                .public_key = try p.base64(toks),
            } },
            .rrsig => return .{ .rrsig = .{
                .type_covered = rtypeFromText(try p.word(toks)) orelse return p.fail("unknown RRSIG type covered"),
                .algorithm = try p.algorithm(try p.word(toks)),
                .labels = try p.int(u8, try p.word(toks)),
                .original_ttl = try p.int(u32, try p.word(toks)),
                .sig_expiration = try p.sigTime(try p.word(toks)),
                .sig_inception = try p.sigTime(try p.word(toks)),
                .key_tag = try p.int(u16, try p.word(toks)),
                .signer_name = try p.name(try p.word(toks)),
                .signature = try p.base64(toks),
            } },
            .nsec => return .{ .nsec = .{
                .next_domain_name = try p.name(try p.word(toks)),
                .type_bit_maps = try p.typeBitmap(toks),
            } },
            else => {
                if (rtype != hinfo) return error.UnsupportedRType;
                // Wire form, as the resolver synthesises it (RFC 8482).
                var wire: std.ArrayList(u8) = .empty;
                for (try p.charStrings(toks)) |str| {
                    if (str.len > 255) return p.fail("character-string too long");
                    try wire.append(arena, @intCast(str.len));
                    try wire.appendSlice(arena, str);
                }
                return .{ .unknown = wire.items };
            },
        }
    }

    /// Quoted strings may span tokens; bare tokens are one each.
    fn charStrings(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const []const u8 {
        var strings: std.ArrayList([]const u8) = .empty;
        while (toks.next()) |t| {
            if (t[0] != '"') {
                try strings.append(p.arena, t);
                continue;
            }
            const start = @intFromPtr(t.ptr) - @intFromPtr(toks.buffer.ptr) + 1;
            const close = mem.indexOfScalarPos(u8, toks.buffer, start, '"') orelse return p.fail("unterminated quoted string");
            try strings.append(p.arena, toks.buffer[start..close]);
            toks.index = close + 1;
        }
        return strings.items;
    }

    fn hex(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const u8 {
        var text: std.ArrayList(u8) = .empty;
        while (toks.next()) |t| try text.appendSlice(p.arena, t);
        if (text.items.len % 2 != 0) return p.fail("odd-length hex");
        const out = try p.arena.alloc(u8, text.items.len / 2);
        _ = std.fmt.hexToBytes(out, text.items) catch return p.fail("bad hex");
        return out;
    }

    /// A number, or an IANA mnemonic as older corpus files spell it.
    fn algorithm(p: *Parser, text: []const u8) Error!dns.DnssecAlgorithm {
        if (isDigits(text)) return @fromBackingInt(try p.int(u8, text));
        const table = .{
            .{ "DSA", 3 },              .{ "RSASHA1", 5 },    .{ "RSASHA1-NSEC3-SHA1", 7 },
            .{ "RSASHA256", 8 },        .{ "RSASHA512", 10 }, .{ "ECDSAP256SHA256", 13 },
            .{ "ECDSAP384SHA384", 14 }, .{ "ED25519", 15 },   .{ "ED448", 16 },
        };
        inline for (table) |row| if (std.ascii.eqlIgnoreCase(text, row[0])) return @fromBackingInt(row[1]);
        return p.fail("unknown DNSSEC algorithm");
    }

    /// Base64 that may span tokens, padded or not.
    fn base64(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const u8 {
        var text: std.ArrayList(u8) = .empty;
        while (toks.next()) |t| try text.appendSlice(p.arena, t);
        const bare = mem.trimEnd(u8, text.items, "=");
        const dec = std.base64.standard_no_pad.Decoder;
        const out = try p.arena.alloc(u8, dec.calcSizeForSlice(bare) catch return p.fail("bad base64"));
        dec.decode(out, bare) catch return p.fail("bad base64");
        return out;
    }

    /// RFC 4034 §3.2: YYYYMMDDHHmmSS, or seconds since the epoch.
    fn sigTime(p: *Parser, text: []const u8) Error!u32 {
        if (text.len != 14) return p.int(u32, text);
        const y = try p.int(i64, text[0..4]);
        const m = try p.int(i64, text[4..6]);
        const d = try p.int(i64, text[6..8]);
        const secs = try p.int(i64, text[8..10]) * 3600 + try p.int(i64, text[10..12]) * 60 + try p.int(i64, text[12..14]);
        // Hinnant's days-from-civil: era-based, no month table.
        const yy = y - @intFromBool(m <= 2);
        const era = @divFloor(yy, 400);
        const yoe = yy - era * 400;
        const doy = @divTrunc(153 * (m + (if (m > 2) @as(i64, -3) else 9)) + 2, 5) + d - 1;
        const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
        const days = era * 146097 + doe - 719468;
        return std.math.cast(u32, days * 86400 + secs) orelse p.fail("signature time out of range");
    }

    /// RFC 4034 §4.1.2 type bitmap from the remaining type mnemonics.
    fn typeBitmap(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var window: [256]u8 = undefined;
        var types: std.ArrayList(u16) = .empty;
        while (toks.next()) |t| try types.append(p.arena, @backingInt(rtypeFromText(t) orelse return p.fail("unknown type in bitmap")));
        mem.sortUnstable(u16, types.items, {}, std.sort.asc(u16));
        var i: usize = 0;
        while (i < types.items.len) {
            const win: u8 = @intCast(types.items[i] >> 8);
            @memset(&window, 0);
            var len: u8 = 0;
            while (i < types.items.len and types.items[i] >> 8 == win) : (i += 1) {
                const low: u8 = @truncate(types.items[i]);
                window[low >> 3] |= @as(u8, 0x80) >> @intCast(low & 7);
                len = (low >> 3) + 1;
            }
            try out.appendSlice(p.arena, &.{ win, len });
            try out.appendSlice(p.arena, window[0..len]);
        }
        return out.items;
    }

    fn word(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const u8 {
        return toks.next() orelse p.fail("rdata is short");
    }

    fn name(p: *Parser, text: []const u8) Error!dns.Name {
        return dns.parseDottedName(p.arena, text) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return p.fail("bad domain name"),
        };
    }

    fn parseAddr(p: *Parser, text: []const u8) Error!na.Address {
        return std.Io.net.IpAddress.parse(text, 53) catch p.fail("bad IP address");
    }

    fn int(p: *Parser, comptime T: type, text: []const u8) Error!T {
        return std.fmt.parseInt(T, text, 10) catch p.fail("bad integer");
    }
};

fn enumIgnoreCase(comptime E: type, s: []const u8) ?E {
    inline for (@typeInfo(E).@"enum".field_names) |field_name| {
        if (std.ascii.eqlIgnoreCase(s, field_name)) return @field(E, field_name);
    }
    return null;
}

fn findKnob(prelude: []const u8, key: []const u8) ?[]const u8 {
    const at = mem.indexOf(u8, prelude, key) orelse return null;
    const rest = prelude[at + key.len ..];
    const end = mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    return mem.trim(u8, rest[0..end], " \t\r\"");
}

fn yes(val: []const u8) bool {
    const v = mem.trim(u8, val, " \t\"");
    return eqlLower(v, "yes") or eqlLower(v, "true") or eqlLower(v, "on") or mem.eql(u8, v, "1");
}

fn eqlLower(a: []const u8, comptime lower: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, lower);
}

fn isDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn appendStr(arena: Allocator, list: []const []const u8, s: []const u8) Allocator.Error![]const []const u8 {
    const out = try arena.alloc([]const u8, list.len + 1);
    @memcpy(out[0..list.len], list);
    out[list.len] = s;
    return out;
}

pub fn rcodeFromText(t: []const u8) ?dns.RCode {
    const table = .{
        .{ "NOERROR", dns.RCode.no_error },
        .{ "FORMERR", dns.RCode.format_error },
        .{ "SERVFAIL", dns.RCode.server_failure },
        .{ "NXDOMAIN", dns.RCode.name_error },
        .{ "NOTIMP", dns.RCode.not_implemented },
        .{ "REFUSED", dns.RCode.refused },
        .{ "YXDOMAIN", dns.RCode.yx_domain },
    };
    inline for (table) |row| if (mem.eql(u8, t, row[0])) return row[1];
    return null;
}

pub fn rtypeFromText(t: []const u8) ?dns.RType {
    var buf: [16]u8 = undefined;
    if (t.len > buf.len) return null;
    const u = std.ascii.upperString(&buf, t);
    if (mem.startsWith(u8, u, "TYPE")) {
        const rtype: dns.RType = @fromBackingInt(std.fmt.parseInt(u16, u[4..], 10) catch return null);
        return rtype;
    }
    const table = .{
        .{ "A", dns.RType.a },                   .{ "NS", dns.RType.ns },         .{ "CNAME", dns.RType.cname },
        .{ "SOA", dns.RType.soa },               .{ "PTR", dns.RType.ptr },       .{ "MX", dns.RType.mx },
        .{ "TXT", dns.RType.txt },               .{ "AAAA", dns.RType.aaaa },     .{ "DNAME", dns.RType.dname },
        .{ "OPT", dns.RType.opt },               .{ "DS", dns.RType.ds },         .{ "RRSIG", dns.RType.rrsig },
        .{ "NSEC", dns.RType.nsec },             .{ "DNSKEY", dns.RType.dnskey }, .{ "NSEC3", dns.RType.nsec3 },
        .{ "NSEC3PARAM", dns.RType.nsec3param }, .{ "SVCB", dns.RType.svcb },     .{ "HTTPS", dns.RType.https },
        .{ "ANY", dns.RType.any },               .{ "HINFO", hinfo },
    };
    inline for (table) |row| if (mem.eql(u8, u, row[0])) return row[1];
    return null;
}

// ── Tests ───────────────────────────────────────────────────────────────

fn parseTest(arena: Allocator, text: []const u8) !Scenario {
    var diag: Diag = .{};
    return parse(arena, text, &diag) catch |err| {
        std.debug.print("line {d}: {s}\n", .{ diag.line, diag.msg });
        return err;
    };
}

test "minimal hark scenario" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const s = try parseTest(arena_state.allocator(),
        \\; hark: root-hints = 127.0.10.1
        \\
        \\SCENARIO_BEGIN minimal
        \\RANGE_BEGIN 0 100
        \\  ADDRESS 127.0.10.1
        \\  ENTRY_BEGIN
        \\    MATCH opcode qname
        \\    ADJUST copy_id copy_query
        \\    REPLY QR AA NOERROR
        \\    SECTION QUESTION
        \\      example.com. IN A
        \\    SECTION ANSWER
        \\      example.com. 3600 IN A 1.2.3.4
        \\      example.com. IN TXT "hello world" plain
        \\  ENTRY_END
        \\RANGE_END
        \\STEP 1 QUERY
        \\ENTRY_BEGIN
        \\  REPLY RD
        \\  SECTION QUESTION
        \\    example.com. IN A
        \\ENTRY_END
        \\STEP 2 CHECK_ANSWER
        \\ENTRY_BEGIN
        \\  MATCH rcode answer ede=3
        \\  REPLY QR RD RA NXDOMAIN
        \\  SECTION QUESTION
        \\    example.com. IN A
        \\ENTRY_END
        \\STEP 3 TIME_PASSES ELAPSE 10
        \\STEP 4 CHECK_MAX_QUERIES 7
        \\SCENARIO_END
    );
    try testing.expectEqualStrings("minimal", s.name);
    try testing.expectEqual(1, s.root_hints.len);
    try testing.expectEqual(1, s.ranges.len);
    const e = s.ranges[0].entries[0];
    try testing.expect(e.match.opcode and e.match.qname and !e.match.qtype);
    try testing.expect(e.flags.qr and e.flags.aa and e.flags.rcode == .no_error);
    try testing.expectEqual(2, e.answers.len);
    try testing.expectEqual([4]u8{ 1, 2, 3, 4 }, e.answers[0].rdata.a);
    try testing.expectEqualStrings("hello world", e.answers[1].rdata.txt.strings[0]);
    try testing.expectEqualStrings("plain", e.answers[1].rdata.txt.strings[1]);
    try testing.expectEqual(4, s.steps.len);
    try testing.expectEqual(Step.Kind.query, s.steps[0].kind);
    try testing.expect(s.steps[0].entry.?.flags.rd);
    try testing.expectEqual(3, s.steps[1].entry.?.ede.?);
    try testing.expectEqual(dns.RCode.name_error, s.steps[1].entry.?.flags.rcode);
    try testing.expectEqual(10, s.steps[2].seconds);
    try testing.expectEqual(7, s.steps[3].max_queries);
}

test "unbound prelude is lifted" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const s = try parseTest(arena_state.allocator(),
        \\; config options
        \\server:
        \\    qname-minimisation: "no"
        \\    minimal-responses: no
        \\stub-zone:
        \\    name: "."
        \\    stub-addr: 193.0.14.129   # K.ROOT-SERVERS.NET.
        \\CONFIG_END
        \\
        \\SCENARIO_BEGIN Test basic
        \\RANGE_BEGIN 0 100
        \\    ADDRESS 193.0.14.129
        \\ENTRY_BEGIN
        \\MATCH opcode qtype qname
        \\ADJUST copy_id
        \\REPLY QR NOERROR
        \\SECTION QUESTION
        \\. IN NS
        \\SECTION ANSWER
        \\. IN NS   K.ROOT-SERVERS.NET.
        \\SECTION ADDITIONAL
        \\K.ROOT-SERVERS.NET.   IN   A   193.0.14.129
        \\ENTRY_END
        \\RANGE_END
        \\RANGE_BEGIN 0 100
        \\ENTRY_BEGIN
        \\MATCH opcode qtype qname
        \\REPLY QR NOERROR
        \\SECTION QUESTION
        \\com. IN NS
        \\ENTRY_END
        \\RANGE_END
        \\STEP 1 QUERY
        \\ENTRY_BEGIN
        \\REPLY RD
        \\SECTION QUESTION
        \\www.example.com. IN A
        \\ENTRY_END
        \\STEP 10 CHECK_ANSWER
        \\ENTRY_BEGIN
        \\MATCH all
        \\REPLY QR RD RA NOERROR
        \\SECTION QUESTION
        \\www.example.com. IN A
        \\SECTION ANSWER
        \\www.example.com. IN A   10.20.30.40
        \\ENTRY_END
        \\SCENARIO_END
    );
    try testing.expectEqual(false, s.qmin.?);
    try testing.expectEqual(false, s.minimal_responses.?);
    try testing.expectEqual(1, s.root_hints.len);
    try testing.expect(na.ipEqual(s.root_hints[0], s.ranges[0].address));
    try testing.expect(na.ipEqual(s.ranges[1].address, s.ranges[0].address));
    try testing.expectEqual(0, s.ranges[0].entries[0].answers[0].name.labels.len);
    try testing.expectEqual(default_ttl, s.ranges[0].entries[0].answers[0].ttl);
    try testing.expect(s.steps[1].entry.?.match.all);
}

test "rejections" {
    const cases = [_]struct { text: []const u8, msg: []const u8 }{
        .{ .text = "SCENARIO_BEGIN x\nSTEP 1 QUERY\nENTRY_BEGIN\nMATCH quesiton\nENTRY_END\nSCENARIO_END", .msg = "unknown MATCH flag" },
        .{ .text = "SCENARIO_BEGIN x\nSTEP 1 QUERY\nENTRY_BEGIN\nADJUST copy_idd\nENTRY_END\nSCENARIO_END", .msg = "unknown ADJUST flag" },
        .{ .text = "SCENARIO_BEGIN x\nSTEP 1 QUERY\nENTRY_BEGIN\nREPLY QR NXOMAIN\nENTRY_END\nSCENARIO_END", .msg = "unknown REPLY token" },
        .{ .text = "SCENARIO_BEGIN x\nSTEP 1 QUERY\nENTRY_BEGIN\nENTRY_END\nSTEP 1 QUERY\nENTRY_BEGIN\nENTRY_END\nSCENARIO_END", .msg = "duplicate STEP number" },
        .{ .text = "SCENARIO_BEGIN x\nSTEP 1 TIME_PASSES\nSCENARIO_END", .msg = "TIME_PASSES needs" },
        .{ .text = "; hark: dns64prefix = x\nSCENARIO_BEGIN x\nSCENARIO_END", .msg = "unknown hark directive" },
        .{ .text = "; hark: dnssec-zone = example.com\nSCENARIO_BEGIN x\nSCENARIO_END", .msg = "first dnssec-zone" },
    };
    for (cases) |c| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        var diag: Diag = .{};
        try testing.expectError(error.Parse, parse(arena_state.allocator(), c.text, &diag));
        try testing.expect(mem.startsWith(u8, diag.msg, c.msg));
    }
}

test "every scenario on disk parses" {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var parsed: usize = 0;
    var unsupported: usize = 0;
    for ([_][]const u8{ "test/scenarios/hark", "test/corpus/unbound" }) |root| {
        var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch return error.SkipZigTest;
        defer dir.close(io);
        var walker = try dir.walk(testing.allocator);
        defer walker.deinit();
        while (try walker.next(io)) |ent| {
            if (ent.kind != .file or !mem.endsWith(u8, ent.basename, ".rpl")) continue;
            const text = try dir.readFileAlloc(io, ent.path, arena, .limited(1 << 20));
            var diag: Diag = .{};
            _ = parse(arena, text, &diag) catch |err| switch (err) {
                error.UnsupportedRType => {
                    unsupported += 1;
                    continue;
                },
                else => {
                    std.debug.print("{s}/{s}:{d}: {s}\n", .{ root, ent.path, diag.line, diag.msg });
                    return err;
                },
            };
            parsed += 1;
        }
    }
    // NSEC3 text is not loaded yet; those scenarios are the unsupported count.
    try testing.expect(parsed >= 80);
    try testing.expect(unsupported <= 18);
}
