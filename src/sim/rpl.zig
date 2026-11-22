//! Loader for `.rpl` scenarios: the hark dialect of Unbound's testbound
//! format, for the sim and, printed as JSON, the live harness.
//!
//! Everything is allocated from the caller's arena, never freed piecemeal.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("../dns.zig");
const na = @import("../net_address.zig");
const dns64 = @import("../dns64.zig");
const proof = @import("../proof.zig");
const stub = @import("../stub.zig");

const default_ttl: u32 = 3600;

const Match = packed struct {
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

/// `DS PLACEHOLDER [<zone>]`: a DS at `owner` the signer swaps for the
/// digest of `zone`'s minted key (default: the owner's).
pub const DsFrom = struct { owner: dns.Name, zone: dns.Name };

/// A record as the scenario wrote it: `rr` as hark reads it off the wire,
/// `owner` and `rdata` in the case written, which is how an authority
/// serves it (RFC 4343 §4.1).
pub const Record = struct {
    rr: dns.ResourceRecord,
    owner: []const u8,
    rdata: []const u8,

    pub fn of(rr: dns.ResourceRecord) Record {
        return .{ .rr = rr, .owner = rr.name.wire, .rdata = rr.rdata };
    }
};

pub const Entry = struct {
    match: Match = .{},
    flags: dns.Header.Flags = .{},
    do_bit: bool = false,
    edns: bool = false,
    ede: ?u16 = null,
    drop: bool = false,
    echo: enum { copy, upper, none } = .copy,
    unsigned: bool = false,
    sign_as: ?dns.Name = null,
    wildcard: ?dns.Name = null,
    ds_from: []const DsFrom = &.{},
    question: ?dns.Question = null,
    answers: []const Record = &.{},
    authorities: []const Record = &.{},
    additionals: []const Record = &.{},
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
    seconds: u32 = 0,
    bound: u32 = 0,

    pub const Kind = enum {
        query,
        check_answer,
        check_query_log,
        check_out_query,
        check_max_queries,
        check_max_verifies,
        check_max_runs,
        unsent,
        time_passes,
    };
};

pub const Scenario = struct {
    root_hints: []const na.Address = &.{},
    stub_zones: []const stub.Zone = &.{},
    ranges: []const Range = &.{},
    steps: []const Step = &.{},
    qmin: ?bool = null,
    rebinding_enabled: ?bool = null,
    rebinding_allow_zones: []const []const u8 = &.{},
    rebinding_extra_allow: []const []const u8 = &.{},
    stagger_ms: ?u32 = null,
    max_queries: ?u32 = null,
    resolve_ms: ?u32 = null,
    dns64_prefix: ?dns64.Prefix = null,
    serve_stale_ttl: ?u32 = null,
    min_ttl: ?u32 = null,
    prefetch: ?bool = null,
    client_timeout_ms: ?u32 = null,
    dnssec_zones: []const []const u8 = &.{},
    sig_validity: ?u32 = null,
    sig_original_ttl: ?u32 = null,
};

pub const Diag = struct {
    line: usize = 0,
    msg: []const u8 = "",
};

pub const Error = error{ Parse, OutOfMemory };

pub fn parse(arena: Allocator, text: []const u8, diag: *Diag) Error!Scenario {
    var p: Parser = .{ .arena = arena, .diag = diag, .lines = mem.splitScalar(u8, text, '\n') };
    return p.parse();
}

const Parser = struct {
    arena: Allocator,
    diag: *Diag,
    lines: mem.SplitIterator(u8, .scalar),
    lineno: usize = 0,
    cur: ?[]const u8 = null,
    scenario: Scenario = .{},
    spelled: std.ArrayList(u8) = .empty,

    fn fail(p: *Parser, msg: []const u8) Error {
        p.diag.* = .{ .line = p.lineno, .msg = msg };
        return error.Parse;
    }

    /// Applies the `; hark: key = value` directives in the comments it skips.
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
        const eq = mem.findScalar(u8, rest, '=') orelse return p.fail("hark directive without '='");
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
        } else if (mem.eql(u8, key, "stub-zone")) {
            var it = mem.tokenizeAny(u8, val, " \t");
            const apex = dns.parseDottedName(p.arena, it.next() orelse return p.fail("stub-zone: no zone")) catch return p.fail("stub-zone: bad zone");
            var servers: std.ArrayList(na.Address) = .empty;
            while (it.next()) |t| try servers.append(p.arena, try p.parseAddr(t));
            if (servers.items.len == 0) return p.fail("stub-zone: no servers");
            const z: stub.Zone = .{ .apex = apex, .servers = servers.items };
            s.stub_zones = try mem.concat(p.arena, stub.Zone, &.{ s.stub_zones, &.{z} });
        } else if (mem.eql(u8, key, "qname-minimisation")) {
            s.qmin = yes(val);
        } else if (mem.eql(u8, key, "rebinding-enabled")) {
            s.rebinding_enabled = yes(val);
        } else if (mem.eql(u8, key, "rebinding-allow-zone")) {
            s.rebinding_allow_zones = try mem.concat(p.arena, []const u8, &.{ s.rebinding_allow_zones, &.{val} });
        } else if (mem.eql(u8, key, "rebinding-extra-allow")) {
            s.rebinding_extra_allow = try mem.concat(p.arena, []const u8, &.{ s.rebinding_extra_allow, &.{val} });
        } else if (mem.eql(u8, key, "stagger-ms")) {
            s.stagger_ms = try p.int(u32, val);
        } else if (mem.eql(u8, key, "max-queries")) {
            s.max_queries = try p.int(u32, val);
        } else if (mem.eql(u8, key, "resolve-ms")) {
            s.resolve_ms = try p.int(u32, val);
        } else if (mem.eql(u8, key, "dns64-prefix")) {
            s.dns64_prefix = dns64.Prefix.parse(val) orelse return p.fail("dns64-prefix: not an RFC 6052 prefix");
        } else if (mem.eql(u8, key, "serve-stale-ttl")) {
            s.serve_stale_ttl = try p.int(u32, val);
        } else if (mem.eql(u8, key, "min-ttl")) {
            s.min_ttl = try p.int(u32, val);
        } else if (mem.eql(u8, key, "sig-validity")) {
            s.sig_validity = try p.int(u32, val);
        } else if (mem.eql(u8, key, "sig-original-ttl")) {
            s.sig_original_ttl = try p.int(u32, val);
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
            s.dnssec_zones = try mem.concat(p.arena, []const u8, &.{ s.dnssec_zones, &.{canon} });
        } else return p.fail("unknown hark directive");
    }

    fn parse(p: *Parser) Error!Scenario {
        const head = try p.next();
        if (!mem.startsWith(u8, head, "SCENARIO_BEGIN")) return p.fail("expected SCENARIO_BEGIN");

        var ranges: std.ArrayList(Range) = .empty;
        var steps: std.ArrayList(Step) = .empty;
        while (try p.peek()) |line| {
            if (mem.eql(u8, line, "SCENARIO_END")) {
                p.advance();
                p.scenario.ranges = ranges.items;
                p.scenario.steps = steps.items;
                if (p.scenario.root_hints.len == 0) return p.fail("no root-hints");
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
            } else if (mem.eql(u8, line, "ENTRY_BEGIN")) {
                p.advance();
                try entries.append(p.arena, try p.entry());
            } else if (mem.eql(u8, line, "RANGE_END")) {
                p.advance();
                const addr = addr_seen orelse return p.fail("RANGE without ADDRESS");
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
                const elapse = toks.next() orelse "";
                const seconds = toks.next() orelse "";
                if (!mem.eql(u8, elapse, "ELAPSE") or toks.next() != null) return p.fail("TIME_PASSES needs `ELAPSE <n>`");
                return .{ .n = n, .kind = kind, .seconds = try p.int(u32, seconds) };
            },
            .unsent => return .{ .n = n, .kind = kind },
            .check_max_queries, .check_max_verifies, .check_max_runs => {
                const bound = try p.int(u32, toks.next() orelse return p.fail("CHECK_MAX_* takes one integer"));
                if (toks.next() != null) return p.fail("CHECK_MAX_* takes one integer");
                return .{ .n = n, .kind = kind, .bound = bound };
            },
            .query, .check_answer, .check_query_log, .check_out_query => {
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
        var answers: std.ArrayList(Record) = .empty;
        var authorities: std.ArrayList(Record) = .empty;
        var additionals: std.ArrayList(Record) = .empty;
        var query_log: std.ArrayList(QueryLogRow) = .empty;
        var ds_from: std.ArrayList(DsFrom) = .empty;
        while (try p.peek()) |line| {
            p.advance();
            if (mem.eql(u8, line, "ENTRY_END")) {
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
                    if (eqlIgnoreCase(t, "drop")) {
                        e.drop = true;
                    } else if (eqlIgnoreCase(t, "force_upper_qname")) {
                        e.echo = .upper;
                    } else if (eqlIgnoreCase(t, "drop_question")) {
                        e.echo = .none;
                    } else if (eqlIgnoreCase(t, "unsigned")) {
                        e.unsigned = true;
                    } else if (!eqlIgnoreCase(t, "copy_id") and !eqlIgnoreCase(t, "copy_query")) {
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
                .question => {
                    if (e.question != null) return p.fail("a second QUESTION");
                    e.question = try p.question(line);
                },
                .query_log => try query_log.append(p.arena, try p.queryLogRow(line)),
                .answer => try answers.append(p.arena, try p.parseRr(line, &ds_from)),
                .authority => try authorities.append(p.arena, try p.parseRr(line, &ds_from)),
                .additional => try additionals.append(p.arena, try p.parseRr(line, &ds_from)),
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
        inline for (.{ "qr", "aa", "tc", "rd", "ra", "ad", "cd" }) |bit| if (eqlIgnoreCase(t, bit)) {
            @field(e.flags, bit) = true;
            return;
        };
        if (eqlIgnoreCase(t, "DO")) {
            e.do_bit = true;
        } else if (eqlIgnoreCase(t, "EDNS")) {
            e.edns = true;
        } else if (rcodeFromText(t)) |rc| {
            e.flags.rcode = rc;
        } else return p.fail("unknown REPLY token");
    }

    fn question(p: *Parser, line: []const u8) Error!dns.Question {
        var toks = mem.tokenizeAny(u8, line, " \t");
        const owner = toks.next().?;
        const a = toks.next() orelse return p.fail("bad QUESTION line");
        const b = toks.next();
        if (toks.next() != null) return p.fail("bad QUESTION line");
        const type_tok = b orelse a;
        if (b != null and !eqlIgnoreCase(a, "in")) return p.fail("only class IN is supported");
        const canonical = try p.name(owner);
        const spelled = try p.spelledName(owner);
        return .{
            .name = canonical,
            .qtype = enumIgnoreCase(dns.RType, type_tok) orelse return p.fail("bad QUESTION type"),
            .qclass = .in,
            .spelled = if (mem.eql(u8, spelled, canonical.wire)) null else spelled,
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
            .qtype = enumIgnoreCase(dns.RType, qtype) orelse return p.fail("bad QUERY_LOG qtype"),
            .dest = if (dest) |d| try p.parseAddr(d) else null,
        };
    }

    fn parseRr(p: *Parser, raw: []const u8, ds_from: *std.ArrayList(DsFrom)) Error!Record {
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
        const owner_text = toks.next().?;
        const owner = try p.name(owner_text);
        var ttl: u32 = default_ttl;
        var t = toks.next() orelse return p.fail("RR needs a type");
        if (isDigits(t)) {
            ttl = try p.int(u32, t);
            t = toks.next() orelse return p.fail("RR needs a type");
        }
        var class: dns.RClass = .in;
        inline for (.{ "in", "ch", "hs" }, .{ 1, 3, 4 }) |text, code| if (eqlIgnoreCase(t, text)) {
            class = @fromBackingInt(code);
            t = toks.next() orelse return p.fail("RR needs a type");
            break;
        };
        if (isDigits(t)) {
            ttl = try p.int(u32, t);
            t = toks.next() orelse return p.fail("RR needs a type");
        }
        const rtype = enumIgnoreCase(dns.RType, t) orelse return p.fail("unknown RR type");
        p.spelled.clearRetainingCapacity();
        const rr: dns.ResourceRecord = try .init(p.arena, .{ .name = owner, .rtype = rtype, .rclass = class, .ttl = ttl, .rdata = try p.rdata(rtype, owner, &toks, ds_from) });
        return p.written(rr, try p.spelledName(owner_text));
    }

    /// The names in rdata lie together after `skip` octets (none of these
    /// types has character-strings ahead of them), and differ from hark's
    /// only in case.
    fn written(p: *Parser, rr: dns.ResourceRecord, owner: []const u8) Error!Record {
        var held = rr;
        const e = dns.embedded(rr.rtype) orelse return .{ .rr = rr, .owner = owner, .rdata = rr.rdata };
        const spelled = try p.arena.dupe(u8, rr.rdata);
        @memcpy(spelled[e.skip..][0..p.spelled.items.len], p.spelled.items);
        // RFC 6840 §5.1: an NSEC's next name is signed, and read, as written.
        // Said here, not taken from hark's reader, which is what this checks.
        if (rr.rtype == .nsec) held.rdata = spelled;
        return .{ .rr = held, .owner = owner, .rdata = spelled };
    }

    fn rdataName(p: *Parser, text: []const u8) Error!dns.Name {
        const n = try p.name(text);
        try p.spelled.appendSlice(p.arena, try p.spelledName(text));
        return n;
    }

    fn spelledName(p: *Parser, text: []const u8) Error![]const u8 {
        return dns.spelledWire(p.arena, text) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => p.fail("bad domain name"),
        };
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
            .ns => return .{ .ns = try p.rdataName(try p.word(toks)) },
            .cname => return .{ .cname = try p.rdataName(try p.word(toks)) },
            .dname => return .{ .dname = try p.rdataName(try p.word(toks)) },
            .ptr => return .{ .ptr = try p.rdataName(try p.word(toks)) },
            .mx => return .{ .mx = .{
                .preference = try p.int(u16, try p.word(toks)),
                .exchange = try p.rdataName(try p.word(toks)),
            } },
            .soa => return .{ .soa = .{
                .mname = try p.rdataName(try p.word(toks)),
                .rname = try p.rdataName(try p.word(toks)),
                .serial = try p.int(u32, try p.word(toks)),
                .refresh = try p.int(u32, try p.word(toks)),
                .retry = try p.int(u32, try p.word(toks)),
                .expire = try p.int(u32, try p.word(toks)),
                .minimum = try p.int(u32, try p.word(toks)),
            } },
            .txt => return .{ .txt = .{ .strings = try p.charStrings(toks) } },
            .ds => {
                const first = try p.word(toks);
                if (eqlIgnoreCase(first, "placeholder")) {
                    const zone = if (toks.next()) |z| try p.name(z) else owner;
                    try ds_from.append(arena, .{ .owner = owner, .zone = zone });
                    return .{ .ds = .{
                        .key_tag = 0,
                        .algorithm = .ecdsap256sha256,
                        .digest_type = @fromBackingInt(2),
                        .digest = &@as([32]u8, @splat(0)),
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
                .type_covered = enumIgnoreCase(dns.RType, try p.word(toks)) orelse return p.fail("unknown RRSIG type covered"),
                .algorithm = try p.algorithm(try p.word(toks)),
                .labels = try p.int(u8, try p.word(toks)),
                .original_ttl = try p.int(u32, try p.word(toks)),
                .sig_expiration = try p.sigTime(try p.word(toks)),
                .sig_inception = try p.sigTime(try p.word(toks)),
                .key_tag = try p.int(u16, try p.word(toks)),
                .signer_name = try p.rdataName(try p.word(toks)),
                .signature = try p.base64(toks),
            } },
            .nsec => return .{ .nsec = .{
                .next_domain_name = try p.rdataName(try p.word(toks)),
                .type_bit_maps = try p.typeBitmap(toks),
            } },
            .nsec3 => {
                const hash_algorithm: dns.Nsec3HashAlgorithm = @fromBackingInt(try p.int(u8, try p.word(toks)));
                const flags = try p.int(u8, try p.word(toks));
                const iterations = try p.int(u16, try p.word(toks));
                const salt = try p.word(toks);
                const next_text = try p.word(toks);
                const hashed = try p.arena.alloc(u8, next_text.len * 5 / 8);
                const n = proof.base32HexDecode(hashed, next_text) catch return p.fail("bad base32hex");
                return .{ .nsec3 = .{
                    .hash_algorithm = hash_algorithm,
                    .flags = flags,
                    .iterations = iterations,
                    .salt = if (mem.eql(u8, salt, "-")) "" else try p.octets(try p.unhex(salt)),
                    .next_hashed_owner = try p.octets(hashed[0..n]),
                    .type_bit_maps = try p.typeBitmap(toks),
                } };
            },
            else => {
                if (rtype != .hinfo) return p.fail("unsupported RR type");
                // HINFO in wire form, as the resolver synthesises it (RFC 8482).
                var wire: std.ArrayList(u8) = .empty;
                for (try p.charStrings(toks)) |str| {
                    try wire.append(arena, @intCast(str.len));
                    try wire.appendSlice(arena, str);
                }
                return .{ .unknown = wire.items };
            },
        }
    }

    fn charStrings(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const []const u8 {
        var strings: std.ArrayList([]const u8) = .empty;
        while (toks.next()) |t| {
            if (t[0] != '"') {
                try strings.append(p.arena, t);
                continue;
            }
            const start = @intFromPtr(t.ptr) - @intFromPtr(toks.buffer.ptr) + 1;
            const close = mem.findScalarPos(u8, toks.buffer, start, '"') orelse return p.fail("unterminated quoted string");
            try strings.append(p.arena, toks.buffer[start..close]);
            toks.index = close + 1;
        }
        for (strings.items) |s| _ = try p.octets(s);
        return strings.items;
    }

    /// A field its length octet must count (RFC 1035 §3.3).
    fn octets(p: *Parser, s: []const u8) Error![]const u8 {
        return if (s.len > 255) p.fail("rdata field too long") else s;
    }

    fn hex(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const u8 {
        var text: std.ArrayList(u8) = .empty;
        while (toks.next()) |t| try text.appendSlice(p.arena, t);
        return p.unhex(text.items);
    }

    fn unhex(p: *Parser, text: []const u8) Error![]const u8 {
        if (text.len % 2 != 0) return p.fail("odd-length hex");
        const out = try p.arena.alloc(u8, text.len / 2);
        _ = std.fmt.hexToBytes(out, text) catch return p.fail("bad hex");
        return out;
    }

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

    fn base64(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const u8 {
        var text: std.ArrayList(u8) = .empty;
        while (toks.next()) |t| try text.appendSlice(p.arena, t);
        const bare = mem.trimEnd(u8, text.items, "=");
        const dec = std.base64.standard_no_pad.Decoder;
        const out = try p.arena.alloc(u8, dec.calcSizeForSlice(bare) catch return p.fail("bad base64"));
        dec.decode(out, bare) catch return p.fail("bad base64");
        return out;
    }

    fn sigTime(p: *Parser, text: []const u8) Error!u32 {
        if (text.len != 14) return p.int(u32, text);
        const y = try p.int(i64, text[0..4]);
        const m = try p.int(i64, text[4..6]);
        const d = try p.int(i64, text[6..8]);
        const secs = try p.int(i64, text[8..10]) * 3600 + try p.int(i64, text[10..12]) * 60 + try p.int(i64, text[12..14]);
        // Hinnant's days-from-civil.
        const yy = y - @intFromBool(m <= 2);
        const era = @divFloor(yy, 400);
        const yoe = yy - era * 400;
        const doy = @divTrunc(153 * (m + (if (m > 2) @as(i64, -3) else 9)) + 2, 5) + d - 1;
        const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
        const days = era * 146097 + doe - 719468;
        return std.math.cast(u32, days * 86400 + secs) orelse p.fail("signature time out of range");
    }

    fn typeBitmap(p: *Parser, toks: *mem.TokenIterator(u8, .any)) Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var window: [256]u8 = undefined;
        var types: std.ArrayList(u16) = .empty;
        while (toks.next()) |t| try types.append(p.arena, @backingInt(enumIgnoreCase(dns.RType, t) orelse return p.fail("unknown type in bitmap")));
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

pub fn print(arena: Allocator, scenario: Scenario, w: *std.Io.Writer) std.Io.Writer.Error!void {
    var s: std.json.Stringify = .{ .writer = w };
    try put(&s, arena, scenario);
}

fn put(s: *std.json.Stringify, arena: Allocator, v: anytype) std.Io.Writer.Error!void {
    const T = @TypeOf(v);
    if (T == []const u8) return s.write(v);
    if (T == dns.Name) {
        var buf: [dns.max_dotted_len + 2]u8 = undefined;
        const text = v.formatInto(buf[0 .. dns.max_dotted_len + 1]);
        buf[text.len] = '.';
        return s.write(buf[0 .. text.len + 1]);
    }
    if (T == na.Address) {
        var buf: [64]u8 = undefined;
        return s.write(na.format(v, &buf));
    }
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            try s.beginObject();
            inline for (info.field_names) |field| if (comptime !(T == Entry and inMessage(field))) {
                const f = @field(v, field);
                if (@typeInfo(@TypeOf(f)) != .optional or f != null) {
                    try s.objectField(field);
                    try put(s, arena, f);
                }
            };
            if (T == Entry) {
                try s.objectField("message");
                try putMessage(s, arena, v);
            }
            try s.endObject();
        },
        .pointer, .array => {
            try s.beginArray();
            for (v) |x| try put(s, arena, x);
            try s.endArray();
        },
        .optional => try put(s, arena, v.?),
        .@"enum" => |info| if (info.mode == .exhaustive) try s.write(@tagName(v)) else try s.write(@backingInt(v)),
        else => try s.write(v),
    }
}

fn inMessage(comptime field: []const u8) bool {
    for ([_][]const u8{ "flags", "question", "answers", "authorities", "additionals" }) |m| if (mem.eql(u8, field, m)) return true;
    return false;
}

fn putMessage(s: *std.json.Stringify, arena: Allocator, e: Entry) std.Io.Writer.Error!void {
    var wire: [65535]u8 = undefined;
    const msg = serve(arena, &wire, .{ .id = 0, .flags = e.flags }, e.question, .{ e.answers, e.authorities, e.additionals }) catch return error.WriteFailed;
    const b64 = std.base64.standard.Encoder;
    var text: [b64.calcSize(wire.len)]u8 = undefined;
    try s.write(b64.encode(&text, msg));
}

/// A message of `sections` as an authority serves it, in the case written.
/// hark's serializer compresses on the names hark holds, which differ from
/// the written ones in case alone, so every octet keeps its place and only
/// takes the written case; a pointer keeps the case of what it points at.
pub fn serve(arena: Allocator, buf: []u8, header: dns.Header, question: ?dns.Question, sections: [3][]const Record) ![]const u8 {
    var held: [3][]dns.ResourceRecord = undefined;
    for (&held, sections) |*h, records| {
        h.* = try arena.alloc(dns.ResourceRecord, records.len);
        for (h.*, records) |*rr, r| rr.* = r.rr;
    }
    const len = (try dns.serializeMessage(buf, .{ .header = header, .question = question, .answers = held[0], .authorities = held[1], .additionals = held[2] })).len;
    const wire = buf[0..len];
    // The question is the first name, which nothing earlier can compress.
    var at: usize = 12 + if (question) |q| (q.spelled orelse q.name.wire).len + 4 else 0;
    for (sections) |records| for (records) |r| {
        at = spellName(wire, at, r.owner);
        const rdlength = mem.readInt(u16, wire[at + 8 ..][0..2], .big);
        at += 10;
        // Only names the serializer may compress move from where rdata holds them.
        const rdata = wire[at..][0..rdlength];
        const e = dns.embedded(r.rr.rtype);
        if (e != null and e.?.spelling == .rfc1035) spellNames(rdata, r.rdata, e.?) else @memcpy(rdata, r.rdata);
        at += rdlength;
    };
    return wire;
}

fn spellNames(wire: []u8, spelled: []const u8, e: dns.Embedded) void {
    var at: usize = e.skip;
    var from: usize = e.skip;
    for (0..e.names) |_| {
        at = spellName(wire, at, spelled[from..]);
        from += dns.wireNameLen(spelled[from..]);
    }
}

fn spellName(wire: []u8, at: usize, spelled: []const u8) usize {
    var i = at;
    var j: usize = 0;
    while (wire[i] != 0 and wire[i] < 0xc0) : ({
        j += 1 + wire[i];
        i += 1 + wire[i];
    }) @memcpy(wire[i + 1 ..][0..wire[i]], spelled[j + 1 ..][0..wire[i]]);
    return i + @as(usize, if (wire[i] == 0) 1 else 2);
}

fn enumIgnoreCase(comptime E: type, s: []const u8) ?E {
    inline for (@typeInfo(E).@"enum".field_names) |field_name| {
        if (std.ascii.eqlIgnoreCase(s, field_name)) return @field(E, field_name);
    }
    return null;
}

fn yes(val: []const u8) bool {
    return eqlIgnoreCase(val, "yes") or eqlIgnoreCase(val, "true") or eqlIgnoreCase(val, "on") or mem.eql(u8, val, "1");
}

const eqlIgnoreCase = std.ascii.eqlIgnoreCase;

fn isDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn rcodeFromText(t: []const u8) ?dns.RCode {
    const table = .{
        .{ "NOERROR", dns.RCode.no_error },
        .{ "FORMERR", dns.RCode.format_error },
        .{ "SERVFAIL", dns.RCode.server_failure },
        .{ "NXDOMAIN", dns.RCode.name_error },
        .{ "NOTIMP", dns.RCode.not_implemented },
        .{ "REFUSED", dns.RCode.refused },
        .{ "YXDOMAIN", dns.RCode.yx_domain },
    };
    inline for (table) |row| if (eqlIgnoreCase(t, row[0])) return row[1];
    return null;
}

fn parseTest(arena: Allocator, text: []const u8) !Scenario {
    var diag: Diag = .{};
    return parse(arena, text, &diag) catch |err| {
        std.debug.print("line {d}: {s}\n", .{ diag.line, diag.msg });
        return err;
    };
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
