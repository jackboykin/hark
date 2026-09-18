//! A client's response, shaped from the graph: policy over facts, no
//! sockets. The live server and the simulator both serve through it.
const std = @import("std");
const Allocator = std.mem.Allocator;
const dns = @import("../dns.zig");
const graph = @import("graph.zig");
const walk = @import("walk.zig");
const dns64 = @import("../dns64.zig");
const special_use = @import("../special_use.zig");

pub const Client = struct {
    rd: bool = true,
    cd: bool = false,
    do_bit: bool = false,
    ad: bool = false,

    pub fn fromQuery(m: dns.Message) Client {
        return .{ .rd = m.header.flags.rd, .cd = m.header.flags.cd, .do_bit = m.opt != null and m.opt.?.do_bit, .ad = m.header.flags.ad };
    }
};

/// RFC 6147 at the client's edge, off under CD (§5.5); the cells stay
/// what the authorities said.
pub const Dns64 = struct {
    prefix: dns64.Prefix,

    pub fn on(prefix: ?dns64.Prefix, c: Client) ?Dns64 {
        return if (prefix) |p| if (c.cd) null else .{ .prefix = p } else null;
    }

    /// A PTR under the prefix becomes the embedded IPv4's in-addr.arpa PTR (§5.3.1).
    pub fn asked(d: Dns64, arena: Allocator, q: dns.Question) !dns.Question {
        if (q.qtype != .ptr) return q;
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        const v6 = dns64.parseIp6Arpa(q.name.formatInto(&buf)) orelse return q;
        if (!d.prefix.contains(&v6)) return q;
        const v4 = d.prefix.extract(&v6);
        const in_addr = try std.fmt.allocPrint(arena, "{d}.{d}.{d}.{d}.in-addr.arpa.", .{ v4[3], v4[2], v4[1], v4[0] });
        return .{ .name = try dns.parseDottedName(arena, in_addr), .qtype = .ptr, .qclass = q.qclass };
    }

    /// §5.1.2: an AAAA that came back empty wants the A too.
    pub fn wantsA(q: dns.Question, served: Served) bool {
        return q.qtype == .aaaa and dns64.wantsSynthesis(served.msg);
    }

    /// PTRs re-owned under the client's name; AAAA embedded from `a` (§5.1.6).
    pub fn shape(d: Dns64, arena: Allocator, q: dns.Question, served: Served, a: ?Served) !Served {
        var out = served;
        if (q.qtype == .ptr and !served.msg.questions[0].name.eql(q.name)) {
            var buf: [dns.max_dotted_len + 1]u8 = undefined;
            try dns64.renamePtr(arena, &out.msg, q.name.formatInto(&buf));
            // A denial there proves a name the client never asked about.
            out.msg.authorities = &.{};
            out.msg.additionals = &.{};
        } else if (a) |from| if (try dns64.synthesizeAaaa(arena, d.prefix, from.msg, served.msg)) |msg| {
            out = .{ .msg = msg, .cacheable = served.cacheable and from.cacheable, .ede = from.ede };
        };
        out.msg.questions = try arena.dupe(dns.Question, &.{q});
        return out;
    }
};

/// A reply, and whether it is a fact past this instant (TTL 0 is served
/// but never memoised).
pub const Served = struct { msg: dns.Message, cacheable: bool, ede: ?dns.Ede = null };

/// RFC 6761 names, answered asking nobody; null: ask the graph.
pub fn special(arena: Allocator, q: dns.Question, c: Client, d64: ?Dns64) !?Served {
    var buf: [dns.max_dotted_len + 1]u8 = undefined;
    const name = q.name.formatInto(&buf);
    const action = special_use.classify(name, q.qtype);
    if (action == .none) return null;
    var msg = try special_use.synthesize(arena, name, action);
    // RFC 8880 §7.1: ipv4only.arpa's AAAA is synthesized here too.
    if (d64) |d| if (q.qtype == .aaaa and dns64.wantsSynthesis(msg)) {
        const a = try special_use.synthesize(arena, name, special_use.classify(name, .a));
        msg = try dns64.synthesizeAaaa(arena, d.prefix, a, msg) orelse msg;
    };
    msg.header.flags.rd = c.rd;
    msg.header.flags.cd = c.cd;
    msg.questions = try arena.dupe(dns.Question, &.{q});
    return .{ .msg = msg, .cacheable = false };
}

/// RFC 8482: ANY is answered with a synthetic HINFO, asking nobody.
pub fn hinfo(arena: Allocator, q: dns.Question, c: Client) !Served {
    const rr: dns.ResourceRecord = .{ .name = q.name, .rtype = @fromBackingInt(13), .rclass = .in, .ttl = 0, .rdata = .{ .unknown = "\x07RFC8482\x00" } };
    return .{ .cacheable = false, .msg = .{
        .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = c.rd, .ra = true, .z = 0, .ad = false, .cd = c.cd, .rcode = .no_error } },
        .questions = try arena.dupe(dns.Question, &.{q}),
        .answers = try arena.dupe(dns.ResourceRecord, &.{rr}),
    } };
}

/// The answer cell shaped for a client: bogus is SERVFAIL unless CD, a
/// verified hop's TTLs end with its proof, signatures only to DO, AD only
/// when asked (RFC 6840 §5.7). `cached`: settled from memory alone.
pub fn build(arena: Allocator, g: *graph.Graph, root: graph.CellId, q: dns.Question, c: Client, minimal: bool, cached: bool) !Served {
    const a = g.cell(root).value.answer;
    var chain: std.ArrayList(dns.ResourceRecord) = .empty;
    var last: graph.Reply = .{ .kind = .servfail, .rcode = .server_failure, .aa = false };
    var age: u32 = 0;
    var life: u32 = std.math.maxInt(u32);
    const served = !a.broken and (a.status != .bogus or c.cd);
    var stale = false;
    if (served) for (a.hops, 0..) |h, i| {
        last = if (a.stale.len > i and a.stale[i] != null) a.stale[i].?.* else g.cell(h).value.rrset;
        age = @intCast(@divTrunc(g.now() - last.stored_ns, std.time.ns_per_s));
        life = std.math.maxInt(u32);
        if (i < a.judged.len) {
            const proven = g.cell(a.judged[i]).value.secure.proven_until_ns;
            life = @intCast(@min(@max(@divTrunc(proven - g.now(), std.time.ns_per_s), 0), std.math.maxInt(u32)));
        }
        const hop_stale = last.ede == .stale_answer;
        stale = stale or hop_stale;
        // A denial's life is the reply's, not a record's.
        if (hop_stale and last.kind != .answer and last.kind != .alias) {
            age = 0;
            life = walk.stale_hold_s;
        }
        try appendAged(arena, &chain, last.answers, age, life, @min(g.cfg.min_ttl, last.ttl), c.do_bit, hop_stale);
    };
    const positive = last.kind == .answer or last.kind == .alias;
    var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
    var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
    if (!(positive and minimal and q.qtype != .ns)) {
        const floor = @min(g.cfg.min_ttl, last.ttl);
        try appendAged(arena, &authorities, last.authorities, age, life, floor, c.do_bit, last.ede == .stale_answer);
        try appendAged(arena, &additionals, last.additionals, age, life, floor, c.do_bit, last.ede == .stale_answer);
    }
    const ede: ?dns.Ede = if (a.broken)
        .{ .code = .other, .text = "cname loop" }
    else if (!served)
        .{ .code = .dnssec_bogus }
    else if (last.kind == .servfail)
        .{ .code = if (cached) .cached_error else last.ede orelse .no_reachable_authority }
    else if (stale) // any hop: a stale alias still redirected
        .{ .code = if (last.kind == .nxdomain) .stale_nxdomain_answer else .stale_answer }
    else if (last.ede) |code|
        .{ .code = code }
    else
        null;
    return .{ .cacheable = g.cell(root).expires_ns > g.now(), .ede = ede, .msg = .{
        .header = .{ .id = 0, .flags = .{
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = c.rd,
            .ra = true,
            .z = 0,
            .ad = served and a.status == .secure and (c.do_bit or c.ad),
            .cd = c.cd,
            .rcode = if (last.kind == .servfail) last.rcode else if (last.kind == .nxdomain) .name_error else .no_error,
        } },
        .questions = try arena.dupe(dns.Question, &.{q}),
        .answers = chain.items,
        .authorities = authorities.items,
        .additionals = additionals.items,
    } };
}

/// TTLs aged since the reply, floored to `floor` and capped by `life`; a
/// record past its TTL in a stale reply gets the hold (RFC 8767 §4).
fn appendAged(arena: Allocator, out: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, age: u32, life: u32, floor: u32, sigs: bool, stale: bool) !void {
    for (rrs) |rr| {
        if (rr.rtype == .rrsig and !sigs) continue;
        var aged = rr;
        aged.ttl = if (stale and rr.ttl <= age) walk.stale_hold_s else @min(@max(rr.ttl, floor) -| age, life);
        try out.append(arena, aged);
    }
}
