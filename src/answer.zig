//! A client's response, shaped from the graph: policy over facts, no
//! sockets. The live server and the simulator both serve through it.
const std = @import("std");
const Allocator = std.mem.Allocator;
const dns = @import("dns.zig");
const graph = @import("graph.zig");
const walk = @import("walk.zig");
const store = @import("store.zig");
const dns64 = @import("dns64.zig");
const special_use = @import("special_use.zig");

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
pub const Served = struct {
    msg: dns.Message,
    cacheable: bool,
    ede: ?dns.Ede = null,
    /// Served stale: hold the question stale until then (`Failures`).
    hold_until_ns: i64 = 0,
};

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

/// SERVFAIL, and why.
pub fn servfail(arena: Allocator, q: dns.Question, c: Client, ede: dns.Ede) !Served {
    return .{ .cacheable = false, .ede = ede, .msg = .{
        .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = c.rd, .ra = true, .z = 0, .ad = false, .cd = c.cd, .rcode = .server_failure } },
        .questions = try arena.dupe(dns.Question, &.{q}),
    } };
}

/// Serve's policy over what the store still holds past a fact's TTL; the
/// graph knows nothing of it.
pub const Retention = struct {
    /// Answer from memory, asking nobody, until a reply is this old.
    min_ttl: u32 = 0,
    /// RFC 8767: serve an answer this long past its retention when it
    /// cannot be refreshed; 0: never.
    serve_stale_ttl: u32 = 0,
};

/// BIND's stale-refresh-time (RFC 8767 §5): after serving stale, how long
/// the question is answered stale without asking.
pub const stale_hold_s = 30;
/// RFC 8767 §5: a resolution past a stub's patience answers stale instead.
pub const stale_client_ms = 1800;

const Hop = struct {
    reply: graph.Reply,
    /// Record TTLs are raised to this (`min-ttl`), before aging.
    floor: u32,
    /// Where a verified hop's proof ends; records live no longer.
    life: u32 = std.math.maxInt(u32),
    /// Past its retention, served under RFC 8767.
    stale: bool = false,
};

/// When `min-ttl` lets a reply go: its TTL floored, under the negative cap
/// and its signatures' validity. TTL 0 is never floored.
fn retainedUntil(g: *graph.Graph, ret: Retention, r: graph.Reply) i64 {
    const own = walk.replyExpiry(r);
    if (r.ttl == 0 or r.ttl >= ret.min_ttl) return own;
    var floor: i64 = ret.min_ttl;
    if (r.kind == .nodata or r.kind == .nxdomain) floor = @min(floor, g.cfg.max_negative_ttl);
    var until = r.stored_ns + floor * std.time.ns_per_s;
    const wall = g.wallNow();
    for ([_][]const dns.ResourceRecord{ r.answers, r.authorities }) |section| {
        for (section) |rr| if (rr.rtype == .rrsig) {
            until = @min(until, g.now() + @as(i64, rr.rdata.rrsig.secondsUntilExpiry(wall)) * std.time.ns_per_s);
        };
    }
    return @max(own, until);
}

fn floorOf(g: *graph.Graph, ret: Retention, r: graph.Reply) u32 {
    const retained = @divTrunc(retainedUntil(g, ret, r) - r.stored_ns, std.time.ns_per_s);
    return @min(ret.min_ttl, @as(u32, @intCast(std.math.clamp(retained, 0, std.math.maxInt(u32)))));
}

/// The answer cell shaped for a client: a failure or bogus is SERVFAIL
/// unless serve-stale has something, bogus data only to CD; a verified
/// hop's TTLs end with its proof, signatures only to DO, AD only when asked
/// (RFC 6840 §5.7).
pub fn build(arena: Allocator, g: *graph.Graph, ret: Retention, root: graph.CellId, q: dns.Question, c: Client, minimal: bool) !Served {
    if (g.cell(root).failure()) |why| return try stale(arena, g, ret, q, c, minimal) orelse servfail(arena, q, c, .{ .code = why.code, .text = why.text });
    const a = g.cell(root).state.fact.answer;
    // Secure only if every hop is; a verdict that failed is bogus (RFC 4035 §4.3).
    var secure = a.judged.len > 0;
    for (a.judged) |j| switch (g.cell(j).state) {
        .fact => |v| secure = secure and v.secure.status == .secure,
        .failure => |why| if (c.cd) {
            secure = false;
        } else return try stale(arena, g, ret, q, c, minimal) orelse servfail(arena, q, c, .{ .code = why.code, .text = why.text }),
        .pending => unreachable,
    };
    std.debug.assert(a.hops.len > 0);
    const hops = try arena.alloc(Hop, a.hops.len);
    for (hops, a.hops, 0..) |*hop, h, i| {
        const r = g.cell(h).state.fact.rrset;
        hop.* = .{ .reply = r, .floor = floorOf(g, ret, r) };
        // A failed verdict proved nothing, so it bounds nothing (CD only).
        if (i < a.judged.len and g.cell(a.judged[i]).failure() == null)
            hop.life = lifeOf(g, g.cell(a.judged[i]).state.fact.secure.proven_until_ns);
    }
    return shape(arena, g, q, c, minimal, hops, secure, g.cell(root).expires_ns > g.now());
}

fn lifeOf(g: *graph.Graph, proven_until_ns: i64) u32 {
    return @intCast(@min(@max(@divTrunc(proven_until_ns - g.now(), std.time.ns_per_s), 0), std.math.maxInt(u32)));
}

/// Null inside the refresh window, where the graph decides on prefetch:
/// a hop born too short to refresh declines its last 2 s.
pub fn fresh(arena: Allocator, g: *graph.Graph, ret: Retention, q: dns.Question, c: Client, minimal: bool) !?Served {
    const chain = try g.recall(arena, q.name, q.qtype, .fresh) orelse return null;
    const judged = g.cfg.trust_anchor != null;
    var secure = judged;
    var expires: i64 = std.math.maxInt(i64);
    const hops = try arena.alloc(Hop, chain.len);
    for (hops, chain) |*hop, h| {
        hop.* = .{ .reply = h.reply, .floor = floorOf(g, ret, h.reply) };
        expires = @min(expires, h.expires_ns);
        if (judged) {
            secure = secure and h.verdict.chain().status == .secure;
            hop.life = lifeOf(g, h.verdict.proven_until_ns);
            expires = @min(expires, h.verdict.until_ns);
        }
    }
    if (g.cfg.prefetch and expires <= g.now() + graph.refresh_window_ns) return null;
    return try shape(arena, g, q, c, minimal, hops, secure, true);
}

/// `min-ttl`: a question whose facts have expired but not their floor is
/// answered from memory, unverified, asking nobody. Null: ask the graph.
pub fn floored(arena: Allocator, g: *graph.Graph, ret: Retention, q: dns.Question, c: Client, minimal: bool) !?Served {
    if (ret.min_ttl == 0) return null;
    const chain = try g.recall(arena, q.name, q.qtype, .any) orelse return null;
    var expired = false;
    for (chain) |h| {
        if (g.now() >= retainedUntil(g, ret, h.reply)) return null;
        expired = expired or g.now() >= walk.replyExpiry(h.reply);
    }
    if (!expired) return null;
    const hops = try arena.alloc(Hop, chain.len);
    for (hops, chain) |*hop, h| hop.* = .{ .reply = h.reply, .floor = floorOf(g, ret, h.reply) };
    return try shape(arena, g, q, c, minimal, hops, false, true);
}

/// RFC 8767: an answer past its retention but inside the stale window,
/// unverified, with EDE 3 or 19; the question is then held stale for
/// `stale_hold_s`, or until the window ends. Null: nothing to serve.
pub fn stale(arena: Allocator, g: *graph.Graph, ret: Retention, q: dns.Question, c: Client, minimal: bool) !?Served {
    if (ret.serve_stale_ttl == 0) return null;
    const chain = try g.recall(arena, q.name, q.qtype, .any) orelse return null;
    var window: i64 = std.math.maxInt(i64);
    var any = false;
    const hops = try arena.alloc(Hop, chain.len);
    for (hops, chain) |*hop, h| {
        const until = retainedUntil(g, ret, h.reply);
        window = @min(window, until + @as(i64, ret.serve_stale_ttl) * std.time.ns_per_s);
        hop.* = .{ .reply = h.reply, .floor = floorOf(g, ret, h.reply), .stale = g.now() >= until };
        any = any or hop.stale;
    }
    if (!any or g.now() >= window) return null;
    var served = try shape(arena, g, q, c, minimal, hops, false, false);
    served.hold_until_ns = g.now() + stale_hold_s * std.time.ns_per_s;
    return served;
}

fn shape(arena: Allocator, g: *graph.Graph, q: dns.Question, c: Client, minimal: bool, hops: []const Hop, secure: bool, cacheable: bool) !Served {
    var chain: std.ArrayList(dns.ResourceRecord) = .empty;
    var last: Hop = undefined;
    var age: u32 = 0;
    var life: u32 = 0;
    var stale_any = false;
    for (hops) |hop| {
        last = hop;
        age = @intCast(@divTrunc(g.now() - hop.reply.stored_ns, std.time.ns_per_s));
        life = hop.life;
        stale_any = stale_any or hop.stale;
        // A denial's life is the reply's, not a record's.
        if (hop.stale and hop.reply.kind != .answer and hop.reply.kind != .alias) {
            age = 0;
            life = stale_hold_s;
        }
        try appendAged(arena, &chain, hop.reply.answers, age, life, hop.floor, c.do_bit, hop.stale);
    }
    const r = last.reply;
    const positive = r.kind == .answer or r.kind == .alias;
    var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
    var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
    if (!(positive and minimal and q.qtype != .ns)) {
        try appendAged(arena, &authorities, r.authorities, age, life, last.floor, c.do_bit, last.stale);
        try appendAged(arena, &additionals, r.additionals, age, life, last.floor, c.do_bit, last.stale);
    }
    const ede: ?dns.Ede = if (stale_any) // any hop: a stale alias still redirected
        .{ .code = if (r.kind == .nxdomain) .stale_nxdomain_answer else .stale_answer }
    else if (r.ede) |code|
        .{ .code = code }
    else
        null;
    return .{ .cacheable = cacheable, .ede = ede, .msg = .{
        .header = .{ .id = 0, .flags = .{
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = c.rd,
            .ra = true,
            .z = 0,
            .ad = secure and (c.do_bit or c.ad),
            .cd = c.cd,
            .rcode = r.rcode,
        } },
        .questions = try arena.dupe(dns.Question, &.{q}),
        .answers = chain.items,
        .authorities = authorities.items,
        .additionals = additionals.items,
    } };
}

/// TTLs aged since the reply, floored to `floor` and capped by `life`; a
/// record past its TTL in a stale reply gets the hold (RFC 8767 §4).
fn appendAged(arena: Allocator, out: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, age: u32, life: u32, floor: u32, sigs: bool, is_stale: bool) !void {
    for (rrs) |rr| {
        if (rr.rtype == .rrsig and !sigs) continue;
        var aged = rr;
        aged.ttl = if (is_stale and rr.ttl <= age) stale_hold_s else @min(@max(rr.ttl, floor) -| age, life);
        try out.append(arena, aged);
    }
}

/// RFC 9520 §3.2's failure cache: a question that failed is answered here,
/// asking nobody, for a window that doubles while it keeps failing, to the
/// RFC's 5 minutes; an answer forgets it. Keyed (qname, qtype, CD), since a
/// CD client is owed bogus data. Policy over no fact, so it is the server's.
pub const Failures = struct {
    map: std.StringHashMapUnmanaged(Entry) = .empty,

    const Entry = struct { until_ns: i64, window_s: u32, ede: dns.Ede };
    const max_window_s = 300;
    const max_entries = 4096;

    pub fn deinit(f: *Failures, gpa: Allocator) void {
        var it = f.map.keyIterator();
        while (it.next()) |k| gpa.free(k.*);
        f.map.deinit(gpa);
    }

    fn key(buf: *[dns.max_dotted_len + 4]u8, q: dns.Question, cd: bool) []const u8 {
        const name = q.name.formatLower(buf[0 .. dns.max_dotted_len + 1]);
        std.mem.writeInt(u16, buf[name.len..][0..2], @backingInt(q.qtype), .little);
        buf[name.len + 2] = @intFromBool(cd);
        return buf[0 .. name.len + 3];
    }

    /// The EDE to answer with while the window lasts. A validation failure
    /// keeps its reason, a stale hold says to serve stale again; anything
    /// else is RFC 8914's cached error.
    pub fn get(f: *Failures, q: dns.Question, cd: bool, now_ns: i64) ?dns.Ede {
        if (f.map.count() == 0) return null;
        var buf: [dns.max_dotted_len + 4]u8 = undefined;
        const e = f.map.get(key(&buf, q, cd)) orelse return null;
        if (e.until_ns <= now_ns) return null;
        return switch (e.ede.code) {
            .dnssec_bogus, .stale_answer, .stale_nxdomain_answer => e.ede,
            else => .{ .code = .cached_error },
        };
    }

    /// Every reply shaped for `q`: a SERVFAIL opens or widens the window, a
    /// stale one holds the question, anything else closes it.
    pub fn note(f: *Failures, gpa: Allocator, q: dns.Question, cd: bool, served: Served, first_s: u32, now_ns: i64) !void {
        // An answer with nothing to forget costs no key: the common case.
        const forgets = served.hold_until_ns == 0 and served.msg.header.flags.rcode != .server_failure;
        if (forgets and f.map.count() == 0) return;
        var buf: [dns.max_dotted_len + 4]u8 = undefined;
        const k = key(&buf, q, cd);
        if (forgets) {
            if (f.map.fetchRemove(k)) |kv| gpa.free(kv.key);
            return;
        }
        if (served.hold_until_ns > 0) return f.put(gpa, k, .{ .until_ns = served.hold_until_ns, .window_s = first_s, .ede = served.ede.? });
        const ede = served.ede orelse dns.Ede{ .code = .other };
        if (f.map.getPtr(k)) |e| {
            // Every client waiting on one failure notes it: once is enough.
            if (now_ns < e.until_ns) return;
            // Failing again within a window of the last lapsing: back off.
            const again = now_ns < e.until_ns + @as(i64, e.window_s) * std.time.ns_per_s;
            e.window_s = if (again) @min(e.window_s * 2, max_window_s) else first_s;
            e.until_ns = now_ns + @as(i64, e.window_s) * std.time.ns_per_s;
            e.ede = ede;
            return;
        }
        if (first_s == 0) return;
        try f.put(gpa, k, .{ .until_ns = now_ns + @as(i64, first_s) * std.time.ns_per_s, .window_s = first_s, .ede = ede });
    }

    /// Past `max_entries` an arbitrary other question is forgotten.
    fn put(f: *Failures, gpa: Allocator, k: []const u8, e: Entry) !void {
        if (f.map.getPtr(k)) |old| {
            old.* = e;
            return;
        }
        if (f.map.count() >= max_entries) {
            var it = f.map.keyIterator();
            const old = it.next().?.*;
            _ = f.map.remove(old);
            gpa.free(old);
        }
        const own = try gpa.dupe(u8, k);
        errdefer gpa.free(own);
        try f.map.put(gpa, own, e);
    }
};

test "a failure is remembered, backs off while it persists, and an answer forgets it" {
    const testing = std.testing;
    var f: Failures = .{};
    defer f.deinit(testing.allocator);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const q: dns.Question = .{ .name = try dns.parseDottedName(arena.allocator(), "Example."), .qtype = .a, .qclass = .in };
    const s = std.time.ns_per_s;
    const failed = try servfail(arena.allocator(), q, .{}, .{ .code = .no_reachable_authority });
    try f.note(testing.allocator, q, false, failed, 5, 0);
    try testing.expectEqual(dns.Ede.Code.cached_error, f.get(q, false, 4 * s).?.code);
    try testing.expectEqual(null, f.get(q, true, 4 * s));
    try testing.expectEqual(null, f.get(q, false, 5 * s));
    try f.note(testing.allocator, q, false, failed, 5, 6 * s);
    // Clients that shared the failure note it at the same instant.
    try f.note(testing.allocator, q, false, failed, 5, 6 * s);
    try testing.expect(f.get(q, false, 15 * s) != null);
    try testing.expectEqual(null, f.get(q, false, 16 * s));
    var ok = failed;
    ok.msg.header.flags.rcode = .no_error;
    try f.note(testing.allocator, q, false, ok, 5, 17 * s);
    try testing.expectEqual(0, f.map.count());
}
