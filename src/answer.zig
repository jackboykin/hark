//! A client's response, shaped from the graph: policy over facts, no
//! sockets. The live server and the simulator both serve through it.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const dns = @import("dns.zig");
const graph = @import("graph.zig");
const walk = @import("walk.zig");
const store = @import("store.zig");
const rand = @import("rand.zig");
const dns64 = @import("dns64.zig");
const special_use = @import("special_use.zig");
const stub = @import("stub.zig");
const response = @import("response.zig");

pub const Client = struct {
    rd: bool = true,
    cd: bool = false,
    do_bit: bool = false,
    ad: bool = false,

    pub fn fromQuery(q: dns.Query) Client {
        return .{ .rd = q.header.flags.rd, .cd = q.header.flags.cd, .do_bit = q.edns != null and q.edns.?.do_bit, .ad = q.header.flags.ad };
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
        const v6 = dns64.parseIp6Arpa(q.name) orelse return q;
        if (!d.prefix.contains(&v6)) return q;
        const v4 = d.prefix.extract(&v6);
        const in_addr = try arena.print("{d}.{d}.{d}.{d}.in-addr.arpa.", .{ v4[3], v4[2], v4[1], v4[0] });
        return .{ .name = try dns.parseDottedName(arena, in_addr), .qtype = .ptr, .qclass = q.qclass };
    }

    /// §5.1.2: an AAAA that came back empty wants the A too.
    pub fn wantsA(q: dns.Question, served: Served) bool {
        return q.qtype == .aaaa and dns64.wantsSynthesis(served.rcode, served.answers);
    }

    /// PTRs re-owned under the client's name; AAAA embedded from `a` (§5.1.6).
    pub fn shape(d: Dns64, arena: Allocator, q: dns.Question, served: Served, a: ?Served) !Served {
        var out = served;
        if (q.qtype == .ptr and !served.question.name.eql(q.name)) {
            out.answers = try dns64.renamePtr(arena, served.answers, q.name);
            out.ad = false;
            // A denial there proves a name the client never asked about.
            out.authorities = &.{};
            out.additionals = &.{};
        } else if (a) |from| {
            if (try dns64.synthesizeAaaa(arena, d.prefix, from.answers, served.authorities)) |aaaa| {
                out = from;
                out.answers = aaaa;
                out.ad = false;
            } else if (from.rcode != .no_error) out = from;
            if (from.rcode == .no_error) {
                out.cacheable = served.cacheable and from.cacheable;
                if (out.hold_until_ns == 0) out.ede = if (served.hold_until_ns > 0) served.ede else if (from.hold_until_ns > 0) from.ede else out.ede;
                out.hold_until_ns = @max(served.hold_until_ns, from.hold_until_ns);
            }
        }
        if (a) |from| out.held = try std.mem.concat(arena, *store.Blob, &.{ served.held, from.held });
        out.question = q;
        return out;
    }
};

/// A reply as it goes out: its records as wire with the TTLs they are
/// sent with, aliasing the blobs in `held` until `release`.
pub const Served = struct {
    rcode: dns.RCode,
    /// Already what the client asked for (RFC 6840 §5.7).
    ad: bool = false,
    /// What the graph was asked; DNS64 may have asked another name.
    question: dns.Question,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
    additionals: []const dns.ResourceRecord = &.{},
    /// A fact past this instant (TTL 0 is served but never memoised).
    cacheable: bool,
    ede: ?dns.Ede = null,
    /// Served stale: hold the question stale until then (`Failures`).
    hold_until_ns: i64 = 0,
    /// A failure of this host's or of the asker's limits, not the DNS's:
    /// never noted (`Failures`).
    theirs: bool = false,
    local: bool = false,
    aa: bool = false,
    held: []const *store.Blob = &.{},

    pub fn release(s: Served, st: *store.Store) void {
        for (s.held) |b| st.unref(b);
    }

    pub fn reply(s: Served) response.Reply {
        return .{ .rcode = s.rcode, .ad = s.ad, .ede = s.ede, .local = s.local, .aa = s.aa, .answers = s.answers, .authorities = s.authorities, .additionals = s.additionals };
    }
};

fn synthesized(q: dns.Question, s: special_use.Synthesized) Served {
    return .{ .rcode = s.rcode, .aa = s.aa, .question = q, .answers = s.answers, .authorities = s.authorities, .cacheable = false, .local = true };
}

pub fn ownAnswer(arena: Allocator, q: dns.Question, o: special_use.Own, d64: ?Dns64) !Served {
    const served = synthesized(q, try special_use.synthesize(arena, q, o));
    // RFC 8880 §7.1: ipv4only.arpa's AAAA is synthesized here too.
    if (d64) |d| if (q.qtype == .aaaa and dns64.wantsSynthesis(served.rcode, served.answers)) {
        var qa = q;
        qa.qtype = .a;
        const of_a = special_use.classify(qa.name, qa.qtype, false) orelse return served;
        var a = synthesized(q, try special_use.synthesize(arena, qa, of_a));
        a.answers = try dns64.synthesizeAaaa(arena, d.prefix, a.answers, &.{}) orelse return served;
        return a;
    };
    return served;
}

/// RFC 8482: ANY is answered with a synthetic HINFO, asking nobody.
pub fn hinfo(arena: Allocator, q: dns.Question) !Served {
    const rr: dns.ResourceRecord = try .init(arena, .{ .name = q.name, .rtype = .hinfo, .rclass = .in, .ttl = 0, .rdata = .{ .unknown = "\x07RFC8482\x00" } });
    return .{ .rcode = .no_error, .question = q, .answers = try arena.dupe(dns.ResourceRecord, &.{rr}), .cacheable = false };
}

/// SERVFAIL, and why.
pub fn servfail(q: dns.Question, ede: dns.Ede) Served {
    return .{ .rcode = .server_failure, .question = q, .cacheable = false, .ede = ede };
}

/// A cell's failure, as SERVFAIL.
fn servfailOf(q: dns.Question, why: graph.Failure) Served {
    var s = servfail(q, .{ .code = why.code, .text = why.text });
    s.theirs = why.cause != .zone;
    return s;
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

/// The client path, in the one order serve and the replay both take:
/// RFC 6761, RFC 8482, RRSIG, a fact still live, the failure cache, then
/// memory past its floor or the graph, which each drives its own way;
/// past the client's patience, stale.
pub const Desk = struct {
    g: *graph.Graph,
    retention: Retention,
    dns64: ?dns64.Prefix,
    failures: Failures = .{},

    pub fn deinit(d: *Desk) void {
        d.failures.deinit(d.g.gpa);
    }

    /// `recalled` and `floored` come noted; `replayed` and `held` never are,
    /// or a hold would extend itself.
    pub const Early = union(enum) {
        synthesized: Served,
        replayed: Served,
        held: Served,
        recalled: Served,
        floored: Served,
        graph,
    };

    pub fn early(d: *Desk, arena: Allocator, q: dns.Question, c: Client) !Early {
        // A stub zone the operator named overrides what hark answers only by
        // default: home.arpa's and service.arpa's empty zones (RFC 6303 §3),
        // and test (RFC 6761 §6.2).
        if (stub.of(d.g.cfg.stub_zones, q.name, q.qtype) == null) if (special_use.classify(q.name, q.qtype, c.do_bit)) |o|
            return .{ .synthesized = try ownAnswer(arena, q, o, Dns64.on(d.dns64, c)) };
        if (q.qtype == .any) return .{ .synthesized = try hinfo(arena, q) };
        // RRSIGs are never signed (RFC 4035 §2.2): an answer of them can't
        // be validated, and SERVFAIL would read as bogus. Validating, the
        // question is a kind not supported (RFC 1035 §4.1.1); under CD, and
        // unvalidated, the RRSIGs are data.
        if (q.qtype == .rrsig and d.g.cfg.trust_anchors != null and !c.cd)
            return .{ .synthesized = .{ .rcode = .not_implemented, .question = q, .cacheable = false, .ede = .{ .code = .not_supported } } };
        if (try d.memory(arena, q, c, .fresh)) |s| return .{ .recalled = try d.derived(q, c, s) };
        if (try d.hold(q, c)) |ede| {
            // Held, the graph is closed: memory serves the last tenth too.
            if (try d.memory(arena, q, c, .live)) |s| return .{ .recalled = try d.derived(q, c, s) };
            switch (ede.code) {
                // A hold with nothing left to serve asks afresh.
                .stale_answer, .stale_nxdomain_answer => if (try d.memory(arena, q, c, .stale)) |s| return .{ .replayed = s },
                .other, .dnssec_bogus, .cached_error, .blocked, .not_supported, .no_reachable_authority, .unsupported_nsec3_iterations, .synthesized, .over_quota => return .{ .held = servfail(q, ede) },
            }
        }
        if (try d.memory(arena, q, c, .floored)) |s| return .{ .floored = try d.derived(q, c, s) };
        return .graph;
    }

    fn hold(d: *Desk, q: dns.Question, c: Client) !?dns.Ede {
        const ede = d.failures.get(q, c.cd, d.g.now()) orelse return null;
        if (!builtin.is_test) return ede;
        return if (try d.g.forgets(.forget, .of(.answer, q.name, q.qtype))) null else ede;
    }

    /// `.fresh` is `.live` short of its last tenth, which the graph takes to prefetch.
    pub fn memory(d: *Desk, arena: Allocator, q: dns.Question, c: Client, how: How) !?Served {
        const aq = try d.asked(arena, q, c);
        const x = Dns64.on(d.dns64, c) orelse return recall(d, arena, aq, c, how);
        const modes = ladder(how);
        const exact = try best(d, arena, aq, c, modes[0..1]);
        const served = exact orelse (if (q.qtype == .aaaa) try best(d, arena, aq, c, modes[1..]) else null) orelse return null;
        errdefer served.release(&d.g.store);
        const wants = Dns64.wantsA(q, served);
        if (!wants and exact == null) return d.drop(served);
        const a = if (!wants) null else try best(d, arena, aOf(q), c, if (exact != null) modes else modes[0..1]) orelse return d.drop(served);
        errdefer if (a) |s| s.release(&d.g.store);
        return try x.shape(arena, q, served, a);
    }

    const How = enum { fresh, live, floored, stale };

    fn ladder(how: How) []const How {
        return switch (how) {
            .fresh => &.{.fresh},
            .live => &.{.live},
            .floored => &.{ .floored, .live },
            .stale => &.{ .stale, .floored, .live },
        };
    }

    fn recall(d: *Desk, arena: Allocator, q: dns.Question, c: Client, how: How) !?Served {
        return switch (how) {
            .fresh => fresh(d, arena, q, c, true),
            .live => fresh(d, arena, q, c, false),
            .floored => floored(d, arena, q, c),
            .stale => stale(d, arena, q, c),
        };
    }

    fn best(d: *Desk, arena: Allocator, q: dns.Question, c: Client, modes: []const How) !?Served {
        for (modes) |m| if (try recall(d, arena, q, c, m)) |s| return s;
        return null;
    }

    fn drop(d: *Desk, s: Served) ?Served {
        s.release(&d.g.store);
        return null;
    }

    pub fn asked(d: *Desk, arena: Allocator, q: dns.Question, c: Client) !dns.Question {
        return if (Dns64.on(d.dns64, c)) |x| try x.asked(arena, q) else q;
    }

    pub fn built(d: *Desk, arena: Allocator, root: graph.CellId, q: dns.Question, c: Client) !Served {
        return build(d, arena, root, try d.asked(arena, q, c), c);
    }

    /// Under DNS64, the A to ask for behind `served`, an empty AAAA (§5.1.2).
    pub fn wantsA(d: *Desk, q: dns.Question, c: Client, served: Served) ?dns.Question {
        return if (Dns64.on(d.dns64, c) != null and Dns64.wantsA(q, served)) aOf(q) else null;
    }

    fn aOf(q: dns.Question) dns.Question {
        return .{ .name = q.name, .qtype = .a, .qclass = q.qclass };
    }

    pub fn finish(d: *Desk, arena: Allocator, q: dns.Question, c: Client, served: Served, a: ?graph.CellId) !Served {
        const x = Dns64.on(d.dns64, c) orelse return served;
        const from = if (a) |id| try build(d, arena, id, aOf(q), c) else null;
        return try x.shape(arena, q, served, from);
    }

    /// Every reply the resolver derived, noted: a failure opens or widens
    /// its window, stale holds it, an answer forgets it.
    pub fn derived(d: *Desk, q: dns.Question, c: Client, served: Served) !Served {
        try d.failures.note(d.g.gpa, q, c.cd, served, d.g.cfg.servfail_ttl, d.g.now());
        return served;
    }
};

/// BIND's stale-refresh-time (RFC 8767 §5): after serving stale, how long
/// the question is answered stale without asking.
const stale_hold_s = 30;
/// RFC 8767 §5: a resolution past a stub's patience answers stale instead.
pub const stale_client_ms = 1800;
/// RFC 8767 §5: "a common timeout value of 2 seconds". Past it a UDP
/// client has given up, or never asked (DNSBomb).
pub const client_timeout_ms = 2000;

const Hop = struct {
    blob: *store.Blob,
    rrset: store.Rrset,
    /// Record TTLs are raised to this (`min-ttl`), before aging.
    floor: u32,
    /// Where a verified hop's proof ends; records live no longer.
    life: u32 = std.math.maxInt(u32),
    /// Past its retention, served under RFC 8767.
    stale: bool = false,
};

/// When `min-ttl` lets a reply go: its TTL floored, under the negative cap
/// and its signatures' validity. TTL 0 is never floored.
fn retainedUntil(d: *const Desk, r: store.Rrset) i64 {
    const g = d.g;
    const ret = d.retention;
    const own = walk.replyExpiry(r);
    if (r.ttl == 0 or r.ttl >= ret.min_ttl) return own;
    var floor: i64 = ret.min_ttl;
    if (r.kind == .nodata or r.kind == .nxdomain) floor = @min(floor, dns.max_negative_ttl);
    var until = r.stored_ns + floor * std.time.ns_per_s;
    const wall = g.wallNow();
    for (r.sections[0..2]) |section| {
        var it = section.iterator();
        while (it.next()) |rr| if (rr.rtype == .rrsig) {
            until = @min(until, g.now() + @as(i64, dns.secondsUntil(rr.rrsig().sig_expiration, wall)) * std.time.ns_per_s);
        };
    }
    return @max(own, until);
}

fn hopOf(d: *const Desk, b: *store.Blob, r: store.Rrset) Hop {
    const retained = @divTrunc(retainedUntil(d, r) - r.stored_ns, std.time.ns_per_s);
    const floor = @min(d.retention.min_ttl, @as(u32, @intCast(std.math.clamp(retained, 0, std.math.maxInt(u32)))));
    return .{ .blob = b, .rrset = r, .floor = floor };
}

/// The answer cell shaped for a client: a failure or bogus is SERVFAIL
/// unless serve-stale has something, bogus data only to CD; a verified
/// hop's TTLs end with its proof, signatures only to DO, AD only when asked
/// (RFC 6840 §5.7).
fn build(d: *const Desk, arena: Allocator, root: graph.CellId, q: dns.Question, c: Client) !Served {
    const g = d.g;
    if (failureOf(g, root, c.cd)) |why| return try stale(d, arena, q, c) orelse servfailOf(q, why);
    const a = g.cell(root).state.fact.answer;
    std.debug.assert(a.hops.len > 0);
    // Secure only if every hop is judged secure; a failed verdict is bogus
    // (RFC 4035 §4.3).
    var secure = true;
    const hops = try arena.alloc(Hop, a.hops.len);
    for (hops, a.hops) |*hop, h| {
        // Every rrset cell settles or loads through a blob.
        const b = g.cell(h.set).blob.?;
        hop.* = hopOf(d, b, .of(b));
        const j = h.judge.unwrap() orelse {
            secure = false;
            continue;
        };
        switch (g.cell(j).state) {
            .fact => |v| {
                secure = secure and v.secure.status == .secure;
                hop.life = lifeOf(g, v.secure.proven_until_ns);
            },
            // A failed verdict proved nothing, so it bounds nothing (CD only).
            .failure => secure = false,
            .pending => unreachable,
        }
    }
    return shape(d, arena, q, c, hops, secure, g.cell(root).expires() > g.now());
}

pub fn failureOf(g: *graph.Graph, root: graph.CellId, cd: bool) ?graph.Failure {
    if (g.cell(root).failure()) |why| return why;
    if (cd) return null;
    for (g.cell(root).state.fact.answer.hops) |h| {
        const j = h.judge.unwrap() orelse continue;
        if (g.cell(j).failure()) |why| return why;
    }
    return null;
}

fn lifeOf(g: *graph.Graph, proven_until_ns: i64) u32 {
    return @intCast(@min(@max(@divTrunc(proven_until_ns - g.now(), std.time.ns_per_s), 0), std.math.maxInt(u32)));
}

fn fresh(d: *const Desk, arena: Allocator, q: dns.Question, c: Client, yield_last_tenth: bool) !?Served {
    const g = d.g;
    const chain = try g.recall(arena, q.name, q.qtype, .fresh) orelse return null;
    var secure = true;
    var first: ?store.Life = null;
    const hops = try arena.alloc(Hop, chain.len);
    for (hops, chain) |*hop, h| {
        hop.* = hopOf(d, h.blob, h.rrset);
        const life: store.Life = .of(hop.rrset.stored_ns, h.blob.expires_ns, h.blob.verdict);
        if (first == null or life.end_ns < first.?.end_ns) first = life;
        if (!g.awaitsVerdict(h.kind)) {
            secure = false;
            continue;
        }
        const v = h.blob.verdict;
        secure = secure and v.chain().status == .secure;
        hop.life = lifeOf(g, v.proven_until_ns);
    }
    if (yield_last_tenth and g.cfg.prefetch and first.?.inLastTenth(g.now())) return null;
    return try shape(d, arena, q, c, hops, secure, true);
}

/// `min-ttl`: a question whose facts have expired but not their floor is
/// answered from memory, unverified, asking nobody. Null: ask the graph.
fn floored(d: *const Desk, arena: Allocator, q: dns.Question, c: Client) !?Served {
    const g = d.g;
    if (d.retention.min_ttl == 0) return null;
    const chain = try g.recall(arena, q.name, q.qtype, .any) orelse return null;
    var expired = false;
    for (chain) |h| {
        if (g.now() >= retainedUntil(d, h.rrset)) return null;
        expired = expired or g.now() >= walk.replyExpiry(h.rrset);
    }
    if (!expired) return null;
    const hops = try arena.alloc(Hop, chain.len);
    for (hops, chain) |*hop, h| hop.* = hopOf(d, h.blob, h.rrset);
    return try shape(d, arena, q, c, hops, false, true);
}

/// RFC 8767: an answer past its retention but inside the stale window,
/// unverified, with EDE 3 or 19; the question is then held stale for
/// `stale_hold_s`, or until the window ends. Null: nothing to serve.
fn stale(d: *const Desk, arena: Allocator, q: dns.Question, c: Client) !?Served {
    const g = d.g;
    if (d.retention.serve_stale_ttl == 0) return null;
    const chain = try g.recall(arena, q.name, q.qtype, .any) orelse return null;
    var window: i64 = std.math.maxInt(i64);
    var any = false;
    const hops = try arena.alloc(Hop, chain.len);
    for (hops, chain) |*hop, h| {
        const until = retainedUntil(d, h.rrset);
        window = @min(window, until + @as(i64, d.retention.serve_stale_ttl) * std.time.ns_per_s);
        hop.* = hopOf(d, h.blob, h.rrset);
        hop.stale = g.now() >= until;
        any = any or hop.stale;
    }
    if (!any or g.now() >= window) return null;
    var served = try shape(d, arena, q, c, hops, false, false);
    served.hold_until_ns = g.now() + stale_hold_s * std.time.ns_per_s;
    return served;
}

/// The one shaper: every reply from the store or the graph passes here,
/// and here only the keep rules below and the TTLs are decided. The
/// rebinding scrub is the wire's (`response.buildResponseWire`).
fn shape(d: *const Desk, arena: Allocator, q: dns.Question, c: Client, hops: []const Hop, secure: bool, cacheable: bool) !Served {
    const g = d.g;
    const held = try arena.alloc(*store.Blob, hops.len);
    var answers: std.ArrayList(dns.ResourceRecord) = .empty;
    var n: usize = 0;
    var proofs: usize = 0;
    for (hops) |hop| {
        n += hop.rrset.sections[0].len;
        proofs += hop.rrset.sections[1].len;
    }
    try answers.ensureTotalCapacityPrecise(arena, n);
    var last: Hop = undefined;
    var age: u32 = 0;
    var life: u32 = 0;
    var stale_any = false;
    // A chain back to a DNAME it passed meets that set again at its owner,
    // asked for it or its signatures: it goes out once (RFC 2181 §5).
    var once: Seen = .{ .bound = n };
    const repeats = hops.len > 1 and (q.qtype == .dname or q.qtype == .rrsig);
    for (hops) |hop| {
        last = hop;
        age = walk.ageOf(hop.rrset.stored_ns, g.now());
        life = hop.life;
        stale_any = stale_any or hop.stale;
        // A denial's life is the reply's, not a record's.
        if (hop.stale and hop.rrset.kind != .answer and hop.rrset.kind != .alias) {
            age = 0;
            life = stale_hold_s;
        }
        try appendAged(arena, &answers, if (repeats) &once else null, hop.rrset.sections[0], .{ .section = .answer, .qtype = q.qtype, .do_bit = c.do_bit }, age, life, hop.floor, hop.stale);
    }
    const r = last.rrset;
    var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
    var seen: Seen = .{ .bound = proofs };
    var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
    // AD vouches for authority (RFC 4035 §3.2.3): under a secure verdict,
    // only the proofs it judged. Every hop's go out: the client needs each
    // to validate the chain (RFC 6672 §5.3.3).
    const keep: Keep = .{ .section = .authority, .qtype = q.qtype, .do_bit = c.do_bit, .denial = r.kind == .nodata or r.kind == .nxdomain, .proofs_only = secure };
    for (hops[0 .. hops.len - 1]) |hop| {
        const hop_age = walk.ageOf(hop.rrset.stored_ns, g.now());
        try appendAged(arena, &authorities, &seen, hop.rrset.sections[1], .{ .section = .authority, .qtype = q.qtype, .do_bit = c.do_bit, .denial = false, .proofs_only = true }, hop_age, hop.life, hop.floor, hop.stale);
    }
    try appendAged(arena, &authorities, &seen, r.sections[1], keep, age, life, last.floor, last.stale);
    // Nothing judges additional, so AD vouches for none of it.
    if (!secure) {
        var add = keep;
        add.section = .additional;
        try appendAged(arena, &additionals, null, r.sections[2], add, age, life, last.floor, last.stale);
    }
    // Any hop counts: a stale alias still redirected.
    const ede: ?dns.Ede = if (stale_any)
        .{ .code = if (r.kind == .nxdomain) .stale_nxdomain_answer else .stale_answer }
    else if (r.ede) |code|
        .{ .code = code }
    else
        null;
    for (hops, held) |hop, *h| h.* = hop.blob.ref();
    return .{
        .rcode = r.kind.rcode(),
        .ad = secure and (c.do_bit or c.ad),
        // A stub zone's servers may give private addresses, and a chain's
        // addresses are all in its last hop.
        .local = @as(graph.Kind, @fromBackingInt(last.blob.kind)) == .stub,
        .question = q,
        .answers = answers.items,
        .authorities = authorities.items,
        .additionals = additionals.items,
        .cacheable = cacheable,
        .ede = ede,
        .held = held,
    };
}

/// What a client is sent of a section. What it needs: the answer (or to
/// know there is none), the SOA to cache its absence (RFC 2308), and with
/// DO the proofs to validate it (RFC 4035 §3.1.1, §3.1.3); DNSSEC records
/// go only to DO or when asked for by type (RFC 3225), never for CD alone
/// (§3.2.2 turns validation off). Intake keeps nothing more but an NS
/// answer's NS and glue (`walk.classify`), and DS is never sent there.
const Keep = struct {
    section: enum { answer, authority, additional },
    qtype: dns.RType,
    do_bit: bool,
    denial: bool = true,
    proofs_only: bool = false,

    fn keeps(k: Keep, rr: dns.ResourceRecord) bool {
        const t = rr.rtype;
        return switch (k.section) {
            .answer => t == k.qtype or switch (t) {
                .rrsig, .nsec, .nsec3 => k.do_bit,
                else => true,
            },
            .authority => (!k.proofs_only or switch (if (t == .rrsig) rr.covers().? else t) {
                .soa, .nsec, .nsec3 => true,
                else => false,
            }) and switch (t) {
                // A denial's SOA is its lifetime; nothing else owes one.
                .soa => k.denial,
                .nsec, .nsec3 => k.do_bit,
                .ds => false,
                // A signature goes with what it covers.
                .rrsig => k.do_bit and switch (rr.covers().?) {
                    .soa => k.denial,
                    .ds => false,
                    else => true,
                },
                else => true,
            },
            .additional => switch (t) {
                .rrsig, .nsec, .nsec3 => k.do_bit,
                else => true,
            },
        };
    }
};

/// The records `keep` keeps, TTLs aged since the reply, floored to
/// `floor` and capped by `life`; a record past its TTL in a stale reply
/// gets the hold (RFC 8767 §4).
fn appendAged(arena: Allocator, out: *std.ArrayList(dns.ResourceRecord), seen: ?*Seen, records: store.Records, keep: Keep, age: u32, life: u32, floor: u32, is_stale: bool) !void {
    try out.ensureUnusedCapacity(arena, records.len);
    var it = records.iterator();
    while (it.next()) |rr| {
        if (!keep.keeps(rr)) continue;
        if (seen) |s| if (!try s.add(arena, out.items, rr)) continue;
        var aged = rr;
        aged.ttl = if (is_stale and rr.ttl <= age) stale_hold_s else @min(@max(rr.ttl, floor) -| age, life);
        out.appendAssumeCapacity(aged);
    }
}

/// A shared proof goes out once. A set: the proofs are a stranger's, and
/// a scan per record is quadratic in them. Sized at its first record, so
/// a reply that keeps no proof pays nothing.
const Seen = struct {
    /// The most records it will hold.
    bound: usize,
    slots: []u32 = &.{},

    const empty = std.math.maxInt(u32);

    /// False if `out` holds `rr`; else `rr` must be appended to `out` next.
    fn add(s: *Seen, arena: Allocator, out: []const dns.ResourceRecord, rr: dns.ResourceRecord) !bool {
        if (s.slots.len == 0) {
            s.slots = try arena.alloc(u32, std.math.ceilPowerOfTwoAssert(usize, 2 * s.bound));
            @memset(s.slots, empty);
        }
        var i = hash(rr) & (s.slots.len - 1);
        while (s.slots[i] != empty) : (i = (i + 1) & (s.slots.len - 1))
            if (sameRecord(out[s.slots[i]], rr)) return false;
        s.slots[i] = @intCast(out.len);
        return true;
    }

    fn hash(rr: dns.ResourceRecord) usize {
        var h: std.hash.Wyhash = .init(rand.hash_seed);
        h.update(rr.name.wire);
        h.update(std.mem.asBytes(&[2]u16{ @backingInt(rr.rtype), @backingInt(rr.rclass) }));
        h.update(rr.rdata);
        return @truncate(h.final());
    }
};

/// Owner, type, class and data alike; TTLs aside.
fn sameRecord(a: dns.ResourceRecord, b: dns.ResourceRecord) bool {
    return a.name.eql(b.name) and a.rtype == b.rtype and a.rclass == b.rclass and std.mem.eql(u8, a.rdata, b.rdata);
}

/// RFC 9520 §3.2's failure cache: a question that failed is answered here,
/// asking nobody, for a window that doubles while it keeps failing, to the
/// RFC's 5 minutes; an answer forgets it. Keyed (qname, qtype, CD), since a
/// CD client is owed bogus data. Policy over no fact, so it is the server's.
pub const Failures = struct {
    /// Array-backed: every answer removes, and a tombstoning map's misses
    /// would probe ever longer.
    map: std.array_hash_map.Custom([]const u8, Entry, Seeded, true) = .empty,

    const Entry = struct { until_ns: i64, window_s: u32, ede: dns.Ede };
    const Seeded = struct {
        pub fn hash(_: Seeded, k: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(rand.hash_seed, k));
        }
        pub fn eql(_: Seeded, a: []const u8, b: []const u8, _: usize) bool {
            return std.mem.eql(u8, a, b);
        }
    };
    const max_window_s = 300;
    const max_entries = 4096;

    pub fn deinit(f: *Failures, gpa: Allocator) void {
        for (f.map.keys()) |k| gpa.free(k);
        f.map.deinit(gpa);
    }

    fn key(buf: *[dns.max_name_wire_len + 3]u8, q: dns.Question, cd: bool) []const u8 {
        const name = q.name.wire;
        @memcpy(buf[0..name.len], name);
        std.mem.writeInt(u16, buf[name.len..][0..2], @backingInt(q.qtype), .little);
        buf[name.len + 2] = @intFromBool(cd);
        return buf[0 .. name.len + 3];
    }

    /// The EDE to answer with while the window lasts. A validation failure
    /// keeps its reason, a stale hold says to serve stale again; anything
    /// else is RFC 8914's cached error.
    pub fn get(f: *Failures, q: dns.Question, cd: bool, now_ns: i64) ?dns.Ede {
        if (f.map.count() == 0) return null;
        var buf: [dns.max_name_wire_len + 3]u8 = undefined;
        const e = f.map.get(key(&buf, q, cd)) orelse return null;
        if (e.until_ns <= now_ns) return null;
        return switch (e.ede.code) {
            .dnssec_bogus, .unsupported_nsec3_iterations, .stale_answer, .stale_nxdomain_answer => e.ede,
            .other, .cached_error, .blocked, .not_supported, .no_reachable_authority, .synthesized, .over_quota => .{ .code = .cached_error },
        };
    }

    /// Every reply shaped for `q`: a SERVFAIL opens or widens the window, a
    /// stale one holds the question, anything else closes it. A failure
    /// of this host's or the asker's limits says nothing about the question.
    pub fn note(f: *Failures, gpa: Allocator, q: dns.Question, cd: bool, served: Served, first_s: u32, now_ns: i64) !void {
        if (served.theirs) return;
        const forgets = served.hold_until_ns == 0 and served.rcode != .server_failure;
        if (forgets and f.map.count() == 0) return;
        var buf: [dns.max_name_wire_len + 3]u8 = undefined;
        const k = key(&buf, q, cd);
        if (forgets) {
            if (f.map.fetchSwapRemove(k)) |kv| gpa.free(kv.key);
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

    /// Past `max_entries` another question is forgotten, one the seeded
    /// hash of this one picks: arbitrary, and no asker's to choose.
    fn put(f: *Failures, gpa: Allocator, k: []const u8, e: Entry) !void {
        if (f.map.getPtr(k)) |old| {
            old.* = e;
            return;
        }
        if (f.map.count() >= max_entries) {
            const at = Seeded.hash(.{}, k) % f.map.count();
            const old = f.map.keys()[at];
            f.map.swapRemoveAt(at);
            gpa.free(old);
        }
        const own = try gpa.dupe(u8, k);
        errdefer gpa.free(own);
        try f.map.put(gpa, own, e);
    }
};

test "a client is sent what Keep keeps" {
    const R = struct {
        section: @FieldType(Keep, "section"),
        rtype: dns.RType,
        covers: dns.RType = .a,
        do_bit: bool = false,
        qtype: dns.RType = .a,
        kept: bool,
    };
    const rows = [_]R{
        .{ .section = .answer, .rtype = .a, .kept = true },
        .{ .section = .answer, .rtype = .rrsig, .kept = false },
        .{ .section = .answer, .rtype = .rrsig, .do_bit = true, .kept = true },
        .{ .section = .answer, .rtype = .nsec, .qtype = .nsec, .kept = true },
        .{ .section = .authority, .rtype = .soa, .kept = true },
        .{ .section = .authority, .rtype = .nsec, .kept = false },
        .{ .section = .authority, .rtype = .nsec, .do_bit = true, .kept = true },
        .{ .section = .authority, .rtype = .ds, .do_bit = true, .kept = false },
        .{ .section = .authority, .rtype = .rrsig, .covers = .nsec, .do_bit = true, .kept = true },
        .{ .section = .authority, .rtype = .rrsig, .covers = .soa, .kept = false },
        .{ .section = .authority, .rtype = .rrsig, .covers = .a, .do_bit = true, .kept = true },
        .{ .section = .additional, .rtype = .a, .kept = true },
        .{ .section = .additional, .rtype = .rrsig, .kept = false },
    };
    for (rows) |row| {
        var rdata: [2]u8 = undefined;
        std.mem.writeInt(u16, &rdata, @backingInt(row.covers), .big);
        const rr: dns.ResourceRecord = .{ .name = .root, .rtype = row.rtype, .rclass = .in, .ttl = 0, .rdata = &rdata };
        const keep: Keep = .{ .section = row.section, .qtype = row.qtype, .do_bit = row.do_bit };
        try std.testing.expectEqual(row.kept, keep.keeps(rr));
    }
}

test "a proof two hops share goes out once" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // NSEC, IN, TTL 3600; rdata: next name the root, an A bitmap.
    const nsec = "\x00\x2f\x00\x01\x00\x00\x0e\x10\x00\x04\x00\x00\x01\x40";
    const ab = "\x01a\x00" ++ nsec ++ "\x01b\x00" ++ nsec;
    const ac = "\x01a\x00" ++ nsec ++ "\x01c\x00" ++ nsec;
    const hops = [_]store.Records{
        .{ .payload = ab, .start = 0, .end = ab.len, .len = 2 },
        .{ .payload = ac, .start = 0, .end = ac.len, .len = 2 },
    };
    var out: std.ArrayList(dns.ResourceRecord) = .empty;
    var seen: Seen = .{ .bound = 4 };
    for (hops) |hop| try appendAged(a, &out, &seen, hop, .{ .section = .authority, .qtype = .a, .do_bit = true }, 0, std.math.maxInt(u32), 0, false);
    try std.testing.expectEqual(3, out.items.len);
}

test "a failure is remembered, backs off while it persists, and an answer forgets it" {
    const testing = std.testing;
    var f: Failures = .{};
    defer f.deinit(testing.allocator);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const q: dns.Question = .{ .name = try dns.parseDottedName(arena.allocator(), "Example."), .qtype = .a, .qclass = .in };
    const s = std.time.ns_per_s;
    const failed = servfail(q, .{ .code = .no_reachable_authority });
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
    ok.rcode = .no_error;
    try f.note(testing.allocator, q, false, ok, 5, 17 * s);
    try testing.expectEqual(0, f.map.count());
    // Past the bound, each question remembered forgets another.
    for (0..Failures.max_entries + 2) |t| {
        var other = q;
        other.qtype = @fromBackingInt(@intCast(t));
        try f.note(testing.allocator, other, false, failed, 5, 0);
    }
    try testing.expectEqual(Failures.max_entries, f.map.count());
}
