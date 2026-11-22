//! A client's response, shaped from the graph: policy over facts, no
//! sockets. The live server and the simulator both serve through it.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const dns = @import("dns.zig");
const graph = @import("graph.zig");
const model = @import("model.zig");
const walk = @import("walk.zig");
const store = @import("store.zig");
const keyed = @import("keyed.zig");
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

const Dns64 = struct {
    prefix: dns64.Prefix,

    pub fn on(prefix: ?dns64.Prefix, c: Client) ?Dns64 {
        return if (prefix) |p| if (c.cd) null else .{ .prefix = p } else null;
    }

    pub fn asked(d: Dns64, arena: Allocator, q: dns.Question) !dns.Question {
        if (q.qtype != .ptr) return q;
        const v6 = dns64.parseIp6Arpa(q.name) orelse return q;
        if (!d.prefix.contains(&v6)) return q;
        const v4 = d.prefix.extract(&v6);
        const in_addr = try arena.print("{d}.{d}.{d}.{d}.in-addr.arpa.", .{ v4[3], v4[2], v4[1], v4[0] });
        return .{ .name = try dns.parseDottedName(arena, in_addr), .qtype = .ptr, .qclass = q.qclass };
    }

    pub fn wantsA(q: dns.Question, served: Served) bool {
        return q.qtype == .aaaa and dns64.wantsSynthesis(served.rcode, served.answers);
    }

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

/// A reply as it goes out. Its records alias the blobs in `held`, which stay
/// referenced until `release`.
pub const Served = struct {
    rcode: dns.RCode,
    ad: bool = false,
    /// What the graph was asked: DNS64 may have asked another name.
    question: dns.Question,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
    additionals: []const dns.ResourceRecord = &.{},
    cacheable: bool,
    ede: ?dns.Ede = null,
    hold_until_ns: i64 = 0,
    /// A failure of this host's or the asker's limits, not of the question's
    /// zone: `Failures` never notes it.
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

fn ownAnswer(arena: Allocator, q: dns.Question, z: *const special_use.Zone, d64: ?Dns64) !Served {
    const served = synthesized(q, try special_use.answer(arena, z, q));
    if (d64) |d| if (q.qtype == .aaaa and dns64.wantsSynthesis(served.rcode, served.answers)) {
        var qa = q;
        qa.qtype = .a;
        var a = synthesized(q, try special_use.answer(arena, z, qa));
        a.answers = try dns64.synthesizeAaaa(arena, d.prefix, a.answers, &.{}) orelse return served;
        return a;
    };
    return served;
}

fn hinfo(arena: Allocator, q: dns.Question) !Served {
    const rr: dns.ResourceRecord = try .init(arena, .{ .name = q.name, .rtype = .hinfo, .rclass = .in, .ttl = 0, .rdata = .{ .unknown = "\x07RFC8482\x00" } });
    return .{ .rcode = .no_error, .question = q, .answers = try arena.dupe(dns.ResourceRecord, &.{rr}), .cacheable = false };
}

pub fn servfail(q: dns.Question, ede: dns.Ede) Served {
    return .{ .rcode = .server_failure, .question = q, .cacheable = false, .ede = ede };
}

fn servfailOf(q: dns.Question, why: model.Failure) Served {
    var s = servfail(q, why.ede());
    s.theirs = why.cause() != .zone;
    return s;
}

const Retention = struct {
    min_ttl: u32 = 0,
    serve_stale_ttl: u32 = 0,
};

pub const Desk = struct {
    g: *graph.Graph,
    retention: Retention,
    dns64: ?dns64.Prefix,
    failures: Failures = .{},

    pub fn deinit(d: *Desk) void {
        d.failures.deinit(d.g.gpa);
    }

    /// `recalled` and `floored` come already noted in `Failures`. `replayed` and
    /// `held` must never be, or a hold would extend itself.
    const Early = union(enum) {
        synthesized: Served,
        replayed: Served,
        held: Served,
        recalled: Served,
        floored: Served,
        graph,
    };

    pub fn early(d: *Desk, arena: Allocator, q: dns.Question, c: Client) !Early {
        if (stub.held(d.g.cfg.stub_zones, q.name, q.qtype, c.do_bit)) |z|
            return .{ .synthesized = try ownAnswer(arena, q, z, Dns64.on(d.dns64, c)) };
        if (q.qtype == .any) return .{ .synthesized = try hinfo(arena, q) };
        // RRSIGs are never signed (RFC 4035 §2.2), so an answer of them cannot be
        // validated, and SERVFAIL would read as bogus: NOTIMP instead. Under CD or
        // without validation they are plain data.
        if (q.qtype == .rrsig and d.g.cfg.trust_anchors != null and !c.cd)
            return .{ .synthesized = .{ .rcode = .not_implemented, .question = q, .cacheable = false, .ede = .{ .code = .not_supported } } };
        if (try d.memory(arena, q, c, .fresh)) |s| return .{ .recalled = d.derived(q, c, s) };
        if (try d.hold(q, c)) |held| switch (held) {
            // A stale hold with nothing left to serve falls through and asks afresh.
            .stale => if (try d.memory(arena, q, c, .stale)) |s| return .{ .replayed = s },
            .failed => |ede| return .{ .held = servfail(q, ede) },
        };
        if (try d.memory(arena, q, c, .floored)) |s| return .{ .floored = d.derived(q, c, s) };
        return .graph;
    }

    fn hold(d: *Desk, q: dns.Question, c: Client) !?Held {
        const held = heldFailure(&d.failures, q, c.cd, d.g.now()) orelse return null;
        // Only a test's chaos may forget a held failure.
        if (!builtin.is_test) return held;
        return if (try d.g.forgets(.forget, .of(.answer, q.name, q.qtype))) null else held;
    }

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

    const How = enum { fresh, floored, stale };

    fn ladder(how: How) []const How {
        return switch (how) {
            .fresh => &.{.fresh},
            .floored => &.{ .floored, .fresh },
            .stale => &.{ .stale, .floored, .fresh },
        };
    }

    fn recall(d: *Desk, arena: Allocator, q: dns.Question, c: Client, how: How) !?Served {
        return switch (how) {
            .fresh => fresh(d, arena, q, c),
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

    pub fn built(d: *Desk, arena: Allocator, root: model.CellId, q: dns.Question, c: Client) !Served {
        return build(d, arena, root, try d.asked(arena, q, c), c);
    }

    pub fn wantsA(d: *Desk, q: dns.Question, c: Client, served: Served) ?dns.Question {
        return if (Dns64.on(d.dns64, c) != null and Dns64.wantsA(q, served)) aOf(q) else null;
    }

    fn aOf(q: dns.Question) dns.Question {
        return .{ .name = q.name, .qtype = .a, .qclass = q.qclass };
    }

    /// Owns `served`: if it fails, it releases it.
    pub fn finish(d: *Desk, arena: Allocator, q: dns.Question, c: Client, served: Served, a: ?model.CellId) !Served {
        const x = Dns64.on(d.dns64, c) orelse return served;
        errdefer served.release(&d.g.store);
        const from = if (a) |id| try build(d, arena, id, aOf(q), c) else null;
        errdefer if (from) |f| f.release(&d.g.store);
        return try x.shape(arena, q, served, from);
    }

    pub fn derived(d: *Desk, q: dns.Question, c: Client, served: Served) Served {
        noteFailure(&d.failures, d.g.gpa, q, c.cd, served, d.g.cfg.servfail_ttl, d.g.now());
        return served;
    }
};

const stale_hold_s = 30;
pub const stale_client_ms = 1800;
pub const client_timeout_ms = 2000;

const Hop = struct {
    blob: *store.Blob,
    rrset: store.Rrset,
    floor: u32,
    life: u32 = std.math.maxInt(u32),
    stale: bool = false,
};

fn retainedUntil(d: *const Desk, r: store.Rrset) i64 {
    const g = d.g;
    const ret = d.retention;
    const own = walk.replyExpiry(r);
    if (r.ttl == 0 or r.ttl >= ret.min_ttl) return own;
    var floor: i64 = ret.min_ttl;
    if (r.kind == .nodata or r.kind == .nxdomain) floor = @min(floor, dns.max_negative_ttl);
    var until = r.stored_ns + floor * std.time.ns_per_s;
    const wall = g.wallNow();
    for (0..2) |i| {
        var it = r.section(i).iterator();
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

fn build(d: *const Desk, arena: Allocator, root: model.CellId, q: dns.Question, c: Client) !Served {
    const g = d.g;
    if (failureOf(g, root, c.cd)) |why| return try stale(d, arena, q, c) orelse servfailOf(q, why);
    const a = g.cell(root).state.fact.answer;
    std.debug.assert(a.hops.len > 0);
    var secure = true;
    const hops = try arena.alloc(Hop, a.hops.len);
    for (hops, a.hops) |*hop, h| {
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
            // Reached only under CD: a failed verdict proved nothing, so it bounds no TTL.
            .failure => secure = false,
            .pending => unreachable,
        }
    }
    return shape(d, arena, q, c, hops, secure, g.cell(root).expires() > g.now());
}

pub fn failureOf(g: *graph.Graph, root: model.CellId, cd: bool) ?model.Failure {
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

fn fresh(d: *const Desk, arena: Allocator, q: dns.Question, c: Client) !?Served {
    const g = d.g;
    const chain = try g.recall(arena, q.name, q.qtype, .fresh) orelse return null;
    defer g.letGo(chain);
    var secure = true;
    var first: ?store.Life = null;
    const hops = try arena.alloc(Hop, chain.len);
    for (hops, chain) |*hop, h| {
        hop.* = hopOf(d, h.blob, h.rrset);
        const life: store.Life = .of(hop.rrset.stored_ns, h.blob.expires_ns, h.blob.verdict);
        if (first == null or life.end_ns < first.?.end_ns) first = life;
        const v = h.standing orelse {
            secure = false;
            continue;
        };
        secure = secure and v.status == .secure;
        hop.life = lifeOf(g, v.proven_until_ns);
    }
    const served = try shape(d, arena, q, c, hops, secure, true);
    if (g.cfg.prefetch and first.?.inLastTenth(g.now()))
        g.refresh(.of(.answer, q.name, q.qtype), q.name, first.?.end_ns) catch {};
    return served;
}

fn floored(d: *const Desk, arena: Allocator, q: dns.Question, c: Client) !?Served {
    const g = d.g;
    if (d.retention.min_ttl == 0) return null;
    const chain = try g.recall(arena, q.name, q.qtype, .any) orelse return null;
    defer g.letGo(chain);
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

fn stale(d: *const Desk, arena: Allocator, q: dns.Question, c: Client) !?Served {
    const g = d.g;
    if (d.retention.serve_stale_ttl == 0) return null;
    const chain = try g.recall(arena, q.name, q.qtype, .any) orelse return null;
    defer g.letGo(chain);
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

fn shape(d: *const Desk, arena: Allocator, q: dns.Question, c: Client, hops: []const Hop, secure: bool, cacheable: bool) !Served {
    const g = d.g;
    const held = try arena.alloc(*store.Blob, hops.len);
    var answers: std.ArrayList(dns.ResourceRecord) = .empty;
    var n: usize = 0;
    var proofs: usize = 0;
    for (hops) |hop| {
        n += hop.rrset.counts[0];
        proofs += hop.rrset.counts[1];
    }
    try answers.ensureTotalCapacityPrecise(arena, n);
    var last: Hop = undefined;
    var age: u32 = 0;
    var life: u32 = 0;
    var stale_any = false;
    // A chain that passed a DNAME meets that set again when the question is
    // for it or its signatures: it goes out once (RFC 2181 §5).
    var once: Seen = .{ .bound = n };
    const repeats = hops.len > 1 and (q.qtype == .dname or q.qtype == .rrsig);
    for (hops) |hop| {
        last = hop;
        age = walk.ageOf(hop.rrset.stored_ns, g.now());
        life = hop.life;
        stale_any = stale_any or hop.stale;
        if (hop.stale and hop.rrset.kind != .answer and hop.rrset.kind != .alias) {
            age = 0;
            life = stale_hold_s;
        }
        try appendAged(arena, &answers, if (repeats) &once else null, hop.rrset.section(0), .{ .section = .answer, .qtype = q.qtype, .do_bit = c.do_bit }, .{ .age = age, .life = life, .floor = hop.floor, .stale = hop.stale });
    }
    const r = last.rrset;
    var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
    var seen: Seen = .{ .bound = proofs };
    var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
    // AD vouches for the authority section too (RFC 4035 §3.2.3), so a secure
    // reply carries only the proofs that were judged. Every hop's proofs go
    // out: the client needs each to validate the chain.
    const keep: Keep = .{ .section = .authority, .qtype = q.qtype, .do_bit = c.do_bit, .denial = r.kind == .nodata or r.kind == .nxdomain, .proofs_only = secure };
    for (hops[0 .. hops.len - 1]) |hop| {
        const hop_age = walk.ageOf(hop.rrset.stored_ns, g.now());
        try appendAged(arena, &authorities, &seen, hop.rrset.section(1), .{ .section = .authority, .qtype = q.qtype, .do_bit = c.do_bit, .denial = false, .proofs_only = true }, .{ .age = hop_age, .life = hop.life, .floor = hop.floor, .stale = hop.stale });
    }
    try appendAged(arena, &authorities, &seen, r.section(1), keep, .{ .age = age, .life = life, .floor = last.floor, .stale = last.stale });
    // Nothing judges additional, so a reply with AD carries none.
    if (!secure) {
        var add = keep;
        add.section = .additional;
        try appendAged(arena, &additionals, null, r.section(2), add, .{ .age = age, .life = life, .floor = last.floor, .stale = last.stale });
    }
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
        // A stub zone may rightly give private addresses, and a chain's addresses
        // are all in its last hop.
        .local = @as(model.Kind, @fromBackingInt(last.blob.kind)) == .stub,
        .question = q,
        .answers = answers.items,
        .authorities = authorities.items,
        .additionals = additionals.items,
        .cacheable = cacheable,
        .ede = ede,
        .held = held,
    };
}

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
                .soa => k.denial,
                .nsec, .nsec3 => k.do_bit,
                .ds => false,
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

const Aging = struct { age: u32, life: u32, floor: u32, stale: bool };

fn appendAged(arena: Allocator, out: *std.ArrayList(dns.ResourceRecord), seen: ?*Seen, records: store.Records, keep: Keep, t: Aging) !void {
    try out.ensureUnusedCapacity(arena, records.len);
    var it = records.iterator();
    while (it.next()) |rr| {
        if (!keep.keeps(rr)) continue;
        if (seen) |s| if (!try s.add(arena, out.items, rr)) continue;
        var aged = rr;
        // Floored, then aged, then capped by the proof's life. A record past its
        // TTL in a stale reply gets the hold instead of 0 (RFC 8767 §4).
        aged.ttl = if (t.stale and rr.ttl <= t.age) stale_hold_s else @min(@max(rr.ttl, t.floor) -| t.age, t.life);
        out.appendAssumeCapacity(aged);
    }
}

const Seen = struct {
    bound: usize,
    slots: []u32 = &.{},

    const empty = std.math.maxInt(u32);

    /// False if `out` holds `rr`. On true the caller must append `rr` to `out`
    /// next: the slot stores that index.
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
        var h: keyed.Hasher = .init(&keyed.hash_key);
        h.update(rr.name.wire);
        h.update(std.mem.asBytes(&[2]u16{ @backingInt(rr.rtype), @backingInt(rr.rclass) }));
        h.update(rr.rdata);
        return @truncate(h.finalInt());
    }
};

fn sameRecord(a: dns.ResourceRecord, b: dns.ResourceRecord) bool {
    return a.name.eql(b.name) and a.rtype == b.rtype and a.rclass == b.rclass and std.mem.eql(u8, a.rdata, b.rdata);
}

/// RFC 9520 §3.2's failure cache: a question that failed is answered from
/// here, asking nobody, for a window that doubles while it keeps failing, up
/// to 5 minutes. Keyed with CD, since a CD client is owed bogus data. The
/// graph remembers the fact that failed, for every question resting on it;
/// this remembers the answer, whose window grows per question.
const Failures = keyed.Memory([]const u8, union(enum) { stale, failure: struct { window_s: u32, ede: dns.Ede } }, keyed.Strings);

const Held = union(enum) { stale, failed: dns.Ede };

const max_window_s = 300;

fn failureKey(buf: *[dns.max_name_wire_len + 3]u8, q: dns.Question, cd: bool) []const u8 {
    const name = q.name.wire;
    @memcpy(buf[0..name.len], name);
    std.mem.writeInt(u16, buf[name.len..][0..2], @backingInt(q.qtype), .little);
    buf[name.len + 2] = @intFromBool(cd);
    return buf[0 .. name.len + 3];
}

fn heldFailure(f: *const Failures, q: dns.Question, cd: bool, now_ns: i64) ?Held {
    var buf: [dns.max_name_wire_len + 3]u8 = undefined;
    return switch (f.get(failureKey(&buf, q, cd), now_ns) orelse return null) {
        .stale => .stale,
        .failure => |x| .{ .failed = x.ede.recalled() },
    };
}

/// Noting only makes a later answer quicker, so a shortage forgoes it.
fn noteFailure(f: *Failures, gpa: Allocator, q: dns.Question, cd: bool, served: Served, first_s: u32, now_ns: i64) void {
    if (served.theirs) return;
    const forgets = served.hold_until_ns == 0 and served.rcode != .server_failure;
    if (forgets and f.map.count() == 0) return;
    var buf: [dns.max_name_wire_len + 3]u8 = undefined;
    const k = failureKey(&buf, q, cd);
    if (forgets) return f.forget(gpa, k);
    if (served.hold_until_ns > 0) return f.put(gpa, k, .{ .until_ns = served.hold_until_ns, .is = .stale }) catch {};
    var window_s = first_s;
    if (f.map.get(k)) |e| {
        if (now_ns < e.until_ns) return;
        switch (e.is) {
            .stale => {},
            .failure => |x| if (now_ns < e.until_ns + @as(i64, x.window_s) * std.time.ns_per_s) {
                window_s = @min(x.window_s * 2, max_window_s);
            },
        }
    }
    if (window_s == 0) return;
    const ede = served.ede orelse dns.Ede{ .code = .other };
    f.put(gpa, k, .{ .until_ns = now_ns + @as(i64, window_s) * std.time.ns_per_s, .is = .{ .failure = .{ .window_s = window_s, .ede = ede } } }) catch {};
}

test "a proof two hops share goes out once" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const nsec = "\x00\x2f\x00\x01\x00\x00\x0e\x10\x00\x04\x00\x00\x01\x40";
    const ab = "\x01a\x00" ++ nsec ++ "\x01b\x00" ++ nsec;
    const ac = "\x01a\x00" ++ nsec ++ "\x01c\x00" ++ nsec;
    const hops = [_]store.Records{
        .{ .payload = ab, .start = 0, .len = 2 },
        .{ .payload = ac, .start = 0, .len = 2 },
    };
    var out: std.ArrayList(dns.ResourceRecord) = .empty;
    var seen: Seen = .{ .bound = 4 };
    for (hops) |hop| try appendAged(a, &out, &seen, hop, .{ .section = .authority, .qtype = .a, .do_bit = true }, .{ .age = 0, .life = std.math.maxInt(u32), .floor = 0, .stale = false });
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
    noteFailure(&f, testing.allocator, q, false, failed, 5, 0);
    try testing.expectEqual(dns.Ede.Code.cached_error, heldFailure(&f, q, false, 4 * s).?.failed.code);
    try testing.expectEqual(null, heldFailure(&f, q, true, 4 * s));
    try testing.expectEqual(null, heldFailure(&f, q, false, 5 * s));
    noteFailure(&f, testing.allocator, q, false, failed, 5, 6 * s);
    noteFailure(&f, testing.allocator, q, false, failed, 5, 6 * s);
    try testing.expect(heldFailure(&f, q, false, 15 * s) != null);
    try testing.expectEqual(null, heldFailure(&f, q, false, 16 * s));
    var ok = failed;
    ok.rcode = .no_error;
    noteFailure(&f, testing.allocator, q, false, ok, 5, 17 * s);
    try testing.expectEqual(0, f.map.count());
    var held = ok;
    held.hold_until_ns = 30 * s;
    held.ede = .{ .code = .stale_answer };
    noteFailure(&f, testing.allocator, q, false, held, 5, 20 * s);
    try testing.expectEqual(Held.stale, heldFailure(&f, q, false, 29 * s).?);
    noteFailure(&f, testing.allocator, q, false, failed, 5, 31 * s);
    try testing.expect(heldFailure(&f, q, false, 35 * s) != null);
    try testing.expectEqual(null, heldFailure(&f, q, false, 36 * s));
    noteFailure(&f, testing.allocator, q, false, ok, 5, 37 * s);
    for (0..Failures.max_entries + 2) |t| {
        var other = q;
        other.qtype = @fromBackingInt(@intCast(t));
        noteFailure(&f, testing.allocator, other, false, failed, 5, 0);
    }
    try testing.expectEqual(Failures.max_entries, f.map.count());
}

test "an answer finished short of memory holds no blob" {
    const testing = std.testing;
    const Quiet = struct {
        fn send(_: *anyopaque, _: graph.Exchange) graph.Error!graph.Exposure {
            return .none;
        }
        fn wake(_: *anyopaque, _: model.CellId, _: u32, _: i64) graph.Error!void {}
    };
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    var g = try graph.Graph.init(testing.allocator, testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = @import("sys.zig").random, .sendFn = Quiet.send, .wakeFn = Quiet.wake });
    defer g.deinit();
    var d: Desk = .{ .g = &g, .retention = .{}, .dns64 = .well_known };
    defer d.deinit();
    const name: dns.Name = .lit("example");
    const q: dns.Question = .{ .name = name, .qtype = .aaaa, .qclass = .in };
    const blob = (try g.fact(.of(.rrset, name, .aaaa), .{ .rrset = .{ .kind = .nodata, .stored_ns = now, .zone = name } }, now + 60 * std.time.ns_per_s)).?;
    const a = try g.demandRoot(name, .a, .new);
    defer g.unhold(a);
    g.fail(a, .{ .name = .unreachable_authority });
    var refused: usize = 0;
    while (true) : (refused += 1) {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const served = (try fresh(&d, arena.allocator(), q, .{})).?;
        var failing: testing.FailingAllocator = .init(arena.allocator(), .{ .fail_index = refused });
        const finished = d.finish(failing.allocator(), q, .{}, served, a) catch {
            try testing.expectEqual(1, blob.refs);
            continue;
        };
        finished.release(&g.store);
        break;
    }
    try testing.expect(refused > 0);
}

test "a last-tenth hit is served from memory, asks for one refresh, and survives a full door" {
    const testing = std.testing;
    const Share = @import("share.zig");
    const Quiet = struct {
        fn send(_: *anyopaque, _: graph.Exchange) graph.Error!graph.Exposure {
            return .none;
        }
        fn wake(_: *anyopaque, _: model.CellId, _: u32, _: i64) graph.Error!void {}
    };
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    var owed: Share = .{ .limit = 8 };
    var g = try graph.Graph.init(testing.allocator, testing.allocator, .{ .root_hints = &.{}, .prefetch = true, .owed = &owed }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = @import("sys.zig").random, .sendFn = Quiet.send, .wakeFn = Quiet.wake });
    defer g.deinit();
    var d: Desk = .{ .g = &g, .retention = .{}, .dns64 = null };
    defer d.deinit();
    const s = std.time.ns_per_s;
    const a_name: dns.Name = .lit("a.example");
    const b_name: dns.Name = .lit("b.example");
    const qa: dns.Question = .{ .name = a_name, .qtype = .a, .qclass = .in };
    const qb: dns.Question = .{ .name = b_name, .qtype = .a, .qclass = .in };
    const rra = [_]dns.ResourceRecord{.fixture(.{ .name = a_name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 192, 0, 2, 1 } } })};
    const rrb = [_]dns.ResourceRecord{.fixture(.{ .name = b_name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 192, 0, 2, 2 } } })};
    _ = (try g.fact(.of(.rrset, a_name, .a), .{ .rrset = .{ .kind = .answer, .answers = &rra, .target = a_name, .zone = .root, .stored_ns = now, .ttl = 60 } }, now + 60 * s)).?;
    _ = (try g.fact(.of(.rrset, b_name, .a), .{ .rrset = .{ .kind = .answer, .answers = &rrb, .target = b_name, .zone = .root, .stored_ns = now, .ttl = 60 } }, now + 60 * s)).?;
    now += 55 * s;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    for (0..2) |_| {
        const hit = try d.early(arena.allocator(), qa, .{});
        try testing.expectEqual(.recalled, std.meta.activeTag(hit));
        hit.recalled.release(&g.store);
    }
    try testing.expectEqual(1, g.stats.resolver.early.refresh);
    try testing.expectEqual(1, g.live);
    owed.held = 7;
    try testing.expectError(error.Full, g.demandRoot(b_name, .a, .new));
    const full = try d.early(arena.allocator(), qb, .{});
    try testing.expectEqual(.recalled, std.meta.activeTag(full));
    full.recalled.release(&g.store);
    try testing.expectEqual(1, g.stats.resolver.detail.unrefreshed);
    try testing.expectEqual(1, g.live);
}
