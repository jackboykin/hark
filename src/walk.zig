//! The delegation walk: how a cut, a host's addresses, an RRset
//! and a client's answer settle. Rules over the model in graph.zig;
//! the chain of trust is trust.zig's.
const std = @import("std");
const mem = std.mem;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const delegation = @import("delegation.zig");
const dnssec = @import("dnssec.zig");
const rrsig = @import("rrsig.zig");
const ns_rtt = @import("ns_rtt.zig");
const graph = @import("graph.zig");
const trust = @import("trust.zig");
const proof = @import("proof.zig");
const denial = @import("denial.zig");
const store = @import("store.zig");
const special_use = @import("special_use.zig");
const stub = @import("stub.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const OptionalCellId = graph.OptionalCellId;
const Key = graph.Key;
const Need = graph.Need;
const Reply = graph.Reply;
const Failure = graph.Failure;

const max_links = graph.max_links;

const max_servers = delegation.max_servers_per_level;

const max_hedge = 3;

const Attempt = struct { exchange: CellId, server: u8, need: Need, case: graph.Case };

pub const Ask = struct {
    zone: dns.Name,
    cut: OptionalCellId = .none,
    servers: [max_servers]na.AddressKey = undefined,
    nservers: u8 = 0,
    tried: u32 = 0,
    fetched_unglued: bool = false,
    more: bool = false,
    retried: bool = false,
    attempts: [max_hedge]Attempt = undefined,
    nattempts: u8 = 0,
    hedge_at: i64 = 0,
    held: OptionalCellId = .none,
    stream_first: bool = false,
    local: bool = false,
    asked_all: bool = false,
    shown: graph.Exposure = .none,
    placed_until_ns: i64 = std.math.maxInt(i64),

    comptime {
        std.debug.assert(max_servers < 32);
        std.debug.assert(@sizeOf(Ask) <= 640);
    }

    pub const Result = union(enum) {
        pending,
        reply: Kept,
        exhausted,
    };

    fn bit(i: anytype) u32 {
        return @as(u32, 1) << @intCast(i);
    }

    const Found = struct { held: u8, new: usize = 0 };

    fn gather(a: *Ask, g: *Graph) Found {
        if (a.nservers == 0) a.stream_first = g.cfg.trust_anchors != null and told(g, a.zone) == null and zoneTruncates(g, a.zone);
        return .{ .held = a.nservers };
    }

    fn hold(a: *Ask, found: *Found, x: na.AddressKey) void {
        for (a.servers[0..found.held]) |s| if (s.eql(x)) return;
        found.new += 1;
        if (a.nservers == max_servers) return;
        a.servers[a.nservers] = x;
        a.nservers += 1;
    }

    /// The send policy filters only what the DNS hands over, so the public DNS
    /// never steers an ask at the inside; told servers go through `hold` unfiltered.
    fn offer(a: *Ask, g: *Graph, found: *Found, x: na.AddressKey) void {
        if (g.cfg.addr_policy.allows(x)) a.hold(found, x);
    }

    fn end(a: *Ask, i: u8) Attempt {
        const at = a.attempts[i];
        mem.copyForwards(Attempt, a.attempts[i .. a.nattempts - 1], a.attempts[i + 1 .. a.nattempts]);
        a.nattempts -= 1;
        return at;
    }

    fn untouched(a: *const Ask) bool {
        return !a.retried and a.tried == 0;
    }

    fn untried(a: *const Ask) u32 {
        return (bit(a.nservers) - 1) & ~a.tried;
    }

    const Pick = struct {
        server: u8,
        track: ns_rtt.Track,
        last: bool,
    };

    fn pick(a: *const Ask, g: *Graph, by: Key, need: Need) !?Pick {
        var best: u64 = std.math.maxInt(u64);
        var best_track: ns_rtt.Track = .dead;
        var best_shows: graph.Exposure = .none;
        var ties: u32 = 0;
        var untimed: [@typeInfo(graph.Exposure).@"enum".field_names.len]u32 = @splat(0);
        var live: u8 = 0;
        var bits: [max_servers]u64 = undefined;
        g.noise(bits[0..a.nservers]);
        var m = a.untried();
        while (m != 0) : (m &= m - 1) {
            const i = @ctz(m);
            const e = g.estimate(a.servers[i]);
            const t = e.track;
            const quote = g.edge.quote(a.servers[i], need);
            const shows = a.shown.max(quote.exposure);
            live += @intFromBool(t != .dead);
            if (t == .untimed) untimed[@backingInt(shows)] |= bit(i);
            const soon = if (t == .timed) g.wait(e.est.?, quote.rounds, bits[i]) else unheard;
            const r = rank(t, shows, soon);
            if (r < best) {
                best = r;
                best_track = t;
                best_shows = shows;
                ties = bit(i);
            } else if (r == best) ties |= bit(i);
        }
        if (ties == 0) return null;
        // Nothing says a never-timed server is slower than the best that answer:
        // an ask's first attempt goes to it as readily, later ones do not.
        if (a.untouched()) ties |= untimed[@backingInt(best_shows)];
        const last = if (best_track == .dead) @popCount(ties) == 1 else live == 1;
        var k = try g.uniform(.pick, by, @popCount(ties));
        while (k > 0) : (k -= 1) ties &= ties - 1;
        return .{ .server = @ctz(ties), .track = best_track, .last = last };
    }

    const unheard: u64 = (1 << 60) - 1;

    /// Lower goes first. Liveness outranks exposure, so privacy never stalls an
    /// answer; exposure outranks speed, however much faster the server showing more.
    fn rank(t: ns_rtt.Track, shows: graph.Exposure, soon: u64) u64 {
        const class: u64 = switch (t) {
            .timed, .untimed => 0,
            .silent => 1,
            .dead => 2,
        };
        return class << 62 | @as(u64, @backingInt(shows)) << 60 | @min(soon, unheard);
    }

    fn flying(a: *const Ask, g: *Graph) ns_rtt.Track {
        var best: ns_rtt.Track = .dead;
        for (a.attempts[0..a.nattempts]) |at| {
            const t = g.track(a.servers[at.server]);
            if (@backingInt(t) < @backingInt(best)) best = t;
        }
        return best;
    }

    fn noneLive(a: *const Ask, g: *Graph) bool {
        var m = a.untried();
        while (m != 0) : (m &= m - 1) if (!g.isDead(a.servers[@ctz(m)])) return false;
        return true;
    }

    fn seed(a: *Ask, g: *Graph, cut: graph.Cut) void {
        var found = a.gather(g);
        a.more = reach(g, a, &found, a.take(cut));
    }

    fn take(a: *Ask, cut: graph.Cut) []const graph.Server {
        a.placed_until_ns = @min(a.placed_until_ns, cut.placed_until_ns);
        return cut.servers;
    }

    fn retry(a: *Ask, g: *Graph) void {
        a.retried = true;
        a.tried = 0;
        for (a.servers[0..a.nservers], 0..) |s, i| if (g.isDead(s)) {
            a.tried |= bit(i);
        };
        if (a.tried == bit(a.nservers) - 1) a.tried = 0;
    }

    /// Bare SERVFAIL, never the held rcode: a REFUSED or FORMERR passed through
    /// reads as hark's own policy, and server order must not change what a client sees.
    fn giveUp(a: *Ask, g: *Graph) Result {
        std.debug.assert(a.nattempts == 0);
        var msg = g.cell(a.held.unwrap() orelse return .exhausted).state.fact.exchange.reply.msg;
        msg.header.flags.rcode = .server_failure;
        msg.answers = &.{};
        msg.authorities = &.{};
        msg.additionals = &.{};
        return .{ .reply = .{ .msg = msg, .verdict = .none } };
    }
};

pub const Kept = struct { msg: dns.Message, verdict: Verdict };

const Verdict = union(enum) { reply: Reply, loop, none };

const Above = struct { fact: OptionalCellId = .none, judge: OptionalCellId = .none };

pub const RrsetScratch = struct {
    cut: OptionalCellId = .none,
    dname: Above = .{},
    denial: Above = .{},
    ask: ?Ask = null,
};

pub const CutScratch = struct {
    parent: OptionalCellId = .none,
    ask: ?Ask = null,
};

pub const AddrScratch = struct {
    rrset: OptionalCellId = .none,
    judge: OptionalCellId = .none,
};

pub const AnswerScratch = struct {
    budget: *graph.Budget = undefined,
    hops: [max_links + 1]graph.Answer.Hop = undefined,
    n: u8 = 0,
    judged: u8 = 0,
};

pub const Links = struct {
    n: u8 = 0,
    owners: [max_links]dns.Name = undefined,

    pub const loop: Failure = .{ .code = .other, .text = "cname loop" };
    pub const too_long: Failure = .{ .code = .other, .text = "alias chain too long" };

    pub const Step = union(enum) { done, next: dns.Name, broken: Failure };

    pub fn pass(l: *Links, owner: dns.Name) ?Failure {
        if (l.left(owner)) return loop;
        if (l.n == max_links) return too_long;
        l.owners[l.n] = owner;
        l.n += 1;
        return null;
    }

    pub fn end(l: *const Links, kind: Reply.Of, target: dns.Name, qtype: dns.RType) Step {
        if (kind != .alias or qtype == .cname) return .done;
        if (l.left(target)) return .{ .broken = loop };
        return .{ .next = target };
    }

    fn left(l: *const Links, name: dns.Name) bool {
        for (l.owners[0..l.n]) |o| if (o.eql(name)) return true;
        return false;
    }
};

/// A CNAME answers every type at its name but itself and those allowed beside it (RFC 4035 §2.5).
pub fn cnameAnswers(qtype: dns.RType) bool {
    return switch (qtype) {
        .cname, .rrsig, .nsec, .key => false,
        else => true,
    };
}

const into_stub: Failure = .{ .code = .no_reachable_authority, .text = "public chain into a stub zone", .cause = .host };

pub fn runAnswer(g: *Graph, id: CellId) !void {
    const kind = g.cell(id).key.kind;
    const qtype = g.cell(id).key.rtype;
    const s = g.cell(id).scratch.answer;
    var next = g.cell(id).name;
    while (true) {
        if (s.n > 0) {
            const i = s.n - 1;
            const hop = &s.hops[i];
            const last = g.cell(hop.set);
            if (!last.settled()) return;
            if (last.failure()) |why| return failAnswer(g, id, why);
            // The RRSIGs ending an RRSIG question are never signed (RFC 4035 §2.2):
            // nothing can judge them.
            const signatures = qtype == .rrsig and last.state.fact.reply().kind == .answer;
            if (s.judged == i) {
                if (g.awaitsVerdict(last.key.kind) and !signatures) hop.judge = .wrap(try trust.demandSecure(g, id, hop.set) orelse
                    return failAnswer(g, id, .unreachable_authority));
                s.judged += 1;
            }
            var links: Links = .{};
            var step: Links.Step = .done;
            for (s.hops[0..s.n]) |h| {
                const r = g.cell(h.set).state.fact.reply();
                step = for (r.answers) |rr| {
                    if (rr.rtype == .cname) if (links.pass(rr.name)) |why| break .{ .broken = why };
                } else links.end(r.kind, r.target, qtype);
                if (step != .next) break;
            }
            switch (step) {
                .done => break,
                .next => |n| next = n,
                .broken => |why| return failAnswer(g, id, why),
            }
        }
        const from: ?graph.Kind = if (s.n == 0) null else g.cell(s.hops[s.n - 1].set).key.kind;
        const hop_kind = g.hopKind(from, next, qtype) orelse return failAnswer(g, id, into_stub);
        const own = if (s.n == 0) g.cell(id).key.at(hop_kind, qtype) else Key.of(hop_kind, next, qtype);
        s.hops[s.n] = .{ .set = try g.demandHop(id, own, next) orelse
            return failAnswer(g, id, .unreachable_authority) };
        s.n += 1;
    }
    var expires: i64 = std.math.maxInt(i64);
    for (s.hops[0..s.n]) |h| {
        expires = @min(expires, g.cell(h.set).expires());
        if (h.judge.unwrap()) |j| {
            if (!g.cell(j).settled()) return;
            expires = @min(expires, g.cell(j).expires());
        } else if (g.awaitsVerdict(g.cell(h.set).key.kind)) {
            expires = @min(expires, g.now());
        }
    }
    try settleAnswer(g, id, .{ .hops = s.hops[0..s.n] }, expires);
    if (kind == .answer and g.cfg.prefetch) if (lapsing(g, s.hops[0..s.n])) |end|
        g.refresh(g.cell(id).key, g.cell(id).name, end) catch {};
}

fn settleAnswer(g: *Graph, id: CellId, a: graph.Answer, expires: i64) !void {
    if (g.cell(id).key.kind == .refresh) return g.settle(id, .refresh, g.now());
    const arena = g.cell(id).arena.allocator();
    try g.settle(id, .{ .answer = .{ .hops = try arena.dupe(graph.Answer.Hop, a.hops) } }, expires);
}

fn failAnswer(g: *Graph, id: CellId, why: Failure) !void {
    if (g.cell(id).key.kind == .refresh) return g.settle(id, .refresh, g.now());
    try g.fail(id, why);
}

fn lapsing(g: *Graph, hops: []const graph.Answer.Hop) ?i64 {
    var first: ?store.Life = null;
    for (hops) |h| {
        const c = g.cell(h.set);
        const life: store.Life = .of(c.state.fact.reply().stored_ns, c.expires(), if (c.blob) |b| b.verdict else .{});
        if (first == null or life.end_ns < first.?.end_ns) first = life;
    }
    const life = first orelse return null;
    return if (life.inLastTenth(g.now())) life.end_ns else null;
}

pub fn runCut(g: *Graph, id: CellId) !void {
    const name = g.cell(id).name;
    const parent_name = name.parent() orelse return g.settle(id, .{ .cut = .{ .zone = name } }, std.math.maxInt(i64));
    if (!probeable(g, name)) return g.fail(id, unplaced);
    const s = g.cell(id).scratch.cut;
    if (s.parent == .none) s.parent = .wrap(try g.demand(id, Key.of(.cut, parent_name, .a), parent_name) orelse
        return g.fail(id, .unreachable_authority));
    const parent = g.cell(s.parent.unwrap().?);
    if (!parent.settled()) return;
    if (parent.failure()) |why| return g.fail(id, why);
    const pc = parent.state.fact.cut;
    // No cut below a name that does not exist (RFC 8020), and none kept, or
    // every name below a denial would store one.
    if (deniedAbove(g, name, pc.zone) != null) return settleInside(g, id, parent, g.now());
    if (g.held(Key.of(.rrset, name, .a))) |known| if (named(store.Rrset.of(known).zone, pc.zone))
        return settleInside(g, id, parent, serving(g, known));
    if (s.ask == null) {
        s.ask = .{ .zone = pc.zone };
        s.ask.?.seed(g, pc);
    }
    const a = &s.ask.?;
    switch (try ask(g, id, a, name, .a)) {
        .pending => return,
        .exhausted => try g.fail(id, ended(g, a)),
        .reply => |kept| {
            const msg = kept.msg;
            switch (delegation.probeStep(msg, name, pc.zone)) {
                .referral => |ref| {
                    const cut = try absorbReferral(g, id, ref, msg, pc.zone, a.placed_until_ns);
                    try g.settle(id, cut.value, cut.expires_ns);
                },
                // Not published, unlike an NXDOMAIN: an answer may be data the parent
                // occludes, and nothing reads a NODATA.
                .answered, .nodata => try settleInside(g, id, parent, switch (kept.verdict) {
                    .reply => |r| replyExpiry(r),
                    .loop, .none => g.now(),
                }),
                .nxdomain => {
                    if (!try publishNxdomain(g, id, kept, name)) return g.fail(id, unplaced);
                    try settleInside(g, id, parent, g.now());
                },
                .failed => try g.fail(id, unplaced),
            }
        },
    }
}

fn settleInside(g: *Graph, id: CellId, parent: *const graph.Cell, until_ns: i64) !void {
    try g.settle(id, .{ .cut = .{ .zone = parent.state.fact.cut.zone } }, @min(parent.expires(), until_ns));
}

fn publishNxdomain(g: *Graph, id: CellId, kept: Kept, name: dns.Name) !bool {
    if (!kept.msg.header.flags.aa) return false;
    const reply = switch (kept.verdict) {
        .reply => |r| r,
        .loop, .none => return false,
    };
    try g.publish(Key.of(.rrset, name, .a), name, id, .{ .rrset = reply }, replyExpiry(reply));
    return true;
}

const unplaced: Failure = .{ .code = .no_reachable_authority, .text = "no probe placed the cut", .unplaced = true };

fn probeable(g: *const Graph, name: dns.Name) bool {
    return g.cfg.qmin and name.depth() <= delegation.max_minimize_count;
}

fn startAt(g: *Graph, qname: dns.Name, from: dns.Name, probe: bool) dns.Name {
    var n = from;
    while (n.parent()) |up| : (n = up) {
        if (g.holds(Key.of(.cut, n, .a))) return n;
        if (probe and n.depth() < qname.depth() and probeable(g, n)) return n;
    }
    return n;
}

const Start = union(enum) { pending, none, cut: CellId, failed: Failure };

pub fn start(g: *Graph, id: CellId, qname: dns.Name, from: dns.Name, slot: *OptionalCellId) !Start {
    if (slot.* == .none) {
        const n = startAt(g, qname, from, true);
        slot.* = .wrap(try g.demand(id, Key.of(.cut, n, .a), n) orelse return .none);
    }
    while (true) {
        const c = g.cell(slot.*.unwrap().?);
        if (!c.settled()) return .pending;
        const why = c.failure() orelse return .{ .cut = slot.*.unwrap().? };
        if (!why.unplaced) return .{ .failed = why };
        const n = startAt(g, qname, from, false);
        if (n.eql(c.name)) return .{ .failed = .unreachable_authority };
        slot.* = .wrap(try g.demand(id, Key.of(.cut, n, .a), n) orelse return .none);
    }
}

fn deniedAbove(g: *Graph, name: dns.Name, zone: dns.Name) ?struct { at: dns.Name, held: *store.Blob } {
    var up = name.parent();
    while (up) |n| : (up = n.parent()) {
        if (n.depth() <= zone.depth()) break;
        const h = g.held(Key.of(.rrset, n, .a)) orelse continue;
        const r: store.Rrset = .of(h);
        if (r.kind == .nxdomain and named(r.target, n)) return .{ .at = n, .held = h };
    }
    return null;
}

fn serving(g: *const Graph, e: *store.Blob) i64 {
    if (g.awaitsVerdict(.rrset) and !e.verdict.judged()) return g.now();
    return e.end();
}

fn named(wire: []const u8, n: dns.Name) bool {
    return dns.Name.of(wire).eql(n);
}

pub fn runAddr(g: *Graph, id: CellId) !void {
    if (g.level(id) + 1 > g.cfg.max_resolve_depth) return g.fail(id, .{ .code = .no_reachable_authority, .text = "too deep" });
    const s = g.cell(id).scratch.addr;
    const key = g.cell(id).key;
    const host = g.cell(id).name;
    if (s.rrset == .none) s.rrset = .wrap(try g.demand(id, key.at(.rrset, key.rtype), host) orelse
        return g.fail(id, .unreachable_authority));
    const rid = s.rrset.unwrap().?;
    if (!g.cell(rid).settled()) return;
    if (g.cell(rid).failure()) |why| return g.fail(id, why);
    var expires = g.cell(rid).expires();
    if (g.cfg.trust_anchors != null) {
        if (s.judge == .none) s.judge = .wrap(try trust.demandSecure(g, id, rid) orelse
            return g.fail(id, .unreachable_authority));
        const j = g.cell(s.judge.unwrap().?);
        if (!j.settled()) return;
        if (j.failure()) |why| return g.fail(id, why);
        expires = @min(expires, j.expires());
    }
    var addrs: std.ArrayList(na.AddressKey) = .empty;
    var own = ownAddresses(g, g.cell(rid).blob.?, key.rtype);
    while (own.next()) |x| try addrs.append(g.scratch.allocator(), x);
    std.debug.assert(addrs.items.len == 0 or g.cell(rid).state.fact.rrset.answers[0].name.eql(host));
    try g.settle(id, .{ .addr = try g.cell(id).arena.allocator().dupe(na.AddressKey, addrs.items) }, expires);
}

/// A stored chain is kept in the order followed, so the host's own set leads.
/// One led by anything else is another name's: an NS name must not be an alias (RFC 2181 §10.3).
fn ownAddresses(g: *const Graph, blob: *store.Blob, family: dns.RType) OwnAddresses {
    return .{ .own = store.Rrset.answered(blob), .family = family, .policy = g.cfg.addr_policy };
}

const OwnAddresses = struct {
    own: ?store.Rrset.Answered,
    family: dns.RType,
    policy: delegation.AddrPolicy,

    fn next(o: *OwnAddresses) ?na.AddressKey {
        const own = if (o.own) |*own| own else return null;
        while (own.next()) |rr| {
            if (rr.rtype == o.family) return o.policy.address(rr).?;
            if (rr.rtype != .rrsig) break;
        }
        o.own = null;
        return null;
    }
};

pub fn runRrset(g: *Graph, id: CellId) !void {
    const name = g.cell(id).name;
    const qtype = g.cell(id).key.rtype;
    const s = g.cell(id).scratch.rrset;
    if (s.ask == null) {
        if (s.cut == .none) {
            if (s.dname.fact == .none) if (dnameAbove(g, name)) |owner| try watchAbove(g, id, &s.dname, Key.of(.rrset, owner, .dname), owner);
            switch (aboveSays(g, &s.dname)) {
                .waits => return,
                .answers => {
                    const reply = try dnameRedirect(g, name, s.dname.fact.unwrap().?);
                    return g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
                },
                .silent => {},
            }
            if (try denial.deny(g, id)) return;
        }
        const from = proof.deepestApex(name, qtype);
        const cut = switch (try start(g, id, name, from, &s.cut)) {
            .pending => return,
            .none => return g.fail(id, .unreachable_authority),
            .failed => |why| return g.fail(id, why),
            .cut => |cid| g.cell(cid),
        };
        if (s.denial.fact == .none and try belowDenial(g, id, s, cut.state.fact.cut.zone)) return;
        switch (aboveSays(g, &s.denial)) {
            .waits => return,
            .answers => return g.settleAs(id, g.cell(s.denial.fact.unwrap().?).blob.?),
            .silent => {},
        }
        s.ask = .{ .zone = cut.state.fact.cut.zone };
        s.ask.?.seed(g, cut.state.fact.cut);
    }
    const a = &s.ask.?;
    while (true) {
        switch (try ask(g, id, a, name, qtype)) {
            .pending => return,
            .exhausted => return g.failRemembered(id, ended(g, a)),
            .reply => |kept| {
                const msg = kept.msg;
                const zone = a.zone;
                if (delegation.extractReferral(msg, name, zone)) |ref| {
                    std.debug.assert(name.isSubdomainOf(ref.zone_cut) and ref.zone_cut.depth() > zone.depth());
                    const cut = try absorbReferral(g, id, ref, msg, zone, a.placed_until_ns);
                    // The parent's referral to the zone is its answer about the zone's DS (RFC 4035 §3.1.4.1).
                    if (qtype == .ds and ref.zone_cut.eql(name)) {
                        const reply = try trust.referralDs(g, msg, zone, name) orelse Reply{ .kind = .nodata, .aa = true, .target = name, .zone = zone, .stored_ns = g.now() };
                        return g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
                    }
                    a.* = .{ .zone = ref.zone_cut };
                    a.seed(g, cut.value.cut);
                    continue;
                }
                const reply = switch (kept.verdict) {
                    .reply => |r| r,
                    .loop => return g.failRemembered(id, Links.loop),
                    .none => return g.failRemembered(id, ended(g, a)),
                };
                try publishAlias(g, id, name, qtype, reply);
                try publishDnames(g, id, reply);
                return g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
            },
        }
    }
}

pub fn ended(g: *const Graph, a: *const Ask) Failure {
    const zones: Failure = .{ .code = .no_reachable_authority, .cause = if (a.local) .host else .zone };
    return if (a.nservers > 0 and a.asked_all) zones else g.limit(g.payer) orelse g.payer.validationStop() orelse zones;
}

fn publishAlias(g: *Graph, by: CellId, name: dns.Name, qtype: dns.RType, reply: Reply) !void {
    if (qtype == .cname or reply.answers.len == 0) return;
    const first = reply.answers[0];
    if (first.rtype != .cname or !first.name.eql(name)) return;
    const set = dnssec.setFrom(reply.answers, 0);
    const a = g.scratch.allocator();
    const kept = try a.alloc(bool, reply.authorities.len);
    @memset(kept, false);
    for (set) |sig| if (sig.rtype == .rrsig and sig.rrsig().labels < rrsig.signedLabels(name)) {
        const zone = sig.rrsig().signer_name;
        const p = proof.noCloserMatch(reply.authorities, name, sig.rrsig().labels, zone, &g.payer.validation);
        // The budget refused a hash, so no proof was chosen: an alias without its own is no fact.
        if (p == .verdict and g.payer.validation.stopped != null) return;
        for (reply.authorities) |rr| if ((rr.rtype == .nsec or rr.rtype == .nsec3) and p.restsOn(rr, zone)) {
            for (reply.authorities, kept) |of, *k| if (of.name.eql(rr.name) and dnssec.covers(of) == rr.rtype) {
                k.* = true;
            };
        };
    };
    var proofs: std.ArrayList(dns.ResourceRecord) = .empty;
    for (reply.authorities, kept) |rr, k| if (k) try proofs.append(a, rr);
    var hop: Reply = .{
        .kind = .alias,
        .aa = reply.aa,
        .answers = set,
        .authorities = proofs.items,
        .target = first.cname(),
        .zone = reply.zone,
        .stored_ns = reply.stored_ns,
    };
    hop.ttl = replyTtl(hop);
    try g.publish(Key.of(.rrset, name, .cname), name, by, .{ .rrset = hop }, replyExpiry(hop));
}

fn publishDnames(g: *Graph, by: CellId, reply: Reply) !void {
    for (reply.answers, 0..) |d, i| {
        if (d.rtype != .dname) continue;
        const dname: Reply = .{ .kind = .answer, .aa = reply.aa, .answers = dnssec.setFrom(reply.answers, i), .zone = reply.zone, .stored_ns = reply.stored_ns, .ttl = d.ttl };
        try g.publish(Key.of(.rrset, d.name, .dname), d.name, by, .{ .rrset = dname }, replyExpiry(dname));
    }
}

fn watchAbove(g: *Graph, id: CellId, above: *Above, key: Key, at: dns.Name) !void {
    above.fact = .wrap(try g.demand(id, key, at));
    if (above.fact.unwrap()) |aid| above.judge = .wrap(try trust.demandSecure(g, id, aid));
}

fn aboveSays(g: *Graph, above: *const Above) enum { waits, answers, silent } {
    const j = g.cell(above.judge.unwrap() orelse return .silent);
    if (!j.settled()) return .waits;
    return if (j.failure() == null and j.state.fact.secure.status == .secure) .answers else .silent;
}

fn belowDenial(g: *Graph, id: CellId, s: *RrsetScratch, zone: dns.Name) !bool {
    if (!denial.denies(g, g.cell(id).key.rtype)) return false;
    const d = deniedAbove(g, g.cell(id).name, zone) orelse return false;
    if (!provable(d.held)) return false;
    if (d.held.verdict.standing(g.instant())) |v| {
        if (v.status != .secure) return false;
        try g.settleAs(id, d.held);
        return true;
    }
    try watchAbove(g, id, &s.denial, Key.of(.rrset, d.at, .a), d.at);
    return false;
}

fn provable(b: *store.Blob) bool {
    var it = store.Rrset.of(b).sections[1].iterator();
    while (it.next()) |rr| if (rr.rtype == .nsec or rr.rtype == .nsec3) return true;
    return false;
}

fn dnameAbove(g: *Graph, name: dns.Name) ?dns.Name {
    var up = name.parent();
    while (up) |owner| : (up = owner.parent()) {
        if (owner.isRoot()) break;
        const d = g.held(Key.of(.rrset, owner, .dname)) orelse continue;
        const r: store.Rrset = .of(d);
        if (r.kind != .answer) continue;
        var it = r.sections[0].iterator();
        while (it.next()) |rr| if (rr.rtype == .dname and rr.name.eql(owner)) return owner;
    }
    return null;
}

fn dnameAt(answers: []const dns.ResourceRecord, owner: dns.Name) ?dns.ResourceRecord {
    for (answers) |rr| if (rr.rtype == .dname and rr.name.eql(owner)) return rr;
    return null;
}

fn dnameRedirect(g: *Graph, name: dns.Name, did: CellId) !Reply {
    const d = g.cell(did).state.fact.rrset;
    const dname = dnameAt(d.answers, g.cell(did).name).?;
    var keep: std.ArrayList(dns.ResourceRecord) = .empty;
    try keep.appendSlice(g.scratch.allocator(), d.answers);
    if (try dns.substituteSuffix(g.scratch.allocator(), name, dname.name, dname.dname())) |target| {
        try keep.append(g.scratch.allocator(), try .init(g.scratch.allocator(), .{ .name = name, .rtype = .cname, .rclass = .in, .ttl = dname.ttl, .rdata = .{ .cname = target } }));
        return .{ .kind = .alias, .aa = d.aa, .answers = keep.items, .target = target, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
    }
    // The substituted name is too long (RFC 6672 §3.3).
    return .{ .kind = .yxdomain, .aa = d.aa, .answers = keep.items, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
}

fn absorbReferral(g: *Graph, by: CellId, ref: delegation.Referral, msg: dns.Message, zone: dns.Name, zone_placed_until_ns: i64) !Graph.Fact {
    const now = g.now();
    var ns_ttl: u32 = std.math.maxInt(u32);
    for (msg.authorities) |rr| if (rr.rtype == .ns and rr.name.eql(ref.zone_cut)) {
        ns_ttl = @min(ns_ttl, rr.ttl);
    };
    // A delegation never outlives the referring zone's own, or a revoked one
    // renews itself: a ghost domain (Jiang et al., NDSS 2012).
    const placed = @min(zone_placed_until_ns, now + @as(i64, ns_ttl) * std.time.ns_per_s);
    var expires = placed;
    const sa = g.scratch.allocator();
    const servers = try sa.alloc(graph.Server, ref.ns_count);
    for (servers, ref.ns_names[0..ref.ns_count]) |*server, host| {
        const key = Key.of(.addr, try host.clone(sa), .a);
        var glue: std.ArrayList(na.AddressKey) = .empty;
        // Glue is the parent's word only inside its own zone.
        if (speaksFor(g, zone, host)) for (msg.additionals) |rr| {
            if (!rr.name.eql(host)) continue;
            const addr = g.cfg.addr_policy.address(rr) orelse continue;
            try glue.append(sa, addr);
            expires = @min(expires, now + @as(i64, rr.ttl) * std.time.ns_per_s);
        };
        server.* = .{ .key = key, .glue = glue.items };
    }
    const cut: graph.Value = .{ .cut = .{ .zone = ref.zone_cut, .servers = servers, .placed_until_ns = placed } };
    try g.publish(Key.of(.cut, ref.zone_cut, .a), ref.zone_cut, by, cut, expires);
    if (g.cfg.trust_anchors != null) {
        if (try trust.referralDs(g, msg, zone, ref.zone_cut)) |ds| try g.publish(Key.of(.rrset, ref.zone_cut, .ds), ref.zone_cut, by, .{ .rrset = ds }, replyExpiry(ds));
        if (try trust.signedDown(g, ref.zone_cut)) try g.fetchKeys(ref.zone_cut);
    }
    return .{ .value = cut, .expires_ns = expires };
}

fn judge(g: *Graph, msg: dns.Message, zone: dns.Name, name: dns.Name, qtype: dns.RType) !?Kept {
    return .{ .msg = msg, .verdict = switch (msg.header.flags.rcode) {
        .no_error, .name_error, .yx_domain => try classify(g, msg, zone, name, qtype) orelse return null,
        else => .none,
    } };
}

fn deepestDname(answers: []const dns.ResourceRecord, cur: dns.Name, zone: dns.Name) ?dns.ResourceRecord {
    var dname: ?dns.ResourceRecord = null;
    for (answers) |rr| {
        if (rr.rtype != .dname or !cur.isSubdomainOf(rr.name) or cur.eql(rr.name) or !rr.name.isSubdomainOf(zone)) continue;
        if (dname == null or rr.name.depth() > dname.?.name.depth()) dname = rr;
    }
    return dname;
}

fn keepDname(g: *Graph, keep: *std.ArrayList(dns.ResourceRecord), answers: []const dns.ResourceRecord, d: dns.ResourceRecord) !void {
    for (keep.items) |k| if (k.rtype == .dname and k.name.eql(d.name)) return;
    try keep.appendSlice(g.scratch.allocator(), dnssec.setAt(answers, d.name, .dname));
}

fn classify(g: *Graph, msg: dns.Message, zone: dns.Name, name: dns.Name, qtype: dns.RType) !?Verdict {
    var keep: std.ArrayList(dns.ResourceRecord) = .empty;
    var cur = name;
    var hops: usize = 0;
    var seen: [max_links + 1]dns.Name = undefined;
    var asked_alias: ?dns.Name = null;
    var passed: usize = 0;
    const denied = msg.header.flags.rcode == .name_error;
    const end: enum { answered, asked_alias, overflow, clipped, left, dead_end } = chain: while (true) : (hops += 1) {
        if (hops > 0 and !speaksFor(g, zone, cur)) break :chain .left;
        for (seen[0..hops]) |n| if (n.eql(cur)) return .loop;
        seen[hops] = cur;
        passed = keep.items.len;
        // Nothing lives below a DNAME's owner (RFC 6672 §2.4): its substitution
        // is the alias, whatever the reply holds at `cur`.
        const dname = deepestDname(msg.answers, cur, zone);
        const here: []const dns.ResourceRecord = if (dname == null) msg.answers else &.{};
        const looped = for (keep.items[0..passed]) |k| {
            if (k.rtype == .dname and k.name.eql(cur)) break true;
        } else false;
        var answered = false;
        for (here) |rr| {
            if (!denied and rr.name.eql(cur) and rr.name.isSubdomainOf(zone) and rr.rtype == qtype) {
                answered = true;
                if (looped and dnssec.covers(rr) == .dname) continue;
                try keep.append(g.scratch.allocator(), rr);
                if (rr.rtype == .cname) asked_alias = rr.cname();
            }
        }
        if (answered) {
            if (qtype != .rrsig and keep.items.len > passed) try keepSigs(g, &keep, here, cur, qtype);
            break :chain if (asked_alias != null) .asked_alias else .answered;
        }
        var cname: ?dns.ResourceRecord = null;
        for (here) |rr| if (rr.rtype == .cname and rr.name.eql(cur) and rr.name.isSubdomainOf(zone)) {
            cname = rr;
            break;
        };
        if ((cname != null or dname != null) and hops == max_links) break :chain .clipped;
        if (dname) |d| {
            try keepDname(g, &keep, msg.answers, d);
            const target = try dns.substituteSuffix(g.scratch.allocator(), cur, d.name, d.dname()) orelse break :chain .overflow;
            cname = try .init(g.scratch.allocator(), .{ .name = cur, .rtype = .cname, .rclass = .in, .ttl = d.ttl, .rdata = .{ .cname = target } });
        }
        const c = cname orelse break :chain .dead_end;
        try keep.append(g.scratch.allocator(), c);
        try keepSigs(g, &keep, here, cur, .cname);
        if (qtype == .cname) {
            asked_alias = c.cname();
            break :chain .asked_alias;
        }
        cur = c.cname();
    };
    const yx = msg.header.flags.rcode == .yx_domain;
    // YXDOMAIN is derived from an overflowing substitution and must match the rcode
    // (RFC 6604 §4). Where the chain leaves the zone the rcode speaks for a name outside it (§3).
    const kind: Reply.Of = switch (end) {
        .left, .clipped, .asked_alias => .alias,
        .overflow => if (yx) .yxdomain else return null,
        .answered => if (yx) return null else .answer,
        .dead_end => if (yx) return null else if (denied) .nxdomain else if (hops > 0) .alias else .nodata,
    };
    var reply: Reply = .{
        .kind = kind,
        .aa = msg.header.flags.aa,
        .answers = keep.items,
        .target = asked_alias orelse cur,
        .zone = zone,
        .stored_ns = g.now(),
    };
    switch (reply.kind) {
        .nxdomain => if (!delegation.soaAbove(msg.authorities, cur)) return null,
        .nodata => if (!delegation.soaAbove(msg.authorities, cur) and delegation.extractReferral(msg, name, zone) == null) return null,
        .answer, .alias, .yxdomain => {},
    }
    // Only an answer to NS keeps the other authority and additional records. No client
    // is sent the rest: NS in authority invites section confusion (CVE-2025-11411).
    const rest = reply.kind == .answer and qtype == .ns;
    if (rest) reply.additionals = msg.additionals;
    const authorities = if (end == .left) try inZone(g, msg.authorities, zone) else msg.authorities;
    reply.authorities = try proofsNeeded(g, authorities, reply, rest);
    reply.ttl = replyTtl(reply);
    return .{ .reply = reply };
}

fn proofsNeeded(g: *Graph, rrs: []const dns.ResourceRecord, reply: Reply, rest: bool) ![]const dns.ResourceRecord {
    const a = g.scratch.allocator();
    // A flood's proofs are kept whole on purpose, for the validator to refuse.
    const flood = proof.proofFlood(rrs);
    const negative = reply.kind == .nodata or reply.kind == .nxdomain;
    const zone = if (negative) proof.denialZone(rrs, reply.target) else null;
    var signers: std.ArrayList(dns.Name) = .empty;
    if (zone) |z| try signers.append(a, z);
    for (reply.answers) |rr| if (rr.rtype == .rrsig and rr.rrsig().labels < rrsig.signedLabels(rr.name)) try signers.append(a, rr.rrsig().signer_name);
    var life: u32 = std.math.maxInt(u32);
    if (zone) |z| for (rrs) |rr| if (rr.rtype == .soa and rr.name.eql(z)) {
        life = @min(rr.ttl, rr.soa().minimum, dns.max_negative_ttl);
    };
    var keep: std.ArrayList(dns.ResourceRecord) = try .initCapacity(a, rrs.len);
    for (rrs) |rr| switch (dnssec.covers(rr)) {
        .soa => if (zone) |z| if (rr.name.eql(z)) {
            var levelled = rr;
            levelled.ttl = @min(rr.ttl, life);
            keep.appendAssumeCapacity(levelled);
        },
        .nsec, .nsec3 => if (flood) keep.appendAssumeCapacity(rr) else for (signers.items) |sn| {
            const signed = if (rr.rtype == .rrsig) rr.rrsig().signer_name.eql(sn) else dnssec.signedBy(rrs, rr.name, rr.rtype, sn);
            if (signed) {
                keep.appendAssumeCapacity(rr);
                break;
            }
        },
        else => if (rest) keep.appendAssumeCapacity(rr),
    };
    return keep.items;
}

fn inZone(g: *Graph, rrs: []const dns.ResourceRecord, zone: dns.Name) ![]const dns.ResourceRecord {
    var keep: std.ArrayList(dns.ResourceRecord) = try .initCapacity(g.scratch.allocator(), rrs.len);
    for (rrs) |rr| if (speaksFor(g, zone, rr.name)) keep.appendAssumeCapacity(rr);
    return keep.items;
}

fn speaksFor(g: *const Graph, zone: dns.Name, name: dns.Name) bool {
    const zones = g.cfg.stub_zones;
    return name.isSubdomainOf(zone) and stub.under(zones, name) == stub.under(zones, zone);
}

fn keepSigs(g: *Graph, keep: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, owner: dns.Name, covered: dns.RType) !void {
    for (rrs) |rr| if (rr.rtype == .rrsig and rr.name.eql(owner) and (covered == .any or rr.rrsig().type_covered == covered)) try keep.append(g.scratch.allocator(), rr);
}

pub fn replyTtl(reply: Reply) u32 {
    var ttl: u32 = std.math.maxInt(u32);
    for (reply.answers) |rr| ttl = @min(ttl, rr.ttl);
    switch (reply.kind) {
        .answer, .alias, .yxdomain => for (reply.authorities) |rr| if (rr.rtype == .nsec or rr.rtype == .nsec3) {
            ttl = @min(ttl, rr.ttl);
        },
        .nodata, .nxdomain => {
            var found = false;
            if (reply.aa) for (reply.authorities) |rr| {
                if (rr.rtype != .soa or !reply.target.isSubdomainOf(rr.name)) continue;
                // An SOA above the zone asked counts only signed, for the validator to judge.
                if (!rr.name.isSubdomainOf(reply.zone) and !dnssec.signedBy(reply.authorities, rr.name, .soa, rr.name)) continue;
                ttl = @min(ttl, rr.ttl, rr.soa().minimum);
                found = true;
            };
            ttl = if (found) @min(ttl, dns.max_negative_ttl) else 0;
        },
    }
    return ttl;
}

pub fn replyExpiry(reply: anytype) i64 {
    return reply.stored_ns + @as(i64, reply.ttl) * std.time.ns_per_s;
}

pub fn ageOf(stored_ns: i64, now_ns: i64) u32 {
    return @intCast(@divFloor(now_ns - stored_ns + std.time.ns_per_s - 1, std.time.ns_per_s));
}

test "an age rounds up to the whole second" {
    try std.testing.expectEqual(0, ageOf(7, 7));
    try std.testing.expectEqual(1, ageOf(7, 8));
    try std.testing.expectEqual(1, ageOf(0, std.time.ns_per_s));
    try std.testing.expectEqual(2, ageOf(0, std.time.ns_per_s + 1));
}

test "a send that shows less goes first, however slower, until the ask has shown more" {
    const testing = std.testing;
    const World = struct {
        now: i64 = std.time.ns_per_s,
        wall: i64 = 0,
        sealed: na.AddressKey,

        fn send(_: *anyopaque, _: graph.Exchange) anyerror!graph.Exposure {
            return .none;
        }
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
        fn quote(ctx: *anyopaque, server: na.AddressKey, need: Need) graph.Quote {
            const w: *@This() = @ptrCast(@alignCast(ctx));
            if (!w.sealed.eql(server)) return .{ .rounds = need.plainRounds(), .exposure = .cleartext };
            return .{ .rounds = 3, .exposure = .encrypted };
        }
    };
    const near: na.AddressKey = .fromAddress(na.initIp4(.{ 192, 0, 2, 1 }, 53));
    const far: na.AddressKey = .fromAddress(na.initIp4(.{ 192, 0, 2, 2 }, 53));
    var w: World = .{ .sealed = far };
    var g = try Graph.init(testing.allocator, testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = &w, .now_ns = &w.now, .wall_sec = &w.wall, .rng = @import("rand.zig").thread, .sendFn = World.send, .wakeFn = World.wake, .quoteFn = World.quote });
    defer g.deinit();
    g.rtt.write(near, 1000).observe(10 * std.time.us_per_ms, 1000);
    g.rtt.write(far, 1000).observe(300 * std.time.us_per_ms, 1000);
    var a: Ask = .{ .zone = .root };
    a.servers[0] = near;
    a.servers[1] = far;
    a.nservers = 2;
    const by: Key = .of(.rrset, .root, .ns);
    try testing.expectEqual(1, (try a.pick(&g, by, .datagram)).?.server);
    a.shown = .cleartext;
    try testing.expectEqual(0, (try a.pick(&g, by, .datagram)).?.server);
}

pub fn ask(g: *Graph, id: CellId, a: *Ask, qname: dns.Name, qtype: dns.RType) !Ask.Result {
    if (a.untouched() and !mayHear(g, a.zone, qname, qtype)) {
        a.local = true;
        return .exhausted;
    }
    var refused = false;
    while (true) {
        var i: u8 = 0;
        while (i < a.nattempts) {
            const ex = g.cell(a.attempts[i].exchange);
            if (!ex.settled()) {
                i += 1;
                continue;
            }
            const at = a.end(i);
            switch (ex.state.fact.exchange) {
                // The deadline cut the wait before the server was due: it was asked
                // nothing, and may be tried again.
                .timeout => if (ex.scratch.exchange.cut_short) {
                    a.tried &= ~Ask.bit(at.server);
                },
                .unsent => a.local = true,
                .moved => if (try sendTo(g, id, a, at.server, a.noneLive(g), at.need, at.case, qname, qtype) == null) {
                    refused = true;
                },
                // The server's breach: no stream retry, only a sibling.
                .oversized => {},
                // Once more over a stream with plain case: a forger cannot follow there,
                // and a server that normalises 0x20 case answers.
                .mismatch, .malformed => if (at.case == .random) {
                    if (try sendTo(g, id, a, at.server, a.noneLive(g), .stream, .plain, qname, qtype) == null) refused = true;
                },
                .reply => |r| {
                    if (r.msg.header.flags.tc) {
                        // TC over a stream is a broken server, as good as a timeout.
                        if (!r.stream) {
                            if (try sendTo(g, id, a, at.server, a.noneLive(g), .stream, .random, qname, qtype) == null) refused = true;
                        }
                    } else {
                        const kept = if (delegation.shouldTrySibling(r.msg, a.zone)) null else try judge(g, r.msg, a.zone, qname, qtype);
                        if (kept) |k| {
                            a.nattempts = 0;
                            return .{ .reply = k };
                        }
                        if (a.held == .none) a.held = .wrap(at.exchange);
                    }
                },
            }
        }
        if (refused) return if (a.nattempts > 0) .pending else a.giveUp(g);
        if (a.nattempts > 0 and (g.cfg.stagger_ms == 0 or a.nattempts == max_hedge)) return .pending;
        const due = a.nattempts == 0 or g.now() >= a.hedge_at;
        const waited = a.flying(g);
        if (!due and waited.mayAnswer()) return .pending;
        const need: Need = if (a.stream_first) .stream else .datagram;
        const p = try a.pick(g, g.cell(id).key, need) orelse {
            switch (try gatherServers(g, id, a)) {
                .ready => continue,
                .pending => return .pending,
                .none, .stopped => |left| {
                    if (a.nattempts > 0) return .pending;
                    a.asked_all = a.asked_all or left == .none;
                    if (a.retried or a.held != .none) return a.giveUp(g);
                    a.retry(g);
                    continue;
                },
            }
        };
        if (!due and !p.track.mayAnswer()) return .pending;
        if (p.track == .dead and waited != .dead) return .pending;
        const last = p.last and !a.more;
        const sent = try sendTo(g, id, a, p.server, last, need, .random, qname, qtype) orelse {
            refused = true;
            continue;
        };
        if (a.retried) g.stats.resolver.detail.retry += 1;
        const stagger = try g.stretch(.stagger, g.cell(id).key, g.holdMs(sent.est, sent.rounds));
        a.hedge_at = g.now() + @as(i64, stagger) * std.time.ns_per_ms;
        if (g.cfg.stagger_ms > 0 and !last) try g.wake(id, a.hedge_at);
        if (p.track.mayAnswer()) return .pending;
    }
}

fn told(g: *const Graph, zone: dns.Name) ?[]const na.Address {
    if (zone.isRoot()) return g.cfg.root_hints;
    const z = stub.under(g.cfg.stub_zones, zone) orelse return null;
    return if (z.apex.depth() == zone.depth()) z.servers else null;
}

fn mayHear(g: *const Graph, zone: dns.Name, qname: dns.Name, qtype: dns.RType) bool {
    const zones = g.cfg.stub_zones;
    const own = stub.of(zones, qname, qtype);
    if (own != stub.under(zones, zone)) return false;
    // A question hark answers itself never leaves the host (RFC 6761 §6). An own
    // zone's DS gets here only for a DO client, so it is classified as one.
    return own != null or special_use.classify(qname, qtype, true) == null;
}

fn zoneTruncates(g: *Graph, zone: dns.Name) bool {
    const key = Key.of(.rrset, zone, .ds);
    const ds = (g.peek(key) catch return false) orelse return false;
    return dnssec.dsExceedsUdp(ds.value.rrset.answers);
}

fn sendTo(g: *Graph, id: CellId, a: *Ask, server: u8, last: bool, need: Need, case: graph.Case, qname: dns.Name, qtype: dns.RType) !?Graph.Sent {
    const ex = try g.exchange(id, a.servers[server], need, case, qname, qtype, a.nattempts == 0 and last) orelse return null;
    a.tried |= Ask.bit(server);
    a.shown = a.shown.max(ex.exposure);
    a.attempts[a.nattempts] = .{ .exchange = ex.id, .server = server, .need = need, .case = case };
    a.nattempts += 1;
    return ex;
}

fn gatherServers(g: *Graph, id: CellId, a: *Ask) !enum { pending, none, stopped, ready } {
    var found = a.gather(g);
    const zone = a.zone;
    var left: Left = .{};
    if (told(g, zone)) |servers| {
        for (servers) |h| a.hold(&found, .fromAddress(h));
    } else {
        if (a.cut == .none) a.cut = .wrap(try g.demand(id, Key.of(.cut, zone, .a), zone) orelse return .none);
        const cut = g.cell(a.cut.unwrap().?);
        if (!cut.settled()) return .pending;
        if (cut.failure()) |why| switch (why.cause) {
            .zone => return .none,
            .host => {
                a.local = true;
                return .none;
            },
            .asker => {
                if (g.spent(g.payer)) return .stopped;
                a.cut = .none;
                return gatherServers(g, id, a);
            },
        };
        const servers: []const graph.Server = if (cut.state.fact.cut.zone.eql(zone)) a.take(cut.state.fact.cut) else &.{};
        const partial = reach(g, a, &found, servers);
        if (found.new == 0 or a.fetched_unglued) try learn(g, id, a, &found, servers, &left);
        a.more = if (a.fetched_unglued) left.awaited else partial;
        if (found.new == 0) {
            var pending = false;
            for (left.busy.items) |key| {
                if (try g.demand(id, key, .of(key.name)) != null) pending = true;
            }
            a.more = a.more or pending;
            if (pending) return .pending;
        }
        const unknown = left.unknown.items;
        if (found.new == 0 and !a.fetched_unglued and unknown.len > 0) {
            a.fetched_unglued = true;
            const limit: usize = switch (g.level(id)) {
                0 => 3,
                1 => 2,
                else => 1,
            };
            try g.shuffle(.gather, g.cell(id).key, Left.Unknown, unknown);
            var demanded = false;
            for (unknown[0..@min(limit, unknown.len)]) |u| {
                const host: dns.Name = .of(u.host.name);
                for (families, u.families) |family, wanted| {
                    if (!wanted) continue;
                    const aid = try g.demand(id, u.host.at(.addr, family), host) orelse continue;
                    if (!g.cell(aid).settled()) demanded = true;
                }
            }
            a.more = demanded;
            if (demanded) return .pending;
            return gatherServers(g, id, a);
        }
    }
    if (a.untried() != 0) return .ready;
    if (g.cfg.trace) {
        var nb: [dns.max_dotted_len + 1]u8 = undefined;
        var zb: [dns.max_dotted_len + 1]u8 = undefined;
        std.debug.print("  {s} at {s}: {d} servers, none left, {s}\n", .{ g.cell(id).name.formatInto(&nb), zone.formatInto(&zb), a.nservers, if (a.held != .none) "best failure held" else "no reply at all" });
    }
    return if (left.stopped) .stopped else .none;
}

const families = [_]dns.RType{ .a, .aaaa };

const Left = struct {
    busy: std.ArrayList(Key) = .empty,
    awaited: bool = false,
    unknown: std.ArrayList(Unknown) = .empty,
    stopped: bool = false,

    const Unknown = struct { host: Key, families: [families.len]bool };
};

/// A glued server is reached at its glue alone: what its own zone says of it
/// never changes how it is reached.
fn reach(g: *Graph, a: *Ask, found: *Ask.Found, servers: []const graph.Server) bool {
    var partial = false;
    for (servers) |server| {
        if (server.glue.len > 0) {
            for (server.glue) |x| a.offer(g, found, x);
            continue;
        }
        for (families) |family| {
            const blob = g.proven(server.key.at(.rrset, family)) orelse {
                partial = true;
                continue;
            };
            var own = ownAddresses(g, blob, family);
            while (own.next()) |x| a.offer(g, found, x);
        }
    }
    return partial;
}

fn learn(g: *Graph, id: CellId, a: *Ask, found: *Ask.Found, servers: []const graph.Server, left: *Left) !void {
    const sa = g.scratch.allocator();
    for (servers) |server| {
        if (server.glue.len > 0) continue;
        var unknown: [families.len]bool = @splat(false);
        for (families, &unknown) |family, *u| {
            if (g.proven(server.key.at(.rrset, family)) != null) continue;
            const key = server.key.at(.addr, family);
            if (g.indexed(key)) |aid| {
                const c = g.cell(aid);
                if (!c.settled()) {
                    left.awaited = left.awaited or g.holdsInput(id, aid);
                    try left.busy.append(sa, key);
                    continue;
                }
                if (g.holdsInput(id, aid)) {
                    const why = c.failure() orelse {
                        for (c.state.fact.addr) |x| a.offer(g, found, x);
                        continue;
                    };
                    switch (why.cause) {
                        .zone => {},
                        .host => a.local = true,
                        .asker => if (g.spent(g.payer)) {
                            left.stopped = true;
                        } else {
                            left.awaited = true;
                            try left.busy.append(sa, key);
                        },
                    }
                    continue;
                }
            }
            u.* = true;
        }
        if (mem.findScalar(bool, &unknown, true) != null) try left.unknown.append(sa, .{ .host = server.key, .families = unknown });
    }
}
