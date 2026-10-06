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

const Graph = graph.Graph;
const CellId = graph.CellId;
const OptionalCellId = graph.OptionalCellId;
const Key = graph.Key;
const Transport = graph.Transport;
const Reply = graph.Reply;
const Failure = graph.Failure;

const max_links = graph.max_links;

const max_servers = delegation.max_servers_per_level;

const max_hedge = 3;

pub const Attempt = struct { exchange: CellId, server: u8, transport: Transport, case: graph.Case };

/// The sibling loop, hedged: the next server starts a stagger after the
/// last or when it ended; what a reply leaves in flight records on its own.
pub const Ask = struct {
    zone: dns.Name = .{ .labels = &.{} },
    /// Held: a TTL-0 delegation answers this ask once, not a re-probe per pass.
    cut: OptionalCellId = .none,
    have_servers: bool = false,
    /// Every address gathered so far; a later gather appends what is new.
    servers: [max_servers]na.AddressKey = undefined,
    nservers: u8 = 0,
    /// Bit i: `servers[i]` sent to or given up on.
    tried: u32 = 0,
    fetched_unglued: bool = false,
    /// Every server silent once: one more attempt each, at the backed-off timeout.
    retried: bool = false,
    /// In flight, oldest first.
    attempts: [max_hedge]Attempt = undefined,
    nattempts: u8 = 0,
    /// When the next attempt may start early.
    hedge_at: i64 = 0,
    /// The first failing reply: an rcode from someone, as opposed to silence.
    held: OptionalCellId = .none,
    /// The zone's DS names ML-DSA-44, whose DO answers truncate: TCP from the start.
    tcp_first: bool = false,
    /// An attempt, or a server set's sub-resolution, never left the host.
    local: bool = false,
    /// The asker's limit kept a server from being asked.
    cut_short: bool = false,
    /// The placement of the cut whose servers this ask took: a delegation
    /// they give lives no longer.
    placed_until_ns: i64 = std.math.maxInt(i64),

    comptime {
        std.debug.assert(max_servers < 32);
        // A waiting walk's scratch is a comptime constant, not a stack; the
        // server list is most of it.
        std.debug.assert(@sizeOf(Ask) <= 640);
    }

    const Result = union(enum) {
        pending,
        reply: Kept,
        /// No reply from anyone: no rcode to surface.
        exhausted,
    };

    fn bit(i: anytype) u32 {
        return @as(u32, 1) << @intCast(i);
    }

    fn knows(a: *const Ask, server: na.Address) bool {
        const key = na.AddressKey.fromAddress(server);
        for (a.servers[0..a.nservers]) |s| if (s.eql(key)) return true;
        return false;
    }

    fn end(a: *Ask, i: u8) Attempt {
        const at = a.attempts[i];
        mem.copyForwards(Attempt, a.attempts[i .. a.nattempts - 1], a.attempts[i + 1 .. a.nattempts]);
        a.nattempts -= 1;
        return at;
    }

    fn reset(a: *Ask, zone: dns.Name) void {
        a.* = .{ .zone = zone };
    }

    fn untried(a: *const Ask) u32 {
        return (bit(a.nservers) - 1) & ~a.tried;
    }

    const Pick = struct {
        server: u8,
        dead: bool,
        /// Last untried of its kind, live or dead: waits uncapped.
        last: bool,
    };

    /// Uniform within the best band. Chosen per send, so a timeout earlier
    /// in this ask already counts.
    fn pick(a: *const Ask, g: *Graph) ?Pick {
        var best: i64 = ns_rtt.dead_band;
        var ties: u32 = 0;
        var live: u8 = 0;
        var m = a.untried();
        while (m != 0) : (m &= m - 1) {
            const i = @ctz(m);
            const b = g.band(a.servers[i]);
            live += @intFromBool(b != ns_rtt.dead_band);
            if (b < best) {
                best = b;
                ties = bit(i);
            } else if (b == best) ties |= bit(i);
        }
        if (ties == 0) return null;
        const dead = best == ns_rtt.dead_band;
        // Every dead server ties in the dead band.
        const last = if (dead) @popCount(ties) == 1 else live == 1;
        var k = g.edge.rng.uintLessThan(u8, @popCount(ties));
        while (k > 0) : (k -= 1) ties &= ties - 1;
        return .{ .server = @ctz(ties), .dead = dead, .last = last };
    }

    /// The dead are hedged to only once nothing live is in flight.
    fn liveInFlight(a: *const Ask, g: *Graph) bool {
        for (a.attempts[0..a.nattempts]) |at| if (!g.isDead(a.servers[at.server])) return true;
        return false;
    }

    fn noneLive(a: *const Ask, g: *Graph) bool {
        var m = a.untried();
        while (m != 0) : (m &= m - 1) if (!g.isDead(a.servers[@ctz(m)])) return false;
        return true;
    }

    fn add(a: *Ask, g: *Graph, addrs: []const na.Address) void {
        if (a.nservers == 0) a.tcp_first = g.cfg.trust_anchor != null and zoneTruncates(g, a.zone);
        for (addrs) |s| {
            if (a.nservers == max_servers) break;
            a.servers[a.nservers] = na.AddressKey.fromAddress(s);
            a.nservers += 1;
        }
        a.have_servers = a.untried() != 0;
    }

    /// The first pass, from the cut in hand: a cut learned this instant
    /// may be one the store refused, or one that lives no time.
    fn seed(a: *Ask, g: *Graph, id: CellId, cut: graph.Cut) !void {
        var list: std.ArrayList(na.Address) = .empty;
        var left: Left = .{};
        try reach(g, id, a, a.take(cut), &list, &left);
        a.add(g, list.items);
    }

    fn take(a: *Ask, cut: graph.Cut) []const graph.Server {
        a.placed_until_ns = @min(a.placed_until_ns, cut.placed_until_ns);
        return cut.servers;
    }

    /// Once more, skipping the dead unless all are.
    fn retry(a: *Ask, g: *Graph) void {
        a.retried = true;
        g.stats.resolver.detail.retry += 1;
        a.tried = 0;
        for (a.servers[0..a.nservers], 0..) |s, i| if (g.isDead(s)) {
            a.tried |= bit(i);
        };
        if (a.tried == bit(a.nservers) - 1) a.tried = 0;
        a.have_servers = a.nservers > 0;
    }

    fn blame(a: *Ask, why: Failure) void {
        a.local = a.local or why.cause == .host;
        a.cut_short = a.cut_short or why.cause == .asker;
    }

    fn heldMsg(a: *const Ask, g: *Graph) ?dns.Message {
        return g.cell(a.held.unwrap() orelse return null).state.fact.exchange.reply.msg;
    }

    /// Every server failed: bare SERVFAIL. An authority's REFUSED or
    /// FORMERR passed through reads as hark's own policy at the stub, and
    /// the randomised server order must not change what the stub sees.
    fn giveUp(a: *Ask, g: *Graph) Result {
        std.debug.assert(a.nattempts == 0);
        var msg = a.heldMsg(g) orelse return .exhausted;
        msg.header.flags.rcode = .server_failure;
        msg.answers = &.{};
        msg.authorities = &.{};
        msg.additionals = &.{};
        return .{ .reply = .{ .msg = msg, .verdict = .none } };
    }
};

/// A reply `ask` settled on, judged against the question it asked.
const Kept = struct { msg: dns.Message, verdict: Verdict };

/// `none`: an rcode that answers nothing.
const Verdict = union(enum) { reply: Reply, loop, none };

pub const RrsetScratch = struct {
    cut: OptionalCellId = .none,
    /// A fresh DNAME above the name; only a secure one redirects from
    /// memory (Unbound's rule; dnssec/023).
    dname: OptionalCellId = .none,
    dname_judge: OptionalCellId = .none,
    dname_checked: bool = false,
    started: bool = false,
    ask: Ask = .{},
};

pub const CutScratch = struct {
    parent: OptionalCellId = .none,
    started: bool = false,
    ask: Ask = .{},
};

/// Inputs are held by id: a version that expires the moment it settles (a
/// non-authoritative denial) still answers the rule that asked for it
/// instead of being re-demanded on every wake.
pub const AddrScratch = struct {
    a: OptionalCellId = .none,
    aaaa: OptionalCellId = .none,
    judge_a: OptionalCellId = .none,
    judge_aaaa: OptionalCellId = .none,
};

pub const AnswerScratch = struct {
    /// The question's; set as the root is made, freed with it.
    budget: *graph.Budget = undefined,
    /// Every hop but the last is an alias, a link at least.
    hops: [max_links + 1]CellId = undefined,
    n: u8 = 0,
    /// `secure(hop)` per hop.
    judged: [max_links + 1]CellId = undefined,
    nj: u8 = 0,
};

// ── Rules ──────────────────────────────────────────────────────────────

/// Each CNAME owner a chain has passed, over every hop.
pub const Links = struct {
    n: u8 = 0,
    owners: [max_links]dns.Name = undefined,

    pub const loop: Failure = .{ .code = .other, .text = "cname loop" };
    pub const too_long: Failure = .{ .code = .other, .text = "alias chain too long" };

    pub const Step = union(enum) { done, next: dns.Name, broken: Failure };

    /// A CNAME a hop passes, at `owner`.
    pub fn pass(l: *Links, owner: dns.Name) ?Failure {
        if (l.left(owner)) return loop;
        if (l.n == max_links) return too_long;
        l.owners[l.n] = owner;
        l.n += 1;
        return null;
    }

    /// Where the chain goes once a hop's CNAMEs are passed. A CNAME
    /// question stops at its name.
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

/// Can a CNAME at a name answer a `qtype` question there? A CNAME is the
/// name's only data, so yes (RFC 1034 §3.6.2), except for the CNAME itself
/// and the types allowed beside it (RFC 4035 §2.5).
pub fn cnameAnswers(qtype: dns.RType) bool {
    return switch (qtype) {
        .cname, .rrsig, .nsec, .key => false,
        else => true,
    };
}

/// `answer(name, type)`: follows aliases from `name`, one hop per name as
/// `Graph.demandHop` picks, until an RRset ends the chain. Length and loop
/// checks run at demand time; a chain that fails them is a resolution
/// failure, like a failed hop.
pub fn runAnswer(g: *Graph, id: CellId) !void {
    var kb: graph.KeyBuf = undefined;
    const kind = g.cell(id).key.kind;
    const qtype = g.cell(id).key.rtype;
    const s = g.cell(id).scratch.answer;
    var next = g.cell(id).name;
    while (true) {
        if (s.n > 0) {
            const i = s.n - 1;
            const last = g.cell(s.hops[i]);
            if (!last.settled()) return;
            if (last.failure()) |why| return failAnswer(g, id, why);
            // Judged as it lands, so its zone's chain of trust overlaps the
            // rest of the walk. The RRSIGs ending an RRSIG question are
            // never signed (RFC 4035 §2.2): nothing can judge them.
            const signatures = qtype == .rrsig and last.state.fact.rrset.kind == .answer;
            if (g.cfg.trust_anchor != null and s.nj == i and !signatures) {
                s.judged[i] = try trust.demandSecure(g, id, s.hops[i]) orelse
                    return failAnswer(g, id, .unreachable_authority);
                s.nj += 1;
            }
            var links: Links = .{};
            var step: Links.Step = .done;
            for (s.hops[0..s.n]) |h| {
                const r = g.cell(h).state.fact.rrset;
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
        // The first step is at the answer's own name, keyed already.
        const own = if (s.n == 0) g.cell(id).key.at(.rrset, qtype) else Key.of(&kb, .rrset, next, qtype);
        // Nothing waits on an answer, so only an orphaned root is refused.
        s.hops[s.n] = try g.demandHop(id, own, next) orelse
            return failAnswer(g, id, .unreachable_authority);
        s.n += 1;
    }
    var expires: i64 = std.math.maxInt(i64);
    for (s.hops[0..s.n]) |h| expires = @min(expires, g.cell(h).expires_ns);
    // A verdict that failed is bogus, and lives no longer.
    for (s.judged[0..s.nj]) |j| {
        if (!g.cell(j).settled()) return;
        expires = @min(expires, g.cell(j).expires_ns);
    }
    // Nothing can judge RRSIGs, so nothing keeps them.
    if (g.awaitsVerdict(.rrset) and s.nj < s.n) expires = g.now();
    try settleAnswer(g, id, .{ .hops = s.hops[0..s.n], .judged = s.judged[0..s.nj] }, expires);
    // Best effort.
    if (kind == .answer and g.cfg.prefetch) if (lapsing(g, s.hops[0..s.n])) |end|
        g.refresh(g.cell(id).key, g.cell(id).name, end) catch {};
}

/// A refresh's inputs are its point; its own answer is nobody's.
fn settleAnswer(g: *Graph, id: CellId, a: graph.Answer, expires: i64) !void {
    if (g.cell(id).key.kind == .refresh) return g.settle(id, .refresh, g.now());
    const arena = g.cell(id).arena.allocator();
    try g.settle(id, .{ .answer = .{ .hops = try arena.dupe(CellId, a.hops), .judged = try arena.dupe(CellId, a.judged) } }, expires);
}

fn failAnswer(g: *Graph, id: CellId, why: Failure) !void {
    if (g.cell(id).key.kind == .refresh) return g.settle(id, .refresh, g.now());
    try g.fail(id, why);
}

fn lapsing(g: *Graph, hops: []const CellId) ?i64 {
    var first: ?store.Life = null;
    for (hops) |h| {
        const c = g.cell(h);
        const life: store.Life = .of(c.state.fact.rrset.stored_ns, c.expires_ns, if (c.blob) |b| b.verdict else .{});
        if (first == null or life.end_ns < first.?.end_ns) first = life;
    }
    const life = first orelse return null;
    return if (life.inLastTenth(g.now())) life.end_ns else null;
}

/// `cut(name)`: from `cut(parent(name))`, probe `name A` at the parent's
/// servers; a referral is a deeper cut, an answer or a denial puts the
/// name inside the parent's zone, silence fails, and any other reply
/// places no cut. Only strict ancestors of a question are probed; the
/// question itself goes out as `rrset`.
pub fn runCut(g: *Graph, id: CellId) !void {
    var kb: graph.KeyBuf = undefined;
    const name = g.cell(id).name;
    // The axiom, re-derived after eviction.
    if (name.labels.len == 0) return g.settle(id, .{ .cut = .{ .zone = name } }, std.math.maxInt(i64));
    // Past minimising's reach only a referral places a cut.
    if (!probeable(g, name)) return g.fail(id, unplaced);
    const parent_name: dns.Name = .{ .labels = name.labels[1..] };
    const s = g.cell(id).scratch.cut;
    if (s.parent == .none) s.parent = .wrap(try g.demand(id, Key.of(&kb, .cut, parent_name, .a), parent_name) orelse
        return g.fail(id, .unreachable_authority));
    const parent = g.cell(s.parent.unwrap().?);
    if (!parent.settled()) return;
    if (parent.failure()) |why| return g.fail(id, why);
    const pc = parent.state.fact.cut;
    // No cut below a name that does not exist (RFC 8020).
    if (try deniedAt(g, parent_name, pc.zone)) |until| return settleInside(g, id, parent, until);
    // A fresh fact at the probe name from the parent's zone answers it
    // without a packet; one from below says nothing about the parent.
    if (try g.peek(Key.of(&kb, .rrset, name, .a))) |known| if (known.value.rrset.zone.eql(pc.zone))
        return settleInside(g, id, parent, known.expires_ns);
    if (!s.started) {
        s.ask.reset(pc.zone);
        s.started = true;
    }
    switch (try ask(g, id, &g.cell(id).scratch.cut.ask, name, .a)) {
        .pending => return,
        .exhausted => try g.fail(id, ended(g, &g.cell(id).scratch.cut.ask)),
        .reply => |kept| {
            const msg = kept.msg;
            switch (delegation.probeStep(msg, name, pc.zone)) {
                .referral => |ref| {
                    const cut = try absorbReferral(g, id, ref, msg, pc.zone, g.cell(id).scratch.cut.ask.placed_until_ns);
                    try g.settle(id, cut.value, cut.expires_ns);
                },
                // Each puts the name inside the parent's zone. Only an
                // NXDOMAIN is published, as deeper cuts read it (RFC 8020).
                // An answer may be data the parent occludes (bailiwick/006);
                // a NODATA is read by nothing and would cost a judgement.
                .answered, .nodata => try settleInside(g, id, parent, switch (kept.verdict) {
                    .reply => |r| replyExpiry(r),
                    .loop, .none => g.now(),
                }),
                .nxdomain => {
                    const until = try publishNxdomain(g, id, kept, name) orelse return g.fail(id, unplaced);
                    try settleInside(g, id, parent, until);
                },
                .failed => try g.fail(id, unplaced),
            }
        },
    }
}

/// Walks below the name ask the servers of the cut above, so it lives no
/// longer than that cut, glue and all.
fn settleInside(g: *Graph, id: CellId, parent: *const graph.Cell, until_ns: i64) !void {
    try g.settle(id, .{ .cut = .{ .zone = parent.state.fact.cut.zone } }, @min(parent.expires_ns, until_ns));
}

/// An authoritative NXDOMAIN at a probe name, published; when it lapses.
fn publishNxdomain(g: *Graph, id: CellId, kept: Kept, name: dns.Name) !?i64 {
    var kb: graph.KeyBuf = undefined;
    if (!kept.msg.header.flags.aa) return null;
    const reply = switch (kept.verdict) {
        .reply => |r| r,
        .loop, .none => return null,
    };
    try g.publish(Key.of(&kb, .rrset, name, .a), name, id, .{ .rrset = reply }, replyExpiry(reply));
    return replyExpiry(reply);
}

const unplaced: Failure = .{ .code = .no_reachable_authority, .text = "no probe placed the cut", .unplaced = true };

fn probeable(g: *const Graph, name: dns.Name) bool {
    return g.cfg.qmin and name.labels.len <= delegation.max_minimize_count;
}

/// The cut a question for `qname` starts from, walking up from `from`:
/// the deepest one known, unless a strict ancestor of `qname` a probe may
/// place comes first.
fn startAt(g: *Graph, qname: dns.Name, from: dns.Name, probe: bool) dns.Name {
    var kb: graph.KeyBuf = undefined;
    var n = from;
    while (n.labels.len > 0) : (n = .{ .labels = n.labels[1..] }) {
        if (g.holds(Key.of(&kb, .cut, n, .a))) return n;
        if (probe and n.labels.len < qname.labels.len and probeable(g, n)) return n;
    }
    return n;
}

pub const Start = union(enum) { pending, none, cut: CellId, failed: Failure };

/// Waits on `startAt`'s cut, or on the deepest one known if no probe
/// could place it.
pub fn start(g: *Graph, id: CellId, qname: dns.Name, from: dns.Name, slot: *OptionalCellId) !Start {
    var kb: graph.KeyBuf = undefined;
    if (slot.* == .none) {
        const n = startAt(g, qname, from, true);
        slot.* = .wrap(try g.demand(id, Key.of(&kb, .cut, n, .a), n) orelse return .none);
    }
    while (true) {
        const c = g.cell(slot.*.unwrap().?);
        if (!c.settled()) return .pending;
        const why = c.failure() orelse return .{ .cut = slot.*.unwrap().? };
        if (!why.unplaced) return .{ .failed = why };
        const n = startAt(g, qname, from, false);
        if (n.eql(c.name)) return .{ .failed = .unreachable_authority };
        slot.* = .wrap(try g.demand(id, Key.of(&kb, .cut, n, .a), n) orelse return .none);
    }
}

/// When the closest name from `from` up to (not including) `zone` known
/// not to exist stops being known.
fn deniedAt(g: *Graph, from: dns.Name, zone: dns.Name) !?i64 {
    var kb: graph.KeyBuf = undefined;
    var n = from;
    while (n.labels.len > zone.labels.len) : (n = .{ .labels = n.labels[1..] }) {
        const f = try g.peek(Key.of(&kb, .rrset, n, .a)) orelse continue;
        const gone = f.value.rrset.nonexistent() orelse continue;
        if (gone.eql(n)) return f.expires_ns;
    }
    return null;
}

/// `addr(host)`: the host's own A and AAAA sets. An NS name must not be an
/// alias (RFC 2181 §10.3): one that is has no address.
pub fn runAddr(g: *Graph, id: CellId) !void {
    var kb: graph.KeyBuf = undefined;
    if (g.level(id) + 1 > g.cfg.max_resolve_depth) return g.fail(id, .{ .code = .no_reachable_authority, .text = "too deep" });
    const s = g.cell(id).scratch.addr;
    const host = g.cell(id).name;
    if (s.a == .none) s.a = .wrap(try g.demand(id, Key.of(&kb, .rrset, host, .a), host));
    if (s.aaaa == .none) s.aaaa = .wrap(try g.demand(id, Key.of(&kb, .rrset, host, .aaaa), host));
    var addrs: std.ArrayList(na.Address) = .empty;
    var pending = false;
    // A denial of one family does not age the other's addresses; an
    // empty set lives only as long as the shortest denial.
    var expires: i64 = std.math.maxInt(i64);
    var denied: i64 = std.math.maxInt(i64);
    var failed: ?Failure = null;
    for ([_]dns.RType{ .a, .aaaa }) |rtype| {
        // Unasked is not denied.
        const rid = (if (rtype == .a) s.a else s.aaaa).unwrap() orelse {
            failed = failed orelse .unreachable_authority;
            continue;
        };
        const c = g.cell(rid);
        if (!c.settled()) {
            pending = true;
            continue;
        }
        var n: usize = 0;
        if (c.failure()) |why| {
            failed = failed orelse why;
            continue;
        }
        const r = c.state.fact.rrset;
        if (r.kind == .answer or r.kind == .alias) {
            // A bogus answer is no address.
            if (g.cfg.trust_anchor != null) {
                const slot = if (rtype == .a) &s.judge_a else &s.judge_aaaa;
                if (slot.* == .none) slot.* = .wrap(try trust.demandSecure(g, id, rid));
                const j = g.cell(slot.*.unwrap() orelse {
                    failed = failed orelse .unreachable_authority;
                    continue;
                });
                if (!j.settled()) {
                    pending = true;
                    continue;
                }
                if (j.failure()) |why| {
                    failed = failed orelse why;
                    continue;
                }
            }
            if (r.kind == .answer) for (r.answers) |rr| {
                if (rr.rtype != rtype or !rr.name.eql(host)) continue;
                if (g.cfg.addr_policy.address(rr)) |a| {
                    try addrs.append(g.scratch.allocator(), a);
                    n += 1;
                }
            };
        }
        if (n > 0) expires = @min(expires, c.expires_ns) else denied = @min(denied, c.expires_ns);
    }
    if (pending) return;
    if (addrs.items.len == 0) {
        // Only denials and aliases make an empty set a fact.
        if (failed) |why| return g.fail(id, why);
        expires = denied;
    }
    try g.settle(id, .{ .addr = addrs.items }, expires);
}

/// `rrset(name, type)`: from the deepest known cut at or above the name,
/// ask its servers; follow referrals; settle on the first kept reply.
pub fn runRrset(g: *Graph, id: CellId) !void {
    var kb: graph.KeyBuf = undefined;
    const name = g.cell(id).name;
    const qtype = g.cell(id).key.rtype;
    const s = g.cell(id).scratch.rrset;
    if (!s.started) {
        // RFC 6672 §3.4.1: a cached DNAME answers before any cut is sought.
        if (!s.dname_checked) {
            s.dname_checked = true;
            if (try dnameAbove(g, name)) |owner| s.dname = .wrap(try g.demand(id, Key.of(&kb, .rrset, owner, .dname), owner));
            if (s.dname.unwrap()) |did| s.dname_judge = .wrap(try trust.demandSecure(g, id, did));
        }
        if (s.dname_judge.unwrap()) |jid| {
            if (!g.cell(jid).settled()) return;
            if (g.cell(jid).failure() == null and g.cell(jid).state.fact.secure.status == .secure) {
                const reply = try dnameRedirect(g, name, s.dname.unwrap().?);
                return g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
            }
        }
        // Indexed proofs deny the name without a packet.
        if (s.cut == .none and try denial.deny(g, id)) return;
        const from = proof.deepestApex(name, qtype);
        const cut = switch (try start(g, id, name, from, &s.cut)) {
            .pending => return,
            .none => return g.fail(id, .unreachable_authority),
            .failed => |why| return g.fail(id, why),
            .cut => |cid| g.cell(cid),
        };
        s.ask.reset(cut.state.fact.cut.zone);
        try s.ask.seed(g, id, cut.state.fact.cut);
        s.started = true;
    }
    while (true) {
        switch (try ask(g, id, &g.cell(id).scratch.rrset.ask, name, qtype)) {
            .pending => return,
            .exhausted => return failAsk(g, id, ended(g, &g.cell(id).scratch.rrset.ask)),
            .reply => |kept| {
                const msg = kept.msg;
                const zone = g.cell(id).scratch.rrset.ask.zone;
                if (delegation.extractReferral(msg, name, zone)) |ref| {
                    // Each referral descends toward the name, so its depth
                    // bounds the walk.
                    std.debug.assert(name.isSubdomainOf(ref.zone_cut) and ref.zone_cut.labels.len > zone.labels.len);
                    const s2 = g.cell(id).scratch.rrset;
                    const cut = try absorbReferral(g, id, ref, msg, zone, s2.ask.placed_until_ns);
                    // The parent's referral to the zone itself is its
                    // answer about the zone's DS (RFC 4035 §3.1.4.1).
                    if (qtype == .ds and ref.zone_cut.eql(name)) {
                        const reply = try trust.referralDs(g, msg, zone, name);
                        return g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
                    }
                    s2.ask.reset(ref.zone_cut);
                    try s2.ask.seed(g, id, cut.value.cut);
                    continue;
                }
                const reply = switch (kept.verdict) {
                    .reply => |r| r,
                    .loop => return failAsk(g, id, Links.loop),
                    // No useful response (RFC 9520 §2).
                    .none => return failAsk(g, id, ended(g, &g.cell(id).scratch.rrset.ask)),
                };
                try publishAlias(g, id, name, qtype, reply);
                try publishDnames(g, id, reply);
                return settleRrset(g, id, reply);
            },
        }
    }
}

/// Once every server was asked, running out is the servers' failure,
/// whatever the asker had left (RFC 9520 §3.2); else it is the asker's limit.
fn ended(g: *const Graph, a: *const Ask) Failure {
    const asked_all = a.nservers > 0 and !a.cut_short and (a.retried or a.untried() == 0);
    const zones: Failure = .{ .code = .no_reachable_authority, .cause = if (a.local) .host else .zone };
    return if (asked_all) zones else g.limit(g.payer) orelse zones;
}

fn settleRrset(g: *Graph, id: CellId, reply: Reply) !void {
    try g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
}

/// The fetch itself failed: the next asker in the window is refused
/// (RFC 9520 §3.2), unless the failure may be the asker's own: a spent
/// budget or deadline (here or in a sub-resolution), an orphan, an address
/// sub-resolution's depth, a refresh, or something that never left the host.
const failed_recently: Failure = .{ .code = .no_reachable_authority, .text = "failed recently" };

fn failAsk(g: *Graph, id: CellId, why: Failure) !void {
    const c = g.cell(id);
    if (why.cause == .zone and !c.orphan and g.payer.refresh_ns == 0 and g.level(id) == 0) try g.remember(c.key, failed_recently);
    try g.fail(id, why);
}

/// A chain starting with a CNAME at `name` is also the fact
/// `rrset(name, CNAME)`, so any later type finds the hop.
fn publishAlias(g: *Graph, by: CellId, name: dns.Name, qtype: dns.RType, reply: Reply) !void {
    var kb: graph.KeyBuf = undefined;
    if (qtype == .cname or reply.answers.len == 0) return;
    const first = reply.answers[0];
    if (first.rtype != .cname or !first.name.eql(name)) return;
    const set = dnssec.setFrom(reply.answers, 0);
    // A wildcard's expansion carries its own no-closer-match proof; the
    // reply's other proofs are other names' facts.
    const a = g.scratch.allocator();
    const kept = try a.alloc(bool, reply.authorities.len);
    @memset(kept, false);
    for (set) |sig| if (sig.rtype == .rrsig and sig.rdata.rrsig.labels < rrsig.signedLabels(name)) {
        const zone = sig.rdata.rrsig.signer_name;
        const p = proof.noCloserMatch(reply.authorities, name, sig.rdata.rrsig.labels, zone, &g.payer.validation);
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
        .target = first.rdata.cname,
        .zone = reply.zone,
        .stored_ns = reply.stored_ns,
    };
    hop.ttl = replyTtl(hop);
    try g.publish(Key.of(&kb, .rrset, name, .cname), name, by, .{ .rrset = hop }, replyExpiry(hop));
}

/// Every DNAME a reply used is the fact `rrset(owner, DNAME)`, signed,
/// so later names under it redirect from memory.
fn publishDnames(g: *Graph, by: CellId, reply: Reply) !void {
    var kb: graph.KeyBuf = undefined;
    for (reply.answers, 0..) |d, i| {
        if (d.rtype != .dname) continue;
        const dname: Reply = .{ .kind = .answer, .aa = reply.aa, .answers = dnssec.setFrom(reply.answers, i), .zone = reply.zone, .stored_ns = reply.stored_ns, .ttl = d.ttl };
        try g.publish(Key.of(&kb, .rrset, d.name, .dname), d.name, by, .{ .rrset = dname }, replyExpiry(dname));
    }
}

/// The owner of the closest DNAME fact above `name`, as `demand` would
/// hand it: the redirect never waits on a new ask nor reads a version it
/// did not judge.
fn dnameAbove(g: *Graph, name: dns.Name) !?dns.Name {
    var kb: graph.KeyBuf = undefined;
    var i: usize = 1;
    while (i < name.labels.len) : (i += 1) {
        const owner: dns.Name = .{ .labels = name.labels[i..] };
        const d = try g.held(Key.of(&kb, .rrset, owner, .dname)) orelse continue;
        if (d.value.rrset.kind == .answer and dnameAt(d.value.rrset.answers, owner) != null) return owner;
    }
    return null;
}

/// A DNAME answer reached through a CNAME may hold another name's DNAME.
fn dnameAt(answers: []const dns.ResourceRecord, owner: dns.Name) ?dns.ResourceRecord {
    for (answers) |rr| if (rr.rtype == .dname and rr.name.eql(owner)) return rr;
    return null;
}

/// The alias a DNAME fact synthesises for `name`, aged from when the
/// DNAME was taken.
fn dnameRedirect(g: *Graph, name: dns.Name, did: CellId) !Reply {
    const d = g.cell(did).state.fact.rrset;
    const dname = dnameAt(d.answers, g.cell(did).name).?;
    var keep: std.ArrayList(dns.ResourceRecord) = .empty;
    try keep.appendSlice(g.scratch.allocator(), d.answers);
    if (try dns.substituteSuffix(g.scratch.allocator(), name, dname.name, dname.rdata.dname)) |target| {
        try keep.append(g.scratch.allocator(), .{ .name = name, .rtype = .cname, .rclass = .in, .ttl = dname.ttl, .rdata = .{ .cname = target } });
        return .{ .kind = .alias, .aa = d.aa, .answers = keep.items, .target = target, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
    }
    // RFC 6672 §3.3: the substituted name is too long; YXDOMAIN.
    return .{ .kind = .yxdomain, .aa = d.aa, .answers = keep.items, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
}

/// A glued server has no other address, so the cut lives no longer than
/// its glue. Its placement never outlives the referring zone's: that is a
/// ghost (Jiang et al., NDSS 2012).
fn absorbReferral(g: *Graph, by: CellId, ref: delegation.Referral, msg: dns.Message, zone: dns.Name, zone_placed_until_ns: i64) !Graph.Fact {
    var kb: graph.KeyBuf = undefined;
    const now = g.now();
    var ns_ttl: u32 = std.math.maxInt(u32);
    for (msg.authorities) |rr| if (rr.rtype == .ns and rr.name.eql(ref.zone_cut)) {
        ns_ttl = @min(ns_ttl, rr.ttl);
    };
    const placed = @min(zone_placed_until_ns, now + @as(i64, ns_ttl) * std.time.ns_per_s);
    var expires = placed;
    const sa = g.scratch.allocator();
    const servers = try sa.alloc(graph.Server, ref.ns_count);
    for (servers, ref.nsNames()) |*server, host| {
        var key = Key.of(&kb, .addr, host, .a);
        key.name = try sa.dupe(u8, key.name);
        var glue: std.ArrayList(na.Address) = .empty;
        // Glue is the parent's word only inside its own zone.
        if (host.isSubdomainOf(zone)) for (msg.additionals) |rr| {
            if (!rr.name.eql(host)) continue;
            const addr = g.cfg.addr_policy.address(rr) orelse continue;
            try glue.append(sa, addr);
            expires = @min(expires, now + @as(i64, rr.ttl) * std.time.ns_per_s);
        };
        server.* = .{ .key = key, .glue = glue.items };
    }
    const cut: graph.Value = .{ .cut = .{ .zone = ref.zone_cut, .servers = servers, .placed_until_ns = placed } };
    try g.publish(Key.of(&kb, .cut, ref.zone_cut, .a), ref.zone_cut, by, cut, expires);
    // The parent's word on the child's DS travels with the referral.
    if (g.cfg.trust_anchor != null) {
        const ds = try trust.referralDs(g, msg, zone, ref.zone_cut);
        if (ds.ttl > 0) try g.publish(Key.of(&kb, .rrset, ref.zone_cut, .ds), ref.zone_cut, by, .{ .rrset = ds }, replyExpiry(ds));
        // A signed delegation from a zone signed all the way down: whatever
        // the walk finds below, its proof runs through these keys, so they
        // are fetched as it descends.
        if (try trust.signedDown(g, ref.zone_cut)) try g.fetchKeys(by, ref.zone_cut);
    }
    return .{ .value = cut, .expires_ns = expires };
}

/// Null when the rcode contradicts the records: bizarre contents (RFC 1034
/// §5.3.3). A referral is judged too, as the nodata it reads as; its
/// asker follows the cut and never reads the verdict.
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
        if (dname == null or rr.name.labels.len > dname.?.name.labels.len) dname = rr;
    }
    return dname;
}

/// A chain may pass one DNAME twice; its set is kept once.
fn keepDname(g: *Graph, keep: *std.ArrayList(dns.ResourceRecord), answers: []const dns.ResourceRecord, d: dns.ResourceRecord) !void {
    for (keep.items) |k| if (k.rtype == .dname and k.name.eql(d.name)) return;
    try keep.appendSlice(g.scratch.allocator(), dnssec.setAt(answers, d.name, .dname));
}

/// What a kept, non-referral reply says about (name, type). The answer
/// section is reduced to the chain from `name`: CNAMEs (and the DNAMEs
/// that synthesise them), then the asked type at the end. Anything else
/// is unsolicited (RFC 2181 §5.4.1) and dropped, NXDOMAIN included.
/// The rcode is one of the three that answer. YXDOMAIN is derived, not
/// taken: the chain must reach an in-zone DNAME whose substitution
/// overflows (RFC 6672 §2.2), and an rcode DNSSEC does not sign must
/// agree (RFC 6604 §4). Where the chain leaves the zone, the final query
/// cycle speaks for a name outside it (RFC 6604 §3): its rcode and its
/// out-of-zone records are dropped and the reply is an alias. A CNAME
/// question reads only the CNAME at its name, synthesised or not: the rest
/// and its rcode go unread. Null: bizarre.
fn classify(g: *Graph, msg: dns.Message, zone: dns.Name, name: dns.Name, qtype: dns.RType) !?Verdict {
    var keep: std.ArrayList(dns.ResourceRecord) = .empty;
    var cur = name;
    var hops: usize = 0;
    var answered = false;
    var overflow = false;
    var clipped = false;
    var seen: [max_links + 1]dns.Name = undefined;
    // A CNAME question's answer: the target of the CNAME it matched.
    var asked_alias: ?dns.Name = null;
    // What the links before `cur` kept: `keep[0..passed]`.
    var passed: usize = 0;
    // NXDOMAIN denies the end of the chain; records there are noise.
    const collect = msg.header.flags.rcode != .name_error;
    while (true) : (hops += 1) {
        for (seen[0..hops]) |n| if (n.eql(cur)) return .loop;
        seen[hops] = cur;
        passed = keep.items.len;
        // Nothing lives below a DNAME's owner (RFC 6672 §2.4): its
        // substitution is the alias, whatever the reply holds at `cur`.
        const dname = deepestDname(msg.answers, cur, zone);
        const here: []const dns.ResourceRecord = if (dname == null) msg.answers else &.{};
        // A chain back to a DNAME it passed ends at its owner, where that set
        // and its signatures are already kept (RFC 2181 §5).
        const looped = for (keep.items[0..passed]) |k| {
            if (k.rtype == .dname and k.name.eql(cur)) break true;
        } else false;
        for (here) |rr| {
            if (collect and rr.name.eql(cur) and rr.name.isSubdomainOf(zone) and rr.rtype == qtype) {
                answered = true;
                if (looped and dnssec.covers(rr) == .dname) continue;
                try keep.append(g.scratch.allocator(), rr);
                if (rr.rtype == .cname) asked_alias = rr.rdata.cname;
            }
        }
        if (answered) {
            // Asked for RRSIG, collecting already took every signature.
            if (qtype != .rrsig and keep.items.len > passed) try keepSigs(g, &keep, here, cur, qtype);
            break;
        }
        var cname: ?dns.ResourceRecord = null;
        for (here) |rr| if (rr.rtype == .cname and rr.name.eql(cur) and rr.name.isSubdomainOf(zone)) {
            cname = rr;
            break;
        };
        // Past the question's limit the rest is left unread: an alias to
        // where it stopped, so the answer finds the chain too long.
        if ((cname != null or dname != null) and hops == max_links) {
            clipped = true;
            break;
        }
        if (dname) |d| {
            try keepDname(g, &keep, msg.answers, d);
            const target = try dns.substituteSuffix(g.scratch.allocator(), cur, d.name, d.rdata.dname) orelse {
                overflow = true;
                break;
            };
            cname = .{ .name = cur, .rtype = .cname, .rclass = .in, .ttl = d.ttl, .rdata = .{ .cname = target } };
        }
        const c = cname orelse break;
        try keep.append(g.scratch.allocator(), c);
        try keepSigs(g, &keep, here, cur, .cname);
        if (qtype == .cname) {
            answered = true;
            asked_alias = c.rdata.cname;
            break;
        }
        cur = c.rdata.cname;
    }
    const yx = msg.header.flags.rcode == .yx_domain;
    const left = !overflow and !answered and hops > 0 and !cur.isSubdomainOf(zone);
    // The rcode is the unread end's.
    const unread = left or clipped or asked_alias != null;
    if (overflow != yx and !(yx and unread)) return null;
    var reply: Reply = .{
        .kind = if (overflow) .yxdomain else if (answered) .answer else if (hops > 0) .alias else .nodata,
        .aa = msg.header.flags.aa,
        .answers = keep.items,
        .additionals = if (left) try inZone(g, msg.additionals, zone) else msg.additionals,
        .target = cur,
        .zone = zone,
        .stored_ns = g.now(),
    };
    // A CNAME question is answered by the alias itself, the fact
    // `publishAlias` records for every other type.
    if (qtype == .cname) if (asked_alias) |t| {
        reply.kind = .alias;
        reply.target = t;
    };
    if (msg.header.flags.rcode == .name_error and !unread) reply.kind = .nxdomain;
    const authorities = if (left) try inZone(g, msg.authorities, zone) else msg.authorities;
    reply.authorities = try proofsNeeded(g, authorities, reply);
    reply.ttl = replyTtl(reply);
    return .{ .reply = reply };
}

/// The proof a reply owes (RFC 4035 §3.1.3): a denial's from the zone it
/// speaks for, a wildcard expansion's from the wildcard's zone. A flood is
/// kept whole for the validator to refuse.
fn proofsNeeded(g: *Graph, rrs: []const dns.ResourceRecord, reply: Reply) ![]const dns.ResourceRecord {
    const a = g.scratch.allocator();
    if (proof.proofFlood(rrs)) return rrs;
    const negative = reply.kind == .nodata or reply.kind == .nxdomain;
    const zone = if (negative) proof.denialZone(rrs, reply.target) else null;
    var signers: std.ArrayList(dns.Name) = .empty;
    if (zone) |z| try signers.append(a, z);
    for (reply.answers) |rr| if (rr.rtype == .rrsig and rr.rdata.rrsig.labels < rrsig.signedLabels(rr.name)) try signers.append(a, rr.rdata.rrsig.signer_name);
    // A denial's SOA, and the signatures over it, go out with the denial's
    // life (RFC 2308 §3), whatever TTL the server sent.
    var life: u32 = std.math.maxInt(u32);
    if (zone) |z| for (rrs) |rr| if (rr.rtype == .soa and rr.name.eql(z)) {
        life = @min(rr.ttl, rr.rdata.soa.minimum, dns.max_negative_ttl);
    };
    var keep: std.ArrayList(dns.ResourceRecord) = try .initCapacity(a, rrs.len);
    for (rrs) |rr| switch (if (rr.rtype == .rrsig) rr.rdata.rrsig.type_covered else rr.rtype) {
        .soa => if (zone) |z| if (rr.name.eql(z)) {
            var levelled = rr;
            levelled.ttl = @min(rr.ttl, life);
            keep.appendAssumeCapacity(levelled);
        },
        .nsec, .nsec3 => for (signers.items) |sn| {
            const signed = if (rr.rtype == .rrsig) rr.rdata.rrsig.signer_name.eql(sn) else dnssec.signedBy(rrs, rr.name, rr.rtype, sn);
            if (signed) {
                keep.appendAssumeCapacity(rr);
                break;
            }
        },
        else => keep.appendAssumeCapacity(rr),
    };
    return keep.items;
}

fn inZone(g: *Graph, rrs: []const dns.ResourceRecord, zone: dns.Name) ![]const dns.ResourceRecord {
    var keep: std.ArrayList(dns.ResourceRecord) = try .initCapacity(g.scratch.allocator(), rrs.len);
    for (rrs) |rr| if (rr.name.isSubdomainOf(zone)) keep.appendAssumeCapacity(rr);
    return keep.items;
}

fn keepSigs(g: *Graph, keep: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, owner: dns.Name, covered: dns.RType) !void {
    for (rrs) |rr| if (rr.rtype == .rrsig and rr.name.eql(owner) and (covered == .any or rr.rdata.rrsig.type_covered == covered)) try keep.append(g.scratch.allocator(), rr);
}

/// The answer's shortest TTL, signatures included (RFC 4034 §3), capped by
/// a wildcard expansion's proof (RFC 9077 §4.1). A denial's comes from an
/// SOA above the name denied (RFC 2308 §3); one above the zone asked (a
/// folded child's parent) counts only signed, for the validator to judge.
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
                if (!rr.name.isSubdomainOf(reply.zone) and !dnssec.signedBy(reply.authorities, rr.name, .soa, rr.name)) continue;
                ttl = @min(ttl, rr.ttl, rr.rdata.soa.minimum);
                found = true;
            };
            ttl = if (found) @min(ttl, dns.max_negative_ttl) else 0;
        },
    }
    return ttl;
}

/// A `graph.Reply` or a `store.Rrset`.
pub fn replyExpiry(reply: anytype) i64 {
    return reply.stored_ns + @as(i64, reply.ttl) * std.time.ns_per_s;
}

/// Rounded up: a TTL less its age never promises a fraction more than
/// is left.
pub fn ageOf(stored_ns: i64, now_ns: i64) u32 {
    return @intCast(@divFloor(now_ns - stored_ns + std.time.ns_per_s - 1, std.time.ns_per_s));
}

test "an age rounds up to the whole second" {
    try std.testing.expectEqual(0, ageOf(7, 7));
    try std.testing.expectEqual(1, ageOf(7, 8));
    try std.testing.expectEqual(1, ageOf(0, std.time.ns_per_s));
    try std.testing.expectEqual(2, ageOf(0, std.time.ns_per_s + 1));
}

// ── The sibling loop ───────────────────────────────────────────────

fn ask(g: *Graph, id: CellId, a: *Ask, qname: dns.Name, qtype: dns.RType) !Ask.Result {
    while (true) {
        if (!a.have_servers) switch (try gatherServers(g, id, a)) {
            .pending => return .pending,
            .none => {
                if (a.retried or a.held != .none) return a.giveUp(g);
                a.retry(g);
                continue;
            },
            .ready => {},
        };
        var i: u8 = 0;
        while (i < a.nattempts) {
            const ex = g.cell(a.attempts[i].exchange);
            if (!ex.settled()) {
                i += 1;
                continue;
            }
            const at = a.end(i);
            switch (ex.state.fact.exchange) {
                // A wait the deadline cut before the server was due asked
                // nothing of it.
                .timeout => a.cut_short = a.cut_short or (!a.retried and ex.scratch.exchange.cut_short),
                .unsent => a.local = true,
                // Over TCP a forger cannot follow, and a server that
                // normalizes case answers; a garbled datagram gets the
                // same second chance.
                .mismatch, .malformed => if (at.case == .random) {
                    _ = try sendTo(g, id, a, at.server, a.noneLive(g), .tcp, .plain, qname, qtype);
                },
                .reply => |r| {
                    if (r.msg.header.flags.tc) {
                        // TC over TCP: a broken server, as good as a timeout.
                        if (at.transport == .udp) {
                            _ = try sendTo(g, id, a, at.server, a.noneLive(g), .tcp, .random, qname, qtype);
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
        const early = g.cfg.stagger_ms > 0 and a.nattempts < max_hedge and g.now() >= a.hedge_at;
        if (a.nattempts == 0 or early) if (a.pick(g)) |p| if (a.nattempts == 0 or !p.dead or !a.liveInFlight(g)) {
            // Hark's policy, not the authorities' word: it judges sends, never facts.
            if (!g.cfg.addr_policy.allows(a.servers[p.server].toAddress())) {
                a.tried |= Ask.bit(p.server);
                continue;
            }
            const state = try sendTo(g, id, a, p.server, p.last, if (a.tcp_first) .tcp else .udp, .random, qname, qtype) orelse continue;
            a.hedge_at = g.now() + @as(i64, state.hedgeStagger() orelse g.cfg.stagger_ms) * std.time.ns_per_ms;
            if (g.cfg.stagger_ms > 0 and !p.last) try g.wake(id, a.hedge_at);
            continue;
        };
        if (a.nattempts > 0) return .pending;
        // Every known server tried: gather again for what settled since.
        a.have_servers = false;
    }
}

fn zoneTruncates(g: *Graph, zone: dns.Name) bool {
    var kb: graph.KeyBuf = undefined;
    const key = Key.of(&kb, .rrset, zone, .ds);
    const ds = (g.peek(key) catch return false) orelse return false;
    return dnssec.dsExceedsUdp(ds.value.rrset.answers);
}

/// Null: refused, so launch nothing more; what is in flight may still answer.
fn sendTo(g: *Graph, id: CellId, a: *Ask, server: u8, last: bool, transport: Transport, case: graph.Case, qname: dns.Name, qtype: dns.RType) !?ns_rtt.RttState {
    a.tried |= Ask.bit(server);
    const ex = try g.exchange(id, a.servers[server], transport, case, qname, qtype, a.nattempts == 0 and last) orelse {
        a.cut_short = a.cut_short or !a.retried;
        a.tried = Ask.bit(a.nservers) - 1;
        a.fetched_unglued = true;
        return null;
    };
    a.attempts[a.nattempts] = .{ .exchange = ex.id, .server = server, .transport = transport, .case = case };
    a.nattempts += 1;
    return ex.est;
}

fn gatherServers(g: *Graph, id: CellId, a: *Ask) !enum { pending, none, ready } {
    var kb: graph.KeyBuf = undefined;
    const sa = g.scratch.allocator();
    var list: std.ArrayList(na.Address) = .empty;
    const zone = a.zone;
    if (zone.labels.len == 0) {
        for (g.cfg.root_hints) |h| if (!a.knows(h)) try list.append(sa, h);
    } else {
        if (a.cut == .none) a.cut = .wrap(try g.demand(id, Key.of(&kb, .cut, zone, .a), zone) orelse return .none);
        const cut = g.cell(a.cut.unwrap().?);
        if (!cut.settled()) return .pending;
        if (cut.failure()) |why| {
            a.blame(why);
            return .none;
        }
        var left: Left = .{};
        // A shallower cut: no delegation here while it holds.
        if (cut.state.fact.cut.zone.eql(zone)) try reach(g, id, a, a.take(cut.state.fact.cut), &list, &left);
        var i: usize = 0;
        while (i < list.items.len) {
            if (a.knows(list.items[i])) _ = list.swapRemove(i) else i += 1;
        }
        // A sibling in progress for someone is waited for only when
        // nothing else is left, and only if it isn't waiting on us.
        if (list.items.len == 0) {
            var pending = false;
            for (left.busy.items) |key| {
                if (try g.demand(id, key, try dns.parseDottedName(sa, key.name)) != null) pending = true;
            }
            if (pending) return .pending;
        }
        const unknown = left.unknown.items;
        if (list.items.len == 0 and !a.fetched_unglued and unknown.len > 0) {
            a.fetched_unglued = true;
            const limit: usize = switch (g.level(id)) {
                0 => 3,
                1 => 2,
                else => 1,
            };
            g.edge.rng.shuffle(Key, unknown);
            var demanded = false;
            for (unknown[0..@min(limit, unknown.len)]) |key| {
                const aid = try g.demand(id, key, try dns.parseDottedName(sa, key.name)) orelse continue;
                if (!g.cell(aid).settled()) demanded = true;
            }
            if (demanded) return .pending;
            return gatherServers(g, id, a);
        }
    }
    a.add(g, list.items);
    if (a.have_servers) return .ready;
    if (g.cfg.trace) {
        var nb: [dns.max_dotted_len + 1]u8 = undefined;
        var zb: [dns.max_dotted_len + 1]u8 = undefined;
        std.debug.print("  {s} at {s}: {d} servers, none left, {s}\n", .{ g.cell(id).name.formatInto(&nb), zone.formatInto(&zb), a.nservers, if (a.held != .none) "best failure held" else "no reply at all" });
    }
    return .none;
}

const Left = struct {
    busy: std.ArrayList(Key) = .empty,
    unknown: std.ArrayList(Key) = .empty,
};

/// The referral alone decides where a server is reached: at its glue, the
/// parent's word, if it gave any, else at its own zone's `addr`. Nothing
/// else held is read, so what a glued server's zone says of it never
/// changes how it is reached.
fn reach(g: *Graph, id: CellId, a: *Ask, servers: []const graph.Server, list: *std.ArrayList(na.Address), left: *Left) !void {
    const sa = g.scratch.allocator();
    for (servers) |server| {
        if (server.glue.len > 0) {
            try list.appendSlice(sa, server.glue);
            continue;
        }
        const key = server.key;
        if (try g.held(key)) |f| {
            try list.appendSlice(sa, f.value.addr);
            continue;
        }
        if (g.index.get(key)) |aid| {
            if (g.cell(aid).settled()) {
                // Ours, settled TTL-0 or failed: a fact serves its
                // demander, a failure gives nothing.
                if (g.holdsInput(id, aid)) {
                    if (g.cell(aid).failure()) |why| a.blame(why) else try list.appendSlice(sa, g.cell(aid).state.fact.addr);
                    continue;
                }
            } else {
                try left.busy.append(sa, key);
                continue;
            }
        }
        try left.unknown.append(sa, key);
    }
}
