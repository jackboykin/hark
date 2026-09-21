//! The delegation walk: how a cut, an NS set, a host's addresses, an
//! RRset and a client's answer settle. Rules over the model in graph.zig;
//! the chain of trust is trust.zig's.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const delegation = @import("delegation.zig");
const dnssec = @import("dnssec.zig");
const ns_rtt = @import("ns_rtt.zig");
const graph = @import("graph.zig");
const trust = @import("trust.zig");
const denial = @import("denial.zig");
const store = @import("store.zig");

const Graph = graph.Graph;
const CellId = graph.CellId;
const Key = graph.Key;
const Transport = graph.Transport;
const Reply = graph.Reply;
const Failure = graph.Failure;

/// Nobody answered usefully, or the walk to them was refused.
const unreachable_authority: Failure = .{ .code = .no_reachable_authority };

const max_cname_chain = graph.max_cname_chain;

const max_servers = delegation.max_servers_per_level;

const max_hedge = 3;

/// BIND's `prefetch 2 9`, the 9: or steering zones double.
pub const refresh_floor_s = 9;

pub const Attempt = struct { exchange: CellId, server: u8, transport: Transport };

/// The sibling loop, hedged: the next server starts a stagger after the
/// last or when it ended; what a reply leaves in flight records on its own.
pub const Ask = struct {
    zone: dns.Name = .{ .labels = &.{} },
    /// `ns(zone)`, held: a TTL-0 set answers this ask once, not a re-probe per pass.
    ns: ?CellId = null,
    have_servers: bool = false,
    /// Every address gathered so far; a later gather appends what is new.
    servers: [max_servers]na.AddressKey = undefined,
    nservers: u8 = 0,
    next: u8 = 0,
    /// Bit i: `servers[i]` has been sent to.
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
    held: ?CellId = null,
    /// The zone's DS names ML-DSA-44, whose DO answers truncate: TCP from the start.
    tcp_first: bool = false,

    comptime {
        std.debug.assert(max_servers < 32);
    }

    const Result = union(enum) {
        pending,
        reply: dns.Message,
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

    /// Appends, shuffled. Dead servers are skipped unless nothing else is left.
    fn add(a: *Ask, g: *Graph, addrs: []const na.Address) void {
        var live: usize = 0;
        for (addrs) |s| live += @intFromBool(!g.isDead(s));
        const from = a.nservers;
        if (from == 0) a.tcp_first = g.cfg.trust_anchor != null and zoneTruncates(g, a.zone);
        for (addrs) |s| {
            if (a.nservers == max_servers) break;
            if (live > 0 and g.isDead(s)) continue;
            a.servers[a.nservers] = na.AddressKey.fromAddress(s);
            a.nservers += 1;
        }
        g.edge.rng.shuffle(na.AddressKey, a.servers[from..a.nservers]);
        // Fastest band first, random within it; a server never timed sorts as fast.
        std.sort.insertion(na.AddressKey, a.servers[from..a.nservers], g, rttBand);
        a.have_servers = a.next < a.nservers;
    }

    fn rttBand(g: *Graph, x: na.AddressKey, y: na.AddressKey) bool {
        const band_us = 50 * std.time.us_per_ms;
        const bx = @divTrunc((g.rtt.get(x) orelse ns_rtt.RttState.unknown).srtt_us, band_us);
        const by = @divTrunc((g.rtt.get(y) orelse ns_rtt.RttState.unknown).srtt_us, band_us);
        return bx < by;
    }

    /// Once more from the top in a fresh order, skipping the dead unless all are.
    fn retry(a: *Ask, g: *Graph) void {
        a.retried = true;
        g.stats.resolver.retry += 1;
        g.edge.rng.shuffle(na.AddressKey, a.servers[0..a.nservers]);
        a.tried = 0;
        for (a.servers[0..a.nservers], 0..) |s, i| if (g.isDead(s.toAddress())) {
            a.tried |= bit(i);
        };
        if (a.tried == bit(a.nservers) - 1) a.tried = 0;
        a.next = 0;
        a.have_servers = a.nservers > 0;
    }

    fn heldMsg(a: *const Ask, g: *Graph) ?dns.Message {
        return g.cell(a.held orelse return null).state.fact.exchange.reply.msg;
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
        return .{ .reply = msg };
    }
};

pub const RrsetScratch = struct {
    cut: ?CellId = null,
    /// A fresh DNAME above the name; only a secure one redirects from
    /// memory (Unbound's rule; dnssec/023).
    dname: ?CellId = null,
    dname_judge: ?CellId = null,
    dname_checked: bool = false,
    started: bool = false,
    ask: Ask = .{},
    delegations: u8 = 0,
};

pub const CutScratch = struct {
    parent: ?CellId = null,
    started: bool = false,
    ask: Ask = .{},
};

/// Inputs are held by id: a version that expires the moment it settles (a
/// non-authoritative denial) still answers the rule that asked for it
/// instead of being re-demanded on every wake.
pub const AddrScratch = struct {
    /// The NS name, or the target of its one allowed CNAME hop.
    host: ?dns.Name = null,
    hopped: bool = false,
    a: ?CellId = null,
    aaaa: ?CellId = null,
    judge_a: ?CellId = null,
    judge_aaaa: ?CellId = null,
};

pub const NsScratch = struct {
    cut: ?CellId = null,
};

pub const AnswerScratch = struct {
    /// The question's; set as the root is made, freed with it.
    budget: *graph.Budget = undefined,
    hops: [max_cname_chain + 1]CellId = undefined,
    n: u8 = 0,
    /// `secure(hop)` per hop.
    judged: [max_cname_chain + 1]CellId = undefined,
    nj: u8 = 0,
};

// ── Rules ──────────────────────────────────────────────────────────────

/// `answer(name, type)`: `rrset(name, type)`, then each alias's target
/// until an RRset ends the chain. Length and loop checks run at demand
/// time; a chain that fails them is a resolution failure, like a failed hop.
pub fn runAnswer(g: *Graph, id: CellId) !void {
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
            // rest of the walk.
            if (g.cfg.trust_anchor != null and s.nj == i) {
                s.judged[i] = try trust.demandSecure(g, id, s.hops[i]);
                s.nj += 1;
            }
            const r = last.state.fact.rrset;
            if (r.kind != .alias or qtype == .cname) break;
            next = r.target;
            var broken = s.n > max_cname_chain;
            for (s.hops[0..s.n]) |h| broken = broken or g.cell(h).name.eql(next);
            if (broken) return failAnswer(g, id, .{ .code = .other, .text = "cname loop" });
        }
        // Nothing waits on an answer, so only an orphaned root is refused.
        s.hops[s.n] = try g.demand(id, try g.keyFor(.rrset, next, qtype), next) orelse
            return failAnswer(g, id, unreachable_authority);
        s.n += 1;
    }
    var expires: i64 = std.math.maxInt(i64);
    for (s.hops[0..s.n]) |h| expires = @min(expires, g.cell(h).expires_ns);
    // A verdict that failed is bogus, and lives no longer.
    for (s.judged[0..s.nj]) |j| {
        if (!g.cell(j).settled()) return;
        expires = @min(expires, g.cell(j).expires_ns);
    }
    try settleAnswer(g, id, .{ .hops = s.hops[0..s.n], .judged = s.judged[0..s.nj] }, expires);
    // Best effort.
    if (kind == .answer and g.cfg.prefetch and refreshable(g, s, expires))
        g.refresh(g.cell(id).key, g.cell(id).name) catch {};
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

/// Lapses inside the window, and no lapsing hop was born short.
fn refreshable(g: *Graph, s: *const AnswerScratch, expires: i64) bool {
    const window = graph.refresh_window_ns;
    if (expires <= g.now() or expires > g.now() + window) return false;
    for (s.hops[0..s.n]) |h| {
        const c = g.cell(h);
        if (c.expires_ns <= g.now() + window and c.state.fact.rrset.ttl <= refresh_floor_s) return false;
    }
    return true;
}

/// `cut(name)`: from `cut(parent(name))`, probe `name A` at the parent's
/// servers when minimising; a referral is a deeper cut, anything else
/// puts the name inside the parent's zone. Only strict ancestors of a
/// question are probed; the question itself goes out as `rrset`.
pub fn runCut(g: *Graph, id: CellId) !void {
    const name = g.cell(id).name;
    // The axiom, re-derived after eviction.
    if (name.labels.len == 0) return g.settle(id, .{ .cut = .{ .zone = name } }, std.math.maxInt(i64));
    const parent_name: dns.Name = .{ .labels = name.labels[1..] };
    const s = g.cell(id).scratch.cut;
    if (s.parent == null) s.parent = try g.demand(id, try g.keyFor(.cut, parent_name, .a), parent_name) orelse
        return g.fail(id, unreachable_authority);
    const parent = g.cell(s.parent.?);
    if (!parent.settled()) return;
    if (parent.failure()) |why| return g.fail(id, why);
    const pc = parent.state.fact.cut;
    const inside: graph.Value = .{ .cut = .{ .zone = pc.zone } };
    if (!g.cfg.qmin or name.labels.len > delegation.max_minimize_count) return g.settle(id, inside, parent.expires_ns);
    // Not a fact: the cut is unknown, and only this instant's demanders read it.
    if (g.payer.unminimised.covers(name)) return g.settle(id, inside, g.now());
    // No cut below a name that does not exist (RFC 8020).
    if (try deniedAt(g, parent_name, pc.zone)) |until| return g.settle(id, inside, @min(parent.expires_ns, until));
    // A fresh fact at the probe name answers it without a packet.
    if (try g.peek(try g.keyFor(.rrset, name, .a))) |known|
        return g.settle(id, inside, @min(parent.expires_ns, known.expires_ns));
    if (!s.started) {
        s.ask.reset(pc.zone);
        s.started = true;
    }
    switch (try ask(g, id, &g.cell(id).scratch.cut.ask, name, .a)) {
        .pending => return,
        .exhausted => try g.fail(id, unreachable_authority),
        .reply => |msg| {
            switch (delegation.probeStep(msg, name, pc.zone, g.cfg.addr_policy)) {
                .referral => |ref| {
                    const cut = try absorbReferral(g, id, ref, msg, pc.zone);
                    try g.settle(id, cut.value, cut.expires_ns);
                },
                .answered => try g.settle(id, inside, parent.expires_ns),
                // An authoritative denial is a fact; NXDOMAIN ends minimising
                // below it. A positive answer is not: the parent may serve
                // occluded data for a name it delegated (bailiwick/006).
                .nodata => {
                    _ = try publishDenial(g, id, msg, pc.zone, name);
                    try g.settle(id, inside, parent.expires_ns);
                },
                .nxdomain => {
                    const until = try publishDenial(g, id, msg, pc.zone, name) orelse return unminimised(g, id, inside);
                    try g.settle(id, inside, @min(parent.expires_ns, until));
                },
                .failed => try unminimised(g, id, inside),
            }
        },
    }
}

/// An authoritative denial at a probe name, published; when it lapses.
fn publishDenial(g: *Graph, id: CellId, msg: dns.Message, zone: dns.Name, name: dns.Name) !?i64 {
    if (!msg.header.flags.aa) return null;
    const reply = try classify(g, msg, zone, name, .a) orelse return null;
    try g.publish(try g.keyFor(.rrset, name, .a), id, .{ .rrset = reply }, replyExpiry(reply));
    return replyExpiry(reply);
}

/// RFC 9156 §2.3: a probe drew an error, or an NXDOMAIN nobody vouches
/// for, so this resolution asks names below it in full. Policy, keyed by
/// the resolution, never a fact about the cut.
pub const Unminimised = struct {
    labels: u8 = 0,
    len: u8 = 0,
    /// Wire form, 255 octets at most; length octets are below 'A', so case
    /// folding spares them.
    below: [dns.max_name_len + 2]u8 = undefined,

    fn covers(u: *const Unminimised, name: dns.Name) bool {
        if (u.labels == 0 or name.labels.len <= u.labels) return false;
        var buf: [dns.max_name_len + 2]u8 = undefined;
        const above: dns.Name = .{ .labels = name.labels[name.labels.len - u.labels ..] };
        const n = dns.writeNameWire(&buf, above) catch return false;
        return std.ascii.eqlIgnoreCase(buf[0..n], u.below[0..u.len]);
    }
};

fn unminimised(g: *Graph, id: CellId, inside: graph.Value) !void {
    const u = &g.payer.unminimised;
    const name = g.cell(id).name;
    u.len = @intCast(try dns.writeNameWire(&u.below, name));
    u.labels = @intCast(name.labels.len);
    try g.settle(id, inside, g.now());
}

/// When the closest name from `from` up to (not including) `zone` known
/// not to exist stops being known.
fn deniedAt(g: *Graph, from: dns.Name, zone: dns.Name) !?i64 {
    var n = from;
    while (n.labels.len > zone.labels.len) : (n = .{ .labels = n.labels[1..] }) {
        const f = try g.peek(try g.keyFor(.rrset, n, .a)) orelse continue;
        if (f.value.rrset.kind == .nxdomain) return f.expires_ns;
    }
    return null;
}

/// `ns(zone)`: only a parent referral settles it. Demanding an
/// unsettled one re-probes the cut, whose referral publishes both.
pub fn runNs(g: *Graph, id: CellId) !void {
    const zone = g.cell(id).name;
    const s = g.cell(id).scratch.ns;
    if (s.cut == null) s.cut = try g.demand(id, try g.keyFor(.cut, zone, .a), zone) orelse
        return g.fail(id, unreachable_authority);
    const cut = g.cell(s.cut.?);
    if (!cut.settled()) return;
    // A cut at `zone` means the referral published us already; a
    // shallower one means no delegation here while it holds.
    if (g.cell(id).settled()) return;
    if (cut.failure()) |why| return g.fail(id, why);
    if (cut.state.fact.cut.zone.eql(zone)) return g.fail(id, unreachable_authority);
    try g.settle(id, .{ .ns = .{ .names = &.{} } }, cut.expires_ns);
}

/// `addr(host)`: glue seeds it provisionally (`absorbReferral`); else
/// the A and AAAA RRsets one level deeper, through at most one CNAME hop.
pub fn runAddr(g: *Graph, id: CellId) !void {
    if (g.level(id) + 1 > g.cfg.max_resolve_depth) return g.fail(id, .{ .code = .no_reachable_authority, .text = "too deep" });
    const s = g.cell(id).scratch.addr;
    if (s.host == null) {
        s.host = g.cell(id).name;
        if (try g.peek(try g.keyFor(.rrset, s.host.?, .cname))) |cname| if (cname.value.rrset.kind == .alias) {
            s.host = try dns.cloneNameFlat(g.cell(id).arena.allocator(), cname.value.rrset.target, false);
            s.hopped = true;
        };
    }
    const host = s.host.?;
    if (s.a == null) s.a = try g.demand(id, try g.keyFor(.rrset, host, .a), host);
    if (s.aaaa == null) s.aaaa = try g.demand(id, try g.keyFor(.rrset, host, .aaaa), host);
    var addrs: std.ArrayList(na.Address) = .empty;
    var pending = false;
    var alias: ?dns.Name = null;
    // A denial of one family does not age the other's addresses; an
    // empty set lives only as long as the shortest denial.
    var expires: i64 = std.math.maxInt(i64);
    var denied: i64 = std.math.maxInt(i64);
    var failed: ?Failure = null;
    for ([_]dns.RType{ .a, .aaaa }) |rtype| {
        const rid = (if (rtype == .a) s.a else s.aaaa) orelse continue;
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
                if (slot.* == null) slot.* = try trust.demandSecure(g, id, rid);
                const j = g.cell(slot.*.?);
                if (!j.settled()) {
                    pending = true;
                    continue;
                }
                if (j.failure()) |why| {
                    failed = failed orelse why;
                    continue;
                }
            }
            if (r.kind == .answer) {
                for (r.answers) |rr| {
                    if (rr.rtype != rtype or !rr.name.eql(host)) continue;
                    if (g.cfg.addr_policy.address(rr)) |a| {
                        try addrs.append(g.scratch.allocator(), a);
                        n += 1;
                    }
                }
            } else if (alias == null) alias = r.target;
        }
        if (n > 0) expires = @min(expires, c.expires_ns) else denied = @min(denied, c.expires_ns);
    }
    if (pending) return;
    if (addrs.items.len == 0) {
        if (alias) |target| if (!s.hopped) {
            s.* = .{ .host = try dns.cloneNameFlat(g.cell(id).arena.allocator(), target, false), .hopped = true };
            return runAddr(g, id);
        };
        // Only denials make an empty set a fact.
        if (failed) |why| return g.fail(id, why);
        expires = denied;
    }
    try g.settle(id, .{ .addr = .{ .addrs = addrs.items, .provisional = false } }, expires);
}

/// `rrset(name, type)`: from the deepest known cut at or above the name,
/// ask its servers; follow referrals; settle on the first kept reply.
pub fn runRrset(g: *Graph, id: CellId) !void {
    const name = g.cell(id).name;
    const qtype = g.cell(id).key.rtype;
    const s = g.cell(id).scratch.rrset;
    if (!s.started) {
        if (s.cut == null) {
            // Indexed proofs deny the name without a packet.
            if (try denial.deny(g, id)) return;
            // A cut at the name itself exists only from a referral;
            // otherwise start at the parent's. A DS always lives there.
            const own = try g.keyFor(.cut, name, .a);
            const parent_name: dns.Name = .{ .labels = name.labels[@min(1, name.labels.len)..] };
            const key = if (qtype != .ds and (try g.peek(own) != null or name.labels.len == 0)) own else try g.keyFor(.cut, parent_name, .a);
            const cut_name = if (key.name.ptr == own.name.ptr) name else parent_name;
            s.cut = try g.demand(id, key, cut_name) orelse
                return g.fail(id, unreachable_authority);
        }
        const cut = g.cell(s.cut.?);
        if (!cut.settled()) return;
        if (cut.failure()) |why| return g.fail(id, why);
        // RFC 6672: a secure DNAME above the name redirects it, asking nobody.
        if (!s.dname_checked) {
            s.dname_checked = true;
            if (try dnameAbove(g, name)) |owner| s.dname = try g.demand(id, try g.keyFor(.rrset, owner, .dname), owner);
            if (s.dname) |did| s.dname_judge = try trust.demandSecure(g, id, did);
        }
        if (s.dname_judge) |jid| {
            if (!g.cell(jid).settled()) return;
            if (g.cell(jid).failure() == null and g.cell(jid).state.fact.secure.status == .secure) {
                const reply = try dnameRedirect(g, name, s.dname.?);
                return g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
            }
        }
        s.ask.reset(cut.state.fact.cut.zone);
        var glue: std.ArrayList(na.Address) = .empty;
        for (cut.state.fact.cut.glue) |gl| if (gl.live(g.now())) try glue.append(g.scratch.allocator(), gl.addr);
        s.ask.add(g, glue.items);
        s.started = true;
    }
    while (true) {
        switch (try ask(g, id, &g.cell(id).scratch.rrset.ask, name, qtype)) {
            .pending => return,
            .exhausted => return failAsk(g, id, unreachable_authority),
            .reply => |msg| {
                const zone = g.cell(id).scratch.rrset.ask.zone;
                if (delegation.extractReferral(msg, name, zone, g.cfg.addr_policy)) |ref| {
                    const s2 = g.cell(id).scratch.rrset;
                    if (s2.delegations >= g.cfg.max_delegations)
                        return failAsk(g, id, unreachable_authority);
                    s2.delegations += 1;
                    _ = try absorbReferral(g, id, ref, msg, zone);
                    // The parent's referral to the zone itself is its
                    // answer about the zone's DS (RFC 4035 §3.1.4.1).
                    if (qtype == .ds and ref.zone_cut.eql(name)) {
                        const reply = try trust.referralDs(g, msg, zone, name);
                        return g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
                    }
                    s2.ask.reset(ref.zone_cut);
                    s2.ask.add(g, ref.addrs[0..ref.addr_count]);
                    continue;
                }
                // Any other rcode is no useful response (RFC 9520 §2).
                switch (msg.header.flags.rcode) {
                    .no_error, .name_error, .yx_domain => {},
                    else => return failAsk(g, id, unreachable_authority),
                }
                const reply = try classify(g, msg, zone, name, qtype) orelse
                    return failAsk(g, id, .{ .code = .other, .text = "cname loop" });
                try publishAlias(g, id, name, qtype, reply);
                try publishDnames(g, id, reply);
                return settleRrset(g, id, reply);
            },
        }
    }
}

fn settleRrset(g: *Graph, id: CellId, reply: Reply) !void {
    try g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
}

/// The fetch itself failed: the next asker in the window is refused
/// (RFC 9520 §3.2), unless the failure may be the asker's own: a spent
/// budget or deadline (here or in a sub-resolution), an orphan, an address
/// sub-resolution's depth, or a refresh.
const failed_recently: Failure = .{ .code = .no_reachable_authority, .text = "failed recently" };

fn failAsk(g: *Graph, id: CellId, why: Failure) !void {
    const c = g.cell(id);
    const spent = g.now() >= g.payer.deadline_ns or g.payer.queries >= g.cfg.max_queries;
    if (!spent and !c.orphan and g.payer.refresh_ns == 0 and g.level(id) == 0) try g.remember(c.key, failed_recently);
    try g.fail(id, why);
}

/// A chain starting with a CNAME at `name` is also the fact
/// `rrset(name, CNAME)`, so any later type finds the hop.
fn publishAlias(g: *Graph, by: CellId, name: dns.Name, qtype: dns.RType, reply: Reply) !void {
    if (qtype == .cname or reply.answers.len == 0) return;
    const first = reply.answers[0];
    if (first.rtype != .cname or !first.name.eql(name)) return;
    const hop: Reply = .{
        .kind = .alias,
        .rcode = .no_error,
        .aa = reply.aa,
        .answers = reply.answers[0..1],
        .target = first.rdata.cname,
        .stored_ns = reply.stored_ns,
        .ttl = first.ttl,
    };
    try g.publish(try g.keyFor(.rrset, name, .cname), by, .{ .rrset = hop }, replyExpiry(hop));
}

/// Every DNAME a reply used is the fact `rrset(owner, DNAME)`, signed,
/// so later names under it redirect from memory.
fn publishDnames(g: *Graph, by: CellId, reply: Reply) !void {
    for (reply.answers) |d| {
        if (d.rtype != .dname) continue;
        var keep: std.ArrayList(dns.ResourceRecord) = .empty;
        try keep.append(g.scratch.allocator(), d);
        try keepSigs(g, &keep, reply.answers, d.name, .dname);
        const dname: Reply = .{ .kind = .answer, .rcode = .no_error, .aa = reply.aa, .answers = keep.items, .zone = reply.zone, .stored_ns = reply.stored_ns, .ttl = d.ttl };
        try g.publish(try g.keyFor(.rrset, d.name, .dname), by, .{ .rrset = dname }, replyExpiry(dname));
    }
}

/// The owner of the closest fresh DNAME fact above `name` (RFC 6672 §3.2).
fn dnameAbove(g: *Graph, name: dns.Name) !?dns.Name {
    var i: usize = 1;
    while (i < name.labels.len) : (i += 1) {
        const owner: dns.Name = .{ .labels = name.labels[i..] };
        const d = try g.peek(try g.keyFor(.rrset, owner, .dname)) orelse continue;
        if (d.value.rrset.kind == .answer) return owner;
    }
    return null;
}

/// The alias a DNAME fact synthesises for `name`, aged from when the
/// DNAME was taken.
fn dnameRedirect(g: *Graph, name: dns.Name, did: CellId) !Reply {
    const d = g.cell(did).state.fact.rrset;
    const dname = for (d.answers) |rr| {
        if (rr.rtype == .dname) break rr;
    } else unreachable;
    var keep: std.ArrayList(dns.ResourceRecord) = .empty;
    try keep.appendSlice(g.scratch.allocator(), d.answers);
    if (try dns.substituteSuffix(g.scratch.allocator(), name, dname.name, dname.rdata.dname)) |target| {
        try keep.append(g.scratch.allocator(), .{ .name = name, .rtype = .cname, .rclass = .in, .ttl = dname.ttl, .rdata = .{ .cname = target } });
        return .{ .kind = .alias, .rcode = .no_error, .aa = d.aa, .answers = keep.items, .target = target, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
    }
    // RFC 6672 §3.3: the substituted name is too long; YXDOMAIN.
    return .{ .kind = .yxdomain, .rcode = .yx_domain, .aa = d.aa, .answers = keep.items, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
}

/// Publish the child's cut, NS set and glue, and return the cut. The
/// delegation never outlives the referring zone's: that is a ghost (Jiang
/// et al., NDSS 2012).
fn absorbReferral(g: *Graph, by: CellId, ref: delegation.Referral, msg: dns.Message, zone: dns.Name) !Graph.Fact {
    var ns_ttl: u32 = std.math.maxInt(u32);
    for (msg.authorities) |rr| if (rr.rtype == .ns and rr.name.eql(ref.zone_cut)) {
        ns_ttl = @min(ns_ttl, rr.ttl);
    };
    // Looked up, not taken from the asking cell: a qmin stop marker names
    // the zone but expires at once. Null: the delegation is gone already.
    const parent = try g.peek(try g.keyFor(.cut, zone, .a));
    const expires = @min(if (parent) |p| p.expires_ns else g.now(), g.now() + @as(i64, ns_ttl) * std.time.ns_per_s);
    const names = try g.scratch.allocator().dupe(dns.Name, ref.nsNames());
    const glue = try g.scratch.allocator().alloc(graph.Glue, ref.addr_count);
    for (glue, ref.addrs[0..ref.addr_count], ref.ttls[0..ref.addr_count]) |*gl, a, ttl|
        gl.* = .{ .addr = a, .expires_ns = @min(expires, g.now() + @as(i64, ttl) * std.time.ns_per_s) };
    const cut: graph.Value = .{ .cut = .{ .zone = ref.zone_cut, .glue = glue } };
    try g.publish(try g.keyFor(.cut, ref.zone_cut, .a), by, cut, expires);
    try g.publish(try g.keyFor(.ns, ref.zone_cut, .a), by, .{ .ns = .{ .names = names } }, expires);
    // The parent's word on the child's DS travels with the referral.
    if (g.cfg.trust_anchor != null) {
        const ds = try trust.referralDs(g, msg, zone, ref.zone_cut);
        if (ds.ttl > 0) try g.publish(try g.keyFor(.rrset, ref.zone_cut, .ds), by, .{ .rrset = ds }, replyExpiry(ds));
        // A signed delegation from a zone signed all the way down: whatever
        // the walk finds below, its proof runs through these keys, so they
        // are fetched as it descends.
        if (ds.kind == .answer and try trust.signedDown(g, zone)) try g.fetchKeys(by, ref.zone_cut);
    }
    // Glue is only a fact: never displacing an authoritative set, nor
    // pre-empting a walk for one in progress.
    for (names[0..ref.glued]) |host| {
        var addrs: std.ArrayList(na.Address) = .empty;
        var ttl: u32 = std.math.maxInt(u32);
        for (msg.additionals) |rr| {
            if (!rr.name.eql(host) or (rr.rtype != .a and rr.rtype != .aaaa)) continue;
            const a = g.cfg.addr_policy.address(rr) orelse continue;
            try addrs.append(g.scratch.allocator(), a);
            ttl = @min(ttl, rr.ttl);
        }
        if (addrs.items.len == 0) continue;
        const key = try g.keyFor(.addr, host, .a);
        if (try g.peek(key)) |existing| if (!existing.value.addr.provisional) continue;
        const glue_expires = @min(expires, g.now() + @as(i64, ttl) * std.time.ns_per_s);
        try g.fact(key, .{ .addr = .{ .addrs = addrs.items, .provisional = true } }, glue_expires);
    }
    return .{ .value = cut, .expires_ns = expires };
}

/// What a kept, non-referral reply says about (name, type). The answer
/// section is reduced to the chain from `name`: CNAMEs (and the DNAMEs
/// that synthesise them), then the asked type at the end. Anything else
/// is unsolicited (RFC 2181 §5.4.1) and dropped, NXDOMAIN included.
/// Null: the chain loops, a resolution failure. The rcode is one of the
/// three that answer.
fn classify(g: *Graph, msg: dns.Message, zone: dns.Name, name: dns.Name, qtype: dns.RType) !?Reply {
    var keep: std.ArrayList(dns.ResourceRecord) = .empty;
    var cur = name;
    var hops: usize = 0;
    var answered = false;
    var seen: [17]dns.Name = undefined;
    // NXDOMAIN denies the end of the chain; records there are noise.
    const collect = msg.header.flags.rcode != .name_error;
    while (hops < 16) : (hops += 1) {
        for (seen[0..hops]) |n| if (n.eql(cur)) return null;
        seen[hops] = cur;
        for (msg.answers) |rr| {
            if (collect and rr.name.eql(cur) and rr.name.isSubdomainOf(zone) and (rr.rtype == qtype or qtype == .any)) {
                try keep.append(g.scratch.allocator(), rr);
                answered = true;
            }
        }
        if (answered) {
            try keepSigs(g, &keep, msg.answers, cur, qtype);
            break;
        }
        var cname: ?dns.ResourceRecord = null;
        for (msg.answers) |rr| if (rr.rtype == .cname and rr.name.eql(cur) and rr.name.isSubdomainOf(zone)) {
            cname = rr;
            break;
        };
        // RFC 6672 §3.3: the deepest DNAME above `cur` synthesises the
        // CNAME and travels with it.
        var dname: ?dns.ResourceRecord = null;
        for (msg.answers) |rr| {
            if (rr.rtype != .dname or !cur.isSubdomainOf(rr.name) or cur.eql(rr.name) or !rr.name.isSubdomainOf(zone)) continue;
            if (dname == null or rr.name.labels.len > dname.?.name.labels.len) dname = rr;
        }
        if (dname) |d| {
            try keep.append(g.scratch.allocator(), d);
            try keepSigs(g, &keep, msg.answers, d.name, .dname);
            if (cname == null) {
                const target = try dns.substituteSuffix(g.scratch.allocator(), cur, d.name, d.rdata.dname) orelse break;
                cname = .{ .name = cur, .rtype = .cname, .rclass = .in, .ttl = d.ttl, .rdata = .{ .cname = target } };
            }
        }
        const c = cname orelse break;
        try keep.append(g.scratch.allocator(), c);
        try keepSigs(g, &keep, msg.answers, cur, .cname);
        cur = c.rdata.cname;
    }
    var reply: Reply = .{
        .kind = if (answered) .answer else if (hops > 0) .alias else .nodata,
        .rcode = msg.header.flags.rcode,
        .aa = msg.header.flags.aa,
        .answers = keep.items,
        .authorities = msg.authorities,
        .additionals = msg.additionals,
        .target = cur,
        .zone = zone,
        .stored_ns = g.now(),
    };
    // A CNAME question is answered by the alias itself, the fact
    // `publishAlias` records for every other type.
    if (qtype == .cname and answered) {
        reply.kind = .alias;
        reply.target = keep.items[0].rdata.cname;
    }
    switch (msg.header.flags.rcode) {
        .name_error => reply.kind = .nxdomain,
        .yx_domain => reply.kind = .yxdomain,
        else => {},
    }
    reply.ttl = replyTtl(g, reply, zone, name);
    return reply;
}

fn keepSigs(g: *Graph, keep: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, owner: dns.Name, covered: dns.RType) !void {
    for (rrs) |rr| if (rr.rtype == .rrsig and rr.name.eql(owner) and (covered == .any or rr.rdata.rrsig.type_covered == covered)) try keep.append(g.scratch.allocator(), rr);
}

/// The answer's shortest TTL; for an authoritative denial, min of the
/// SOA's TTL and MINIMUM (RFC 2308 §3) from an SOA above the name and
/// inside the zone, nothing otherwise.
pub fn replyTtl(g: *Graph, reply: Reply, zone: dns.Name, name: dns.Name) u32 {
    var ttl: u32 = 0;
    switch (reply.kind) {
        .answer, .alias, .yxdomain => {
            ttl = std.math.maxInt(u32);
            for (reply.answers) |rr| if (rr.rtype != .rrsig) {
                ttl = @min(ttl, rr.ttl);
            };
            // A bare YXDOMAIN carries no record to live by.
            if (ttl == std.math.maxInt(u32)) ttl = 0;
        },
        .nodata, .nxdomain => if (reply.aa) {
            ttl = g.cfg.max_negative_ttl;
            var found = false;
            for (reply.authorities) |rr| {
                if (rr.rtype != .soa or !name.isSubdomainOf(rr.name) or !rr.name.isSubdomainOf(zone)) continue;
                ttl = @min(ttl, @min(rr.ttl, rr.rdata.soa.minimum));
                found = true;
            }
            if (!found) ttl = 0;
        },
    }
    return ttl;
}

pub fn replyExpiry(reply: Reply) i64 {
    return reply.stored_ns + @as(i64, reply.ttl) * std.time.ns_per_s;
}

// ── The sibling loop ───────────────────────────────────────────────

fn ask(g: *Graph, id: CellId, a: *Ask, qname: dns.Name, qtype: dns.RType) !Ask.Result {
    while (true) {
        if (!a.have_servers) switch (try gatherServers(g, id, a)) {
            .pending => return .pending,
            .none => {
                if (a.retried or a.held != null) return a.giveUp(g);
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
                .timeout => {},
                .mismatch => {},
                .mangled => if (at.transport == .udp) {
                    _ = try sendTo(g, id, a, at.server, .tcp, qname, qtype);
                },
                .reply => |r| {
                    if (r.msg.header.flags.tc) {
                        // TC over TCP: a broken server, as good as a timeout.
                        if (at.transport == .udp) {
                            _ = try sendTo(g, id, a, at.server, .tcp, qname, qtype);
                        }
                    } else if (!delegation.shouldTrySibling(r.msg, a.zone, g.cfg.addr_policy)) {
                        a.nattempts = 0;
                        return .{ .reply = r.msg };
                    } else if (a.held == null) a.held = at.exchange;
                },
            }
        }
        while (a.next < a.nservers and a.tried & Ask.bit(a.next) != 0) a.next += 1;
        const early = g.cfg.stagger_ms > 0 and a.nattempts < max_hedge and g.now() >= a.hedge_at;
        if (a.next < a.nservers and (a.nattempts == 0 or early)) {
            const server = a.next;
            a.next += 1;
            const state = try sendTo(g, id, a, server, if (a.tcp_first) .tcp else .udp, qname, qtype) orelse continue;
            a.hedge_at = g.now() + @as(i64, state.hedgeStagger() orelse g.cfg.stagger_ms) * std.time.ns_per_ms;
            if (g.cfg.stagger_ms > 0 and a.next < a.nservers) try g.wake(id, a.hedge_at);
            continue;
        }
        if (a.nattempts > 0) return .pending;
        // Every known server tried: gather again for what settled since.
        a.have_servers = false;
    }
}

fn zoneTruncates(g: *Graph, zone: dns.Name) bool {
    const key = g.keyFor(.rrset, zone, .ds) catch return false;
    const ds = (g.peek(key) catch return false) orelse return false;
    return dnssec.dsExceedsUdp(ds.value.rrset.answers);
}

/// One attempt on the estimate's timeout; only the last of all is uncapped.
/// Null: refused, so launch nothing more; what is in flight may still answer.
fn sendTo(g: *Graph, id: CellId, a: *Ask, server: u8, transport: Transport, qname: dns.Name, qtype: dns.RType) !?ns_rtt.RttState {
    a.tried |= Ask.bit(server);
    const key = a.servers[server];
    const state = g.rtt.get(key) orelse ns_rtt.RttState.unknown;
    const timeout_ms = state.timeout(a.nattempts == 0 and a.next >= a.nservers, transport);
    const ex = try g.exchange(id, key.toAddress(), transport, qname, qtype, timeout_ms) orelse {
        a.next = a.nservers;
        a.fetched_unglued = true;
        return null;
    };
    a.attempts[a.nattempts] = .{ .exchange = ex, .server = server, .transport = transport };
    a.nattempts += 1;
    return state;
}

/// The server set for `a.zone`: hints at the root, else the addresses
/// already known for the NS names. Only when none are known, or all
/// have failed, are unglued names resolved, up to a per-depth limit.
fn gatherServers(g: *Graph, id: CellId, a: *Ask) !enum { pending, none, ready } {
    var list: std.ArrayList(na.Address) = .empty;
    defer list.deinit(g.gpa);
    const zone = a.zone;
    if (zone.labels.len == 0) {
        for (g.cfg.root_hints) |h| if (!a.knows(h)) try list.append(g.gpa, h);
    } else {
        if (a.ns == null) a.ns = try g.demand(id, try g.keyFor(.ns, zone, .a), zone) orelse return .none;
        const ns = g.cell(a.ns.?);
        if (!ns.settled()) return .pending;
        if (ns.failure() != null) return .none;
        const names = ns.state.fact.ns.names;
        var unknown: std.ArrayList(dns.Name) = .empty;
        defer unknown.deinit(g.gpa);
        var pending = false;
        for (names) |host| {
            const key = try g.keyFor(.addr, host, .a);
            if (try g.peek(key)) |known| {
                try list.appendSlice(g.gpa, known.value.addr.addrs);
                continue;
            }
            if (g.index.get(key)) |aid| {
                if (g.cell(aid).settled()) {
                    // Ours, settled TTL-0 or failed: a fact
                    // serves its demander, a failure gives nothing.
                    if (g.holdsInput(id, aid)) {
                        if (g.cell(aid).failure() == null) try list.appendSlice(g.gpa, g.cell(aid).state.fact.addr.addrs);
                        continue;
                    }
                } else {
                    // In progress for someone: wait, unless it is
                    // transitively waiting on us.
                    if (try g.demand(id, key, host) != null) pending = true;
                    continue;
                }
            }
            try unknown.append(g.gpa, host);
        }
        var i: usize = 0;
        while (i < list.items.len) {
            if (a.knows(list.items[i])) _ = list.swapRemove(i) else i += 1;
        }
        // A sibling still resolving is waited for only when nothing
        // else is left.
        if (list.items.len == 0 and pending) return .pending;
        if (list.items.len == 0 and !a.fetched_unglued and unknown.items.len > 0) {
            a.fetched_unglued = true;
            const limit: usize = switch (g.level(id)) {
                0 => 3,
                1 => 2,
                else => 1,
            };
            g.edge.rng.shuffle(dns.Name, unknown.items);
            var demanded = false;
            for (unknown.items[0..@min(limit, unknown.items.len)]) |host| {
                const aid = try g.demand(id, try g.keyFor(.addr, host, .a), host) orelse continue;
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
        std.debug.print("  {s} at {s}: {d} servers tried, none left, {s}\n", .{ g.cell(id).name.formatInto(&nb), zone.formatInto(&zb), @popCount(a.tried), if (a.held != null) "best failure held" else "no reply at all" });
    }
    return .none;
}

test "an ask has a static bound" {
    // A waiting walk's scratch is a comptime constant, not a stack; the
    // server list is most of it.
    try std.testing.expect(@sizeOf(Ask) <= 640);
}
