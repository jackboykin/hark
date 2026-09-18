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

const max_cname_chain = graph.max_cname_chain;

const max_servers = delegation.max_servers_per_level;

const max_hedge = 3;

/// BIND's stale-refresh-time (RFC 8767 §5).
pub const stale_hold_s = 30;
/// RFC 8767 §5: a refresh past a stub's patience answers stale instead.
pub const stale_client_ms = 1800;
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
    /// The exchange whose failing reply ranks best
    /// (`delegation.failurePrecedence`), served when every server fails
    /// with an rcode.
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
        a.have_servers = a.next < a.nservers;
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
        return g.cell(a.held orelse return null).value.exchange.reply.msg;
    }

    /// A rank-0 reply (lame, recursor) leaves as bare SERVFAIL so the
    /// randomised server order cannot change what the stub sees.
    fn giveUp(a: *Ask, g: *Graph) Result {
        std.debug.assert(a.nattempts == 0);
        var msg = a.heldMsg(g) orelse return .exhausted;
        if (delegation.failurePrecedence(msg.header.flags.rcode) == 0) {
            msg.header.flags.rcode = .server_failure;
            msg.answers = &.{};
            msg.authorities = &.{};
            msg.additionals = &.{};
        }
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
    stale: [2]?*const Reply = .{ null, null },
    stale_checked: [2]bool = .{ false, false },
};

pub const NsScratch = struct {
    cut: ?CellId = null,
};

pub const AnswerScratch = struct {
    hops: [max_cname_chain + 1]CellId = undefined,
    n: u8 = 0,
    /// `secure(hop)` per hop.
    judged: [max_cname_chain + 1]CellId = undefined,
    nj: u8 = 0,
    stale: [max_cname_chain + 1]?*const Reply = @splat(null),
    stale_checked: [max_cname_chain + 1]bool = @splat(false),
    /// Where the client's patience ends; one wake.
    stale_at: i64 = 0,
    armed: bool = false,
};

// ── Rules ──────────────────────────────────────────────────────────────

pub fn runAnswer(g: *Graph, id: CellId) !void {
    const kind = g.cell(id).key.kind;
    const qtype = g.cell(id).key.rtype;
    const s = g.cell(id).scratch.answer;
    if (s.stale_at == 0) s.stale_at = g.now() + stale_client_ms * std.time.ns_per_ms;
    var next = g.cell(id).name;
    while (true) {
        if (s.n > 0) {
            const i = s.n - 1;
            const last = g.cell(s.hops[i]);
            if (!last.settled) {
                // Past the client's patience: stale answers and holds; the refresh is orphaned.
                const until = staleWindow(g, last.key) orelse return;
                if (g.store.any(last.key).?.hold_until_ns <= g.now()) {
                    if (g.now() < s.stale_at) {
                        if (!s.armed) try g.wake(id, s.stale_at);
                        s.armed = true;
                        return;
                    }
                    holdStale(g, last.key, until);
                }
                s.stale[i] = try staleReply(g, last.key, g.cell(id).arena.allocator());
                s.stale_checked[i] = true;
            } else if (!s.stale_checked[i]) {
                s.stale_checked[i] = true;
                if (last.value.rrset.kind == .servfail) s.stale[i] = try staleReply(g, last.key, g.cell(id).arena.allocator());
            }
            const r = if (s.stale[i]) |st| st.* else last.value.rrset;
            if (r.kind != .alias or qtype == .cname) break;
            next = r.target;
            var broken = s.n > max_cname_chain;
            for (s.hops[0..s.n]) |h| broken = broken or g.cell(h).name.eql(next);
            if (broken) return settleAnswer(g, id, .{ .hops = s.hops[0..s.n], .broken = true }, failureExpiry(g, id));
        }
        // Nothing waits on an answer, so only an orphaned root is refused.
        s.hops[s.n] = try g.demand(id, try g.keyFor(.rrset, next, qtype), next, 0) orelse
            return settleAnswer(g, id, .{ .hops = s.hops[0..s.n], .broken = true }, g.now());
        s.n += 1;
    }
    var expires: i64 = std.math.maxInt(i64);
    var stale = false;
    for (s.hops[0..s.n], s.stale[0..s.n]) |h, st| {
        expires = @min(expires, g.cell(h).expires_ns);
        stale = stale or st != null;
    }
    // Stale hops go unjudged: their signatures may have expired.
    var status: dnssec.SecurityStatus = .unchecked;
    if (g.cfg.trust_anchor != null and !stale) {
        while (s.nj < s.n) : (s.nj += 1) s.judged[s.nj] = try trust.demandSecure(g, id, s.hops[s.nj]);
        status = .secure;
        for (s.judged[0..s.nj]) |j| {
            const c = g.cell(j);
            if (!c.settled) return;
            status = dnssec.weakest(status, c.value.secure.status);
            expires = @min(expires, c.expires_ns);
        }
        if (status == .bogus) expires = failureExpiry(g, id);
    }
    try settleAnswer(g, id, .{ .hops = s.hops[0..s.n], .status = status, .judged = s.judged[0..s.nj], .stale = s.stale[0..s.n] }, expires);
    // Best effort.
    if (kind == .answer and g.cfg.prefetch and !stale and refreshable(g, s, expires))
        g.refresh(g.cell(id).key, g.cell(id).name) catch {};
}

/// A refresh's inputs are its point; its own answer is nobody's.
fn settleAnswer(g: *Graph, id: CellId, a: graph.Answer, expires: i64) !void {
    if (g.cell(id).key.kind == .refresh) return g.settle(id, .refresh, g.now());
    const arena = g.cell(id).arena.allocator();
    try g.settle(id, .{ .answer = .{ .hops = try arena.dupe(CellId, a.hops), .broken = a.broken, .status = a.status, .judged = try arena.dupe(CellId, a.judged), .stale = try arena.dupe(?*const Reply, a.stale) } }, expires);
}

/// Lapses inside the window, and no lapsing hop was born short.
fn refreshable(g: *Graph, s: *const AnswerScratch, expires: i64) bool {
    const window = graph.refresh_window_ns;
    if (expires <= g.now() or expires > g.now() + window) return false;
    for (s.hops[0..s.n]) |h| {
        const c = g.cell(h);
        if (c.expires_ns <= g.now() + window and c.value.rrset.ttl <= refresh_floor_s) return false;
    }
    return true;
}

/// `cut(name)`: from `cut(parent(name))`, probe `name A` at the parent's
/// servers when minimising; a referral is a deeper cut, anything else
/// puts the name inside the parent's zone. Only strict ancestors of a
/// question are probed; the question itself goes out as `rrset`.
pub fn runCut(g: *Graph, id: CellId) !void {
    const name = g.cell(id).name;
    std.debug.assert(name.labels.len > 0);
    const parent_name: dns.Name = .{ .labels = name.labels[1..] };
    const s = g.cell(id).scratch.cut;
    if (s.parent == null) s.parent = try g.demand(id, try g.keyFor(.cut, parent_name, .a), parent_name, g.cell(id).depth) orelse {
        try g.settle(id, .{ .cut = .{ .zone = .{ .labels = &.{} }, .failed = true } }, g.now());
        return;
    };
    const parent = g.cell(s.parent.?);
    if (!parent.settled) return;
    const pc = parent.value.cut;
    if (!g.cfg.qmin or pc.stop or pc.failed or pc.probes >= delegation.max_minimize_count) {
        try g.settle(id, .{ .cut = pc }, parent.expires_ns);
        return;
    }
    // A fresh fact at the probe name answers it without a packet; a
    // denial there stops minimising.
    if (try g.peek(try g.keyFor(.rrset, name, .a))) |known| {
        try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1, .stop = known.value.rrset.kind == .nxdomain } }, @min(parent.expires_ns, known.expires_ns));
        return;
    }
    if (!s.started) {
        s.ask.reset(pc.zone);
        s.started = true;
    }
    switch (try ask(g, id, &g.cell(id).scratch.cut.ask, name, .a)) {
        .pending => return,
        .exhausted => try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1, .failed = true } }, g.now()),
        .reply => |msg| {
            const walk: delegation.Walk = .{ .name = "", .target = name, .zone = pc.zone };
            switch (delegation.probeStep(msg, &walk, g.cfg.addr_policy)) {
                .referral => |ref| {
                    const expires = try absorbReferral(g, id, ref, msg, pc.zone);
                    try g.settle(id, .{ .cut = .{ .zone = ref.zone_cut, .probes = pc.probes + 1, .addrs = ref.addrs[0..ref.addr_count] } }, expires);
                },
                .nxdomain, .failed => try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1, .stop = true } }, g.now()),
                .answered => try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1 } }, parent.expires_ns),
                .nodata => {
                    // An authoritative denial at the probe name is a
                    // fact. A positive answer is not: the parent may
                    // serve occluded data for a name it delegated
                    // (bailiwick/006).
                    if (msg.header.flags.aa) {
                        const reply = try classify(g, msg, pc.zone, name, .a);
                        try g.publish(try g.keyFor(.rrset, name, .a), id, .{ .rrset = reply }, replyExpiry(reply));
                    }
                    try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1 } }, parent.expires_ns);
                },
            }
        },
    }
}

/// `ns(zone)`: only a parent referral settles it. Demanding an
/// unsettled one re-probes the cut, whose referral publishes both.
pub fn runNs(g: *Graph, id: CellId) !void {
    const zone = g.cell(id).name;
    const s = g.cell(id).scratch.ns;
    if (s.cut == null) s.cut = try g.demand(id, try g.keyFor(.cut, zone, .a), zone, g.cell(id).depth) orelse {
        try g.settle(id, .{ .ns = .{ .names = &.{} } }, g.now());
        return;
    };
    const cut = g.cell(s.cut.?);
    if (!cut.settled) return;
    // A cut at `zone` means the referral published us already; a
    // shallower one means no delegation here while it holds.
    if (g.cell(id).settled) return;
    try g.settle(id, .{ .ns = .{ .names = &.{} } }, if (cut.value.cut.zone.eql(zone)) g.now() else cut.expires_ns);
}

/// `addr(host)`: glue seeds it provisionally (`absorbReferral`); else
/// the A and AAAA RRsets one level deeper, through at most one CNAME hop.
pub fn runAddr(g: *Graph, id: CellId) !void {
    const depth = g.cell(id).depth + 1;
    if (depth > g.cfg.max_resolve_depth) return g.settle(id, .{ .addr = .{ .addrs = &.{}, .provisional = false } }, g.now());
    const s = g.cell(id).scratch.addr;
    if (s.host == null) {
        s.host = g.cell(id).name;
        if (try g.peek(try g.keyFor(.rrset, s.host.?, .cname))) |cname| if (cname.value.rrset.kind == .alias) {
            s.host = try dns.cloneNameFlat(g.cell(id).arena.allocator(), cname.value.rrset.target, false);
            s.hopped = true;
        };
    }
    const host = s.host.?;
    if (s.a == null) s.a = try g.demand(id, try g.keyFor(.rrset, host, .a), host, depth);
    if (s.aaaa == null) s.aaaa = try g.demand(id, try g.keyFor(.rrset, host, .aaaa), host, depth);
    var addrs: std.ArrayList(na.Address) = .empty;
    var pending = false;
    var alias: ?dns.Name = null;
    // A denial of one family does not age the other's addresses; an
    // empty set lives only as long as the shortest denial.
    var expires: i64 = std.math.maxInt(i64);
    var denied: i64 = std.math.maxInt(i64);
    var provisional = false;
    for ([_]dns.RType{ .a, .aaaa }) |rtype| {
        const rid = (if (rtype == .a) s.a else s.aaaa) orelse continue;
        const c = g.cell(rid);
        if (!c.settled) {
            pending = true;
            continue;
        }
        var n: usize = 0;
        const fi: usize = @intFromBool(rtype == .aaaa);
        if (c.value.rrset.kind == .servfail and !s.stale_checked[fi]) {
            s.stale_checked[fi] = true;
            s.stale[fi] = try staleReply(g, c.key, g.cell(id).arena.allocator());
        }
        // Stale addresses are glue-grade: unverified.
        const stale_hop = s.stale[fi] != null;
        const r = if (s.stale[fi]) |st| st.* else c.value.rrset;
        if (r.kind == .answer or r.kind == .alias) {
            // A bogus answer is no address.
            if (g.cfg.trust_anchor != null and !stale_hop) {
                const slot = if (rtype == .a) &s.judge_a else &s.judge_aaaa;
                if (slot.* == null) slot.* = try trust.demandSecure(g, id, rid);
                const j = g.cell(slot.*.?);
                if (!j.settled) {
                    pending = true;
                    continue;
                }
                if (j.value.secure.status == .bogus) {
                    denied = @min(denied, j.expires_ns);
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
        provisional = provisional or (stale_hop and n > 0);
        if (n > 0) expires = @min(expires, c.expires_ns) else denied = @min(denied, c.expires_ns);
    }
    if (pending) return;
    if (addrs.items.len == 0) {
        if (alias) |target| if (!s.hopped) {
            s.* = .{ .host = try dns.cloneNameFlat(g.cell(id).arena.allocator(), target, false), .hopped = true };
            return runAddr(g, id);
        };
        expires = if (denied == std.math.maxInt(i64)) g.now() else denied;
    }
    try g.settle(id, .{ .addr = .{ .addrs = addrs.items, .provisional = provisional } }, expires);
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
            // Held: SERVFAIL, asking nobody.
            if (g.store.any(g.cell(id).key)) |e| if (e.hold_until_ns > g.now())
                return g.settle(id, .{ .rrset = servfail(.no_reachable_authority) }, g.now());
            // A cut at the name itself exists only from a referral;
            // otherwise start at the parent's. A DS always lives there.
            const own = try g.keyFor(.cut, name, .a);
            const parent_name: dns.Name = .{ .labels = name.labels[@min(1, name.labels.len)..] };
            const key = if (qtype != .ds and (try g.peek(own) != null or name.labels.len == 0)) own else try g.keyFor(.cut, parent_name, .a);
            const cut_name = if (key.name.ptr == own.name.ptr) name else parent_name;
            s.cut = try g.demand(id, key, cut_name, g.cell(id).depth) orelse
                return settleRrset(g, id, servfail(.no_reachable_authority));
        }
        const cut = g.cell(s.cut.?);
        if (!cut.settled) return;
        if (cut.value.cut.failed) return settleRrset(g, id, servfail(.no_reachable_authority));
        // RFC 6672: a secure DNAME above the name redirects it, asking nobody.
        if (!s.dname_checked) {
            s.dname_checked = true;
            if (try dnameAbove(g, name)) |owner| s.dname = try g.demand(id, try g.keyFor(.rrset, owner, .dname), owner, g.cell(id).depth);
            if (s.dname) |did| s.dname_judge = try trust.demandSecure(g, id, did);
        }
        if (s.dname_judge) |jid| {
            if (!g.cell(jid).settled) return;
            if (g.cell(jid).value.secure.status == .secure) {
                const reply = try dnameRedirect(g, name, s.dname.?);
                return g.settle(id, .{ .rrset = reply }, replyExpiry(reply));
            }
        }
        s.ask.reset(cut.value.cut.zone);
        s.ask.add(g, cut.value.cut.addrs);
        s.started = true;
    }
    while (true) {
        switch (try ask(g, id, &g.cell(id).scratch.rrset.ask, name, qtype)) {
            .pending => return,
            .exhausted => return settleRrset(g, id, servfail(.no_reachable_authority)),
            .reply => |msg| {
                const zone = g.cell(id).scratch.rrset.ask.zone;
                if (delegation.extractReferral(msg, name, zone, g.cfg.addr_policy)) |ref| {
                    const s2 = g.cell(id).scratch.rrset;
                    if (s2.delegations >= g.cfg.max_delegations)
                        return settleRrset(g, id, servfail(.no_reachable_authority));
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
                const reply = try classify(g, msg, zone, name, qtype);
                try publishAlias(g, id, name, qtype, reply);
                try publishDnames(g, id, reply);
                return settleRrset(g, id, reply);
            },
        }
    }
}

/// A SERVFAIL inside the stale window holds the fact instead of
/// replacing it; the failure is no fact. Only the answer and addr rules
/// substitute the stale reply, so DS and DNSKEY fail for the hold.
fn settleRrset(g: *Graph, id: CellId, reply: Reply) !void {
    const key = g.cell(id).key;
    if (reply.kind == .servfail and reply.rcode == .server_failure) if (staleWindow(g, key)) |until| {
        holdStale(g, key, until);
        return g.settle(id, .{ .rrset = reply }, g.now());
    };
    try g.settle(id, .{ .rrset = reply }, if (reply.kind == .servfail) failureExpiry(g, id) else replyExpiry(reply));
}

fn holdStale(g: *Graph, key: Key, until: i64) void {
    g.store.hold(key, @min(g.now() + stale_hold_s * std.time.ns_per_s, until));
}

fn staleWindow(g: *Graph, key: Key) ?i64 {
    if (g.cfg.serve_stale_ttl == 0) return null;
    const e = g.store.any(key) orelse return null;
    const life = store.rrsetLife(e.blob) catch return null;
    const until = life.expires_ns + @as(i64, g.cfg.serve_stale_ttl) * std.time.ns_per_s;
    if (life.servfail or g.now() < life.expires_ns or g.now() >= until) return null;
    return until;
}

fn staleReply(g: *Graph, key: Key, arena: Allocator) !?*const Reply {
    if (staleWindow(g, key) == null) return null;
    const e = g.store.any(key).?;
    const held = try arena.create(Reply);
    held.* = (try store.Store.parse(arena, e.blob)).rrset;
    held.ede = .stale_answer;
    return held;
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
    const d = g.cell(did).value.rrset;
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
    return .{ .kind = .servfail, .rcode = .yx_domain, .aa = d.aa, .answers = keep.items, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
}

fn servfail(ede: dns.Ede.Code) Reply {
    return .{ .kind = .servfail, .rcode = .server_failure, .aa = false, .ede = ede };
}

/// A fact for the client's SERVFAIL window alone.
fn failureExpiry(g: *Graph, id: CellId) i64 {
    const c = g.cell(id);
    return g.now() + if (c.depth == 0 and c.budget.refresh_ns == 0) @as(i64, g.cfg.servfail_ttl) * std.time.ns_per_s else 0;
}

/// Publish the child's cut, NS set and glue; returns the delegation's
/// expiry.
fn absorbReferral(g: *Graph, by: CellId, ref: delegation.Referral, msg: dns.Message, zone: dns.Name) !i64 {
    var ns_ttl: u32 = std.math.maxInt(u32);
    for (msg.authorities) |rr| if (rr.rtype == .ns and rr.name.eql(ref.zone_cut)) {
        ns_ttl = @min(ns_ttl, rr.ttl);
    };
    const expires = g.now() + @as(i64, ns_ttl) * std.time.ns_per_s;
    const names = try g.scratch.allocator().dupe(dns.Name, ref.nsNames());
    try g.publish(try g.keyFor(.cut, ref.zone_cut, .a), by, .{ .cut = .{ .zone = ref.zone_cut, .addrs = ref.addrs[0..ref.addr_count] } }, expires);
    try g.publish(try g.keyFor(.ns, ref.zone_cut, .a), by, .{ .ns = .{ .names = names } }, expires);
    // The parent's word on the child's DS travels with the referral.
    if (g.cfg.trust_anchor != null) {
        const ds = try trust.referralDs(g, msg, zone, ref.zone_cut);
        if (ds.ttl > 0) try g.publish(try g.keyFor(.rrset, ref.zone_cut, .ds), by, .{ .rrset = ds }, replyExpiry(ds));
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
    return expires;
}

/// What a kept, non-referral reply says about (name, type). The answer
/// section is reduced to the chain from `name`: CNAMEs (and the DNAMEs
/// that synthesise them), then the asked type at the end. Anything else
/// is unsolicited (RFC 2181 §5.4.1) and dropped, NXDOMAIN included.
fn classify(g: *Graph, msg: dns.Message, zone: dns.Name, name: dns.Name, qtype: dns.RType) !Reply {
    var keep: std.ArrayList(dns.ResourceRecord) = .empty;
    var cur = name;
    var hops: usize = 0;
    var answered = false;
    var seen: [17]dns.Name = undefined;
    // NXDOMAIN denies the end of the chain; records there are noise.
    const collect = msg.header.flags.rcode != .name_error;
    while (hops < 16) : (hops += 1) {
        // A loop is a resolution failure, not an answer.
        for (seen[0..hops]) |n| if (n.eql(cur)) return servfail(.other);
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
        .no_error => {},
        .name_error => reply.kind = .nxdomain,
        else => reply.kind = .servfail,
    }
    reply.ttl = replyTtl(g, reply, zone, name);
    return reply;
}

fn keepSigs(g: *Graph, keep: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, owner: dns.Name, covered: dns.RType) !void {
    for (rrs) |rr| if (rr.rtype == .rrsig and rr.name.eql(owner) and (covered == .any or rr.rdata.rrsig.type_covered == covered)) try keep.append(g.scratch.allocator(), rr);
}

/// The answer's shortest TTL; for an authoritative denial, min of the
/// SOA's TTL and MINIMUM (RFC 2308 §3) from an SOA above the name and
/// inside the zone, nothing otherwise. `min-ttl` floors the rest under the
/// negative cap and the signatures' validity; by-products keep their own.
pub fn replyTtl(g: *Graph, reply: Reply, zone: dns.Name, name: dns.Name) u32 {
    var ttl: u32 = 0;
    switch (reply.kind) {
        .answer, .alias => {
            ttl = std.math.maxInt(u32);
            for (reply.answers) |rr| if (rr.rtype != .rrsig) {
                ttl = @min(ttl, rr.ttl);
            };
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
        .servfail => {},
    }
    if (ttl == 0 or ttl >= g.cfg.min_ttl) return ttl;
    var floor = g.cfg.min_ttl;
    if (reply.kind == .nodata or reply.kind == .nxdomain) floor = @min(floor, g.cfg.max_negative_ttl);
    const now = g.wallNow();
    for ([_][]const dns.ResourceRecord{ reply.answers, reply.authorities }) |section| {
        for (section) |rr| if (rr.rtype == .rrsig) {
            floor = @min(floor, rr.rdata.rrsig.secondsUntilExpiry(now));
        };
    }
    return @max(ttl, floor);
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
            if (!ex.settled) {
                i += 1;
                continue;
            }
            const at = a.end(i);
            switch (ex.value.exchange) {
                .timeout => {},
                .mismatch => {},
                // Launch nothing more; what is in flight may still answer.
                .budget => {
                    a.next = a.nservers;
                    a.fetched_unglued = true;
                },
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
                    } else if (outranks(r.msg, a.heldMsg(g))) a.held = at.exchange;
                },
            }
        }
        while (a.next < a.nservers and a.tried & Ask.bit(a.next) != 0) a.next += 1;
        const early = g.cfg.stagger_ms > 0 and a.nattempts < max_hedge and g.now() >= a.hedge_at;
        if (a.next < a.nservers and (a.nattempts == 0 or early)) {
            const server = a.next;
            a.next += 1;
            const state = try sendTo(g, id, a, server, if (a.tcp_first) .tcp else .udp, qname, qtype);
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

/// `delegation.recordFailure`'s rule: a later reply wins ties.
fn outranks(msg: dns.Message, held: ?dns.Message) bool {
    const h = held orelse return true;
    return delegation.failurePrecedence(msg.header.flags.rcode) >= delegation.failurePrecedence(h.header.flags.rcode);
}

/// One attempt on the estimate's timeout; only the last of all is uncapped.
fn sendTo(g: *Graph, id: CellId, a: *Ask, server: u8, transport: Transport, qname: dns.Name, qtype: dns.RType) !ns_rtt.RttState {
    a.tried |= Ask.bit(server);
    const key = a.servers[server];
    const state = g.rtt.get(key) orelse ns_rtt.RttState.unknown;
    const timeout_ms = state.timeout(a.nattempts == 0 and a.next >= a.nservers, transport);
    a.attempts[a.nattempts] = .{ .exchange = try g.exchange(id, key.toAddress(), transport, qname, qtype, timeout_ms), .server = server, .transport = transport };
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
        if (a.ns == null) a.ns = try g.demand(id, try g.keyFor(.ns, zone, .a), zone, g.cell(id).depth) orelse return .none;
        const ns = g.cell(a.ns.?);
        if (!ns.settled) return .pending;
        const names = ns.value.ns.names;
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
                if (g.cell(aid).settled) {
                    // Ours, settled TTL-0 (stale-backed, or failed and
                    // empty): a fact serves its demander.
                    if (g.holdsInput(id, aid)) {
                        try list.appendSlice(g.gpa, g.cell(aid).value.addr.addrs);
                        continue;
                    }
                } else {
                    // In progress for someone: wait, unless it is
                    // transitively waiting on us.
                    if (try g.demand(id, key, host, g.cell(id).depth) != null) pending = true;
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
            const limit: usize = switch (g.cell(id).depth) {
                0 => 3,
                1 => 2,
                else => 1,
            };
            g.edge.rng.shuffle(dns.Name, unknown.items);
            var demanded = false;
            for (unknown.items[0..@min(limit, unknown.items.len)]) |host| {
                const aid = try g.demand(id, try g.keyFor(.addr, host, .a), host, g.cell(id).depth) orelse continue;
                if (!g.cell(aid).settled) demanded = true;
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
