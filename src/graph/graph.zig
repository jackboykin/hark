//! The resolver as a graph of typed DNS facts.
//!
//! A cell is a fact with a TTL: a zone cut, an NS set, a host's addresses,
//! an RRset, or one exchange with a server. A rule settles a cell kind; it
//! runs when the cell is first demanded and again whenever an input settles.
//! Rules are pure over their inputs, scratch, now and rng; the exchange cell
//! is the only impure leaf, settled by the edge.
//!
//! So far: the delegation walk and the chain of trust (trust.zig); one core.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("../dns.zig");
const na = @import("../net_address.zig");
const delegation = @import("../delegation.zig");
const dnssec = @import("../dnssec.zig");
const ns_rtt = @import("../ns_rtt.zig");
const sim = @import("sim.zig");
const trust = @import("trust.zig");

const max_cname_chain = @import("../cache.zig").max_cname_chain;

pub const CellId = u32;

pub const Kind = enum(u8) { cut, ns, addr, rrset, answer, ds, dnskey, secure, exchange };

/// Names are keyed by lowercase presentation form (`Name.formatLower`),
/// which is injective.
pub const Key = struct {
    kind: Kind,
    rtype: dns.RType = .a,
    name: []const u8,

    const Context = struct {
        pub fn hash(_: Context, k: Key) u64 {
            var h = std.hash.Wyhash.init(@backingInt(k.kind));
            h.update(mem.asBytes(&k.rtype));
            h.update(k.name);
            return h.final();
        }
        pub fn eql(_: Context, a: Key, b: Key) bool {
            return a.kind == b.kind and a.rtype == b.rtype and mem.eql(u8, a.name, b.name);
        }
    };
};

pub const Config = struct {
    qmin: bool = true,
    root_hints: []const na.Address,
    addr_policy: delegation.AddrPolicy = .{},
    max_queries: u32 = 100,
    resolve_ms: u32 = 7000,
    /// The hedge stagger before a server has answered; 0: no hedge.
    stagger_ms: u32 = 150,
    max_resolve_depth: u8 = 3,
    max_delegations: u8 = 16,
    max_negative_ttl: u32 = 3 * 3600,
    servfail_ttl: u32 = 5,
    /// Null: DNSSEC off, nothing is judged.
    trust_anchor: ?dns.DsData = null,
    trace: bool = false,
};

// ── Values ─────────────────────────────────────────────────────────────

/// The zone cut above a name, as learned from the parent's servers.
pub const Cut = struct {
    zone: dns.Name,
    /// RFC 9156 relaxed mode: the probe got NXDOMAIN or an error rcode, so
    /// deeper names skip probing and ask in full here.
    stop: bool = false,
    /// Minimised steps so far (`max_minimize_count`).
    probes: u8 = 0,
    /// Every parent server failed the probe.
    failed: bool = false,
};

/// NS names from the parent referral. The root's is empty: hints carry
/// addresses, not names.
pub const Ns = struct { names: []const dns.Name };

pub const Addr = struct {
    addrs: []const na.Address,
    /// Seeded by glue: usable, unverified.
    provisional: bool,
};

/// The RRset at (name, type), as the reply sections that settled it, so
/// the client sees what the authority said.
pub const Reply = struct {
    kind: enum { answer, alias, nodata, nxdomain, servfail },
    rcode: dns.RCode,
    aa: bool,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
    additionals: []const dns.ResourceRecord = &.{},
    /// `.alias` only: where the chain in `answers` ends.
    target: dns.Name = .{ .labels = &.{} },
    /// The zone whose servers answered; what `secure` judges it against.
    zone: dns.Name = .{ .labels = &.{} },
    ede: ?dns.Ede.Code = null,
    /// TTLs age from here.
    stored_ns: i64 = 0,
    /// Seconds the reply stays a fact (`replyTtl`).
    ttl: u32 = 0,
};

/// A client question: the alias chain from `rrset(name, type)` to the
/// RRset that ends it.
pub const Answer = struct {
    /// In chain order; every one but the last is an alias.
    hops: []const CellId,
    /// Looped or outran `max_cname_chain`: served as SERVFAIL.
    broken: bool = false,
    /// The weakest `secure(hop)` verdict; `.unchecked` with DNSSEC off.
    status: dnssec.SecurityStatus = .unchecked,
};

pub const Outcome = union(enum) {
    reply: struct { msg: dns.Message, rtt_ns: i64 },
    timeout,
    /// Wrong id, question or case: a spoof.
    mismatch,
    /// Same name, different bytes: the server mangles case; retry over TCP.
    mangled,
    /// Refused by the root's query budget or deadline.
    budget,
};

pub const Value = union(Kind) {
    cut: Cut,
    ns: Ns,
    addr: Addr,
    rrset: Reply,
    answer: Answer,
    ds: trust.Chain,
    dnskey: trust.Chain,
    secure: trust.Chain,
    exchange: Outcome,
};

pub const Budget = struct {
    queries: u32 = 0,
    deadline_ns: i64 = 0,
};

// ── Scratch ────────────────────────────────────────────────────────────

const max_servers = delegation.max_servers_per_level;

const max_hedge = 3;

const Attempt = struct { exchange: CellId, server: na.Address, transport: sim.Transport };

/// The sibling loop, hedged: the next server starts a stagger after the
/// last or when it ended; what a reply leaves in flight records on its own.
pub const Ask = struct {
    zone: dns.Name = .{ .labels = &.{} },
    have_servers: bool = false,
    servers: [max_servers]na.Address = undefined,
    nservers: u8 = 0,
    order: [max_servers]u8 = undefined,
    next: u8 = 0,
    tried: [max_servers]na.Address = undefined,
    ntried: u8 = 0,
    fetched_unglued: bool = false,
    /// In flight, oldest first.
    attempts: [max_hedge]Attempt = undefined,
    nattempts: u8 = 0,
    /// When the next attempt may start early.
    hedge_at: i64 = 0,
    /// Best failing reply (`delegation.failurePrecedence`), served when
    /// every server fails with an rcode.
    held: ?dns.Message = null,

    const Result = union(enum) {
        pending,
        reply: dns.Message,
        /// No reply from anyone: no rcode to surface.
        exhausted,
    };

    fn hasTried(a: *const Ask, server: na.Address) bool {
        for (a.tried[0..a.ntried]) |t| if (na.ipEqual(t, server)) return true;
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

    /// Referral glue, used before the addr cells whatever its TTL.
    fn seed(a: *Ask, addrs: []const na.Address, rng: std.Random) void {
        a.nservers = @intCast(@min(addrs.len, max_servers));
        @memcpy(a.servers[0..a.nservers], addrs[0..a.nservers]);
        for (0..a.nservers) |i| a.order[i] = @intCast(i);
        rng.shuffle(u8, a.order[0..a.nservers]);
        a.next = 0;
        a.have_servers = a.nservers > 0;
    }

    /// A rank-0 reply (lame, recursor) leaves as bare SERVFAIL so the
    /// randomised server order cannot change what the stub sees.
    fn giveUp(a: *Ask) Result {
        std.debug.assert(a.nattempts == 0);
        var msg = a.held orelse return .exhausted;
        if (delegation.failurePrecedence(msg.header.flags.rcode) == 0) {
            msg.header.flags.rcode = .server_failure;
            msg.answers = &.{};
            msg.authorities = &.{};
            msg.additionals = &.{};
        }
        return .{ .reply = msg };
    }
};

const RrsetScratch = struct {
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

const CutScratch = struct {
    parent: ?CellId = null,
    started: bool = false,
    ask: Ask = .{},
};

/// Inputs are held by id: a version that expires the moment it settles (a
/// non-authoritative denial) still answers the rule that asked for it
/// instead of being re-demanded on every wake.
const AddrScratch = struct {
    /// The NS name, or the target of its one allowed CNAME hop.
    host: ?dns.Name = null,
    hopped: bool = false,
    a: ?CellId = null,
    aaaa: ?CellId = null,
};

const NsScratch = struct {
    cut: ?CellId = null,
};

const AnswerScratch = struct {
    hops: [max_cname_chain + 1]CellId = undefined,
    n: u8 = 0,
    /// `secure(hop)` per hop.
    judged: [max_cname_chain + 1]CellId = undefined,
    nj: u8 = 0,
};

const ExchangeScratch = struct {
    id: u16,
    sent_name: dns.Name,
    qtype: dns.RType,
    server: na.Address,
    transport: sim.Transport,
    sent_ns: i64,
};

pub const Scratch = union(enum) {
    none,
    cut: CutScratch,
    ns: NsScratch,
    addr: AddrScratch,
    rrset: RrsetScratch,
    answer: AnswerScratch,
    ds: trust.DsScratch,
    dnskey: trust.DnskeyScratch,
    secure: trust.SecureScratch,
    exchange: ExchangeScratch,
};

pub const Cell = struct {
    key: Key,
    name: dns.Name,
    settled: bool = false,
    value: Value = undefined,
    expires_ns: i64 = 0,
    waiters: std.ArrayList(CellId) = .empty,
    /// The client demand paying for this cell's exchanges.
    root: CellId,
    /// Demand-chain length through NS-address sub-resolutions.
    depth: u8,
    budget: Budget = .{},
    scratch: Scratch = .none,
};

// ── Graph ──────────────────────────────────────────────────────────────

pub const Graph = struct {
    arena: Allocator,
    gpa: Allocator,
    cfg: Config,
    edge: *sim.Sim,
    /// Cells live in the arena so rule-held pointers survive appends.
    cells: std.ArrayList(*Cell) = .empty,
    index: std.HashMapUnmanaged(Key, CellId, Key.Context, 80) = .empty,
    ready: std.ArrayList(CellId) = .empty,
    /// Per-server estimate; the one state outliving a demand.
    rtt: std.HashMapUnmanaged(na.AddressKey, ns_rtt.RttState, na.AddressKey.HashCtx, 80) = .empty,

    pub fn init(arena: Allocator, gpa: Allocator, cfg: Config, edge: *sim.Sim) !Graph {
        var g: Graph = .{ .arena = arena, .gpa = gpa, .cfg = cfg, .edge = edge };
        // The root cut and NS set are axiomatic.
        const root: dns.Name = .{ .labels = &.{} };
        const cut = try g.newCell(.{ .kind = .cut, .name = "" }, root, 0, 0);
        try g.settle(cut, .{ .cut = .{ .zone = root } }, std.math.maxInt(i64));
        try g.index.put(gpa, g.cell(cut).key, cut);
        const ns = try g.newCell(.{ .kind = .ns, .name = "" }, root, 0, 0);
        try g.settle(ns, .{ .ns = .{ .names = &.{} } }, std.math.maxInt(i64));
        try g.index.put(gpa, g.cell(ns).key, ns);
        return g;
    }

    pub fn deinit(g: *Graph) void {
        for (g.cells.items) |c| c.waiters.deinit(g.gpa);
        g.cells.deinit(g.gpa);
        g.index.deinit(g.gpa);
        g.ready.deinit(g.gpa);
        g.rtt.deinit(g.gpa);
    }

    pub fn now(g: *const Graph) i64 {
        return g.edge.now_ns;
    }

    /// Wall seconds, for signature windows.
    pub fn wallNow(g: *const Graph) u32 {
        return @intCast(g.edge.wall_sec);
    }

    pub fn cell(g: *Graph, id: CellId) *Cell {
        return g.cells.items[id];
    }

    pub fn keyFor(g: *Graph, kind: Kind, name: dns.Name, rtype: dns.RType) !Key {
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        return .{ .kind = kind, .rtype = rtype, .name = try g.arena.dupe(u8, name.formatLower(&buf)) };
    }

    /// A client question: memoised if fresh or in progress, else a new
    /// cell with its own budget.
    pub fn demandRoot(g: *Graph, name: dns.Name, qtype: dns.RType) !CellId {
        const key = try g.keyFor(.answer, name, qtype);
        if (g.lookup(key)) |id| return id;
        const id: CellId = @intCast(g.cells.items.len);
        _ = try g.newCell(key, name, id, 0);
        g.cell(id).budget = .{ .deadline_ns = g.now() + @as(i64, g.cfg.resolve_ms) * std.time.ns_per_ms };
        try g.index.put(g.gpa, key, id);
        try g.ready.append(g.gpa, id);
        return id;
    }

    pub fn drain(g: *Graph) !void {
        while (g.ready.pop()) |id| try g.run(id);
    }

    pub fn complete(g: *Graph, id: CellId, completion: sim.Completion) !void {
        if (completion == .wake) {
            try g.ready.append(g.gpa, id);
            return g.drain();
        }
        const c = g.cell(id);
        const sc = c.scratch.exchange;
        const outcome: Outcome = switch (completion) {
            .wake => unreachable,
            .timeout => .timeout,
            .reply => |bytes| blk: {
                const msg = dns.parseMessage(g.arena, bytes) catch break :blk .mismatch;
                if (msg.header.id != sc.id or !msg.header.flags.qr) break :blk .mismatch;
                dns.validateResponse(msg, sc.sent_name, sc.qtype) catch break :blk .mismatch;
                switch (dns.checkEcho(msg, sc.sent_name, sc.qtype)) {
                    .mismatch => break :blk .mismatch,
                    .mangled => break :blk .mangled,
                    .ok => {},
                }
                // 0x20 case checked; every name is a lowercase fact from here.
                inline for (.{ msg.answers, msg.authorities, msg.additionals }) |section| {
                    for (@constCast(section)) |*rr| {
                        rr.name = try dns.cloneNameLower(g.arena, rr.name);
                        try dns.lowercaseRDataNames(g.arena, &rr.rdata);
                    }
                }
                break :blk .{ .reply = .{ .msg = msg, .rtt_ns = g.now() - sc.sent_ns } };
            },
        };
        if (g.cfg.trace) {
            var ab: [64]u8 = undefined;
            var nb: [dns.max_dotted_len + 1]u8 = undefined;
            std.debug.print("  {s} {s} {t} {t} -> {t}\n", .{ na.format(sc.server, &ab), sc.sent_name.formatInto(&nb), sc.qtype, sc.transport, std.meta.activeTag(outcome) });
            if (outcome == .reply) {
                const m = outcome.reply.msg;
                std.debug.print("      aa={} tc={} ra={} rcode={t} an={d} ns={d} ar={d}\n", .{ m.header.flags.aa, m.header.flags.tc, m.header.flags.ra, m.header.flags.rcode, m.answers.len, m.authorities.len, m.additionals.len });
            }
        }
        // A timeout the root's deadline cut short says nothing about the server.
        switch (outcome) {
            .reply => |r| try g.observe(sc.server, r.rtt_ns),
            .timeout => if (g.now() < g.cell(c.root).budget.deadline_ns) try g.observeTimeout(sc.server),
            else => {},
        }
        try g.settle(id, .{ .exchange = outcome }, g.now());
        try g.drain();
    }

    // ── Cells ──────────────────────────────────────────────────────────

    pub fn newCell(g: *Graph, key: Key, name: dns.Name, root: CellId, depth: u8) !CellId {
        const id: CellId = @intCast(g.cells.items.len);
        const c = try g.arena.create(Cell);
        c.* = .{
            .key = key,
            .name = name,
            .root = root,
            .depth = depth,
            .scratch = switch (key.kind) {
                .cut => .{ .cut = .{} },
                .ns => .{ .ns = .{} },
                .addr => .{ .addr = .{} },
                .rrset => .{ .rrset = .{} },
                .answer => .{ .answer = .{} },
                .ds => .{ .ds = .{} },
                .dnskey => .{ .dnskey = .{} },
                .secure => .{ .secure = .{} },
                .exchange => .none,
            },
        };
        try g.cells.append(g.gpa, c);
        return id;
    }

    pub fn settle(g: *Graph, id: CellId, value: Value, expires_ns: i64) !void {
        const c = g.cell(id);
        c.settled = true;
        c.value = value;
        c.expires_ns = expires_ns;
        try g.ready.appendSlice(g.gpa, c.waiters.items);
        c.waiters.clearRetainingCapacity();
    }

    fn fresh(g: *Graph, id: CellId) bool {
        const c = g.cell(id);
        return c.settled and c.expires_ns > g.now();
    }

    /// The newest fresh or pending version of `key`, if any.
    pub fn lookup(g: *Graph, key: Key) ?CellId {
        const id = g.index.get(key) orelse return null;
        const c = g.cell(id);
        return if (!c.settled or c.expires_ns > g.now()) id else null;
    }

    /// Demand `key` for `by`. Null when `by` already (transitively) feeds
    /// the cell: a cycle, refused before any work.
    pub fn demand(g: *Graph, by: CellId, key: Key, name: dns.Name, depth: u8) !?CellId {
        if (g.lookup(key)) |id| {
            if (g.fresh(id)) return id;
            if (g.reaches(by, id)) return null;
            try g.addWaiter(id, by);
            return id;
        }
        const id = try g.newCell(key, name, g.cell(by).root, depth);
        try g.index.put(g.gpa, key, id);
        try g.ready.append(g.gpa, id);
        try g.addWaiter(id, by);
        return id;
    }

    pub fn addWaiter(g: *Graph, id: CellId, by: CellId) !void {
        const c = g.cell(id);
        for (c.waiters.items) |w| if (w == by) return;
        try c.waiters.append(g.gpa, by);
    }

    /// Does settling `from` transitively wake `target`? Then `from`
    /// demanding `target` would be a cycle.
    fn reaches(g: *Graph, from: CellId, target: CellId) bool {
        var stack: std.ArrayList(CellId) = .empty;
        defer stack.deinit(g.gpa);
        var seen: std.DynamicBitSetUnmanaged = .{};
        defer seen.deinit(g.gpa);
        seen.resize(g.gpa, g.cells.items.len, false) catch return true;
        stack.append(g.gpa, from) catch return true;
        while (stack.pop()) |id| {
            if (id == target) return true;
            if (seen.isSet(id)) continue;
            seen.set(id);
            for (g.cell(id).waiters.items) |w| stack.append(g.gpa, w) catch return true;
        }
        return false;
    }

    /// A settled version that ran no rule: evidence from a referral, or an
    /// authoritative denial at a probe name.
    fn publish(g: *Graph, key: Key, name: dns.Name, by: CellId, value: Value, expires_ns: i64) !CellId {
        if (g.index.get(key)) |id| {
            const c = g.cell(id);
            if (!c.settled) {
                try g.settle(id, value, expires_ns);
                return id;
            }
        }
        const id = try g.newCell(key, name, g.cell(by).root, g.cell(by).depth);
        try g.index.put(g.gpa, key, id);
        try g.settle(id, value, expires_ns);
        return id;
    }

    // ── Rules ──────────────────────────────────────────────────────────

    fn run(g: *Graph, id: CellId) !void {
        if (g.cell(id).settled) return;
        switch (g.cell(id).key.kind) {
            .cut => try g.runCut(id),
            .rrset => try g.runRrset(id),
            .ns => try g.runNs(id),
            .addr => try g.runAddr(id),
            .answer => try g.runAnswer(id),
            .ds => try trust.runDs(g, id),
            .dnskey => try trust.runDnskey(g, id),
            .secure => try trust.runSecure(g, id),
            .exchange => {},
        }
    }

    /// `answer(name, type)`: `rrset(name, type)`, then each alias's target
    /// until an RRset ends the chain. Length and loop checks run at demand
    /// time; a chain that fails them is a resolution failure, a fact for
    /// the SERVFAIL window like any other.
    fn runAnswer(g: *Graph, id: CellId) !void {
        const qtype = g.cell(id).key.rtype;
        const s = &g.cell(id).scratch.answer;
        var next = g.cell(id).name;
        while (true) {
            if (s.n > 0) {
                const last = g.cell(s.hops[s.n - 1]);
                if (!last.settled) return;
                const r = last.value.rrset;
                if (r.kind != .alias or qtype == .cname) break;
                next = r.target;
                var broken = s.n > max_cname_chain;
                for (s.hops[0..s.n]) |h| broken = broken or g.cell(h).name.eql(next);
                if (broken) return g.settle(id, .{ .answer = .{ .hops = try g.arena.dupe(CellId, s.hops[0..s.n]), .broken = true } }, g.failureExpiry(id));
            }
            // Nothing waits on an answer cell, so its demands cannot cycle.
            s.hops[s.n] = try g.demand(id, try g.keyFor(.rrset, next, qtype), next, 0) orelse unreachable;
            s.n += 1;
        }
        var expires: i64 = std.math.maxInt(i64);
        for (s.hops[0..s.n]) |h| expires = @min(expires, g.cell(h).expires_ns);
        var status: dnssec.SecurityStatus = .unchecked;
        if (g.cfg.trust_anchor != null) {
            while (s.nj < s.n) : (s.nj += 1) s.judged[s.nj] = try trust.demandSecure(g, id, s.hops[s.nj]);
            status = .secure;
            for (s.judged[0..s.nj]) |j| {
                const c = g.cell(j);
                if (!c.settled) return;
                status = dnssec.weakest(status, c.value.secure.status);
                expires = @min(expires, c.expires_ns);
            }
            if (status == .bogus) expires = g.failureExpiry(id);
        }
        try g.settle(id, .{ .answer = .{ .hops = try g.arena.dupe(CellId, s.hops[0..s.n]), .status = status } }, expires);
    }

    /// `cut(name)`: from `cut(parent(name))`, probe `name A` at the parent's
    /// servers when minimising; a referral is a deeper cut, anything else
    /// puts the name inside the parent's zone. Only strict ancestors of a
    /// question are probed; the question itself goes out as `rrset`.
    fn runCut(g: *Graph, id: CellId) !void {
        const name = g.cell(id).name;
        std.debug.assert(name.labels.len > 0);
        const parent_name: dns.Name = .{ .labels = name.labels[1..] };
        const s = &g.cell(id).scratch.cut;
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
        if (g.lookup(try g.keyFor(.rrset, name, .a))) |rid| if (g.fresh(rid)) {
            const known = g.cell(rid).value.rrset;
            try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1, .stop = known.kind == .nxdomain } }, @min(parent.expires_ns, g.cell(rid).expires_ns));
            return;
        };
        if (!s.started) {
            s.ask.reset(pc.zone);
            s.started = true;
        }
        switch (try g.ask(id, &g.cell(id).scratch.cut.ask, name, .a)) {
            .pending => return,
            .exhausted => try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1, .failed = true } }, g.now()),
            .reply => |msg| {
                const walk: delegation.Walk = .{ .name = "", .target = name, .zone = pc.zone };
                switch (delegation.probeStep(msg, &walk, g.cfg.addr_policy)) {
                    .referral => |ref| {
                        const expires = try g.absorbReferral(id, ref, msg, pc.zone);
                        try g.settle(id, .{ .cut = .{ .zone = ref.zone_cut, .probes = pc.probes + 1 } }, expires);
                    },
                    .nxdomain, .failed => try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1, .stop = true } }, g.now()),
                    .answered => try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1 } }, parent.expires_ns),
                    .nodata => {
                        // An authoritative denial at the probe name is a
                        // fact. A positive answer is not: the parent may
                        // serve occluded data for a name it delegated
                        // (bailiwick/006).
                        if (msg.header.flags.aa) {
                            const reply = try g.classify(msg, pc.zone, name, .a);
                            _ = try g.publish(try g.keyFor(.rrset, name, .a), name, id, .{ .rrset = reply }, g.replyExpiry(reply));
                        }
                        try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1 } }, parent.expires_ns);
                    },
                }
            },
        }
    }

    /// `ns(zone)`: only a parent referral settles it. Demanding an
    /// unsettled one re-probes the cut, whose referral publishes both.
    fn runNs(g: *Graph, id: CellId) !void {
        const zone = g.cell(id).name;
        const s = &g.cell(id).scratch.ns;
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
    fn runAddr(g: *Graph, id: CellId) !void {
        const depth = g.cell(id).depth + 1;
        if (depth > g.cfg.max_resolve_depth) return g.settle(id, .{ .addr = .{ .addrs = &.{}, .provisional = false } }, g.now());
        const s = &g.cell(id).scratch.addr;
        if (s.host == null) {
            s.host = g.cell(id).name;
            if (g.lookup(try g.keyFor(.rrset, s.host.?, .cname))) |cid| if (g.fresh(cid) and g.cell(cid).value.rrset.kind == .alias) {
                s.host = g.cell(cid).value.rrset.target;
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
        for ([_]dns.RType{ .a, .aaaa }) |rtype| {
            const rid = (if (rtype == .a) s.a else s.aaaa) orelse continue;
            const c = g.cell(rid);
            if (!c.settled) {
                pending = true;
                continue;
            }
            var n: usize = 0;
            switch (c.value.rrset.kind) {
                .answer => for (c.value.rrset.answers) |rr| {
                    if (rr.rtype != rtype or !rr.name.eql(host)) continue;
                    if (g.cfg.addr_policy.address(rr)) |a| {
                        try addrs.append(g.arena, a);
                        n += 1;
                    }
                },
                .alias => if (alias == null) {
                    alias = c.value.rrset.target;
                },
                else => {},
            }
            if (n > 0) expires = @min(expires, c.expires_ns) else denied = @min(denied, c.expires_ns);
        }
        if (pending) return;
        if (addrs.items.len == 0) {
            if (alias) |target| if (!s.hopped) {
                s.* = .{ .host = target, .hopped = true };
                return g.runAddr(id);
            };
            expires = if (denied == std.math.maxInt(i64)) g.now() else denied;
        }
        try g.settle(id, .{ .addr = .{ .addrs = addrs.items, .provisional = false } }, expires);
    }

    /// `rrset(name, type)`: from the deepest known cut at or above the name,
    /// ask its servers; follow referrals; settle on the first kept reply.
    fn runRrset(g: *Graph, id: CellId) !void {
        const name = g.cell(id).name;
        const qtype = g.cell(id).key.rtype;
        const s = &g.cell(id).scratch.rrset;
        if (!s.started) {
            if (s.cut == null) {
                // A cut at the name itself exists only from a referral;
                // otherwise start at the parent's. A DS always lives there.
                const own = try g.keyFor(.cut, name, .a);
                const parent_name: dns.Name = .{ .labels = name.labels[@min(1, name.labels.len)..] };
                const key = if (qtype != .ds and (g.lookup(own) != null or name.labels.len == 0)) own else try g.keyFor(.cut, parent_name, .a);
                const cut_name = if (key.name.ptr == own.name.ptr) name else parent_name;
                s.cut = try g.demand(id, key, cut_name, g.cell(id).depth) orelse
                    return g.settle(id, .{ .rrset = servfail(.no_reachable_authority) }, g.failureExpiry(id));
            }
            const cut = g.cell(s.cut.?);
            if (!cut.settled) return;
            if (cut.value.cut.failed) return g.settle(id, .{ .rrset = servfail(.no_reachable_authority) }, g.failureExpiry(id));
            // RFC 6672: a secure DNAME above the name redirects it, asking nobody.
            if (!s.dname_checked) {
                s.dname_checked = true;
                s.dname = try g.dnameAbove(name);
                if (s.dname) |did| s.dname_judge = try trust.demandSecure(g, id, did);
            }
            if (s.dname_judge) |jid| {
                if (!g.cell(jid).settled) return;
                if (g.cell(jid).value.secure.status == .secure) {
                    const reply = try g.dnameRedirect(name, s.dname.?);
                    return g.settle(id, .{ .rrset = reply }, g.replyExpiry(reply));
                }
            }
            s.ask.reset(cut.value.cut.zone);
            s.started = true;
        }
        while (true) {
            switch (try g.ask(id, &g.cell(id).scratch.rrset.ask, name, qtype)) {
                .pending => return,
                .exhausted => return g.settle(id, .{ .rrset = servfail(.no_reachable_authority) }, g.failureExpiry(id)),
                .reply => |msg| {
                    const zone = g.cell(id).scratch.rrset.ask.zone;
                    if (delegation.extractReferral(msg, name, zone, g.cfg.addr_policy)) |ref| {
                        const s2 = &g.cell(id).scratch.rrset;
                        if (s2.delegations >= g.cfg.max_delegations)
                            return g.settle(id, .{ .rrset = servfail(.no_reachable_authority) }, g.failureExpiry(id));
                        s2.delegations += 1;
                        _ = try g.absorbReferral(id, ref, msg, zone);
                        // The parent's referral to the zone itself is its
                        // answer about the zone's DS (RFC 4035 §3.1.4.1).
                        if (qtype == .ds and ref.zone_cut.eql(name)) {
                            const reply = try trust.referralDs(g, msg, zone, name);
                            return g.settle(id, .{ .rrset = reply }, g.replyExpiry(reply));
                        }
                        s2.ask.reset(ref.zone_cut);
                        s2.ask.seed(ref.addrs[0..ref.addr_count], g.edge.random());
                        continue;
                    }
                    const reply = try g.classify(msg, zone, name, qtype);
                    try g.publishAlias(id, name, qtype, reply);
                    try g.publishDnames(id, reply);
                    return g.settle(id, .{ .rrset = reply }, if (reply.kind == .servfail) g.failureExpiry(id) else g.replyExpiry(reply));
                },
            }
        }
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
        _ = try g.publish(try g.keyFor(.rrset, name, .cname), name, by, .{ .rrset = hop }, g.replyExpiry(hop));
    }

    /// Every DNAME a reply used is the fact `rrset(owner, DNAME)`, signed,
    /// so later names under it redirect from memory.
    fn publishDnames(g: *Graph, by: CellId, reply: Reply) !void {
        for (reply.answers) |d| {
            if (d.rtype != .dname) continue;
            var keep: std.ArrayList(dns.ResourceRecord) = .empty;
            try keep.append(g.arena, d);
            try keepSigs(g, &keep, reply.answers, d.name, .dname);
            const fact: Reply = .{ .kind = .answer, .rcode = .no_error, .aa = reply.aa, .answers = keep.items, .zone = reply.zone, .stored_ns = reply.stored_ns, .ttl = d.ttl };
            _ = try g.publish(try g.keyFor(.rrset, d.name, .dname), d.name, by, .{ .rrset = fact }, g.replyExpiry(fact));
        }
    }

    /// The closest fresh DNAME fact above `name` (RFC 6672 §3.2).
    fn dnameAbove(g: *Graph, name: dns.Name) !?CellId {
        var i: usize = 1;
        while (i < name.labels.len) : (i += 1) {
            const owner: dns.Name = .{ .labels = name.labels[i..] };
            const did = g.lookup(try g.keyFor(.rrset, owner, .dname)) orelse continue;
            if (g.fresh(did) and g.cell(did).value.rrset.kind == .answer) return did;
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
        try keep.appendSlice(g.arena, d.answers);
        if (try dns.substituteSuffix(g.arena, name, dname.name, dname.rdata.dname)) |target| {
            try keep.append(g.arena, .{ .name = name, .rtype = .cname, .rclass = .in, .ttl = dname.ttl, .rdata = .{ .cname = target } });
            return .{ .kind = .alias, .rcode = .no_error, .aa = d.aa, .answers = keep.items, .target = target, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
        }
        // RFC 6672 §3.3: the substituted name is too long; YXDOMAIN.
        return .{ .kind = .servfail, .rcode = .yx_domain, .aa = d.aa, .answers = keep.items, .zone = d.zone, .stored_ns = d.stored_ns, .ttl = d.ttl };
    }

    fn servfail(ede: dns.Ede.Code) Reply {
        return .{ .kind = .servfail, .rcode = .server_failure, .aa = false, .ede = ede };
    }

    /// A failure is a fact only for the client's own question; a
    /// sub-resolution's is retried by the next asker.
    fn failureExpiry(g: *Graph, id: CellId) i64 {
        return g.now() + if (g.cell(id).depth == 0) @as(i64, g.cfg.servfail_ttl) * std.time.ns_per_s else 0;
    }

    /// Publish the child's cut, NS set and glue; returns the delegation's
    /// expiry.
    fn absorbReferral(g: *Graph, by: CellId, ref: delegation.Referral, msg: dns.Message, zone: dns.Name) !i64 {
        var ns_ttl: u32 = std.math.maxInt(u32);
        for (msg.authorities) |rr| if (rr.rtype == .ns and rr.name.eql(ref.zone_cut)) {
            ns_ttl = @min(ns_ttl, rr.ttl);
        };
        const expires = g.now() + @as(i64, ns_ttl) * std.time.ns_per_s;
        const names = try g.arena.dupe(dns.Name, ref.nsNames());
        _ = try g.publish(try g.keyFor(.cut, ref.zone_cut, .a), ref.zone_cut, by, .{ .cut = .{ .zone = ref.zone_cut } }, expires);
        _ = try g.publish(try g.keyFor(.ns, ref.zone_cut, .a), ref.zone_cut, by, .{ .ns = .{ .names = names } }, expires);
        // The parent's word on the child's DS travels with the referral.
        if (g.cfg.trust_anchor != null) {
            const ds = try trust.referralDs(g, msg, zone, ref.zone_cut);
            if (ds.ttl > 0) _ = try g.publish(try g.keyFor(.rrset, ref.zone_cut, .ds), ref.zone_cut, by, .{ .rrset = ds }, g.replyExpiry(ds));
        }
        // Glue: provisional addresses, never displacing a fresh authoritative set.
        for (names[0..ref.glued]) |host| {
            var addrs: std.ArrayList(na.Address) = .empty;
            var ttl: u32 = std.math.maxInt(u32);
            for (msg.additionals) |rr| {
                if (!rr.name.eql(host) or (rr.rtype != .a and rr.rtype != .aaaa)) continue;
                const a = g.cfg.addr_policy.address(rr) orelse continue;
                try addrs.append(g.arena, a);
                ttl = @min(ttl, rr.ttl);
            }
            if (addrs.items.len == 0) continue;
            const key = try g.keyFor(.addr, host, .a);
            if (g.lookup(key)) |existing| if (g.fresh(existing) and !g.cell(existing).value.addr.provisional) continue;
            const glue_expires = @min(expires, g.now() + @as(i64, ttl) * std.time.ns_per_s);
            _ = try g.publish(key, host, by, .{ .addr = .{ .addrs = addrs.items, .provisional = true } }, glue_expires);
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
                    try keep.append(g.arena, rr);
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
                try keep.append(g.arena, d);
                try keepSigs(g, &keep, msg.answers, d.name, .dname);
                if (cname == null) {
                    const target = try dns.substituteSuffix(g.arena, cur, d.name, d.rdata.dname) orelse break;
                    cname = .{ .name = cur, .rtype = .cname, .rclass = .in, .ttl = d.ttl, .rdata = .{ .cname = target } };
                }
            }
            const c = cname orelse break;
            try keep.append(g.arena, c);
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
        reply.ttl = g.replyTtl(reply, zone, name);
        return reply;
    }

    fn keepSigs(g: *Graph, keep: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, owner: dns.Name, covered: dns.RType) !void {
        for (rrs) |rr| if (rr.rtype == .rrsig and rr.name.eql(owner) and (covered == .any or rr.rdata.rrsig.type_covered == covered)) try keep.append(g.arena, rr);
    }

    /// The answer's shortest TTL; for an authoritative denial, min of the
    /// SOA's TTL and MINIMUM (RFC 2308 §3) from an SOA above the name and
    /// inside the zone, nothing otherwise.
    fn replyTtl(g: *Graph, reply: Reply, zone: dns.Name, name: dns.Name) u32 {
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
        return ttl;
    }

    fn replyExpiry(g: *Graph, reply: Reply) i64 {
        _ = g;
        return reply.stored_ns + @as(i64, reply.ttl) * std.time.ns_per_s;
    }

    // ── The sibling loop ───────────────────────────────────────────────

    fn ask(g: *Graph, id: CellId, a: *Ask, qname: dns.Name, qtype: dns.RType) !Ask.Result {
        while (true) {
            if (!a.have_servers) switch (try g.gatherServers(id, a)) {
                .pending => return .pending,
                .none => return a.giveUp(),
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
                        _ = try g.sendTo(id, a, at.server, .tcp, qname, qtype);
                    },
                    .reply => |r| {
                        if (r.msg.header.flags.tc) {
                            // TC over TCP: a broken server, as good as a timeout.
                            if (at.transport == .udp) {
                                _ = try g.sendTo(id, a, at.server, .tcp, qname, qtype);
                            }
                        } else if (!delegation.shouldTrySibling(r.msg, a.zone, g.cfg.addr_policy)) {
                            a.nattempts = 0;
                            return .{ .reply = r.msg };
                        } else delegation.recordFailure(&a.held, r.msg);
                    },
                }
            }
            const early = g.cfg.stagger_ms > 0 and a.nattempts < max_hedge and g.now() >= a.hedge_at;
            if (a.next < a.nservers and (a.nattempts == 0 or early)) {
                const server = a.servers[a.order[a.next]];
                a.next += 1;
                const state = try g.sendTo(id, a, server, .udp, qname, qtype);
                a.hedge_at = g.now() + @as(i64, state.hedgeStagger() orelse g.cfg.stagger_ms) * std.time.ns_per_ms;
                if (g.cfg.stagger_ms > 0 and a.next < a.nservers) try g.edge.wake(id, a.hedge_at);
                continue;
            }
            if (a.nattempts > 0) return .pending;
            // Every known server tried: pay for the unglued names once.
            if (a.fetched_unglued or a.zone.labels.len == 0) return a.giveUp();
            a.have_servers = false;
        }
    }

    /// One attempt on the estimate's timeout; only the last of all is uncapped.
    fn sendTo(g: *Graph, id: CellId, a: *Ask, server: na.Address, transport: sim.Transport, qname: dns.Name, qtype: dns.RType) !ns_rtt.RttState {
        if (!a.hasTried(server) and a.ntried < max_servers) {
            a.tried[a.ntried] = server;
            a.ntried += 1;
        }
        const state = g.rtt.get(na.AddressKey.fromAddress(server)) orelse ns_rtt.RttState.unknown;
        const timeout_ms = state.timeout(a.nattempts == 0 and a.next >= a.nservers, transport);
        a.attempts[a.nattempts] = .{ .exchange = try g.exchange(id, server, transport, qname, qtype, timeout_ms), .server = server, .transport = transport };
        a.nattempts += 1;
        return state;
    }

    fn observe(g: *Graph, server: na.Address, rtt_ns: i64) !void {
        const gop = try g.rtt.getOrPut(g.gpa, na.AddressKey.fromAddress(server));
        if (!gop.found_existing) gop.value_ptr.* = .unknown;
        gop.value_ptr.observe(@divTrunc(rtt_ns, std.time.ns_per_us), g.nowMs());
    }

    fn observeTimeout(g: *Graph, server: na.Address) !void {
        const gop = try g.rtt.getOrPut(g.gpa, na.AddressKey.fromAddress(server));
        if (!gop.found_existing) gop.value_ptr.* = .unknown;
        _ = gop.value_ptr.observeTimeout(g.nowMs());
    }

    fn nowMs(g: *const Graph) i64 {
        return @divTrunc(g.now(), std.time.ns_per_ms);
    }

    fn isDead(g: *Graph, server: na.Address) bool {
        const state = g.rtt.get(na.AddressKey.fromAddress(server)) orelse return false;
        return state.isDead(g.nowMs());
    }

    /// The server set for `a.zone`: hints at the root, else the addresses
    /// already known for the NS names. Only when none are known, or all
    /// have failed, are unglued names resolved, up to a per-depth limit.
    fn gatherServers(g: *Graph, id: CellId, a: *Ask) !enum { pending, none, ready } {
        var list: std.ArrayList(na.Address) = .empty;
        defer list.deinit(g.gpa);
        const zone = a.zone;
        if (zone.labels.len == 0) {
            for (g.cfg.root_hints) |h| if (!a.hasTried(h)) try list.append(g.gpa, h);
        } else {
            const ns_id = try g.demand(id, try g.keyFor(.ns, zone, .a), zone, g.cell(id).depth) orelse return .none;
            const ns = g.cell(ns_id);
            if (!ns.settled) return .pending;
            const names = ns.value.ns.names;
            var unknown: std.ArrayList(dns.Name) = .empty;
            defer unknown.deinit(g.gpa);
            var pending = false;
            for (names) |host| {
                const key = try g.keyFor(.addr, host, .a);
                if (g.lookup(key)) |aid| {
                    const c = g.cell(aid);
                    if (!c.settled) {
                        // In progress for someone: wait, unless it is
                        // transitively waiting on us.
                        if (try g.demand(id, key, host, g.cell(id).depth) != null) pending = true;
                        continue;
                    }
                    try list.appendSlice(g.gpa, c.value.addr.addrs);
                } else try unknown.append(g.gpa, host);
            }
            var i: usize = 0;
            while (i < list.items.len) {
                if (a.hasTried(list.items[i])) _ = list.swapRemove(i) else i += 1;
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
                g.edge.random().shuffle(dns.Name, unknown.items);
                var demanded = false;
                for (unknown.items[0..@min(limit, unknown.items.len)]) |host| {
                    const aid = try g.demand(id, try g.keyFor(.addr, host, .a), host, g.cell(id).depth) orelse continue;
                    if (!g.cell(aid).settled) demanded = true;
                }
                if (demanded) return .pending;
                return g.gatherServers(id, a);
            }
        }
        // Dead servers are skipped unless nothing else is left.
        var live: usize = 0;
        for (list.items) |s| live += @intFromBool(!g.isDead(s));
        if (live > 0) {
            var i: usize = 0;
            while (i < list.items.len) {
                if (g.isDead(list.items[i])) _ = list.swapRemove(i) else i += 1;
            }
        }
        if (list.items.len == 0) return .none;
        a.nservers = @intCast(@min(list.items.len, max_servers));
        @memcpy(a.servers[0..a.nservers], list.items[0..a.nservers]);
        for (0..a.nservers) |i| a.order[i] = @intCast(i);
        g.edge.random().shuffle(u8, a.order[0..a.nservers]);
        a.next = 0;
        a.have_servers = true;
        return .ready;
    }

    // ── Exchanges ──────────────────────────────────────────────────────

    /// One query to one server, charged to the root; `.budget` when the
    /// root's budget or deadline refuses it.
    fn exchange(g: *Graph, by: CellId, server: na.Address, transport: sim.Transport, qname: dns.Name, qtype: dns.RType, timeout_ms: u32) !CellId {
        const root = g.cell(g.cell(by).root);
        const id = try g.newCell(.{ .kind = .exchange, .name = "" }, qname, g.cell(by).root, g.cell(by).depth);
        try g.addWaiter(id, by);
        if (g.now() >= root.budget.deadline_ns or root.budget.queries >= g.cfg.max_queries) {
            try g.settle(id, .{ .exchange = .budget }, g.now());
            return id;
        }
        root.budget.queries += 1;
        const rng = g.edge.random();
        var name_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const qid = rng.int(u16);
        const msg = try dns.buildQuery(g.arena, qid, qname.formatInto(&name_buf), qtype, .{ .rd = false, .edns = .{ .do_bit = g.cfg.trust_anchor != null }, .case_rng = rng });
        var wire_buf: [512]u8 = undefined;
        const wire = try g.arena.dupe(u8, try dns.serializeMessage(&wire_buf, msg));
        g.cell(id).scratch = .{ .exchange = .{
            .id = qid,
            .sent_name = msg.questions[0].name,
            .qtype = qtype,
            .server = server,
            .transport = transport,
            .sent_ns = g.now(),
        } };
        try g.edge.send(.{
            .id = id,
            .server = server,
            .transport = transport,
            .wire = wire,
            .deadline_ns = @min(root.budget.deadline_ns, g.now() + @as(i64, timeout_ms) * std.time.ns_per_ms),
        });
        return id;
    }
};

test "per-cell state has a static bound" {
    // A waiting resolution's scratch is a comptime constant,
    // not a stack. Ask's two address arrays are most of it.
    try std.testing.expect(@sizeOf(Cell) <= 2560);
    try std.testing.expect(@sizeOf(Ask) <= 2048);
}
