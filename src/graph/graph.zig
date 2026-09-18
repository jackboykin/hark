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
const monotonic = @import("../monotonic.zig");
const ns_rtt = @import("../ns_rtt.zig");
const trust = @import("trust.zig");
const denial = @import("denial.zig");
const store = @import("store.zig");

const max_cname_chain = @import("../cache.zig").max_cname_chain;

pub const CellId = u32;

pub const Transport = ns_rtt.Transport;

pub const Exchange = struct {
    id: CellId,
    server: na.Address,
    transport: Transport,
    wire: []const u8,
    deadline_ns: i64,
};

pub const Completion = union(enum) {
    /// Bytes the cell may hold: they are parsed in place.
    reply: []const u8,
    timeout,
    /// The cell asked to run again at this time.
    wake,
};

/// What the graph asks of the world; the simulator and the live edge
/// both implement it.
pub const Edge = struct {
    ctx: *anyopaque,
    now_ns: *const i64,
    wall_sec: *const i64,
    rng: std.Random,
    sendFn: *const fn (*anyopaque, Exchange) anyerror!void,
    wakeFn: *const fn (*anyopaque, CellId, i64) anyerror!void,

    fn send(e: Edge, ex: Exchange) !void {
        return e.sendFn(e.ctx, ex);
    }

    fn wake(e: Edge, id: CellId, at_ns: i64) !void {
        return e.wakeFn(e.ctx, id, at_ns);
    }
};

pub const Kind = enum(u8) { cut, ns, addr, rrset, answer, ds, dnskey, secure, exchange };

/// Names are keyed by lowercase presentation form (`Name.formatLower`),
/// which is injective.
pub const Key = struct {
    kind: Kind,
    rtype: dns.RType = .a,
    name: []const u8,

    pub fn hash(k: Key) u64 {
        var h = std.hash.Wyhash.init(@backingInt(k.kind));
        h.update(mem.asBytes(&k.rtype));
        h.update(k.name);
        return h.final();
    }

    pub fn eql(a: Key, b: Key) bool {
        return a.kind == b.kind and a.rtype == b.rtype and mem.eql(u8, a.name, b.name);
    }

    const Context = struct {
        pub fn hash(_: Context, k: Key) u64 {
            return k.hash();
        }
        pub fn eql(_: Context, a: Key, b: Key) bool {
            return a.eql(b);
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
    /// `secure(hop)` per hop; empty with DNSSEC off.
    judged: []const CellId = &.{},
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

/// Referenced by every cell charged to it.
pub const Budget = struct {
    queries: u32 = 0,
    deadline_ns: i64,
    refs: u32 = 0,
};

/// The model should cost less than a parse.
pub const Tally = struct {
    runs: u64 = 0,
    settles: u64 = 0,
    parses: u64 = 0,
    rule_ns: u64 = 0,
    send_ns: u64 = 0,
    verify_ns: u64 = 0,
    parse_ns: u64 = 0,
    store_ns: u64 = 0,
    reruns: u64 = 0,
    rerun_ns: u64 = 0,

    pub const Clock = struct {
        t0: i128,
        into: *u64,
        pub fn stop(c: Clock) void {
            c.into.* += @intCast(monotonic.nowNs() - c.t0);
        }
    };

    pub fn clock(into: *u64) Clock {
        return .{ .t0 = monotonic.nowNs(), .into = into };
    }
};

// ── Scratch ────────────────────────────────────────────────────────────

const max_servers = delegation.max_servers_per_level;

const max_hedge = 3;

const Attempt = struct { exchange: CellId, server: na.Address, transport: Transport };

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
    judge_a: ?CellId = null,
    judge_aaaa: ?CellId = null,
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
    transport: Transport,
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

/// Alive while pinned, by demanders (`waiters`) or clients and the edge
/// (`holds`). Orphaned, it spends nothing more; freed once nothing holds
/// it and nothing of its own is in flight, its id recycled.
pub const Cell = struct {
    key: Key,
    name: dns.Name,
    live: bool = true,
    settled: bool = false,
    orphan: bool = false,
    value: Value = undefined,
    expires_ns: i64 = 0,
    waiters: std.ArrayList(CellId) = .empty,
    /// Unpinned at settle; an answer's at free.
    inputs: std.ArrayList(CellId) = .empty,
    holds: u32 = 0,
    budget: *Budget,
    /// Demand-chain length through NS-address sub-resolutions.
    depth: u8,
    scratch: Scratch = .none,
    blob: ?*store.Blob = null,
    /// Everything the cell owns; freed with it.
    arena: std.heap.ArenaAllocator,

    fn inFlight(c: *const Cell, g: *Graph) bool {
        for (c.inputs.items) |i| {
            const in = g.cell(i);
            if (in.key.kind == .exchange and !in.settled) return true;
        }
        return false;
    }
};

// ── Graph ──────────────────────────────────────────────────────────────

pub const Graph = struct {
    gpa: Allocator,
    cfg: Config,
    edge: Edge,
    /// One run's transients, reset at every run.
    scratch: std.heap.ArenaAllocator,
    /// Rule-held pointers survive appends; a freed slot is reused.
    cells: std.ArrayList(*Cell) = .empty,
    free_ids: std.ArrayList(CellId) = .empty,
    live: u32 = 0,
    budgets: u32 = 0,
    created: u64 = 0,
    /// Live cells only.
    index: std.HashMapUnmanaged(Key, CellId, Key.Context, 80) = .empty,
    ready: std.ArrayList(CellId) = .empty,
    /// Per-server estimate; the one state outliving a demand.
    rtt: std.HashMapUnmanaged(na.AddressKey, ns_rtt.RttState, na.AddressKey.HashCtx, 80) = .empty,
    tally: Tally = .{},
    /// Verified NSEC facts in span order (denial.zig).
    denial: denial.Index = .{},
    store: store.Store,

    pub fn init(gpa: Allocator, cfg: Config, edge: Edge) !Graph {
        var g: Graph = .{ .gpa = gpa, .cfg = cfg, .edge = edge, .scratch = std.heap.ArenaAllocator.init(gpa), .store = try store.Store.init(gpa) };
        errdefer g.deinit();
        // The root cut and NS set are axiomatic facts.
        const root: dns.Name = .{ .labels = &.{} };
        try g.store.put(.{ .kind = .cut, .name = "" }, try g.store.build(.{ .cut = .{ .zone = root } }), std.math.maxInt(i64));
        try g.store.put(.{ .kind = .ns, .name = "" }, try g.store.build(.{ .ns = .{ .names = &.{} } }), std.math.maxInt(i64));
        return g;
    }

    pub fn deinit(g: *Graph) void {
        for (g.cells.items, 0..) |c, i| if (c.live) g.free(@intCast(i), c) catch {};
        for (g.cells.items) |c| g.gpa.destroy(c);
        g.cells.deinit(g.gpa);
        g.free_ids.deinit(g.gpa);
        g.scratch.deinit();
        g.index.deinit(g.gpa);
        g.ready.deinit(g.gpa);
        g.rtt.deinit(g.gpa);
        g.denial.deinit(g.gpa);
        g.store.deinit();
    }

    pub fn now(g: *const Graph) i64 {
        return g.edge.now_ns.*;
    }

    /// Wall seconds, for signature windows.
    pub fn wallNow(g: *const Graph) u32 {
        return @intCast(g.edge.wall_sec.*);
    }

    pub fn cell(g: *Graph, id: CellId) *Cell {
        return g.cells.items[id];
    }

    pub fn keyFor(g: *Graph, kind: Kind, name: dns.Name, rtype: dns.RType) !Key {
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        return .{ .kind = kind, .rtype = rtype, .name = try g.scratch.allocator().dupe(u8, name.formatLower(&buf)) };
    }

    /// Held for the client until `unhold`. A failed answer is memoised for
    /// its SERVFAIL window, not for a client with CD, who is owed the data.
    pub fn demandRoot(g: *Graph, name: dns.Name, qtype: dns.RType, cd: bool) !CellId {
        const key = try g.keyFor(.answer, name, qtype);
        if (g.index.get(key)) |id| if (!g.cell(id).settled or g.fresh(id)) {
            g.cell(id).holds += 1;
            return id;
        };
        const budget = try g.gpa.create(Budget);
        errdefer g.gpa.destroy(budget);
        budget.* = .{ .deadline_ns = g.now() + @as(i64, g.cfg.resolve_ms) * std.time.ns_per_ms };
        const memo = if (cd) null else g.store.get(key, g.now());
        const id = if (memo) |e| try g.materialise(key, name, budget, e) else try g.newCell(key, name, budget, 0);
        g.budgets += 1;
        g.cell(id).holds += 1;
        if (memo == null) try g.ready.append(g.gpa, id);
        return id;
    }

    pub fn unhold(g: *Graph, id: CellId) void {
        g.cell(id).holds -= 1;
        g.release(id);
    }

    pub fn drain(g: *Graph) !void {
        while (g.ready.pop()) |id| try g.run(id);
    }

    pub fn complete(g: *Graph, id: CellId, completion: Completion) !void {
        if (completion == .wake) {
            try g.ready.append(g.gpa, id);
            return g.drain();
        }
        const c = g.cell(id);
        std.debug.assert(c.live and c.key.kind == .exchange);
        const sc = c.scratch.exchange;
        const arena = c.arena.allocator();
        const outcome: Outcome = switch (completion) {
            .wake => unreachable,
            .timeout => .timeout,
            .reply => |borrowed| blk: {
                const clock = Tally.clock(&g.tally.parse_ns);
                defer clock.stop();
                g.tally.parses += 1;
                const bytes = try arena.dupe(u8, borrowed);
                const msg = dns.parseMessage(arena, bytes) catch break :blk .mismatch;
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
                        rr.name = try dns.cloneNameLower(arena, rr.name);
                        try dns.lowercaseRDataNames(arena, &rr.rdata);
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
            .timeout => if (g.now() < c.budget.deadline_ns) try g.observeTimeout(sc.server),
            else => {},
        }
        c.holds -= 1;
        try g.settle(id, .{ .exchange = outcome }, g.now());
        try g.drain();
    }

    // ── Cells ──────────────────────────────────────────────────────────

    pub fn newCell(g: *Graph, key: Key, name: dns.Name, budget: *Budget, depth: u8) !CellId {
        const reused = g.free_ids.pop();
        const id: CellId = reused orelse @intCast(g.cells.items.len);
        const c = if (reused != null) g.cells.items[id] else try g.gpa.create(Cell);
        errdefer if (reused == null) g.gpa.destroy(c);
        var arena = std.heap.ArenaAllocator.init(g.gpa);
        errdefer arena.deinit();
        c.* = .{
            .key = .{ .kind = key.kind, .rtype = key.rtype, .name = try arena.allocator().dupe(u8, key.name) },
            .name = try dns.cloneNameFlat(arena.allocator(), name, false),
            .budget = budget,
            .depth = depth,
            .arena = arena,
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
        if (reused == null) try g.cells.append(g.gpa, c);
        if (key.kind != .exchange) try g.index.put(g.gpa, c.key, id);
        budget.refs += 1;
        g.live += 1;
        g.created += 1;
        return id;
    }

    // ── Pins ───────────────────────────────────────────────────────────

    pub fn pin(g: *Graph, id: CellId, by: CellId) !void {
        const c = g.cell(id);
        for (c.waiters.items) |w| if (w == by) return;
        try c.waiters.append(g.gpa, by);
        try g.cell(by).inputs.append(g.gpa, id);
        if (c.orphan and !g.cell(by).orphan) g.adopt(id);
    }

    fn unpin(g: *Graph, id: CellId, by: CellId) void {
        const c = g.cell(id);
        for (c.waiters.items, 0..) |w, i| if (w == by) {
            _ = c.waiters.swapRemove(i);
            break;
        };
        g.release(id);
    }

    fn pins(g: *Graph, id: CellId) u32 {
        const c = g.cell(id);
        var n = c.holds;
        for (c.waiters.items) |w| n += @intFromBool(!g.cell(w).orphan);
        return n;
    }

    /// Nothing live pins it: an orphan, and so is everything it waits on.
    fn release(g: *Graph, id: CellId) void {
        const c = g.cell(id);
        if (!c.live or g.pins(id) > 0) return;
        if (!c.orphan) {
            c.orphan = true;
            for (c.inputs.items) |i| g.release(i);
        }
        if (c.holds == 0 and c.waiters.items.len == 0 and (c.settled or !c.inFlight(g))) g.free(id, c) catch {};
    }

    fn adopt(g: *Graph, id: CellId) void {
        const c = g.cell(id);
        if (!c.orphan) return;
        c.orphan = false;
        for (c.inputs.items) |i| g.adopt(i);
    }

    fn free(g: *Graph, id: CellId, c: *Cell) !void {
        std.debug.assert(c.live);
        c.live = false;
        g.live -= 1;
        for (c.inputs.items) |i| g.unpin(i, id);
        c.inputs.deinit(g.gpa);
        c.waiters.deinit(g.gpa);
        if (c.blob) |b| g.store.unref(b);
        if (g.index.get(c.key)) |i| if (i == id) {
            _ = g.index.remove(c.key);
        };
        c.budget.refs -= 1;
        if (c.budget.refs == 0) {
            g.gpa.destroy(c.budget);
            g.budgets -= 1;
        }
        c.arena.deinit();
        c.arena = std.heap.ArenaAllocator.init(g.gpa);
        try g.free_ids.append(g.gpa, id);
    }

    /// Copies out: the value becomes the blob's parse, the blob the store's
    /// version while fresh; a verdict is stamped on the bytes it judged.
    pub fn settle(g: *Graph, id: CellId, value: Value, expires_ns: i64) !void {
        const c = g.cell(id);
        std.debug.assert(!c.settled);
        g.tally.settles += 1;
        if (g.cfg.trace) switch (value) {
            .ds, .dnskey, .secure => |chain| {
                var nb: [dns.max_dotted_len + 1]u8 = undefined;
                std.debug.print("  {t}({s}) -> {t} for {d} s\n", .{ std.meta.activeTag(value), c.name.formatInto(&nb), chain.status, @divTrunc(expires_ns - g.now(), std.time.ns_per_s) });
            },
            else => {},
        };
        c.settled = true;
        c.value = value;
        c.expires_ns = expires_ns;
        switch (value) {
            .cut, .ns, .addr, .rrset, .ds, .dnskey => {
                const clock = Tally.clock(&g.tally.store_ns);
                defer clock.stop();
                const blob = try g.store.build(value);
                c.blob = blob;
                c.value = try store.Store.parse(c.arena.allocator(), blob);
                if (expires_ns > g.now()) try g.store.put(c.key, blob.ref(), expires_ns);
            },
            .secure => |v| if (g.cell(c.scratch.secure.target).blob) |b| b.verdict.stamp(v, expires_ns),
            .answer => |a| if (a.broken or a.status == .bogus) try g.fact(c.key, value, expires_ns),
            .exchange => {},
        }
        try g.ready.appendSlice(g.gpa, c.waiters.items);
        // An answer serves from its hops; everything else has copied out.
        if (value != .answer) {
            for (c.inputs.items) |i| g.unpin(i, id);
            c.inputs.clearRetainingCapacity();
        }
        g.release(id);
    }

    pub fn fresh(g: *Graph, id: CellId) bool {
        const c = g.cell(id);
        return c.settled and c.expires_ns > g.now();
    }

    /// In progress, or settled and fresh; a store hit is materialised,
    /// unpinned.
    fn lookup(g: *Graph, key: Key, name: dns.Name, budget: *Budget) !?CellId {
        const live = g.index.get(key);
        if (live) |id| if (!g.cell(id).settled) return id;
        if (g.store.get(key, g.now())) |e| {
            if (live) |id| if (g.cell(id).blob == e.blob) return id;
            return try g.materialise(key, name, budget, e);
        }
        if (live) |id| if (g.cell(id).expires_ns > g.now()) return id;
        return null;
    }

    fn materialise(g: *Graph, key: Key, name: dns.Name, budget: *Budget, e: store.Entry) !CellId {
        const id = try g.newCell(key, name, budget, 0);
        const c = g.cell(id);
        c.settled = true;
        c.blob = e.blob.ref();
        c.value = try store.Store.parse(c.arena.allocator(), e.blob);
        c.expires_ns = e.expires_ns;
        return id;
    }

    pub const Fact = struct { value: Value, expires_ns: i64 };

    /// No cell, no wait: `demand` is the only pin.
    pub fn peek(g: *Graph, key: Key) !?Fact {
        const live = g.index.get(key);
        if (g.store.get(key, g.now())) |e| {
            if (live) |id| if (g.cell(id).blob == e.blob) return .{ .value = g.cell(id).value, .expires_ns = e.expires_ns };
            return .{ .value = try store.Store.parse(g.scratch.allocator(), e.blob), .expires_ns = e.expires_ns };
        }
        if (live) |id| if (g.fresh(id)) return .{ .value = g.cell(id).value, .expires_ns = g.cell(id).expires_ns };
        return null;
    }

    /// Null on a cycle, or on new work for an orphan.
    pub fn demand(g: *Graph, by: CellId, key: Key, name: dns.Name, depth: u8) !?CellId {
        if (try g.lookup(key, name, g.cell(by).budget)) |id| {
            if (!g.fresh(id) and g.reaches(by, id)) return null;
            try g.pin(id, by);
            return id;
        }
        if (g.cell(by).orphan) return null;
        const id = try g.newCell(key, name, g.cell(by).budget, depth);
        try g.ready.append(g.gpa, id);
        try g.pin(id, by);
        return id;
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

    /// Evidence from a referral or a denial at a probe name: settles a
    /// cell in progress for the key, except the publisher's own; else a fact.
    pub fn publish(g: *Graph, key: Key, by: CellId, value: Value, expires_ns: i64) !void {
        if (g.index.get(key)) |id| if (id != by and !g.cell(id).settled) return g.settle(id, value, expires_ns);
        try g.fact(key, value, expires_ns);
    }

    fn fact(g: *Graph, key: Key, value: Value, expires_ns: i64) !void {
        if (expires_ns <= g.now()) return;
        const blob = try g.store.build(value);
        errdefer g.store.unref(blob);
        try g.store.put(key, blob, expires_ns);
    }

    // ── Rules ──────────────────────────────────────────────────────────

    /// Held for the run: what it publishes may settle and free its own
    /// readers while the rule still has the cell in hand.
    fn run(g: *Graph, id: CellId) !void {
        const c = g.cell(id);
        if (!c.live or c.settled) return;
        c.holds += 1;
        defer {
            c.holds -= 1;
            g.release(id);
        }
        _ = g.scratch.reset(.retain_capacity);
        g.tally.runs += 1;
        const clock = Tally.clock(&g.tally.rule_ns);
        defer clock.stop();
        // Ended waiting and created nothing: the model's own cost.
        const created_before = g.created;
        defer if (g.cell(id).live and !g.cell(id).settled and g.created == created_before) {
            g.tally.reruns += 1;
            g.tally.rerun_ns += @intCast(monotonic.nowNs() - clock.t0);
        };
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
                if (broken) return g.settle(id, .{ .answer = .{ .hops = try g.cell(id).arena.allocator().dupe(CellId, s.hops[0..s.n]), .broken = true } }, g.failureExpiry(id));
            }
            // Nothing waits on an answer, so only an orphaned root is refused.
            s.hops[s.n] = try g.demand(id, try g.keyFor(.rrset, next, qtype), next, 0) orelse
                return g.settle(id, .{ .answer = .{ .hops = try g.cell(id).arena.allocator().dupe(CellId, s.hops[0..s.n]), .broken = true } }, g.now());
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
        const arena = g.cell(id).arena.allocator();
        try g.settle(id, .{ .answer = .{ .hops = try arena.dupe(CellId, s.hops[0..s.n]), .status = status, .judged = try arena.dupe(CellId, s.judged[0..s.nj]) } }, expires);
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
        if (try g.peek(try g.keyFor(.rrset, name, .a))) |known| {
            try g.settle(id, .{ .cut = .{ .zone = pc.zone, .probes = pc.probes + 1, .stop = known.value.rrset.kind == .nxdomain } }, @min(parent.expires_ns, known.expires_ns));
            return;
        }
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
                            try g.publish(try g.keyFor(.rrset, name, .a), id, .{ .rrset = reply }, g.replyExpiry(reply));
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
        for ([_]dns.RType{ .a, .aaaa }) |rtype| {
            const rid = (if (rtype == .a) s.a else s.aaaa) orelse continue;
            const c = g.cell(rid);
            if (!c.settled) {
                pending = true;
                continue;
            }
            var n: usize = 0;
            const r = c.value.rrset;
            if (r.kind == .answer or r.kind == .alias) {
                // A bogus answer is no address.
                if (g.cfg.trust_anchor != null) {
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
            if (n > 0) expires = @min(expires, c.expires_ns) else denied = @min(denied, c.expires_ns);
        }
        if (pending) return;
        if (addrs.items.len == 0) {
            if (alias) |target| if (!s.hopped) {
                s.* = .{ .host = try dns.cloneNameFlat(g.cell(id).arena.allocator(), target, false), .hopped = true };
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
                // Indexed proofs deny the name without a packet.
                if (try denial.deny(g, id)) return;
                // A cut at the name itself exists only from a referral;
                // otherwise start at the parent's. A DS always lives there.
                const own = try g.keyFor(.cut, name, .a);
                const parent_name: dns.Name = .{ .labels = name.labels[@min(1, name.labels.len)..] };
                const key = if (qtype != .ds and (try g.peek(own) != null or name.labels.len == 0)) own else try g.keyFor(.cut, parent_name, .a);
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
                if (try g.dnameAbove(name)) |owner| s.dname = try g.demand(id, try g.keyFor(.rrset, owner, .dname), owner, g.cell(id).depth);
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
                        s2.ask.seed(ref.addrs[0..ref.addr_count], g.edge.rng);
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
        try g.publish(try g.keyFor(.rrset, name, .cname), by, .{ .rrset = hop }, g.replyExpiry(hop));
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
            try g.publish(try g.keyFor(.rrset, d.name, .dname), by, .{ .rrset = dname }, g.replyExpiry(dname));
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
        const names = try g.scratch.allocator().dupe(dns.Name, ref.nsNames());
        try g.publish(try g.keyFor(.cut, ref.zone_cut, .a), by, .{ .cut = .{ .zone = ref.zone_cut } }, expires);
        try g.publish(try g.keyFor(.ns, ref.zone_cut, .a), by, .{ .ns = .{ .names = names } }, expires);
        // The parent's word on the child's DS travels with the referral.
        if (g.cfg.trust_anchor != null) {
            const ds = try trust.referralDs(g, msg, zone, ref.zone_cut);
            if (ds.ttl > 0) try g.publish(try g.keyFor(.rrset, ref.zone_cut, .ds), by, .{ .rrset = ds }, g.replyExpiry(ds));
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
        reply.ttl = g.replyTtl(reply, zone, name);
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

    pub fn replyExpiry(g: *Graph, reply: Reply) i64 {
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
    fn sendTo(g: *Graph, id: CellId, a: *Ask, server: na.Address, transport: Transport, qname: dns.Name, qtype: dns.RType) !ns_rtt.RttState {
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
                if (try g.peek(key)) |known| {
                    try list.appendSlice(g.gpa, known.value.addr.addrs);
                    continue;
                }
                if (g.index.get(key)) |aid| if (!g.cell(aid).settled) {
                    // In progress for someone: wait, unless it is
                    // transitively waiting on us.
                    if (try g.demand(id, key, host, g.cell(id).depth) != null) pending = true;
                    continue;
                };
                try unknown.append(g.gpa, host);
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
                g.edge.rng.shuffle(dns.Name, unknown.items);
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
        g.edge.rng.shuffle(u8, a.order[0..a.nservers]);
        a.next = 0;
        a.have_servers = true;
        return .ready;
    }

    // ── Exchanges ──────────────────────────────────────────────────────

    /// `.budget` when the asker's budget, deadline or orphaning refuses it.
    fn exchange(g: *Graph, by: CellId, server: na.Address, transport: Transport, qname: dns.Name, qtype: dns.RType, timeout_ms: u32) !CellId {
        const budget = g.cell(by).budget;
        const id = try g.newCell(.{ .kind = .exchange, .name = "" }, qname, budget, g.cell(by).depth);
        try g.pin(id, by);
        if (g.cell(by).orphan or g.now() >= budget.deadline_ns or budget.queries >= g.cfg.max_queries) {
            try g.settle(id, .{ .exchange = .budget }, g.now());
            return id;
        }
        budget.queries += 1;
        g.cell(id).holds += 1;
        const clock = Tally.clock(&g.tally.send_ns);
        defer clock.stop();
        const rng = g.edge.rng;
        var name_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const qid = rng.int(u16);
        const arena = g.cell(id).arena.allocator();
        const msg = try dns.buildQuery(arena, qid, qname.formatInto(&name_buf), qtype, .{ .rd = false, .edns = .{ .do_bit = g.cfg.trust_anchor != null }, .case_rng = rng });
        var wire_buf: [512]u8 = undefined;
        const wire = try arena.dupe(u8, try dns.serializeMessage(&wire_buf, msg));
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
            .deadline_ns = @min(budget.deadline_ns, g.now() + @as(i64, timeout_ms) * std.time.ns_per_ms),
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
