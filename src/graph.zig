//! The resolver as a graph of typed DNS facts.
//!
//! A cell is a fact with a TTL: a zone cut, an NS set, a host's addresses,
//! an RRset, or one exchange with a server; or a failure, which is none.
//! A rule settles a cell kind; it runs when the cell is first demanded and
//! again whenever an input settles.
//! Rules are pure over their inputs, scratch, now and rng; the exchange cell
//! is the only impure leaf, settled by the edge.
//!
//! The rules live beside it: the delegation walk in walk.zig, the chain of
//! trust in trust.zig, aggressive denial in denial.zig; one core.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const delegation = @import("delegation.zig");
const dnssec = @import("dnssec.zig");
const monotonic = @import("monotonic.zig");
const ns_rtt = @import("ns_rtt.zig");
const trust = @import("trust.zig");
const denial = @import("denial.zig");
const store = @import("store.zig");
const walk = @import("walk.zig");

/// Hops an answer may follow. Clears 8-hop CDN chains; matches PowerDNS and Hickory.
pub const max_cname_chain = 16;

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
    /// Run again at this time; carries the cell's generation, since ids recycle.
    wake: u32,
};

/// What the graph asks of the world; the simulator and the live edge
/// both implement it.
pub const Edge = struct {
    ctx: *anyopaque,
    now_ns: *const i64,
    wall_sec: *const i64,
    rng: std.Random,
    sendFn: *const fn (*anyopaque, Exchange) anyerror!void,
    wakeFn: *const fn (*anyopaque, CellId, u32, i64) anyerror!void,

    pub fn send(e: Edge, ex: Exchange) !void {
        return e.sendFn(e.ctx, ex);
    }

    pub fn wake(e: Edge, id: CellId, gen: u32, at_ns: i64) !void {
        return e.wakeFn(e.ctx, id, gen, at_ns);
    }
};

/// `refresh`: `answer` derived again for the store; nobody waits.
pub const Kind = enum(u8) { cut, ns, addr, rrset, answer, ds, dnskey, secure, exchange, refresh };

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
    /// Resolutions, or exchanges, in flight at once; a client past either is turned away.
    max_in_flight: u32 = 1024,
    max_delegations: u8 = 16,
    max_negative_ttl: u32 = 3 * 3600,
    /// The first window a failure is remembered: by the server per
    /// question, by trust per zone (RFC 9520 §3.2).
    servfail_ttl: u32 = 5,
    /// Serve an expired fact this long past expiry while its refresh fails; 0: never.
    serve_stale_ttl: u32 = 0,
    /// Floor for every TTL but zero (`walk.replyTtl`).
    min_ttl: u32 = 0,
    /// Refresh a fact hit just before it expires.
    prefetch: bool = false,
    /// Null: DNSSEC off, nothing is judged.
    trust_anchor: ?dns.DsData = null,
    store_bytes: usize = 12 << 20,
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
    /// The referral's glue: asked before the addr cells, whatever its TTL.
    addrs: []const na.Address = &.{},
};

/// NS names from the parent referral. The root has none: hints carry
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
    kind: enum { answer, alias, nodata, nxdomain, yxdomain },
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
    /// `secure(hop)` per hop, held; empty with DNSSEC off or served stale.
    judged: []const CellId = &.{},
    /// Per hop, a stale stand-in for a failed one; this cell's alone.
    stale: []const ?*const Reply = &.{},
};

pub const Outcome = union(enum) {
    reply: struct { msg: dns.Message, rtt_ns: i64 },
    timeout,
    /// Wrong id, question or case: a spoof.
    mismatch,
    /// Same name, different bytes: the server mangles case; retry over TCP.
    mangled,
};

/// Why a cell settled on no fact: nothing about the DNS, so it is never
/// stored and expires as it settles. Its demanders read it; the next
/// demand starts afresh, and remembering it is the server's policy.
pub const Failure = struct {
    code: dns.Ede.Code,
    text: []const u8 = "",
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
    refresh: void,
};

/// Referenced by every cell charged to it.
pub const Budget = struct {
    queries: u32 = 0,
    deadline_ns: i64,
    refs: u32 = 0,
    /// When a refresh began; 0 for a client.
    refresh_ns: i64 = 0,
    /// KeyTrap: every verify the resolution does, whichever cell does it.
    validation: dnssec.ValidationBudget = .{},
};

/// Cumulative since start; `serve.zig` prints them.
pub const Stats = struct {
    clients: struct { udp: u64 = 0, tcp: u64 = 0, nxdomain: u64 = 0, servfail: u64 = 0, refused: u64 = 0, other: u64 = 0, dropped: u64 = 0, abandoned: u64 = 0, hit: u64 = 0, miss: u64 = 0, stale: u64 = 0 } = .{},
    resolver: struct { udp: u64 = 0, tcp: u64 = 0, timeout: u64 = 0, retry: u64 = 0, refresh: u64 = 0, refused: u64 = 0 } = .{},
    trust: struct { secure: u64 = 0, insecure: u64 = 0, bogus: u64 = 0 } = .{},
};

const max_failed = 4096;

const Refusal = struct { until_ns: i64, why: Failure };

/// BIND's `prefetch 2`.
pub const refresh_window_ns = 2 * std.time.ns_per_s;
/// So a refresh does not time the client.
const refresh_jitter_ns = std.time.ns_per_s;

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
    /// Cycle checks, and cells they walked.
    reaches: u64 = 0,
    reaches_visits: u64 = 0,

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

const ExchangeScratch = struct {
    id: u16,
    sent_name: dns.Name,
    qtype: dns.RType,
    server: na.Address,
    transport: Transport,
    sent_ns: i64,
};

/// In the cell's arena: a cell pays for its own kind's, not the largest.
pub const Scratch = union(enum) {
    none,
    cut: *walk.CutScratch,
    ns: *walk.NsScratch,
    addr: *walk.AddrScratch,
    rrset: *walk.RrsetScratch,
    answer: *walk.AnswerScratch,
    ds: *trust.DsScratch,
    dnskey: *trust.DnskeyScratch,
    secure: *trust.SecureScratch,
    exchange: *ExchangeScratch,

    fn init(kind: Kind, arena: Allocator) !Scratch {
        return switch (kind) {
            .exchange => .none,
            .refresh => init(.answer, arena),
            inline else => |k| blk: {
                const p = try arena.create(@typeInfo(@FieldType(Scratch, @tagName(k))).pointer.child);
                p.* = .{};
                break :blk @unionInit(Scratch, @tagName(k), p);
            },
        };
    }
};

/// Alive while pinned, by demanders (`waiters`) or clients and the edge
/// (`holds`). Orphaned, it spends nothing more; freed once nothing holds
/// it and nothing of its own is in flight, its id recycled.
pub const Cell = struct {
    key: Key,
    name: dns.Name,
    live: bool = true,
    orphan: bool = false,
    /// Bumped each time the slot is reused.
    gen: u32 = 0,
    /// The cycle check that last walked through here.
    seen: u64 = 0,
    state: State = .pending,
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

    pub const State = union(enum) { pending, fact: Value, failure: Failure };

    pub fn settled(c: *const Cell) bool {
        return c.state != .pending;
    }

    pub fn failure(c: *const Cell) ?Failure {
        return if (c.state == .failure) c.state.failure else null;
    }

    fn inFlight(c: *const Cell, g: *Graph) bool {
        for (c.inputs.items) |i| {
            const in = g.cell(i);
            if (in.key.kind == .exchange and !in.settled()) return true;
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
    checks: u64 = 0,
    live: u32 = 0,
    budgets: u32 = 0,
    /// Exchanges the edge holds.
    flights: u32 = 0,
    /// Work that failed, refused at `demand` rather than tried again
    /// (RFC 9520 §3.2): an upstream fetch, a zone's DS or keys. Policy,
    /// outside cells.
    failed: std.HashMapUnmanaged(Key, Refusal, Key.Context, 80) = .empty,
    stats: Stats = .{},
    created: u64 = 0,
    /// Live cells only.
    index: std.HashMapUnmanaged(Key, CellId, Key.Context, 80) = .empty,
    ready: std.ArrayList(CellId) = .empty,
    /// Per-server estimate, capped; the one state outliving a demand.
    rtt: std.HashMapUnmanaged(na.AddressKey, ns_rtt.RttState, na.AddressKey.HashCtx, 80) = .empty,
    tally: Tally = .{},
    /// Verified NSEC facts in span order (denial.zig).
    denial: denial.Index = .{},
    store: store.Store,

    pub fn init(gpa: Allocator, cfg: Config, edge: Edge) !Graph {
        var g: Graph = .{ .gpa = gpa, .cfg = cfg, .edge = edge, .scratch = std.heap.ArenaAllocator.init(gpa), .store = try store.Store.init(gpa, cfg.store_bytes) };
        errdefer g.deinit();
        // The root cut is an axiom; `runCut` re-derives it if evicted.
        try g.fact(.{ .kind = .cut, .name = "" }, .{ .cut = .{ .zone = .{ .labels = &.{} } } }, std.math.maxInt(i64));
        return g;
    }

    /// Pins the graph's address.
    pub fn attach(g: *Graph) void {
        g.store.on_evict = .{ .ctx = g, .f = evictedErased };
    }

    fn evictedErased(ctx: *anyopaque, key: Key) void {
        const g: *Graph = @ptrCast(@alignCast(ctx));
        denial.evicted(g, key);
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
        var it = g.failed.keyIterator();
        while (it.next()) |k| g.gpa.free(k.name);
        g.failed.deinit(g.gpa);
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

    /// Held for the client until `unhold`. Null: new work past
    /// `max_in_flight`, or anything unsettled for a caller that cannot `wait`.
    pub fn demandRoot(g: *Graph, name: dns.Name, qtype: dns.RType, wait: bool) !?CellId {
        const key = try g.keyFor(.answer, name, qtype);
        if (g.index.get(key)) |id| if (!g.cell(id).settled() or g.fresh(id)) {
            if (!wait and !g.cell(id).settled()) {
                g.stats.clients.dropped += 1;
                return null;
            }
            g.cell(id).holds += 1;
            return id;
        };
        if (!wait or g.budgets >= g.cfg.max_in_flight or g.flights >= g.cfg.max_in_flight) {
            g.stats.clients.dropped += 1;
            return null;
        }
        const budget = try g.gpa.create(Budget);
        budget.* = .{ .deadline_ns = g.now() + @as(i64, g.cfg.resolve_ms) * std.time.ns_per_ms };
        const id = try g.newCell(key, name, budget, 0);
        g.cell(id).holds += 1;
        errdefer g.unhold(id);
        try g.ready.append(g.gpa, id);
        return id;
    }

    pub fn unhold(g: *Graph, id: CellId) void {
        g.cell(id).holds -= 1;
        g.release(id);
    }

    /// One per key at a time; holds itself until it settles.
    pub fn refresh(g: *Graph, key: Key, name: dns.Name) !void {
        const rkey: Key = .{ .kind = .refresh, .rtype = key.rtype, .name = key.name };
        if (g.index.contains(rkey)) return;
        if (g.budgets >= g.cfg.max_in_flight / 2 or g.flights >= g.cfg.max_in_flight / 2) {
            g.stats.resolver.refused += 1;
            return;
        }
        const budget = try g.gpa.create(Budget);
        const at = g.now() + g.edge.rng.intRangeLessThan(i64, 0, refresh_jitter_ns);
        budget.* = .{ .deadline_ns = 0, .refresh_ns = g.now() };
        const id = try g.newCell(rkey, name, budget, 0);
        g.cell(id).holds += 1;
        errdefer g.unhold(id);
        try g.wake(id, at);
        g.stats.resolver.refresh += 1;
        if (g.cfg.trace) std.debug.print("  refresh {s} {t} in {d} ms\n", .{ key.name, key.rtype, @divTrunc(at - g.now(), std.time.ns_per_ms) });
    }

    pub fn drain(g: *Graph) !void {
        while (g.ready.pop()) |id| try g.run(id);
    }

    pub fn wake(g: *Graph, id: CellId, at_ns: i64) !void {
        return g.edge.wake(id, g.cell(id).gen, at_ns);
    }

    pub fn complete(g: *Graph, id: CellId, completion: Completion) !void {
        if (completion == .wake) {
            if (g.cell(id).gen == completion.wake) {
                // A refresh's budget runs from its first wake.
                if (g.cell(id).key.kind == .refresh and g.cell(id).budget.deadline_ns == 0) g.cell(id).budget.deadline_ns = g.now() + @as(i64, g.cfg.resolve_ms) * std.time.ns_per_ms;
                try g.ready.append(g.gpa, id);
            }
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
            .timeout => {
                g.stats.resolver.timeout += 1;
                if (g.now() < c.budget.deadline_ns) try g.observeTimeout(sc.server);
            },
            else => {},
        }
        c.holds -= 1;
        g.flights -= 1;
        try g.settle(id, .{ .exchange = outcome }, g.now());
        try g.drain();
    }

    // ── Cells ──────────────────────────────────────────────────────────

    /// Owns `budget` from the call; all or nothing.
    pub fn newCell(g: *Graph, key: Key, name: dns.Name, budget: *Budget, depth: u8) !CellId {
        errdefer if (budget.refs == 0) g.gpa.destroy(budget);
        const reused = g.free_ids.pop();
        errdefer if (reused) |r| g.free_ids.appendAssumeCapacity(r);
        const id: CellId = reused orelse @intCast(g.cells.items.len);
        const c = if (reused != null) g.cells.items[id] else try g.gpa.create(Cell);
        errdefer if (reused == null) g.gpa.destroy(c);
        var arena = std.heap.ArenaAllocator.init(g.gpa);
        errdefer arena.deinit();
        const scratch = try Scratch.init(key.kind, arena.allocator());
        const own_key: Key = .{ .kind = key.kind, .rtype = key.rtype, .name = try arena.allocator().dupe(u8, key.name) };
        const own_name = try dns.cloneNameFlat(arena.allocator(), name, false);
        if (reused == null) try g.cells.append(g.gpa, c);
        errdefer if (reused == null) {
            _ = g.cells.pop();
        };
        if (key.kind != .exchange) {
            // In progress keeps the slot. A settled owner yields it, key too:
            // its arena dies with it.
            const gop = try g.index.getOrPut(g.gpa, own_key);
            if (!gop.found_existing or g.cell(gop.value_ptr.*).settled()) {
                gop.key_ptr.* = own_key;
                gop.value_ptr.* = id;
            }
        }
        // Nothing fallible past here: the errdefers assume `c` unbuilt.
        c.* = .{
            .gen = if (reused != null) c.gen +% 1 else 0,
            .key = own_key,
            .name = own_name,
            .budget = budget,
            .depth = depth,
            .arena = arena,
            .scratch = scratch,
        };
        budget.refs += 1;
        if (budget.refs == 1) g.budgets += 1;
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

    pub fn holdsInput(g: *Graph, by: CellId, id: CellId) bool {
        for (g.cell(by).inputs.items) |i| if (i == id) return true;
        return false;
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
        if (c.holds == 0 and c.waiters.items.len == 0 and (c.settled() or !c.inFlight(g))) g.free(id, c) catch {};
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
        c.scratch = .none;
        try g.free_ids.append(g.gpa, id);
    }

    /// Copies out: the value becomes the blob's parse, the blob the store's
    /// version while fresh; a verdict is stamped on the bytes it judged.
    pub fn settle(g: *Graph, id: CellId, value: Value, expires_ns: i64) !void {
        const c = g.cell(id);
        std.debug.assert(!c.settled());
        g.tally.settles += 1;
        if (g.cfg.trace) switch (value) {
            .ds, .dnskey, .secure => |chain| {
                var nb: [dns.max_dotted_len + 1]u8 = undefined;
                std.debug.print("  {t}({s}) -> {t} for {d} s\n", .{ std.meta.activeTag(value), c.name.formatInto(&nb), chain.status, @divTrunc(expires_ns - g.now(), std.time.ns_per_s) });
            },
            else => {},
        };
        c.state = .{ .fact = value };
        c.expires_ns = expires_ns;
        switch (value) {
            .cut, .ns, .addr, .rrset, .ds, .dnskey => {
                const clock = Tally.clock(&g.tally.store_ns);
                defer clock.stop();
                const blob = try g.store.build(value);
                c.blob = blob;
                c.state.fact = try store.Store.parse(c.arena.allocator(), blob);
                if (expires_ns > g.now()) g.store.put(c.key, blob.ref(), expires_ns, g.now()) catch |err| {
                    g.store.unref(blob);
                    if (err != error.Refused) return err;
                };
            },
            .secure => |v| {
                if (v.status == .secure) g.stats.trust.secure += 1 else g.stats.trust.insecure += 1;
                if (g.cell(c.scratch.secure.target).blob) |b| b.verdict.stamp(v, c.expires_ns);
            },
            .answer, .exchange, .refresh => {},
        }
        try g.woken(id, value == .answer);
    }

    /// Settles on no fact (`Failure`): nothing is stored, nothing outlives
    /// this instant but what its demanders read now.
    pub fn fail(g: *Graph, id: CellId, why: Failure) !void {
        const c = g.cell(id);
        std.debug.assert(!c.settled());
        g.tally.settles += 1;
        if (g.cfg.trace) {
            var nb: [dns.max_dotted_len + 1]u8 = undefined;
            std.debug.print("  {t}({s}) failed: {t} {s}\n", .{ c.key.kind, c.name.formatInto(&nb), why.code, why.text });
        }
        if (c.key.kind == .secure) g.stats.trust.bogus += 1;
        c.state = .{ .failure = why };
        c.expires_ns = g.now();
        try g.woken(id, false);
    }

    fn woken(g: *Graph, id: CellId, keep_inputs: bool) !void {
        const c = g.cell(id);
        try g.ready.appendSlice(g.gpa, c.waiters.items);
        // An answer serves from its hops; everything else has copied out.
        if (!keep_inputs) {
            for (c.inputs.items) |i| g.unpin(i, id);
            c.inputs.clearRetainingCapacity();
        }
        // The run's hold still pins a refresh; one release, below.
        if (c.key.kind == .refresh) c.holds -= 1;
        g.release(id);
    }

    /// Refuse new work for `key` with `why` for `servfail_ttl`; past
    /// `max_failed` keys an arbitrary other one is forgotten.
    pub fn remember(g: *Graph, key: Key, why: Failure) !void {
        const r: Refusal = .{ .until_ns = g.now() + @as(i64, g.cfg.servfail_ttl) * std.time.ns_per_s, .why = why };
        if (g.failed.getPtr(key)) |u| {
            u.* = r;
            return;
        }
        if (g.failed.count() >= max_failed) {
            var it = g.failed.keyIterator();
            const old = it.next().?.*;
            _ = g.failed.remove(old);
            g.gpa.free(old.name);
        }
        const own: Key = .{ .kind = key.kind, .rtype = key.rtype, .name = try g.gpa.dupe(u8, key.name) };
        errdefer g.gpa.free(own.name);
        try g.failed.put(g.gpa, own, r);
    }

    fn refused(g: *Graph, key: Key) ?Failure {
        if (g.failed.count() == 0) return null;
        const r = g.failed.get(key) orelse return null;
        return if (r.until_ns > g.now()) r.why else null;
    }

    pub fn fresh(g: *Graph, id: CellId) bool {
        const c = g.cell(id);
        return c.settled() and c.expires_ns > g.now();
    }

    pub fn bound(g: *Graph, budget: *const Budget) i64 {
        return if (budget.refresh_ns == 0) g.now() else @max(g.now(), budget.refresh_ns + refresh_window_ns);
    }

    /// Stored since the refresh began counts, inclusive: the edge reads the
    /// clock once per event, so a refresh shares an instant with what its
    /// trigger stored.
    fn lookup(g: *Graph, key: Key, name: dns.Name, budget: *Budget) !?CellId {
        const live = g.index.get(key);
        if (g.store.get(key, g.now())) |e| if (e.expires_ns > g.bound(budget) or e.stored_ns >= budget.refresh_ns) {
            if (live) |id| if (g.cell(id).blob == e.blob) return id;
            return try g.materialise(key, name, budget, e);
        };
        if (live) |id| {
            const c = g.cell(id);
            if (!c.settled() or c.expires_ns > g.bound(budget) or (c.budget == budget and c.expires_ns > g.now())) return id;
        }
        return null;
    }

    fn materialise(g: *Graph, key: Key, name: dns.Name, budget: *Budget, e: store.Entry) !CellId {
        const id = try g.newCell(key, name, budget, 0);
        const c = g.cell(id);
        c.state = .{ .fact = store.Store.parse(c.arena.allocator(), e.blob) catch |err| {
            g.free(id, c) catch {};
            return err;
        } };
        c.blob = e.blob.ref();
        c.expires_ns = e.expires_ns;
        return id;
    }

    pub const Fact = struct { value: Value, expires_ns: i64 };

    /// No cell, no wait: `demand` is the only pin.
    pub fn peek(g: *Graph, key: Key) !?Fact {
        const live = g.index.get(key);
        if (g.store.get(key, g.now())) |e| {
            if (live) |id| if (g.cell(id).blob == e.blob) return .{ .value = g.cell(id).state.fact, .expires_ns = e.expires_ns };
            return .{ .value = try store.Store.parse(g.scratch.allocator(), e.blob), .expires_ns = e.expires_ns };
        }
        if (live) |id| if (g.fresh(id)) return .{ .value = g.cell(id).state.fact, .expires_ns = g.cell(id).expires_ns };
        return null;
    }

    /// Null on a cycle, or on new work for an orphan. New work that failed
    /// recently settles as that failure, its rule never run.
    pub fn demand(g: *Graph, by: CellId, key: Key, name: dns.Name, depth: u8) !?CellId {
        if (try g.lookup(key, name, g.cell(by).budget)) |id| {
            if (!g.fresh(id) and g.reaches(by, id)) return null;
            try g.pin(id, by);
            return id;
        }
        if (g.cell(by).orphan) return null;
        const id = try g.newCell(key, name, g.cell(by).budget, depth);
        try g.pin(id, by);
        if (g.refused(key)) |why| try g.fail(id, why) else try g.ready.append(g.gpa, id);
        return id;
    }

    /// Does settling `from` transitively wake `target`? Then `from`
    /// demanding `target` would be a cycle. Walks the waiters above
    /// `from`: the demand chain, not the graph.
    fn reaches(g: *Graph, from: CellId, target: CellId) bool {
        g.checks += 1;
        g.tally.reaches += 1;
        var stack: std.ArrayList(CellId) = .empty;
        stack.append(g.scratch.allocator(), from) catch return true;
        while (stack.pop()) |id| {
            if (id == target) return true;
            const c = g.cell(id);
            if (c.seen == g.checks) continue;
            c.seen = g.checks;
            g.tally.reaches_visits += 1;
            stack.appendSlice(g.scratch.allocator(), c.waiters.items) catch return true;
        }
        return false;
    }

    /// Evidence from a referral or a denial at a probe name: settles a
    /// cell in progress for the key, except the publisher's own; else a fact.
    pub fn publish(g: *Graph, key: Key, by: CellId, value: Value, expires_ns: i64) !void {
        if (g.index.get(key)) |id| if (id != by and !g.cell(id).settled()) return g.settle(id, value, expires_ns);
        try g.fact(key, value, expires_ns);
    }

    pub fn fact(g: *Graph, key: Key, value: Value, expires_ns: i64) !void {
        if (expires_ns <= g.now()) return;
        const blob = try g.store.build(value);
        g.store.put(key, blob, expires_ns, g.now()) catch |err| {
            g.store.unref(blob);
            if (err != error.Refused) return err;
        };
    }

    // ── Rules ──────────────────────────────────────────────────────────

    /// Held for the run: what it publishes may settle and free its own
    /// readers while the rule still has the cell in hand.
    fn run(g: *Graph, id: CellId) !void {
        const c = g.cell(id);
        if (!c.live or c.settled()) return;
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
        defer if (g.cell(id).live and !g.cell(id).settled() and g.created == created_before) {
            g.tally.reruns += 1;
            g.tally.rerun_ns += @intCast(monotonic.nowNs() - clock.t0);
        };
        switch (g.cell(id).key.kind) {
            .cut => try walk.runCut(g, id),
            .rrset => try walk.runRrset(g, id),
            .ns => try walk.runNs(g, id),
            .addr => try walk.runAddr(g, id),
            .answer, .refresh => try walk.runAnswer(g, id),
            .ds => try trust.runDs(g, id),
            .dnskey => try trust.runDnskey(g, id),
            .secure => try trust.runSecure(g, id),
            .exchange => {},
        }
    }

    pub fn observe(g: *Graph, server: na.Address, rtt_ns: i64) !void {
        (try g.estimate(server)).observe(@divTrunc(rtt_ns, std.time.ns_per_us), g.nowMs());
    }

    pub fn observeTimeout(g: *Graph, server: na.Address) !void {
        _ = (try g.estimate(server)).observeTimeout(g.nowMs());
    }

    /// Past `ns_rtt.max_entries` servers, an arbitrary other one is forgotten.
    fn estimate(g: *Graph, server: na.Address) !*ns_rtt.RttState {
        const key = na.AddressKey.fromAddress(server);
        if (g.rtt.getPtr(key)) |s| return s;
        if (g.rtt.count() >= ns_rtt.max_entries) {
            var it = g.rtt.keyIterator();
            g.rtt.removeByPtr(it.next().?);
        }
        const gop = try g.rtt.getOrPut(g.gpa, key);
        gop.value_ptr.* = .unknown;
        return gop.value_ptr;
    }

    pub fn nowMs(g: *const Graph) i64 {
        return @divTrunc(g.now(), std.time.ns_per_ms);
    }

    pub fn isDead(g: *Graph, server: na.Address) bool {
        const state = g.rtt.get(na.AddressKey.fromAddress(server)) orelse return false;
        return state.isDead(g.nowMs());
    }

    // ── Exchanges ──────────────────────────────────────────────────────

    /// Null, like `demand`, when the asker's budget, deadline or orphaning
    /// refuses the work.
    pub fn exchange(g: *Graph, by: CellId, server: na.Address, transport: Transport, qname: dns.Name, qtype: dns.RType, timeout_ms: u32) !?CellId {
        const budget = g.cell(by).budget;
        if (g.cell(by).orphan or g.now() >= budget.deadline_ns or budget.queries >= g.cfg.max_queries) {
            if (g.cfg.trace) {
                var nb: [dns.max_dotted_len + 1]u8 = undefined;
                std.debug.print("  {s} {t} refused: {s}\n", .{ qname.formatInto(&nb), qtype, if (g.cell(by).orphan) "orphan" else if (g.now() >= budget.deadline_ns) "past the deadline" else "query budget spent" });
            }
            return null;
        }
        const id = try g.newCell(.{ .kind = .exchange, .name = "" }, qname, budget, g.cell(by).depth);
        try g.pin(id, by);
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
        const sc = try arena.create(ExchangeScratch);
        sc.* = .{ .id = qid, .sent_name = msg.questions[0].name, .qtype = qtype, .server = server, .transport = transport, .sent_ns = g.now() };
        g.cell(id).scratch = .{ .exchange = sc };
        try g.edge.send(.{
            .id = id,
            .server = server,
            .transport = transport,
            .wire = wire,
            .deadline_ns = @min(budget.deadline_ns, g.now() + @as(i64, timeout_ms) * std.time.ns_per_ms),
        });
        g.flights += 1;
        if (transport == .udp) g.stats.resolver.udp += 1 else g.stats.resolver.tcp += 1;
        return id;
    }
};

test "a cell is a few words" {
    // Scratch is a pointer: the slot bound is not the largest kind's.
    try std.testing.expect(@sizeOf(Cell) <= 384);
}

test "a cell replacing an expired one takes over the index entry's key" {
    const testing = std.testing;
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    const Stub = struct {
        fn send(_: *anyopaque, _: Exchange) anyerror!void {}
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
    };
    var g = try Graph.init(testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = @import("rand.zig").thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const name = try dns.parseDottedName(arena.allocator(), "example.");
    const first = (try g.demandRoot(name, .a, true)).?;
    try g.settle(first, .{ .answer = .{ .hops = &.{} } }, now);
    const second = (try g.demandRoot(name, .a, true)).?;
    try testing.expect(first != second);
    g.unhold(first);
    try testing.expect(!g.cell(first).live);
    // The entry's key must be the survivor's.
    const key = try g.keyFor(.answer, name, .a);
    try testing.expectEqual(second, g.index.get(key).?);
    try testing.expectEqual(g.cell(second).key.name.ptr, g.index.getKey(key).?.name.ptr);
    g.unhold(second);
}

test "a caller that cannot wait gets only what is settled" {
    const testing = std.testing;
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    const Stub = struct {
        fn send(_: *anyopaque, _: Exchange) anyerror!void {}
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
    };
    var g = try Graph.init(testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = @import("rand.zig").thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const name = try dns.parseDottedName(arena.allocator(), "example.");
    try testing.expectEqual(null, try g.demandRoot(name, .a, false));
    const first = (try g.demandRoot(name, .a, true)).?;
    try testing.expectEqual(null, try g.demandRoot(name, .a, false));
    try testing.expectEqual(@as(u64, 2), g.stats.clients.dropped);
    try g.settle(first, .{ .answer = .{ .hops = &.{} } }, now + std.time.ns_per_s);
    try testing.expectEqual(first, (try g.demandRoot(name, .a, false)).?);
    g.unhold(first);
    g.unhold(first);
}

test "an evicted root cut is re-derived, not walked" {
    const testing = std.testing;
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    const Stub = struct {
        fn send(_: *anyopaque, _: Exchange) anyerror!void {}
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
    };
    var g = try Graph.init(testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = @import("rand.zig").thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
    defer g.deinit();
    const root_cut: Key = .{ .kind = .cut, .name = "" };
    g.store.drop(root_cut, g.store.any(root_cut).?.blob);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = (try g.demandRoot(try dns.parseDottedName(arena.allocator(), "com."), .a, true)).?;
    try g.drain();
    try testing.expect(g.store.get(root_cut, now) != null);
    g.unhold(root);
}
