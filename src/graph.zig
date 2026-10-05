//! The resolver as a graph of typed DNS facts.
//!
//! A cell is a fact with a TTL: a zone cut with its NS names, a host's
//! addresses, an RRset, or one exchange with a server; or a failure, which
//! is none.
//! A rule settles a cell kind; it runs when the cell is first demanded and
//! again whenever an input settles.
//! Rules are pure over their inputs, scratch, now and rng; the exchange cell
//! is the only impure leaf, settled by the edge.
//!
//! The rules live beside it: the delegation walk in walk.zig, the chain of
//! trust in trust.zig, aggressive denial in denial.zig; one core.
const std = @import("std");
const builtin = @import("builtin");
const rand = @import("rand.zig");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const delegation = @import("delegation.zig");
const rrsig = @import("rrsig.zig");
const dnssec = @import("dnssec.zig");
const monotonic = @import("monotonic.zig");
const ns_rtt = @import("ns_rtt.zig");
const trust = @import("trust.zig");
const denial = @import("denial.zig");
const store = @import("store.zig");
const walk = @import("walk.zig");

/// CNAME and DNAME links one question may follow, a DNAME and its
/// synthesised CNAME counting once. Chains in the wild run to 12;
/// resolvers stop at 10 to 19.
pub const max_links = 14;

pub const CellId = u32;

/// A `?CellId` in half the bytes.
pub const OptionalCellId = enum(CellId) {
    none = std.math.maxInt(CellId),
    _,

    pub fn wrap(id: ?CellId) OptionalCellId {
        const i = id orelse return .none;
        std.debug.assert(i != @backingInt(OptionalCellId.none));
        return @fromBackingInt(i);
    }

    pub fn unwrap(o: OptionalCellId) ?CellId {
        return if (o == .none) null else @backingInt(o);
    }
};

pub const Transport = ns_rtt.Transport;

pub const Exchange = struct {
    id: CellId,
    server: na.Address,
    transport: Transport,
    wire: []const u8,
    deadline_ns: i64,
};

pub const Completion = union(enum) {
    /// Borrowed for the call: the cell parses its own copy.
    reply: []const u8,
    timeout,
    /// Never left the host: out of sockets, buffers or memory. Says
    /// nothing about the server.
    unsent,
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
/// `ahead`: an rrset's judge, started before anyone asks.
pub const Kind = enum(u8) { cut, addr, rrset, answer, ds, dnskey, secure, exchange, refresh, ahead };

/// Names are keyed by lowercase presentation form (`Name.formatLower`),
/// which is injective.
pub const KeyBuf = [dns.max_dotted_len + 1]u8;

pub const Key = struct {
    kind: Kind,
    rtype: dns.RType,
    name: []const u8,
    /// `name`'s, taken once: every key at the name mixes its own from it.
    name_hash: u32,

    /// Borrows `buf`: whatever keeps a key dupes its name (`newCell`, `remember`).
    pub fn of(buf: *KeyBuf, kind: Kind, name: dns.Name, rtype: dns.RType) Key {
        return .init(kind, name.formatLower(buf), rtype);
    }

    pub fn init(kind: Kind, name: []const u8, rtype: dns.RType) Key {
        return .{ .kind = kind, .rtype = rtype, .name = name, .name_hash = hashName(name) };
    }

    /// Another key at the same name, whose hash it keeps.
    pub fn at(k: Key, kind: Kind, rtype: dns.RType) Key {
        return .{ .kind = kind, .rtype = rtype, .name = k.name, .name_hash = k.name_hash };
    }

    fn hashName(name: []const u8) u32 {
        return @truncate(std.hash.Wyhash.hash(rand.hash_seed, name));
    }

    /// A Fibonacci multiply, folded: the kind and type reach the low bits,
    /// which pick the slot. Keys at one name land in related slots; probing
    /// ran no longer for it than under a full mix, which takes three
    /// multiplies.
    pub fn hash(k: Key) u64 {
        if (builtin.mode == .debug) std.debug.assert(k.name_hash == hashName(k.name));
        const x = @as(u64, k.name_hash) << 32 | @as(u64, @backingInt(k.kind)) << 16 | @backingInt(k.rtype);
        const p = @as(u128, x) * 0x9e3779b97f4a7c15;
        return @truncate(p ^ p >> 64);
    }

    pub fn eql(a: Key, b: Key) bool {
        return a.kind == b.kind and a.rtype == b.rtype and mem.eql(u8, a.name, b.name);
    }

    /// For array hash maps: they delete without tombstones, so a map
    /// under steady churn keeps its probes short.
    pub const Context = struct {
        pub fn hash(_: Context, k: Key) u32 {
            return @truncate(k.hash());
        }
        pub fn eql(_: Context, a: Key, b: Key, _: usize) bool {
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
    max_flights: u32 = std.math.maxInt(u32),
    max_work_bytes: usize = std.math.maxInt(usize),
    /// The first window a failure is remembered: by the server per
    /// question, by trust per zone (RFC 9520 §3.2).
    servfail_ttl: u32 = 5,
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
    /// `zone`'s, from a referral. None at the root: hints carry addresses.
    servers: []const Server = &.{},
    /// How long the delegation stands, glue aside: its NS TTL, capped by
    /// the referring zone's. One that `zone`'s servers give lives no longer.
    placed_until_ns: i64 = std.math.maxInt(i64),
};

pub const Server = struct {
    /// Its `addr(name)` key, kept whole so no walk formats or hashes the name.
    key: Key,
    glue: []const na.Address = &.{},
};

/// The RRset at (name, type), as the reply sections that settled it, so
/// the client sees what the authority said. A section holds each set
/// whole and together, followed by its signatures (`dnssec.bindSets`).
pub const Reply = struct {
    kind: Of,
    aa: bool,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
    additionals: []const dns.ResourceRecord = &.{},
    /// Where the chain in `answers` ends: an alias's next name, or the
    /// name a negative denies.
    target: dns.Name = .{ .labels = &.{} },
    /// The zone whose servers answered; what `secure` judges it against.
    zone: dns.Name = .{ .labels = &.{} },
    ede: ?dns.Ede.Code = null,
    /// TTLs age from here.
    stored_ns: i64 = 0,
    /// Seconds the reply stays a fact (`replyTtl`).
    ttl: u32 = 0,

    /// The name an NXDOMAIN says does not exist: where its chain ends,
    /// not always the name asked (RFC 8020 §2).
    pub fn nonexistent(r: Reply) ?dns.Name {
        return if (r.kind == .nxdomain) r.target else null;
    }

    pub const Of = enum {
        answer,
        alias,
        nodata,
        nxdomain,
        yxdomain,

        /// Only rcodes that answer are kept; a chain's is its final query
        /// cycle's (RFC 6604 §3).
        pub fn rcode(k: Of) dns.RCode {
            return switch (k) {
                .answer, .alias, .nodata => .no_error,
                .nxdomain => .name_error,
                .yxdomain => .yx_domain,
            };
        }
    };
};

/// A client question: the alias chain from `rrset(name, type)` to the
/// RRset that ends it.
pub const Answer = struct {
    /// In chain order; every one but the last is an alias.
    hops: []const CellId,
    /// `secure(hop)` per hop, held; empty with DNSSEC off.
    judged: []const CellId = &.{},
};

pub const Outcome = union(enum) {
    reply: struct { msg: dns.Message, rtt_ns: i64 },
    timeout,
    unsent,
    /// Parses, but a wrong id, question or 0x20 case: not the reply sent for.
    mismatch,
    /// Does not parse.
    malformed,
};

/// Plain goes only over TCP, where a forger cannot follow.
pub const Case = enum { random, plain };

/// Why a cell settled on no fact: nothing about the DNS, so it is never
/// stored and expires as it settles. Its demanders read it; the next
/// demand starts afresh, and remembering it is the server's policy.
pub const Failure = struct {
    code: dns.Ede.Code,
    text: []const u8 = "",
    /// Only the zone's failures are remembered: never what failed to
    /// leave the host, nor what an asker's own limit ended.
    cause: enum { zone, host, asker } = .zone,
    /// No probe could place the cut: ask in full from the deepest one known.
    unplaced: bool = false,

    /// Nobody answered usefully, or the walk to them was refused
    /// (`Graph.demand`'s null): nothing more is proven.
    pub const unreachable_authority: Failure = .{ .code = .no_reachable_authority };
};

pub const Value = union(Kind) {
    cut: Cut,
    addr: []const na.Address,
    rrset: Reply,
    answer: Answer,
    ds: trust.Chain,
    dnskey: trust.Chain,
    secure: trust.Chain,
    exchange: Outcome,
    refresh: void,
    ahead: void,
};

/// Bytes held by work in progress, counted where they are allocated: cell
/// arenas by the chunk, budgets, the edge's TCP buffers, the query bytes
/// of clients waiting.
pub const Work = struct {
    child: Allocator,
    bytes: usize = 0,

    pub fn allocator(w: *Work) Allocator {
        return .{ .ptr = w, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, a: mem.Alignment, ra: usize) ?[*]u8 {
        const w: *Work = @ptrCast(@alignCast(ctx));
        const p = w.child.rawAlloc(len, a, ra) orelse return null;
        w.bytes += len;
        return p;
    }

    fn resize(ctx: *anyopaque, m: []u8, a: mem.Alignment, len: usize, ra: usize) bool {
        const w: *Work = @ptrCast(@alignCast(ctx));
        if (!w.child.rawResize(m, a, len, ra)) return false;
        w.bytes = w.bytes - m.len + len;
        return true;
    }

    fn remap(ctx: *anyopaque, m: []u8, a: mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const w: *Work = @ptrCast(@alignCast(ctx));
        const p = w.child.rawRemap(m, a, len, ra) orelse return null;
        w.bytes = w.bytes - m.len + len;
        return p;
    }

    fn free(ctx: *anyopaque, m: []u8, a: mem.Alignment, ra: usize) void {
        const w: *Work = @ptrCast(@alignCast(ctx));
        w.child.rawFree(m, a, ra);
        w.bytes -= m.len;
    }
};

/// A question's: its root holds it, and every run the root waits on pays
/// from it (`payerOf`).
pub const Budget = struct {
    queries: u32 = 0,
    /// A question's end is its deadline too: the key fetches its walk
    /// began stop with it.
    deadline_ns: i64,
    /// The roots sharing it: a question and the key fetches its walk began.
    refs: u32 = 1,
    /// When a refresh began, and when the life it replaces ends; 0 for a
    /// client.
    refresh_ns: i64 = 0,
    lapses_ns: i64 = 0,
    /// KeyTrap: every verify the resolution does, whichever cell does it.
    validation: rrsig.ValidationBudget = .{},
};

/// Cumulative since start; `serve.zig` prints them.
pub const Stats = struct {
    resolver: struct {
        exchanges: struct { udp: u64 = 0, tcp: u64 = 0 } = .{},
        faults: struct {
            timeout: u64 = 0,
            /// Never left the host.
            unsent: u64 = 0,
        } = .{},
        early: struct { refresh: u64 = 0 } = .{},
        detail: struct {
            retry: u64 = 0,
            /// Not begun, over half the flights or work.
            unrefreshed: u64 = 0,
            /// DNSKEY fetches begun ahead of need.
            ahead: u64 = 0,
        } = .{},
    } = .{},
    trust: struct { secure: u64 = 0, insecure: u64 = 0, bogus: u64 = 0 } = .{},
};

const max_failed = 4096;

const Refusal = struct { until_ns: i64, why: Failure };

/// So a refresh does not time the client; never past half the life left.
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

    /// Only the replay reads the timings; serve skips the clock reads.
    pub const timed = builtin.is_test;

    pub const Clock = struct {
        t0: i128,
        into: *u64,
        pub fn stop(c: Clock) void {
            if (timed) c.into.* += @intCast(monotonic.nowNs() - c.t0);
        }
    };

    pub fn clock(into: *u64) Clock {
        return .{ .t0 = if (timed) monotonic.nowNs() else 0, .into = into };
    }
};

const ExchangeScratch = struct {
    id: u16,
    sent_name: dns.Name,
    qtype: dns.RType,
    server: na.Address,
    transport: Transport,
    case: Case,
    sent_ns: i64,
    /// The payer's deadline came before the wait the server is owed, so a
    /// timeout says nothing about it, nor about its zone.
    cut_short: bool,
};

/// In the cell's arena: a cell pays for its own kind's, not the largest.
pub const Scratch = union(enum) {
    none,
    cut: *walk.CutScratch,
    addr: *walk.AddrScratch,
    rrset: *walk.RrsetScratch,
    answer: *walk.AnswerScratch,
    ds: *trust.DsScratch,
    dnskey: *trust.DnskeyScratch,
    secure: *trust.SecureScratch,
    exchange: *ExchangeScratch,
    ahead: *trust.AheadScratch,

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
    scratch: Scratch = .none,
    blob: ?*store.Blob = null,
    /// Everything the cell owns; freed with it.
    arena: std.heap.ArenaAllocator,

    comptime {
        // Scratch is a pointer: the slot bound is not the largest kind's.
        std.debug.assert(@sizeOf(Cell) <= 384);
    }

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
    work: Work,
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
    /// Who pays for the running rule: derived at each run, never stored.
    payer: *Budget = undefined,
    /// A run nobody waits on spends nothing.
    unpaid: Budget = undefined,
    /// Exchanges the edge holds.
    flights: u32 = 0,
    /// Work that failed, refused at `demand` rather than tried again
    /// (RFC 9520 §3.2): an upstream fetch, a zone's DS or keys. Policy,
    /// outside cells.
    failed: std.ArrayHashMapUnmanaged(Key, Refusal, Key.Context, true) = .empty,
    stats: Stats = .{},
    created: u64 = 0,
    /// Live cells only.
    index: std.ArrayHashMapUnmanaged(Key, CellId, Key.Context, true) = .empty,
    ready: std.ArrayList(CellId) = .empty,
    /// Questions settled since the server last looked: its cue, not a fact.
    answered: std.ArrayList(CellId) = .empty,
    /// Per-server estimate, capped.
    rtt: std.HashMapUnmanaged(na.AddressKey, ns_rtt.RttState, na.AddressKey.HashCtx, 80) = .empty,
    tally: Tally = .{},
    /// Verified NSEC facts in span order (denial.zig).
    denial: denial.Index = .{},
    /// Signatures already verified, by content: a speedup, never a verdict.
    verify_memo: rrsig.VerifyMemo = .{},
    store: store.Store,

    pub fn init(gpa: Allocator, cfg: Config, edge: Edge) !Graph {
        var g: Graph = .{ .gpa = gpa, .work = .{ .child = gpa }, .cfg = cfg, .edge = edge, .scratch = std.heap.ArenaAllocator.init(gpa), .store = try store.Store.init(gpa, cfg.store_bytes) };
        errdefer g.deinit();
        if (cfg.trust_anchor != null) g.verify_memo = try .init(gpa);
        // The root cut is an axiom; `runCut` re-derives it if evicted.
        _ = try g.fact(.init(.cut, "", .a), .{ .cut = .{ .zone = .{ .labels = &.{} } } }, std.math.maxInt(i64));
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
        // Not `free`: in slot order a cell would unpin from inputs gone first.
        for (g.cells.items) |c| {
            if (c.live) {
                c.inputs.deinit(g.gpa);
                c.waiters.deinit(g.gpa);
                if (c.blob) |bl| g.store.unref(bl);
                if (budgetOf(c)) |b| g.unref(b);
                c.arena.deinit();
            }
            g.gpa.destroy(c);
        }
        g.cells.deinit(g.gpa);
        g.free_ids.deinit(g.gpa);
        g.scratch.deinit();
        g.index.deinit(g.gpa);
        g.ready.deinit(g.gpa);
        g.answered.deinit(g.gpa);
        g.rtt.deinit(g.gpa);
        for (g.failed.keys()) |k| g.gpa.free(k.name);
        g.failed.deinit(g.gpa);
        g.denial.deinit(g.gpa, &g.store);
        g.verify_memo.deinit(g.gpa);
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

    /// What a client may start: `join`, only what is settled or in
    /// progress; `new`, a resolution of its own.
    pub const Admit = enum { join, new };

    /// Held for the client until `unhold`. `Novel`: a new resolution
    /// `admit` does not allow. `Full`: anything unsettled past
    /// `max_work_bytes` (a joiner is work too), or new work past `max_flights`.
    pub fn demandRoot(g: *Graph, name: dns.Name, qtype: dns.RType, admit: Admit) !CellId {
        var kb: KeyBuf = undefined;
        const key = Key.of(&kb, .answer, name, qtype);
        if (g.index.get(key)) |id| if (!g.cell(id).settled() or g.fresh(id)) {
            if (!g.cell(id).settled() and g.work.bytes >= g.cfg.max_work_bytes) return error.Full;
            g.cell(id).holds += 1;
            return id;
        };
        if (admit != .new) return error.Novel;
        if (g.flights >= g.cfg.max_flights or g.work.bytes >= g.cfg.max_work_bytes) return error.Full;
        const id = try g.newRoot(key, name, .{ .deadline_ns = g.now() + @as(i64, g.cfg.resolve_ms) * std.time.ns_per_ms });
        g.cell(id).holds += 1;
        errdefer g.unhold(id);
        try g.ready.append(g.gpa, id);
        return id;
    }

    pub fn unhold(g: *Graph, id: CellId) void {
        g.cell(id).holds -= 1;
        g.release(id);
    }

    /// `dnskey(zone)` ahead of need, for a question's own walk only.
    pub fn fetchKeys(g: *Graph, by: CellId, zone: dns.Name) !void {
        var kb: KeyBuf = undefined;
        if (g.spent(g.payer) or g.level(by) > 0) return;
        _ = try g.ahead(Key.of(&kb, .rrset, zone, .dnskey), zone);
    }

    /// One per key at a time, holding itself until its judge settles, on the
    /// running payer's budget; null once that is spent.
    fn ahead(g: *Graph, key: Key, name: dns.Name) !?CellId {
        if (g.spent(g.payer)) return null;
        const akey = key.at(.ahead, key.rtype);
        if (g.index.get(akey)) |id| if (!g.cell(id).settled()) return id;
        const id = try g.newCell(akey, name);
        g.cell(id).scratch.ahead.budget = g.payer;
        g.payer.refs += 1;
        g.cell(id).holds += 1;
        errdefer g.unhold(id);
        try g.ready.append(g.gpa, id);
        g.stats.resolver.detail.ahead += 1;
        if (g.cfg.trace) std.debug.print("  ahead {s} {t}\n", .{ key.name, key.rtype });
        return id;
    }

    /// One per key at a time; holds itself until it settles.
    pub fn refresh(g: *Graph, key: Key, name: dns.Name, lapses_ns: i64) !void {
        const rkey = key.at(.refresh, key.rtype);
        if (g.index.contains(rkey)) return;
        if (g.flights >= g.cfg.max_flights / 2 or g.work.bytes >= g.cfg.max_work_bytes / 2) {
            g.stats.resolver.detail.unrefreshed += 1;
            return;
        }
        const jitter = @min(refresh_jitter_ns, @divTrunc(lapses_ns - g.now(), 2));
        const at = g.now() + if (jitter > 0) g.edge.rng.intRangeLessThan(i64, 0, jitter) else 0;
        const id = try g.newRoot(rkey, name, .{ .deadline_ns = 0, .refresh_ns = g.now(), .lapses_ns = lapses_ns });
        g.cell(id).holds += 1;
        errdefer g.unhold(id);
        try g.wake(id, at);
        g.stats.resolver.early.refresh += 1;
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
                const c = g.cell(id);
                if (c.key.kind == .refresh and c.scratch.answer.budget.deadline_ns == 0) c.scratch.answer.budget.deadline_ns = g.now() + @as(i64, g.cfg.resolve_ms) * std.time.ns_per_ms;
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
            .unsent => .unsent,
            .reply => |borrowed| blk: {
                const clock = Tally.clock(&g.tally.parse_ns);
                defer clock.stop();
                g.tally.parses += 1;
                const bytes = try arena.dupe(u8, borrowed);
                var msg = dns.parseMessage(arena, bytes) catch break :blk .malformed;
                if (msg.header.id != sc.id) break :blk .mismatch;
                dns.validateResponse(msg, sc.sent_name, sc.qtype, sc.case == .random) catch break :blk .mismatch;
                // 0x20 case checked; every name is a lowercase fact from here.
                // Asked in IN, a record of another class answers nothing.
                inline for (.{ &msg.answers, &msg.authorities, &msg.additionals }) |section| {
                    const rrs = @constCast(section.*);
                    var n: usize = 0;
                    for (rrs) |rr| if (rr.rclass == .in) {
                        rrs[n] = rr;
                        rrs[n].name = try dns.cloneNameLower(arena, rr.name);
                        try dns.lowercaseRDataNames(arena, &rrs[n].rdata);
                        n += 1;
                    };
                    section.* = rrs[0..n];
                }
                const scratch = g.scratch.allocator();
                msg.answers = try dnssec.bindSets(scratch, @constCast(msg.answers), sc.qtype == .rrsig);
                msg.authorities = try dnssec.bindSets(scratch, @constCast(msg.authorities), false);
                msg.additionals = try dnssec.bindSets(scratch, @constCast(msg.additionals), false);
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
                g.stats.resolver.faults.timeout += 1;
                if (!sc.cut_short) try g.observeTimeout(sc.server);
            },
            .unsent => g.stats.resolver.faults.unsent += 1,
            else => {},
        }
        c.holds -= 1;
        g.flights -= 1;
        try g.settle(id, .{ .exchange = outcome }, g.now());
        try g.drain();
    }

    // ── Cells ──────────────────────────────────────────────────────────

    /// A question's cell, holding its budget.
    fn newRoot(g: *Graph, key: Key, name: dns.Name, budget: Budget) !CellId {
        const b = try g.work.allocator().create(Budget);
        errdefer g.work.allocator().destroy(b);
        b.* = budget;
        const id = try g.newCell(key, name);
        g.cell(id).scratch.answer.budget = b;
        g.budgets += 1;
        return id;
    }

    /// All or nothing.
    pub fn newCell(g: *Graph, key: Key, name: dns.Name) !CellId {
        const reused = g.free_ids.pop();
        errdefer if (reused) |r| g.free_ids.appendAssumeCapacity(r);
        const id: CellId = reused orelse @intCast(g.cells.items.len);
        const c = if (reused != null) g.cells.items[id] else try g.gpa.create(Cell);
        errdefer if (reused == null) g.gpa.destroy(c);
        var arena = std.heap.ArenaAllocator.init(g.work.allocator());
        errdefer arena.deinit();
        const scratch = try Scratch.init(key.kind, arena.allocator());
        var own_key = key;
        own_key.name = try arena.allocator().dupe(u8, key.name);
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
            .arena = arena,
            .scratch = scratch,
        };
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
        if (g.index.getIndex(c.key)) |i| if (g.index.values()[i] == id) g.index.swapRemoveAt(i);
        if (budgetOf(c)) |b| {
            // A question gone, the key fetches its walk began end too.
            if (c.scratch == .answer) b.deadline_ns = @min(b.deadline_ns, g.now());
            g.unref(b);
        }
        c.arena.deinit();
        c.arena = std.heap.ArenaAllocator.init(g.work.allocator());
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
            .cut, .addr, .rrset, .ds, .dnskey => {
                const clock = Tally.clock(&g.tally.store_ns);
                defer clock.stop();
                const blob = try g.store.build(value);
                c.blob = blob;
                c.state.fact = try store.Store.parse(c.arena.allocator(), blob);
                if (!g.awaitsVerdict(c.key.kind)) try g.keep(id);
            },
            .secure => |v| {
                if (v.status == .secure) g.stats.trust.secure += 1 else g.stats.trust.insecure += 1;
                const t = c.scratch.secure.target;
                if (g.cell(t).blob) |b| b.verdict.stamp(v, c.expires_ns, g.now());
                try g.keep(t);
            },
            .answer, .exchange, .refresh, .ahead => {},
        }
        try g.woken(id, value == .answer);
    }

    /// An rrset's bytes as its judge read them, set before the verdict is
    /// stamped on them (`trust.keepWeighed`).
    pub fn narrow(g: *Graph, id: CellId, reply: Reply) !void {
        const c = g.cell(id);
        const blob = try g.store.build(.{ .rrset = reply });
        errdefer g.store.unref(blob);
        const parsed = try store.Store.parse(c.arena.allocator(), blob);
        if (c.blob) |b| g.store.unref(b);
        c.blob = blob;
        c.state.fact = parsed;
    }

    /// With DNSSEC on, an rrset is no fact until judged: its bytes wait in
    /// their cell and die with it unless their judge keeps them.
    pub fn awaitsVerdict(g: *const Graph, kind: Kind) bool {
        return kind == .rrset and g.cfg.trust_anchor != null;
    }

    /// The one way into the store, aged from when the bytes arrived.
    pub fn keep(g: *Graph, id: CellId) !void {
        const c = g.cell(id);
        const blob = c.blob orelse return;
        if (c.expires_ns <= g.now()) return;
        if (g.store.any(c.key)) |e| if (e.blob == blob) return;
        const at = if (c.state.fact == .rrset) c.state.fact.rrset.stored_ns else g.now();
        g.store.put(c.key, blob.ref(), c.expires_ns, at) catch |err| {
            g.store.unref(blob);
            if (err != error.Refused) return err;
        };
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
        if (c.key.kind == .secure and why.code == .dnssec_bogus) g.stats.trust.bogus += 1;
        c.state = .{ .failure = why };
        c.expires_ns = g.now();
        try g.woken(id, false);
    }

    fn woken(g: *Graph, id: CellId, keep_inputs: bool) !void {
        const c = g.cell(id);
        try g.ready.appendSlice(g.gpa, c.waiters.items);
        if (c.key.kind == .answer) try g.answered.append(g.gpa, id);
        // An answer serves from its hops; everything else has copied out.
        if (!keep_inputs) {
            for (c.inputs.items) |i| g.unpin(i, id);
            c.inputs.clearRetainingCapacity();
        }
        // The run's hold still pins a self-held root; one release, below.
        if (c.key.kind == .refresh or c.key.kind == .ahead) c.holds -= 1;
        g.release(id);
    }

    /// Refuse new work for `key` with `why` for `servfail_ttl`; past
    /// `max_failed` keys a random other one is forgotten.
    pub fn remember(g: *Graph, key: Key, why: Failure) !void {
        const r: Refusal = .{ .until_ns = g.now() + @as(i64, g.cfg.servfail_ttl) * std.time.ns_per_s, .why = why };
        if (g.failed.getPtr(key)) |u| {
            u.* = r;
            return;
        }
        if (g.failed.count() >= max_failed) {
            const at = g.edge.rng.uintLessThan(usize, g.failed.count());
            const old = g.failed.keys()[at];
            g.failed.swapRemoveAt(at);
            g.gpa.free(old.name);
        }
        var own = key;
        own.name = try g.gpa.dupe(u8, key.name);
        errdefer g.gpa.free(own.name);
        try g.failed.put(g.gpa, own, r);
    }

    fn refused(g: *Graph, key: Key) ?Failure {
        if (g.failed.count() == 0) return null;
        const r = g.failed.get(key) orelse return null;
        return if (r.until_ns > g.now()) r.why else null;
    }

    /// RFC 4035 §5.3.3: an rrset accepted as authentic ends with the
    /// signatures that authenticated it.
    pub fn authenticUntil(g: *Graph, id: CellId, until_ns: i64) void {
        const c = g.cell(id);
        c.expires_ns = @min(c.expires_ns, until_ns);
        if (c.blob) |b| g.store.shorten(c.key, b, until_ns);
    }

    pub fn fresh(g: *Graph, id: CellId) bool {
        const c = g.cell(id);
        return c.settled() and c.expires_ns > g.now();
    }

    pub fn bound(g: *const Graph, budget: *const Budget) i64 {
        return if (budget.refresh_ns == 0) g.now() else @max(g.now(), budget.lapses_ns);
    }

    /// Evidence stored since the refresh began counts, inclusive: the edge
    /// reads the clock once per event, so a refresh shares an instant with
    /// what its trigger fetched. A verdict is stored when judged, however
    /// old its evidence, so it is judged again.
    fn lookup(g: *Graph, key: Key, name: dns.Name, live: ?CellId, found: ?Served) !?CellId {
        if (found) |s| return switch (s) {
            .stored => |e| g.liveVersion(live, e) orelse try g.materialise(key, name, e),
            .live => |id| id,
        };
        const id = live orelse return null;
        return if (g.cell(id).settled()) null else id;
    }

    /// What `demand` hands the running rule without running it; the one
    /// predicate `lookup`, `holds` and `held` share.
    const Served = union(enum) { stored: store.Entry, live: CellId };

    fn served(g: *Graph, key: Key, live: ?CellId) ?Served {
        if (g.stored(key)) |e| return .{ .stored = e };
        return .{ .live = g.liveServed(live) orelse return null };
    }

    fn liveServed(g: *Graph, live: ?CellId) ?CellId {
        const id = live orelse return null;
        return if (g.cell(id).settled() and g.serves(id)) id else null;
    }

    fn liveVersion(g: *Graph, live: ?CellId, e: store.Entry) ?CellId {
        const id = live orelse return null;
        return if (g.cell(id).blob == e.blob) id else null;
    }

    /// The stored fact `demand` would hand the running rule.
    fn stored(g: *Graph, key: Key) ?store.Entry {
        const e = g.store.get(key, g.now()) orelse return null;
        const verdict = key.kind == .ds or key.kind == .dnskey;
        return if (e.expires_ns > g.bound(g.payer) or (!verdict and e.stored_ns >= g.payer.refresh_ns)) e else null;
    }

    /// Would `demand` hand the running rule a fact for `key` without
    /// running it?
    pub fn holds(g: *Graph, key: Key) bool {
        // `served`'s order, without reading the index when the store has it.
        if (g.stored(key) != null) return true;
        const id = g.liveServed(g.index.get(key)) orelse return false;
        return g.cell(id).state == .fact;
    }

    /// The fact `demand` would hand the running rule for `key` without
    /// running it: the same version, not merely a fresh one.
    pub fn held(g: *Graph, key: Key) !?Fact {
        const live = g.index.get(key);
        return switch (g.served(key, live) orelse return null) {
            .stored => |e| try g.factOf(live, e),
            .live => |id| g.liveFact(id),
        };
    }

    /// A stored fact, read from its live version when there is one.
    fn factOf(g: *Graph, live: ?CellId, e: store.Entry) !Fact {
        if (g.liveVersion(live, e)) |id| if (g.liveFact(id)) |f| return .{ .value = f.value, .expires_ns = e.expires_ns };
        return .{ .value = try store.Store.parse(g.scratch.allocator(), e.blob), .expires_ns = e.expires_ns };
    }

    fn liveFact(g: *Graph, id: CellId) ?Fact {
        const c = g.cell(id);
        return if (c.state == .fact) .{ .value = c.state.fact, .expires_ns = c.expires_ns } else null;
    }

    /// A live fact serves the running rule while it outlives the payer's
    /// bound, or, still fresh, is already the payer's own input.
    pub fn serves(g: *Graph, id: CellId) bool {
        const c = g.cell(id);
        return c.expires_ns > g.bound(g.payer) or (g.fresh(id) and g.pays(id));
    }

    /// Does the running rule's payer already wait on `id`?
    fn pays(g: *Graph, id: CellId) bool {
        g.checks += 1;
        var stack: std.ArrayList(CellId) = .empty;
        stack.append(g.scratch.allocator(), id) catch return false;
        while (stack.pop()) |i| {
            const c = g.cell(i);
            if (c.seen == g.checks) continue;
            c.seen = g.checks;
            if (budgetOf(c)) |b| if (b == g.payer) return true;
            stack.appendSlice(g.scratch.allocator(), c.waiters.items) catch return false;
        }
        return false;
    }

    fn materialise(g: *Graph, key: Key, name: dns.Name, e: store.Entry) !CellId {
        const id = try g.newCell(key, name);
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

    pub const Recalled = struct { blob: *store.Blob, rrset: store.Rrset, expires_ns: i64 };

    /// The answer rule read against the store, building no cell: the
    /// question's chain as stored, into `arena`. `.fresh` is what the rule
    /// would settle on for a client, whose bound is now; `.any` is every
    /// age, for the callers that decide what age serves. Null where the
    /// rule would have work to do: a hop not stored, not judged or no
    /// longer proven (DNSSEC on), or a broken chain. The blobs are the
    /// store's; the caller refs what it keeps.
    pub fn recall(g: *Graph, arena: Allocator, name: dns.Name, qtype: dns.RType, age: Age) !?[]const Recalled {
        var hops: std.ArrayList(Recalled) = .empty;
        var links: walk.Links = .{};
        var next = name;
        while (true) {
            const e = g.storedHop(next, qtype, age) orelse return null;
            const v = e.blob.verdict;
            if (g.cfg.trust_anchor != null and !(if (age == .fresh) v.serves(g.now()) else v.judged())) return null;
            const r: store.Rrset = .of(e.blob);
            try hops.append(arena, .{ .blob = e.blob, .rrset = r, .expires_ns = e.expires_ns });
            var pos: usize = 0;
            const target: dns.Name = if (r.kind == .alias) try dns.readNameWire(arena, r.target, &pos) else .{ .labels = &.{} };
            var it = r.sections[0].iterator();
            while (it.next()) |rr| if (rr.rtype() == .cname) {
                var at: usize = 0;
                if (links.pass(try dns.readNameWire(arena, rr.owner, &at)) != null) return null;
            };
            switch (links.end(r.kind, target, qtype)) {
                .done => return hops.items,
                .next => |nx| next = nx,
                .broken => return null,
            }
        }
    }

    pub const Age = enum { fresh, any };

    /// `demandHop`, read from the store. Inline: it is a hit's lookup.
    pub inline fn storedHop(g: *Graph, name: dns.Name, qtype: dns.RType, age: Age) ?store.Entry {
        var kb: KeyBuf = undefined;
        const own = @call(.always_inline, Key.of, .{ &kb, .rrset, name, qtype });
        if (g.entry(own, age)) |e| return e;
        if (!walk.cnameAnswers(qtype)) return null;
        const e = g.entry(own.at(.rrset, .cname), age) orelse return null;
        return if (store.Rrset.of(e.blob).kind == .alias) e else null;
    }

    inline fn entry(g: *Graph, key: Key, age: Age) ?store.Entry {
        return if (age == .fresh) g.store.get(key, g.now()) else g.store.any(key);
    }

    /// No cell, no wait: `demand` is the only pin.
    pub fn peek(g: *Graph, key: Key) !?Fact {
        const live = g.index.get(key);
        if (g.store.get(key, g.now())) |e| return try g.factOf(live, e);
        const id = live orelse return null;
        return if (g.fresh(id)) g.liveFact(id) else null;
    }

    /// Null on a cycle, or on new work for an orphan. New work that failed
    /// recently settles as that failure, its rule never run.
    pub fn demand(g: *Graph, by: CellId, key: Key, name: dns.Name) !?CellId {
        const live = g.index.get(key);
        return g.demandFound(by, key, name, live, g.served(key, live));
    }

    /// `demand` for a step of an answer's chain, `own` the rrset at `name`:
    /// the type's own set where held, as it may hold more of the chain;
    /// else an alias held at the name; else the own set, to fetch. Each key
    /// is read once.
    pub fn demandHop(g: *Graph, by: CellId, own: Key, name: dns.Name) !?CellId {
        const live = g.index.get(own);
        const found = g.served(own, live);
        const holds_own = if (found) |s| s == .stored or g.cell(s.live).state == .fact else false;
        if (!holds_own and walk.cnameAnswers(own.rtype)) {
            const alias = own.at(.rrset, .cname);
            const alias_live = g.index.get(alias);
            if (g.served(alias, alias_live)) |s| if (switch (s) {
                .stored => |e| store.Rrset.of(e.blob).kind == .alias,
                .live => |id| g.cell(id).state == .fact and g.cell(id).state.fact.rrset.kind == .alias,
            }) return g.demandFound(by, alias, name, alias_live, s);
        }
        return g.demandFound(by, own, name, live, found);
    }

    fn demandFound(g: *Graph, by: CellId, key: Key, name: dns.Name, live: ?CellId, found: ?Served) !?CellId {
        if (try g.lookup(key, name, live, found)) |id| return g.join(by, id);
        if (g.cell(by).orphan) return null;
        const id = try g.newCell(key, name);
        try g.pin(id, by);
        if (g.refused(key)) |why| try g.fail(id, why) else try g.ready.append(g.gpa, id);
        return id;
    }

    pub fn join(g: *Graph, by: CellId, id: CellId) !?CellId {
        if (!g.fresh(id) and g.reaches(by, id)) return null;
        try g.pin(id, by);
        return id;
    }

    /// The first question waiting on `id`, depth first in pin order, whose
    /// budget has room; else the first one at all. None for an orphan.
    fn payerOf(g: *Graph, id: CellId) ?*Budget {
        g.checks += 1;
        var first: ?*Budget = null;
        var stack: std.ArrayList(CellId) = .empty;
        stack.append(g.scratch.allocator(), id) catch return null;
        while (stack.pop()) |i| {
            const c = g.cell(i);
            if (c.seen == g.checks or c.orphan) continue;
            c.seen = g.checks;
            if (budgetOf(c)) |b| {
                if (!g.spent(b)) return b;
                first = first orelse b;
                continue;
            }
            var w = c.waiters.items.len;
            while (w > 0) {
                w -= 1;
                stack.append(g.scratch.allocator(), c.waiters.items[w]) catch return first;
            }
        }
        return first;
    }

    fn budgetOf(c: *const Cell) ?*Budget {
        return switch (c.scratch) {
            .answer => |a| a.budget,
            .ahead => |k| k.budget,
            else => null,
        };
    }

    fn unref(g: *Graph, b: *Budget) void {
        b.refs -= 1;
        if (b.refs > 0) return;
        g.work.allocator().destroy(b);
        g.budgets -= 1;
    }

    /// The deadline or query budget that stops `b` asking: the asker's
    /// reasons, never the servers'.
    pub fn limit(g: *const Graph, b: *const Budget) ?Failure {
        if (g.now() >= b.deadline_ns) return .{ .code = .other, .text = "resolution deadline passed", .cause = .asker };
        if (b.queries >= g.cfg.max_queries) return .{ .code = .other, .text = "query budget spent", .cause = .asker };
        return null;
    }

    pub fn spent(g: *const Graph, b: *const Budget) bool {
        return g.limit(b) != null or b.validation.exhausted();
    }

    /// NS-address sub-resolutions (an addr's own rrsets) between `id` and
    /// its nearest question, along the shortest demand chain; 0 for an orphan.
    pub fn level(g: *Graph, id: CellId) u8 {
        g.checks += 1;
        const gpa = g.scratch.allocator();
        var here: std.ArrayList(CellId) = .empty;
        var next: std.ArrayList(CellId) = .empty;
        here.append(gpa, id) catch return 0;
        var d: u8 = 0;
        while (true) : (d +|= 1) {
            while (here.pop()) |i| {
                const c = g.cell(i);
                if (c.seen == g.checks or c.orphan) continue;
                c.seen = g.checks;
                if (budgetOf(c) != null) return d;
                for (c.waiters.items) |w| {
                    const list = if (c.key.kind == .rrset and g.cell(w).key.kind == .addr) &next else &here;
                    list.append(gpa, w) catch return d;
                }
            }
            if (next.items.len == 0) return 0;
            std.mem.swap(std.ArrayList(CellId), &here, &next);
        }
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

    /// What a reply says for another key: settles a cell in progress for it,
    /// except the publisher's own; else a fact, or, awaiting a verdict, held
    /// by an `ahead` root for its judge. A served version stands: bytes
    /// nobody judged displace none.
    pub fn publish(g: *Graph, key: Key, name: dns.Name, by: CellId, value: Value, expires_ns: i64) !void {
        if (g.index.get(key)) |id| if (id != by and !g.cell(id).settled()) return g.settle(id, value, expires_ns);
        if (!g.awaitsVerdict(key.kind)) {
            _ = try g.fact(key, value, expires_ns);
            return;
        }
        if (expires_ns <= g.now() or g.holds(key)) return;
        const root = try g.ahead(key, name) orelse return;
        const s = g.cell(root).scratch.ahead;
        if (s.rrset != .none) return;
        const id = try g.newCell(key, name);
        try g.pin(id, root);
        s.rrset = .wrap(id);
        try g.settle(id, value, expires_ns);
    }

    /// Judged already, or of a kind nobody judges. The bytes the store
    /// kept, borrowed; null when it kept none.
    pub fn fact(g: *Graph, key: Key, value: Value, expires_ns: i64) !?*store.Blob {
        if (expires_ns <= g.now()) return null;
        const blob = try g.store.build(value);
        g.store.put(key, blob, expires_ns, g.now()) catch |err| {
            g.store.unref(blob);
            if (err != error.Refused) return err;
            return null;
        };
        return g.kept(key, blob);
    }

    /// `blob`, if it is what the store holds for `key`: a put may refuse
    /// it, or evict it as it lands.
    fn kept(g: *Graph, key: Key, blob: ?*store.Blob) ?*store.Blob {
        const b = blob orelse return null;
        const e = g.store.any(key) orelse return null;
        return if (e.blob == b) b else null;
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
        // Debug frees it, so a read past its run fails every time, not by luck.
        _ = g.scratch.reset(if (builtin.mode == .debug) .free_all else .retain_capacity);
        g.unpaid = .{ .deadline_ns = 0, .validation = .{ .max_sig_verify = 0, .max_nsec3_blocks = 0 } };
        g.payer = g.payerOf(id) orelse &g.unpaid;
        defer g.payer = &g.unpaid;
        g.tally.runs += 1;
        const clock = Tally.clock(&g.tally.rule_ns);
        defer clock.stop();
        // Ended waiting and created nothing: the model's own cost.
        const created_before = g.created;
        defer if (g.cell(id).live and !g.cell(id).settled() and g.created == created_before) {
            g.tally.reruns += 1;
            if (Tally.timed) g.tally.rerun_ns += @intCast(monotonic.nowNs() - clock.t0);
        };
        switch (g.cell(id).key.kind) {
            .cut => try walk.runCut(g, id),
            .rrset => try walk.runRrset(g, id),
            .addr => try walk.runAddr(g, id),
            .answer, .refresh => try walk.runAnswer(g, id),
            .ds => try trust.runDs(g, id),
            .dnskey => try trust.runDnskey(g, id),
            .secure => try trust.runSecure(g, id),
            .ahead => try trust.runAhead(g, id),
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

    fn nowMs(g: *const Graph) i64 {
        return @divTrunc(g.now(), std.time.ns_per_ms);
    }

    pub fn band(g: *Graph, server: na.AddressKey) i64 {
        return (g.rtt.get(server) orelse ns_rtt.RttState.unknown).band(g.nowMs());
    }

    pub fn isDead(g: *Graph, server: na.AddressKey) bool {
        return g.band(server) == ns_rtt.dead_band;
    }

    // ── Exchanges ──────────────────────────────────────────────────────

    pub const Sent = struct { id: CellId, est: ns_rtt.RttState };

    /// Null, like `demand`, when the payer's budget or deadline, or the
    /// asker's orphaning, refuses the work.
    pub fn exchange(g: *Graph, by: CellId, server: na.AddressKey, transport: Transport, case: Case, qname: dns.Name, qtype: dns.RType, uncapped: bool) !?Sent {
        std.debug.assert(case == .random or transport == .tcp);
        // The run's payer may spend itself mid-run while another waiter
        // still has room: the shared work goes on at that one's cost.
        if (g.limit(g.payer) != null) g.payer = g.payerOf(by) orelse g.payer;
        const budget = g.payer;
        const stop: ?[]const u8 = if (g.cell(by).orphan) "orphan" else if (g.limit(budget)) |why| why.text else null;
        if (stop) |why| {
            if (g.cfg.trace) {
                var nb: [dns.max_dotted_len + 1]u8 = undefined;
                std.debug.print("  {s} {t} refused: {s}\n", .{ qname.formatInto(&nb), qtype, why });
            }
            return null;
        }
        const id = try g.newCell(.init(.exchange, "", .a), qname);
        try g.pin(id, by);
        budget.queries += 1;
        g.cell(id).holds += 1;
        const clock = Tally.clock(&g.tally.send_ns);
        defer clock.stop();
        const rng = g.edge.rng;
        var name_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const qid = rng.int(u16);
        const arena = g.cell(id).arena.allocator();
        const msg = try dns.buildQuery(arena, qid, qname.formatInto(&name_buf), qtype, .{ .rd = false, .edns = .{ .do_bit = g.cfg.trust_anchor != null }, .case_rng = if (case == .random) rng else null });
        var wire_buf: [512]u8 = undefined;
        const wire = try arena.dupe(u8, try dns.serializeMessage(&wire_buf, msg));
        const sc = try arena.create(ExchangeScratch);
        const est = g.rtt.getPtr(server);
        const state = if (est) |s| s.* else ns_rtt.RttState.unknown;
        // Silent past the capped wait is silent, however long this send waits.
        const owed_at = g.now() + @as(i64, state.timeout(false, transport)) * std.time.ns_per_ms;
        const timeout_at = g.now() + @as(i64, state.timeout(uncapped, transport)) * std.time.ns_per_ms;
        const deadline_ns = @min(budget.deadline_ns, timeout_at);
        if (est) |s| s.sent(@divTrunc(deadline_ns, std.time.ns_per_ms) + 1);
        const addr = server.toAddress();
        sc.* = .{ .id = qid, .sent_name = msg.questions[0].name, .qtype = qtype, .server = addr, .transport = transport, .case = case, .sent_ns = g.now(), .cut_short = budget.deadline_ns <= owed_at };
        g.cell(id).scratch = .{ .exchange = sc };
        try g.edge.send(.{
            .id = id,
            .server = addr,
            .transport = transport,
            .wire = wire,
            .deadline_ns = deadline_ns,
        });
        g.flights += 1;
        if (transport == .udp) g.stats.resolver.exchanges.udp += 1 else g.stats.resolver.exchanges.tcp += 1;
        return .{ .id = id, .est = state };
    }
};

test "a cell replacing an expired one takes over the index entry's key" {
    var kb: KeyBuf = undefined;
    const testing = std.testing;
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    const Stub = struct {
        fn send(_: *anyopaque, _: Exchange) anyerror!void {}
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
    };
    var g = try Graph.init(testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = rand.thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const name = try dns.parseDottedName(arena.allocator(), "example.");
    const first = try g.demandRoot(name, .a, .new);
    try g.settle(first, .{ .answer = .{ .hops = &.{} } }, now);
    const second = try g.demandRoot(name, .a, .new);
    try testing.expect(first != second);
    g.unhold(first);
    try testing.expect(!g.cell(first).live);
    // The entry's key must be the survivor's.
    const key = Key.of(&kb, .answer, name, .a);
    try testing.expectEqual(second, g.index.get(key).?);
    try testing.expectEqual(g.cell(second).key.name.ptr, g.index.getKey(key).?.name.ptr);
    g.unhold(second);
}

test "a joiner starts nothing, and past the work ceiling joins only what is settled" {
    const testing = std.testing;
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    const Stub = struct {
        fn send(_: *anyopaque, _: Exchange) anyerror!void {}
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
    };
    var g = try Graph.init(testing.allocator, .{ .root_hints = &.{}, .max_work_bytes = 1 }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = rand.thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const name = try dns.parseDottedName(arena.allocator(), "example.");
    try testing.expectError(error.Novel, g.demandRoot(name, .a, .join));
    const first = try g.demandRoot(name, .a, .new);
    // Its own bytes are past the ceiling: nothing unsettled is joined or started.
    try testing.expectError(error.Full, g.demandRoot(name, .a, .join));
    try testing.expectError(error.Full, g.demandRoot(try dns.parseDottedName(arena.allocator(), "other."), .a, .new));
    try g.settle(first, .{ .answer = .{ .hops = &.{} } }, now + std.time.ns_per_s);
    try testing.expectEqual(first, try g.demandRoot(name, .a, .join));
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
    var g = try Graph.init(testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = rand.thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
    defer g.deinit();
    const root_cut: Key = .init(.cut, "", .a);
    g.store.drop(root_cut, g.store.any(root_cut).?.blob);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = try g.demandRoot(try dns.parseDottedName(arena.allocator(), "com."), .a, .new);
    try g.drain();
    try testing.expect(g.store.get(root_cut, now) != null);
    g.unhold(root);
}

test "a shared cell is paid by a waiting question with room, not its first demander" {
    var kb: KeyBuf = undefined;
    const testing = std.testing;
    var now: i64 = std.time.ns_per_s;
    var wall: i64 = 0;
    var ctx: u8 = 0;
    const Stub = struct {
        fn send(_: *anyopaque, _: Exchange) anyerror!void {}
        fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
    };
    var g = try Graph.init(testing.allocator, .{ .root_hints = &.{} }, .{ .ctx = &ctx, .now_ns = &now, .wall_sec = &wall, .rng = rand.thread, .sendFn = Stub.send, .wakeFn = Stub.wake });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const host = try dns.parseDottedName(arena.allocator(), "ns.example.");
    const first = try g.demandRoot(try dns.parseDottedName(arena.allocator(), "a.example."), .a, .new);
    const second = try g.demandRoot(host, .a, .new);
    const shared = try g.newCell(Key.of(&kb, .rrset, host, .a), host);
    try g.pin(shared, first);
    try g.pin(shared, second);
    g.cell(first).scratch.answer.budget.queries = g.cfg.max_queries;
    try testing.expectEqual(g.cell(second).scratch.answer.budget, g.payerOf(shared).?);
    // Nobody with room: the first still pays, and is refused.
    g.cell(second).scratch.answer.budget.queries = g.cfg.max_queries;
    try testing.expectEqual(g.cell(first).scratch.answer.budget, g.payerOf(shared).?);
    g.payer = g.cell(first).scratch.answer.budget;
    try testing.expectEqual(null, try g.exchange(shared, .fromAddress(na.initIp4(.{ 127, 0, 0, 1 }, 53)), .udp, .random, host, .a, true));
    g.cell(second).scratch.answer.budget.queries = 0;
    g.payer = g.cell(first).scratch.answer.budget;
    try testing.expect(try g.exchange(shared, .fromAddress(na.initIp4(.{ 127, 0, 0, 1 }, 53)), .udp, .random, host, .a, true) != null);
    try testing.expectEqual(1, g.cell(second).scratch.answer.budget.queries);
    g.payer = &g.unpaid;
    g.unhold(first);
    g.unhold(second);
}

test "a key's name hash follows the process seed" {
    const saved = rand.hash_seed;
    defer rand.hash_seed = saved;
    const a: Key = .init(.rrset, "www.example", .a);
    rand.hash_seed = 0xdeadbeefcafef00d;
    const b: Key = .init(.rrset, "www.example", .a);
    try std.testing.expect(a.name_hash != b.name_hash);
}
