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
const Arena = @import("arena.zig");
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
const stub = @import("stub.zig");
const chaos = @import("chaos.zig");

/// A DNAME and its synthesised CNAME count once. Chains in the wild run to
/// 12; resolvers stop at 10 to 19.
pub const max_links = 14;

pub const CellId = u32;

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

pub const Need = enum {
    datagram,
    stream,

    pub fn plainRounds(n: Need) u32 {
        return switch (n) {
            .datagram => 1,
            .stream => 2,
        };
    }
};

pub const Exchange = struct {
    id: CellId,
    server: na.Address,
    need: Need,
    /// Held by the cell until the exchange completes.
    wire: []const u8,
    deadline_ns: i64,
};

pub const Exposure = enum(u2) {
    none,
    encrypted,
    cleartext,

    pub fn max(a: Exposure, b: Exposure) Exposure {
        return if (@backingInt(a) >= @backingInt(b)) a else b;
    }
};

pub const Quote = struct {
    rounds: u32,
    exposure: Exposure,
};

pub const Heard = struct {
    /// Borrowed for the call: the cell parses its own copy.
    bytes: []const u8,
    stream: bool = false,
    queued_ns: i64 = 0,
};

pub const Completion = union(enum) {
    reply: Heard,
    timeout,
    unsent,
    moved,
    /// The cell's generation, since ids recycle.
    wake: u32,
};

pub const Edge = struct {
    ctx: *anyopaque,
    now_ns: *const i64,
    wall_sec: *const i64,
    rng: std.Random,
    sendFn: *const fn (*anyopaque, Exchange) anyerror!Exposure,
    wakeFn: *const fn (*anyopaque, CellId, u32, i64) anyerror!void,
    quoteFn: ?*const fn (*anyopaque, na.AddressKey, Need) Quote = null,
    chaos: ?*chaos.Chaos = null,

    pub fn send(e: Edge, ex: Exchange) !Exposure {
        return e.sendFn(e.ctx, ex);
    }

    pub fn wake(e: Edge, id: CellId, gen: u32, at_ns: i64) !void {
        return e.wakeFn(e.ctx, id, gen, at_ns);
    }

    pub fn quote(e: Edge, server: na.AddressKey, need: Need) Quote {
        const f = e.quoteFn orelse return .{ .rounds = need.plainRounds(), .exposure = .cleartext };
        return f(e.ctx, server, need);
    }
};

/// `parental` is held for the denial index alone and is never a cell.
pub const Kind = enum(u8) { cut, addr, rrset, stub, answer, ds, dnskey, secure, exchange, refresh, ahead, parental };

pub const Key = struct {
    kind: Kind,
    rtype: dns.RType,
    name: []const u8,
    name_hash: u32,

    /// Borrows `name`: whatever keeps a key dupes it.
    pub fn of(kind: Kind, name: dns.Name, rtype: dns.RType) Key {
        return .init(kind, name.wire, rtype);
    }

    pub fn shown(k: Key, buf: *[dns.max_dotted_len + 1]u8) []const u8 {
        return if (k.name.len == 0) "" else dns.Name.of(k.name).formatInto(buf);
    }

    pub fn init(kind: Kind, name: []const u8, rtype: dns.RType) Key {
        return .{ .kind = kind, .rtype = rtype, .name = name, .name_hash = hashName(name) };
    }

    pub fn at(k: Key, kind: Kind, rtype: dns.RType) Key {
        return .{ .kind = kind, .rtype = rtype, .name = k.name, .name_hash = k.name_hash };
    }

    fn hashName(name: []const u8) u32 {
        return @truncate(std.hash.Wyhash.hash(rand.hash_seed, name));
    }

    pub fn hash(k: Key) u64 {
        if (builtin.mode == .debug) std.debug.assert(k.name_hash == hashName(k.name));
        const x = @as(u64, k.name_hash) << 32 | @as(u64, @backingInt(k.kind)) << 16 | @backingInt(k.rtype);
        const p = @as(u128, x) * 0x9e3779b97f4a7c15;
        return @truncate(p ^ p >> 64);
    }

    pub fn eql(a: Key, b: Key) bool {
        return a.kind == b.kind and a.rtype == b.rtype and mem.eql(u8, a.name, b.name);
    }

    pub const Context = struct {
        pub fn hash(_: Context, k: Key) u32 {
            return @truncate(k.hash());
        }
        pub fn eql(_: Context, a: Key, b: Key, _: usize) bool {
            return a.eql(b);
        }
    };
};

pub const Asked = struct {
    key: Key,
    as_of: i64,

    fn hash(a: Asked) u32 {
        return @truncate(a.key.hash() ^ @as(u64, @bitCast(a.as_of)) *% 0x9e3779b97f4a7c15);
    }
};

pub const Config = struct {
    qmin: bool = true,
    root_hints: []const na.Address,
    stub_zones: []const stub.Zone = &.{},
    addr_policy: delegation.AddrPolicy = .{},
    max_queries: u32 = 100,
    resolve_ms: u32 = 7000,
    stagger_ms: u32 = 150,
    max_resolve_depth: u8 = 3,
    max_flights: u32 = std.math.maxInt(u32),
    max_work_bytes: usize = std.math.maxInt(usize),
    servfail_ttl: u32 = 5,
    prefetch: bool = false,
    trust_anchors: ?[]const dns.DsData = null,
    store_bytes: usize = 12 << 20,
    trace: bool = false,
};

pub const Cut = struct {
    zone: dns.Name,
    servers: []const Server = &.{},
    placed_until_ns: i64 = std.math.maxInt(i64),
};

pub const Server = struct {
    key: Key,
    glue: []const na.AddressKey = &.{},
};

pub const Reply = struct {
    kind: Of,
    aa: bool,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
    additionals: []const dns.ResourceRecord = &.{},
    target: dns.Name = .root,
    zone: dns.Name = .root,
    ede: ?dns.Ede.Code = null,
    stored_ns: i64 = 0,
    ttl: u32 = 0,

    pub const Of = enum {
        answer,
        alias,
        nodata,
        nxdomain,
        yxdomain,

        pub fn rcode(k: Of) dns.RCode {
            return switch (k) {
                .answer, .alias, .nodata => .no_error,
                .nxdomain => .name_error,
                .yxdomain => .yx_domain,
            };
        }
    };
};

pub const Answer = struct {
    hops: []const Hop,

    pub const Hop = struct {
        set: CellId,
        judge: OptionalCellId = .none,
    };
};

pub const Outcome = union(enum) {
    reply: struct { msg: dns.Message, rtt_ns: i64, stream: bool },
    timeout,
    unsent,
    moved,
    mismatch,
    malformed,
    oversized,
};

/// Plain goes only by stream, where a forger cannot follow.
pub const Case = enum { random, plain };

pub const Failure = struct {
    code: dns.Ede.Code,
    text: []const u8 = "",
    cause: enum { zone, host, asker } = .zone,
    remembered: bool = false,
    unplaced: bool = false,

    pub const unreachable_authority: Failure = .{ .code = .no_reachable_authority };
};

pub const Value = union(Kind) {
    cut: Cut,
    addr: []const na.AddressKey,
    rrset: Reply,
    stub: Reply,
    answer: Answer,
    ds: trust.Chain,
    dnskey: trust.Chain,
    secure: trust.Chain,
    exchange: Outcome,
    refresh: void,
    ahead: void,
    parental: void,

    pub fn reply(v: Value) Reply {
        return switch (v) {
            .rrset, .stub => |r| r,
            .cut, .addr, .answer, .ds, .dnskey, .secure, .exchange, .refresh, .ahead, .parental => unreachable,
        };
    }
};

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

pub const Budget = struct {
    queries: u32 = 0,
    deadline_ns: i64,
    refs: u32 = 1,
    validation: rrsig.ValidationBudget = .{},

    pub fn validationStop(b: *const Budget) ?Failure {
        return switch (b.validation.stopped orelse return null) {
            .nsec3 => .{ .code = .unsupported_nsec3_iterations, .text = "nsec3 budget spent", .cause = .asker },
            .verify => .{ .code = .other, .text = "validation budget spent", .cause = .asker },
        };
    }
};

pub const Stats = struct {
    resolver: struct {
        exchanges: struct { datagram: u64 = 0, stream: u64 = 0 } = .{},
        faults: struct {
            timeout: u64 = 0,
            unsent: u64 = 0,
            moved: u64 = 0,
        } = .{},
        early: struct { refresh: u64 = 0 } = .{},
        detail: struct {
            retry: u64 = 0,
            unrefreshed: u64 = 0,
            ahead: u64 = 0,
        } = .{},
    } = .{},
    trust: struct { secure: u64 = 0, insecure: u64 = 0, bogus: u64 = 0 } = .{},
};

const max_failed = 4096;

const Refusal = struct { until_ns: i64, why: Failure };

const refresh_jitter_ns = std.time.ns_per_s;

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
    reaches: u64 = 0,
    reaches_visits: u64 = 0,

    pub const timed = builtin.is_test;

    pub const Clock = struct {
        t0: i64,
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
    sent: []const u8,
    qtype: dns.RType,
    server: na.Address,
    need: Need,
    case: Case,
    sent_ns: i64,
    /// The payer's deadline came before the wait the server is owed, so a
    /// timeout says nothing about the server or its zone.
    cut_short: bool,
};

pub const Scratch = union(enum) {
    none,
    cut: *walk.CutScratch,
    addr: *walk.AddrScratch,
    rrset: *walk.RrsetScratch,
    stub: *stub.Scratch,
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
            .parental => unreachable,
            inline else => |k| blk: {
                const p = try arena.create(@typeInfo(@FieldType(Scratch, @tagName(k))).pointer.child);
                p.* = .{};
                break :blk @unionInit(Scratch, @tagName(k), p);
            },
        };
    }
};

pub const Cell = struct {
    key: Key,
    name: dns.Name,
    /// The instant whose facts the cell reads: 0 is now, a client's; a refresh's
    /// is when the life it renews lapses. The two never share a cell.
    as_of: i64,
    orphan: bool = false,
    seen: u64 = 0,
    state: State = .pending,
    bare_expires_ns: i64 = 0,
    waiters: std.DoublyLinkedList = .{},
    inputs: std.SinglyLinkedList = .{},
    holds: u32 = 0,
    backers: u32 = 0,
    scratch: Scratch = .none,
    blob: ?*store.Blob = null,
    arena: Arena,

    comptime {
        std.debug.assert(@sizeOf(Cell) <= 176);
    }

    pub const State = union(enum) { pending, fact: *Value, failure: *const Failure };

    pub fn expires(c: *const Cell) i64 {
        return if (c.blob) |b| b.expires_ns else c.bare_expires_ns;
    }

    pub fn settled(c: *const Cell) bool {
        return c.state != .pending;
    }

    pub fn failure(c: *const Cell) ?Failure {
        return if (c.state == .failure) c.state.failure.* else null;
    }

    fn own(c: *Cell, v: anytype) !*@TypeOf(v) {
        const p = try c.arena.allocator().create(@TypeOf(v));
        p.* = v;
        return p;
    }

    fn inFlight(c: *const Cell, g: *Graph) bool {
        var it = c.inputIds();
        while (it.next()) |i| {
            const in = g.cell(i);
            if (in.key.kind == .exchange and !in.settled()) return true;
        }
        return false;
    }

    fn waiterIds(c: *const Cell) Pin.Waiters {
        return .{ .at = c.waiters.first };
    }

    fn inputIds(c: *const Cell) Pin.Inputs {
        return .{ .at = c.inputs.first };
    }
};

const Pin = struct {
    on: CellId,
    by: CellId,
    waiter: std.DoublyLinkedList.Node = .{},
    input: std.SinglyLinkedList.Node = .{},

    fn ofWaiter(n: *std.DoublyLinkedList.Node) *Pin {
        return @fieldParentPtr("waiter", n);
    }

    fn ofInput(n: *std.SinglyLinkedList.Node) *Pin {
        return @fieldParentPtr("input", n);
    }

    const Waiters = struct {
        at: ?*std.DoublyLinkedList.Node,

        fn next(w: *Waiters) ?CellId {
            const n = w.at orelse return null;
            w.at = n.next;
            return ofWaiter(n).by;
        }
    };

    const Inputs = struct {
        at: ?*std.SinglyLinkedList.Node,

        fn next(i: *Inputs) ?CellId {
            const n = i.at orelse return null;
            i.at = n.next;
            return ofInput(n).on;
        }
    };
};

const Slot = struct {
    cell: ?*Cell = null,
    /// Bumped at each free, so a held id can tell its cell from the slot's next.
    gen: u32 = 0,
    next: OptionalCellId = .none,
};

pub const Graph = struct {
    gpa: Allocator,
    work: Work,
    cfg: Config,
    edge: Edge,
    scratch: Arena,
    cells: std.ArrayList(Slot) = .empty,
    empty: OptionalCellId = .none,
    checks: u64 = 0,
    live: u32 = 0,
    budgets: u32 = 0,
    payer: *Budget = undefined,
    as_of: i64 = 0,
    unpaid: Budget = undefined,
    flights: u32 = 0,
    failed: std.array_hash_map.Custom(Key, Refusal, Key.Context, true) = .empty,
    stats: Stats = .{},
    created: u64 = 0,
    index: std.array_hash_map.Custom(CellId, void, struct {}, true) = .empty,
    ready: std.ArrayList(Queued) = .empty,
    answered: std.ArrayList(CellId) = .empty,
    rtt: *ns_rtt.Table,
    tally: Tally = .{},
    schedule: if (builtin.is_test) u64 else void = if (builtin.is_test) 0 else {},
    denial: denial.Index = .{},
    verify_memo: rrsig.VerifyMemo = .{},
    store: store.Store,

    pub fn init(gpa: Allocator, work: Allocator, cfg: Config, edge: Edge) !Graph {
        const rtt = try ns_rtt.Table.create(gpa);
        var g: Graph = .{ .gpa = gpa, .work = .{ .child = work }, .cfg = cfg, .edge = edge, .scratch = .init(gpa), .rtt = rtt, .store = store.Store.init(gpa, cfg.store_bytes) catch |err| {
            gpa.destroy(rtt);
            return err;
        } };
        errdefer g.deinit();
        g.store.on_evict = evicted;
        const forgoes = if (g.chaosAt(.memo)) |ch| try ch.choose(.memo, ch.named(.memo, 0), 2, .none) == 1 else false;
        if (cfg.trust_anchors != null and !forgoes) g.verify_memo = try .init(gpa);
        // The root cut is an axiom; `runCut` re-derives it if evicted.
        _ = try g.fact(.of(.cut, .root, .a), .{ .cut = .{ .zone = .root } }, std.math.maxInt(i64));
        return g;
    }

    fn evicted(s: *store.Store, blob: *store.Blob) void {
        denial.evicted(@fieldParentPtr("store", s), blob);
    }

    pub fn deinit(g: *Graph) void {
        // Not `free`: in slot order a cell would unpin from inputs gone first.
        for (g.cells.items) |s| if (s.cell) |c| {
            while (c.inputs.popFirst()) |n| g.work.allocator().destroy(Pin.ofInput(n));
            if (c.blob) |bl| g.store.unref(bl);
            if (budgetOf(c)) |b| g.unref(b);
            c.arena.deinit();
            g.work.allocator().destroy(c);
        };
        g.cells.deinit(g.gpa);
        g.scratch.deinit();
        g.index.deinit(g.gpa);
        g.ready.deinit(g.gpa);
        g.answered.deinit(g.gpa);
        g.gpa.destroy(g.rtt);
        for (g.failed.keys()) |k| g.gpa.free(k.name);
        g.failed.deinit(g.gpa);
        g.denial.deinit(g.gpa, &g.store);
        g.verify_memo.deinit(g.gpa);
        g.store.deinit();
    }

    pub fn now(g: *const Graph) i64 {
        return g.edge.now_ns.*;
    }

    /// Truncated on purpose: signature times are serials, wall seconds mod 2^32 (RFC 4034 §3.1.5).
    pub fn wallNow(g: *const Graph) u32 {
        return @truncate(@as(u64, @bitCast(g.edge.wall_sec.*)));
    }

    pub fn cell(g: *Graph, id: CellId) *Cell {
        return g.cells.items[id].cell.?;
    }

    pub fn alive(g: *Graph, id: CellId) ?*Cell {
        return g.cells.items[id].cell;
    }

    pub fn gen(g: *const Graph, id: CellId) u32 {
        return g.cells.items[id].gen;
    }

    pub const Admit = enum { join, new };

    pub fn demandRoot(g: *Graph, name: dns.Name, qtype: dns.RType, admit: Admit) !CellId {
        const key = Key.of(.answer, name, qtype);
        if (g.asking(.{ .key = key, .as_of = 0 })) |id| if (!g.cell(id).settled() or g.fresh(id)) {
            if (!g.cell(id).settled() and g.work.bytes >= g.cfg.max_work_bytes) return error.Full;
            g.cell(id).holds += 1;
            return id;
        };
        if (admit != .new) return error.Novel;
        if (g.flights >= g.cfg.max_flights or g.work.bytes >= g.cfg.max_work_bytes) return error.Full;
        const id = try g.newRoot(key, name, 0, .{ .deadline_ns = g.now() + @as(i64, g.cfg.resolve_ms) * std.time.ns_per_ms });
        g.cell(id).holds += 1;
        errdefer g.unhold(id);
        try g.enqueue(id);
        return id;
    }

    pub fn unhold(g: *Graph, id: CellId) void {
        g.cell(id).holds -= 1;
        g.release(id);
    }

    pub fn fetchKeys(g: *Graph, zone: dns.Name) !void {
        _ = try g.ahead(Key.of(.rrset, zone, .dnskey), zone);
    }

    fn ahead(g: *Graph, key: Key, name: dns.Name) !?CellId {
        if (g.spent(g.payer) or try g.skips(.ahead, key)) return null;
        const akey = key.at(.ahead, key.rtype);
        if (g.indexed(akey)) |id| if (!g.cell(id).settled()) return id;
        const id = try g.newCell(akey, name, g.as_of);
        g.cell(id).scratch.ahead.budget = g.payer;
        g.payer.refs += 1;
        g.cell(id).holds += 1;
        errdefer g.unhold(id);
        try g.enqueue(id);
        g.stats.resolver.detail.ahead += 1;
        var nb: [dns.max_dotted_len + 1]u8 = undefined;
        if (g.cfg.trace) std.debug.print("  ahead {s} {f}\n", .{ key.shown(&nb), dns.tag(key.rtype) });
        return id;
    }

    pub fn refresh(g: *Graph, key: Key, name: dns.Name, lapses_ns: i64) !void {
        std.debug.assert(lapses_ns > 0);
        const rkey = key.at(.refresh, key.rtype);
        if (g.asking(.{ .key = rkey, .as_of = lapses_ns }) != null or try g.skips(.prefetch, rkey)) return;
        if (g.flights >= g.cfg.max_flights / 2 or g.work.bytes >= g.cfg.max_work_bytes / 2) {
            g.stats.resolver.detail.unrefreshed += 1;
            return;
        }
        const jitter = @min(refresh_jitter_ns, @divTrunc(lapses_ns - g.now(), 2));
        const at = g.now() + if (jitter > 0) @as(i64, @intCast(try g.uniform(.prefetch, rkey, @intCast(jitter)))) else 0;
        const id = try g.newRoot(rkey, name, lapses_ns, .{ .deadline_ns = at + @as(i64, g.cfg.resolve_ms) * std.time.ns_per_ms });
        g.cell(id).holds += 1;
        errdefer g.unhold(id);
        try g.wake(id, at);
        g.stats.resolver.early.refresh += 1;
        var nb: [dns.max_dotted_len + 1]u8 = undefined;
        if (g.cfg.trace) std.debug.print("  refresh {s} {f} in {d} ms\n", .{ key.shown(&nb), dns.tag(key.rtype), @divTrunc(at - g.now(), std.time.ns_per_ms) });
    }

    const Queued = struct { id: CellId, gen: u32 };

    pub fn enqueue(g: *Graph, id: CellId) !void {
        try g.ready.append(g.gpa, .{ .id = id, .gen = g.gen(id) });
    }

    pub fn drain(g: *Graph) !void {
        while (try g.nextReady()) |q| if (g.gen(q.id) == q.gen) try g.run(q.id);
    }

    fn nextReady(g: *Graph) !?Queued {
        const ch = g.chaosAt(.settle) orelse return g.ready.pop();
        const n = g.ready.items.len;
        if (n == 0) return null;
        for (g.ready.items, 0..) |q, i| if (g.gen(q.id) != q.gen or g.cell(q.id).settled()) return g.ready.orderedRemove(i);
        var pick = n - 1;
        if (n > 1) {
            var top: u64 = 0;
            for (g.ready.items, 0..) |q, i| {
                const key = g.cell(q.id).key;
                const draw = try ch.choose(.settle, ch.peek(.settle, key), std.math.maxInt(u64), .{ .key = key });
                if (draw >= top) {
                    pick = i;
                    top = draw;
                }
            }
        }
        const q = g.ready.orderedRemove(pick);
        try ch.spend(.settle, g.cell(q.id).key);
        return q;
    }

    fn chaosAt(g: *const Graph, site: chaos.Site) ?*chaos.Chaos {
        if (!builtin.is_test) return null;
        const ch = g.edge.chaos orelse return null;
        return if (ch.live(site)) ch else null;
    }

    fn decide(g: *Graph, site: chaos.Site, key: Key, n: u64) !u64 {
        const ch = g.chaosAt(site) orelse return 0;
        const event = ch.peek(site, key);
        try ch.spend(site, key);
        return ch.choose(site, event, n, .{ .key = key });
    }

    pub fn uniform(g: *Graph, site: chaos.Site, key: Key, n: usize) !usize {
        if (g.chaosAt(site) == null) return g.edge.rng.uintLessThan(usize, n);
        return @intCast(try g.decide(site, key, n));
    }

    pub fn stretch(g: *Graph, site: chaos.Site, key: Key, ms: u32) !u32 {
        const v = try g.decide(site, key, 4 * @as(u64, ms));
        return if (v == 0) ms else @intCast(v);
    }

    fn skips(g: *Graph, site: chaos.Site, key: Key) !bool {
        return try g.decide(site, key, 2) == 1;
    }

    pub fn forgets(g: *Graph, site: chaos.Site, key: Key) !bool {
        if (try g.decide(site, key, 2) == 0) return false;
        g.edge.chaos.?.forgot = true;
        return true;
    }

    pub fn shuffle(g: *Graph, site: chaos.Site, key: Key, comptime T: type, items: []T) !void {
        if (g.chaosAt(site) == null) return g.edge.rng.shuffle(T, items);
        var i = items.len;
        while (i > 1) {
            i -= 1;
            mem.swap(T, &items[i], &items[i - try g.decide(site, key, i + 1)]);
        }
    }

    pub fn wake(g: *Graph, id: CellId, at_ns: i64) !void {
        std.debug.assert(g.alive(id) != null);
        return g.edge.wake(id, g.gen(id), at_ns);
    }

    pub fn complete(g: *Graph, id: CellId, completion: Completion) !void {
        if (completion == .wake) {
            if (g.gen(id) == completion.wake) try g.enqueue(id);
            return g.drain();
        }
        const c = g.cell(id);
        std.debug.assert(c.key.kind == .exchange);
        const sc = c.scratch.exchange;
        const arena = c.arena.allocator();
        const outcome: Outcome = switch (completion) {
            .wake => unreachable,
            .timeout => .timeout,
            .unsent => .unsent,
            .moved => .moved,
            .reply => |heard| blk: {
                const clock = Tally.clock(&g.tally.parse_ns);
                defer clock.stop();
                g.tally.parses += 1;
                const bytes = try arena.dupe(u8, heard.bytes);
                var p = dns.parse(arena, bytes) catch break :blk .malformed;
                if (p.header.id != sc.id) break :blk .mismatch;
                dns.validateResponse(p.message(), sc.sent, sc.qtype, sc.case == .random) catch break :blk .mismatch;
                // After the match, so a forger gains nothing over a mismatch.
                if (!heard.stream and bytes.len > dns.edns_udp_payload) break :blk .oversized;
                inline for (.{ &p.answers, &p.authorities, &p.additionals }) |section| {
                    var n: usize = 0;
                    for (section.*) |rr| if (rr.rclass == .in) {
                        section.*[n] = rr;
                        n += 1;
                    };
                    section.* = section.*[0..n];
                }
                const scratch = g.scratch.allocator();
                p.answers = try dnssec.bindSets(scratch, p.answers, sc.qtype == .rrsig);
                p.authorities = try dnssec.bindSets(scratch, p.authorities, false);
                p.additionals = try dnssec.bindSets(scratch, p.additionals, false);
                break :blk .{ .reply = .{ .msg = p.message(), .rtt_ns = g.now() - sc.sent_ns - heard.queued_ns, .stream = heard.stream } };
            },
        };
        if (g.cfg.trace) {
            var ab: [64]u8 = undefined;
            var nb: [dns.max_dotted_len + 1]u8 = undefined;
            const over: []const u8 = if (completion == .reply and completion.reply.stream) " over a session" else "";
            std.debug.print("  {s} {s} {f} {t}{s} -> {t}\n", .{ na.format(sc.server, &ab), c.name.formatInto(&nb), dns.tag(sc.qtype), sc.need, over, std.meta.activeTag(outcome) });
            if (outcome == .reply) {
                const m = outcome.reply.msg;
                std.debug.print("      aa={} tc={} ra={} rcode={f} an={d} ns={d} ar={d}\n", .{ m.header.flags.aa, m.header.flags.tc, m.header.flags.ra, dns.tag(m.header.flags.rcode), m.answers.len, m.authorities.len, m.additionals.len });
            }
        }
        switch (outcome) {
            .reply => |r| g.observe(sc.server, r.rtt_ns),
            .timeout => {
                g.stats.resolver.faults.timeout += 1;
                if (!sc.cut_short) g.observeTimeout(sc.server);
            },
            .unsent => g.stats.resolver.faults.unsent += 1,
            .moved => g.stats.resolver.faults.moved += 1,
            .mismatch, .malformed, .oversized => {},
        }
        c.holds -= 1;
        g.flights -= 1;
        try g.settle(id, .{ .exchange = outcome }, g.now());
        try g.drain();
    }

    fn newRoot(g: *Graph, key: Key, name: dns.Name, as_of: i64, budget: Budget) !CellId {
        const b = try g.work.allocator().create(Budget);
        errdefer g.work.allocator().destroy(b);
        b.* = budget;
        b.queries += @intCast(try g.decide(.budget, key, @as(u64, g.cfg.max_queries) + 1));
        const v = &b.validation;
        v.max_sig_verify -= @intCast(try g.decide(.budget, key, v.max_sig_verify + 1));
        v.max_nsec3_blocks -= @intCast(try g.decide(.budget, key, v.max_nsec3_blocks + 1));
        if (b.deadline_ns > g.now()) b.deadline_ns -= @intCast(try g.decide(.budget, key, @intCast(b.deadline_ns - g.now())));
        const id = try g.newCell(key, name, as_of);
        g.cell(id).scratch.answer.budget = b;
        g.budgets += 1;
        return id;
    }

    pub fn newCell(g: *Graph, key: Key, name: dns.Name, as_of: i64) !CellId {
        if (g.empty == .none) {
            try g.cells.append(g.gpa, .{});
            g.empty = .wrap(@intCast(g.cells.items.len - 1));
        }
        const id = g.empty.unwrap().?;
        const c = try g.work.allocator().create(Cell);
        errdefer g.work.allocator().destroy(c);
        var arena: Arena = .init(g.work.allocator());
        errdefer arena.deinit();
        const scratch = try Scratch.init(key.kind, arena.allocator());
        std.debug.assert(key.kind == .exchange or mem.eql(u8, key.name, name.wire));
        const own_name = try name.clone(arena.allocator());
        var own_key = key;
        if (key.kind != .exchange) {
            own_key.name = own_name.wire;
            // A cell in progress keeps the index entry; a settled one yields it.
            const gop = try g.index.getOrPutAdapted(g.gpa, Asked{ .key = key, .as_of = as_of }, Indexed{ .g = g });
            if (!gop.found_existing or g.cell(gop.key_ptr.*).settled()) gop.key_ptr.* = id;
        }
        // Nothing fallible past here: the errdefers assume `c` unbuilt.
        const s = &g.cells.items[id];
        g.empty = s.next;
        s.cell = c;
        c.* = .{
            .key = own_key,
            .name = own_name,
            .as_of = as_of,
            .arena = arena,
            .scratch = scratch,
        };
        g.live += 1;
        g.created += 1;
        return id;
    }

    pub fn pin(g: *Graph, id: CellId, by: CellId) !void {
        const c = g.cell(id);
        const b = g.cell(by);
        std.debug.assert(c.as_of == b.as_of);
        if (g.holdsInput(by, id)) return;
        const p = try g.work.allocator().create(Pin);
        p.* = .{ .on = id, .by = by };
        c.waiters.append(&p.waiter);
        b.inputs.prepend(&p.input);
        if (b.orphan) return;
        c.backers += 1;
        g.adopt(id);
    }

    pub fn holdsInput(g: *Graph, by: CellId, id: CellId) bool {
        var it = g.cell(by).inputIds();
        while (it.next()) |i| if (i == id) return true;
        return false;
    }

    /// Takes the cell, not its id: `free` has already emptied its slot.
    fn unpinAll(g: *Graph, by: *Cell) void {
        while (by.inputs.popFirst()) |n| {
            const p = Pin.ofInput(n);
            const on = p.on;
            const c = g.cell(on);
            c.waiters.remove(&p.waiter);
            if (!by.orphan) c.backers -= 1;
            g.work.allocator().destroy(p);
            g.release(on);
        }
    }

    fn release(g: *Graph, id: CellId) void {
        const c = g.cell(id);
        if (c.holds + c.backers > 0) return;
        if (!c.orphan) {
            c.orphan = true;
            var it = c.inputIds();
            while (it.next()) |i| {
                g.cell(i).backers -= 1;
                g.release(i);
            }
        }
        if (c.holds == 0 and c.waiters.first == null and (c.settled() or !c.inFlight(g))) g.free(id);
    }

    fn adopt(g: *Graph, id: CellId) void {
        const c = g.cell(id);
        if (!c.orphan) return;
        c.orphan = false;
        var it = c.inputIds();
        while (it.next()) |i| {
            g.cell(i).backers += 1;
            g.adopt(i);
        }
    }

    fn free(g: *Graph, id: CellId) void {
        const c = g.cell(id);
        _ = g.index.swapRemoveAdapted(Asked{ .key = c.key, .as_of = c.as_of }, Own{ .id = id });
        const s = &g.cells.items[id];
        s.* = .{ .gen = s.gen +% 1, .next = g.empty };
        g.empty = .wrap(id);
        g.live -= 1;
        g.unpinAll(c);
        if (c.blob) |b| g.store.unref(b);
        if (budgetOf(c)) |b| {
            // A question gone, the key fetches its walk began end too.
            if (c.scratch == .answer) b.deadline_ns = @min(b.deadline_ns, g.now());
            g.unref(b);
        }
        c.arena.deinit();
        g.work.allocator().destroy(c);
    }

    pub fn settle(g: *Graph, id: CellId, value: Value, expires_ns: i64) !void {
        const c = g.cell(id);
        std.debug.assert(!c.settled());
        g.tally.settles += 1;
        if (g.cfg.trace) switch (value) {
            .ds, .dnskey, .secure => |chain| {
                var nb: [dns.max_dotted_len + 1]u8 = undefined;
                std.debug.print("  {t}({s}) -> {t} for {d} s\n", .{ std.meta.activeTag(value), c.name.formatInto(&nb), chain.status, @divTrunc(expires_ns - g.now(), std.time.ns_per_s) });
            },
            .cut, .addr, .rrset, .stub, .answer, .exchange, .refresh, .ahead, .parental => {},
        };
        switch (value) {
            .cut, .rrset, .stub, .ds, .dnskey => {
                const clock = Tally.clock(&g.tally.store_ns);
                defer clock.stop();
                const blob = try g.store.build(c.key, value, expires_ns);
                const owned = owned: {
                    errdefer g.store.unref(blob);
                    break :owned try c.own(try store.Store.parse(c.arena.allocator(), blob));
                };
                c.blob = blob;
                c.state = .{ .fact = owned };
                if (!g.awaitsVerdict(c.key.kind)) try g.keep(id);
            },
            .addr, .answer, .exchange, .refresh, .ahead, .parental => {
                const owned = try c.own(value);
                c.bare_expires_ns = expires_ns;
                c.state = .{ .fact = owned };
            },
            .secure => |v| {
                const owned = try c.own(value);
                c.bare_expires_ns = expires_ns;
                c.state = .{ .fact = owned };
                if (v.status == .secure) g.stats.trust.secure += 1 else g.stats.trust.insecure += 1;
                const t = c.scratch.secure.target;
                if (g.cell(t).blob) |b| b.verdict.stamp(v, expires_ns, g.now());
                try g.keep(t);
            },
        }
        try g.woken(id, value == .answer);
    }

    pub fn settleAs(g: *Graph, id: CellId, v: *store.Blob) !void {
        const c = g.cell(id);
        std.debug.assert(!c.settled() and c.key.kind == .rrset);
        std.debug.assert(!g.awaitsVerdict(c.key.kind) or v.verdict.judged());
        g.tally.settles += 1;
        const value = try store.Store.parse(c.arena.allocator(), v);
        const blob = try g.store.build(c.key, value, v.end());
        blob.verdict = v.verdict;
        const owned = owned: {
            errdefer g.store.unref(blob);
            break :owned try c.own(value);
        };
        c.blob = blob;
        c.state = .{ .fact = owned };
        try g.woken(id, false);
    }

    pub fn narrow(g: *Graph, id: CellId, reply: Reply) !void {
        const c = g.cell(id);
        const blob = try g.store.build(c.key, .{ .rrset = reply }, c.expires());
        errdefer g.store.unref(blob);
        const parsed = try store.Store.parse(c.arena.allocator(), blob);
        if (c.blob) |b| g.store.unref(b);
        c.blob = blob;
        c.state.fact.* = parsed;
    }

    /// With DNSSEC on, an rrset is no fact until judged: its bytes wait in
    /// their cell and die with it unless their judge keeps them.
    pub fn awaitsVerdict(g: *const Graph, kind: Kind) bool {
        return kind == .rrset and g.cfg.trust_anchors != null;
    }

    pub fn keep(g: *Graph, id: CellId) !void {
        const c = g.cell(id);
        const blob = c.blob orelse return;
        if (blob.expires_ns <= g.now()) return;
        if (g.store.any(c.key) == blob) return;
        if (try g.forgets(.keep, c.key)) return;
        std.debug.assert(blob.key().eql(c.key));
        g.store.put(blob.ref()) catch |err| {
            g.store.unref(blob);
            if (err != error.Refused) return err;
        };
    }

    pub fn fail(g: *Graph, id: CellId, why: Failure) !void {
        const c = g.cell(id);
        std.debug.assert(!c.settled());
        g.tally.settles += 1;
        if (g.cfg.trace) {
            var nb: [dns.max_dotted_len + 1]u8 = undefined;
            std.debug.print("  {t}({s}) failed: {t} {s}\n", .{ c.key.kind, c.name.formatInto(&nb), why.code, why.text });
        }
        if (c.key.kind == .secure and why.code == .dnssec_bogus) g.stats.trust.bogus += 1;
        const owned = try c.own(why);
        c.state = .{ .failure = owned };
        c.bare_expires_ns = g.now();
        try g.woken(id, false);
    }

    fn woken(g: *Graph, id: CellId, keep_inputs: bool) !void {
        const c = g.cell(id);
        var it = c.waiterIds();
        while (it.next()) |w| try g.enqueue(w);
        if (c.key.kind == .answer) try g.answered.append(g.gpa, id);
        // An answer serves from its hops; everything else has copied out.
        if (!keep_inputs) g.unpinAll(c);
        // The run's hold still pins a self-held root; the one release is below.
        if (c.key.kind == .refresh or c.key.kind == .ahead) c.holds -= 1;
        g.release(id);
    }

    /// Remembered (RFC 9520 §3.2) unless the asker may have caused it: its
    /// limits, an orphan, a refresh, an address lookup's depth, a send that never left.
    pub fn failRemembered(g: *Graph, id: CellId, why: Failure) !void {
        const c = g.cell(id);
        if (why.cause == .zone and !why.remembered and !c.orphan and c.as_of == 0 and g.level(id) == 0) try g.remember(c.key, why);
        try g.fail(id, why);
    }

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

    fn refused(g: *Graph, key: Key) !?Failure {
        if (g.failed.count() == 0) return null;
        const r = g.failed.get(key) orelse return null;
        if (r.until_ns <= g.now() or try g.forgets(.forget, key)) return null;
        var why = r.why;
        why.remembered = true;
        return why;
    }

    /// An rrset accepted as authentic ends with the signatures that authenticated it (RFC 4035 §5.3.3).
    pub fn authenticUntil(g: *Graph, id: CellId, until_ns: i64) void {
        g.cell(id).blob.?.shorten(until_ns);
    }

    pub fn fresh(g: *Graph, id: CellId) bool {
        const c = g.cell(id);
        return c.settled() and c.expires() > g.now();
    }

    pub fn instant(g: *const Graph) i64 {
        return @max(g.now(), g.as_of);
    }

    pub fn indexed(g: *const Graph, key: Key) ?CellId {
        return g.asking(.{ .key = key, .as_of = g.as_of });
    }

    fn asking(g: *const Graph, asked: Asked) ?CellId {
        return g.index.getKeyAdapted(asked, Indexed{ .g = g });
    }

    const Indexed = struct {
        g: *const Graph,
        pub fn hash(_: Indexed, a: Asked) u32 {
            return a.hash();
        }
        pub fn eql(x: Indexed, a: Asked, id: CellId, _: usize) bool {
            const c = x.g.cells.items[id].cell.?;
            return a.as_of == c.as_of and a.key.eql(c.key);
        }
    };

    const Own = struct {
        id: CellId,
        pub fn hash(_: Own, a: Asked) u32 {
            return a.hash();
        }
        pub fn eql(o: Own, _: Asked, id: CellId, _: usize) bool {
            return id == o.id;
        }
    };

    fn lookup(g: *Graph, key: Key, name: dns.Name, live: ?CellId, found: ?Served) !?CellId {
        if (found) |s| return switch (s) {
            .stored => |e| g.liveVersion(live, e) orelse try g.materialise(key, name, e),
            .live => |id| id,
        };
        const id = live orelse return null;
        return if (g.cell(id).settled()) null else id;
    }

    const Served = union(enum) { stored: *store.Blob, live: CellId };

    fn served(g: *Graph, key: Key, live: ?CellId) ?Served {
        if (g.stored(key)) |e| return .{ .stored = e };
        return .{ .live = g.liveServed(live) orelse return null };
    }

    fn liveServed(g: *Graph, live: ?CellId) ?CellId {
        const id = live orelse return null;
        return if (g.fresh(id)) id else null;
    }

    fn liveVersion(g: *Graph, live: ?CellId, b: *store.Blob) ?CellId {
        const id = live orelse return null;
        return if (g.cell(id).blob == b) id else null;
    }

    fn stored(g: *Graph, key: Key) ?*store.Blob {
        const e = g.store.get(key, g.now()) orelse return null;
        return if (e.expires_ns > g.instant()) e else null;
    }

    pub fn proven(g: *Graph, key: Key) ?*store.Blob {
        std.debug.assert(key.kind == .rrset);
        const e = g.stored(key) orelse return null;
        if (g.cfg.trust_anchors != null and e.verdict.standing(g.instant()) == null) return null;
        return e;
    }

    pub fn holds(g: *Graph, key: Key) bool {
        if (g.stored(key) != null) return true;
        const id = g.liveServed(g.indexed(key)) orelse return false;
        return g.cell(id).state == .fact;
    }

    pub fn held(g: *Graph, key: Key) ?*store.Blob {
        std.debug.assert(key.kind == .rrset);
        return switch (g.served(key, g.indexed(key)) orelse return null) {
            .stored => |e| e,
            .live => |id| if (g.cell(id).state == .fact) g.cell(id).blob.? else null,
        };
    }

    fn factOf(g: *Graph, live: ?CellId, e: *store.Blob) !Fact {
        if (g.liveVersion(live, e)) |id| if (g.liveFact(id)) |f| return .{ .value = f.value, .expires_ns = e.expires_ns };
        return .{ .value = try store.Store.parse(g.scratch.allocator(), e), .expires_ns = e.expires_ns };
    }

    fn liveFact(g: *Graph, id: CellId) ?Fact {
        const c = g.cell(id);
        return if (c.state == .fact) .{ .value = c.state.fact.*, .expires_ns = c.expires() } else null;
    }

    fn materialise(g: *Graph, key: Key, name: dns.Name, e: *store.Blob) !CellId {
        const id = try g.newCell(key, name, g.as_of);
        errdefer g.free(id);
        const c = g.cell(id);
        const owned = try c.own(try store.Store.parse(c.arena.allocator(), e));
        c.state = .{ .fact = owned };
        c.blob = e.ref();
        return id;
    }

    pub const Fact = struct { value: Value, expires_ns: i64 };

    pub const Recalled = struct { blob: *store.Blob, rrset: store.Rrset, standing: ?trust.Chain };

    /// The blobs are the store's; the caller refs what it keeps.
    pub fn recall(g: *Graph, arena: Allocator, name: dns.Name, qtype: dns.RType, age: Age) !?[]const Recalled {
        var hops: std.ArrayList(Recalled) = .empty;
        var links: walk.Links = .{};
        var next = name;
        var kind: ?Kind = null;
        while (true) {
            kind = g.hopKind(kind, next, qtype) orelse return null;
            const e = g.storedHop(kind.?, next, qtype, age) orelse return null;
            var standing: ?trust.Chain = null;
            if (g.awaitsVerdict(kind.?)) {
                standing = e.verdict.standing(g.now());
                if (if (age == .fresh) standing == null else !e.verdict.judged()) return null;
            }
            const r: store.Rrset = .of(e);
            try hops.append(arena, .{ .blob = e, .rrset = r, .standing = standing });
            const target: dns.Name = if (r.kind == .alias) .of(r.target) else .root;
            var it = r.sections[0].iterator();
            while (it.next()) |rr| if (rr.rtype == .cname) {
                if (links.pass(rr.name) != null) return null;
            };
            switch (links.end(r.kind, target, qtype)) {
                .done => return hops.items,
                .next => |nx| next = nx,
                .broken => return null,
            }
        }
    }

    pub const Age = enum { fresh, any };

    pub inline fn storedHop(g: *Graph, kind: Kind, name: dns.Name, qtype: dns.RType, age: Age) ?*store.Blob {
        const own = @call(.always_inline, Key.of, .{ kind, name, qtype });
        if (g.entry(own, age)) |e| return e;
        if (!walk.cnameAnswers(qtype)) return null;
        const e = g.entry(own.at(kind, .cname), age) orelse return null;
        return if (store.Rrset.of(e).kind == .alias) e else null;
    }

    pub fn hopKind(g: *const Graph, from: ?Kind, name: dns.Name, qtype: dns.RType) ?Kind {
        const kind: Kind = if (stub.of(g.cfg.stub_zones, name, qtype) != null) .stub else .rrset;
        return if (from == .rrset and kind == .stub) null else kind;
    }

    inline fn entry(g: *Graph, key: Key, age: Age) ?*store.Blob {
        return if (age == .fresh) g.store.get(key, g.now()) else g.store.any(key);
    }

    /// Pins nothing and reads the store as of now: good for a speedup's guess,
    /// never as the cause of a fact.
    pub fn peek(g: *Graph, key: Key) !?Fact {
        const live = g.indexed(key);
        if (g.store.get(key, g.now())) |e| return try g.factOf(live, e);
        const id = live orelse return null;
        return if (g.fresh(id)) g.liveFact(id) else null;
    }

    /// Null on a cycle, or on new work for an orphan. New work that failed
    /// recently settles as that failure, its rule never run.
    pub fn demand(g: *Graph, by: CellId, key: Key, name: dns.Name) !?CellId {
        const live = g.indexed(key);
        return g.demandFound(by, key, name, live, g.served(key, live));
    }

    pub fn demandHop(g: *Graph, by: CellId, own: Key, name: dns.Name) !?CellId {
        const live = g.indexed(own);
        const found = g.served(own, live);
        const holds_own = if (found) |s| s == .stored or g.cell(s.live).state == .fact else false;
        if (!holds_own and walk.cnameAnswers(own.rtype)) {
            const alias = own.at(own.kind, .cname);
            const alias_live = g.indexed(alias);
            if (g.served(alias, alias_live)) |s| if (switch (s) {
                .stored => |e| store.Rrset.of(e).kind == .alias,
                .live => |id| g.cell(id).state == .fact and g.cell(id).state.fact.reply().kind == .alias,
            }) return g.demandFound(by, alias, name, alias_live, s);
        }
        return g.demandFound(by, own, name, live, found);
    }

    fn demandFound(g: *Graph, by: CellId, key: Key, name: dns.Name, live: ?CellId, found: ?Served) !?CellId {
        if (try g.lookup(key, name, live, found)) |id| return g.join(by, id);
        if (g.cell(by).orphan) return null;
        const id = try g.newCell(key, name, g.as_of);
        try g.pin(id, by);
        if (try g.refused(key)) |why| try g.fail(id, why) else try g.enqueue(id);
        return id;
    }

    pub fn join(g: *Graph, by: CellId, id: CellId) !?CellId {
        if (!g.fresh(id) and g.reaches(by, id)) return null;
        try g.pin(id, by);
        return id;
    }

    fn payerOf(g: *Graph, id: CellId) ?*Budget {
        g.checks += 1;
        var first: ?*Budget = null;
        var roomy: std.ArrayList(*Budget) = .empty;
        const ch = g.chaosAt(.payer);
        var stack: std.ArrayList(CellId) = .empty;
        stack.append(g.scratch.allocator(), id) catch return null;
        while (stack.pop()) |i| {
            const c = g.cell(i);
            if (c.seen == g.checks or c.orphan) continue;
            c.seen = g.checks;
            if (budgetOf(c)) |b| {
                if (!g.spent(b)) {
                    if (ch == null) return b;
                    roomy.append(g.scratch.allocator(), b) catch return b;
                }
                first = first orelse b;
                continue;
            }
            // Last first, so the stack pops them in pin order.
            var n = c.waiters.last;
            while (n) |w| : (n = w.prev) stack.append(g.scratch.allocator(), Pin.ofWaiter(w).by) catch return first;
        }
        if (roomy.items.len > 0) return roomy.items[@intCast(g.decide(.payer, g.cell(id).key, roomy.items.len) catch 0)];
        return first;
    }

    fn budgetOf(c: *const Cell) ?*Budget {
        return switch (c.scratch) {
            .answer => |a| a.budget,
            .ahead => |k| k.budget,
            .none, .cut, .addr, .rrset, .stub, .ds, .dnskey, .secure, .exchange => null,
        };
    }

    fn unref(g: *Graph, b: *Budget) void {
        b.refs -= 1;
        if (b.refs > 0) return;
        g.work.allocator().destroy(b);
        g.budgets -= 1;
    }

    pub fn limit(g: *const Graph, b: *const Budget) ?Failure {
        if (g.now() >= b.deadline_ns) return .{ .code = .other, .text = "resolution deadline passed", .cause = .asker };
        if (b.queries >= g.cfg.max_queries) return .{ .code = .other, .text = "query budget spent", .cause = .asker };
        return null;
    }

    pub fn spent(g: *const Graph, b: *const Budget) bool {
        return g.limit(b) != null or b.validation.exhausted();
    }

    /// NS-address sub-resolutions between `id` and its nearest question, along
    /// the shortest demand chain; 0 for an orphan.
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
                var it = c.waiterIds();
                while (it.next()) |w| {
                    const list = if (c.key.kind == .rrset and g.cell(w).key.kind == .addr) &next else &here;
                    list.append(gpa, w) catch return d;
                }
            }
            if (next.items.len == 0) return 0;
            std.mem.swap(std.ArrayList(CellId), &here, &next);
        }
    }

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
            var it = c.waiterIds();
            while (it.next()) |w| stack.append(g.scratch.allocator(), w) catch return true;
        }
        return false;
    }

    pub fn publish(g: *Graph, key: Key, name: dns.Name, by: CellId, value: Value, expires_ns: i64) !void {
        if (g.indexed(key)) |id| if (id != by and !g.cell(id).settled()) return g.settle(id, value, expires_ns);
        if (!g.awaitsVerdict(key.kind)) {
            _ = try g.fact(key, value, expires_ns);
            return;
        }
        // A served version stands: bytes nobody judged displace none.
        if (expires_ns <= g.now() or g.holds(key)) return;
        const root = try g.ahead(key, name) orelse return;
        const s = g.cell(root).scratch.ahead;
        if (s.rrset != .none) return;
        const id = try g.newCell(key, name, g.as_of);
        try g.pin(id, root);
        s.rrset = .wrap(id);
        try g.settle(id, value, expires_ns);
    }

    pub fn fact(g: *Graph, key: Key, value: Value, expires_ns: i64) !?*store.Blob {
        if (expires_ns <= g.now()) return null;
        const blob = try g.store.build(key, value, expires_ns);
        g.store.put(blob) catch |err| {
            g.store.unref(blob);
            if (err != error.Refused) return err;
            return null;
        };
        // A put may evict what it lands as it lands.
        const e = g.store.any(key) orelse return null;
        return if (e == blob) blob else null;
    }

    /// Held for the run: what it publishes may settle and free its own readers
    /// while the rule still has the cell in hand.
    fn run(g: *Graph, id: CellId) !void {
        const c = g.cell(id);
        if (c.settled()) return;
        c.holds += 1;
        defer {
            c.holds -= 1;
            g.release(id);
        }
        g.scratch.reset();
        g.unpaid = .{ .deadline_ns = 0, .validation = .{ .max_sig_verify = 0, .max_nsec3_blocks = 0 } };
        g.payer = g.payerOf(id) orelse &g.unpaid;
        defer g.payer = &g.unpaid;
        g.as_of = c.as_of;
        defer g.as_of = 0;
        g.tally.runs += 1;
        if (builtin.is_test) g.schedule = std.hash.Wyhash.hash(g.schedule, mem.asBytes(&c.key.hash()));
        const clock = Tally.clock(&g.tally.rule_ns);
        defer clock.stop();
        const created_before = g.created;
        defer if (!c.settled() and g.created == created_before) {
            g.tally.reruns += 1;
            if (Tally.timed) g.tally.rerun_ns += @intCast(monotonic.nowNs() - clock.t0);
        };
        switch (g.cell(id).key.kind) {
            .cut => try walk.runCut(g, id),
            .rrset => try walk.runRrset(g, id),
            .stub => try stub.run(g, id),
            .addr => try walk.runAddr(g, id),
            .answer, .refresh => try walk.runAnswer(g, id),
            .ds => try trust.runDs(g, id),
            .dnskey => try trust.runDnskey(g, id),
            .secure => try trust.runSecure(g, id),
            .ahead => try trust.runAhead(g, id),
            .exchange => {},
            .parental => unreachable,
        }
    }

    fn observe(g: *Graph, server: na.Address, rtt_ns: i64) void {
        g.rtt.write(.fromAddress(server), g.nowMs()).observe(@divTrunc(rtt_ns, std.time.ns_per_us), g.nowMs());
    }

    fn observeTimeout(g: *Graph, server: na.Address) void {
        g.rtt.write(.fromAddress(server), g.nowMs()).observeTimeout(g.nowMs());
    }

    fn nowMs(g: *const Graph) i64 {
        return @divTrunc(g.now(), std.time.ns_per_ms);
    }

    pub fn track(g: *Graph, server: na.AddressKey) ns_rtt.Track {
        return g.estimate(server).track;
    }

    const Estimate = struct { track: ns_rtt.Track, est: ?*const ns_rtt.RttState };

    pub fn estimate(g: *Graph, server: na.AddressKey) Estimate {
        if (g.chaosAt(.dead)) |ch| {
            const event = ch.named(.dead, std.hash.Wyhash.hash(0, &server.addr) ^ server.port);
            if ((ch.choose(.dead, event, 4, .{ .server = server }) catch 0) == 1) return .{ .track = .dead, .est = null };
        }
        const s = g.rtt.get(server) orelse return .{ .track = ns_rtt.RttState.unknown.track(g.nowMs()), .est = null };
        return .{ .track = s.track(g.nowMs()), .est = s };
    }

    pub fn isDead(g: *Graph, server: na.AddressKey) bool {
        return g.track(server) == .dead;
    }

    pub fn wait(g: *Graph, est: *const ns_rtt.RttState, rounds: u32, bits: u64) u64 {
        if (g.chaosAt(.pick) != null) return 0;
        const hold_ms = if (est.loss == 0) 0 else g.holdMs(est.*, rounds);
        return est.wait(g.nowMs(), rounds, hold_ms, ns_rtt.normal(bits));
    }

    pub fn noise(g: *Graph, out: []u64) void {
        if (g.chaosAt(.pick) != null) return @memset(out, 0);
        g.edge.rng.bytes(mem.sliceAsBytes(out));
    }

    pub fn holdMs(g: *const Graph, est: ns_rtt.RttState, rounds: u32) u32 {
        if (g.cfg.stagger_ms == 0) return est.timeout(false, rounds);
        return (est.hedgeStagger() orelse g.cfg.stagger_ms) * rounds;
    }

    pub const Sent = struct { id: CellId, est: ns_rtt.RttState, rounds: u32, exposure: Exposure };

    pub fn exchange(g: *Graph, by: CellId, server: na.AddressKey, need: Need, case: Case, qname: dns.Name, qtype: dns.RType, uncapped: bool) !?Sent {
        std.debug.assert(case == .random or need == .stream);
        // The run's payer may spend itself mid-run while another waiter still has
        // room: the shared work goes on at that one's cost.
        if (g.limit(g.payer) != null) g.payer = g.payerOf(by) orelse g.payer;
        const budget = g.payer;
        const stop: ?[]const u8 = if (g.cell(by).orphan) "orphan" else if (g.limit(budget)) |why| why.text else null;
        if (stop) |why| {
            if (g.cfg.trace) {
                var nb: [dns.max_dotted_len + 1]u8 = undefined;
                std.debug.print("  {s} {f} refused: {s}\n", .{ qname.formatInto(&nb), dns.tag(qtype), why });
            }
            return null;
        }
        const id = try g.newCell(.init(.exchange, "", .a), qname, g.as_of);
        try g.pin(id, by);
        budget.queries += 1;
        g.cell(id).holds += 1;
        const clock = Tally.clock(&g.tally.send_ns);
        defer clock.stop();
        const rng = g.edge.rng;
        const qid = rng.int(u16);
        const arena = g.cell(id).arena.allocator();
        const msg = try dns.buildQuery(arena, qid, qname, qtype, g.cfg.trust_anchors != null, if (case == .random) rng else null);
        var wire_buf: [512]u8 = undefined;
        const wire = try arena.dupe(u8, try dns.serializeMessage(&wire_buf, msg));
        const sc = try arena.create(ExchangeScratch);
        const est = g.rtt.get(server);
        const state = if (est) |s| s.* else ns_rtt.RttState.unknown;
        const patience: i64 = 1 + @as(i64, @intCast(try g.decide(.rto, g.cell(by).key, 4)));
        const addr = server.toAddress();
        const rounds = g.edge.quote(server, need).rounds;
        // Silent past the capped wait is silent, however long this send waits.
        const owed_at = g.now() + patience * state.timeout(false, rounds) * std.time.ns_per_ms;
        const timeout_at = g.now() + patience * state.timeout(uncapped, rounds) * std.time.ns_per_ms;
        const deadline_ns = @min(budget.deadline_ns, timeout_at);
        if (est) |s| s.sent(@divTrunc(deadline_ns, std.time.ns_per_ms) + 1);
        sc.* = .{ .id = qid, .sent = msg.question.?.spelled.?, .qtype = qtype, .server = addr, .need = need, .case = case, .sent_ns = g.now(), .cut_short = budget.deadline_ns <= owed_at };
        g.cell(id).scratch = .{ .exchange = sc };
        const exposure = try g.edge.send(.{
            .id = id,
            .server = addr,
            .need = need,
            .wire = wire,
            .deadline_ns = deadline_ns,
        });
        g.flights += 1;
        if (need == .datagram) g.stats.resolver.exchanges.datagram += 1 else g.stats.resolver.exchanges.stream += 1;
        return .{ .id = id, .est = state, .rounds = rounds, .exposure = exposure };
    }
};

const Quiet = struct {
    now: i64 = std.time.ns_per_s,
    wall: i64 = 0,

    fn graph(q: *Quiet, cfg: Config) !Graph {
        return .init(std.testing.allocator, std.testing.allocator, cfg, .{ .ctx = q, .now_ns = &q.now, .wall_sec = &q.wall, .rng = rand.thread, .sendFn = send, .wakeFn = wake });
    }

    fn send(_: *anyopaque, _: Exchange) anyerror!Exposure {
        return .none;
    }
    fn wake(_: *anyopaque, _: CellId, _: u32, _: i64) anyerror!void {}
};

test "a cell replacing an expired one keeps the index entry when the old one goes" {
    const testing = std.testing;
    var q: Quiet = .{};
    var g = try q.graph(.{ .root_hints = &.{} });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const name = try dns.parseDottedName(arena.allocator(), "example.");
    const first = try g.demandRoot(name, .a, .new);
    try g.settle(first, .{ .answer = .{ .hops = &.{} } }, q.now);
    const second = try g.demandRoot(name, .a, .new);
    try testing.expect(first != second);
    g.unhold(first);
    try testing.expect(g.alive(first) == null);
    try testing.expectEqual(second, g.indexed(Key.of(.answer, name, .a)).?);
    g.unhold(second);
}

test "a cell freed while queued leaves its slot's next tenant waiting" {
    const testing = std.testing;
    var q: Quiet = .{};
    var g = try q.graph(.{ .root_hints = &.{} });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const name = try dns.parseDottedName(arena.allocator(), "example.");
    const gone = try g.demandRoot(name, .a, .new);
    g.unhold(gone);
    try testing.expect(g.alive(gone) == null);
    try g.refresh(Key.of(.answer, name, .a), name, q.now + 60 * std.time.ns_per_s);
    const tenant = g.alive(gone).?;
    try testing.expectEqual(.refresh, tenant.key.kind);
    try g.drain();
    try testing.expect(!tenant.settled());
}

test "a joiner starts nothing, and past the work ceiling joins only what is settled" {
    const testing = std.testing;
    var q: Quiet = .{};
    var g = try q.graph(.{ .root_hints = &.{}, .max_work_bytes = 1 });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const name = try dns.parseDottedName(arena.allocator(), "example.");
    try testing.expectError(error.Novel, g.demandRoot(name, .a, .join));
    const first = try g.demandRoot(name, .a, .new);
    try testing.expectError(error.Full, g.demandRoot(name, .a, .join));
    try testing.expectError(error.Full, g.demandRoot(try dns.parseDottedName(arena.allocator(), "other."), .a, .new));
    try g.settle(first, .{ .answer = .{ .hops = &.{} } }, q.now + std.time.ns_per_s);
    try testing.expectEqual(first, try g.demandRoot(name, .a, .join));
    g.unhold(first);
    g.unhold(first);
}

test "an evicted root cut is re-derived, not walked" {
    const testing = std.testing;
    var q: Quiet = .{};
    var g = try q.graph(.{ .root_hints = &.{} });
    defer g.deinit();
    const root_cut: Key = .of(.cut, .root, .a);
    g.store.drop(g.store.any(root_cut).?);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = try g.demandRoot(try dns.parseDottedName(arena.allocator(), "com."), .a, .new);
    try g.drain();
    try testing.expect(g.store.get(root_cut, q.now) != null);
    g.unhold(root);
}

test "a version shortened through one instant's cell ends for every cell holding it" {
    const testing = std.testing;
    var q: Quiet = .{};
    var g = try q.graph(.{ .root_hints = &.{} });
    defer g.deinit();
    const name: dns.Name = .lit("example");
    const key = Key.of(.rrset, name, .a);
    const rrs = [_]dns.ResourceRecord{.fixture(.{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 0, 2, 1 } } })};
    const now = try g.newCell(key, name, 0);
    g.cell(now).holds += 1;
    defer g.unhold(now);
    try g.settle(now, .{ .rrset = .{ .kind = .answer, .aa = true, .answers = &rrs, .target = name, .zone = .root, .stored_ns = q.now, .ttl = 300 } }, q.now + 300 * std.time.ns_per_s);
    const version = g.cell(now).blob.?;
    const lapse = q.now + 200 * std.time.ns_per_s;
    const refresh = try g.newCell(Key.of(.refresh, name, .a), name, lapse);
    g.cell(refresh).holds += 1;
    defer g.unhold(refresh);
    g.as_of = lapse;
    const later = (try g.demand(refresh, key, name)).?;
    try testing.expectEqual(version, g.cell(later).blob.?);
    g.authenticUntil(later, q.now + 250 * std.time.ns_per_s);
    g.as_of = 0;
    g.store.drop(version);
    try testing.expectEqual(version, g.held(key).?);
    try testing.expectEqual(q.now + 250 * std.time.ns_per_s, g.cell(now).expires());
}

test "a shared cell is paid by a waiting question with room, not its first demander" {
    const testing = std.testing;
    var q: Quiet = .{};
    var g = try q.graph(.{ .root_hints = &.{} });
    defer g.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const host = try dns.parseDottedName(arena.allocator(), "ns.example.");
    const first = try g.demandRoot(try dns.parseDottedName(arena.allocator(), "a.example."), .a, .new);
    const second = try g.demandRoot(host, .a, .new);
    const shared = try g.newCell(Key.of(.rrset, host, .a), host, 0);
    try g.pin(shared, first);
    try g.pin(shared, second);
    g.cell(first).scratch.answer.budget.queries = g.cfg.max_queries;
    try testing.expectEqual(g.cell(second).scratch.answer.budget, g.payerOf(shared).?);
    g.cell(second).scratch.answer.budget.queries = g.cfg.max_queries;
    try testing.expectEqual(g.cell(first).scratch.answer.budget, g.payerOf(shared).?);
    g.payer = g.cell(first).scratch.answer.budget;
    try testing.expectEqual(null, try g.exchange(shared, .fromAddress(na.initIp4(.{ 127, 0, 0, 1 }, 53)), .datagram, .random, host, .a, true));
    g.cell(second).scratch.answer.budget.queries = 0;
    g.payer = g.cell(first).scratch.answer.budget;
    try testing.expect(try g.exchange(shared, .fromAddress(na.initIp4(.{ 127, 0, 0, 1 }, 53)), .datagram, .random, host, .a, true) != null);
    try testing.expectEqual(1, g.cell(second).scratch.answer.budget.queries);
    g.payer = &g.unpaid;
    g.unhold(first);
    g.unhold(second);
}

test "a key's name hash follows the process seed" {
    const saved = rand.hash_seed;
    defer rand.hash_seed = saved;
    const a: Key = .of(.rrset, .lit("www.example"), .a);
    rand.hash_seed = 0xdeadbeefcafef00d;
    const b: Key = .of(.rrset, .lit("www.example"), .a);
    try std.testing.expect(a.name_hash != b.name_hash);
}
