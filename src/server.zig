const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const Io = std.Io;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const Completion = @import("event_loop.zig").Completion;
const max_operations = @import("event_loop.zig").max_operations;
const recursive = @import("recursive.zig");
const acl = @import("acl.zig");
const EncryptedNs = @import("encrypted_ns.zig").EncryptedNs;
const CaseState = @import("case_state.zig").CaseState;
const RttCache = @import("ns_rtt.zig").RttCache;
const NsSelector = @import("ns_selector.zig").NsSelector;
const cache_mod = @import("cache.zig");
const RRsetCache = cache_mod.RRsetCache;
const dedup_mod = @import("dedup.zig");
const InFlightTable = dedup_mod.InFlightTable;
const NsecCache = @import("nsec_cache.zig").NsecCache;
const CountingAllocator = @import("counting_allocator.zig").CountingAllocator;
const BumpGatedGroup = @import("bg_group.zig");
const ServerConfig = @import("config.zig").ServerConfig;
const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const TcpConnectionPool = @import("connection_pool.zig").TcpConnectionPool;
const Transports = recursive.Transports;
const na = @import("net_address.zig");
const response = @import("response.zig");
const ResponseContext = response.ResponseContext;
const buildResponseWire = response.buildResponseWire;
const serializeErrorResponse = response.serializeErrorResponse;
const validateQuery = response.validateQuery;
const sys = @import("sys.zig");
const monotonic = @import("monotonic.zig");
const build_options = @import("build_options");

const log = std.log.scoped(.server);

/// Response rcode as a leading-space-prefixed tag, or "" when NOERROR — the
/// common case, kept off the per-query log line so it isn't repeated endlessly.
fn rcodeSuffix(rcode: dns.RCode, buf: []u8) []const u8 {
    if (rcode == .no_error) return "";
    var tmp: [24]u8 = undefined;
    const tag = dns.safeTagName(rcode, &tmp);
    return std.fmt.bufPrint(buf, " {s}", .{tag}) catch tag;
}

/// Parse the test-harness clock-advance control qname. Returns the number
/// of seconds to advance, or null if the qname doesn't match. Format:
/// `_advance-clock.<seconds>.testharness.invalid` (server layer strips the
/// trailing dot). RFC 6761 reserves `invalid.` so the name is unrouted in
/// production; gating on `build_options.testing_enabled` compiles the
/// intercept out of release builds entirely.
inline fn parseAdvanceClockQname(name: []const u8) ?i64 {
    const prefix = "_advance-clock.";
    const suffix = ".testharness.invalid";
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    if (!std.mem.endsWith(u8, name, suffix)) return null;
    const middle = name[prefix.len .. name.len - suffix.len];
    return std.fmt.parseInt(i64, middle, 10) catch null;
}

const work_queue_capacity = 256;

// ── Optional WorkQueue instrumentation ────────────────────────────────
// Behind `-Dqueue_instr=true`. Off by default: every field is a
// `void`-sized struct and every helper compiles to nothing. On:
// per-op acquisition counts + log-bucketed histograms for lock-wait
// and held-time, dumped on shutdown.

const queue_instr_on = build_options.queue_instr;

/// Log-spaced buckets: <1µs, <10µs, <100µs, <1ms, <10ms, <100ms, <1s, ≥1s.
const q_bucket_labels = [_][]const u8{ "<1µs", "<10µs", "<100µs", "<1ms", "<10ms", "<100ms", "<1s", "≥1s" };

inline fn qBucket(ns: u64) usize {
    if (ns < 1_000) return 0;
    if (ns < 10_000) return 1;
    if (ns < 100_000) return 2;
    if (ns < 1_000_000) return 3;
    if (ns < 10_000_000) return 4;
    if (ns < 100_000_000) return 5;
    if (ns < 1_000_000_000) return 6;
    return 7;
}

const QInstrOpStats = if (queue_instr_on) struct {
    count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    wait_buckets: [8]std.atomic.Value(u64) = @splat(std.atomic.Value(u64).init(0)),
    hold_buckets: [8]std.atomic.Value(u64) = @splat(std.atomic.Value(u64).init(0)),

    fn record(self: *@This(), wait_ns: u64, hold_ns: u64) void {
        _ = self.count.fetchAdd(1, .monotonic);
        _ = self.wait_buckets[qBucket(wait_ns)].fetchAdd(1, .monotonic);
        _ = self.hold_buckets[qBucket(hold_ns)].fetchAdd(1, .monotonic);
    }

    fn dump(self: *const @This(), op: []const u8) void {
        const total = self.count.load(.monotonic);
        if (total == 0) {
            log.info("queue.{s}: count=0", .{op});
            return;
        }
        var wait_buf: [256]u8 = undefined;
        var hold_buf: [256]u8 = undefined;
        const wait_str = formatBuckets(&wait_buf, &self.wait_buckets);
        const hold_str = formatBuckets(&hold_buf, &self.hold_buckets);
        log.info("queue.{s}: count={d} wait[{s}] hold[{s}]", .{ op, total, wait_str, hold_str });
    }

    fn formatBuckets(buf: []u8, buckets: *const [8]std.atomic.Value(u64)) []const u8 {
        var w = std.Io.Writer.fixed(buf);
        for (buckets, q_bucket_labels, 0..) |*b, label, i| {
            if (i > 0) w.writeAll(" ") catch break;
            w.print("{s}={d}", .{ label, b.load(.monotonic) }) catch break;
        }
        return w.buffered();
    }
} else struct {
    inline fn record(_: *@This(), _: u64, _: u64) void {}
    inline fn dump(_: *const @This(), _: []const u8) void {}
};

const QInstr = struct {
    push: QInstrOpStats = .{},
    pop: QInstrOpStats = .{},
    release: QInstrOpStats = .{},

    fn dumpAll(self: *const QInstr) void {
        if (!queue_instr_on) return;
        self.push.dump("push");
        self.pop.dump("pop");
        self.release.dump("release");
    }
};

/// Three timestamps: before lock, after lock-acquired, and start of the real
/// critical section. For push/release the latter two coincide and `locked()`
/// sets both; for `pop` they differ because `dequeueLocked` may sleep on the
/// not-empty condvar (releasing the mutex), which would otherwise inflate
/// wait_ns. `pop` calls `workBegun()` after `dequeueLocked` returns to record
/// the critical-section start, so condvar idle isn't billed as either wait
/// time or hold time.
const QInstrTimer = struct {
    t_before_lock: if (queue_instr_on) i128 else void = if (queue_instr_on) 0 else {},
    t_after_lock: if (queue_instr_on) i128 else void = if (queue_instr_on) 0 else {},
    t_work_begun: if (queue_instr_on) i128 else void = if (queue_instr_on) 0 else {},

    inline fn start(self: *QInstrTimer) void {
        if (queue_instr_on) self.t_before_lock = monotonic.nowNs();
    }
    inline fn locked(self: *QInstrTimer) void {
        if (!queue_instr_on) return;
        const t = monotonic.nowNs();
        self.t_after_lock = t;
        self.t_work_begun = t;
    }
    inline fn workBegun(self: *QInstrTimer) void {
        if (queue_instr_on) self.t_work_begun = monotonic.nowNs();
    }
    inline fn finishInto(self: *QInstrTimer, stats: *QInstrOpStats) void {
        if (!queue_instr_on) return;
        const now = monotonic.nowNs();
        const wait_ns: u64 = @intCast(@max(0, self.t_after_lock - self.t_before_lock));
        const hold_ns: u64 = @intCast(@max(0, now - self.t_work_begun));
        stats.record(wait_ns, hold_ns);
    }
};

// Per-thread query arena, owned by a pool thread and reused across queries
// via reset(.retain_capacity). Layering: caller → CountingAllocator → arena.
// The CountingAllocator sits in front so each query's allocations are bounded
// by query_memory_limit regardless of retained arena capacity (retention
// cannot bypass the cap).
//
// `init` takes *PerThreadArena (unlike most struct inits in this file) because
// cap.backing stores &self.arena — the struct is self-referential and cannot
// be returned by value without risking a dangling pointer if NRVO doesn't fire.
const PerThreadArena = struct {
    arena: std.heap.ArenaAllocator,
    cap: CountingAllocator,

    fn init(self: *PerThreadArena, gpa: mem.Allocator, max_bytes: usize) void {
        self.arena = std.heap.ArenaAllocator.init(gpa);
        self.cap = CountingAllocator.init(
            self.arena.allocator(),
            if (max_bytes > 0) max_bytes else std.math.maxInt(usize),
            .payload,
        );
    }

    fn reset(self: *PerThreadArena) mem.Allocator {
        self.cap.current_bytes.store(0, .monotonic);
        _ = self.arena.reset(.retain_capacity);
        return self.cap.allocator();
    }

    fn deinit(self: *PerThreadArena) void {
        self.arena.deinit();
    }
};

// ── Work Queue for resolution thread pool ─────────────────────────────

const max_work_query_bytes = @import("event_loop.zig").multishot_payload_max;

/// .bg payload: [qtype u16 BE][BgKind u8][name]
/// .tcp payload: [*TcpClient usize LE][query wire]
const Protocol = enum { udp, tcp, bg };

// No field defaults: a defaulted Slot inside `slots: ... = @splat(.{})`
// once made Zig emit all 256 copies (1 MiB, mostly zeros) into .rodata as
// the memcpy template for WorkQueue's default aggregate. init() writes the
// sentinels instead.
const Slot = struct {
    buf: [max_work_query_bytes]u8,
    len: u16,
    client_addr: na.Address,
    sock_fd: posix.fd_t,
    protocol: Protocol,
};

const PopResult = struct {
    payload: []const u8,
    reservation: u16,
    client_addr: na.Address,
    sock_fd: posix.fd_t,
    protocol: Protocol,
};

// Bounded MPMC queue over a fixed slot array. Two rings: an order ring
// holding queued indices (FIFO), and a free-list stack holding indices
// available for claim. The `*Locked` primitives assume the caller holds
// `mutex` — keeping push/pop atomic across claim+enqueue / dequeue+copy
// means the wrapper does one lock acquisition per operation, not two.

const WorkQueue = struct {
    slots: [work_queue_capacity]Slot = undefined,
    order: [work_queue_capacity]u16 = undefined,
    head: u16 = 0,
    tail: u16 = 0,
    queued: u16 = 0,
    free_list: [work_queue_capacity]u16 = undefined,
    free_count: u16 = 0,
    mutex: Io.Mutex = Io.Mutex.init,
    not_empty: Io.Condition = Io.Condition.init,
    io: Io = undefined,
    instr: QInstr = .{},

    fn init(self: *WorkQueue, io: Io) void {
        self.* = .{ .io = io };
        for (&self.slots) |*s| {
            s.len = 0;
            s.client_addr = na.initIp4(.{ 0, 0, 0, 0 }, 0);
            s.sock_fd = -1;
            s.protocol = .udp;
        }
        for (0..work_queue_capacity) |i| self.free_list[i] = @intCast(work_queue_capacity - 1 - i);
        self.free_count = work_queue_capacity;
    }

    fn lock(self: *WorkQueue) void {
        self.mutex.lockUncancelable(self.io);
    }

    fn unlock(self: *WorkQueue) void {
        self.mutex.unlock(self.io);
    }

    /// Reserve a free slot. Caller MUST follow with `enqueueLocked(idx)`
    /// once the slot is populated, or `releaseLocked(idx)` to abandon.
    fn claimLocked(self: *WorkQueue) ?struct { idx: u16, slot: *Slot } {
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        const idx = self.free_list[self.free_count];
        return .{ .idx = idx, .slot = &self.slots[idx] };
    }

    /// Publish a populated slot to the FIFO and wake one waiter.
    fn enqueueLocked(self: *WorkQueue, idx: u16) void {
        self.order[self.tail] = idx;
        self.tail = (self.tail + 1) % work_queue_capacity;
        self.queued += 1;
        self.not_empty.signal(self.io);
    }

    fn dequeueLocked(self: *WorkQueue) struct { idx: u16, slot: *Slot } {
        while (self.queued == 0) {
            self.not_empty.waitUncancelable(self.io, &self.mutex);
        }
        const idx = self.order[self.head];
        self.head = (self.head + 1) % work_queue_capacity;
        self.queued -= 1;
        return .{ .idx = idx, .slot = &self.slots[idx] };
    }

    fn releaseLocked(self: *WorkQueue, idx: u16) void {
        self.free_list[self.free_count] = idx;
        self.free_count += 1;
    }

    fn push(self: *WorkQueue, data: []const u8, client_addr: na.Address, sock_fd: posix.fd_t, protocol: Protocol) bool {
        // Slots are never read before push populates them; every field must
        // be written below (and read back in pop). Grew a field? Wire it
        // through here, pop(), and init()'s sentinels, then bump the count.
        comptime std.debug.assert(@typeInfo(Slot).@"struct".field_names.len == 5);
        if (data.len > max_work_query_bytes) return false;
        var t: QInstrTimer = .{};
        t.start();
        self.lock();
        t.locked();
        // LIFO defer order: unlock first, then record. Recording calls
        // monotonic.nowNs() (clock_gettime); doing it under the lock would
        // inflate hold_ns and block waiters by the syscall latency.
        defer t.finishInto(&self.instr.push);
        defer self.unlock();
        const claimed = self.claimLocked() orelse return false;
        @memcpy(claimed.slot.buf[0..data.len], data);
        claimed.slot.len = @intCast(data.len);
        claimed.slot.client_addr = client_addr;
        claimed.slot.sock_fd = sock_fd;
        claimed.slot.protocol = protocol;
        self.enqueueLocked(claimed.idx);
        return true;
    }

    /// Returned payload borrows from the slot until `release(reservation)`.
    fn pop(self: *WorkQueue) PopResult {
        var t: QInstrTimer = .{};
        t.start();
        self.lock();
        t.locked();
        defer t.finishInto(&self.instr.pop);
        defer self.unlock();
        const taken = self.dequeueLocked();
        t.workBegun();
        return PopResult{
            .payload = taken.slot.buf[0..taken.slot.len],
            .reservation = taken.idx,
            .client_addr = taken.slot.client_addr,
            .sock_fd = taken.slot.sock_fd,
            .protocol = taken.slot.protocol,
        };
    }

    fn release(self: *WorkQueue, reservation: u16) void {
        var t: QInstrTimer = .{};
        t.start();
        self.lock();
        t.locked();
        defer t.finishInto(&self.instr.release);
        defer self.unlock();
        self.releaseLocked(reservation);
    }

    fn dumpInstr(self: *const WorkQueue) void {
        self.instr.dumpAll();
    }
};

// ── Context tags for the event loop ────────────────────────────────────

const CtxTag = enum { udp_recv, tcp_accept, tcp_read, tick, signal };

const Ctx = struct {
    tag: CtxTag,
    fd: posix.fd_t,
};

const max_listen_addrs = 8;

/// Ring slots left by listeners, signalfd, tick.
const max_tcp_clients_per_worker = max_operations - 2 * max_listen_addrs - 2;
const tick_ms = 1000;

/// Consecutive unreadable signalfd completions tolerated before the worker
/// stops trying. Only a genuinely broken fd reaches this.
const max_signal_misfires: u32 = 16;

// ── Background task bookkeeping ────────────────────────────────────────

const max_bg_tasks: u32 = 16;

/// Dedup flag value for background CD=1 revalidation tasks. Distinct
/// from CD=0 (flag=0) and CD=1-client (flag=1) so a client-facing query
/// and a background revalidation of the same (name, qtype) don't coalesce.
const bg_revalidate_flag: u8 = 2;

// ── Server ─────────────────────────────────────────────────────────────

pub const Server = struct {
    config: ServerConfig,
    allocator: mem.Allocator,
    io: Io,
    cache: RRsetCache,
    rtt_cache: RttCache,
    ns_selector: NsSelector,
    dedup: ?InFlightTable,
    encrypted_ns: ?EncryptedNs,
    case_state: ?CaseState,
    nsec_cache: ?NsecCache,
    key_cache: ?RRsetCache,
    udp_queue_drops: std.atomic.Value(u64) align(std.atomic.cache_line),
    tcp_queue_drops: std.atomic.Value(u64) align(std.atomic.cache_line),
    udp_send_drops: std.atomic.Value(u64) align(std.atomic.cache_line),
    /// Bumped when the recv-thread cache-hit fast path's cache-only resolver
    /// returns anything other than `CacheOnlyMiss`. Slow path re-runs the
    /// resolve, so the work is duplicated when this happens.
    fast_path_errors: std.atomic.Value(u64) align(std.atomic.cache_line),
    /// Client-facing cache accounting: exactly one bump per answered client
    /// query (UDP fast path, UDP slow path, TCP). `hits` = answered with
    /// zero upstream queries. This is the operator-meaningful hit rate — the
    /// RRsetCache counters count every internal lookup during recursion
    /// (CNAME probes, NX-ancestor walks, NS/DS/DNSKEY infra), which
    /// amplifies each client miss into ~10 counted misses and pins the
    /// reported rate far below the truth.
    client_cache_hits: std.atomic.Value(u64) align(std.atomic.cache_line),
    client_cache_misses: std.atomic.Value(u64) align(std.atomic.cache_line),
    prefetch_drops: std.atomic.Value(u64) align(std.atomic.cache_line),
    /// Shared slow-path queue. Heap-allocated to keep the embedded buffers
    /// off Server's stack frame at init.
    work_queue: *WorkQueue,
    exiting: std.atomic.Value(bool) = .init(false),
    /// RFC 8109 priming: first pool thread to win the CAS issues a single
    /// `. NS` recursive query so subsequent resolutions hit a warm cache
    /// with the live root NS RRset (not just the in-source root_hints).
    primed: std.atomic.Value(bool) align(std.atomic.cache_line) = std.atomic.Value(bool).init(false),
    bg_tasks: BumpGatedGroup,
    /// Hot-set refresh tracker (`prefetch-hot`); heap-owned so the
    /// cache's remiss hook holds a stable pointer.
    hot_set: ?*HotSet = null,

    /// `allocator` must be thread-safe: it backs the RRset/key/NSEC caches,
    /// which recv workers, resolution pools and bg-prefetch all share. Callers
    /// pass `init.gpa` or `testing.allocator`, both of which qualify in every
    /// build mode. The two `FailingAllocator` tests below are safe only because
    /// neither spawns a worker — do not copy them into one that does.
    pub fn init(allocator: mem.Allocator, cfg: ServerConfig, io: Io) !Server {
        if (cfg.allow_loopback_upstreams) {
            log.warn("allow-loopback-upstreams is enabled — DNS rebinding defence is disabled for upstream addresses; intended for test environments only", .{});
        }

        // Randomize hash seeds for cache, dedup, and AddressKey-keyed tables
        // (RttCache, NsSelector arms) so an authoritative can't engineer
        // bucket collisions via crafted glue addresses or query keys.
        cache_mod.randomizeHashSeed(io);
        dedup_mod.randomizeHashSeed(io);
        na.randomizeHashSeed(io);

        // The caches used to hardcode `std.heap.smp_allocator`, so the largest
        // region in the process escaped whatever checking allocator the caller
        // supplied — the server tests and a ReleaseSafe soak both saw nothing
        // (RRsetCache's own tests always used `testing.allocator`). The shipped
        // binary is unaffected: it links no libc, so ReleaseFast resolves
        // `init.gpa` to `smp_allocator`, exactly what was hardcoded here.
        const thread_safe = !builtin.single_threaded;
        // Cache readers = recv workers + their resolution-thread pools; both
        // caches size their shards from this.
        const reader_concurrency: u32 = @as(u32, cfg.workers) * (1 + @as(u32, cfg.resolution_threads));
        var cache = RRsetCache.init(.{
            .backing = allocator,
            .max_bytes = cfg.cache_size,
            .io = io,
            .prefetch = cfg.prefetch,
            .serve_stale_ttl = cfg.serve_stale_ttl,
            .min_ttl = cfg.min_ttl,
            .skip_key_types = cfg.dnssec,
            .reader_concurrency = reader_concurrency,
        });
        errdefer cache.deinit();

        var rtt_cache = RttCache.init(.{
            .allocator = allocator,
            .io = io,
            .thread_safe = thread_safe,
        });
        errdefer rtt_cache.deinit();

        var ns_selector = NsSelector.init(.{
            .allocator = allocator,
            .io = io,
            .thread_safe = thread_safe,
        });
        errdefer ns_selector.deinit();

        const work_queue = try allocator.create(WorkQueue);
        errdefer allocator.destroy(work_queue);
        work_queue.init(io);

        // Every remaining fallible step happens here, before the return
        // literal; inside it they'd run after every field above them with
        // no errdefer in reach.
        const hot_set: ?*HotSet = if (cfg.prefetch_hot) blk: {
            const hs = try allocator.create(HotSet);
            hs.init(io);
            break :blk hs;
        } else null;
        errdefer if (hot_set) |hs| allocator.destroy(hs);

        return .{
            .config = cfg,
            .allocator = allocator,
            .io = io,
            .cache = cache,
            .rtt_cache = rtt_cache,
            .ns_selector = ns_selector,
            .dedup = if (cfg.workers > 1) InFlightTable.init(allocator, io) else null,
            .encrypted_ns = if (cfg.opportunistic) EncryptedNs.init(allocator, io, cfg.upstream_tcp_idle_sec) else null,
            .case_state = if (cfg.case_randomization) CaseState.init(allocator, io) else null,
            .nsec_cache = if (cfg.dnssec) NsecCache.init(.{
                .backing = allocator,
                .max_bytes = NsecCache.default_max_bytes,
                .io = io,
                .thread_safe = thread_safe,
            }) else null,
            .key_cache = if (cfg.dnssec) RRsetCache.init(.{
                .backing = allocator,
                .max_bytes = cfg.key_cache_size,
                .io = io,
                .reader_concurrency = reader_concurrency,
            }) else null,
            .udp_queue_drops = std.atomic.Value(u64).init(0),
            .tcp_queue_drops = std.atomic.Value(u64).init(0),
            .udp_send_drops = std.atomic.Value(u64).init(0),
            .fast_path_errors = std.atomic.Value(u64).init(0),
            .client_cache_hits = std.atomic.Value(u64).init(0),
            .client_cache_misses = std.atomic.Value(u64).init(0),
            .prefetch_drops = std.atomic.Value(u64).init(0),
            .bg_tasks = .init(@min(max_bg_tasks, @max(1, @as(u32, cfg.workers) * cfg.resolution_threads / 2))),
            .work_queue = work_queue,
            .hot_set = hot_set,
        };
    }

    pub fn resolverContext(self: *Server) recursive.RecursiveResolver.Context {
        return .{
            .config = &self.config,
            .io = self.io,
            .gpa = self.allocator,
            .cache = &self.cache,
            .rtt_cache = &self.rtt_cache,
            .ns_selector = &self.ns_selector,
            .encrypted_ns = if (self.encrypted_ns) |*oc| oc else null,
            .case_state = if (self.case_state) |*cs| cs else null,
            .dedup = if (self.dedup) |*d| d else null,
            .nsec_cache = if (self.nsec_cache) |*nc| nc else null,
            .key_cache = if (self.key_cache) |*kc| kc else null,
            .tcp_pool = null,
        };
    }

    fn logFootprint(self: *Server) void {
        var buf: [512]u8 = undefined;
        const statm = Io.Dir.cwd().readFile(self.io, "/proc/self/statm", &buf) catch return;
        var it = mem.tokenizeScalar(u8, statm, ' ');
        _ = it.next();
        const rss_pages = std.fmt.parseInt(u64, it.next() orelse return, 10) catch return;
        const stat = Io.Dir.cwd().readFile(self.io, "/proc/self/stat", &buf) catch return;
        const after_comm = stat[(mem.lastIndexOfScalar(u8, stat, ')') orelse return) + 2 ..];
        var fields = mem.tokenizeScalar(u8, after_comm, ' ');
        const num_threads_field = 18;
        var threads: []const u8 = "?";
        for (0..num_threads_field) |_| threads = fields.next() orelse "?";
        log.info("footprint: rss {d} MiB, {s} threads, {d}/{d} bg tasks", .{
            rss_pages * std.heap.pageSize() / (1024 * 1024), threads, self.bg_tasks.inFlight(), self.bg_tasks.max,
        });
    }

    /// `0% while capable > 0` is the signature of capability knowledge
    /// going unused — the failure shape this line exists to catch.
    fn logOteStats(self: *Server) void {
        const oc = if (self.encrypted_ns) |*o| o else return;
        const s = oc.getStats();
        const total = s.dot_answers + s.do53_answers;
        const pct: u64 = if (total > 0) s.dot_answers * 100 / total else 0;
        log.info("ote: {d}/{d} upstream answers over DoT ({d}%), {d} servers capable, {d} evicted", .{
            s.dot_answers, total, pct, s.capable, s.evictions,
        });
    }

    pub fn deinit(self: *Server) void {
        if (self.encrypted_ns) |*oc| oc.deinit();
        if (self.case_state) |*cs| cs.deinit();
        if (self.dedup) |*d| d.deinit();
        if (self.nsec_cache) |*nc| nc.deinit();
        if (self.key_cache) |*kc| kc.deinit();
        self.cache.deinit();
        self.rtt_cache.deinit();
        self.ns_selector.deinit();
        self.allocator.destroy(self.work_queue);
        if (self.hot_set) |hs| self.allocator.destroy(hs);
    }

    /// Nothing unwinds: pool threads hold pointers into their worker's frame,
    /// and a drain has no wall-clock bound.
    fn exit(self: *Server, status: u8) noreturn {
        if (self.exiting.swap(true, .monotonic)) {
            while (true) self.io.sleep(.fromSeconds(60), .awake) catch {};
        }
        if (status == 0) self.logFinalStats();
        std.process.exit(status);
    }

    pub fn run(self: *Server) !noreturn {
        const listen_addrs: []const na.Address = if (self.config.listen.len > 0)
            self.config.listen
        else
            &.{na.initIp4(.{ 127, 0, 0, 1 }, 53)};

        if (listen_addrs.len > max_listen_addrs) {
            log.err("too many listen addresses ({d}), maximum is {d}", .{ listen_addrs.len, max_listen_addrs });
            return error.TooManyListenAddresses;
        }

        const workers = self.config.workers;

        // Block signals before spawning threads so all workers inherit the mask
        const sig_fd = setupSignalFd() catch -1;

        for (listen_addrs) |addr| {
            var addr_buf: [64]u8 = undefined;
            const addr_str = na.format(addr, &addr_buf);
            log.info("binding {s} (UDP+TCP)", .{addr_str});
        }

        // Fail closed: a non-loopback recursive bind without an explicit ACL
        // is an open resolver (BCP 140). Operators who genuinely want to
        // serve a public network must say so explicitly via allow-from
        // (e.g. ["0.0.0.0/0", "::/0"] for fully-open). The kernel firewall
        // is the right place for most ACLs; this check just stops the
        // accidental amplifier-on-startup case.
        if (self.config.allow_from.len == 0) {
            for (listen_addrs) |addr| {
                if (isNonLoopback(addr)) {
                    var addr_buf: [64]u8 = undefined;
                    log.err("refusing to start: recursive resolver bound to non-loopback {s} without [server].allow-from. " ++
                        "This would be an open resolver (BCP 140). Set allow-from to an explicit CIDR list.", .{na.format(addr, &addr_buf)});
                    return error.OpenResolverRefused;
                }
            }
        }

        log.info("workers={d}", .{workers});

        // Everything that needs privilege — rings (io_uring_disabled=1
        // gates setup on CAP_SYS_ADMIN) and low-port binds — happens here
        // on the main thread, before the drop and before any thread
        // exists to inherit the wrong credentials.
        const rigs = try self.allocator.alloc(Rig, workers);
        for (rigs) |*rig| {
            rig.loop = EventLoop.create(self.allocator) catch |err| {
                log.err("failed to create event loop: {s}", .{@errorName(err)});
                return err;
            };
            rig.udp = @splat(-1);
            rig.tcp = @splat(-1);
            for (listen_addrs, 0..) |addr, i| {
                var addr_buf: [64]u8 = undefined;
                const addr_str = na.format(addr, &addr_buf);
                rig.udp[i] = createSocket(addr, posix.SOCK.DGRAM, workers > 1, false) catch |err| {
                    log.warn("failed to create UDP socket for {s}: {s}", .{ addr_str, @errorName(err) });
                    continue;
                };
                rig.tcp[i] = createSocket(addr, posix.SOCK.STREAM, workers > 1, true) catch |err| {
                    log.warn("failed to create TCP socket for {s}: {s}", .{ addr_str, @errorName(err) });
                    sys.close(rig.udp[i]);
                    rig.udp[i] = -1;
                    continue;
                };
            }
            const any_ok = for (rig.udp[0..listen_addrs.len]) |fd| {
                if (fd >= 0) break true;
            } else false;
            if (!any_ok) {
                log.err("failed to bind any listen address", .{});
                return error.BindFailed;
            }
        }

        if (self.config.drop_gid != null or self.config.drop_uid != null) {
            dropPrivileges(self.config.drop_gid, self.config.drop_uid) catch |err| {
                log.err("failed to drop privileges: {s}", .{@errorName(err)});
                return err;
            };
            if (self.config.drop_gid) |g| log.info("dropped group to gid={d}", .{g});
            if (self.config.drop_uid) |u| log.info("dropped user to uid={d}", .{u});
        }

        // Hot-set refresh: hook wired here, not init — self is at its
        // final address by run() (init returns by value).
        if (self.hot_set) |hs| {
            self.cache.remiss_hook = .{ .ctx = hs, .call = &hotSetRemissHook };
            _ = std.Thread.spawn(.{}, hotSetSweeper, .{self}) catch |err| {
                log.warn("hot-set sweeper failed to spawn — prefetch-hot inactive: {s}", .{@errorName(err)});
            };
        }

        for (rigs[1..], 1..) |*rig, i| {
            _ = std.Thread.spawn(.{}, runWorker, .{ self, rig, listen_addrs.len, @as(posix.fd_t, -1) }) catch |err| {
                log.err("failed to spawn worker {d}: {s}", .{ i, @errorName(err) });
                return err;
            };
        }
        self.runWorker(&rigs[0], listen_addrs.len, sig_fd);
    }

    /// The client-query line is the operator-meaningful hit rate (one count
    /// per answered query); the rrset-lookup line below it counts all
    /// internal recursion traffic and reads structurally lower — don't
    /// compare the two.
    fn logFinalStats(self: *Server) void {
        const c_hits = self.client_cache_hits.load(.monotonic);
        const c_misses = self.client_cache_misses.load(.monotonic);
        const c_total = c_hits + c_misses;
        const c_pct: u64 = if (c_total > 0) c_hits * 100 / c_total else 0;
        log.info("client queries: {d} cache-served, {d} upstream ({d}% cache-served)", .{ c_hits, c_misses, c_pct });
        const stats = self.cache.getStats();
        const hit_total = stats.hits + stats.misses;
        const hit_pct: u64 = if (hit_total > 0) stats.hits * 100 / hit_total else 0;
        log.info("cache stats (rrset lookups, incl. internal): {d} entries, {d}/{d} KiB, {d} hits, {d} misses ({d}% hit, {d} expired-remiss), {d} evictions ({d} cap-exhausted), {d} prefetch-eligible, {d} stale", .{
            stats.entries, stats.memory_bytes / 1024, stats.max_bytes / 1024, stats.hits, stats.misses, hit_pct, stats.expired_remiss, stats.evictions, stats.cap_exhausted_evictions, stats.prefetch_eligible, stats.stale_hits,
        });
        self.logOteStats();
        if (self.key_cache) |*kc| {
            const ks = kc.getStats();
            const k_total = ks.hits + ks.misses;
            const k_pct: u64 = if (k_total > 0) ks.hits * 100 / k_total else 0;
            log.info("key cache: {d} entries, {d}/{d} KiB, {d} hits, {d} misses ({d}% hit rate)", .{
                ks.entries, ks.memory_bytes / 1024, ks.max_bytes / 1024, ks.hits, ks.misses, k_pct,
            });
        }
        if (self.nsec_cache) |*nc| {
            const ns = nc.getStats();
            const ns_total = ns.hits + ns.misses;
            const ns_pct: u64 = if (ns_total > 0) ns.hits * 100 / ns_total else 0;
            log.info("nsec cache: {d} zones, {d} bytes, {d} hits, {d} misses ({d}% hit rate)", .{
                ns.zones, ns.memory_bytes, ns.hits, ns.misses, ns_pct,
            });
        }
        const udp_drops = self.udp_queue_drops.load(.monotonic);
        const tcp_drops = self.tcp_queue_drops.load(.monotonic);
        if (udp_drops > 0 or tcp_drops > 0) {
            log.info("work queue drops: {d} UDP, {d} TCP", .{ udp_drops, tcp_drops });
        }
        logCounterIfNonzero("UDP send-buffer drops", self.udp_send_drops.load(.monotonic));
        logCounterIfNonzero("fast-path resolver errors (fell through to slow path)", self.fast_path_errors.load(.monotonic));
        logCounterIfNonzero("prefetches dropped (bg cap or work queue full)", self.prefetch_drops.load(.monotonic));
        if (self.hot_set) |hs| {
            logCounterIfNonzero("hot-set promotions", hs.promotions.load(.monotonic));
            logCounterIfNonzero("hot-set refreshes fired", hs.fired.load(.monotonic));
        }
        self.work_queue.dumpInstr();
    }

    /// One worker's privileged assets, built on the main thread before
    /// the drop.
    const Rig = struct {
        loop: *EventLoop,
        udp: [max_listen_addrs]posix.fd_t,
        tcp: [max_listen_addrs]posix.fd_t,
    };

    fn runWorker(self: *Server, rig: *const Rig, n_addrs: usize, sig_fd: posix.fd_t) noreturn {
        rig.loop.enable() catch |err| {
            log.err("failed to enable io_uring: {s}", .{@errorName(err)});
            self.exit(1);
        };
        // Per-worker Do53 TCP connection pool (RFC 7766)
        var do53_tcp_pool = TcpConnectionPool.init(self.allocator, self.io);
        do53_tcp_pool.max_idle_sec = self.config.upstream_tcp_idle_sec;

        var ws = WorkerState{
            .server = self,
            .loop = rig.loop,
            .tcp_pool = &do53_tcp_pool,
            .pool = .{ .size = self.config.resolution_threads },
        };

        var spawned: usize = 0;
        for (0..self.config.resolution_threads) |_| {
            _ = std.Thread.spawn(.{}, WorkerState.poolThread, .{&ws}) catch |err| {
                log.err("failed to spawn pool thread: {s}", .{@errorName(err)});
                break;
            };
            spawned += 1;
        }

        if (spawned == 0) {
            log.err("no pool threads spawned", .{});
            self.exit(1);
        }

        ws.serveLoop(rig.udp[0..n_addrs], rig.tcp[0..n_addrs], sig_fd);
    }

    /// Hot-set sweeper: one tick per 500 ms. Shares the cache's clock
    /// source, so TIME_PASSES test scenarios drive it consistently.
    fn hotSetSweeper(self: *Server) noreturn {
        const hs = self.hot_set.?;
        const Firer = struct {
            server: *Server,
            fn fire(f: @This(), name: []const u8, qtype: dns.RType) void {
                _ = f.server.trySpawnBgPrefetch(name, qtype, .prefetch);
            }
        };
        while (true) {
            hs.tick(monotonic.nowSec(), &self.cache, Firer{ .server = self });
            self.io.sleep(.fromMilliseconds(500), .awake) catch {};
        }
    }

    fn trySpawnBgPrefetch(self: *Server, name: []const u8, qtype: dns.RType, kind: BgKind) bool {
        if (name.len == 0 or name.len > dns.max_name_len + 1) return false;
        if (!self.bg_tasks.tryClaim()) return false;

        var payload: [3 + dns.max_name_len + 1]u8 = undefined;
        mem.writeInt(u16, payload[0..2], @backingInt(qtype), .big);
        payload[2] = @backingInt(kind);
        @memcpy(payload[3..][0..name.len], name);
        if (!self.work_queue.push(payload[0 .. 3 + name.len], na.initIp4(.{ 0, 0, 0, 0 }, 0), -1, .bg)) {
            self.bg_tasks.release();
            return false;
        }
        return true;
    }
};

/// Hot-set expiry refresh (config `[cache] prefetch-hot`): names found
/// dead twice within a window (expired-remiss events) earn a refresh
/// lease; a sweeper re-fetches them just before each expiry. Closes the
/// prefetch blind spot for query-interval > TTL demand (e.g. behind a
/// TTL-honoring forwarder, where all repeats arrive post-expiry).
///
/// Leases are fixed-length: a working refresh loop turns demand into hits
/// this tracker never sees, so "demand stopped" is unobservable — the
/// lease just lapses and live demand re-promotes at the cost of two
/// misses. CNAME chains refresh piecewise (redirect and tail remiss under
/// their own keys). No pattern learning: the lease already refreshes every hot
/// name, and every scheme considered needed per-name history this tracker
/// cannot afford at these slot counts.
const HotSet = struct {
    const candidate_slots = 512;
    const registry_slots = 256;
    /// Remiss events within `candidate_window` to earn a lease.
    const promote_at = 2;
    const candidate_window: i64 = 600;
    const lease_secs: i64 = 1800;
    /// Fire this early so the fresh entry lands while the old one serves.
    const fire_lead: i64 = 2;
    /// Re-probe delay after firing, letting the bg resolve store.
    const post_fire_delay: i64 = 3;
    /// Failing-refresh retry floor; doubles up to << max_backoff_shift.
    const base_backoff: i64 = 5;
    const max_backoff_shift: u6 = 4;
    /// Per-tick fire cap — excess due entries just wait a tick.
    const max_due_per_tick = 16;

    const Candidate = struct { tag: u64 = 0, credit: u8 = 0, last_seen: i64 = 0 };

    const Lease = struct {
        /// 0 = empty (keyTag never returns 0).
        tag: u64 = 0,
        name_buf: [dns.max_name_len + 1]u8 = undefined,
        name_len: u8 = 0,
        qtype: dns.RType = .a,
        lease_until: i64 = 0,
        next_check: i64 = 0,
        fail_shift: u6 = 0,
    };

    /// Leaf lock: taken from the cache's remiss hook (under a shard's
    /// SHARED lock) and by the sweeper. Nothing that holds this may touch
    /// a shard lock — see tick()'s copy-out discipline.
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    io: std.Io,
    // undefined + init(): `@splat(.{})` defaults made the whole default
    // aggregate an ~86 KiB mostly-zero .rodata memcpy template.
    candidates: [candidate_slots]Candidate = undefined,
    registry: [registry_slots]Lease = undefined,
    promotions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    fired: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn init(self: *HotSet, io: std.Io) void {
        self.* = .{ .io = io };
        for (&self.candidates) |*c| c.* = .{};
        for (&self.registry) |*l| l.* = .{};
    }

    fn keyTag(name: []const u8, qtype: dns.RType) u64 {
        // Static seed: a collision only makes a name fail to promote —
        // exactly today's behavior, nothing to attack.
        var h = std.hash.Wyhash.init(0x686f747365745f68);
        h.update(name);
        const q = @backingInt(qtype);
        h.update(std.mem.asBytes(&q));
        const tag = h.final();
        return if (tag == 0) 1 else tag;
    }

    /// Expired-remiss event from the cache hook. Runs under a shard's
    /// shared lock — leaf mutex only in here, and `name` must be copied,
    /// not retained.
    fn onRemiss(self: *HotSet, name: []const u8, qtype: dns.RType, now: i64) void {
        if (name.len == 0 or name.len > dns.max_name_len + 1) return;
        const tag = keyTag(name, qtype);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        // Already leased but demand re-missed: refresh loop is struggling.
        // Renew rather than making the name re-earn its slot.
        if (self.findSlotLocked(tag)) |slot| {
            slot.lease_until = now + lease_secs;
            return;
        }

        const c = &self.candidates[@intCast(tag % candidate_slots)];
        if (c.tag != tag or now - c.last_seen > candidate_window) {
            // Claim the bucket; collision loss is benign (loser stays unprotected).
            c.* = .{ .tag = tag, .credit = 1, .last_seen = now };
            return;
        }
        c.last_seen = now;
        c.credit +|= 1;
        if (c.credit < promote_at) return;

        c.* = .{}; // consumed
        self.insertLocked(tag, name, qtype, now);
        _ = self.promotions.fetchAdd(1, .monotonic);
    }

    fn findSlotLocked(self: *HotSet, tag: u64) ?*Lease {
        for (&self.registry) |*s| if (s.tag == tag) return s;
        return null;
    }

    fn insertLocked(self: *HotSet, tag: u64, name: []const u8, qtype: dns.RType, now: i64) void {
        // First empty slot, else evict the earliest lease.
        var victim: *Lease = &self.registry[0];
        for (&self.registry) |*s| {
            if (s.tag == 0) {
                victim = s;
                break;
            }
            if (s.lease_until < victim.lease_until) victim = s;
        }
        victim.* = .{
            .tag = tag,
            .name_len = @intCast(name.len),
            .qtype = qtype,
            .lease_until = now + lease_secs,
            .next_check = now, // probe on the next tick
        };
        @memcpy(victim.name_buf[0..name.len], name);
    }

    const Due = struct {
        name_buf: [dns.max_name_len + 1]u8,
        name_len: u8,
        qtype: dns.RType,
        tag: u64,
    };

    /// One sweep. `cache`/`firer` are anytype so tests can stub them.
    /// Lock discipline: due slots are COPIED OUT under the mutex, released
    /// before any cache probe or fire — holding it across shard access
    /// deadlocks against onRemiss (shared-shard→mutex) once a shard writer
    /// queues between the two shared acquisitions.
    fn tick(self: *HotSet, now: i64, cache: anytype, firer: anytype) void {
        var due: [max_due_per_tick]Due = undefined;
        var n: usize = 0;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            for (&self.registry) |*s| {
                if (s.tag == 0) continue;
                if (now >= s.lease_until) {
                    s.* = .{}; // lease lapsed; re-promotion costs two misses
                    continue;
                }
                if (now < s.next_check) continue;
                if (n == due.len) break;
                due[n] = .{ .name_buf = s.name_buf, .name_len = s.name_len, .qtype = s.qtype, .tag = s.tag };
                // Provisional bump so a stalled fire path isn't re-collected.
                s.next_check = now + post_fire_delay;
                n += 1;
            }
        }

        for (due[0..n]) |*d| {
            const name = d.name_buf[0..d.name_len];
            var next_check: i64 = undefined;
            var healthy = true;
            if (cache.entryExpiry(name, d.qtype, .in)) |expires_at| {
                if (expires_at - now > fire_lead) {
                    // Healthy and young: sleep until the fire window.
                    next_check = expires_at - fire_lead;
                } else if (expires_at > now) {
                    // In the window: refresh before it dies.
                    firer.fire(name, d.qtype);
                    _ = self.fired.fetchAdd(1, .monotonic);
                    next_check = now + post_fire_delay;
                } else {
                    // Dead and lingering — last refresh didn't take. Back off.
                    firer.fire(name, d.qtype);
                    _ = self.fired.fetchAdd(1, .monotonic);
                    next_check = now + self.currentBackoff(d.tag);
                    healthy = false;
                }
            } else {
                // Absent (evicted or never re-stored): same as dead.
                firer.fire(name, d.qtype);
                _ = self.fired.fetchAdd(1, .monotonic);
                next_check = now + self.currentBackoff(d.tag);
                healthy = false;
            }
            self.writeBack(d.tag, next_check, healthy);
        }
    }

    /// Read the slot's current backoff (mutex-guarded; slot may be gone).
    fn currentBackoff(self: *HotSet, tag: u64) i64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const slot = self.findSlotLocked(tag) orelse return base_backoff;
        return base_backoff << slot.fail_shift;
    }

    fn writeBack(self: *HotSet, tag: u64, next_check: i64, healthy: bool) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const slot = self.findSlotLocked(tag) orelse return; // replaced meanwhile
        slot.next_check = next_check;
        slot.fail_shift = if (healthy) 0 else @min(slot.fail_shift + 1, max_backoff_shift);
    }
};

/// Remiss-hook thunk: anyopaque → HotSet (see RRsetCache.remiss_hook).
fn hotSetRemissHook(ctx: *anyopaque, name: []const u8, rtype: dns.RType) void {
    const hs: *HotSet = @ptrCast(@alignCast(ctx));
    hs.onRemiss(name, rtype, monotonic.nowSec());
}

const BgKind = enum {
    /// Cache-refresh prefetch (near-expiry answer RRset or DNSKEY). Always
    /// runs with `bypass_cache=true` and dnssec_enabled mirrors config —
    /// semantically equivalent to a fresh CD=0 query.
    prefetch,
    /// Happy-Eyeballs A↔AAAA co-prefetch, fired on cache *absence*. Runs
    /// with the cache (unlike .prefetch) so it is semantically the client
    /// query it pre-empts — CNAME follows, NX cuts and all. The only kind
    /// that records its failures (RFC 9520): absence is the fire condition,
    /// so an unrecorded failure re-fires on every client query.
    cousin,
    /// CD=1 revalidation. Re-resolve with dnssec_enabled=true
    /// to upgrade the .unchecked cache entry to .secure (or invalidate on
    /// BOGUS). Runs with `bypass_cache=true` so validation actually fires
    /// — cache-hit on .unchecked records returns them without re-verifying,
    /// so we pay the upstream round-trip to get signed data for validation.
    revalidate,
};

/// Errors are expected and ignored; runs for cache side effects.
fn runBgTask(ctx: recursive.RecursiveResolver.Context, transports: Transports, alloc: mem.Allocator, name: []const u8, qtype: dns.RType, kind: BgKind) void {
    const dedup_flag: u8 = if (kind == .revalidate) bg_revalidate_flag else 0;
    if (ctx.dedup) |d| if (!d.tryAcquireLeader(name, qtype, dedup_flag)) return;
    defer if (ctx.dedup) |d| d.releaseLeader(name, qtype, dedup_flag);

    var resolver = recursive.RecursiveResolver.fromContext(ctx, transports, .{ .bypass_cache = kind != .cousin });
    _ = resolver.resolve(alloc, name, qtype) catch |err| {
        var qtype_buf: [24]u8 = undefined;
        log.debug("bg resolve {s} {s}: {s}", .{ name, dns.safeTagName(qtype, &qtype_buf), @errorName(err) });
        // Only cousins record: a refresh kind still holds the entry it meant
        // to refresh, so a SERVFAIL would clobber it. cacheServfail refuses
        // fresh entries under the shard write lock, which closes the race
        // with a concurrent successful resolve.
        if (kind == .cousin) ctx.cache.cacheServfail(name, qtype);
    };
}

// ── TCP clients ────────────────────────────────────────────────────────

const TcpClient = struct {
    fd: posix.fd_t,
    peer: na.Address,
    ctx: Ctx,
    last_activity_ns: i128,
    buf: [2 + max_frame]u8 = undefined,
    len: usize = 0,
    served: u32 = 0,
    refs: std.atomic.Value(u32) = .init(1),
    write_mutex: Io.Mutex = .init,

    const max_frame = max_work_query_bytes - @sizeOf(usize);

    fn ref(self: *TcpClient) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    fn unref(self: *TcpClient, allocator: mem.Allocator) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        sys.close(self.fd);
        allocator.destroy(self);
    }

    fn write(self: *TcpClient, io: Io, data: []const u8, timeout_ms: u32) void {
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        const deadline_ns = monotonic.nowNs() + @as(i128, timeout_ms) * std.time.ns_per_ms;
        tcpWriteMessage(io, self.fd, data, deadline_ns) orelse {};
    }
};

const Reply = union(enum) {
    udp: struct { sock: posix.fd_t, addr: na.Address },
    tcp: *TcpClient,

    fn peer(self: Reply) na.Address {
        return switch (self) {
            .udp => |u| u.addr,
            .tcp => |c| c.peer,
        };
    }
};

// ── WorkerState ────────────────────────────────────────────────────────
// Per-thread state that handles the actual serve loop.

const WorkerState = struct {
    server: *Server,
    loop: *EventLoop,
    tcp_pool: ?*TcpConnectionPool = null,
    tcp_clients: [max_tcp_clients_per_worker]*TcpClient = undefined,
    tcp_count: usize = 0,
    pool: recursive.PoolOccupancy,
    recv_pta: PerThreadArena = undefined,

    /// Build a resolver Context: the server-level one plus this worker's
    /// Do53 TCP pool. Per-query knobs (cd, bypass_cache) go through
    /// RuntimeOpts, not here.
    fn resolverContext(self: *WorkerState) recursive.RecursiveResolver.Context {
        var ctx = self.server.resolverContext();
        ctx.tcp_pool = self.tcp_pool;
        ctx.pool = &self.pool;
        return ctx;
    }

    fn logCacheStats(self: *const WorkerState) void {
        const stats = self.server.cache.getStats();
        const hit_total = stats.hits + stats.misses;
        const hit_pct: u64 = if (hit_total > 0) stats.hits * 100 / hit_total else 0;
        log.info("cache: {d} entries, {d}/{d} KiB, {d}% hit, {d} evictions", .{
            stats.entries, stats.memory_bytes / 1024, stats.max_bytes / 1024, hit_pct, stats.evictions,
        });
        self.server.logOteStats();
        self.server.logFootprint();
    }

    /// Logs a failed arm; the repair loop at the bottom of each tick
    /// retries silently until it takes.
    fn armed(result: anytype, what: []const u8) bool {
        _ = result catch |err| {
            log.err("failed to arm {s}: {s}", .{ what, @errorName(err) });
            return false;
        };
        return true;
    }

    fn acceptTcp(self: *WorkerState, fd: posix.fd_t, peer: na.Address) void {
        // BCP 140.
        if (self.server.config.allow_from.len > 0 and !acl.allow(self.server.config.allow_from, peer)) return sys.close(fd);
        if (self.tcp_count == max_tcp_clients_per_worker) {
            log.debug("TCP client limit reached ({d}), dropping connection", .{max_tcp_clients_per_worker});
            return sys.close(fd);
        }
        const client = self.server.allocator.create(TcpClient) catch return sys.close(fd);
        client.* = .{ .fd = fd, .peer = peer, .ctx = .{ .tag = .tcp_read, .fd = fd }, .last_activity_ns = monotonic.nowNs() };
        self.tcp_clients[self.tcp_count] = client;
        self.tcp_count += 1;
        sys.setNoDelay(fd);
        if (!armed(self.loop.readStream(fd, &client.buf, @ptrCast(&client.ctx)), "TCP read")) self.dropTcpClient(client);
    }

    /// False: close.
    fn feedTcp(self: *WorkerState, client: *TcpClient, n: usize) bool {
        client.len += n;
        client.last_activity_ns = monotonic.nowNs();
        var start: usize = 0;
        while (client.len - start >= 2) {
            const frame_len: usize = mem.readInt(u16, client.buf[start..][0..2], .big);
            if (frame_len == 0 or frame_len > TcpClient.max_frame) return false;
            if (client.len - start < 2 + frame_len) break;
            if (client.served >= self.server.config.tcp_queries_per_conn) return false;
            client.served += 1;
            if (!self.dispatchTcp(client, client.buf[start + 2 ..][0..frame_len])) return false;
            start += 2 + frame_len;
        }
        if (start > 0) {
            mem.copyForwards(u8, &client.buf, client.buf[start..client.len]);
            client.len -= start;
        }
        return true;
    }

    fn dispatchTcp(self: *WorkerState, client: *TcpClient, wire: []const u8) bool {
        var payload: [max_work_query_bytes]u8 = undefined;
        mem.writeInt(usize, payload[0..@sizeOf(usize)], @intFromPtr(client), .little);
        @memcpy(payload[@sizeOf(usize)..][0..wire.len], wire);
        client.ref();
        if (self.server.work_queue.push(payload[0 .. @sizeOf(usize) + wire.len], client.peer, client.fd, .tcp)) return true;
        client.unref(self.server.allocator);
        _ = self.server.tcp_queue_drops.fetchAdd(1, .monotonic);
        log.debug("resolution queue full, dropping TCP client", .{});
        return false;
    }

    /// Only with no read pending on `buf`.
    fn dropTcpClient(self: *WorkerState, client: *TcpClient) void {
        for (self.tcp_clients[0..self.tcp_count], 0..) |c, i| {
            if (c == client) {
                self.tcp_count -= 1;
                self.tcp_clients[i] = self.tcp_clients[self.tcp_count];
                break;
            }
        }
        client.unref(self.server.allocator);
    }

    /// RFC 7766 §6.2.3.
    fn sweepTcpIdle(self: *WorkerState) void {
        const idle_ns: i128 = @as(i128, self.server.config.tcp_idle_timeout_ms) * std.time.ns_per_ms;
        const now = monotonic.nowNs();
        for (self.tcp_clients[0..self.tcp_count]) |c| {
            if (c.refs.load(.acquire) > 1) {
                c.last_activity_ns = now;
            } else if (now - c.last_activity_ns > idle_ns) {
                sys.shutdown(c.fd);
            }
        }
    }

    fn serveLoop(self: *WorkerState, udp_socks: []const posix.fd_t, tcp_socks: []const posix.fd_t, sig_fd: posix.fd_t) noreturn {
        const n = udp_socks.len;

        self.recv_pta.init(self.server.allocator, self.server.config.query_memory_limit);

        var udp_ctxs: [max_listen_addrs]Ctx = undefined;
        var tcp_ctxs: [max_listen_addrs]Ctx = undefined;
        var signal_ctx = Ctx{ .tag = .signal, .fd = sig_fd };

        var udp_armed: [max_listen_addrs]bool = @splat(false);
        var tcp_armed: [max_listen_addrs]bool = @splat(false);

        // Multishot recvmsg — one SQE per socket stays armed and produces
        // CQEs for every inbound packet until the kernel terminates it.
        for (udp_socks, 0..) |fd, i| {
            if (fd < 0) continue;
            udp_ctxs[i] = .{ .tag = .udp_recv, .fd = fd };
            udp_armed[i] = armed(self.loop.recvFromMulti(fd, @ptrCast(&udp_ctxs[i])), "UDP recvmsg");
        }

        // Register accept for each TCP socket
        for (tcp_socks, 0..) |fd, i| {
            if (fd < 0) continue;
            tcp_ctxs[i] = .{ .tag = .tcp_accept, .fd = fd };
            tcp_armed[i] = armed(self.loop.accept(fd, @ptrCast(&tcp_ctxs[i])), "TCP accept");
        }

        var signal_armed = sig_fd >= 0 and !std.meta.isError(self.loop.read(sig_fd, @ptrCast(&signal_ctx)));
        var tick_ctx = Ctx{ .tag = .tick, .fd = -1 };
        var tick_armed = armed(self.loop.timer(tick_ms, @ptrCast(&tick_ctx)), "tick");

        // Consecutive unreadable signalfd completions; see the `.signal` arm.
        var signal_misfires: u32 = 0;

        var completions: [max_operations]Completion = undefined;
        var last_stats_ns: i128 = monotonic.nowNs();
        const stats_interval_ns: i128 = 180 * std.time.ns_per_s;

        // The cache is shared per-process, so every worker would log identical
        // stats. Only the main worker (the one holding the signalfd) emits the
        // periodic line, keeping it to one entry per interval.
        const log_stats = sig_fd >= 0;
        if (log_stats) self.server.logFootprint();

        while (true) {
            const results = self.loop.tick(&completions) catch |err| {
                log.err("io_uring tick failed: {s}", .{@errorName(err)});
                self.server.exit(1);
            };

            const now_ns = monotonic.nowNs();
            if (log_stats and now_ns - last_stats_ns >= stats_interval_ns) {
                self.logCacheStats();
                const elapsed = now_ns - last_stats_ns;
                last_stats_ns += @divFloor(elapsed, stats_interval_ns) * stats_interval_ns;
            }

            for (results) |c| {
                const ctx: *Ctx = @ptrCast(@alignCast(c.context));
                switch (ctx.tag) {
                    .signal => {
                        switch (classifySignalRead(c.result)) {
                            .shutdown => {
                                log.info("shutting down", .{});
                                self.server.exit(0);
                            },
                            .stats => {
                                self.logCacheStats();
                                signal_misfires = 0;
                            },
                            // Re-arm rather than exit. A permanently broken fd
                            // would spin the worker instead, so give up after a
                            // bounded run — by shutting down, because signals
                            // are blocked process-wide with this fd as their
                            // only reader, and a resolver nobody can SIGTERM is
                            // worse than one that exits for its supervisor to
                            // restart.
                            .ignore => {
                                signal_misfires += 1;
                                if (signal_misfires > max_signal_misfires) {
                                    log.err("signalfd unreadable {d}x; shutting down", .{signal_misfires});
                                    self.server.exit(1);
                                }
                            },
                        }
                        // Both ways this can fail (slot table full, SQ full)
                        // clear on the next tick; the repair loop below retries.
                        signal_armed = !std.meta.isError(self.loop.read(ctx.fd, @ptrCast(ctx)));
                        continue;
                    },
                    .udp_recv => {
                        switch (c.result) {
                            .recv => |recv| {
                                if (recv.err == null and recv.data.len > 0) {
                                    self.handleUdpQuery(ctx.fd, recv.data, recv.addr);
                                }
                                if (recv.buf_id) |bid| self.loop.releaseBuf(bid);
                            },
                            else => {},
                        }
                        const idx = ctxIndex(&udp_ctxs, n, ctx) orelse continue;
                        // Re-arm only on kernel termination, signalled by this
                        // CQE — never the slot table (see Completion.terminated
                        // for the mid-batch id-recycle trap). ENOBUFS on the
                        // shared buffer ring is flood-triggerable; a missed
                        // re-arm leaves SO_REUSEPORT hashing traffic into a
                        // dead worker until restart.
                        if (!c.terminated) continue;
                        udp_armed[idx] = armed(self.loop.recvFromMulti(ctx.fd, @ptrCast(ctx)), "UDP recvmsg");
                    },
                    .tcp_accept => {
                        switch (c.result) {
                            .accept => |acc| if (acc.err == null and acc.fd >= 0) self.acceptTcp(acc.fd, acc.addr),
                            else => {},
                        }
                        const idx = ctxIndex(&tcp_ctxs, n, ctx) orelse continue;
                        tcp_armed[idx] = armed(self.loop.accept(ctx.fd, @ptrCast(ctx)), "TCP accept");
                    },
                    .tcp_read => {
                        const client: *TcpClient = @alignCast(@fieldParentPtr("ctx", ctx));
                        const got = c.result.stream;
                        if (got == 0 or !self.feedTcp(client, got) or
                            !armed(self.loop.readStream(client.fd, client.buf[client.len..], @ptrCast(&client.ctx)), "TCP read"))
                        {
                            self.dropTcpClient(client);
                        }
                    },
                    .tick => {
                        self.sweepTcpIdle();
                        tick_armed = armed(self.loop.timer(tick_ms, @ptrCast(&tick_ctx)), "tick");
                    },
                }
            }

            // The signalfd read joins the same repair loop as the listeners:
            // a transient arm failure must not cost the daemon its signals.
            if (sig_fd >= 0 and !signal_armed) {
                signal_armed = !std.meta.isError(self.loop.read(sig_fd, @ptrCast(&signal_ctx)));
            }
            if (!tick_armed) tick_armed = !std.meta.isError(self.loop.timer(tick_ms, @ptrCast(&tick_ctx)));

            // Retry re-registration for any listeners that failed above.
            // Placed after completion processing so freshly freed slots are available.
            for (0..n) |i| {
                if (udp_socks[i] >= 0 and !udp_armed[i]) {
                    udp_armed[i] = !std.meta.isError(self.loop.recvFromMulti(udp_ctxs[i].fd, @ptrCast(&udp_ctxs[i])));
                }
                if (tcp_socks[i] >= 0 and !tcp_armed[i]) {
                    tcp_armed[i] = !std.meta.isError(self.loop.accept(tcp_ctxs[i].fd, @ptrCast(&tcp_ctxs[i])));
                }
            }
        }
    }

    fn sendErrorUdp(self: *WorkerState, sock: posix.fd_t, id: u16, opcode: dns.OpCode, rcode: dns.RCode, extended_rcode: u8, rd: bool, questions: []const dns.Question, client_addr: na.Address) void {
        var wire_buf: [dns.max_udp_payload]u8 = undefined;
        if (serializeErrorResponse(&wire_buf, id, opcode, rcode, extended_rcode, rd, questions)) |wire| {
            self.sendUdpResponse(sock, wire, client_addr);
        }
    }

    fn sendUdpResponse(self: *WorkerState, sock: posix.fd_t, data: []const u8, dest: na.Address) void {
        // MSG_DONTWAIT keeps the pool thread off a saturated kernel send buffer.
        // Dropping the response is correct DNS behavior — the client retransmits.
        // All sendto failures (WouldBlock, SystemResources, MessageTooBig, peer
        // resets, etc.) are counted under one drop signal: any send failure is
        // operationally a "response not delivered" event the operator wants to see.
        var storage: na.PosixAddress = undefined;
        const sa_len = na.toSockaddr(&dest, &storage);
        _ = sys.sendto(sock, data, posix.MSG.DONTWAIT, &storage.any, sa_len) catch {
            _ = self.server.udp_send_drops.fetchAdd(1, .monotonic);
        };
    }

    /// Send the resolver response or SERVFAIL the client. Handles both
    /// failure modes internally — wire-buffer alloc OOM and serializer OOM
    /// both fall through to `sendErrorUdp`, which uses a stack buffer and
    /// doesn't share the failing arena.
    fn sendUdpResponseFromResult(
        self: *WorkerState,
        sock: posix.fd_t,
        query_msg: dns.Message,
        result_msg: dns.Message,
        alloc: mem.Allocator,
        client_addr: na.Address,
    ) void {
        // Floor at the bare-EDNS-0 minimum, ceiling at the operator cap.
        // Trusting an unbounded client claim is a reflection-amp surface.
        const client_payload = if (query_msg.opt) |opt| opt.udp_payload_size else dns.max_udp_payload;
        const resolved_payload: u16 = @min(@max(client_payload, dns.max_udp_payload), self.server.config.max_udp_payload);

        var wire_stack: [4096]u8 = undefined;
        const wire_buf: ?[]u8 = if (resolved_payload <= wire_stack.len)
            wire_stack[0..]
        else
            alloc.alloc(u8, resolved_payload) catch null;

        if (wire_buf) |buf| {
            var ctx = ResponseContext.fromQuery(query_msg, resolved_payload);
            ctx.minimal_responses = self.server.config.minimal_responses;
            ctx.rebinding = &self.server.config.rebinding;
            if (buildResponseWire(buf, ctx, result_msg, alloc)) |wire| {
                self.sendUdpResponse(sock, wire, client_addr);
                return;
            }
        }
        self.sendErrorUdp(sock, query_msg.header.id, query_msg.header.flags.opcode, .server_failure, 0, query_msg.header.flags.rd, query_msg.questions, client_addr);
    }

    fn handleUdpQuery(self: *WorkerState, sock: posix.fd_t, data: []const u8, client_addr: na.Address) void {
        if (data.len < 12) return;
        // BCP 140: silently drop UDP from sources outside allow-from. Replying
        // with REFUSED would still amplify and confirm the resolver exists;
        // a drop is the only correct anti-reflection behavior. Empty list ==
        // no ACL == accept all (back-compat).
        if (!acl.allow(self.server.config.allow_from, client_addr)) return;
        // RFC 1035 §4.1.1: drop QR=1 silently. Treating a spoofed response
        // as a query would let an attacker reflect upstream resolutions
        // off this server.
        if (data[2] & 0x80 != 0) return;
        const id = mem.readInt(u16, data[0..2], .big);
        const rd = data[2] & 0x01 != 0; // RFC 1035 §4.1.1: echo RD in response
        // Pre-validate from raw header bytes to avoid wasting pool threads
        // on garbage: opcode (bits 1-4 of byte 2), qdcount (bytes 4-5).
        const opcode_bits: u4 = @truncate(data[2] >> 3);
        const client_opcode: dns.OpCode = @fromBackingInt(@intCast(opcode_bits));
        if (opcode_bits != 0) { // Only QUERY (0) supported
            @branchHint(.cold);
            self.sendErrorUdp(sock, id, client_opcode, .not_implemented, 0, rd, &.{}, client_addr);
            return;
        }
        const qdcount = mem.readInt(u16, data[4..6], .big);
        if (qdcount != 1) {
            @branchHint(.cold);
            self.sendErrorUdp(sock, id, .query, .format_error, 0, rd, &.{}, client_addr);
            return;
        }

        if (self.tryCacheHitReply(sock, data, client_addr)) return;

        if (!self.server.work_queue.push(data, client_addr, sock, .udp)) {
            @branchHint(.cold);
            // Silent drop on pool saturation (matches Unbound ip-ratelimit,
            // PowerDNS over-capacity, dnsdist default). A SERVFAIL here
            // would get pinned in every downstream cache for up to 5
            // minutes (RFC 9520), turning a transient queue blip into a
            // multi-minute outage from each client's perspective. Drop
            // applies natural backpressure via the client's retry timeout.
            // Per-drop log stays at debug — under a UDP flood, a warn
            // here would itself become the DoS surface; the
            // `udp_queue_drops` atomic is the operator-facing signal.
            _ = self.server.udp_queue_drops.fetchAdd(1, .monotonic);
            log.debug("resolution queue full, dropping query", .{});
        }
    }

    /// Recv-thread cache-hit fast path. Returns true when the query was
    /// fully handled inline; false to fall through to the slow-path queue.
    fn tryCacheHitReply(self: *WorkerState, sock: posix.fd_t, data: []const u8, client_addr: na.Address) bool {
        const alloc = self.recv_pta.reset();
        const query_msg = dns.parseMessage(alloc, data) catch return false;
        if (validateQuery(query_msg)) |_| return false;
        const question = query_msg.questions[0];

        var name_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const name_str = question.name.formatInto(&name_buf);

        // Clock-advance control queries must reach the slow-path intercept;
        // `invalid.` is RFC 6761 special-use and would NXDOMAIN inline here.
        if (build_options.testing_enabled and parseAdvanceClockQname(name_str) != null) return false;

        var resolver = recursive.RecursiveResolver.fromContext(
            self.resolverContext(),
            null,
            .{ .cd = query_msg.header.flags.cd, .cache_only = true },
        );
        const result = resolver.resolve(alloc, name_str, question.qtype) catch |err| {
            // CacheOnlyMiss is the expected miss signal — anything else (OOM,
            // validation budget exhaustion, etc.) is operationally interesting
            // and would otherwise be silently re-tried on the slow path.
            if (err != error.CacheOnlyMiss) {
                _ = self.server.fast_path_errors.fetchAdd(1, .monotonic);
                log.debug("fast-path resolver error: {s}", .{@errorName(err)});
            }
            return false;
        };

        self.sendUdpResponseFromResult(sock, query_msg, result.message, alloc, client_addr);

        self.recordClientOutcome(result.from_cache); // cache_only ⇒ always a hit
        self.dispatchPrefetches(result, name_str);
        if (query_msg.header.flags.cd) self.scheduleCd1Revalidate(name_str, question.qtype);
        return true;
    }

    /// One bump per answered client query — see Server.client_cache_hits.
    /// SERVFAILs count as misses (the client waited on failed upstream
    /// work); malformed/refused queries are never counted.
    fn recordClientOutcome(self: *WorkerState, from_cache: bool) void {
        const ctr = if (from_cache) &self.server.client_cache_hits else &self.server.client_cache_misses;
        _ = ctr.fetchAdd(1, .monotonic);
    }

    fn resolveQueryWith(
        self: *WorkerState,
        alloc: mem.Allocator,
        name: []const u8,
        qtype: dns.RType,
        cd: bool,
        bypass_cache: bool,
        transports: Transports,
    ) !recursive.RecursiveResolver.ResolveResult {
        // Test harness control channel: `_advance-clock.<N>.testharness.invalid.`
        // advances the synthetic monotonic clock by <N> seconds and returns
        // an empty NOERROR. Used by `STEP n TIME_PASSES` to observe TTL
        // expiry without wall-clock sleeps. Gated on `-Dtesting=true` — the
        // intercept doesn't exist in production builds.
        if (build_options.testing_enabled) {
            if (parseAdvanceClockQname(name)) |secs| {
                monotonic.advanceTestClock(secs);
                return .{
                    .message = response.synthesizedMessage(&.{}, &.{}, .no_error, false),
                };
            }
        }
        var resolver = recursive.RecursiveResolver.fromContext(
            self.resolverContext(),
            transports,
            .{ .cd = cd, .bypass_cache = bypass_cache },
        );
        return resolver.resolve(alloc, name, qtype);
    }

    /// Resolution thread pool entry point.
    fn poolThread(self: *WorkerState) noreturn {
        var udp = BlockingUdpTransport.init(.{}, self.server.io);
        const transports: Transports = .{ .udp = &udp, .tcp_enabled = true };

        var query_pta: PerThreadArena = undefined;
        query_pta.init(self.server.allocator, self.server.config.query_memory_limit);

        // RFC 8109: first pool thread anywhere on this Server primes the
        // cache with a live "." NS lookup. Single CAS gates the work, so
        // sibling pool threads start serving immediately. On failure
        // (no network at boot, all root hints unreachable, SERVFAIL) reset
        // the flag so a *later* pool thread can retry. In practice all
        // pool threads spawn before priming I/O completes, so the retry
        // window is "next pool thread that observes primed=false after
        // the failing thread releases the flag" — which is bounded by
        // pool-thread loop iteration cadence. Real client queries that
        // need root NS still self-heal via the normal root_hints fallback
        // and populate the cache through ordinary recursion.
        if (self.server.primed.cmpxchgStrong(false, true, .acq_rel, .monotonic) == null) {
            const alloc = query_pta.reset();
            if (self.resolveWithDedupUsing(alloc, ".", .ns, false, transports)) |result| {
                // SERVFAIL counts as failure even though Zig sees a normal
                // return — otherwise the .unchecked SERVFAIL written into
                // the cache by the resolver (5 min ceiling) would shadow
                // root NS lookups for the entire boot window.
                if (result.message.header.flags.rcode != .no_error) {
                    self.server.primed.store(false, .release);
                }
            } else |_| {
                self.server.primed.store(false, .release);
            }
        }

        while (true) {
            const item = self.server.work_queue.pop();
            switch (item.protocol) {
                .udp => {
                    // item.payload borrows from the slot; parseMessage
                    // copies what it keeps into the per-thread arena, so
                    // releasing right after processQuery is safe.
                    defer self.server.work_queue.release(item.reservation);
                    self.processQuery(.{ .udp = .{ .sock = item.sock_fd, .addr = item.client_addr } }, item.payload, transports, &query_pta);
                },
                .bg => {
                    defer self.server.work_queue.release(item.reservation);
                    defer self.server.bg_tasks.release();
                    const qtype: dns.RType = @fromBackingInt(mem.readInt(u16, item.payload[0..2], .big));
                    const kind: BgKind = @fromBackingInt(@intCast(item.payload[2]));
                    runBgTask(self.resolverContext(), transports, query_pta.reset(), item.payload[3..], qtype, kind);
                },
                .tcp => {
                    defer self.server.work_queue.release(item.reservation);
                    const client: *TcpClient = @ptrFromInt(mem.readInt(usize, item.payload[0..@sizeOf(usize)], .little));
                    defer client.unref(self.server.allocator);
                    self.processQuery(.{ .tcp = client }, item.payload[@sizeOf(usize)..], transports, &query_pta);
                },
            }
        }
    }

    fn processQuery(self: *WorkerState, reply: Reply, data: []const u8, transports: Transports, query_pta: *PerThreadArena) void {
        const alloc = query_pta.reset();

        const query = dns.parseMessage(alloc, data) catch {
            @branchHint(.cold);
            if (data.len >= 3) {
                const id = mem.readInt(u16, data[0..2], .big);
                // Best-effort opcode echo from raw header even when parse failed.
                const op_bits: u4 = @truncate(data[2] >> 3);
                self.sendError(reply, id, @fromBackingInt(@intCast(op_bits)), .format_error, 0, false, &.{});
            }
            return;
        };

        if (validateQuery(query)) |fail| {
            self.sendError(reply, query.header.id, query.header.flags.opcode, fail.rcode, fail.extended_rcode, query.header.flags.rd, query.questions);
            return;
        }

        const question = query.questions[0];
        var name_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const name_str = question.name.formatInto(&name_buf);
        var peer_buf: [64]u8 = undefined;
        const peer_str = na.format(reply.peer(), &peer_buf);
        const tag: []const u8 = if (reply == .tcp) " tcp" else "";

        const start_ns = monotonic.nowNs();
        const result = self.resolveWithDedupUsing(alloc, name_str, question.qtype, query.header.flags.cd, transports) catch |err| {
            @branchHint(.cold);
            const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
            var qtype_buf: [24]u8 = undefined;
            log.warn("client={s} id=0x{x:0>4} {s} {s} SERVFAIL {d}ms{s} ({s})", .{ peer_str, query.header.id, name_str, dns.safeTagName(question.qtype, &qtype_buf), elapsed_ms, tag, @errorName(err) });
            self.server.cache.cacheServfail(name_str, question.qtype);
            self.recordClientOutcome(false);
            self.sendError(reply, query.header.id, query.header.flags.opcode, .server_failure, 0, query.header.flags.rd, query.questions);
            return;
        };
        const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
        var qtype_buf: [24]u8 = undefined;
        var rcode_buf: [24]u8 = undefined;
        log.debug("client={s} id=0x{x:0>4} {s} {s}{s} {d}ms{s}", .{ peer_str, query.header.id, name_str, dns.safeTagName(question.qtype, &qtype_buf), rcodeSuffix(result.message.header.flags.rcode, &rcode_buf), elapsed_ms, tag });

        self.sendResponse(reply, query, result.message, alloc);

        self.recordClientOutcome(result.from_cache);
        self.dispatchPrefetches(result, name_str);
        if (query.header.flags.cd) {
            self.scheduleCd1Revalidate(name_str, question.qtype);
        }
    }

    fn sendError(self: *WorkerState, reply: Reply, id: u16, opcode: dns.OpCode, rcode: dns.RCode, extended_rcode: u8, rd: bool, questions: []const dns.Question) void {
        switch (reply) {
            .udp => |u| self.sendErrorUdp(u.sock, id, opcode, rcode, extended_rcode, rd, questions, u.addr),
            .tcp => |c| {
                var buf: [dns.max_udp_payload]u8 = undefined;
                const wire = serializeErrorResponse(&buf, id, opcode, rcode, extended_rcode, rd, questions) orelse return;
                c.write(self.server.io, wire, self.server.config.tcp_idle_timeout_ms);
            },
        }
    }

    fn sendResponse(self: *WorkerState, reply: Reply, query: dns.Message, result: dns.Message, alloc: mem.Allocator) void {
        switch (reply) {
            .udp => |u| self.sendUdpResponseFromResult(u.sock, query, result, alloc, u.addr),
            .tcp => |c| {
                var buf: [dns.max_message_len]u8 = undefined;
                var ctx = ResponseContext.fromQuery(query, dns.max_message_len);
                // RFC 7828, units of 100 ms.
                ctx.tcp_keepalive = @intCast(self.server.config.tcp_idle_timeout_ms / 100);
                ctx.minimal_responses = self.server.config.minimal_responses;
                ctx.rebinding = &self.server.config.rebinding;
                const wire = buildResponseWire(&buf, ctx, result, alloc) orelse
                    return self.sendError(reply, query.header.id, query.header.flags.opcode, .server_failure, 0, query.header.flags.rd, query.questions);
                c.write(self.server.io, wire, self.server.config.tcp_idle_timeout_ms);
            },
        }
    }

    fn dispatchPrefetches(
        self: *WorkerState,
        result: recursive.RecursiveResolver.ResolveResult,
        query_name: []const u8,
    ) void {
        if (result.prefetch_name) |n| self.spawnPrefetch(n, result.prefetch_qtype);
        if (result.prefetch_dnskey_zone) |z| self.spawnPrefetch(z, .dnskey);

        if (!self.server.config.prefetch_cousin) return;
        // RFC 8305 A↔AAAA pairing.
        if (result.cousin_prefetch_qtype) |qt| {
            if (!self.server.cache.containsFresh(query_name, qt, .in)) {
                _ = self.server.trySpawnBgPrefetch(query_name, qt, .cousin);
            }
        }
        // HEv3 §4.2.1: A/AAAA of a SVCB/HTTPS TargetName the client
        // can only chase after this answer arrives.
        if (result.cousin_prefetch_name) |target| {
            for ([_]dns.RType{ .aaaa, .a }) |qt| {
                if (!self.server.cache.containsFresh(target, qt, .in)) {
                    _ = self.server.trySpawnBgPrefetch(target, qt, .cousin);
                }
            }
        }
    }

    fn spawnPrefetch(self: *WorkerState, name: []const u8, qtype: dns.RType) void {
        if (self.server.trySpawnBgPrefetch(name, qtype, .prefetch)) return;
        _ = self.server.prefetch_drops.fetchAdd(1, .monotonic);
    }

    /// Schedule background DNSSEC validation for a cache entry populated by
    /// a CD=1 query. The original response shipped to the client with AD=0
    /// and the RRset is cached as .unchecked; background validation
    /// promotes it to .secure (benefiting subsequent CD=0 lookups) or
    /// invalidates on BOGUS. Silently drops on cap/spawn failure — the only
    /// loss is missed cache warming, never an incorrect response.
    fn scheduleCd1Revalidate(self: *WorkerState, name: []const u8, qtype: dns.RType) void {
        if (!self.server.config.dnssec) return;
        if (self.server.cache.hasValidatedPositive(name, qtype, .in)) return;
        _ = self.server.trySpawnBgPrefetch(name, qtype, .revalidate);
    }

    fn resolveWithDedupUsing(
        self: *WorkerState,
        alloc: mem.Allocator,
        name: []const u8,
        qtype: dns.RType,
        cd: bool,
        transports: Transports,
    ) !recursive.RecursiveResolver.ResolveResult {
        _ = self.pool.busy.fetchAdd(1, .monotonic);
        defer _ = self.pool.busy.fetchSub(1, .monotonic);
        // Dedup only prevents duplicate upstream queries. On a cache hit no
        // upstream I/O happens, so the InFlightTable mutex pair is pure
        // overhead; a shared-lock existence probe skips it. On miss we fall
        // through to the normal dedup + resolve path.
        if (self.server.cache.containsFresh(name, qtype, .in)) {
            return self.resolveQueryWith(alloc, name, qtype, cd, false, transports);
        }

        const cd_flag: u8 = @intFromBool(cd);
        var is_leader = true;
        if (self.server.dedup) |*dedup| {
            switch (dedup.acquireOrWait(name, qtype, cd_flag)) {
                .leader => {},
                .follower => {
                    is_leader = false;
                },
            }
        }
        errdefer if (is_leader) {
            if (self.server.dedup) |*dedup| dedup.releaseLeader(name, qtype, cd_flag);
        };
        var result = try self.resolveQueryWith(alloc, name, qtype, cd, false, transports);
        if (is_leader) {
            if (self.server.dedup) |*dedup| dedup.releaseLeader(name, qtype, cd_flag);
        } else {
            // A follower's own resolve is a cache hit by construction (the
            // leader populated it), but the client still waited on the
            // leader's upstream round-trip — that's a miss experientially.
            result.from_cache = false;
        }
        return result;
    }
};

// ── TCP helpers (blocking I/O) ─────────────────────────────────────────

fn tcpWriteAllBlocking(io: Io, fd: posix.fd_t, data: []const u8, deadline_ns: i128) ?void {
    sys.writeAllDeadline(io, fd, data, deadline_ns) catch |err| {
        if (err != error.Closed) log.debug("tcp client write: {s}", .{@errorName(err)});
        return null;
    };
}

fn tcpWriteMessage(io: Io, fd: posix.fd_t, data: []const u8, deadline_ns: i128) ?void {
    var len_prefix: [2]u8 = undefined;
    mem.writeInt(u16, &len_prefix, @intCast(data.len), .big);
    tcpWriteAllBlocking(io, fd, &len_prefix, deadline_ns) orelse return null;
    tcpWriteAllBlocking(io, fd, data, deadline_ns) orelse return null;
}

// ── Helpers ────────────────────────────────────────────────────────────

fn ctxIndex(ctxs: *const [max_listen_addrs]Ctx, n: usize, target: *const Ctx) ?usize {
    for (0..n) |i| {
        if (&ctxs[i] == target) return i;
    }
    return null;
}

fn logCounterIfNonzero(name: []const u8, value: u64) void {
    if (value > 0) log.info("{s}: {d}", .{ name, value });
}

fn isNonLoopback(a: na.Address) bool {
    switch (a) {
        .ip4 => |v4| return v4.bytes[0] != 127,
        .ip6 => |v6| {
            const loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
            return !mem.eql(u8, &v6.bytes, &loopback);
        },
    }
}

// ── Socket creation ────────────────────────────────────────────────────

fn createSocket(addr: na.Address, sock_type: u32, reuseport: bool, listen_flag: bool) !posix.fd_t {
    const af = na.afU32(addr);
    const sock = try sys.socket(af, sock_type | posix.SOCK.NONBLOCK, 0);
    errdefer sys.close(sock);

    if (af == posix.AF.INET6) {
        // V6ONLY=1 keeps v4 and v6 listeners on disjoint socket families.
        // The ACL in `acl.zig` is family-strict (a v4 CIDR will not match a
        // v4-mapped-v6 peer); without V6ONLY a v6 socket would deliver
        // ::ffff:0:0/96-mapped peers and silently bypass v4 allow rules.
        const v6only: c_int = 1;
        try posix.setsockopt(sock, posix.SOL.IPV6, linux.IPV6.V6ONLY, &mem.toBytes(v6only));
    }
    const optval: c_int = 1;
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(optval));
    if (reuseport) {
        try posix.setsockopt(sock, posix.SOL.SOCKET, linux.SO.REUSEPORT, &mem.toBytes(optval));
    }
    if (sock_type & posix.SOCK.DGRAM != 0) {
        const bufsize: c_int = 1024 * 1024;
        posix.setsockopt(sock, posix.SOL.SOCKET, linux.SO.RCVBUF, &mem.toBytes(bufsize)) catch {};
        posix.setsockopt(sock, posix.SOL.SOCKET, linux.SO.SNDBUF, &mem.toBytes(bufsize)) catch {};
    }
    try na.bindTo(sock, &addr);
    if (listen_flag) {
        try sys.listen(sock, 128);
    }

    return sock;
}

fn setupSignalFd() !posix.fd_t {
    // Mask size is load-bearing: standard signals coalesce to one pending
    // signalfd_siginfo per signo, so event_loop.zig sizes its read buffer
    // (`read_buf_size`) to hold exactly this many records. Adding a signo
    // here only delays the excess record by one re-arm cycle, but keep the
    // two in step anyway.
    var mask = linux.sigemptyset();
    linux.sigaddset(&mask, linux.SIG.INT);
    linux.sigaddset(&mask, linux.SIG.TERM);
    linux.sigaddset(&mask, linux.SIG.HUP);
    linux.sigaddset(&mask, linux.SIG.USR1);

    // Create the reader before blocking, not after. Blocking first and then
    // failing here would leave the process with INT/TERM blocked and nothing
    // reading them — unkillable except by SIGKILL, for its whole life.
    const fd = try sys.signalfd(-1, &mask, linux.SFD.NONBLOCK);
    _ = linux.sigprocmask(linux.SIG.BLOCK, &mask, null);
    return fd;
}

/// `.ignore` is the default for anything unrecognised: only a TERM or INT
/// record actually present in the buffer may stop the process. Treating an
/// unexpected read as a shutdown request killed the daemon on a spurious
/// wake, an errored read, or a signo outside `setupSignalFd`'s mask — the
/// same family as the eventfd/slot-aliasing bug ReadResult's doc comment
/// describes.
const SignalAction = enum { stats, shutdown, ignore };

/// Walk every signalfd_siginfo record in the buffer (the kernel can pack
/// many into one read). Shutdown signals win over stats.
fn classifySignalRead(result: anytype) SignalAction {
    const siginfo_size = @sizeOf(linux.signalfd_siginfo);
    const r = switch (result) {
        .read => |x| x,
        else => return .ignore,
    };
    // Covers the zero-length read too: reap maps `cqe.res == 0` to EndOfFile.
    if (r.err != null) return .ignore;

    const bytes = r.data();
    var saw_stats = false;
    var off: usize = 0;
    while (off + 4 <= bytes.len) : (off += siginfo_size) {
        const signo = std.mem.readInt(u32, bytes[off..][0..4], .little);
        if (signo == @backingInt(linux.SIG.TERM) or signo == @backingInt(linux.SIG.INT)) {
            return .shutdown;
        }
        if (signo == @backingInt(linux.SIG.USR1) or signo == @backingInt(linux.SIG.HUP)) {
            saw_stats = true;
        }
    }
    return if (saw_stats) .stats else .ignore;
}

/// Drop credentials for the calling thread only (raw syscall; without libc
/// there is no SIGSETXID broadcast), so it runs once on main before any
/// thread exists — threads inherit.
///
/// Scope: clears supplementary groups, sets r/e/s gid and r/e/s uid. On
/// euid 0 → non-zero the kernel auto-drops the permitted cap set. NOT
/// covered: ambient capabilities and the bounding set. Operators wanting
/// full credential hygiene should prefer systemd User= /
/// CapabilityBoundingSet= over this in-process drop.
fn dropPrivileges(gid: ?u32, uid: ?u32) !void {
    // Clear supplementary groups while we still have CAP_SETGID. Without
    // this, a process launched as root inherits root's groups (wheel, adm,
    // disk, …) and keeps them after the uid drop. Skip when not root:
    // setgroups would EPERM and there's nothing to clear anyway.
    if (linux.geteuid() == 0) {
        const rc = if (@hasField(linux.SYS, "setgroups32"))
            linux.syscall2(.setgroups32, 0, 0)
        else
            linux.syscall2(.setgroups, 0, 0);
        if (@as(isize, @bitCast(rc)) != 0) return error.SetGroupsFailed;
    }
    // Drop group first so setgid still has CAP_SETGID. Once setuid runs,
    // the thread loses CAP_SETGID along with the rest of root's caps.
    if (gid) |g| {
        const rc = linux.setresgid(g, g, g);
        if (rc != 0) return error.SetGidFailed;
    }
    if (uid) |u| {
        const rc = linux.setresuid(u, u, u);
        if (rc != 0) return error.SetUidFailed;
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

test "server init and deinit" {
    const config = @import("config.zig");
    var cfg = config.parseConfig(testing.allocator, "") catch return error.SkipZigTest;
    defer cfg.deinit();

    var server = try Server.init(testing.allocator, cfg, testing.io);
    defer server.deinit();
}

test "parseMessage rejects multiple OPT records (RFC 6891 §6.1.1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Build a query, then manually append a second OPT to additionals.
    var query = try dns.buildQuery(arena.allocator(), 0, "example.com", .a, .{});
    query.opt = .{
        .udp_payload_size = 4096,
        .extended_rcode = 0,
        .version = 0,
        .do_bit = false,
        .options = &.{},
    };
    // Inject a second OPT as a raw additional. dns.serializeMessage emits the
    // first via msg.opt; we hand-craft an extra OPT at the end of the wire.
    var buf: [dns.max_udp_payload]u8 = undefined;
    const base = try dns.serializeMessage(&buf, query);
    // Bump ar_count by 1 in the header (offset 10, big-endian u16).
    const ar_count_before = std.mem.readInt(u16, buf[10..12], .big);
    std.mem.writeInt(u16, buf[10..12], ar_count_before + 1, .big);
    // Append a minimal OPT: root name (0), type=41, class=4096, ttl=0, rdlen=0.
    const extra: [11]u8 = .{ 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0 };
    const extended_len = base.len + extra.len;
    @memcpy(buf[base.len..extended_len], &extra);

    try testing.expectError(error.MultipleOptRecords, dns.parseMessage(arena.allocator(), buf[0..extended_len]));
}

test "createSocket UDP binds to ephemeral port" {
    const addr = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    const sock = createSocket(addr, posix.SOCK.DGRAM, false, false) catch return error.SkipZigTest;
    defer sys.close(sock);

    try testing.expect((try na.getSockName(sock)).getPort() > 0);
}

test "createSocket TCP binds and listens" {
    const addr = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    const sock = createSocket(addr, posix.SOCK.STREAM, false, true) catch return error.SkipZigTest;
    defer sys.close(sock);

    try testing.expect((try na.getSockName(sock)).getPort() > 0);
}

test "createSocket UDP reuseport allows multiple binds" {
    const addr = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    const sock1 = createSocket(addr, posix.SOCK.DGRAM, true, false) catch return error.SkipZigTest;
    defer sys.close(sock1);

    // Get the actual port
    const port = (try na.getSockName(sock1)).getPort();

    // Second socket on same port should succeed with SO_REUSEPORT
    const addr2 = na.initIp4(.{ 127, 0, 0, 1 }, port);
    const sock2 = createSocket(addr2, posix.SOCK.DGRAM, true, false) catch return error.SkipZigTest;
    defer sys.close(sock2);
}

test "AD bit cleared on unvalidated (.unchecked) cache hit" {
    // RFC 6840 §5.9 / RFC 4035 §3.2.2: AD MUST NOT be set unless the
    // resolver verified. A cache entry stored as .unchecked (e.g. by the
    // CD=1 early-serve path before background validation upgrades it)
    // must not produce AD=1 responses to CD=0 clients.

    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = try a.alloc(dns.Question, 1);
    questions[0] = .{ .name = try dns.parseDottedName(a, "example.com"), .qtype = .a, .qclass = .in };

    // Simulate a cached-and-returned message where the resolver did NOT
    // set ad=true (because security_status was .unchecked at lookup time —
    // recursive.zig sets `ad = security_status == .secure`).
    const response_unchecked = dns.Message{
        .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = false, .ra = true, .z = 0, .ad = false, .cd = false, .rcode = .no_error }, .qd_count = 0, .an_count = 0, .ns_count = 0, .ar_count = 0 },
        .questions = &.{},
    };

    var buf: [dns.edns_udp_payload]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 1,
        .opcode = .query,
        .rd = true,
        .cd = false, // CD=0 client — asking us to validate
        .questions = questions,
        .client_edns = true,
        .client_do = true, // DO=1 → client_wants_ad via fromQuery; exercise the AD-strip path
        .client_wants_ad = true,
        .max_udp_payload = dns.edns_udp_payload,
    }, response_unchecked, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(false, parsed.header.flags.ad);

    // Same message with validation-proven security_status=.secure would have
    // response.header.flags.ad == true upstream of buildResponseWire; confirm the
    // path then emits AD=1.
    const response_secure = dns.Message{
        .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = false, .ra = true, .z = 0, .ad = true, .cd = false, .rcode = .no_error }, .qd_count = 0, .an_count = 0, .ns_count = 0, .ar_count = 0 },
        .questions = &.{},
    };
    var buf2: [dns.edns_udp_payload]u8 = undefined;
    const wire2 = buildResponseWire(&buf2, .{
        .query_id = 2,
        .opcode = .query,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = true,
        .client_do = true,
        .client_wants_ad = true,
        .max_udp_payload = dns.edns_udp_payload,
    }, response_secure, a).?;
    const parsed2 = try dns.parseMessage(a, wire2);
    try testing.expectEqual(true, parsed2.header.flags.ad);
}

test "hasValidatedPositive returns true only for non-.unchecked entries" {
    // Guards the predicate that scheduleCd1Revalidate uses to short-circuit
    // repeated CD=1 queries to an already-validated name. A steady CD=1
    // workload would otherwise pay a bg spawn + upstream round-trip per
    // query even after the cache entry is .secure.
    const config = @import("config.zig");
    var cfg = config.parseConfig(testing.allocator,
        \\[server]
        \\dnssec = true
    ) catch return error.SkipZigTest;
    defer cfg.deinit();

    var server = try Server.init(testing.allocator, cfg, testing.io);
    defer server.deinit();

    // Before any cached entry: hasValidatedPositive is false; bg scheduler
    // would spawn (we don't actually spawn here — just exercise the check).
    try testing.expect(!server.cache.hasValidatedPositive("example.com", .a, .in));

    // Populate cache with a .secure answer (simulates a prior CD=0 resolve
    // or a completed bg revalidation).
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const name = try dns.parseDottedName(a, "example.com");
    const answers = try a.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
    const resp = dns.Message{
        .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = true, .tc = false, .rd = false, .ra = false, .z = 0, .ad = false, .cd = false, .rcode = .no_error }, .qd_count = 0, .an_count = 1, .ns_count = 0, .ar_count = 0 },
        .questions = &.{},
        .answers = answers,
    };
    server.cache.storeResponse(resp, dns.Name{ .labels = &.{} }, .secure, std.math.maxInt(u32));

    try testing.expect(server.cache.hasValidatedPositive("example.com", .a, .in));
    // .unchecked entries are NOT protected — bg scheduler should still fire.
    try testing.expect(!server.cache.hasValidatedPositive("unknown.com", .a, .in));
}

test "trySpawnBgPrefetch rejects oversize and empty names" {
    // Input validation before the expensive heap+spawn path. Protects against
    // a malformed name slipping through and the thread getting a truncated
    // or empty buffer.
    const config = @import("config.zig");
    var cfg = config.parseConfig(testing.allocator, "") catch return error.SkipZigTest;
    defer cfg.deinit();

    var server = try Server.init(testing.allocator, cfg, testing.io);
    defer server.deinit();

    try testing.expect(!server.trySpawnBgPrefetch("", .a, .prefetch));
    var too_long: [dns.max_name_len + 2]u8 = undefined;
    @memset(&too_long, 'a');
    try testing.expect(!server.trySpawnBgPrefetch(&too_long, .a, .prefetch));
    try testing.expectEqual(@as(u32, 0), server.bg_tasks.inFlight());
}

test "bg failure recording: cousin writes SERVFAIL, refresh kinds do not, fresh entries survive" {
    const config = @import("config.zig");
    var cfg = config.parseConfig(testing.allocator, "") catch return error.SkipZigTest;
    defer cfg.deinit();

    var server = try Server.init(testing.allocator, cfg, testing.io);
    defer server.deinit();
    var udp = BlockingUdpTransport.init(.{}, server.io);
    defer udp.deinit();
    const transports: Transports = .{ .udp = &udp, .tcp_enabled = true };
    const run = struct {
        fn f(srv: *Server, t: Transports, name: []const u8, kind: BgKind) void {
            runBgTask(srv.resolverContext(), t, testing.failing_allocator, name, .aaaa, kind);
        }
    }.f;

    // Cousin failure on an absent key → RFC 9520 SERVFAIL marker.
    run(&server, transports, "brk.example.com", .cousin);
    {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const r = server.cache.lookup(arena.allocator(), "brk.example.com", .aaaa, .in) orelse return error.TestUnexpectedResult;
        switch (r) {
            .negative => |n| try testing.expectEqual(dns.RCode.server_failure, n.rcode),
            .hit => return error.TestUnexpectedResult,
        }
    }

    // Same failure under a refresh kind → nothing recorded.
    run(&server, transports, "brk2.example.com", .prefetch);
    try testing.expect(!server.cache.containsFresh("brk2.example.com", .aaaa, .in));

    // Cousin failure with a fresh entry present → guard keeps the entry.
    {
        var store_arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer store_arena.deinit();
        const sa = store_arena.allocator();
        const owner = try dns.parseDottedName(sa, "fresh.example.com");
        const rrs = try sa.alloc(dns.ResourceRecord, 1);
        rrs[0] = .{ .name = owner, .rtype = .aaaa, .rclass = .in, .ttl = 300, .rdata = .{ .aaaa = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
        const msg = dns.Message{
            .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = true, .tc = false, .rd = false, .ra = false, .z = 0, .ad = false, .cd = false, .rcode = .no_error }, .qd_count = 0, .an_count = 1, .ns_count = 0, .ar_count = 0 },
            .questions = &.{},
            .answers = rrs,
        };
        server.cache.storeResponse(msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    }
    run(&server, transports, "fresh.example.com", .cousin);
    {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const r = server.cache.lookup(arena.allocator(), "fresh.example.com", .aaaa, .in) orelse return error.TestUnexpectedResult;
        switch (r) {
            .hit => {},
            .negative => return error.TestUnexpectedResult,
        }
    }
}

// ── HotSet unit tests ──────────────────────────────────────────────────

const HotSetStubCache = struct {
    expiry: ?i64,
    pub fn entryExpiry(self: *@This(), name: []const u8, rtype: dns.RType, rclass: dns.RClass) ?i64 {
        _ = name;
        _ = rtype;
        _ = rclass;
        return self.expiry;
    }
};

const HotSetFireLog = struct {
    count: usize = 0,
    pub fn fire(self: *@This(), name: []const u8, qtype: dns.RType) void {
        _ = name;
        _ = qtype;
        self.count += 1;
    }
};

test "HotSet promotes after two remiss events, not one" {
    var hs: HotSet = undefined;
    hs.init(testing.io);
    const tag = HotSet.keyTag("cdn.example.com", .a);

    hs.onRemiss("cdn.example.com", .a, 1000);
    try testing.expect(hs.findSlotLocked(tag) == null);

    hs.onRemiss("cdn.example.com", .a, 1010);
    const slot = hs.findSlotLocked(tag) orelse return error.TestExpectedPromotion;
    try testing.expectEqualStrings("cdn.example.com", slot.name_buf[0..slot.name_len]);
    try testing.expectEqual(dns.RType.a, slot.qtype);
    try testing.expectEqual(@as(u64, 1), hs.promotions.load(.monotonic));
}

test "HotSet stale candidate does not accumulate across the window" {
    var hs: HotSet = undefined;
    hs.init(testing.io);
    const tag = HotSet.keyTag("slow.example.com", .aaaa);

    hs.onRemiss("slow.example.com", .aaaa, 1000);
    // Second event past the candidate window restarts the count.
    hs.onRemiss("slow.example.com", .aaaa, 1000 + HotSet.candidate_window + 1);
    try testing.expect(hs.findSlotLocked(tag) == null);
}

test "HotSet tick: healthy entry waits, in-window entry fires, dead entry backs off" {
    var hs: HotSet = undefined;
    hs.init(testing.io);
    hs.onRemiss("hot.example.com", .a, 1000);
    hs.onRemiss("hot.example.com", .a, 1010);
    const tag = HotSet.keyTag("hot.example.com", .a);

    var fires = HotSetFireLog{};

    // Fresh and young: no fire, next_check parked at expiry - lead.
    var cache = HotSetStubCache{ .expiry = 1300 };
    hs.tick(1011, &cache, &fires);
    try testing.expectEqual(@as(usize, 0), fires.count);
    try testing.expectEqual(@as(i64, 1300 - HotSet.fire_lead), hs.findSlotLocked(tag).?.next_check);

    // In the fire window (expiry - now <= lead, still alive): refresh.
    hs.tick(1299, &cache, &fires);
    try testing.expectEqual(@as(usize, 1), fires.count);

    // Dead and lingering: fires again, backoff shift grows.
    cache.expiry = 1200; // past
    hs.tick(1305, &cache, &fires);
    try testing.expectEqual(@as(usize, 2), fires.count);
    try testing.expectEqual(@as(u6, 1), hs.findSlotLocked(tag).?.fail_shift);

    // Recovery: fresh entry resets the backoff.
    cache.expiry = 1700;
    hs.tick(1320, &cache, &fires);
    try testing.expectEqual(@as(u6, 0), hs.findSlotLocked(tag).?.fail_shift);
}

test "HotSet lease lapses silently and slot frees" {
    var hs: HotSet = undefined;
    hs.init(testing.io);
    hs.onRemiss("gone.example.com", .a, 1000);
    hs.onRemiss("gone.example.com", .a, 1010);
    const tag = HotSet.keyTag("gone.example.com", .a);
    try testing.expect(hs.findSlotLocked(tag) != null);

    var fires = HotSetFireLog{};
    var cache = HotSetStubCache{ .expiry = null };
    hs.tick(1010 + HotSet.lease_secs + 1, &cache, &fires);
    try testing.expect(hs.findSlotLocked(tag) == null);
    try testing.expectEqual(@as(usize, 0), fires.count);
}

test "HotSet remiss on a leased name renews the lease" {
    var hs: HotSet = undefined;
    hs.init(testing.io);
    hs.onRemiss("busy.example.com", .a, 1000);
    hs.onRemiss("busy.example.com", .a, 1010);
    const tag = HotSet.keyTag("busy.example.com", .a);
    const first_lease = hs.findSlotLocked(tag).?.lease_until;

    hs.onRemiss("busy.example.com", .a, 2000);
    try testing.expectEqual(@as(i64, 2000 + HotSet.lease_secs), hs.findSlotLocked(tag).?.lease_until);
    try testing.expect(hs.findSlotLocked(tag).?.lease_until > first_lease);
    // Renewal must not consume a registry slot or count as a promotion.
    try testing.expectEqual(@as(u64, 1), hs.promotions.load(.monotonic));
}

// ── classifySignalRead ─────────────────────────────────────────────────

const ELResult = @import("event_loop.zig").Result;
const ELReadResult = @import("event_loop.zig").ReadResult;

fn signalReadOf(signos: []const u32) ELResult {
    var r = ELReadResult{ .buf = @splat(0), .len = 0, .err = null };
    const stride = @sizeOf(linux.signalfd_siginfo);
    for (signos, 0..) |s, i| {
        std.mem.writeInt(u32, r.buf[i * stride ..][0..4], s, .little);
    }
    r.len = signos.len * stride;
    return .{ .read = r };
}

test "classifySignalRead: only a real TERM/INT record may stop the process" {
    const term: u32 = @backingInt(linux.SIG.TERM);
    const int: u32 = @backingInt(linux.SIG.INT);
    const usr1: u32 = @backingInt(linux.SIG.USR1);
    const hup: u32 = @backingInt(linux.SIG.HUP);

    try testing.expectEqual(SignalAction.shutdown, classifySignalRead(signalReadOf(&.{term})));
    try testing.expectEqual(SignalAction.shutdown, classifySignalRead(signalReadOf(&.{int})));
    try testing.expectEqual(SignalAction.stats, classifySignalRead(signalReadOf(&.{usr1})));
    try testing.expectEqual(SignalAction.stats, classifySignalRead(signalReadOf(&.{hup})));

    // Shutdown still wins when packed alongside stats, in either order.
    try testing.expectEqual(SignalAction.shutdown, classifySignalRead(signalReadOf(&.{ usr1, term })));
    try testing.expectEqual(SignalAction.shutdown, classifySignalRead(signalReadOf(&.{ term, usr1 })));
}

test "classifySignalRead: an unreadable or unrecognised completion is ignored, not a shutdown" {
    // Regression: every one of these returned .shutdown and the caller
    // exited the process.

    // Zero-length read. reap maps cqe.res == 0 to EndOfFile, so this is
    // covered by the err check, but pin the payload shape too.
    try testing.expectEqual(SignalAction.ignore, classifySignalRead(signalReadOf(&.{})));

    // Errored read (EAGAIN on a NONBLOCK fd, a spurious wake, EOF).
    var errored = ELReadResult{ .buf = @splat(0), .len = 0, .err = error.ReadFailed };
    try testing.expectEqual(SignalAction.ignore, classifySignalRead(ELResult{ .read = errored }));
    errored.err = error.EndOfFile;
    try testing.expectEqual(SignalAction.ignore, classifySignalRead(ELResult{ .read = errored }));

    // A signo outside setupSignalFd's mask.
    try testing.expectEqual(SignalAction.ignore, classifySignalRead(signalReadOf(&.{@backingInt(linux.SIG.CHLD)})));

    // A completion that is not a read at all.
    const not_a_read = ELResult{ .accept = .{ .fd = -1, .addr = na.initIp4(.{ 0, 0, 0, 0 }, 0), .err = error.AcceptFailed } };
    try testing.expectEqual(SignalAction.ignore, classifySignalRead(not_a_read));
}

test "Server.init does not leak when a late allocation fails" {
    // Regression: the HotSet allocation sat inside the return literal, which
    // Zig evaluates in field order — after every cache, with no errdefer in
    // reach.
    const config = @import("config.zig");
    var cfg = config.parseConfig(testing.allocator,
        \\[cache]
        \\prefetch-hot = true
    ) catch return error.SkipZigTest;
    defer cfg.deinit();

    var counter = std.testing.FailingAllocator.init(testing.allocator, .{});
    {
        var s = try Server.init(counter.allocator(), cfg, testing.io);
        s.deinit();
    }
    const total = counter.alloc_index;
    try testing.expect(total > 0);

    var idx: usize = 0;
    while (idx < total) : (idx += 1) {
        var f = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = idx });
        if (Server.init(f.allocator(), cfg, testing.io)) |srv| {
            var s = srv;
            s.deinit();
        } else |err| {
            if (err != error.OutOfMemory) return err;
        }
        try testing.expectEqual(f.allocated_bytes, f.freed_bytes);
    }
}
