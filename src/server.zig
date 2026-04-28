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
const OperationId = @import("event_loop.zig").OperationId;
const recursive = @import("recursive.zig");
const RecursiveResolver = recursive.RecursiveResolver;
const ForwardingResolver = @import("resolver.zig").ForwardingResolver;
const TlsTransport = @import("tls_transport.zig").TlsTransport;
const EncryptedNsCache = @import("encrypted_ns.zig").EncryptedNsCache;
const pool_mod = @import("connection_pool.zig");
const ConnectionPool = pool_mod.ConnectionPool(pool_mod.PooledConnection);
const RttCache = @import("ns_rtt.zig").RttCache;
const NsSelector = @import("ns_selector.zig").NsSelector;
const cache_mod = @import("cache.zig");
const RRsetCache = cache_mod.RRsetCache;
const dedup_mod = @import("dedup.zig");
const InFlightTable = dedup_mod.InFlightTable;
const NsecCache = @import("nsec_cache.zig").NsecCache;
const CountingAllocator = @import("counting_allocator.zig").CountingAllocator;
const ServerConfig = @import("config.zig").ServerConfig;
const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const BlockingTcpTransport = @import("blocking_transport.zig").BlockingTcpTransport;
const TcpConnectionPool = @import("connection_pool.zig").TcpConnectionPool;
const transport_mod = @import("transport.zig");
const Transports = transport_mod.Transports;
const Certificate = std.crypto.Certificate;
const na = @import("net_address.zig");
const sys = @import("sys.zig");
const monotonic = @import("monotonic.zig");

const log = std.log.scoped(.server);

const tcp_idle_timeout_ns: i128 = 5_000 * std.time.ns_per_ms;
const max_tcp_queries_per_conn: u32 = 128;

const work_queue_capacity = 256;

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

const WorkItem = struct {
    query_buf: [4096]u8 = undefined,
    query_len: u16 = 0,
    client_addr: na.Address = na.initIp4(.{ 0, 0, 0, 0 }, 0),
    sock_fd: posix.fd_t = -1,
    protocol: Protocol = .udp,
    const Protocol = enum { udp, tcp };
};

const WorkQueue = struct {
    items: [work_queue_capacity]WorkItem = undefined,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    mutex: Io.Mutex = Io.Mutex.init,
    not_empty: Io.Condition = Io.Condition.init,
    io: Io,
    shutdown: bool = false,

    fn push(self: *WorkQueue, data: []const u8, client_addr: na.Address, sock_fd: posix.fd_t, protocol: WorkItem.Protocol) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.count >= work_queue_capacity) return false;
        if (data.len > 4096) return false;
        const item = &self.items[self.tail];
        @memcpy(item.query_buf[0..data.len], data);
        item.query_len = @intCast(data.len);
        item.client_addr = client_addr;
        item.sock_fd = sock_fd;
        item.protocol = protocol;
        self.tail = (self.tail + 1) % work_queue_capacity;
        self.count += 1;
        self.not_empty.signal(self.io);
        return true;
    }

    fn pop(self: *WorkQueue) ?WorkItem {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.count == 0 and !self.shutdown) {
            self.not_empty.waitUncancelable(self.io, &self.mutex);
        }
        if (self.count == 0) return null;
        const item = self.items[self.head];
        self.head = (self.head + 1) % work_queue_capacity;
        self.count -= 1;
        return item;
    }

    fn signalShutdown(self: *WorkQueue) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.shutdown = true;
        self.not_empty.broadcast(self.io);
    }
};

// ── Context tags for the event loop ────────────────────────────────────

const CtxTag = enum { udp_recv, tcp_accept, signal };

const Ctx = struct {
    tag: CtxTag,
    fd: posix.fd_t,
};

const max_listen_addrs = 8;

// ── Background task bookkeeping ────────────────────────────────────────

/// Cap concurrent background tasks (prefetch + CD=1 validation). Mirrors
/// the pattern in encrypted_ns.EncryptedNsCache / tls_transport.probeInBackground:
/// spawn detached threads with a CAS-loop cap, poll to drain on shutdown.
/// Conservative cap — DNSSEC cold-cache bursts can otherwise deadlock on
/// over-fanout.
const max_bg_tasks: u32 = 16;

/// Dedup flag value for background CD=1 revalidation tasks. Distinct
/// from CD=0 (flag=0) and CD=1-client (flag=1) so a client-facing query
/// and a background revalidation of the same (name, qtype) don't coalesce.
const bg_revalidate_flag: u8 = 2;

const BackgroundTasks = struct {
    active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Reserve a slot for a new background thread. Returns false when the
    /// cap is hit or we're shutting down — caller must fall back (run inline
    /// or drop), never block here.
    fn tryClaim(self: *BackgroundTasks) bool {
        if (self.shutting_down.load(.acquire)) return false;
        while (true) {
            const cur = self.active.load(.monotonic);
            if (cur >= max_bg_tasks) return false;
            if (self.active.cmpxchgStrong(cur, cur + 1, .monotonic, .monotonic) == null) return true;
        }
    }

    fn release(self: *BackgroundTasks) void {
        _ = self.active.fetchSub(1, .release);
    }

    fn inFlight(self: *const BackgroundTasks) u32 {
        return self.active.load(.acquire);
    }

    /// Block until all in-flight background threads finish. Called from
    /// Server.deinit so caches/config outlive the threads that read them.
    fn awaitAll(self: *BackgroundTasks) void {
        self.shutting_down.store(true, .release);
        while (self.inFlight() > 0) {
            const ts = std.os.linux.timespec{ .sec = 0, .nsec = 1_000_000 };
            _ = std.os.linux.nanosleep(&ts, null); // 1ms
        }
    }
};

// ── Server ─────────────────────────────────────────────────────────────

pub const Server = struct {
    config: ServerConfig,
    allocator: mem.Allocator,
    io: Io,
    cache: RRsetCache,
    rtt_cache: RttCache,
    ns_selector: NsSelector,
    dedup: ?InFlightTable,
    ca_bundle: Certificate.Bundle,
    encrypted_ns_cache: ?EncryptedNsCache,
    enc_pool: ?ConnectionPool,
    nsec_cache: ?NsecCache,
    key_cache: ?RRsetCache,
    shutdown: std.atomic.Value(bool),
    worker_errors: std.atomic.Value(u32),
    udp_queue_drops: std.atomic.Value(u64),
    tcp_queue_drops: std.atomic.Value(u64),
    udp_send_drops: std.atomic.Value(u64),
    bg_tasks: BackgroundTasks = .{},

    pub fn init(allocator: mem.Allocator, cfg: ServerConfig, io: Io) !Server {
        // Randomize hash seeds for cache and dedup tables (hash collision attack defense).
        cache_mod.randomizeHashSeed(io);
        dedup_mod.randomizeHashSeed(io);

        const cache_alloc = if (builtin.single_threaded)
            allocator
        else
            std.heap.smp_allocator;
        const cache = RRsetCache.init(.{
            .backing = cache_alloc,
            .max_bytes = cfg.cache_size,
            .max_entries = cfg.cache_entries,
            .io = io,
            .thread_safe = cfg.workers > 1,
            .prefetch = cfg.prefetch,
            .serve_stale_ttl = cfg.serve_stale_ttl,
            .min_ttl = cfg.min_ttl,
            .skip_key_types = cfg.dnssec,
        });

        const rtt_cache = RttCache.init(.{
            .allocator = allocator,
            .io = io,
            .thread_safe = cfg.workers > 1,
        });

        const ns_selector = NsSelector.init(.{
            .allocator = allocator,
            .io = io,
            .thread_safe = cfg.workers > 1,
        });

        var ca_bundle: Certificate.Bundle = .empty;
        if (cfg.opportunistic) {
            ca_bundle.rescan(allocator, io, Io.Timestamp.now(io, .real)) catch |err| {
                log.err("failed to load CA certificates: {s}", .{@errorName(err)});
                return err;
            };
        }

        return .{
            .config = cfg,
            .allocator = allocator,
            .io = io,
            .cache = cache,
            .rtt_cache = rtt_cache,
            .ns_selector = ns_selector,
            .dedup = if (cfg.workers > 1) InFlightTable.init(allocator, io) else null,
            .ca_bundle = ca_bundle,
            .encrypted_ns_cache = if (cfg.opportunistic) EncryptedNsCache.init(allocator, io) else null,
            .enc_pool = if (cfg.opportunistic) ConnectionPool.init(allocator, io) else null,
            .nsec_cache = if (cfg.dnssec) NsecCache.init(.{
                .backing = if (builtin.single_threaded) allocator else std.heap.smp_allocator,
                .max_bytes = NsecCache.default_max_bytes,
                .io = io,
                .thread_safe = cfg.workers > 1,
            }) else null,
            .key_cache = if (cfg.dnssec) RRsetCache.init(.{
                .backing = cache_alloc,
                .max_bytes = cfg.key_cache_size,
                .max_entries = cfg.key_cache_entries,
                .io = io,
                .thread_safe = cfg.workers > 1,
            }) else null,
            .shutdown = std.atomic.Value(bool).init(false),
            .worker_errors = std.atomic.Value(u32).init(0),
            .udp_queue_drops = std.atomic.Value(u64).init(0),
            .tcp_queue_drops = std.atomic.Value(u64).init(0),
            .udp_send_drops = std.atomic.Value(u64).init(0),
        };
    }

    pub fn deinit(self: *Server) void {
        // Drain detached prefetch/revalidate threads before freeing the
        // caches/dedup/CA bundle they read.
        self.bg_tasks.awaitAll();
        if (self.encrypted_ns_cache) |*oc| {
            oc.awaitProbes();
            oc.deinit();
        }
        if (self.enc_pool) |*pool| pool.deinit();
        if (self.config.opportunistic) {
            self.ca_bundle.deinit(self.allocator);
        }
        if (self.dedup) |*d| d.deinit();
        if (self.nsec_cache) |*nc| nc.deinit();
        if (self.key_cache) |*kc| kc.deinit();
        self.cache.deinit();
        self.rtt_cache.deinit();
        self.ns_selector.deinit();
    }

    pub fn run(self: *Server) !void {
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
        defer if (sig_fd >= 0) sys.close(sig_fd);

        for (listen_addrs) |addr| {
            var addr_buf: [64]u8 = undefined;
            const addr_str = na.format(addr, &addr_buf);
            log.info("listening on {s} (UDP+TCP)", .{addr_str});
        }

        if (self.config.mode == .recursive) {
            for (listen_addrs) |addr| {
                if (isNonLoopback(addr)) {
                    log.warn("listening on a non-loopback address with recursion enabled — " ++
                        "this server is an open resolver; consider adding access controls", .{});
                    break;
                }
            }
        }

        if (workers <= 1) {
            // Single-threaded mode: use simple sockets (no SO_REUSEPORT)
            log.info("{d} worker", .{workers});
            self.runWorker(listen_addrs, sig_fd, false);
        } else {
            log.info("{d} workers", .{workers});

            // Spawn N-1 worker threads + run one on main thread
            const threads = self.allocator.alloc(std.Thread, workers - 1) catch |err| {
                log.err("failed to allocate thread array: {s}", .{@errorName(err)});
                return err;
            };
            defer self.allocator.free(threads);

            for (threads, 0..) |*t, i| {
                t.* = std.Thread.spawn(.{}, runWorker, .{ self, listen_addrs, @as(posix.fd_t, -1), true }) catch |err| {
                    log.err("failed to spawn worker {d}: {s}", .{ i + 1, @errorName(err) });
                    // Signal shutdown to already-spawned threads
                    self.shutdown.store(true, .release);
                    for (threads[0..i]) |prev| prev.join();
                    return err;
                };
            }

            // Main thread runs a worker too, with signalfd for shutdown
            self.runWorker(listen_addrs, sig_fd, true);

            // Join all worker threads
            for (threads) |t| t.join();
        }

        // Check for worker failures
        const failed = self.worker_errors.load(.monotonic);
        if (failed > 0) {
            log.warn("{d} worker(s) failed to initialize — running with degraded capacity", .{failed});
        }

        // Log cache stats on shutdown
        const stats = self.cache.getStats();
        const hit_total = stats.hits + stats.misses;
        const hit_pct: u64 = if (hit_total > 0) stats.hits * 100 / hit_total else 0;
        log.info("cache stats: {d} entries, {d} bytes, {d} hits, {d} misses ({d}% hit rate), {d} evictions ({d} cap-exhausted), {d} prefetch-eligible, {d} stale", .{
            stats.entries, stats.memory_bytes, stats.hits, stats.misses, hit_pct, stats.evictions, stats.cap_exhausted_evictions, stats.prefetch_eligible, stats.stale_hits,
        });
        if (self.key_cache) |*kc| {
            const ks = kc.getStats();
            const k_total = ks.hits + ks.misses;
            const k_pct: u64 = if (k_total > 0) ks.hits * 100 / k_total else 0;
            log.info("key cache: {d} entries, {d} bytes, {d} hits, {d} misses ({d}% hit rate)", .{
                ks.entries, ks.memory_bytes, ks.hits, ks.misses, k_pct,
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
        const udp_send_drops = self.udp_send_drops.load(.monotonic);
        if (udp_send_drops > 0) {
            log.info("UDP send-buffer drops: {d}", .{udp_send_drops});
        }
    }

    fn runWorker(self: *Server, listen_addrs: []const na.Address, sig_fd: posix.fd_t, reuseport: bool) void {
        // Per-thread EventLoop for server accept/recv
        const server_loop = EventLoop.create(self.allocator) catch |err| {
            log.err("worker failed to create event loop: {s}", .{@errorName(err)});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            return;
        };
        defer server_loop.destroy();

        // Per-thread server sockets — one UDP + one TCP per listen address
        var udp_socks: [max_listen_addrs]posix.fd_t = .{-1} ** max_listen_addrs;
        var tcp_socks: [max_listen_addrs]posix.fd_t = .{-1} ** max_listen_addrs;

        defer for (0..listen_addrs.len) |i| {
            if (udp_socks[i] >= 0) sys.close(udp_socks[i]);
            if (tcp_socks[i] >= 0) sys.close(tcp_socks[i]);
        };

        for (listen_addrs, 0..) |addr, i| {
            var addr_buf: [64]u8 = undefined;
            const addr_str = na.format(addr, &addr_buf);

            udp_socks[i] = createSocket(addr, posix.SOCK.DGRAM, reuseport, false) catch |err| {
                log.warn("failed to create UDP socket for {s}: {s}", .{ addr_str, @errorName(err) });
                continue;
            };

            tcp_socks[i] = createSocket(addr, posix.SOCK.STREAM, reuseport, true) catch |err| {
                log.warn("failed to create TCP socket for {s}: {s}", .{ addr_str, @errorName(err) });
                sys.close(udp_socks[i]);
                udp_socks[i] = -1;
                continue;
            };
        }

        // Check at least one address succeeded
        const any_ok = for (udp_socks[0..listen_addrs.len]) |s| {
            if (s >= 0) break true;
        } else false;
        if (!any_ok) {
            log.err("worker failed to bind any listen address", .{});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            return;
        }

        var queue = WorkQueue{ .io = self.io };

        // Per-worker Do53 TCP connection pool (RFC 7766)
        var do53_tcp_pool = TcpConnectionPool.init(self.allocator, self.io);
        defer do53_tcp_pool.deinit();

        // Worker state
        var ws = WorkerState{
            .server = self,
            .config = &self.config,
            .allocator = self.allocator,
            .io = self.io,
            .loop = server_loop,
            .enc_pool = if (self.enc_pool) |*pool| pool else null,
            .encrypted_ns_cache = if (self.encrypted_ns_cache) |*oc| oc else null,
            .cache = &self.cache,
            .key_cache = if (self.key_cache) |*kc| kc else null,
            .rtt_cache = &self.rtt_cache,
            .ns_selector = &self.ns_selector,
            .dedup = if (self.dedup) |*d| d else null,
            .nsec_cache = if (self.nsec_cache) |*nc| nc else null,
            .shutdown = &self.shutdown,
            .queue = &queue,
            .udp_queue_drops = &self.udp_queue_drops,
            .tcp_queue_drops = &self.tcp_queue_drops,
            .udp_send_drops = &self.udp_send_drops,
            .ca_bundle = self.ca_bundle,
            .tcp_pool = &do53_tcp_pool,
            .max_tcp_clients = @max(1, self.config.resolution_threads / 2),
        };

        const pool_size = self.config.resolution_threads;
        const pool_threads = self.allocator.alloc(std.Thread, pool_size) catch |err| {
            log.err("failed to allocate pool threads: {s}", .{@errorName(err)});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            return;
        };
        defer self.allocator.free(pool_threads);

        var spawned: usize = 0;
        for (pool_threads) |*pt| {
            pt.* = std.Thread.spawn(.{}, WorkerState.poolThread, .{&ws}) catch |err| {
                log.err("failed to spawn pool thread: {s}", .{@errorName(err)});
                break;
            };
            spawned += 1;
        }

        if (spawned == 0) {
            log.err("no pool threads spawned", .{});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            return;
        }

        ws.serveLoop(udp_socks[0..listen_addrs.len], tcp_socks[0..listen_addrs.len], sig_fd);

        queue.signalShutdown();
        for (pool_threads[0..spawned]) |pt| pt.join();

        // Drain detached DoT probe threads before the per-pool-thread
        // TlsTransport instances they captured go out of scope.
        if (self.encrypted_ns_cache) |*enc| enc.awaitProbes();
    }

    /// Attempt to hand off a prefetch or CD=1 revalidation to a detached
    /// background thread. Returns true if spawned; false means the caller
    /// should fall back (run inline or drop — caller's choice). The bg
    /// thread owns the heap-allocated context and releases the bg_tasks
    /// slot on exit.
    fn trySpawnBgPrefetch(self: *Server, name: []const u8, qtype: dns.RType, kind: BgKind) bool {
        if (name.len == 0 or name.len > dns.max_name_len + 1) return false;
        if (!self.bg_tasks.tryClaim()) return false;

        const ctx = self.allocator.create(BgPrefetchCtx) catch {
            self.bg_tasks.release();
            return false;
        };
        ctx.* = .{ .server = self, .qtype = qtype, .kind = kind, .name_len = @intCast(name.len) };
        @memcpy(ctx.name_buf[0..name.len], name);

        const thread = std.Thread.spawn(.{ .stack_size = 1 << 20 }, bgPrefetchThread, .{ctx}) catch {
            self.allocator.destroy(ctx);
            self.bg_tasks.release();
            return false;
        };
        thread.detach();
        return true;
    }
};

const BgKind = enum {
    /// Cache-refresh prefetch (near-expiry answer RRset or DNSKEY). Always
    /// runs with `bypass_cache=true` and dnssec_enabled mirrors config —
    /// semantically equivalent to a fresh CD=0 query.
    prefetch,
    /// CD=1 revalidation. Re-resolve with dnssec_enabled=true
    /// to upgrade the .unchecked cache entry to .secure (or invalidate on
    /// BOGUS). Runs with `bypass_cache=true` so validation actually fires
    /// — cache-hit on .unchecked records returns them without re-verifying,
    /// so we pay the upstream round-trip to get signed data for validation.
    revalidate,
};

const BgPrefetchCtx = struct {
    server: *Server,
    name_buf: [dns.max_name_len + 1]u8 = undefined,
    name_len: u8 = 0,
    qtype: dns.RType,
    kind: BgKind,
};

fn bgPrefetchThread(ctx: *BgPrefetchCtx) void {
    const server = ctx.server;
    defer server.allocator.destroy(ctx);
    defer server.bg_tasks.release();

    const name = ctx.name_buf[0..ctx.name_len];
    const qtype = ctx.qtype;

    // Coalesce bursts of near-expiry client queries that would otherwise
    // fan out into N upstream refreshes for the same (name, qtype, kind).
    const dedup_flag: u8 = switch (ctx.kind) {
        .prefetch => 0,
        .revalidate => bg_revalidate_flag,
    };
    const dedup_opt: ?*InFlightTable = if (server.dedup) |*d| d else null;
    if (dedup_opt) |dedup| {
        if (!dedup.tryAcquireLeader(name, qtype, dedup_flag)) return;
    }
    defer if (dedup_opt) |dedup| dedup.releaseLeader(name, qtype, dedup_flag);

    // Fresh per-thread transports (mirrors the resolveNsAddressesFanout
    // pattern). BG threads never reuse per-worker TCP pools — a rare
    // refresh doesn't need amortized pooling.
    var udp_t = BlockingUdpTransport.init(.{}, server.io);
    defer udp_t.deinit();
    var tcp_t = BlockingTcpTransport.init(.{});

    var tls_t: ?TlsTransport = if (server.config.opportunistic) blk: {
        var t = TlsTransport.init(server.allocator, .{}, server.ca_bundle, server.io);
        if (server.enc_pool) |*pool| t.pool = pool;
        break :blk t;
    } else null;
    const tls_ptr: ?*TlsTransport = if (tls_t) |*t| t else null;

    var cap = CountingAllocator.init(server.allocator, server.config.query_memory_limit);
    var arena = std.heap.ArenaAllocator.init(cap.allocator());
    defer arena.deinit();
    const alloc = arena.allocator();

    var resolver = RecursiveResolver{
        .transports = .{
            .do53 = .{ .blocking = .{ .udp = &udp_t, .tcp = &tcp_t } },
            .tls = tls_ptr,
        },
        .io = server.io,
        .cache = &server.cache,
        .qname_minimisation = server.config.qname_minimization,
        .dnssec_aware = server.config.dnssec,
        .dnssec_enabled = server.config.dnssec,
        .encrypted_ns_cache = if (server.encrypted_ns_cache) |*oc| oc else null,
        .rtt_cache = &server.rtt_cache,
        .ns_selector = &server.ns_selector,
        .bypass_cache = true,
        .stagger_ms = server.config.stagger_ms,
        .dedup = if (server.dedup) |*d| d else null,
        .tcp_pool = null,
        .gpa = server.allocator,
        .query_memory_limit = server.config.query_memory_limit,
        .nsec_cache = if (server.nsec_cache) |*nc| nc else null,
        .key_cache = if (server.key_cache) |*kc| kc else null,
    };

    // Errors are common (network flakiness, upstream SERVFAIL) and not
    // actionable here — the task runs for cache side effects only.
    _ = resolver.resolve(alloc, name, qtype) catch |err| {
        var qtype_buf: [24]u8 = undefined;
        log.debug("bg resolve {s} {s}: {s}", .{ name, dns.safeTagName(dns.RType, qtype, &qtype_buf), @errorName(err) });
    };
}

// ── WorkerState ────────────────────────────────────────────────────────
// Per-thread state that handles the actual serve loop.

const WorkerState = struct {
    server: *Server,
    config: *const ServerConfig,
    allocator: mem.Allocator,
    io: Io,
    loop: *EventLoop,
    enc_pool: ?*ConnectionPool,
    encrypted_ns_cache: ?*EncryptedNsCache,
    cache: *RRsetCache,
    key_cache: ?*RRsetCache,
    rtt_cache: *RttCache,
    ns_selector: *NsSelector,
    dedup: ?*InFlightTable,
    nsec_cache: ?*NsecCache,
    shutdown: *std.atomic.Value(bool),
    queue: *WorkQueue,
    udp_queue_drops: *std.atomic.Value(u64),
    tcp_queue_drops: *std.atomic.Value(u64),
    udp_send_drops: *std.atomic.Value(u64),
    ca_bundle: Certificate.Bundle,
    tcp_pool: ?*TcpConnectionPool = null,
    active_tcp_clients: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    max_tcp_clients: u32 = 0,

    /// Try to claim a TCP client slot. Returns true on success (caller
    /// must fetchSub when done). CAS loop prevents overcount.
    fn claimTcpSlot(self: *WorkerState) bool {
        while (true) {
            const current = self.active_tcp_clients.load(.monotonic);
            if (current >= self.max_tcp_clients) return false;
            if (self.active_tcp_clients.cmpxchgStrong(current, current + 1, .monotonic, .monotonic) == null) return true;
        }
    }

    fn serveLoop(self: *WorkerState, udp_socks: []const posix.fd_t, tcp_socks: []const posix.fd_t, sig_fd: posix.fd_t) void {
        const n = udp_socks.len;

        var udp_ctxs: [max_listen_addrs]Ctx = undefined;
        var tcp_ctxs: [max_listen_addrs]Ctx = undefined;
        var signal_ctx = Ctx{ .tag = .signal, .fd = sig_fd };

        // Op IDs indexed by listen address; null means inactive
        var udp_ops: [max_listen_addrs]?OperationId = .{null} ** max_listen_addrs;
        var tcp_ops: [max_listen_addrs]?OperationId = .{null} ** max_listen_addrs;

        // Prefer multishot recvmsg — one SQE per socket stays armed and
        // produces CQEs for every inbound packet. Fall back to one-shot
        // if the kernel / buffer-ring setup rejected it.
        const use_multishot_udp = self.loop.supportsMultishotRecv();
        for (udp_socks, 0..) |fd, i| {
            if (fd < 0) continue;
            udp_ctxs[i] = .{ .tag = .udp_recv, .fd = fd };
            udp_ops[i] = (if (use_multishot_udp)
                self.loop.recvFromMulti(fd, @ptrCast(&udp_ctxs[i]))
            else
                self.loop.recvFrom(fd, @ptrCast(&udp_ctxs[i]))) catch |err| blk: {
                log.err("failed to register UDP recvFrom: {s}", .{@errorName(err)});
                break :blk null;
            };
        }

        // Register accept for each TCP socket
        for (tcp_socks, 0..) |fd, i| {
            if (fd < 0) continue;
            tcp_ctxs[i] = .{ .tag = .tcp_accept, .fd = fd };
            tcp_ops[i] = self.loop.accept(fd, @ptrCast(&tcp_ctxs[i])) catch null;
        }

        const signal_op: ?OperationId = if (sig_fd >= 0)
            self.loop.read(sig_fd, @ptrCast(&signal_ctx)) catch null
        else
            null;

        var completions: [max_operations]Completion = undefined;
        var last_stats_ns: i128 = monotonic.nowNs();
        const stats_interval_ns: i128 = 60 * std.time.ns_per_s;

        while (!self.shutdown.load(.acquire)) {
            const results = self.loop.tick(&completions) catch break;

            // Periodic cache stats logging
            const now_ns = monotonic.nowNs();
            if (now_ns - last_stats_ns >= stats_interval_ns) {
                const stats = self.cache.getStats();
                const hit_total = stats.hits + stats.misses;
                const hit_pct: u64 = if (hit_total > 0) stats.hits * 100 / hit_total else 0;
                log.info("cache: {d} entries, {d}/{d} bytes, {d}% hit rate, {d} evictions", .{
                    stats.entries, stats.memory_bytes, stats.max_bytes, hit_pct, stats.evictions,
                });
                last_stats_ns = now_ns;
            }

            for (results) |c| {
                const ctx: *Ctx = @ptrCast(@alignCast(c.context));
                switch (ctx.tag) {
                    .signal => {
                        log.info("shutting down", .{});
                        self.shutdown.store(true, .release);
                        break;
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
                        if (self.shutdown.load(.acquire)) continue;
                        const idx = ctxIndex(&udp_ctxs, n, ctx) orelse continue;
                        // Multishot stays armed across CQEs; re-arm only
                        // when the kernel terminated it.
                        if (self.loop.stillArmed(udp_ops[idx])) continue;
                        udp_ops[idx] = (if (use_multishot_udp)
                            self.loop.recvFromMulti(ctx.fd, @ptrCast(ctx))
                        else
                            self.loop.recvFrom(ctx.fd, @ptrCast(ctx))) catch |err| {
                            log.err("failed to re-register UDP recvFrom: {s}", .{@errorName(err)});
                            udp_ops[idx] = null;
                            continue;
                        };
                    },
                    .tcp_accept => {
                        switch (c.result) {
                            .accept => |acc| {
                                if (acc.err == null and acc.fd >= 0) {
                                    if (!self.queue.push(&.{}, na.initIp4(.{ 0, 0, 0, 0 }, 0), acc.fd, .tcp)) {
                                        // Drop silently (no SERVFAIL): we haven't read the
                                        // query yet so we don't have an ID, and reading it
                                        // would consume the pool capacity we're protecting.
                                        // Client sees TCP reset and should retry (typically
                                        // over UDP).
                                        _ = self.tcp_queue_drops.fetchAdd(1, .monotonic);
                                        log.warn("resolution queue full, dropping TCP client", .{});
                                        sys.close(acc.fd);
                                    }
                                }
                            },
                            else => {},
                        }
                        if (!self.shutdown.load(.acquire)) {
                            const idx = ctxIndex(&tcp_ctxs, n, ctx) orelse continue;
                            tcp_ops[idx] = self.loop.accept(ctx.fd, @ptrCast(ctx)) catch |err| {
                                log.err("failed to re-register TCP accept: {s}", .{@errorName(err)});
                                tcp_ops[idx] = null;
                                continue;
                            };
                        }
                    },
                }
            }

            // Retry re-registration for any listeners that failed above.
            // Placed after completion processing so freshly freed slots are available.
            for (0..n) |i| {
                if (udp_ops[i] == null) {
                    udp_ops[i] = self.loop.recvFrom(udp_ctxs[i].fd, @ptrCast(&udp_ctxs[i])) catch null;
                }
                if (tcp_ops[i] == null) {
                    tcp_ops[i] = self.loop.accept(tcp_ctxs[i].fd, @ptrCast(&tcp_ctxs[i])) catch null;
                }
            }
        }

        // Cancel pending operations before draining, so flush() doesn't block
        for (0..n) |i| {
            if (udp_ops[i]) |op| self.loop.cancel(op) catch {};
            if (tcp_ops[i]) |op| self.loop.cancel(op) catch {};
        }
        if (signal_op) |op| self.loop.cancel(op) catch {};
        self.loop.flush();
    }

    fn sendErrorUdp(self: *WorkerState, sock: posix.fd_t, id: u16, rcode: dns.RCode, extended_rcode: u8, rd: bool, questions: []const dns.Question, client_addr: na.Address) void {
        var wire_buf: [dns.max_udp_payload]u8 = undefined;
        if (serializeErrorResponse(&wire_buf, id, rcode, extended_rcode, rd, questions)) |wire| {
            self.sendUdpResponse(sock, wire, client_addr);
        }
    }

    fn sendUdpResponse(self: *WorkerState, sock: posix.fd_t, data: []const u8, dest: na.Address) void {
        // MSG_DONTWAIT keeps the pool thread off a saturated kernel send buffer:
        // dropping the response on WouldBlock/SystemResources is correct DNS
        // behavior (the client retransmits), and beats stalling the worker.
        var storage: na.PosixAddress = undefined;
        const sa_len = na.toSockaddr(&dest, &storage);
        _ = sys.sendto(sock, data, posix.MSG.DONTWAIT, &storage.any, sa_len) catch |err| switch (err) {
            error.WouldBlock, error.SystemResources => {
                _ = self.udp_send_drops.fetchAdd(1, .monotonic);
            },
            else => {},
        };
    }

    fn handleUdpQuery(self: *WorkerState, sock: posix.fd_t, data: []const u8, client_addr: na.Address) void {
        if (data.len < 12) return;
        // RFC 1035 §4.1.1: drop QR=1 silently. Treating a spoofed response
        // as a query would let an attacker reflect upstream resolutions
        // off this server.
        if (data[2] & 0x80 != 0) return;
        const id = mem.readInt(u16, data[0..2], .big);
        const rd = data[2] & 0x01 != 0; // RFC 1035 §4.1.1: echo RD in response
        // Pre-validate from raw header bytes to avoid wasting pool threads
        // on garbage: opcode (bits 1-4 of byte 2), qdcount (bytes 4-5).
        const opcode: u4 = @truncate(data[2] >> 3);
        if (opcode != 0) { // Only QUERY (0) supported
            self.sendErrorUdp(sock, id, .not_implemented, 0, rd, &.{}, client_addr);
            return;
        }
        const qdcount = mem.readInt(u16, data[4..6], .big);
        if (qdcount != 1) {
            self.sendErrorUdp(sock, id, .format_error, 0, rd, &.{}, client_addr);
            return;
        }
        if (!self.queue.push(data, client_addr, sock, .udp)) {
            _ = self.udp_queue_drops.fetchAdd(1, .monotonic);
            log.warn("resolution queue full, dropping query", .{});
            self.sendErrorUdp(sock, id, .server_failure, 0, rd, &.{}, client_addr);
        }
    }

    fn processTcpClient(
        self: *WorkerState,
        client_fd: posix.fd_t,
        transports: Transports,
        query_pta: *PerThreadArena,
        prefetch_pta: *PerThreadArena,
    ) void {
        defer sys.close(client_fd);

        // Switch accepted fd to blocking mode with idle timeout.
        const flags = sys.fcntl(client_fd, posix.F.GETFL, 0) catch return;
        const nonblock_bit = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
        _ = sys.fcntl(client_fd, posix.F.SETFL, flags & ~nonblock_bit) catch return;
        sys.setNoDelay(client_fd);

        var tcp_queries: u32 = 0;
        while (!self.shutdown.load(.acquire) and tcp_queries < max_tcp_queries_per_conn) {
            tcp_queries += 1;
            const read_deadline_ns: i128 = monotonic.nowNs() + tcp_idle_timeout_ns;
            var len_buf: [2]u8 = undefined;
            tcpReadExactBlocking(client_fd, &len_buf, read_deadline_ns) orelse return;
            const msg_len = mem.readInt(u16, &len_buf, .big);
            if (msg_len == 0) return;

            var query_buf: [dns.max_message_len]u8 = undefined;
            tcpReadExactBlocking(client_fd, query_buf[0..msg_len], read_deadline_ns) orelse return;
            sys.setQuickAck(client_fd);

            const alloc = query_pta.reset();
            var response_wire: [dns.max_message_len]u8 = undefined;
            const data = query_buf[0..msg_len];

            const query = dns.parseMessage(alloc, data) catch {
                if (data.len >= 2) {
                    const id = mem.readInt(u16, data[0..2], .big);
                    const w = serializeErrorResponse(&response_wire, id, .format_error, 0, false, &.{}) orelse return;
                    tcpWriteMessage(client_fd, w, read_deadline_ns) orelse return;
                    continue;
                }
                return;
            };

            if (validateQuery(query)) |fail| {
                const w = serializeErrorResponse(&response_wire, query.header.id, fail.rcode, fail.extended_rcode, query.header.rd, query.questions) orelse return;
                tcpWriteMessage(client_fd, w, read_deadline_ns) orelse return;
                continue;
            }

            const question = query.questions[0];
            var name_buf: [dns.max_name_len + 1]u8 = undefined;
            const name_str = question.name.formatInto(&name_buf);

            const start_ns = monotonic.nowNs();
            const result = self.resolveWithDedupUsing(alloc, name_str, question.qtype, query.header.cd, transports) catch |err| {
                const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
                var qtype_buf: [24]u8 = undefined;
                log.warn("{s} {s} SERVFAIL {d}ms (tcp, {s})", .{ name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf), elapsed_ms, @errorName(err) });
                const w = serializeErrorResponse(&response_wire, query.header.id, .server_failure, 0, query.header.rd, query.questions) orelse return;
                const write_deadline_ns: i128 = monotonic.nowNs() + tcp_idle_timeout_ns;
                tcpWriteMessage(client_fd, w, write_deadline_ns) orelse return;
                continue;
            };
            const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
            var qtype_buf: [24]u8 = undefined;
            var rcode_buf: [24]u8 = undefined;
            log.debug("{s} {s} {s} {d}ms (tcp)", .{ name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf), dns.safeTagName(dns.RCode, result.message.header.rcode, &rcode_buf), elapsed_ms });

            const wire = buildResponseWire(&response_wire, ResponseContext.fromQuery(query, dns.max_message_len), result.message, alloc) orelse return;
            const write_deadline_ns: i128 = monotonic.nowNs() + tcp_idle_timeout_ns;
            tcpWriteMessage(client_fd, wire, write_deadline_ns) orelse return;

            self.dispatchPrefetches(result, name_str, transports, prefetch_pta);
            if (query.header.cd) {
                self.scheduleCd1Revalidate(name_str, question.qtype);
            }
        }
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
        switch (self.config.mode) {
            .recursive => {
                var resolver = RecursiveResolver{
                    .transports = transports,
                    .io = self.io,
                    .cache = self.cache,
                    .qname_minimisation = self.config.qname_minimization,
                    // RFC 4035 §3.2.1: always request DNSSEC data (DO bit) if capable
                    .dnssec_aware = self.config.dnssec,
                    // RFC 4035 §3.2.2: CD=1 means client handles validation — skip ours
                    .dnssec_enabled = self.config.dnssec and !cd,
                    .encrypted_ns_cache = self.encrypted_ns_cache,
                    .rtt_cache = self.rtt_cache,
                    .ns_selector = self.ns_selector,
                    .bypass_cache = bypass_cache,
                    .stagger_ms = self.config.stagger_ms,
                    .dedup = self.dedup,
                    .tcp_pool = self.tcp_pool,
                    .gpa = self.allocator,
                    .query_memory_limit = self.config.query_memory_limit,
                    .nsec_cache = if (self.config.dnssec and !cd) self.nsec_cache else null,
                    .key_cache = if (self.config.dnssec) self.key_cache else null,
                };
                var result = try resolver.resolve(alloc, name, qtype);
                // Dupe into arena — points into stack-local resolver.pending_dnskey_buf
                if (result.prefetch_dnskey_zone) |z| {
                    result.prefetch_dnskey_zone = alloc.dupe(u8, z) catch null;
                }
                return result;
            },
            .forward => {
                var resolver = ForwardingResolver{
                    .transports = transports,
                    .io = self.io,
                };
                const upstreams = if (self.config.upstreams.len > 0)
                    self.config.upstreams
                else
                    &[_]na.Address{na.initIp4(.{ 8, 8, 8, 8 }, 53)};
                var last_err: anyerror = error.Timeout;
                for (upstreams) |upstream| {
                    const msg = resolver.resolve(alloc, name, qtype, upstream) catch |err| {
                        last_err = err;
                        continue;
                    };
                    return .{ .message = msg };
                }
                return last_err;
            },
        }
    }

    fn doPrefetchWith(self: *WorkerState, prefetch_name: []const u8, prefetch_qtype: dns.RType, transports: Transports, prefetch_pta: *PerThreadArena) void {
        const alloc = prefetch_pta.reset();
        _ = self.resolveQueryWith(alloc, prefetch_name, prefetch_qtype, false, true, transports) catch {};
    }

    /// Resolution thread pool entry point.
    fn poolThread(self: *WorkerState) void {
        var udp_t = BlockingUdpTransport.init(.{}, self.io);
        defer udp_t.deinit();
        var tcp_t = BlockingTcpTransport.init(.{});

        var tls_t: ?TlsTransport = if (self.config.opportunistic) blk: {
            var t = TlsTransport.init(self.allocator, .{}, self.ca_bundle, self.io);
            t.pool = self.enc_pool;
            break :blk t;
        } else null;

        const transports: Transports = .{
            .do53 = .{ .blocking = .{ .udp = &udp_t, .tcp = &tcp_t } },
            .tls = if (tls_t) |*t| t else null,
        };

        var query_pta: PerThreadArena = undefined;
        query_pta.init(self.allocator, self.config.query_memory_limit);
        defer query_pta.deinit();

        var prefetch_pta: PerThreadArena = undefined;
        prefetch_pta.init(self.allocator, self.config.query_memory_limit);
        defer prefetch_pta.deinit();

        while (self.queue.pop()) |item| {
            switch (item.protocol) {
                .udp => self.processUdpQuery(
                    item.sock_fd,
                    item.query_buf[0..item.query_len],
                    item.client_addr,
                    transports,
                    &query_pta,
                    &prefetch_pta,
                ),
                .tcp => {
                    if (self.claimTcpSlot()) {
                        defer _ = self.active_tcp_clients.fetchSub(1, .monotonic);
                        self.processTcpClient(item.sock_fd, transports, &query_pta, &prefetch_pta);
                    } else {
                        // Drop silently for the same reason as the queue-full path above.
                        log.debug("TCP client limit reached ({d}), dropping connection", .{self.max_tcp_clients});
                        sys.close(item.sock_fd);
                    }
                },
            }
        }
    }

    fn processUdpQuery(
        self: *WorkerState,
        sock: posix.fd_t,
        data: []const u8,
        client_addr: na.Address,
        transports: Transports,
        query_pta: *PerThreadArena,
        prefetch_pta: *PerThreadArena,
    ) void {
        const alloc = query_pta.reset();

        const query_msg = dns.parseMessage(alloc, data) catch {
            if (data.len >= 2) {
                const id = mem.readInt(u16, data[0..2], .big);
                self.sendErrorUdp(sock, id, .format_error, 0, false, &.{}, client_addr);
            }
            return;
        };

        if (validateQuery(query_msg)) |fail| {
            self.sendErrorUdp(sock, query_msg.header.id, fail.rcode, fail.extended_rcode, query_msg.header.rd, query_msg.questions, client_addr);
            return;
        }

        const question = query_msg.questions[0];
        var name_buf: [dns.max_name_len + 1]u8 = undefined;
        const name_str = question.name.formatInto(&name_buf);

        const max_payload: u16 = if (query_msg.opt) |opt| @max(opt.udp_payload_size, dns.max_udp_payload) else dns.max_udp_payload;

        const start_ns = monotonic.nowNs();
        const result = self.resolveWithDedupUsing(alloc, name_str, question.qtype, query_msg.header.cd, transports) catch |err| {
            const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
            var qtype_buf1: [24]u8 = undefined;
            log.warn("{s} {s} SERVFAIL {d}ms ({s})", .{ name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf1), elapsed_ms, @errorName(err) });
            self.sendErrorUdp(sock, query_msg.header.id, .server_failure, 0, query_msg.header.rd, query_msg.questions, client_addr);
            return;
        };
        const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
        var qtype_buf2: [24]u8 = undefined;
        var rcode_buf2: [24]u8 = undefined;
        log.debug("{s} {s} {s} {d}ms", .{ name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf2), dns.safeTagName(dns.RCode, result.message.header.rcode, &rcode_buf2), elapsed_ms });

        var wire_buf: [dns.max_message_len]u8 = undefined;
        if (buildResponseWire(&wire_buf, ResponseContext.fromQuery(query_msg, max_payload), result.message, alloc)) |wire| {
            self.sendUdpResponse(sock, wire, client_addr);
        }

        self.dispatchPrefetches(result, name_str, transports, prefetch_pta);

        if (query_msg.header.cd) {
            self.scheduleCd1Revalidate(name_str, question.qtype);
        }
    }

    fn dispatchPrefetches(
        self: *WorkerState,
        result: recursive.RecursiveResolver.ResolveResult,
        query_name: []const u8,
        transports: Transports,
        prefetch_pta: *PerThreadArena,
    ) void {
        // TTL-refresh: bg thread, with inline fallback so a refresh is never dropped.
        if (result.prefetch_name) |n| self.spawnOrInline(n, result.prefetch_qtype, transports, prefetch_pta);
        if (result.prefetch_dnskey_zone) |z| self.spawnOrInline(z, .dnskey, transports, prefetch_pta);

        // RFC 8305 cousin co-prefetch: fire-and-forget, gated on a cache miss.
        const cousin_qtype = result.cousin_prefetch_qtype orelse return;
        if (!self.config.prefetch_cousin) return;
        if (self.cache.lookupExists(query_name, cousin_qtype, .in)) return;
        _ = self.server.trySpawnBgPrefetch(query_name, cousin_qtype, .prefetch);
    }

    fn spawnOrInline(
        self: *WorkerState,
        name: []const u8,
        qtype: dns.RType,
        transports: Transports,
        prefetch_pta: *PerThreadArena,
    ) void {
        if (!self.server.trySpawnBgPrefetch(name, qtype, .prefetch)) {
            self.doPrefetchWith(name, qtype, transports, prefetch_pta);
        }
    }

    /// Schedule background DNSSEC validation for a cache entry populated by
    /// a CD=1 query. The original response shipped to the client with AD=0
    /// and the RRset is cached as .unchecked; background validation
    /// promotes it to .secure (benefiting subsequent CD=0 lookups) or
    /// invalidates on BOGUS. Silently drops on cap/spawn failure — the only
    /// loss is missed cache warming, never an incorrect response.
    fn scheduleCd1Revalidate(self: *WorkerState, name: []const u8, qtype: dns.RType) void {
        if (!self.config.dnssec) return;
        if (self.cache.hasValidatedPositive(name, qtype, .in)) return;
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
        // Dedup only prevents duplicate upstream queries. On a cache hit no
        // upstream I/O happens, so the InFlightTable mutex pair is pure
        // overhead; a shared-lock existence probe skips it. On miss we fall
        // through to the normal dedup + resolve path.
        if (self.cache.lookupExists(name, qtype, .in)) {
            return self.resolveQueryWith(alloc, name, qtype, cd, false, transports);
        }

        const cd_flag: u8 = @intFromBool(cd);
        var is_leader = true;
        if (self.dedup) |dedup| {
            switch (dedup.acquireOrWait(name, qtype, cd_flag)) {
                .leader => {},
                .follower => {
                    is_leader = false;
                },
            }
        }
        errdefer if (is_leader) {
            if (self.dedup) |dedup| dedup.releaseLeader(name, qtype, cd_flag);
        };
        const result = try self.resolveQueryWith(alloc, name, qtype, cd, false, transports);
        if (is_leader) {
            if (self.dedup) |dedup| dedup.releaseLeader(name, qtype, cd_flag);
        }
        return result;
    }
};

// ── Response building ──────────────────────────────────────────────────

/// RFC 4035 §3.2.1: strip authenticating DNSSEC RRs (RRSIG, NSEC, NSEC3) when
/// client didn't set the DO bit. Records whose type matches the QTYPE are kept
/// in the answer section (explicit query for that type).
fn stripDnssecRRs(alloc: mem.Allocator, records: []const dns.ResourceRecord, qtype: dns.RType, is_answer: bool) []const dns.ResourceRecord {
    var count: usize = 0;
    for (records) |rr| {
        if (isDnssecAuthRR(rr.rtype) and !(is_answer and rr.rtype == qtype)) {
            continue;
        }
        count += 1;
    }
    if (count == records.len) return records;

    const filtered = alloc.alloc(dns.ResourceRecord, count) catch return records;
    var i: usize = 0;
    for (records) |rr| {
        if (isDnssecAuthRR(rr.rtype) and !(is_answer and rr.rtype == qtype)) {
            continue;
        }
        filtered[i] = rr;
        i += 1;
    }
    return filtered;
}

fn isDnssecAuthRR(rtype: dns.RType) bool {
    return switch (rtype) {
        .rrsig, .nsec, .nsec3 => true,
        else => false,
    };
}

const ResponseContext = struct {
    query_id: u16,
    rd: bool,
    cd: bool,
    questions: []const dns.Question,
    client_edns: bool,
    client_do: bool,
    client_wants_ad: bool,
    max_payload: u16,

    fn fromQuery(query: dns.Message, max_payload: u16) ResponseContext {
        const client_do = query.opt != null and query.opt.?.do_bit;
        return .{
            .query_id = query.header.id,
            .rd = query.header.rd,
            .cd = query.header.cd,
            .questions = query.questions,
            .client_edns = query.opt != null,
            .client_do = client_do,
            // RFC 6840 §5.8: set AD only if client signalled DO or AD
            .client_wants_ad = client_do or query.header.ad,
            .max_payload = max_payload,
        };
    }
};

fn buildResponseWire(
    wire_buf: []u8,
    ctx: ResponseContext,
    response: dns.Message,
    alloc: mem.Allocator,
) ?[]const u8 {
    const opt: ?dns.OptRecord = if (ctx.client_edns) .{
        .udp_payload_size = dns.edns_udp_payload,
        .extended_rcode = 0,
        .version = 0,
        .do_bit = ctx.client_do,
        .options = &.{},
    } else null;

    const qtype = if (ctx.questions.len > 0) ctx.questions[0].qtype else .a;

    // RFC 4035 §3.2.1: strip authenticating DNSSEC RRs when client didn't set DO
    const answers = if (!ctx.client_do) stripDnssecRRs(alloc, response.answers, qtype, true) else response.answers;
    const authorities = if (!ctx.client_do) stripDnssecRRs(alloc, response.authorities, qtype, false) else response.authorities;
    const additionals = if (!ctx.client_do) stripDnssecRRs(alloc, response.additionals, qtype, false) else response.additionals;

    var msg = dns.Message{
        .header = .{
            .id = ctx.query_id,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = ctx.rd,
            .ra = true,
            .z = 0,
            .ad = response.header.ad and ctx.client_wants_ad,
            .cd = ctx.cd,
            .rcode = response.header.rcode,
            .qd_count = @intCast(ctx.questions.len),
            .an_count = @intCast(answers.len),
            .ns_count = @intCast(authorities.len),
            .ar_count = @intCast(additionals.len),
        },
        .questions = ctx.questions,
        .answers = answers,
        .authorities = authorities,
        .additionals = additionals,
        .opt = opt,
    };

    // Try full response
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_payload) return wire;
    } else |_| {}

    // Drop additionals
    msg.additionals = &.{};
    msg.header.ar_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_payload) return wire;
    } else |_| {}

    // Drop authorities
    msg.authorities = &.{};
    msg.header.ns_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_payload) return wire;
    } else |_| {}

    // TC bit with answers
    msg.header.tc = true;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= ctx.max_payload) return wire;
    } else |_| {}

    // TC with no answers
    msg.answers = &.{};
    msg.header.an_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        return wire[0..@min(wire.len, ctx.max_payload)];
    } else |_| {}

    return null;
}

fn serializeErrorResponse(
    wire_buf: []u8,
    query_id: u16,
    rcode: dns.RCode,
    extended_rcode: u8,
    rd: bool,
    questions: []const dns.Question,
) ?[]const u8 {
    const opt: ?dns.OptRecord = if (extended_rcode != 0) .{
        .udp_payload_size = dns.edns_udp_payload,
        .extended_rcode = extended_rcode,
        .version = 0,
        .do_bit = false,
        .options = &.{},
    } else null;
    const msg = dns.Message{
        .header = .{
            .id = query_id,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = rd,
            .ra = true,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = rcode,
            .qd_count = @intCast(questions.len),
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = questions,
        .opt = opt,
    };
    return dns.serializeMessage(wire_buf, msg) catch null;
}

// ── TCP helpers (blocking I/O) ─────────────────────────────────────────

fn tcpReadExactBlocking(fd: posix.fd_t, buf: []u8, deadline_ns: i128) ?void {
    var total: usize = 0;
    while (total < buf.len) {
        sys.updateTimeout(fd, posix.SO.RCVTIMEO, deadline_ns) catch return null;
        const n = sys.read(fd, buf[total..]) catch return null;
        if (n == 0) return null; // connection closed
        total += n;
    }
}

fn tcpWriteAllBlocking(fd: posix.fd_t, data: []const u8, deadline_ns: i128) ?void {
    var total: usize = 0;
    while (total < data.len) {
        sys.updateTimeout(fd, posix.SO.SNDTIMEO, deadline_ns) catch return null;
        const n = sys.write(fd, data[total..]) catch return null;
        total += n;
    }
}

const ValidationFailure = struct {
    rcode: dns.RCode,
    extended_rcode: u8 = 0,
};

fn validateQuery(query: dns.Message) ?ValidationFailure {
    // RFC 1035 §4.1.1: a QR=1 packet is a response, not a query. Don't
    // resolve it. Returning format_error keeps the TCP connection useful
    // (UDP path drops silently before parse).
    if (query.header.qr) return .{ .rcode = .format_error };
    if (query.header.opcode != .query) return .{ .rcode = .not_implemented };
    if (query.questions.len != 1) return .{ .rcode = .format_error };
    if (query.questions[0].qclass != .in) return .{ .rcode = .refused };
    // RFC 6891 §6.1.3: BADVERS (extended RCODE 16) for unsupported EDNS
    // version. Header RCODE bits = 0; OPT extended_rcode field = 1.
    if (query.opt) |opt| if (opt.version != 0) return .{ .rcode = .no_error, .extended_rcode = 1 };
    return null;
}

fn tcpWriteMessage(fd: posix.fd_t, data: []const u8, deadline_ns: i128) ?void {
    var len_prefix: [2]u8 = undefined;
    mem.writeInt(u16, &len_prefix, @intCast(data.len), .big);
    tcpWriteAllBlocking(fd, &len_prefix, deadline_ns) orelse return null;
    tcpWriteAllBlocking(fd, data, deadline_ns) orelse return null;
}

// ── Helpers ────────────────────────────────────────────────────────────

fn ctxIndex(ctxs: *const [max_listen_addrs]Ctx, n: usize, target: *const Ctx) ?usize {
    for (0..n) |i| {
        if (&ctxs[i] == target) return i;
    }
    return null;
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
    var mask = linux.sigemptyset();
    linux.sigaddset(&mask, linux.SIG.INT);
    linux.sigaddset(&mask, linux.SIG.TERM);

    // Block signals so they arrive via signalfd
    // SIG_BLOCK = 0 on Linux x86_64
    _ = linux.sigprocmask(0, &mask, null);

    const SFD_NONBLOCK: u32 = 0o4000;
    return posix.signalfd(-1, &mask, SFD_NONBLOCK);
}

// ── Tests ──────────────────────────────────────────────────────────────

fn isLinuxIoUringAvailable() bool {
    if (comptime @import("builtin").os.tag != .linux) return false;
    return true;
}

test "server init and deinit" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const config = @import("config.zig");
    var cfg = config.parseConfig(testing.allocator, "") catch return error.SkipZigTest;
    defer cfg.deinit();

    var server = try Server.init(testing.allocator, cfg, testing.io);
    defer server.deinit();

    try testing.expectEqual(false, server.shutdown.load(.acquire));
}

test "server init thread-safe cache when workers > 1" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const config = @import("config.zig");
    var cfg = config.parseConfig(testing.allocator,
        \\[server]
        \\workers = 4
    ) catch return error.SkipZigTest;
    defer cfg.deinit();

    var server = try Server.init(testing.allocator, cfg, testing.io);
    defer server.deinit();

    try testing.expect(server.cache.rwlock != null);
}

test "buildResponseWire sets correct header fields" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;

    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = try a.alloc(dns.Question, 1);
    const name = try dns.parseDottedName(a, "example.com");
    questions[0] = .{ .name = name, .qtype = .a, .qclass = .in };

    const response = dns.Message{
        .header = .{
            .id = 0,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = true,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = .server_failure,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
    };

    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x1234,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = false,
        .client_do = false,
        .client_wants_ad = false,
        .max_payload = dns.max_udp_payload,
    }, response, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(true, parsed.header.qr);
    try testing.expectEqual(true, parsed.header.rd);
    try testing.expectEqual(true, parsed.header.ra);
    try testing.expectEqual(dns.RCode.server_failure, parsed.header.rcode);
    try testing.expectEqual(@as(u16, 1), parsed.header.qd_count);
}

test "buildResponseWire with EDNS0" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;

    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = try a.alloc(dns.Question, 1);
    const name = try dns.parseDottedName(a, "example.com");
    questions[0] = .{ .name = name, .qtype = .a, .qclass = .in };

    const response = dns.Message{
        .header = .{
            .id = 0,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = true,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
    };

    var buf: [dns.edns_udp_payload]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x5678,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = true,
        .client_do = false,
        .client_wants_ad = false,
        .max_payload = dns.edns_udp_payload,
    }, response, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u16, dns.edns_udp_payload), parsed.opt.?.udp_payload_size);
}

test "serializeErrorResponse produces valid DNS message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const name = try dns.parseDottedName(a, "example.com");
    const questions: []const dns.Question = &.{.{ .name = name, .qtype = .a, .qclass = .in }};

    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0xABCD, .refused, 0, true, questions).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0xABCD), parsed.header.id);
    try testing.expectEqual(dns.RCode.refused, parsed.header.rcode);
    try testing.expectEqual(true, parsed.header.rd);
    try testing.expectEqual(true, parsed.header.ra);
    try testing.expectEqual(true, parsed.header.qr);
    try testing.expectEqual(@as(u16, 1), parsed.header.qd_count);
}

test "serializeErrorResponse with no question (parse failure)" {
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x1234, .format_error, 0, false, &.{}).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(dns.RCode.format_error, parsed.header.rcode);
    try testing.expectEqual(@as(u16, 0), parsed.header.qd_count);
}

test "validateQuery rejects QR=1 (response posing as query)" {
    // RFC 1035 §4.1.1: resolving a QR=1 packet would make hark a reflection vector.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var spoofed = try dns.buildQuery(arena.allocator(), 0, "example.com", .a);
    spoofed.header.qr = true;

    try testing.expectEqual(dns.RCode.format_error, validateQuery(spoofed).?.rcode);
}

test "validateQuery returns BADVERS for unsupported EDNS version" {
    // RFC 6891 §6.1.3: header RCODE = 0, OPT extended_rcode = 1.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var query = try dns.buildQuery(arena.allocator(), 0, "example.com", .a);
    query.opt = .{
        .udp_payload_size = 4096,
        .extended_rcode = 0,
        .version = 1, // unsupported
        .do_bit = false,
        .options = &.{},
    };

    const fail = validateQuery(query).?;
    try testing.expectEqual(dns.RCode.no_error, fail.rcode);
    try testing.expectEqual(@as(u8, 1), fail.extended_rcode);
}

test "serializeErrorResponse emits BADVERS OPT when extended_rcode != 0" {
    var buf: [dns.max_udp_payload]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x1234, .no_error, 1, false, &.{}).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(dns.RCode.no_error, parsed.header.rcode);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u8, 1), parsed.opt.?.extended_rcode);
}

test "parseMessage rejects multiple OPT records (RFC 6891 §6.1.1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Build a query, then manually append a second OPT to additionals.
    var query = try dns.buildQuery(arena.allocator(), 0, "example.com", .a);
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

test "BackgroundTasks.tryClaim caps concurrent tasks" {
    var bg = BackgroundTasks{};
    for (0..max_bg_tasks) |_| {
        try testing.expect(bg.tryClaim());
    }
    try testing.expect(!bg.tryClaim());
    bg.release();
    try testing.expect(bg.tryClaim());
    for (0..max_bg_tasks) |_| bg.release();
    try testing.expectEqual(@as(u32, 0), bg.inFlight());
}

test "BackgroundTasks rejects tryClaim after shutdown" {
    var bg = BackgroundTasks{};
    bg.shutting_down.store(true, .release);
    // Even with empty slots, shutdown short-circuits tryClaim so bg threads
    // can drain to zero and awaitAll can return.
    try testing.expect(!bg.tryClaim());
    try testing.expectEqual(@as(u32, 0), bg.inFlight());
}

test "AD bit cleared on unvalidated (.unchecked) cache hit" {
    // RFC 6840 §5.9 / RFC 4035 §3.2.2: AD MUST NOT be set unless the
    // resolver verified. A cache entry stored as .unchecked (e.g. by the
    // CD=1 early-serve path before background validation upgrades it)
    // must not produce AD=1 responses to CD=0 clients.
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;

    const alloc = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const questions = try a.alloc(dns.Question, 1);
    questions[0] = .{ .name = try dns.parseDottedName(a, "example.com"), .qtype = .a, .qclass = .in };

    // Simulate a cached-and-returned message where the resolver did NOT
    // set ad=true (because security_status was .unchecked at lookup time —
    // recursive.zig:182 computes `ad = h.security_status == .secure`).
    const response_unchecked = dns.Message{
        .header = .{ .id = 0, .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = false, .ra = true, .z = 0, .ad = false, .cd = false, .rcode = .no_error, .qd_count = 0, .an_count = 0, .ns_count = 0, .ar_count = 0 },
        .questions = &.{},
    };

    var buf: [dns.edns_udp_payload]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 1,
        .rd = true,
        .cd = false, // CD=0 client — asking us to validate
        .questions = questions,
        .client_edns = true,
        .client_do = true, // DO=1 → client_wants_ad via fromQuery; exercise the AD-strip path
        .client_wants_ad = true,
        .max_payload = dns.edns_udp_payload,
    }, response_unchecked, a).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(false, parsed.header.ad);

    // Same message with validation-proven security_status=.secure would have
    // response.header.ad == true upstream of buildResponseWire; confirm the
    // path then emits AD=1.
    const response_secure = dns.Message{
        .header = .{ .id = 0, .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = false, .ra = true, .z = 0, .ad = true, .cd = false, .rcode = .no_error, .qd_count = 0, .an_count = 0, .ns_count = 0, .ar_count = 0 },
        .questions = &.{},
    };
    var buf2: [dns.edns_udp_payload]u8 = undefined;
    const wire2 = buildResponseWire(&buf2, .{
        .query_id = 2,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = true,
        .client_do = true,
        .client_wants_ad = true,
        .max_payload = dns.edns_udp_payload,
    }, response_secure, a).?;
    const parsed2 = try dns.parseMessage(a, wire2);
    try testing.expectEqual(true, parsed2.header.ad);
}

test "hasValidatedPositive returns true only for non-.unchecked entries" {
    // Guards the predicate that scheduleCd1Revalidate uses to short-circuit
    // repeated CD=1 queries to an already-validated name. A steady CD=1
    // workload would otherwise pay a bg spawn + upstream round-trip per
    // query even after the cache entry is .secure.
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
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
        .header = .{ .id = 0, .qr = true, .opcode = .query, .aa = true, .tc = false, .rd = false, .ra = false, .z = 0, .ad = false, .cd = false, .rcode = .no_error, .qd_count = 0, .an_count = 1, .ns_count = 0, .ar_count = 0 },
        .questions = &.{},
        .answers = answers,
    };
    server.cache.storeResponseWithStatus(resp, dns.Name{ .labels = &.{} }, .secure);

    try testing.expect(server.cache.hasValidatedPositive("example.com", .a, .in));
    // .unchecked entries are NOT protected — bg scheduler should still fire.
    try testing.expect(!server.cache.hasValidatedPositive("unknown.com", .a, .in));
}

test "trySpawnBgPrefetch rejects oversize and empty names" {
    // Input validation before the expensive heap+spawn path. Protects against
    // a malformed name slipping through and the thread getting a truncated
    // or empty buffer.
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const config = @import("config.zig");
    var cfg = config.parseConfig(testing.allocator, "") catch return error.SkipZigTest;
    defer cfg.deinit();

    var server = try Server.init(testing.allocator, cfg, testing.io);
    defer server.deinit();

    try testing.expect(!server.trySpawnBgPrefetch("", .a, .prefetch));
    var too_long: [dns.max_name_len + 2]u8 = undefined;
    @memset(&too_long, 'a');
    try testing.expect(!server.trySpawnBgPrefetch(&too_long, .a, .prefetch));

    // Drain: no thread should have been spawned for the rejected inputs.
    server.bg_tasks.awaitAll();
    try testing.expectEqual(@as(u32, 0), server.bg_tasks.inFlight());
}
