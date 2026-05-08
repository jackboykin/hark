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
const CaseState = @import("case_state.zig").CaseState;
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
const response = @import("response.zig");
const ResponseContext = response.ResponseContext;
const buildResponseWire = response.buildResponseWire;
const serializeErrorResponse = response.serializeErrorResponse;
const validateQuery = response.validateQuery;
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

/// Buffer slot for a queued query. Sized for any reasonable Do53 wire
/// query (RFC 1035 caps QNAME at 255 bytes; with EDNS this fits well
/// under 4 KiB). Dispatch ignores items > this on push.
const max_work_query_bytes = 4096;

const WorkItem = struct {
    query_buf: [max_work_query_bytes]u8 = undefined,
    query_len: u16 = 0,
    client_addr: na.Address = na.initIp4(.{ 0, 0, 0, 0 }, 0),
    sock_fd: posix.fd_t = -1,
    protocol: Protocol = .udp,
    const Protocol = enum { udp, tcp };
};

/// What `pop` hands back: small metadata + a slice into the caller's
/// scratch buffer holding the live query bytes only. Avoids a 4 KiB
/// by-value copy of WorkItem on every dispatch.
const PopResult = struct {
    query_data: []const u8,
    client_addr: na.Address,
    sock_fd: posix.fd_t,
    protocol: WorkItem.Protocol,
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
        if (data.len > max_work_query_bytes) return false;
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

    /// Pop a slot, copying only the live query bytes into `scratch` so we
    /// can release the slot for re-push immediately. The returned slice
    /// borrows from `scratch` and is valid until the next `pop` on the
    /// same buffer.
    fn pop(self: *WorkQueue, scratch: *[max_work_query_bytes]u8) ?PopResult {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.count == 0 and !self.shutdown) {
            self.not_empty.waitUncancelable(self.io, &self.mutex);
        }
        if (self.count == 0) return null;
        const slot = &self.items[self.head];
        const len = slot.query_len;
        @memcpy(scratch[0..len], slot.query_buf[0..len]);
        const result = PopResult{
            .query_data = scratch[0..len],
            .client_addr = slot.client_addr,
            .sock_fd = slot.sock_fd,
            .protocol = slot.protocol,
        };
        self.head = (self.head + 1) % work_queue_capacity;
        self.count -= 1;
        return result;
    }

    fn signalShutdown(self: *WorkQueue) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.shutdown = true;
        self.not_empty.broadcast(self.io);
    }
};

// ── Context tags for the event loop ────────────────────────────────────

const CtxTag = enum { udp_recv, tcp_accept, signal, wake };

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
            // .acq_rel on success: the release publishes our bump so awaitAll's
            // acquire-load sees it; the acquire pairs with the post-bump
            // shutdown re-check below.
            if (self.active.cmpxchgStrong(cur, cur + 1, .acq_rel, .monotonic) == null) {
                // Re-check shutdown after the bump landed. Between our pre-check
                // and CAS, awaitAll may have set shutting_down and observed
                // inFlight==0 (because our bump hadn't published yet) and
                // exited. If shutdown is now set, roll back so we don't spawn
                // into torn-down server state.
                if (self.shutting_down.load(.acquire)) {
                    _ = self.active.fetchSub(1, .release);
                    return false;
                }
                return true;
            }
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
    ///
    /// The poll-sleep is load-bearing for `tryClaim`'s rollback contract: a
    /// CAS bump can land after `shutting_down` is set, so the poll must
    /// observe the transient bump and wait for the subsequent rollback
    /// decrement that the post-CAS re-check performs. A single-shot wait
    /// (e.g. condvar) would re-open the race.
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
    case_state: ?CaseState,
    enc_pool: ?ConnectionPool,
    nsec_cache: ?NsecCache,
    key_cache: ?RRsetCache,
    /// Hot atomics — each on its own cache line to avoid false sharing.
    /// `shutdown` is read every tick by every worker; the *_drops counters
    /// are written by every worker on contention events. Without padding,
    /// the read on `shutdown` would invalidate alongside writes to the
    /// drop counters and bounce cache lines across cores.
    shutdown: std.atomic.Value(bool) align(std.atomic.cache_line),
    worker_errors: std.atomic.Value(u32) align(std.atomic.cache_line),
    udp_queue_drops: std.atomic.Value(u64) align(std.atomic.cache_line),
    tcp_queue_drops: std.atomic.Value(u64) align(std.atomic.cache_line),
    udp_send_drops: std.atomic.Value(u64) align(std.atomic.cache_line),
    /// One eventfd per worker. Only the main worker reads the signalfd;
    /// without per-worker wakes, peers would block in io_uring_enter forever
    /// waiting for a CQE that never arrives (no traffic = no wake). Spawned
    /// workers take indices [0..workers-1]; the main thread takes the last.
    wake_fds: []posix.fd_t,
    /// Number of workers that have finished binding their listen sockets.
    /// Each worker drops privileges itself once this reaches `workers`.
    bound_count: std.atomic.Value(u32) align(std.atomic.cache_line) = std.atomic.Value(u32).init(0),
    bg_tasks: BackgroundTasks = .{},

    pub fn init(allocator: mem.Allocator, cfg: ServerConfig, io: Io) !Server {
        // Randomize hash seeds for cache, dedup, and AddressKey-keyed tables
        // (RttCache, NsSelector arms) so an authoritative can't engineer
        // bucket collisions via crafted glue addresses or query keys.
        cache_mod.randomizeHashSeed(io);
        dedup_mod.randomizeHashSeed(io);
        na.randomizeHashSeed(io);

        const cache_alloc = if (builtin.single_threaded)
            allocator
        else
            std.heap.smp_allocator;
        var cache = RRsetCache.init(.{
            .backing = cache_alloc,
            .max_bytes = cfg.cache_size,
            .max_entries = cfg.cache_entries,
            .io = io,
            .prefetch = cfg.prefetch,
            .serve_stale_ttl = cfg.serve_stale_ttl,
            .min_ttl = cfg.min_ttl,
            .skip_key_types = cfg.dnssec,
        });
        errdefer cache.deinit();

        var rtt_cache = RttCache.init(.{
            .allocator = allocator,
            .io = io,
            .thread_safe = cfg.workers > 1,
        });
        errdefer rtt_cache.deinit();

        var ns_selector = NsSelector.init(.{
            .allocator = allocator,
            .io = io,
            .thread_safe = cfg.workers > 1,
        });
        errdefer ns_selector.deinit();

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
            .case_state = if (cfg.case_randomization and cfg.mode == .recursive) CaseState.init(allocator, io) else null,
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
            }) else null,
            .shutdown = std.atomic.Value(bool).init(false),
            .worker_errors = std.atomic.Value(u32).init(0),
            .udp_queue_drops = std.atomic.Value(u64).init(0),
            .tcp_queue_drops = std.atomic.Value(u64).init(0),
            .udp_send_drops = std.atomic.Value(u64).init(0),
            .wake_fds = try createWakeFds(allocator, cfg.workers),
        };
    }

    pub fn deinit(self: *Server) void {
        // awaitProbes MUST precede ca_bundle.deinit: each probe holds a
        // by-value TlsTransport whose ca_bundle slices alias this owner.
        self.bg_tasks.awaitAll();
        if (self.encrypted_ns_cache) |*oc| {
            oc.awaitProbes();
            oc.deinit();
        }
        if (self.case_state) |*cs| cs.deinit();
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
        for (self.wake_fds) |fd| if (fd >= 0) sys.close(fd);
        self.allocator.free(self.wake_fds);
    }

    /// Flip the shared shutdown atomic and post a wake to every worker's
    /// eventfd. Idempotent and safe from any thread; over-posting is harmless
    /// because each fd's counter accumulates and is drained on close.
    fn requestShutdown(self: *Server) void {
        self.shutdown.store(true, .release);
        for (self.wake_fds) |fd| wakeWorker(fd);
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
            self.runWorker(listen_addrs, sig_fd, self.wake_fds[0], false);
        } else {
            log.info("{d} workers", .{workers});

            // Spawn N-1 worker threads + run one on main thread. Spawned
            // workers take wake_fds[0..workers-1]; main takes the last slot.
            const threads = self.allocator.alloc(std.Thread, workers - 1) catch |err| {
                log.err("failed to allocate thread array: {s}", .{@errorName(err)});
                return err;
            };
            defer self.allocator.free(threads);

            for (threads, 0..) |*t, i| {
                t.* = std.Thread.spawn(.{}, runWorker, .{ self, listen_addrs, @as(posix.fd_t, -1), self.wake_fds[i], true }) catch |err| {
                    log.err("failed to spawn worker {d}: {s}", .{ i + 1, @errorName(err) });
                    self.requestShutdown();
                    for (threads[0..i]) |prev| prev.join();
                    return err;
                };
            }

            // Main thread runs a worker too, with signalfd for shutdown
            self.runWorker(listen_addrs, sig_fd, self.wake_fds[workers - 1], true);

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

    fn runWorker(self: *Server, listen_addrs: []const na.Address, sig_fd: posix.fd_t, wake_fd: posix.fd_t, reuseport: bool) void {
        // Wake every peer out of the bound_count barrier and the io_uring
        // tick if this worker dies before reaching serveLoop.
        var failed = false;
        defer if (failed) self.requestShutdown();

        // Per-thread EventLoop for server accept/recv
        const server_loop = EventLoop.create(self.allocator) catch |err| {
            log.err("worker failed to create event loop: {s}", .{@errorName(err)});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            _ = self.bound_count.fetchAdd(1, .release);
            failed = true;
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
            _ = self.bound_count.fetchAdd(1, .release);
            failed = true;
            return;
        }

        _ = self.bound_count.fetchAdd(1, .release);

        // setresuid is per-thread on Linux without libc's SIGSETXID broadcast,
        // so every worker drops independently after the last peer binds.
        if (self.config.drop_gid != null or self.config.drop_uid != null) {
            const ts = std.os.linux.timespec{ .sec = 0, .nsec = 1_000_000 };
            while (self.bound_count.load(.acquire) < self.config.workers and
                !self.shutdown.load(.acquire))
            {
                _ = std.os.linux.nanosleep(&ts, null);
            }
            if (self.shutdown.load(.acquire)) return;
            dropPrivileges(self.config.drop_gid, self.config.drop_uid) catch |err| {
                log.err("failed to drop privileges: {s}", .{@errorName(err)});
                _ = self.worker_errors.fetchAdd(1, .monotonic);
                self.requestShutdown();
                return;
            };
            const is_main = sig_fd >= 0;
            if (is_main) {
                if (self.config.drop_gid) |g| log.info("dropped group to gid={d}", .{g});
                if (self.config.drop_uid) |u| log.info("dropped user to uid={d}", .{u});
            }
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
            .case_state = if (self.case_state) |*cs| cs else null,
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
            failed = true;
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
            failed = true;
            return;
        }

        ws.serveLoop(udp_socks[0..listen_addrs.len], tcp_socks[0..listen_addrs.len], sig_fd, wake_fd);

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
        .case_state = if (server.case_state) |*cs| cs else null,
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
    case_state: ?*CaseState,
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

    fn logCacheStats(self: *const WorkerState) void {
        const stats = self.cache.getStats();
        const hit_total = stats.hits + stats.misses;
        const hit_pct: u64 = if (hit_total > 0) stats.hits * 100 / hit_total else 0;
        log.info("cache: {d} entries, {d}/{d} bytes, {d}% hit rate, {d} evictions", .{
            stats.entries, stats.memory_bytes, stats.max_bytes, hit_pct, stats.evictions,
        });
    }

    fn serveLoop(self: *WorkerState, udp_socks: []const posix.fd_t, tcp_socks: []const posix.fd_t, sig_fd: posix.fd_t, wake_fd: posix.fd_t) void {
        const n = udp_socks.len;

        var udp_ctxs: [max_listen_addrs]Ctx = undefined;
        var tcp_ctxs: [max_listen_addrs]Ctx = undefined;
        var signal_ctx = Ctx{ .tag = .signal, .fd = sig_fd };
        var wake_ctx = Ctx{ .tag = .wake, .fd = wake_fd };

        // Op IDs indexed by listen address; null means inactive
        var udp_ops: [max_listen_addrs]?OperationId = .{null} ** max_listen_addrs;
        var tcp_ops: [max_listen_addrs]?OperationId = .{null} ** max_listen_addrs;

        // Multishot recvmsg — one SQE per socket stays armed and produces
        // CQEs for every inbound packet until the kernel terminates it.
        for (udp_socks, 0..) |fd, i| {
            if (fd < 0) continue;
            udp_ctxs[i] = .{ .tag = .udp_recv, .fd = fd };
            udp_ops[i] = self.loop.recvFromMulti(fd, @ptrCast(&udp_ctxs[i])) catch |err| blk: {
                log.err("failed to register UDP recvmsg: {s}", .{@errorName(err)});
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

        // Every worker reads its own wake eventfd. requestShutdown writes 1
        // to each fd, so each worker's tick() returns with no need to
        // reason about who else is consuming. If the read can't be
        // registered the worker would block in tick forever on shutdown —
        // escalate to a process-wide shutdown so peers exit.
        if (wake_fd >= 0) {
            _ = self.loop.read(wake_fd, @ptrCast(&wake_ctx)) catch |err| {
                log.err("failed to register wake_fd read: {s}", .{@errorName(err)});
                self.server.requestShutdown();
                return;
            };
        }

        var completions: [max_operations]Completion = undefined;
        var last_stats_ns: i128 = monotonic.nowNs();
        const stats_interval_ns: i128 = 60 * std.time.ns_per_s;

        while (!self.shutdown.load(.acquire)) {
            const results = self.loop.tick(&completions) catch break;

            // Periodic cache stats logging
            const now_ns = monotonic.nowNs();
            if (now_ns - last_stats_ns >= stats_interval_ns) {
                self.logCacheStats();
                last_stats_ns = now_ns;
            }

            for (results) |c| {
                const ctx: *Ctx = @ptrCast(@alignCast(c.context));
                switch (ctx.tag) {
                    .signal => switch (classifySignalRead(c.result)) {
                        .stats => {
                            self.logCacheStats();
                            _ = self.loop.read(ctx.fd, @ptrCast(ctx)) catch |err|
                                log.err("failed to re-arm signalfd: {s}", .{@errorName(err)});
                            continue;
                        },
                        .shutdown => {
                            log.info("shutting down", .{});
                            self.server.requestShutdown();
                            break;
                        },
                    },
                    .wake => {
                        // Counterpart wrote to wake_fd — shutdown is in flight.
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
                        udp_ops[idx] = self.loop.recvFromMulti(ctx.fd, @ptrCast(ctx)) catch |err| {
                            log.err("failed to re-register UDP recvmsg: {s}", .{@errorName(err)});
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
                    udp_ops[i] = self.loop.recvFromMulti(udp_ctxs[i].fd, @ptrCast(&udp_ctxs[i])) catch null;
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
        // MSG_DONTWAIT keeps the pool thread off a saturated kernel send buffer.
        // Dropping the response is correct DNS behavior — the client retransmits.
        // All sendto failures (WouldBlock, SystemResources, MessageTooBig, peer
        // resets, etc.) are counted under one drop signal: any send failure is
        // operationally a "response not delivered" event the operator wants to see.
        var storage: na.PosixAddress = undefined;
        const sa_len = na.toSockaddr(&dest, &storage);
        _ = sys.sendto(sock, data, posix.MSG.DONTWAIT, &storage.any, sa_len) catch {
            _ = self.udp_send_drops.fetchAdd(1, .monotonic);
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
            // Silent drop on pool saturation (matches Unbound ip-ratelimit,
            // PowerDNS over-capacity, dnsdist default). A SERVFAIL here
            // would get pinned in every downstream cache for up to 5
            // minutes (RFC 9520), turning a transient queue blip into a
            // multi-minute outage from each client's perspective. Drop
            // applies natural backpressure via the client's retry timeout.
            // Per-drop log stays at debug — under a UDP flood, a warn
            // here would itself become the DoS surface; the
            // `udp_queue_drops` atomic is the operator-facing signal.
            _ = self.udp_queue_drops.fetchAdd(1, .monotonic);
            log.debug("resolution queue full, dropping query", .{});
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

        // A TCP socket's remote address is fixed for its lifetime, so
        // resolve once per connection rather than per query.
        var peer_buf: [64]u8 = undefined;
        const peer_str = if (na.getPeerName(client_fd)) |peer|
            na.format(peer, &peer_buf)
        else |_|
            "?";

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
                log.warn("client={s} id=0x{x:0>4} {s} {s} SERVFAIL {d}ms (tcp, {s})", .{ peer_str, query.header.id, name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf), elapsed_ms, @errorName(err) });
                self.cache.cacheServfail(name_str, question.qtype);
                const w = serializeErrorResponse(&response_wire, query.header.id, .server_failure, 0, query.header.rd, query.questions) orelse return;
                const write_deadline_ns: i128 = monotonic.nowNs() + tcp_idle_timeout_ns;
                tcpWriteMessage(client_fd, w, write_deadline_ns) orelse return;
                continue;
            };
            const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
            var qtype_buf: [24]u8 = undefined;
            var rcode_buf: [24]u8 = undefined;
            log.debug("client={s} id=0x{x:0>4} {s} {s} {s} {d}ms (tcp)", .{ peer_str, query.header.id, name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf), dns.safeTagName(dns.RCode, result.message.header.rcode, &rcode_buf), elapsed_ms });

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
                    .case_state = self.case_state,
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

        var pop_scratch: [max_work_query_bytes]u8 = undefined;
        while (self.queue.pop(&pop_scratch)) |item| {
            switch (item.protocol) {
                .udp => self.processUdpQuery(
                    item.sock_fd,
                    item.query_data,
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

        // Floor at the bare-EDNS-0 minimum, ceiling at the operator-configured
        // server cap. Trusting an unbounded client claim is a reflection-amp
        // surface — the kernel will fragment a 65 kB datagram, but we'd still
        // amplify the wire serialization cost.
        const client_payload = if (query_msg.opt) |opt| opt.udp_payload_size else dns.max_udp_payload;
        const max_payload: u16 = @min(@max(client_payload, dns.max_udp_payload), self.config.max_udp_payload);

        const start_ns = monotonic.nowNs();
        var peer_buf: [64]u8 = undefined;
        const peer_str = na.format(client_addr, &peer_buf);
        const result = self.resolveWithDedupUsing(alloc, name_str, question.qtype, query_msg.header.cd, transports) catch |err| {
            const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
            var qtype_buf1: [24]u8 = undefined;
            log.warn("client={s} id=0x{x:0>4} {s} {s} SERVFAIL {d}ms ({s})", .{ peer_str, query_msg.header.id, name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf1), elapsed_ms, @errorName(err) });
            self.cache.cacheServfail(name_str, question.qtype);
            self.sendErrorUdp(sock, query_msg.header.id, .server_failure, 0, query_msg.header.rd, query_msg.questions, client_addr);
            return;
        };
        const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
        var qtype_buf2: [24]u8 = undefined;
        var rcode_buf2: [24]u8 = undefined;
        log.debug("client={s} id=0x{x:0>4} {s} {s} {s} {d}ms", .{ peer_str, query_msg.header.id, name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf2), dns.safeTagName(dns.RCode, result.message.header.rcode, &rcode_buf2), elapsed_ms });

        // 4 KB stack buffer covers EDNS-0 default (1232) and the common
        // operator cap of 4096; larger configured caps fall through to the
        // per-query arena. The 64 KiB frame this used to reserve was a
        // ReleaseSafe memset hotspot and a stack-prologue tax in ReleaseFast.
        var wire_stack: [4096]u8 = undefined;
        const wire_buf: ?[]u8 = if (max_payload <= wire_stack.len)
            wire_stack[0..]
        else
            alloc.alloc(u8, max_payload) catch null;
        if (wire_buf) |buf| {
            if (buildResponseWire(buf, ResponseContext.fromQuery(query_msg, max_payload), result.message, alloc)) |wire| {
                self.sendUdpResponse(sock, wire, client_addr);
            }
        } else {
            self.sendErrorUdp(sock, query_msg.header.id, .server_failure, 0, query_msg.header.rd, query_msg.questions, client_addr);
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
    linux.sigaddset(&mask, linux.SIG.HUP);
    linux.sigaddset(&mask, linux.SIG.USR1);

    // Block signals so they arrive via signalfd
    // SIG_BLOCK = 0 on Linux x86_64
    _ = linux.sigprocmask(0, &mask, null);

    const SFD_NONBLOCK: u32 = 0o4000;
    return posix.signalfd(-1, &mask, SFD_NONBLOCK);
}

const SignalAction = enum { stats, shutdown };

/// Walk every signalfd_siginfo record in the buffer (the kernel can pack
/// many into one read). Shutdown signals win over stats.
fn classifySignalRead(result: anytype) SignalAction {
    const siginfo_size = @sizeOf(linux.signalfd_siginfo);
    const r = switch (result) {
        .read => |x| x,
        else => return .shutdown,
    };
    if (r.err != null) return .shutdown;

    var saw_stats = false;
    var off: usize = 0;
    while (off + 4 <= r.data.len) : (off += siginfo_size) {
        const signo = std.mem.readInt(u32, r.data[off..][0..4], .little);
        if (signo == @intFromEnum(linux.SIG.TERM) or signo == @intFromEnum(linux.SIG.INT)) {
            return .shutdown;
        }
        if (signo == @intFromEnum(linux.SIG.USR1) or signo == @intFromEnum(linux.SIG.HUP)) {
            saw_stats = true;
        }
    }
    return if (saw_stats) .stats else .shutdown;
}

const EFD_NONBLOCK: u32 = 0o4000;

fn makeWakeEventFd() !posix.fd_t {
    const rc = linux.eventfd(0, EFD_NONBLOCK);
    const sr = @as(isize, @bitCast(rc));
    if (sr < 0) return error.EventFdFailed;
    return @intCast(sr);
}

fn createWakeFds(allocator: mem.Allocator, n: usize) ![]posix.fd_t {
    const fds = try allocator.alloc(posix.fd_t, n);
    var created: usize = 0;
    errdefer {
        for (fds[0..created]) |fd| sys.close(fd);
        allocator.free(fds);
    }
    while (created < n) : (created += 1) {
        fds[created] = try makeWakeEventFd();
    }
    return fds;
}

fn wakeWorker(fd: posix.fd_t) void {
    if (fd < 0) return;
    var v: u64 = 1;
    _ = sys.write(fd, std.mem.asBytes(&v)) catch {};
}

/// Drop credentials for the calling thread only (raw syscall). Every worker
/// thread must call this independently — without libc we have no SIGSETXID
/// broadcast to propagate the change across threads.
///
/// Scope: clears supplementary groups, sets r/e/s gid and r/e/s uid. On
/// euid 0 → non-zero the kernel auto-drops the permitted cap set. NOT
/// covered: ambient capabilities, the bounding set, and io_uring kernel
/// io-wq workers (forked at ring creation, before this drop). Operators
/// wanting full credential hygiene should prefer systemd User= /
/// CapabilityBoundingSet= over this in-process drop.
fn dropPrivileges(gid: ?u32, uid: ?u32) !void {
    // Clear supplementary groups while we still have CAP_SETGID. Without
    // this, a process launched as root inherits root's groups (wheel, adm,
    // disk, …) and keeps them after the uid drop. Skip when not root:
    // setgroups would EPERM and there's nothing to clear anyway.
    if (std.os.linux.geteuid() == 0) {
        const rc = if (@hasField(std.os.linux.SYS, "setgroups32"))
            std.os.linux.syscall2(.setgroups32, 0, 0)
        else
            std.os.linux.syscall2(.setgroups, 0, 0);
        if (@as(isize, @bitCast(rc)) != 0) return error.SetGroupsFailed;
    }
    // Drop group first so setgid still has CAP_SETGID. Once setuid runs,
    // the thread loses CAP_SETGID along with the rest of root's caps.
    if (gid) |g| {
        const rc = std.os.linux.setresgid(g, g, g);
        if (rc != 0) return error.SetGidFailed;
    }
    if (uid) |u| {
        const rc = std.os.linux.setresuid(u, u, u);
        if (rc != 0) return error.SetUidFailed;
    }
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

test "wakeWorker delivers a read-ready event" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const fd = try makeWakeEventFd();
    defer sys.close(fd);

    wakeWorker(fd);

    var buf: [8]u8 = undefined;
    const r = try sys.read(fd, &buf);
    try testing.expectEqual(@as(usize, 8), r);

    // Counter drained — subsequent read returns EAGAIN.
    try testing.expectError(error.WouldBlock, sys.read(fd, &buf));
}

test "createWakeFds allocates one eventfd per worker" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const fds = try createWakeFds(testing.allocator, 4);
    defer {
        for (fds) |fd| sys.close(fd);
        testing.allocator.free(fds);
    }
    try testing.expectEqual(@as(usize, 4), fds.len);

    // Wake worker 2 only — its fd reads ready, the others don't.
    wakeWorker(fds[2]);
    var buf: [8]u8 = undefined;
    const r = try sys.read(fds[2], &buf);
    try testing.expectEqual(@as(usize, 8), r);
    for ([_]usize{ 0, 1, 3 }) |i| {
        try testing.expectError(error.WouldBlock, sys.read(fds[i], &buf));
    }
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
