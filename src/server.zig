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
const UdpTransport = @import("transport.zig").UdpTransport;
const TcpTransport = @import("tcp_transport.zig").TcpTransport;
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
const AnyUdpTransport = @import("transport.zig").AnyUdpTransport;
const AnyTcpTransport = @import("tcp_transport.zig").AnyTcpTransport;
const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const BlockingTcpTransport = @import("blocking_transport.zig").BlockingTcpTransport;
const TcpConnectionPool = @import("connection_pool.zig").TcpConnectionPool;
const Certificate = std.crypto.Certificate;
const na = @import("net_address.zig");
const sys = @import("sys.zig");
const monotonic = @import("monotonic.zig");

const log = std.log.scoped(.server);

const tcp_idle_timeout_ms: u32 = 5_000;
const max_tcp_queries_per_conn: u32 = 128;

const work_queue_capacity = 256;

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

    pub fn init(allocator: mem.Allocator, cfg: ServerConfig, io: Io) !Server {
        // Randomize hash seeds for cache and dedup tables (hash collision attack defense).
        cache_mod.randomizeHashSeed(io);
        dedup_mod.randomizeHashSeed(io);

        const cache_opts = RRsetCache.CacheOptions{
            .prefetch = cfg.prefetch,
            .serve_stale_ttl = cfg.serve_stale_ttl,
            .min_ttl = cfg.min_ttl,
            .skip_key_types = cfg.dnssec,
        };
        const cache_alloc = if (builtin.single_threaded)
            allocator
        else
            std.heap.smp_allocator;
        const cache = if (cfg.workers > 1)
            RRsetCache.initThreadSafeWithOptions(cache_alloc, cfg.cache_size, cfg.cache_entries, cache_opts, io)
        else
            RRsetCache.initWithOptions(cache_alloc, cfg.cache_size, cfg.cache_entries, cache_opts);

        const rtt_cache = if (cfg.workers > 1)
            RttCache.initThreadSafe(allocator, io)
        else
            RttCache.init(allocator);

        const ns_selector = if (cfg.workers > 1)
            NsSelector.initThreadSafe(allocator, io)
        else
            NsSelector.init(allocator, io);

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
            .nsec_cache = if (cfg.dnssec) blk: {
                const nsec_alloc = if (builtin.single_threaded) allocator else std.heap.smp_allocator;
                break :blk if (cfg.workers > 1)
                    NsecCache.initThreadSafe(nsec_alloc, NsecCache.default_max_bytes, io)
                else
                    NsecCache.init(nsec_alloc, NsecCache.default_max_bytes);
            } else null,
            .key_cache = if (cfg.dnssec) blk: {
                break :blk if (cfg.workers > 1)
                    RRsetCache.initThreadSafe(cache_alloc, cfg.key_cache_size, cfg.key_cache_entries, io)
                else
                    RRsetCache.init(cache_alloc, cfg.key_cache_size, cfg.key_cache_entries);
            } else null,
            .shutdown = std.atomic.Value(bool).init(false),
            .worker_errors = std.atomic.Value(u32).init(0),
        };
    }

    pub fn deinit(self: *Server) void {
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
                t.* = std.Thread.spawn(.{}, workerThread, .{ self, listen_addrs }) catch |err| {
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
        log.info("cache stats: {d} entries, {d} bytes, {d} hits, {d} misses ({d}% hit rate), {d} evictions, {d} prefetch-eligible, {d} stale", .{
            stats.entries, stats.memory_bytes, stats.hits, stats.misses, hit_pct, stats.evictions, stats.prefetch_eligible, stats.stale_hits,
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
    }

    fn workerThread(self: *Server, listen_addrs: []const na.Address) void {
        self.runWorker(listen_addrs, -1, true);
    }

    fn runWorker(self: *Server, listen_addrs: []const na.Address, sig_fd: posix.fd_t, reuseport: bool) void {
        // Per-thread EventLoop for server accept/recv
        const server_loop = EventLoop.create(self.allocator) catch |err| {
            log.err("worker failed to create event loop: {s}", .{@errorName(err)});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            return;
        };
        defer server_loop.destroy();

        // Separate EventLoop for outbound resolution queries.
        // The resolver's tick()/flush() must not interfere with the
        // server's pending accept/signalfd operations.
        const transport_loop = EventLoop.create(self.allocator) catch |err| {
            log.err("worker failed to create transport event loop: {s}", .{@errorName(err)});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            return;
        };
        defer transport_loop.destroy();

        // Per-thread outbound transport (uses its own loop)
        var udp_transport = UdpTransport.init(transport_loop, .{}, self.io) catch |err| {
            log.err("worker failed to create UDP transport: {s}", .{@errorName(err)});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            return;
        };
        defer udp_transport.deinit();

        var tcp_transport = TcpTransport.init(transport_loop, .{});

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
        var any_ok = false;
        for (0..listen_addrs.len) |i| {
            if (udp_socks[i] >= 0) {
                any_ok = true;
                break;
            }
        }
        if (!any_ok) {
            log.err("worker failed to bind any listen address", .{});
            _ = self.worker_errors.fetchAdd(1, .monotonic);
            return;
        }

        // Per-worker TLS transport (shares encrypted_ns_cache + pool across workers)
        var tls_transport = TlsTransport.init(transport_loop, self.allocator, .{}, self.ca_bundle, self.io);
        if (self.enc_pool) |*pool| tls_transport.pool = pool;

        var queue = WorkQueue{ .io = self.io };

        // Per-worker Do53 TCP connection pool (RFC 7766)
        var do53_tcp_pool = TcpConnectionPool.init(self.allocator, self.io);
        defer do53_tcp_pool.deinit();

        // Worker state
        var ws = WorkerState{
            .config = &self.config,
            .allocator = self.allocator,
            .io = self.io,
            .loop = server_loop,
            .udp_transport = &udp_transport,
            .tcp_transport = &tcp_transport,
            .tls_transport = if (self.config.opportunistic) &tls_transport else null,
            .encrypted_ns_cache = if (self.encrypted_ns_cache) |*oc| oc else null,
            .cache = &self.cache,
            .key_cache = if (self.key_cache) |*kc| kc else null,
            .rtt_cache = &self.rtt_cache,
            .ns_selector = &self.ns_selector,
            .dedup = if (self.dedup) |*d| d else null,
            .nsec_cache = if (self.nsec_cache) |*nc| nc else null,
            .shutdown = &self.shutdown,
            .queue = &queue,
            .ca_bundle = self.ca_bundle,
            .tcp_pool = &do53_tcp_pool,
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

        // Ensure background probe threads that captured &tls_transport complete
        // before the stack-allocated TlsTransport is destroyed.
        if (self.encrypted_ns_cache) |*enc| enc.awaitProbes();
    }
};

// ── WorkerState ────────────────────────────────────────────────────────
// Per-thread state that handles the actual serve loop.

const WorkerState = struct {
    config: *const ServerConfig,
    allocator: mem.Allocator,
    io: Io,
    loop: *EventLoop,
    udp_transport: *UdpTransport,
    tcp_transport: *TcpTransport,
    tls_transport: ?*TlsTransport,
    encrypted_ns_cache: ?*EncryptedNsCache,
    cache: *RRsetCache,
    key_cache: ?*RRsetCache,
    rtt_cache: *RttCache,
    ns_selector: *NsSelector,
    dedup: ?*InFlightTable,
    nsec_cache: ?*NsecCache,
    shutdown: *std.atomic.Value(bool),
    queue: *WorkQueue,
    ca_bundle: Certificate.Bundle,
    tcp_pool: ?*TcpConnectionPool = null,

    /// Create a per-query memory cap. When the limit is hit, arena returns
    /// OutOfMemory and existing error handling sends SERVFAIL.
    fn queryCap(self: *WorkerState) CountingAllocator {
        const limit = self.config.query_memory_limit;
        return CountingAllocator.init(self.allocator, if (limit > 0) limit else std.math.maxInt(usize));
    }

    fn serveLoop(self: *WorkerState, udp_socks: []const posix.fd_t, tcp_socks: []const posix.fd_t, sig_fd: posix.fd_t) void {
        const n = udp_socks.len;

        var udp_ctxs: [max_listen_addrs]Ctx = undefined;
        var tcp_ctxs: [max_listen_addrs]Ctx = undefined;
        var signal_ctx = Ctx{ .tag = .signal, .fd = sig_fd };

        // Op IDs indexed by listen address; null means inactive
        var udp_ops: [max_listen_addrs]?OperationId = .{null} ** max_listen_addrs;
        var tcp_ops: [max_listen_addrs]?OperationId = .{null} ** max_listen_addrs;

        // Register recvFrom for each UDP socket
        for (udp_socks, 0..) |fd, i| {
            if (fd < 0) continue;
            udp_ctxs[i] = .{ .tag = .udp_recv, .fd = fd };
            udp_ops[i] = self.loop.recvFrom(fd, @ptrCast(&udp_ctxs[i])) catch |err| blk: {
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
                            },
                            else => {},
                        }
                        if (!self.shutdown.load(.acquire)) {
                            // Find which index this ctx belongs to and re-register
                            const idx = ctxIndex(&udp_ctxs, n, ctx) orelse continue;
                            udp_ops[idx] = self.loop.recvFrom(ctx.fd, @ptrCast(ctx)) catch |err| {
                                log.err("failed to re-register UDP recvFrom: {s}", .{@errorName(err)});
                                udp_ops[idx] = null;
                                continue;
                            };
                        }
                    },
                    .tcp_accept => {
                        switch (c.result) {
                            .accept => |acc| {
                                if (acc.err == null and acc.fd >= 0) {
                                    self.handleTcpClient(acc.fd);
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

    fn sendErrorUdp(sock: posix.fd_t, id: u16, rcode: dns.RCode, rd: bool, questions: []const dns.Question, client_addr: na.Address) void {
        var wire_buf: [512]u8 = undefined;
        if (serializeErrorResponse(&wire_buf, id, rcode, rd, questions)) |wire| {
            sendUdpResponse(sock, wire, client_addr);
        }
    }

    fn handleUdpQuery(self: *WorkerState, sock: posix.fd_t, data: []const u8, client_addr: na.Address) void {
        if (data.len < 12) return;
        const id = mem.readInt(u16, data[0..2], .big);
        const rd = data[2] & 0x01 != 0; // RFC 1035 §4.1.1: echo RD in response
        // Pre-validate from raw header bytes to avoid wasting pool threads
        // on garbage: opcode (bits 1-4 of byte 2), qdcount (bytes 4-5).
        const opcode: u4 = @truncate(data[2] >> 3);
        if (opcode != 0) { // Only QUERY (0) supported
            sendErrorUdp(sock, id, .not_implemented, rd, &.{}, client_addr);
            return;
        }
        const qdcount = mem.readInt(u16, data[4..6], .big);
        if (qdcount != 1) {
            sendErrorUdp(sock, id, .format_error, rd, &.{}, client_addr);
            return;
        }
        if (!self.queue.push(data, client_addr, sock, .udp)) {
            log.warn("resolution queue full, dropping query", .{});
            sendErrorUdp(sock, id, .server_failure, rd, &.{}, client_addr);
        }
    }

    fn handleTcpClient(self: *WorkerState, client_fd: posix.fd_t) void {
        defer sys.close(client_fd);

        // Switch accepted fd to blocking mode with idle timeout.
        // This avoids calling tick() on the server_loop, which would steal
        // completions for accept/recvFrom/signalfd and cause a deadlock.
        const flags = sys.fcntl(client_fd, posix.F.GETFL, 0) catch return;
        const nonblock_bit = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
        _ = sys.fcntl(client_fd, posix.F.SETFL, flags & ~nonblock_bit) catch return;

        sys.setSocketTimeouts(client_fd, tcp_idle_timeout_ms);

        var tcp_queries: u32 = 0;
        while (!self.shutdown.load(.acquire) and tcp_queries < max_tcp_queries_per_conn) {
            tcp_queries += 1;
            var len_buf: [2]u8 = undefined;
            tcpReadExactBlocking(client_fd, &len_buf) orelse return;
            const msg_len = mem.readInt(u16, &len_buf, .big);
            if (msg_len == 0) return;

            var query_buf: [65535]u8 = undefined;
            tcpReadExactBlocking(client_fd, query_buf[0..msg_len]) orelse return;

            var cap = self.queryCap();
            var arena = std.heap.ArenaAllocator.init(cap.allocator());
            defer arena.deinit();
            const alloc = arena.allocator();
            var response_wire: [65535]u8 = undefined;
            const data = query_buf[0..msg_len];

            const query = dns.parseMessage(alloc, data) catch {
                if (data.len >= 2) {
                    const id = mem.readInt(u16, data[0..2], .big);
                    const w = serializeErrorResponse(&response_wire, id, .format_error, false, &.{}) orelse return;
                    tcpWriteMessage(client_fd, w) orelse return;
                    continue;
                }
                return;
            };

            if (validateQuery(query)) |rcode| {
                const w = serializeErrorResponse(&response_wire, query.header.id, rcode, query.header.rd, query.questions) orelse return;
                tcpWriteMessage(client_fd, w) orelse return;
                continue;
            }

            const question = query.questions[0];
            const name_buf = question.name.format();
            const name_len = mem.indexOfScalar(u8, &name_buf, 0) orelse name_buf.len;
            const name_str = name_buf[0..name_len];

            const start_ns = monotonic.nowNs();
            const result = self.resolveWithDedup(alloc, name_str, question.qtype, query.header.cd) catch |err| {
                const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
                var qtype_buf: [24]u8 = undefined;
                log.warn("{s} {s} SERVFAIL {d}ms (tcp, {s})", .{ name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf), elapsed_ms, @errorName(err) });
                const w = serializeErrorResponse(&response_wire, query.header.id, .server_failure, query.header.rd, query.questions) orelse return;
                tcpWriteMessage(client_fd, w) orelse return;
                continue;
            };
            const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
            var qtype_buf: [24]u8 = undefined;
            var rcode_buf: [24]u8 = undefined;
            log.debug("{s} {s} {s} {d}ms (tcp)", .{ name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf), dns.safeTagName(dns.RCode, result.message.header.rcode, &rcode_buf), elapsed_ms });

            const wire = buildResponseWire(&response_wire, ResponseContext.fromQuery(query, 65535), result.message, alloc) orelse return;
            tcpWriteMessage(client_fd, wire) orelse return;

            if (result.prefetch_name) |prefetch_name| {
                self.doPrefetch(prefetch_name, result.prefetch_qtype);
            }
            if (result.prefetch_dnskey_zone) |zone| {
                self.doPrefetch(zone, .dnskey);
            }
        }
    }

    fn resolveWithDedup(self: *WorkerState, alloc: mem.Allocator, name: []const u8, qtype: dns.RType, cd: bool) !recursive.RecursiveResolver.ResolveResult {
        return self.resolveWithDedupUsing(alloc, name, qtype, cd, .{ .uring = self.udp_transport }, .{ .uring = self.tcp_transport }, self.tls_transport);
    }

    fn resolveQueryWith(
        self: *WorkerState,
        alloc: mem.Allocator,
        name: []const u8,
        qtype: dns.RType,
        cd: bool,
        bypass_cache: bool,
        udp: AnyUdpTransport,
        tcp: AnyTcpTransport,
        tls: ?*TlsTransport,
    ) !recursive.RecursiveResolver.ResolveResult {
        switch (self.config.mode) {
            .recursive => {
                var resolver = RecursiveResolver{
                    .transport = udp,
                    .tcp_transport = tcp,
                    .io = self.io,
                    .cache = self.cache,
                    .qname_minimisation = self.config.qname_minimization,
                    // RFC 4035 §3.2.1: always request DNSSEC data (DO bit) if capable
                    .dnssec_aware = self.config.dnssec,
                    // RFC 4035 §3.2.2: CD=1 means client handles validation — skip ours
                    .dnssec_enabled = self.config.dnssec and !cd,
                    .tls_transport = tls,
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
                var resolver = ForwardingResolver.initWithTcp(udp, tcp);
                resolver.io = self.io;
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

    fn doPrefetch(self: *WorkerState, prefetch_name: []const u8, prefetch_qtype: dns.RType) void {
        self.doPrefetchWith(prefetch_name, prefetch_qtype, .{ .uring = self.udp_transport }, .{ .uring = self.tcp_transport }, self.tls_transport);
    }

    fn doPrefetchWith(self: *WorkerState, prefetch_name: []const u8, prefetch_qtype: dns.RType, udp: AnyUdpTransport, tcp: AnyTcpTransport, tls: ?*TlsTransport) void {
        var cap = self.queryCap();
        var prefetch_arena = std.heap.ArenaAllocator.init(cap.allocator());
        defer prefetch_arena.deinit();
        _ = self.resolveQueryWith(prefetch_arena.allocator(), prefetch_name, prefetch_qtype, false, true, udp, tcp, tls) catch {};
    }

    /// Resolution thread pool entry point.
    fn poolThread(self: *WorkerState) void {
        var udp_t = BlockingUdpTransport.init(.{}, self.io);
        var tcp_t = BlockingTcpTransport.init(.{});

        // Pool threads use queryOpportunisticBlocking (blocking TCP connect),
        // so no EventLoop is needed. Passing null ensures connectTcp panics
        // if accidentally called from a pool thread.
        var tls_t: ?TlsTransport = if (self.config.opportunistic) blk: {
            var t = TlsTransport.init(null, self.allocator, .{}, self.ca_bundle, self.io);
            if (self.tls_transport) |main_tls| {
                t.pool = main_tls.pool;
            }
            break :blk t;
        } else null;

        while (self.queue.pop()) |item| {
            switch (item.protocol) {
                .udp => self.processUdpQuery(
                    item.sock_fd,
                    item.query_buf[0..item.query_len],
                    item.client_addr,
                    &udp_t,
                    &tcp_t,
                    if (tls_t) |*t| t else null,
                ),
                .tcp => {}, // TCP clients still handled on io_uring worker thread (handleTcpClient)
            }
        }
    }

    fn processUdpQuery(
        self: *WorkerState,
        sock: posix.fd_t,
        data: []const u8,
        client_addr: na.Address,
        udp_t: *BlockingUdpTransport,
        tcp_t: *BlockingTcpTransport,
        tls_t: ?*TlsTransport,
    ) void {
        var cap = self.queryCap();
        var arena = std.heap.ArenaAllocator.init(cap.allocator());
        defer arena.deinit();
        const alloc = arena.allocator();

        const query_msg = dns.parseMessage(alloc, data) catch {
            if (data.len >= 2) {
                const id = mem.readInt(u16, data[0..2], .big);
                sendErrorUdp(sock, id, .format_error, false, &.{}, client_addr);
            }
            return;
        };

        if (validateQuery(query_msg)) |rcode| {
            sendErrorUdp(sock, query_msg.header.id, rcode, query_msg.header.rd, query_msg.questions, client_addr);
            return;
        }

        const question = query_msg.questions[0];
        const name_buf = question.name.format();
        const name_len = mem.indexOfScalar(u8, &name_buf, 0) orelse name_buf.len;
        const name_str = name_buf[0..name_len];

        const max_payload: u16 = if (query_msg.opt) |opt| @max(opt.udp_payload_size, dns.max_udp_payload) else dns.max_udp_payload;

        const start_ns = monotonic.nowNs();
        const result = self.resolveWithDedupUsing(alloc, name_str, question.qtype, query_msg.header.cd, .{ .blocking = udp_t }, .{ .blocking = tcp_t }, tls_t) catch |err| {
            const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
            var qtype_buf1: [24]u8 = undefined;
            log.warn("{s} {s} SERVFAIL {d}ms ({s})", .{ name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf1), elapsed_ms, @errorName(err) });
            sendErrorUdp(sock, query_msg.header.id, .server_failure, query_msg.header.rd, query_msg.questions, client_addr);
            return;
        };
        const elapsed_ms: i64 = @intCast(@divFloor(monotonic.nowNs() - start_ns, 1_000_000));
        var qtype_buf2: [24]u8 = undefined;
        var rcode_buf2: [24]u8 = undefined;
        log.debug("{s} {s} {s} {d}ms", .{ name_str, dns.safeTagName(dns.RType, question.qtype, &qtype_buf2), dns.safeTagName(dns.RCode, result.message.header.rcode, &rcode_buf2), elapsed_ms });

        var wire_buf: [65535]u8 = undefined;
        if (buildResponseWire(&wire_buf, ResponseContext.fromQuery(query_msg, max_payload), result.message, alloc)) |wire| {
            sendUdpResponse(sock, wire, client_addr);
        }

        if (result.prefetch_name) |prefetch_name| {
            self.doPrefetchWith(prefetch_name, result.prefetch_qtype, .{ .blocking = udp_t }, .{ .blocking = tcp_t }, tls_t);
        }
        if (result.prefetch_dnskey_zone) |zone| {
            self.doPrefetchWith(zone, .dnskey, .{ .blocking = udp_t }, .{ .blocking = tcp_t }, tls_t);
        }
    }

    fn resolveWithDedupUsing(
        self: *WorkerState,
        alloc: mem.Allocator,
        name: []const u8,
        qtype: dns.RType,
        cd: bool,
        udp: AnyUdpTransport,
        tcp: AnyTcpTransport,
        tls: ?*TlsTransport,
    ) !recursive.RecursiveResolver.ResolveResult {
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
        const result = try self.resolveQueryWith(alloc, name, qtype, cd, false, udp, tcp, tls);
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

fn serializeErrorResponse(wire_buf: []u8, query_id: u16, rcode: dns.RCode, rd: bool, questions: []const dns.Question) ?[]const u8 {
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
    };
    return dns.serializeMessage(wire_buf, msg) catch null;
}

// ── TCP helpers (blocking I/O) ─────────────────────────────────────────

fn tcpReadExactBlocking(fd: posix.fd_t, buf: []u8) ?void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = sys.read(fd, buf[total..]) catch return null;
        if (n == 0) return null; // connection closed
        total += n;
    }
}

fn tcpWriteAllBlocking(fd: posix.fd_t, data: []const u8) ?void {
    var total: usize = 0;
    while (total < data.len) {
        const n = sys.write(fd, data[total..]) catch return null;
        total += n;
    }
}

fn validateQuery(query: dns.Message) ?dns.RCode {
    if (query.header.opcode != .query) return .not_implemented;
    if (query.questions.len != 1) return .format_error;
    if (query.questions[0].qclass != .in) return .refused;
    return null;
}

fn tcpWriteMessage(fd: posix.fd_t, data: []const u8) ?void {
    var len_prefix: [2]u8 = undefined;
    mem.writeInt(u16, &len_prefix, @intCast(data.len), .big);
    tcpWriteAllBlocking(fd, &len_prefix) orelse return null;
    tcpWriteAllBlocking(fd, data) orelse return null;
}

fn sendUdpResponse(sock: posix.fd_t, data: []const u8, dest: na.Address) void {
    // Use direct sendto instead of io_uring to avoid consuming server CQEs
    // (accept, signalfd) that might arrive during the send.
    var storage: na.PosixAddress = undefined;
    const sa_len = na.toSockaddr(&dest, &storage);
    _ = sys.sendto(sock, data, 0, &storage.any, sa_len) catch return;
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

fn setV6Only(sock: posix.fd_t, af: u32) !void {
    if (af == posix.AF.INET6) {
        const v6only: c_int = 1;
        try posix.setsockopt(sock, posix.SOL.IPV6, linux.IPV6.V6ONLY, &mem.toBytes(v6only));
    }
}

// ── Socket creation ────────────────────────────────────────────────────

fn createSocket(addr: na.Address, sock_type: u32, reuseport: bool, listen_flag: bool) !posix.fd_t {
    const af = na.afU32(addr);
    const sock = try sys.socket(af, sock_type | posix.SOCK.NONBLOCK, 0);
    errdefer sys.close(sock);

    try setV6Only(sock, af);
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

    var buf: [512]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x1234,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = false,
        .client_do = false,
        .client_wants_ad = false,
        .max_payload = 512,
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

    var buf: [1232]u8 = undefined;
    const wire = buildResponseWire(&buf, .{
        .query_id = 0x5678,
        .rd = true,
        .cd = false,
        .questions = questions,
        .client_edns = true,
        .client_do = false,
        .client_wants_ad = false,
        .max_payload = 1232,
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

    var buf: [512]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0xABCD, .refused, true, questions).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expectEqual(@as(u16, 0xABCD), parsed.header.id);
    try testing.expectEqual(dns.RCode.refused, parsed.header.rcode);
    try testing.expectEqual(true, parsed.header.rd);
    try testing.expectEqual(true, parsed.header.ra);
    try testing.expectEqual(true, parsed.header.qr);
    try testing.expectEqual(@as(u16, 1), parsed.header.qd_count);
}

test "serializeErrorResponse with no question (parse failure)" {
    var buf: [512]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0x1234, .format_error, false, &.{}).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try testing.expectEqual(dns.RCode.format_error, parsed.header.rcode);
    try testing.expectEqual(@as(u16, 0), parsed.header.qd_count);
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
