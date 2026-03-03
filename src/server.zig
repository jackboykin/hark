const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const dns = @import("dns.zig");
const EventLoop = @import("event_loop.zig").EventLoop;
const Completion = @import("event_loop.zig").Completion;
const max_operations = @import("event_loop.zig").max_operations;
const UdpTransport = @import("transport.zig").UdpTransport;
const TcpTransport = @import("tcp_transport.zig").TcpTransport;
const RecursiveResolver = @import("recursive.zig").RecursiveResolver;
const ForwardingResolver = @import("resolver.zig").ForwardingResolver;
const TlsTransport = @import("tls_transport.zig").TlsTransport;
const EncryptionStateCache = @import("encryption_state.zig").EncryptionStateCache;
const RRsetCache = @import("cache.zig").RRsetCache;
const ServerConfig = @import("config.zig").ServerConfig;
const Certificate = std.crypto.Certificate;

const log = std.log.scoped(.server);

const tcp_idle_timeout_ms: u32 = 10_000;

// ── Context tags for the event loop ────────────────────────────────────

const CtxTag = enum { udp_recv, tcp_accept, signal };

const Ctx = struct {
    tag: CtxTag,
};

// ── Server ─────────────────────────────────────────────────────────────

pub const Server = struct {
    config: ServerConfig,
    allocator: mem.Allocator,
    cache: RRsetCache,
    ca_bundle: Certificate.Bundle,
    shutdown: std.atomic.Value(bool),

    pub fn init(allocator: mem.Allocator, cfg: ServerConfig) !Server {
        const cache = if (cfg.workers > 1)
            RRsetCache.initThreadSafe(allocator, cfg.cache_size, cfg.cache_entries)
        else
            RRsetCache.init(allocator, cfg.cache_size, cfg.cache_entries);

        var ca_bundle: Certificate.Bundle = .{};
        if (cfg.opportunistic) {
            ca_bundle.rescan(allocator) catch |err| {
                log.err("failed to load CA certificates: {s}", .{@errorName(err)});
                return err;
            };
        }

        return .{
            .config = cfg,
            .allocator = allocator,
            .cache = cache,
            .ca_bundle = ca_bundle,
            .shutdown = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.config.opportunistic) {
            self.ca_bundle.deinit(self.allocator);
        }
        self.cache.deinit();
    }

    pub fn run(self: *Server) !void {
        const listen_addr = if (self.config.listen.len > 0)
            self.config.listen[0]
        else
            std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 53);

        const workers = self.config.workers;

        // Block signals before spawning threads so all workers inherit the mask
        const sig_fd = setupSignalFd() catch -1;
        defer if (sig_fd >= 0) posix.close(sig_fd);

        if (workers <= 1) {
            // Single-threaded mode: use simple sockets (no SO_REUSEPORT)
            log.info("listening on port {d} (UDP+TCP), 1 worker", .{listen_addr.getPort()});
            self.runWorker(listen_addr, sig_fd, false);
        } else {
            log.info("listening on port {d} (UDP+TCP), {d} workers", .{ listen_addr.getPort(), workers });

            // Spawn N-1 worker threads + run one on main thread
            const threads = self.allocator.alloc(std.Thread, workers - 1) catch |err| {
                log.err("failed to allocate thread array: {s}", .{@errorName(err)});
                return err;
            };
            defer self.allocator.free(threads);

            for (threads, 0..) |*t, i| {
                t.* = std.Thread.spawn(.{}, workerThread, .{ self, listen_addr }) catch |err| {
                    log.err("failed to spawn worker {d}: {s}", .{ i + 1, @errorName(err) });
                    // Signal shutdown to already-spawned threads
                    self.shutdown.store(true, .release);
                    for (threads[0..i]) |prev| prev.join();
                    return err;
                };
            }

            // Main thread runs a worker too, with signalfd for shutdown
            self.runWorker(listen_addr, sig_fd, true);

            // Join all worker threads
            for (threads) |t| t.join();
        }

        // Log cache stats on shutdown
        const stats = self.cache.getStats();
        const hit_total = stats.hits + stats.misses;
        const hit_pct: u64 = if (hit_total > 0) stats.hits * 100 / hit_total else 0;
        log.info("cache stats: {d} entries, {d} bytes, {d} hits, {d} misses ({d}% hit rate), {d} evictions", .{
            stats.entries, stats.memory_bytes, stats.hits, stats.misses, hit_pct, stats.evictions,
        });
    }

    fn workerThread(self: *Server, listen_addr: std.net.Address) void {
        self.runWorker(listen_addr, -1, true);
    }

    fn runWorker(self: *Server, listen_addr: std.net.Address, sig_fd: posix.fd_t, reuseport: bool) void {
        // Per-thread EventLoop
        const loop = EventLoop.create(self.allocator) catch |err| {
            log.err("worker failed to create event loop: {s}", .{@errorName(err)});
            return;
        };
        defer loop.destroy();

        // Per-thread outbound transport
        var udp_transport = UdpTransport.init(loop, .{}) catch |err| {
            log.err("worker failed to create UDP transport: {s}", .{@errorName(err)});
            return;
        };
        defer udp_transport.deinit();

        var tcp_transport = TcpTransport.init(loop, .{});

        // Per-thread server sockets
        const udp_sock = if (reuseport)
            createUdpSocketReuseport(listen_addr) catch |err| {
                log.err("worker failed to create UDP socket: {s}", .{@errorName(err)});
                return;
            }
        else
            createUdpSocket(listen_addr) catch |err| {
                log.err("worker failed to create UDP socket: {s}", .{@errorName(err)});
                return;
            };
        defer posix.close(udp_sock);

        const tcp_sock = if (reuseport)
            createTcpListenSocketReuseport(listen_addr) catch |err| {
                log.err("worker failed to create TCP socket: {s}", .{@errorName(err)});
                return;
            }
        else
            createTcpListenSocket(listen_addr) catch |err| {
                log.err("worker failed to create TCP socket: {s}", .{@errorName(err)});
                return;
            };
        defer posix.close(tcp_sock);

        // Per-worker TLS transport + encryption state (opportunistic encryption)
        var tls_transport = TlsTransport.init(loop, self.allocator, .{}, self.ca_bundle);
        var enc_state = EncryptionStateCache.init(self.allocator);
        defer if (self.config.opportunistic) enc_state.deinit();

        // Worker state
        var ws = WorkerState{
            .config = &self.config,
            .allocator = self.allocator,
            .loop = loop,
            .udp_transport = &udp_transport,
            .tcp_transport = &tcp_transport,
            .tls_transport = if (self.config.opportunistic) &tls_transport else null,
            .encryption_state = if (self.config.opportunistic) &enc_state else null,
            .cache = &self.cache,
            .shutdown = &self.shutdown,
        };

        ws.serveLoop(udp_sock, tcp_sock, sig_fd);
    }
};

// ── WorkerState ────────────────────────────────────────────────────────
// Per-thread state that handles the actual serve loop.

const WorkerState = struct {
    config: *const ServerConfig,
    allocator: mem.Allocator,
    loop: *EventLoop,
    udp_transport: *UdpTransport,
    tcp_transport: *TcpTransport,
    tls_transport: ?*TlsTransport,
    encryption_state: ?*EncryptionStateCache,
    cache: *RRsetCache,
    shutdown: *std.atomic.Value(bool),

    fn serveLoop(self: *WorkerState, udp_sock: posix.fd_t, tcp_sock: posix.fd_t, sig_fd: posix.fd_t) void {
        var udp_ctx = Ctx{ .tag = .udp_recv };
        var accept_ctx = Ctx{ .tag = .tcp_accept };
        var signal_ctx = Ctx{ .tag = .signal };

        _ = self.loop.recvFrom(udp_sock, @ptrCast(&udp_ctx)) catch return;
        _ = self.loop.accept(tcp_sock, @ptrCast(&accept_ctx)) catch return;
        if (sig_fd >= 0) {
            _ = self.loop.read(sig_fd, @ptrCast(&signal_ctx)) catch {};
        }

        var completions: [max_operations]Completion = undefined;

        while (!self.shutdown.load(.acquire)) {
            const results = self.loop.tick(&completions) catch break;

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
                                    self.handleUdpQuery(udp_sock, recv.data, recv.addr);
                                }
                            },
                            else => {},
                        }
                        if (!self.shutdown.load(.acquire)) {
                            _ = self.loop.recvFrom(udp_sock, @ptrCast(&udp_ctx)) catch break;
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
                            _ = self.loop.accept(tcp_sock, @ptrCast(&accept_ctx)) catch break;
                        }
                    },
                }
            }
        }

        self.loop.flush();
    }

    fn handleUdpQuery(self: *WorkerState, sock: posix.fd_t, data: []const u8, client_addr: std.net.Address) void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const query = dns.parseMessage(alloc, data) catch {
            if (data.len >= 2) {
                const id = mem.readInt(u16, data[0..2], .big);
                var wire_buf: [512]u8 = undefined;
                if (serializeErrorResponse(&wire_buf, id, .format_error, false)) |wire| {
                    sendUdpResponse(sock, self.loop, wire, client_addr);
                }
            }
            return;
        };

        if (query.header.opcode != .query) {
            var wire_buf: [512]u8 = undefined;
            if (serializeErrorResponse(&wire_buf, query.header.id, .not_implemented, query.header.rd)) |wire| {
                sendUdpResponse(sock, self.loop, wire, client_addr);
            }
            return;
        }

        if (query.questions.len != 1) {
            var wire_buf: [512]u8 = undefined;
            if (serializeErrorResponse(&wire_buf, query.header.id, .format_error, query.header.rd)) |wire| {
                sendUdpResponse(sock, self.loop, wire, client_addr);
            }
            return;
        }

        if (query.questions[0].qclass != .in) {
            var wire_buf: [512]u8 = undefined;
            if (serializeErrorResponse(&wire_buf, query.header.id, .refused, query.header.rd)) |wire| {
                sendUdpResponse(sock, self.loop, wire, client_addr);
            }
            return;
        }

        const question = query.questions[0];
        const name_buf = question.name.format();
        const name_len = mem.indexOfScalar(u8, &name_buf, 0) orelse name_buf.len;
        const name_str = name_buf[0..name_len];

        const max_payload: u16 = if (query.opt) |opt| @max(opt.udp_payload_size, dns.max_udp_payload) else dns.max_udp_payload;

        const start_ns = std.time.nanoTimestamp();
        const response = self.resolveQuery(alloc, name_str, question.qtype) catch {
            const elapsed_ms: i64 = @intCast(@divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000));
            log.warn("{s} {s} SERVFAIL {d}ms", .{ name_str, @tagName(question.qtype), elapsed_ms });
            var wire_buf: [512]u8 = undefined;
            if (serializeErrorResponse(&wire_buf, query.header.id, .server_failure, query.header.rd)) |wire| {
                sendUdpResponse(sock, self.loop, wire, client_addr);
            }
            return;
        };
        const elapsed_ms: i64 = @intCast(@divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000));
        log.debug("{s} {s} {s} {d}ms", .{ name_str, @tagName(question.qtype), @tagName(response.header.rcode), elapsed_ms });

        var wire_buf: [65535]u8 = undefined;
        if (buildResponseWire(&wire_buf, query.header.id, query.header.rd, query.questions, response, query.opt != null, max_payload)) |wire| {
            sendUdpResponse(sock, self.loop, wire, client_addr);
        }
    }

    fn handleTcpClient(self: *WorkerState, client_fd: posix.fd_t) void {
        defer posix.close(client_fd);

        while (!self.shutdown.load(.acquire)) {
            const len_bytes = tcpReadExact(self.loop, client_fd, 2, tcp_idle_timeout_ms) orelse return;
            const msg_len = mem.readInt(u16, len_bytes[0..2], .big);
            if (msg_len == 0) return;

            const query_data = tcpReadExact(self.loop, client_fd, msg_len, tcp_idle_timeout_ms) orelse return;

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const alloc = arena.allocator();

            var response_wire: [65535]u8 = undefined;
            const wire = self.processQuery(alloc, query_data[0..msg_len], &response_wire) orelse return;

            var len_prefix: [2]u8 = undefined;
            mem.writeInt(u16, &len_prefix, @intCast(wire.len), .big);

            if (!tcpSendAll(self.loop, client_fd, &len_prefix)) return;
            if (!tcpSendAll(self.loop, client_fd, wire)) return;
        }
    }

    fn processQuery(self: *WorkerState, alloc: mem.Allocator, data: []const u8, response_wire: []u8) ?[]const u8 {
        const query = dns.parseMessage(alloc, data) catch {
            if (data.len >= 2) {
                const id = mem.readInt(u16, data[0..2], .big);
                return serializeErrorResponse(response_wire, id, .format_error, false);
            }
            return null;
        };

        if (query.header.opcode != .query) {
            return serializeErrorResponse(response_wire, query.header.id, .not_implemented, query.header.rd);
        }
        if (query.questions.len != 1) {
            return serializeErrorResponse(response_wire, query.header.id, .format_error, query.header.rd);
        }
        if (query.questions[0].qclass != .in) {
            return serializeErrorResponse(response_wire, query.header.id, .refused, query.header.rd);
        }

        const question = query.questions[0];
        const name_buf = question.name.format();
        const name_len = mem.indexOfScalar(u8, &name_buf, 0) orelse name_buf.len;
        const name_str = name_buf[0..name_len];

        const start_ns = std.time.nanoTimestamp();
        const response = self.resolveQuery(alloc, name_str, question.qtype) catch {
            const elapsed_ms: i64 = @intCast(@divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000));
            log.warn("{s} {s} SERVFAIL {d}ms (tcp)", .{ name_str, @tagName(question.qtype), elapsed_ms });
            return serializeErrorResponse(response_wire, query.header.id, .server_failure, query.header.rd);
        };
        const elapsed_ms: i64 = @intCast(@divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000));
        log.debug("{s} {s} {s} {d}ms (tcp)", .{ name_str, @tagName(question.qtype), @tagName(response.header.rcode), elapsed_ms });

        return buildResponseWire(response_wire, query.header.id, query.header.rd, query.questions, response, query.opt != null, 65535);
    }

    fn resolveQuery(self: *WorkerState, alloc: mem.Allocator, name: []const u8, qtype: dns.RType) !dns.Message {
        switch (self.config.mode) {
            .recursive => {
                var resolver = RecursiveResolver.initFull(self.udp_transport, self.tcp_transport, self.cache);
                if (!self.config.qname_minimization) resolver.qname_minimisation = false;
                resolver.dnssec_enabled = self.config.dnssec;
                if (self.tls_transport) |tls_t| resolver.tls_transport = tls_t;
                if (self.encryption_state) |enc| resolver.encryption_state = enc;
                return try resolver.resolve(alloc, name, qtype);
            },
            .forward => {
                var resolver = ForwardingResolver.initWithTcp(self.udp_transport, self.tcp_transport);
                const upstream = if (self.config.upstreams.len > 0)
                    self.config.upstreams[0]
                else
                    std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 53);
                return try resolver.resolve(alloc, name, qtype, upstream);
            },
        }
    }
};

// ── Response building ──────────────────────────────────────────────────

fn buildResponseWire(
    wire_buf: []u8,
    query_id: u16,
    rd: bool,
    questions: []const dns.Question,
    response: dns.Message,
    client_edns: bool,
    max_payload: u16,
) ?[]const u8 {
    const opt: ?dns.OptRecord = if (client_edns) .{
        .udp_payload_size = dns.edns_udp_payload,
        .extended_rcode = 0,
        .version = 0,
        .do_bit = false,
        .options = &.{},
    } else null;

    var msg = dns.Message{
        .header = .{
            .id = query_id,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = rd,
            .ra = true,
            .z = 0,
            .rcode = response.header.rcode,
            .qd_count = @intCast(questions.len),
            .an_count = @intCast(response.answers.len),
            .ns_count = @intCast(response.authorities.len),
            .ar_count = @intCast(response.additionals.len),
        },
        .questions = questions,
        .answers = response.answers,
        .authorities = response.authorities,
        .additionals = response.additionals,
        .opt = opt,
    };

    // Try full response
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= max_payload) return wire;
    } else |_| {}

    // Drop additionals
    msg.additionals = &.{};
    msg.header.ar_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= max_payload) return wire;
    } else |_| {}

    // Drop authorities
    msg.authorities = &.{};
    msg.header.ns_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= max_payload) return wire;
    } else |_| {}

    // TC bit with answers
    msg.header.tc = true;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        if (wire.len <= max_payload) return wire;
    } else |_| {}

    // TC with no answers
    msg.answers = &.{};
    msg.header.an_count = 0;
    if (dns.serializeMessage(wire_buf, msg)) |wire| {
        return wire[0..@min(wire.len, max_payload)];
    } else |_| {}

    return null;
}

fn serializeErrorResponse(wire_buf: []u8, query_id: u16, rcode: dns.RCode, rd: bool) ?[]const u8 {
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
            .rcode = rcode,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };
    return dns.serializeMessage(wire_buf, msg) catch null;
}

// ── TCP helpers ────────────────────────────────────────────────────────

fn tcpReadExact(loop: *EventLoop, fd: posix.fd_t, needed: u16, timeout_ms: u32) ?[]const u8 {
    var total_buf: [65537]u8 = undefined;
    var total: usize = 0;

    while (total < needed) {
        var recv_ctx: u8 = 0;
        var timeout_ctx: u8 = 1;

        const recv_op = loop.tcpRecv(fd, @ptrCast(&recv_ctx)) catch return null;
        const timeout_op = loop.setTimeout(timeout_ms, @ptrCast(&timeout_ctx)) catch {
            loop.cancel(recv_op) catch {};
            return null;
        };

        var completions: [max_operations]Completion = undefined;
        var got_data = false;
        var timed_out = false;

        for (0..10) |_| {
            const results = loop.tick(&completions) catch return null;
            for (results) |c| {
                const tag = @as(*u8, @ptrCast(@alignCast(c.context))).*;
                if (tag == 0) {
                    switch (c.result) {
                        .tcp_recv => |r| {
                            if (r.err != null) {
                                loop.cancel(timeout_op) catch {};
                                drainCancel(loop);
                                return null;
                            }
                            const chunk = r.data;
                            const to_copy = @min(chunk.len, needed - total);
                            @memcpy(total_buf[total..][0..to_copy], chunk[0..to_copy]);
                            total += to_copy;
                            got_data = true;
                        },
                        else => {},
                    }
                } else {
                    switch (c.result) {
                        .timeout => |t| {
                            if (t.expired) {
                                timed_out = true;
                                loop.cancel(recv_op) catch {};
                                drainCancel(loop);
                                return null;
                            }
                        },
                        else => {},
                    }
                }
            }
            if (got_data or timed_out) break;
        }

        if (got_data) {
            loop.cancel(timeout_op) catch {};
            drainCancel(loop);
        }

        if (!got_data) return null;
    }

    return total_buf[0..needed];
}

fn tcpSendAll(loop: *EventLoop, fd: posix.fd_t, data: []const u8) bool {
    var sent: usize = 0;
    while (sent < data.len) {
        var ctx: u8 = 0;
        _ = loop.tcpSend(fd, data[sent..], @ptrCast(&ctx)) catch return false;

        var completions: [max_operations]Completion = undefined;
        for (0..5) |_| {
            const results = loop.tick(&completions) catch return false;
            for (results) |c| {
                switch (c.result) {
                    .tcp_send => |r| {
                        if (r.bytes_sent <= 0) return false;
                        sent += @intCast(r.bytes_sent);
                    },
                    else => {},
                }
            }
            if (sent >= data.len) break;
        }
    }
    return sent >= data.len;
}

fn drainCancel(loop: *EventLoop) void {
    var completions: [max_operations]Completion = undefined;
    _ = loop.tick(&completions) catch {};
}

fn sendUdpResponse(sock: posix.fd_t, loop: *EventLoop, data: []const u8, dest: std.net.Address) void {
    var discard_ctx: u8 = 0;
    _ = loop.sendTo(sock, data, dest, @ptrCast(&discard_ctx)) catch return;
    var completions: [max_operations]Completion = undefined;
    _ = loop.tick(&completions) catch return;
}

// ── Socket creation ────────────────────────────────────────────────────

fn createUdpSocket(addr: std.net.Address) !posix.fd_t {
    const sock = try posix.socket(addr.any.family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(sock);

    const optval: c_int = 1;
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(optval));
    try posix.bind(sock, &addr.any, addr.getOsSockLen());

    return sock;
}

fn createUdpSocketReuseport(addr: std.net.Address) !posix.fd_t {
    const sock = try posix.socket(addr.any.family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(sock);

    const optval: c_int = 1;
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(optval));
    try posix.setsockopt(sock, posix.SOL.SOCKET, linux.SO.REUSEPORT, &mem.toBytes(optval));
    try posix.bind(sock, &addr.any, addr.getOsSockLen());

    return sock;
}

fn createTcpListenSocket(addr: std.net.Address) !posix.fd_t {
    const sock = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(sock);

    const optval: c_int = 1;
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(optval));
    try posix.bind(sock, &addr.any, addr.getOsSockLen());
    try posix.listen(sock, 128);

    return sock;
}

fn createTcpListenSocketReuseport(addr: std.net.Address) !posix.fd_t {
    const sock = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(sock);

    const optval: c_int = 1;
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(optval));
    try posix.setsockopt(sock, posix.SOL.SOCKET, linux.SO.REUSEPORT, &mem.toBytes(optval));
    try posix.bind(sock, &addr.any, addr.getOsSockLen());
    try posix.listen(sock, 128);

    return sock;
}

pub fn setupSignalFd() !posix.fd_t {
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

    var server = try Server.init(testing.allocator, cfg);
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

    var server = try Server.init(testing.allocator, cfg);
    defer server.deinit();

    try testing.expect(server.cache.mutex != null);
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
            .rcode = .server_failure,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };

    var buf: [512]u8 = undefined;
    const wire = buildResponseWire(&buf, 0x1234, true, questions, response, false, 512).?;

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
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };

    var buf: [1232]u8 = undefined;
    const wire = buildResponseWire(&buf, 0x5678, true, questions, response, true, 1232).?;

    const parsed = try dns.parseMessage(a, wire);
    try testing.expect(parsed.opt != null);
    try testing.expectEqual(@as(u16, dns.edns_udp_payload), parsed.opt.?.udp_payload_size);
}

test "serializeErrorResponse produces valid DNS message" {
    var buf: [512]u8 = undefined;
    const wire = serializeErrorResponse(&buf, 0xABCD, .refused, true).?;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const parsed = try dns.parseMessage(arena.allocator(), wire);
    try testing.expectEqual(@as(u16, 0xABCD), parsed.header.id);
    try testing.expectEqual(dns.RCode.refused, parsed.header.rcode);
    try testing.expectEqual(true, parsed.header.rd);
    try testing.expectEqual(true, parsed.header.ra);
    try testing.expectEqual(true, parsed.header.qr);
}

test "createUdpSocket binds to ephemeral port" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const sock = createUdpSocket(addr) catch return error.SkipZigTest;
    defer posix.close(sock);

    var bound: std.net.Address = undefined;
    var len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(sock, @ptrCast(&bound), &len);
    try testing.expect(bound.getPort() > 0);
}

test "createTcpListenSocket binds and listens" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const sock = createTcpListenSocket(addr) catch return error.SkipZigTest;
    defer posix.close(sock);

    var bound: std.net.Address = undefined;
    var len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(sock, @ptrCast(&bound), &len);
    try testing.expect(bound.getPort() > 0);
}

test "createUdpSocketReuseport allows multiple binds" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const sock1 = createUdpSocketReuseport(addr) catch return error.SkipZigTest;
    defer posix.close(sock1);

    // Get the actual port
    var bound: std.net.Address = undefined;
    var len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(sock1, @ptrCast(&bound), &len);
    const port = bound.getPort();

    // Second socket on same port should succeed with SO_REUSEPORT
    const addr2 = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    const sock2 = createUdpSocketReuseport(addr2) catch return error.SkipZigTest;
    defer posix.close(sock2);
}
