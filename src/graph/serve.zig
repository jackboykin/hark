//! The proof-of-concept server: one thread, one graph, the live edge.
//! Every policy that is not a cell and not answer shaping lives here.
const std = @import("std");
const Allocator = std.mem.Allocator;
const dns = @import("../dns.zig");
const graph = @import("graph.zig");
const answer = @import("answer.zig");

const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const build_options = @import("build_options");
const na = @import("../net_address.zig");
const sys = @import("../sys_union.zig");
const acl = @import("../acl.zig");
const config = @import("../config.zig");
const monotonic = @import("../monotonic.zig");
const response = @import("../response.zig");
const server = @import("../server.zig");
const Edge = @import("edge.zig");
const log = std.log.scoped(.graph);

const max_frame = 4096;
const udp_recv_max = 4096;

const Conn = struct {
    fd: posix.fd_t,
    addr: na.Address,
    token: u32,
    buf: [2 + max_frame]u8 = undefined,
    len: usize = 0,
    served: u32 = 0,
    last_ns: i64,
    /// Answers owed; a half-closed client waits for them.
    owed: u32 = 0,
    eof: bool = false,
    /// Reply bytes the socket has not taken; while any wait, nothing more is asked.
    out: std.ArrayList(u8) = .empty,
    blocked_ns: i64 = 0,
};

const Reply = union(enum) {
    udp: struct { fd: posix.fd_t, addr: na.Address },
    tcp: *Conn,
};

const Watched = union(enum) {
    udp: posix.fd_t,
    listen: posix.fd_t,
    conn: *Conn,
    signal: posix.fd_t,
    free,
};

/// Re-read at answer time: the graph never holds client bytes.
const Pending = struct {
    root: graph.CellId,
    /// Under DNS64, the A behind an empty AAAA.
    a: ?graph.CellId = null,
    /// Settled from memory alone.
    cached: bool,
    wire: []u8,
    reply: Reply,
};

const Server = struct {
    gpa: Allocator,
    cfg: *const config.ServerConfig,
    e: *Edge,
    g: *graph.Graph,
    watched: std.ArrayList(Watched) = .empty,
    pending: std.ArrayList(Pending) = .empty,
    scratch: std.heap.ArenaAllocator,
    stopping: bool = false,

    fn token(s: *Server, w: Watched) !u32 {
        for (s.watched.items, 0..) |x, i| if (x == .free) {
            s.watched.items[i] = w;
            return @intCast(i);
        };
        try s.watched.append(s.gpa, w);
        return @intCast(s.watched.items.len - 1);
    }

    /// TERM and INT stop the loop; USR1 and HUP print the footprint line.
    /// A handler is not optional: as PID 1 of a container the kernel drops
    /// every signal the process has no disposition for, TERM included.
    fn onSignal(s: *Server, fd: posix.fd_t) void {
        var infos: [4]linux.signalfd_siginfo = undefined;
        const rc = linux.read(fd, @ptrCast(&infos), @sizeOf(@TypeOf(infos)));
        if (linux.errno(rc) != .SUCCESS) return;
        for (infos[0 .. rc / @sizeOf(linux.signalfd_siginfo)]) |info| switch (@as(linux.SIG, @fromBackingInt(@intCast(info.signo)))) {
            .TERM, .INT => s.stopping = true,
            else => logFootprint(s.g),
        };
    }

    fn listen(s: *Server, addr: na.Address) !void {
        const udp = try server.createSocket(addr, posix.SOCK.DGRAM, false, false);
        try s.e.watch(udp, try s.token(.{ .udp = udp }), linux.EPOLL.IN);
        const tcp = try server.createSocket(addr, posix.SOCK.STREAM, false, true);
        try s.e.watch(tcp, try s.token(.{ .listen = tcp }), linux.EPOLL.IN);
    }

    fn onClient(s: *Server, tok: u32, events: u32) !void {
        switch (s.watched.items[tok]) {
            .udp => |fd| try s.readUdp(fd),
            .listen => |fd| try s.accept(fd),
            .conn => |c| if (c.out.items.len != 0) try s.flush(c) else try s.readTcp(c, events),
            .signal => |fd| s.onSignal(fd),
            .free => {},
        }
    }

    fn readUdp(s: *Server, fd: posix.fd_t) !void {
        var buf: [udp_recv_max]u8 = undefined;
        var pa: na.PosixAddress = undefined;
        var len: posix.socklen_t = @sizeOf(na.PosixAddress);
        const rc = linux.recvfrom(fd, &buf, buf.len, linux.MSG.DONTWAIT, &pa.any, &len);
        if (linux.errno(rc) != .SUCCESS) return;
        const data = buf[0..rc];
        const from = na.fromSockaddr(&pa);
        if (!acl.allow(s.cfg.allow_from, from)) return;
        try s.ask(data, .{ .udp = .{ .fd = fd, .addr = from } });
    }

    fn accept(s: *Server, fd: posix.fd_t) !void {
        while (true) {
            var pa: na.PosixAddress = undefined;
            var len: posix.socklen_t = @sizeOf(na.PosixAddress);
            const rc = linux.accept4(fd, &pa.any, &len, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC);
            if (linux.errno(rc) != .SUCCESS) return;
            const cfd: posix.fd_t = @intCast(rc);
            // A small kernel queue, so write progress measures the client.
            posix.setsockopt(cfd, posix.SOL.SOCKET, linux.SO.SNDBUF, &mem.toBytes(client_sndbuf)) catch {};
            const c = try s.gpa.create(Conn);
            c.* = .{ .fd = cfd, .addr = na.fromSockaddr(&pa), .token = 0, .last_ns = s.e.now_ns };
            c.token = try s.token(.{ .conn = c });
            try s.e.watch(c.fd, c.token, linux.EPOLL.IN);
        }
    }

    fn readTcp(s: *Server, c: *Conn, events: u32) !void {
        if (events & (linux.EPOLL.ERR | linux.EPOLL.HUP) != 0 and events & linux.EPOLL.IN == 0) return s.drop(c);
        const rc = linux.read(c.fd, c.buf[c.len..].ptr, c.buf.len - c.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .AGAIN, .INTR => return,
            else => return s.drop(c),
        }
        if (rc == 0) {
            c.eof = true;
            if (c.owed == 0) s.drop(c);
            return;
        }
        c.len += rc;
        c.last_ns = s.e.now_ns;
        try s.frames(c);
    }

    fn frames(s: *Server, c: *Conn) !void {
        const tok = c.token;
        var start: usize = 0;
        while (c.len - start >= 2 and c.out.items.len == 0) {
            const flen: usize = mem.readInt(u16, c.buf[start..][0..2], .big);
            if (flen == 0 or flen > max_frame or c.served >= s.cfg.tcp_queries_per_conn) return s.drop(c);
            if (c.len - start < 2 + flen) break;
            c.served += 1;
            c.owed += 1;
            try s.ask(c.buf[start + 2 ..][0..flen], .{ .tcp = c });
            // Turned away, or a failed write: the connection is gone.
            if (s.watched.items[tok] != .conn) return;
            start += 2 + flen;
        }
        mem.copyForwards(u8, c.buf[0 .. c.len - start], c.buf[start..c.len]);
        c.len -= start;
    }

    /// Clients still waiting get nothing; the graph frees their roots.
    fn deinit(s: *Server) void {
        for (s.watched.items) |w| if (w == .conn) s.drop(w.conn);
        for (s.pending.items) |p| s.release(p);
        s.pending.deinit(s.gpa);
        s.watched.deinit(s.gpa);
        s.scratch.deinit();
    }

    fn drop(s: *Server, c: *Conn) void {
        for (s.pending.items) |*p| if (p.reply == .tcp and p.reply.tcp == c) {
            p.reply = .{ .udp = .{ .fd = -1, .addr = c_addr_none } };
        };
        sys.close(c.fd);
        s.watched.items[c.token] = .free;
        c.out.deinit(s.gpa);
        s.gpa.destroy(c);
    }

    const c_addr_none = na.initIp4(.{ 0, 0, 0, 0 }, 0);
    const client_sndbuf: c_int = 64 * 1024;

    fn sweep(s: *Server) void {
        const idle_ns = @as(i64, s.cfg.tcp_idle_timeout_ms) * std.time.ns_per_ms;
        var i: usize = 0;
        while (i < s.watched.items.len) : (i += 1) {
            const c = switch (s.watched.items[i]) {
                .conn => |c| c,
                else => continue,
            };
            // A client owed an answer gets the resolve deadline on top.
            const since = if (c.out.items.len != 0) c.blocked_ns else c.last_ns;
            const owed_ns = if (c.owed > 0 and c.out.items.len == 0) @as(i64, s.g.cfg.resolve_ms) * std.time.ns_per_ms else 0;
            if (s.e.now_ns - since >= idle_ns + owed_ns) s.drop(c);
        }
    }

    fn ask(s: *Server, wire: []const u8, reply: Reply) !void {
        _ = s.scratch.reset(.retain_capacity);
        const arena = s.scratch.allocator();
        // BCP 140: a UDP reply is dropped silently; over TCP `validateQuery` answers it.
        if (wire.len < 12 or (reply == .udp and wire[2] & 0x80 != 0)) return if (reply == .tcp) s.drop(reply.tcp);
        const query = dns.parseMessage(arena, wire) catch {
            const id = mem.readInt(u16, wire[0..2], .big);
            return s.sendError(reply, id, .query, .format_error, 0, wire[2] & 1 != 0, &.{}, null);
        };
        if (response.validateQuery(query)) |v| return s.sendError(reply, query.header.id, query.header.flags.opcode, v.rcode, v.extended_rcode, query.header.flags.rd, query.questions, query.opt);
        const q = query.questions[0];
        const client = answer.Client.fromQuery(query);
        var name_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const name = q.name.formatInto(&name_buf);
        if (build_options.testing_enabled) if (server.parseAdvanceClockQname(dns.stripTrailingDot(name))) |secs| {
            monotonic.advanceTestClock(secs);
            return s.send(reply, query, response.synthesizedMessage(&.{}, &.{}, .no_error, false), null);
        };
        const d64 = answer.Dns64.on(s.cfg.dns64, client);
        if (try answer.special(arena, q, client, d64)) |served| return s.send(reply, query, served.msg, null);
        if (q.qtype == .any) return s.send(reply, query, (try answer.hinfo(arena, q, client)).msg, null);
        const asked = if (d64) |d| try d.asked(arena, q) else q;
        // BCP 140 again: turned away is silence on UDP, a close on TCP.
        const root = try s.g.demandRoot(asked.name, asked.qtype, client.cd) orelse return if (reply == .tcp) s.drop(reply.tcp);
        try s.g.drain();
        var p: Pending = .{ .root = root, .cached = s.g.cell(root).settled, .wire = &.{}, .reply = reply };
        errdefer s.release(p);
        if (p.cached) if (try s.finish(arena, &p, query)) |served| {
            s.send(reply, query, served.msg, served.ede);
            return s.release(p);
        };
        p.wire = try s.gpa.dupe(u8, wire);
        try s.pending.append(s.gpa, p);
    }

    fn settle(s: *Server) !void {
        var i: usize = 0;
        while (i < s.pending.items.len) {
            const p = &s.pending.items[i];
            if (!s.g.cell(p.root).settled) {
                i += 1;
                continue;
            }
            _ = s.scratch.reset(.retain_capacity);
            const arena = s.scratch.allocator();
            const query = try dns.parseMessage(arena, p.wire);
            const served = try s.finish(arena, p, query) orelse {
                i += 1;
                continue;
            };
            s.send(p.reply, query, served.msg, served.ede);
            s.release(p.*);
            _ = s.pending.swapRemove(i);
        }
    }

    /// The reply once every root it needs has settled.
    fn finish(s: *Server, arena: Allocator, p: *Pending, query: dns.Message) !?answer.Served {
        const q = query.questions[0];
        const client = answer.Client.fromQuery(query);
        const d64 = answer.Dns64.on(s.cfg.dns64, client) orelse return try answer.build(arena, s.g, p.root, q, client, s.cfg.minimal_responses, p.cached);
        const served = try answer.build(arena, s.g, p.root, try d64.asked(arena, q), client, s.cfg.minimal_responses, p.cached);
        if (p.a == null and answer.Dns64.wantsA(q, served)) if (try s.g.demandRoot(q.name, .a, client.cd)) |a| {
            p.a = a;
            try s.g.drain();
        };
        var a: ?answer.Served = null;
        if (p.a) |id| {
            if (!s.g.cell(id).settled) return null;
            a = try answer.build(arena, s.g, id, .{ .name = q.name, .qtype = .a, .qclass = q.qclass }, client, s.cfg.minimal_responses, p.cached);
        }
        return try d64.shape(arena, q, served, a);
    }

    fn release(s: *Server, p: Pending) void {
        s.g.unhold(p.root);
        if (p.a) |a| s.g.unhold(a);
        s.gpa.free(p.wire);
    }

    fn send(s: *Server, reply: Reply, query: dns.Message, msg: dns.Message, ede: ?dns.Ede) void {
        const arena = s.scratch.allocator();
        var buf: [2 + @as(usize, dns.max_message_len)]u8 = undefined;
        const payload: u16 = switch (reply) {
            .udp => blk: {
                const claimed = if (query.opt) |o| o.udp_payload_size else dns.max_udp_payload;
                break :blk @min(@max(claimed, dns.max_udp_payload), s.cfg.max_udp_payload);
            },
            .tcp => dns.max_message_len,
        };
        var ctx = response.ResponseContext.fromQuery(query, payload);
        ctx.minimal_responses = s.cfg.minimal_responses;
        ctx.rebinding = &s.cfg.rebinding;
        if (reply == .tcp) ctx.tcp_keepalive = @intCast(s.cfg.tcp_idle_timeout_ms / 100);
        ctx.ede = ede;
        const wire = response.buildResponseWire(buf[2..], ctx, msg, arena) orelse
            return s.sendError(reply, query.header.id, query.header.flags.opcode, .server_failure, 0, query.header.flags.rd, query.questions, query.opt);
        if (s.cfg.log_queries) {
            var ab: [64]u8 = undefined;
            var nb: [dns.max_dotted_len + 1]u8 = undefined;
            var tb: [24]u8 = undefined;
            const q = query.questions[0];
            const peer = switch (reply) {
                .udp => |u| u.addr,
                .tcp => |c| c.addr,
            };
            log.debug("client={s} id=0x{x:0>4} {s} {s} {t}", .{ na.format(peer, &ab), query.header.id, q.name.formatInto(&nb), dns.safeTagName(q.qtype, &tb), msg.header.flags.rcode });
        }
        s.write(reply, buf[0 .. 2 + wire.len]);
    }

    fn sendError(s: *Server, reply: Reply, id: u16, opcode: dns.OpCode, rcode: dns.RCode, extended: u8, rd: bool, questions: []const dns.Question, opt: ?dns.OptRecord) void {
        var buf: [2 + @as(usize, dns.max_udp_payload)]u8 = undefined;
        const wire = response.serializeErrorResponse(buf[2..], id, opcode, rcode, extended, rd, questions, opt) orelse return;
        s.write(reply, buf[0 .. 2 + wire.len]);
    }

    /// `framed`: two bytes of room, then the wire.
    fn write(s: *Server, reply: Reply, framed: []u8) void {
        switch (reply) {
            .udp => |u| {
                if (u.fd < 0) return;
                var pa: na.PosixAddress = undefined;
                const len = na.toSockaddr(&u.addr, &pa);
                _ = sys.sendto(u.fd, framed[2..], linux.MSG.DONTWAIT, &pa.any, len) catch {};
            },
            .tcp => |c| {
                mem.writeInt(u16, framed[0..2], @intCast(framed.len - 2), .big);
                c.owed -= 1;
                c.last_ns = s.e.now_ns;
                var rest: []const u8 = framed;
                if (c.out.items.len == 0) {
                    const n = s.take(c, rest) orelse return;
                    rest = rest[n..];
                }
                if (rest.len == 0) return s.closeIfDone(c);
                c.out.appendSlice(s.gpa, rest) catch return s.drop(c);
                if (c.out.items.len == rest.len) {
                    c.blocked_ns = s.e.now_ns;
                    s.e.rewatch(c.fd, c.token, linux.EPOLL.OUT) catch s.drop(c);
                }
            },
        }
    }

    fn flush(s: *Server, c: *Conn) !void {
        const n = s.take(c, c.out.items) orelse return;
        if (n == 0) return;
        c.last_ns = s.e.now_ns;
        mem.copyForwards(u8, c.out.items, c.out.items[n..]);
        c.out.shrinkRetainingCapacity(c.out.items.len - n);
        if (c.out.items.len != 0) return;
        s.e.rewatch(c.fd, c.token, linux.EPOLL.IN) catch return s.drop(c);
        if (c.eof and c.owed == 0) return s.drop(c);
        try s.frames(c);
    }

    /// Null: the connection is gone.
    fn take(s: *Server, c: *Conn, bytes: []const u8) ?usize {
        return sys.write(c.fd, bytes) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => {
                s.drop(c);
                return null;
            },
        };
    }

    fn closeIfDone(s: *Server, c: *Conn) void {
        if (c.eof and c.owed == 0) s.drop(c);
    }
};

pub fn run(gpa: Allocator, cfg: *const config.ServerConfig, trace: bool) !void {
    var e = try Edge.init(gpa);
    defer e.deinit();
    const anchors = cfg.trustAnchors();
    var g = try graph.Graph.init(gpa, .{
        .qmin = cfg.qname_minimization,
        .root_hints = cfg.rootHints(),
        .addr_policy = .{ .upstream_port = cfg.upstream_port, .allow_loopback = cfg.allow_loopback_upstreams },
        .stagger_ms = cfg.stagger_ms,
        .trust_anchor = if (cfg.dnssec) anchors[0] else null,
        .store_bytes = cfg.cache_size,
        .serve_stale_ttl = cfg.serve_stale_ttl,
        .min_ttl = cfg.min_ttl,
        .max_in_flight = cfg.max_in_flight,
        .trace = trace,
    }, e.edge());
    defer g.deinit();
    g.attach();
    var s: Server = .{ .gpa = gpa, .cfg = cfg, .e = &e, .g = &g, .scratch = std.heap.ArenaAllocator.init(gpa) };
    defer s.deinit();
    for (cfg.listen) |addr| try s.listen(addr);
    if (cfg.drop_gid != null or cfg.drop_uid != null) {
        try server.dropPrivileges(cfg.drop_gid, cfg.drop_uid);
        log.info("dropped to uid={?d} gid={?d}", .{ cfg.drop_uid, cfg.drop_gid });
    }
    if (linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0) != 0) return error.NoNewPrivsFailed;
    const sig = try server.setupSignalFd();
    defer sys.close(sig);
    try e.watch(sig, try s.token(.{ .signal = sig }), linux.EPOLL.IN);
    log.info("graph server listening on {d} address(es)", .{cfg.listen.len});
    var stats_at = e.now_ns + stats_every;
    while (!s.stopping) {
        const ev = try e.next(e.now_ns + std.time.ns_per_s) orelse {
            s.sweep();
            if (e.now_ns >= stats_at) {
                stats_at = e.now_ns + stats_every;
                logFootprint(&g);
            }
            continue;
        };
        switch (ev) {
            .exchange => |x| {
                defer if (x.completion == .reply) gpa.free(x.completion.reply);
                try g.complete(x.id, x.completion);
            },
            .client => |c| try s.onClient(c.token, c.events),
        }
        try s.settle();
    }
    log.info("shutting down", .{});
}

const stats_every = 60 * std.time.ns_per_s;

fn logFootprint(g: *graph.Graph) void {
    var buf: [128]u8 = undefined;
    const rc = linux.open("/proc/self/statm", .{}, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: posix.fd_t = @intCast(rc);
    defer sys.close(fd);
    const n = linux.read(fd, &buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return;
    var it = mem.tokenizeScalar(u8, buf[0..n], ' ');
    _ = it.next();
    const rss_pages = std.fmt.parseInt(u64, it.next() orelse return, 10) catch return;
    log.info("footprint: rss {d} MiB; store {d} KiB in {d} facts, {d} KiB more held by cells, {d} evicted, {d} refused; {d} live cells, {d} resolutions and {d} exchanges in flight, {d} clients turned away", .{
        rss_pages * std.heap.pageSize() / (1024 * 1024),
        g.store.held / 1024,
        g.store.map.count(),
        (g.store.bytes - g.store.held) / 1024,
        g.store.evictions,
        g.store.refusals,
        g.live,
        g.budgets,
        g.flights,
        g.shed,
    });
}
