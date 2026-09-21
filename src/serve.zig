//! The server: one thread, one graph, the live edge.
//! Every policy that is not a cell and not answer shaping lives here.
const std = @import("std");
const Allocator = std.mem.Allocator;
const dns = @import("dns.zig");
const graph = @import("graph.zig");
const answer = @import("answer.zig");

const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const build_options = @import("build_options");
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");
const acl = @import("acl.zig");
const config = @import("config.zig");
const monotonic = @import("monotonic.zig");
const response = @import("response.zig");
const sys_linux = @import("sys_linux.zig");
const Edge = @import("edge.zig");
const log = std.log.scoped(.serve);

const max_frame = 4096;
const udp_recv_max = 4096;
/// Reads per wake. A hit answers inline, so only the cap on misses, which
/// start upstream work, keeps replies from starving: at 64 misses per
/// wake they fell 13%, at 8 they held.
const udp_per_wake = 64;
const udp_misses_per_wake = 8;

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

/// A token is a slot and its generation: an event queued for a dropped
/// connection must not land on the slot's next tenant.
const Slot = struct {
    gen: u32 = 0,
    w: Watched = .free,
};
const slot_bits = 20;
const slot_mask = (1 << slot_bits) - 1;

/// Re-read at answer time: the graph never holds client bytes.
const Pending = struct {
    root: graph.CellId,
    /// Under DNS64, the A behind an empty AAAA.
    a: ?graph.CellId = null,
    /// Settled from memory alone.
    cached: bool,
    wire: []u8,
    reply: Reply,
    asked_ns: i64,
    /// Past the client's patience, stale was looked for once.
    stale_tried: bool = false,
};

const Server = struct {
    gpa: Allocator,
    cfg: *const config.ServerConfig,
    e: *Edge,
    g: *graph.Graph,
    watched: std.ArrayList(Slot) = .empty,
    pending: std.ArrayList(Pending) = .empty,
    failures: answer.Failures = .{},
    retention: answer.Retention,
    scratch: std.heap.ArenaAllocator,
    stopping: bool = false,

    fn token(s: *Server, w: Watched) !u32 {
        for (s.watched.items, 0..) |*x, i| if (x.w == .free) {
            x.gen +%= 1;
            x.w = w;
            return @intCast(i | (x.gen << slot_bits));
        };
        std.debug.assert(s.watched.items.len <= slot_mask);
        try s.watched.append(s.gpa, .{ .w = w });
        return @intCast(s.watched.items.len - 1);
    }

    /// TERM and INT stop the loop; USR1 and HUP print the stats.
    /// A handler is not optional: as PID 1 of a container the kernel drops
    /// every signal the process has no disposition for, TERM included.
    fn onSignal(s: *Server, fd: posix.fd_t) void {
        var infos: [4]linux.signalfd_siginfo = undefined;
        const rc = linux.read(fd, @ptrCast(&infos), @sizeOf(@TypeOf(infos)));
        if (linux.errno(rc) != .SUCCESS) return;
        for (infos[0 .. rc / @sizeOf(linux.signalfd_siginfo)]) |info| switch (@as(linux.SIG, @fromBackingInt(@intCast(info.signo)))) {
            .TERM, .INT => s.stopping = true,
            else => logStats(s.g),
        };
    }

    fn listen(s: *Server, addr: na.Address) !void {
        const udp = try listenOn(addr, posix.SOCK.DGRAM);
        try s.e.watch(udp, try s.token(.{ .udp = udp }), linux.EPOLL.IN);
        const tcp = try listenOn(addr, posix.SOCK.STREAM);
        // Edge-triggered: an EMFILE accept must not re-fire until the next arrival.
        try s.e.watch(tcp, try s.token(.{ .listen = tcp }), linux.EPOLL.IN | linux.EPOLL.ET);
        var ab: [64]u8 = undefined;
        log.info("listening on {s}", .{na.format(addr, &ab)});
    }

    fn onClient(s: *Server, tok: u32, events: u32) !void {
        const x = s.watched.items[tok & slot_mask];
        if (x.gen << slot_bits != tok & ~@as(u32, slot_mask)) return;
        switch (x.w) {
            .udp => |fd| try s.readUdp(fd),
            .listen => |fd| try s.accept(fd),
            .conn => |c| if (c.out.items.len != 0) try s.flush(c) else try s.readTcp(c, events),
            .signal => |fd| s.onSignal(fd),
            .free => {},
        }
    }

    /// Drains the socket in one wake: an epoll call per query cost a third
    /// of the syscall time under load.
    fn readUdp(s: *Server, fd: posix.fd_t) !void {
        var buf: [udp_recv_max]u8 = undefined;
        const parked = s.pending.items.len;
        for (0..udp_per_wake) |_| {
            if (s.pending.items.len - parked == udp_misses_per_wake) return;
            var pa: na.PosixAddress = undefined;
            var len: posix.socklen_t = @sizeOf(na.PosixAddress);
            const rc = linux.recvfrom(fd, &buf, buf.len, linux.MSG.DONTWAIT, &pa.any, &len);
            if (linux.errno(rc) != .SUCCESS) return;
            const from = na.fromSockaddr(&pa);
            if (acl.allow(s.cfg.allow_from, from)) try s.ask(buf[0..rc], .{ .udp = .{ .fd = fd, .addr = from } });
        }
    }

    fn accept(s: *Server, fd: posix.fd_t) !void {
        while (true) {
            var pa: na.PosixAddress = undefined;
            var len: posix.socklen_t = @sizeOf(na.PosixAddress);
            const rc = linux.accept4(fd, &pa.any, &len, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .CONNABORTED, .INTR => continue,
                else => return,
            }
            const cfd: posix.fd_t = @intCast(rc);
            const addr = na.fromSockaddr(&pa);
            if (!acl.allow(s.cfg.allow_from, addr)) {
                sys.close(cfd);
                continue;
            }
            // A small kernel queue, so write progress measures the client.
            posix.setsockopt(cfd, posix.SOL.SOCKET, linux.SO.SNDBUF, &mem.toBytes(client_sndbuf)) catch {};
            const c = try s.gpa.create(Conn);
            c.* = .{ .fd = cfd, .addr = addr, .token = 0, .last_ns = s.e.now_ns };
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
        // Only a whole frame resets the idle clock.
        c.len += rc;
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
            c.last_ns = s.e.now_ns;
            try s.ask(c.buf[start + 2 ..][0..flen], .{ .tcp = c });
            // Turned away, or a failed write: the connection is gone.
            if (s.watched.items[tok & slot_mask].w != .conn) return;
            start += 2 + flen;
        }
        mem.copyForwards(u8, c.buf[0 .. c.len - start], c.buf[start..c.len]);
        c.len -= start;
    }

    /// Clients still waiting get nothing; the graph frees their roots.
    fn deinit(s: *Server) void {
        for (s.watched.items) |x| if (x.w == .conn) s.drop(x.w.conn);
        for (s.pending.items) |p| s.release(p);
        s.pending.deinit(s.gpa);
        s.failures.deinit(s.gpa);
        s.watched.deinit(s.gpa);
        s.scratch.deinit();
    }

    fn drop(s: *Server, c: *Conn) void {
        for (s.pending.items) |*p| if (p.reply == .tcp and p.reply.tcp == c) {
            p.reply = .{ .udp = .{ .fd = -1, .addr = c_addr_none } };
        };
        sys.close(c.fd);
        s.watched.items[c.token & slot_mask].w = .free;
        c.out.deinit(s.gpa);
        s.gpa.destroy(c);
    }

    const c_addr_none = na.initIp4(.{ 0, 0, 0, 0 }, 0);
    const client_sndbuf: c_int = 64 * 1024;

    fn sweep(s: *Server) void {
        const idle_ns = @as(i64, s.cfg.tcp_idle_timeout_ms) * std.time.ns_per_ms;
        var i: usize = 0;
        while (i < s.watched.items.len) : (i += 1) {
            const c = switch (s.watched.items[i].w) {
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
        if (reply == .udp) s.g.stats.clients.udp += 1 else s.g.stats.clients.tcp += 1;
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
        if (build_options.testing_enabled) if (advanceClockSeconds(dns.stripTrailingDot(name))) |secs| {
            monotonic.advanceTestClock(secs);
            return s.send(reply, query, response.synthesizedMessage(&.{}, &.{}, .no_error, false), null, s.e.now_ns);
        };
        const d64 = answer.Dns64.on(s.cfg.dns64, client);
        if (try answer.special(arena, q, client, d64)) |served| return s.send(reply, query, served.msg, null, s.e.now_ns);
        if (q.qtype == .any) return s.send(reply, query, (try answer.hinfo(arena, q, client)).msg, null, s.e.now_ns);
        if (s.failures.get(q, client.cd, s.e.now_ns)) |ede| switch (ede.code) {
            // A hold with nothing left to serve asks afresh.
            .stale_answer, .stale_nxdomain_answer => if (try s.memory(arena, q, client, .stale)) |served| {
                s.g.stats.clients.hit += 1;
                return s.send(reply, query, served.msg, served.ede, s.e.now_ns);
            },
            else => {
                s.g.stats.clients.hit += 1;
                return s.send(reply, query, (try answer.servfail(arena, q, client, ede)).msg, ede, s.e.now_ns);
            },
        };
        if (try s.memory(arena, q, client, .floored)) |served| {
            s.g.stats.clients.hit += 1;
            return s.answered(reply, query, served, s.e.now_ns);
        }
        const asked = if (d64) |d| try d.asked(arena, q) else q;
        // BCP 140 again: turned away is silence on UDP, a close on TCP. Past
        // `max_in_flight` waiters only what is known is served (DNSBomb).
        const wait = s.pending.items.len < s.g.cfg.max_in_flight;
        const root = try s.g.demandRoot(asked.name, asked.qtype, wait) orelse return if (reply == .tcp) s.drop(reply.tcp);
        try s.g.drain();
        var p: Pending = .{ .root = root, .cached = s.g.cell(root).settled(), .wire = &.{}, .reply = reply, .asked_ns = s.e.now_ns };
        errdefer s.release(p);
        if (p.cached) if (try s.shape(arena, &p, q, client)) |served| {
            s.g.stats.clients.hit += 1;
            try s.answered(reply, query, served, p.asked_ns);
            return s.release(p);
        };
        p.wire = try s.gpa.dupe(u8, wire);
        try s.pending.append(s.gpa, p);
    }

    fn settle(s: *Server) !void {
        var i: usize = 0;
        while (i < s.pending.items.len) {
            const p = &s.pending.items[i];
            if (!s.g.cell(p.root).settled()) {
                if (try s.impatient(p)) {
                    s.release(p.*);
                    _ = s.pending.swapRemove(i);
                } else i += 1;
                continue;
            }
            if (p.reply == .udp and p.reply.udp.fd == -1) {
                s.g.stats.clients.abandoned += 1;
                s.release(p.*);
                _ = s.pending.swapRemove(i);
                continue;
            }
            _ = s.scratch.reset(.retain_capacity);
            const arena = s.scratch.allocator();
            const query = try dns.parseMessage(arena, p.wire);
            const served = try s.shape(arena, p, query.questions[0], answer.Client.fromQuery(query)) orelse {
                i += 1;
                continue;
            };
            s.g.stats.clients.miss += 1;
            try s.answered(p.reply, query, served, p.asked_ns);
            s.release(p.*);
            _ = s.pending.swapRemove(i);
        }
    }

    /// RFC 8767 §5: past the client's patience, stale if there is any, held;
    /// the resolution goes on without it.
    fn impatient(s: *Server, p: *Pending) !bool {
        if (p.stale_tried or s.retention.serve_stale_ttl == 0 or s.e.now_ns < patience(p.*)) return false;
        p.stale_tried = true;
        _ = s.scratch.reset(.retain_capacity);
        const arena = s.scratch.allocator();
        const query = try dns.parseMessage(arena, p.wire);
        const q = query.questions[0];
        const client = answer.Client.fromQuery(query);
        const served = try s.memory(arena, q, client, .stale) orelse return false;
        s.g.stats.clients.miss += 1;
        try s.answered(p.reply, query, served, p.asked_ns);
        return true;
    }

    fn patience(p: Pending) i64 {
        return p.asked_ns + answer.stale_client_ms * std.time.ns_per_ms;
    }

    /// When the loop must look at the pending clients next.
    fn nextPatience(s: *Server) i64 {
        var at: i64 = std.math.maxInt(i64);
        if (s.retention.serve_stale_ttl == 0) return at;
        for (s.pending.items) |p| if (!p.stale_tried) {
            at = @min(at, patience(p));
        };
        return at;
    }

    /// An answer from what the store still holds, asking nobody.
    fn memory(s: *Server, arena: Allocator, q: dns.Question, client: answer.Client, how: enum { floored, stale }) !?answer.Served {
        const d64 = answer.Dns64.on(s.cfg.dns64, client);
        const asked = if (d64) |d| try d.asked(arena, q) else q;
        const served = try switch (how) {
            .floored => answer.floored(arena, s.g, s.retention, asked, client, s.cfg.minimal_responses),
            .stale => answer.stale(arena, s.g, s.retention, asked, client, s.cfg.minimal_responses),
        } orelse return null;
        return if (d64) |d| try d.shape(arena, q, served, null) else served;
    }

    /// A reply the resolver derived, noted in the failure cache: a failure
    /// opens or widens its window, stale holds it, an answer forgets it.
    /// What the cache replays is its own note, sent as is.
    fn answered(s: *Server, reply: Reply, query: dns.Message, served: answer.Served, asked_ns: i64) !void {
        try s.failures.note(s.gpa, query.questions[0], answer.Client.fromQuery(query).cd, served, s.g.cfg.servfail_ttl, s.e.now_ns);
        s.send(reply, query, served.msg, served.ede, asked_ns);
    }

    fn shape(s: *Server, arena: Allocator, p: *Pending, q: dns.Question, client: answer.Client) !?answer.Served {
        const d64 = answer.Dns64.on(s.cfg.dns64, client) orelse return try answer.build(arena, s.g, s.retention, p.root, q, client, s.cfg.minimal_responses);
        const served = try answer.build(arena, s.g, s.retention, p.root, try d64.asked(arena, q), client, s.cfg.minimal_responses);
        if (p.a == null and answer.Dns64.wantsA(q, served)) if (try s.g.demandRoot(q.name, .a, true)) |a| {
            p.a = a;
            try s.g.drain();
        };
        var a: ?answer.Served = null;
        if (p.a) |id| {
            if (!s.g.cell(id).settled()) return null;
            a = try answer.build(arena, s.g, s.retention, id, .{ .name = q.name, .qtype = .a, .qclass = q.qclass }, client, s.cfg.minimal_responses);
        }
        return try d64.shape(arena, q, served, a);
    }

    fn release(s: *Server, p: Pending) void {
        s.g.unhold(p.root);
        if (p.a) |a| s.g.unhold(a);
        s.gpa.free(p.wire);
    }

    fn count(s: *Server, rcode: dns.RCode, ede: ?dns.Ede) void {
        const c = &s.g.stats.clients;
        switch (rcode) {
            .no_error => {},
            .name_error => c.nxdomain += 1,
            .server_failure => c.servfail += 1,
            .refused => c.refused += 1,
            else => c.other += 1,
        }
        if (ede) |e| if (e.code == .stale_answer) {
            c.stale += 1;
        };
    }

    fn send(s: *Server, reply: Reply, query: dns.Message, msg: dns.Message, ede: ?dns.Ede, asked_ns: i64) void {
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
            const rcode = msg.header.flags.rcode;
            var rb: [24]u8 = undefined;
            const outcome = if (rcode == .no_error) "" else std.fmt.bufPrint(&rb, " {t}", .{rcode}) catch "";
            log.debug("client={s} id=0x{x:0>4} {s} {s}{s} {d}ms", .{ na.format(peer, &ab), query.header.id, q.name.formatInto(&nb), dns.safeTagName(q.qtype, &tb), outcome, @divTrunc(s.e.now_ns - asked_ns, std.time.ns_per_ms) });
        }
        s.count(msg.header.flags.rcode, ede);
        s.write(reply, buf[0 .. 2 + wire.len]);
    }

    fn sendError(s: *Server, reply: Reply, id: u16, opcode: dns.OpCode, rcode: dns.RCode, extended: u8, rd: bool, questions: []const dns.Question, opt: ?dns.OptRecord) void {
        var buf: [2 + @as(usize, dns.max_udp_payload)]u8 = undefined;
        const wire = response.serializeErrorResponse(buf[2..], id, opcode, rcode, extended, rd, questions, opt) orelse return;
        s.count(rcode, null);
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
        .max_queries = cfg.max_queries,
        .trust_anchor = if (cfg.dnssec) anchors[0] else null,
        .store_bytes = cfg.cache_size,
        .servfail_ttl = cfg.servfail_ttl,
        .prefetch = cfg.prefetch,
        .max_in_flight = cfg.max_in_flight,
        .trace = trace,
    }, e.edge());
    defer g.deinit();
    g.attach();
    var s: Server = .{ .gpa = gpa, .cfg = cfg, .e = &e, .g = &g, .retention = .{ .min_ttl = cfg.min_ttl, .serve_stale_ttl = cfg.serve_stale_ttl }, .scratch = std.heap.ArenaAllocator.init(gpa) };
    defer s.deinit();
    for (cfg.listen) |addr| try s.listen(addr);
    if (cfg.drop_gid != null or cfg.drop_uid != null) {
        try dropPrivileges(cfg.drop_gid, cfg.drop_uid);
        log.info("dropped to uid={?d} gid={?d}", .{ cfg.drop_uid, cfg.drop_gid });
    }
    if (linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0) != 0) return error.NoNewPrivsFailed;
    const sig = try signalFd();
    defer sys.close(sig);
    try e.watch(sig, try s.token(.{ .signal = sig }), linux.EPOLL.IN);
    var sweep_at = e.now_ns + std.time.ns_per_s;
    var stats_at = e.now_ns + stats_every;
    while (!s.stopping) {
        // Under load `next` always has an event; the timers run here, not on idle.
        if (e.now_ns >= sweep_at) {
            sweep_at = e.now_ns + std.time.ns_per_s;
            s.sweep();
        }
        if (e.now_ns >= stats_at) {
            stats_at = e.now_ns + stats_every;
            logStats(&g);
        }
        const ev = try e.next(@min(e.now_ns + std.time.ns_per_s, s.nextPatience())) orelse {
            try s.settle();
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
    logStats(&g);
    log.info("shutting down", .{});
}

const stats_every = 5 * std.time.ns_per_min;

/// Cumulative since start, one line per plane. Every five minutes, on
/// USR1/HUP, and at exit.
fn logStats(g: *graph.Graph) void {
    const c = g.stats.clients;
    const r = g.stats.resolver;
    const t = g.stats.trust;
    const served = c.hit + c.miss;
    log.info("stats clients   {d} queries  udp {d}  tcp {d} | nxdomain {d}  servfail {d}  refused {d}  other {d}  dropped {d}  abandoned {d} | resolved {d}  hit {d}%  stale {d}", .{
        c.udp + c.tcp, c.udp, c.tcp, c.nxdomain, c.servfail, c.refused, c.other, c.dropped, c.abandoned, served, if (served > 0) c.hit * 100 / served else 0, c.stale,
    });
    log.info("stats resolver  {d} exchanges  udp {d}  tcp {d} | timeout {d}  retry {d} | refresh {d}  keys {d}  refused {d}", .{
        r.udp + r.tcp, r.udp, r.tcp, r.timeout, r.retry, r.refresh, r.keys, r.refused,
    });
    log.info("stats trust     secure {d}  insecure {d}  bogus {d}", .{ t.secure, t.insecure, t.bogus });
    log.info("stats store     {d} KiB in {d} facts  in cells {d} KiB | evicted {d}  refused {d}", .{
        g.store.held / 1024, g.store.map.count(), (g.store.bytes - g.store.held) / 1024, g.store.evictions, g.store.refusals,
    });
    log.info("stats process   rss {d} MiB  live cells {d}  in flight {d}", .{ rssMiB() orelse 0, g.live, g.flights });
}

fn rssMiB() ?u64 {
    var buf: [128]u8 = undefined;
    const rc = linux.open("/proc/self/statm", .{}, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: posix.fd_t = @intCast(rc);
    defer sys.close(fd);
    const n = linux.read(fd, &buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return null;
    var it = mem.tokenizeScalar(u8, buf[0..n], ' ');
    _ = it.next();
    const pages = std.fmt.parseInt(u64, it.next() orelse return null, 10) catch return null;
    return pages * std.heap.pageSize() / (1024 * 1024);
}

fn listenOn(addr: na.Address, sock_type: u32) !posix.fd_t {
    const af = na.afU32(addr);
    const sock = try sys.socket(af, sock_type | posix.SOCK.NONBLOCK, 0);
    errdefer sys.close(sock);
    const one: c_int = 1;
    // V6ONLY keeps the families disjoint: the ACL is family-strict, and a
    // v4-mapped-v6 peer would otherwise bypass every v4 allow rule.
    if (af == posix.AF.INET6) try posix.setsockopt(sock, posix.SOL.IPV6, linux.IPV6.V6ONLY, &mem.toBytes(one));
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(one));
    if (sock_type == posix.SOCK.DGRAM) {
        const bufsize: c_int = 1024 * 1024;
        posix.setsockopt(sock, posix.SOL.SOCKET, linux.SO.RCVBUF, &mem.toBytes(bufsize)) catch {};
        posix.setsockopt(sock, posix.SOL.SOCKET, linux.SO.SNDBUF, &mem.toBytes(bufsize)) catch {};
    }
    try na.bindTo(sock, &addr);
    if (sock_type == posix.SOCK.STREAM) try sys.listen(sock, 128);
    return sock;
}

/// INT/TERM stop, USR1/HUP print stats. The reader exists before the signals
/// are blocked: blocked with nothing reading them is unkillable but by KILL.
fn signalFd() !posix.fd_t {
    var mask = linux.sigemptyset();
    linux.sigaddset(&mask, linux.SIG.INT);
    linux.sigaddset(&mask, linux.SIG.TERM);
    linux.sigaddset(&mask, linux.SIG.HUP);
    linux.sigaddset(&mask, linux.SIG.USR1);
    const fd = try sys_linux.signalfd(-1, &mask, linux.SFD.NONBLOCK);
    _ = linux.sigprocmask(linux.SIG.BLOCK, &mask, null);
    return fd;
}

/// Raw syscalls credential the calling thread only (no libc, no SIGSETXID
/// broadcast), so this runs before any thread exists. Clears supplementary
/// groups, then r/e/s gid, then r/e/s uid; euid 0 → non-zero drops the
/// permitted caps. Ambient caps and the bounding set are systemd's job.
fn dropPrivileges(gid: ?u32, uid: ?u32) !void {
    if (linux.geteuid() == 0) {
        const rc = if (@hasField(linux.SYS, "setgroups32")) linux.syscall2(.setgroups32, 0, 0) else linux.syscall2(.setgroups, 0, 0);
        if (@as(isize, @bitCast(rc)) != 0) return error.SetGroupsFailed;
    }
    if (gid) |g| if (linux.setresgid(g, g, g) != 0) return error.SetGidFailed;
    if (uid) |u| if (linux.setresuid(u, u, u) != 0) return error.SetUidFailed;
}

/// `_advance-clock.<seconds>.testharness.invalid`, the harness's clock jump.
fn advanceClockSeconds(name: []const u8) ?i64 {
    const prefix = "_advance-clock.";
    const suffix = ".testharness.invalid";
    if (!mem.startsWith(u8, name, prefix) or !mem.endsWith(u8, name, suffix)) return null;
    return std.fmt.parseInt(i64, name[prefix.len .. name.len - suffix.len], 10) catch null;
}
