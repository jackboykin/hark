//! Serving a client from the graph.
const std = @import("std");
const Allocator = std.mem.Allocator;
const dns = @import("../dns.zig");
const graph = @import("graph.zig");

pub const Client = struct { rd: bool = true, cd: bool = false, do_bit: bool = false, ad: bool = false };

/// A reply, and whether it is a fact past this instant (TTL 0 is served
/// but never memoised).
pub const Served = struct { msg: dns.Message, cacheable: bool, ede: ?dns.Ede = null };

/// RFC 8482: ANY is answered with a synthetic HINFO, asking nobody.
pub fn hinfo(arena: Allocator, q: dns.Question, c: Client) !Served {
    const rr: dns.ResourceRecord = .{ .name = q.name, .rtype = @fromBackingInt(13), .rclass = .in, .ttl = 0, .rdata = .{ .unknown = "\x07RFC8482\x00" } };
    return .{ .cacheable = false, .msg = .{
        .header = .{ .id = 0, .flags = .{ .qr = true, .opcode = .query, .aa = false, .tc = false, .rd = c.rd, .ra = true, .z = 0, .ad = false, .cd = c.cd, .rcode = .no_error } },
        .questions = try arena.dupe(dns.Question, &.{q}),
        .answers = try arena.dupe(dns.ResourceRecord, &.{rr}),
    } };
}

/// The answer cell shaped for a client: bogus is SERVFAIL unless CD, a
/// verified hop's TTLs end with its proof, signatures only to DO, AD only
/// when asked (RFC 6840 §5.7). `cached`: settled from memory alone.
pub fn answer(arena: Allocator, g: *graph.Graph, root: graph.CellId, q: dns.Question, c: Client, minimal: bool, cached: bool) !Served {
    const a = g.cell(root).value.answer;
    var chain: std.ArrayList(dns.ResourceRecord) = .empty;
    var last: graph.Reply = .{ .kind = .servfail, .rcode = .server_failure, .aa = false };
    var age: u32 = 0;
    var life: u32 = std.math.maxInt(u32);
    const served = !a.broken and (a.status != .bogus or c.cd);
    if (served) for (a.hops, 0..) |h, i| {
        last = g.cell(h).value.rrset;
        age = @intCast(@divTrunc(g.now() - last.stored_ns, std.time.ns_per_s));
        life = std.math.maxInt(u32);
        if (i < a.judged.len) {
            const proven = g.cell(a.judged[i]).value.secure.proven_until_ns;
            life = @intCast(@min(@max(@divTrunc(proven - g.now(), std.time.ns_per_s), 0), std.math.maxInt(u32)));
        }
        try appendAged(arena, &chain, last.answers, age, life, c.do_bit);
    };
    const positive = last.kind == .answer or last.kind == .alias;
    var authorities: std.ArrayList(dns.ResourceRecord) = .empty;
    var additionals: std.ArrayList(dns.ResourceRecord) = .empty;
    if (!(positive and minimal and q.qtype != .ns)) {
        try appendAged(arena, &authorities, last.authorities, age, life, c.do_bit);
        try appendAged(arena, &additionals, last.additionals, age, life, c.do_bit);
    }
    const ede: ?dns.Ede = if (a.broken)
        .{ .code = .other, .text = "cname loop" }
    else if (!served)
        .{ .code = .dnssec_bogus }
    else if (last.kind == .servfail)
        .{ .code = if (cached) .cached_error else last.ede orelse .no_reachable_authority }
    else if (last.ede) |code|
        .{ .code = code }
    else
        null;
    return .{ .cacheable = g.cell(root).expires_ns > g.now(), .ede = ede, .msg = .{
        .header = .{ .id = 0, .flags = .{
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = c.rd,
            .ra = true,
            .z = 0,
            .ad = served and a.status == .secure and (c.do_bit or c.ad),
            .cd = c.cd,
            .rcode = if (last.kind == .servfail) last.rcode else if (last.kind == .nxdomain) .name_error else .no_error,
        } },
        .questions = try arena.dupe(dns.Question, &.{q}),
        .answers = chain.items,
        .authorities = authorities.items,
        .additionals = additionals.items,
    } };
}

/// TTLs less the time since the reply was taken, at most `life`;
/// signatures only when wanted.
fn appendAged(arena: Allocator, out: *std.ArrayList(dns.ResourceRecord), rrs: []const dns.ResourceRecord, age: u32, life: u32, sigs: bool) !void {
    for (rrs) |rr| {
        if (rr.rtype == .rrsig and !sigs) continue;
        var aged = rr;
        aged.ttl = @min(rr.ttl -| age, life);
        try out.append(arena, aged);
    }
}

// ── The proof-of-concept server: one thread, one graph, the live edge.
// Every policy that is not a cell lives here.

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
const special_use = @import("../special_use.zig");
const server = @import("../server.zig");
const Edge = @import("edge.zig");
const log = std.log.scoped(.graph);

const max_frame = 4096;
const udp_recv_max = 4096;

const Conn = struct {
    fd: posix.fd_t,
    token: u32,
    buf: [2 + max_frame]u8 = undefined,
    len: usize = 0,
    served: u32 = 0,
    last_ns: i64,
    /// Answers owed; a half-closed client waits for them.
    owed: u32 = 0,
    eof: bool = false,
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
            .conn => |c| try s.readTcp(c, events),
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
        // BCP 140: a silent drop is the only non-amplifying refusal.
        if (data.len < 12 or data[2] & 0x80 != 0 or !acl.allow(s.cfg.allow_from, from)) return;
        try s.ask(data, .{ .udp = .{ .fd = fd, .addr = from } });
    }

    fn accept(s: *Server, fd: posix.fd_t) !void {
        while (true) {
            const rc = linux.accept4(fd, null, null, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC);
            if (linux.errno(rc) != .SUCCESS) return;
            const c = try s.gpa.create(Conn);
            c.* = .{ .fd = @intCast(rc), .token = 0, .last_ns = s.e.now_ns };
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
        var start: usize = 0;
        while (c.len - start >= 2) {
            const flen: usize = mem.readInt(u16, c.buf[start..][0..2], .big);
            if (flen == 0 or flen > max_frame or c.served >= s.cfg.tcp_queries_per_conn) return s.drop(c);
            if (c.len - start < 2 + flen) break;
            c.served += 1;
            c.owed += 1;
            try s.ask(c.buf[start + 2 ..][0..flen], .{ .tcp = c });
            start += 2 + flen;
        }
        mem.copyForwards(u8, c.buf[0 .. c.len - start], c.buf[start..c.len]);
        c.len -= start;
    }

    /// Clients still waiting get nothing; the graph frees their roots.
    fn deinit(s: *Server) void {
        for (s.watched.items) |w| if (w == .conn) s.drop(w.conn);
        for (s.pending.items) |p| {
            s.g.unhold(p.root);
            s.gpa.free(p.wire);
        }
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
        s.gpa.destroy(c);
    }

    const c_addr_none = na.initIp4(.{ 0, 0, 0, 0 }, 0);

    fn sweep(s: *Server) void {
        const idle_ns = @as(i64, s.cfg.tcp_idle_timeout_ms) * std.time.ns_per_ms;
        var i: usize = 0;
        while (i < s.watched.items.len) : (i += 1) {
            const c = switch (s.watched.items[i]) {
                .conn => |c| c,
                else => continue,
            };
            if (c.owed == 0 and s.e.now_ns - c.last_ns >= idle_ns) s.drop(c);
        }
    }

    fn ask(s: *Server, wire: []const u8, reply: Reply) !void {
        _ = s.scratch.reset(.retain_capacity);
        const arena = s.scratch.allocator();
        const query = dns.parseMessage(arena, wire) catch {
            const id = mem.readInt(u16, wire[0..2], .big);
            return s.sendError(reply, id, .query, .format_error, 0, wire[2] & 1 != 0, &.{}, null);
        };
        if (response.validateQuery(query)) |v| return s.sendError(reply, query.header.id, query.header.flags.opcode, v.rcode, v.extended_rcode, query.header.flags.rd, query.questions, query.opt);
        const q = query.questions[0];
        const client: Client = .{ .rd = query.header.flags.rd, .cd = query.header.flags.cd, .do_bit = query.opt != null and query.opt.?.do_bit, .ad = query.header.flags.ad };
        var name_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const name = q.name.formatInto(&name_buf);
        if (build_options.testing_enabled) if (server.parseAdvanceClockQname(dns.stripTrailingDot(name))) |secs| {
            monotonic.advanceTestClock(secs);
            return s.send(reply, query, response.synthesizedMessage(&.{}, &.{}, .no_error, false), null);
        };
        const action = special_use.classify(name, q.qtype);
        if (action != .none) return s.send(reply, query, try special_use.synthesize(arena, name, action), null);
        if (q.qtype == .any) return s.send(reply, query, (try hinfo(arena, q, client)).msg, null);
        const root = try s.g.demandRoot(q.name, q.qtype, client.cd);
        try s.g.drain();
        if (s.g.cell(root).settled) {
            defer s.g.unhold(root);
            const served = try answer(arena, s.g, root, q, client, s.cfg.minimal_responses, true);
            return s.send(reply, query, served.msg, served.ede);
        }
        try s.pending.append(s.gpa, .{ .root = root, .wire = try s.gpa.dupe(u8, wire), .reply = reply });
    }

    fn settle(s: *Server) !void {
        var i: usize = 0;
        while (i < s.pending.items.len) {
            const p = s.pending.items[i];
            if (!s.g.cell(p.root).settled) {
                i += 1;
                continue;
            }
            _ = s.scratch.reset(.retain_capacity);
            const arena = s.scratch.allocator();
            const query = try dns.parseMessage(arena, p.wire);
            const q = query.questions[0];
            const client: Client = .{ .rd = query.header.flags.rd, .cd = query.header.flags.cd, .do_bit = query.opt != null and query.opt.?.do_bit, .ad = query.header.flags.ad };
            const served = try answer(arena, s.g, p.root, q, client, s.cfg.minimal_responses, false);
            s.send(p.reply, query, served.msg, served.ede);
            s.g.unhold(p.root);
            s.gpa.free(p.wire);
            _ = s.pending.swapRemove(i);
        }
    }

    fn send(s: *Server, reply: Reply, query: dns.Message, msg: dns.Message, ede: ?dns.Ede) void {
        const arena = s.scratch.allocator();
        var buf: [dns.max_message_len]u8 = undefined;
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
        const wire = response.buildResponseWire(&buf, ctx, msg, arena) orelse
            return s.sendError(reply, query.header.id, query.header.flags.opcode, .server_failure, 0, query.header.flags.rd, query.questions, query.opt);
        s.write(reply, wire);
    }

    fn sendError(s: *Server, reply: Reply, id: u16, opcode: dns.OpCode, rcode: dns.RCode, extended: u8, rd: bool, questions: []const dns.Question, opt: ?dns.OptRecord) void {
        var buf: [dns.max_udp_payload]u8 = undefined;
        const wire = response.serializeErrorResponse(&buf, id, opcode, rcode, extended, rd, questions, opt) orelse return;
        s.write(reply, wire);
    }

    fn write(s: *Server, reply: Reply, wire: []const u8) void {
        switch (reply) {
            .udp => |u| {
                if (u.fd < 0) return;
                var pa: na.PosixAddress = undefined;
                const len = na.toSockaddr(&u.addr, &pa);
                _ = sys.sendto(u.fd, wire, linux.MSG.DONTWAIT, &pa.any, len) catch {};
            },
            .tcp => |c| {
                var hdr: [2]u8 = undefined;
                mem.writeInt(u16, &hdr, @intCast(wire.len), .big);
                c.owed -= 1;
                c.last_ns = s.e.now_ns;
                const ok = (sys.write(c.fd, &hdr) catch 0) == 2 and (sys.write(c.fd, wire) catch 0) == wire.len;
                if (!ok or (c.eof and c.owed == 0)) s.drop(c);
            },
        }
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
        .trace = trace,
    }, e.edge());
    defer g.deinit();
    g.attach();
    var s: Server = .{ .gpa = gpa, .cfg = cfg, .e = &e, .g = &g, .scratch = std.heap.ArenaAllocator.init(gpa) };
    defer s.deinit();
    for (cfg.listen) |addr| try s.listen(addr);
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
    log.info("footprint: rss {d} MiB; store {d} KiB in {d} facts, {d} KiB more held by cells, {d} evicted, {d} refused; {d} live cells", .{
        rss_pages * std.heap.pageSize() / (1024 * 1024),
        g.store.held / 1024,
        g.store.map.count(),
        (g.store.bytes - g.store.held) / 1024,
        g.store.evictions,
        g.store.refusals,
        g.live,
    });
}
