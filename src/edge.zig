//! The live edge: one epoll, a socket per exchange, a timer heap.
//! Listener fds and sessions ride the same epoll under a token.
gpa: Allocator,
work: Allocator,
epfd: posix.fd_t,
now_ns: i64 = 0,
wall_sec: i64 = 0,
timers: std.PriorityQueue(Timer, void, Timer.before) = .empty,
seq: u32 = 0,
flights: std.array_hash_map.Auto(CellId, Flight) = .empty,
idle: std.EnumArray(Family, Idle) = .initFill(.{}),
idle_max: u32 = std.math.maxInt(u32),
queue: std.ArrayList(Event) = .empty,
head: usize = 0,
batch: [64]linux.epoll_event = undefined,
batch_len: usize = 0,
batch_at: usize = 0,
rx: [dns.max_message_len]u8 = undefined,
sessions: ?*Sessions = null,

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const sys = @import("sys.zig");
const monotonic = @import("monotonic.zig");
const rand = @import("rand.zig");
const graph = @import("graph.zig");
const model = @import("model.zig");
const Sessions = @import("sessions.zig");

const CellId = model.CellId;
const Completion = graph.Completion;
const Exchange = graph.Exchange;

const Edge = @This();

pub const Event = union(enum) {
    /// Reply bytes are borrowed until the next call to `next`.
    exchange: struct { id: CellId, completion: Completion },
    client: struct { token: u32, events: u32 },
};

const Timer = struct {
    at_ns: i64,
    seq: u32,
    id: CellId,
    /// By kind: a wake's cell generation, a timeout's flight sequence, or a
    /// session's token, whose wake sequence then rides in `id`.
    gen: u32,
    kind: Kind,

    const Kind = enum { timeout, wake, carried, conn };

    fn before(_: void, a: Timer, b: Timer) std.math.Order {
        return switch (std.math.order(a.at_ns, b.at_ns)) {
            .eq => std.math.order(a.seq, b.seq),
            else => |o| o,
        };
    }
};

const Flight = struct {
    fd: posix.fd_t,
    seq: u32,
    over: union(enum) {
        datagram: Family,
        stream: *Tcp,
    },
};

const Family = std.meta.Tag(na.Address);

const Idle = struct {
    fds: std.ArrayList(posix.fd_t) = .empty,
    aged: usize = 0,

    fn pop(idle: *Idle) ?posix.fd_t {
        const fd = idle.fds.pop() orelse return null;
        idle.aged = @min(idle.aged, idle.fds.items.len);
        return fd;
    }
};

const Tcp = struct {
    query: []u8,
    written: usize = 0,
    got: std.ArrayList(u8) = .empty,
};

const client_tag: u64 = 1 << 32;
pub const session_tag: u64 = 1 << 33;

pub fn init(gpa: Allocator) !Edge {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.EpollCreateFailed;
    var e: Edge = .{ .gpa = gpa, .work = gpa, .epfd = @intCast(rc) };
    e.tick();
    return e;
}

pub fn enableSessions(e: *Edge, plain_port: u16, dot_port: u16) !void {
    e.sessions = try .create(e, plain_port, dot_port);
}

pub fn deinit(e: *Edge) void {
    for (e.flights.values()) |f| e.close(f);
    e.flights.deinit(e.gpa);
    for (&e.idle.values) |*idle| {
        for (idle.fds.items) |fd| sys.close(fd);
        idle.fds.deinit(e.gpa);
    }
    if (e.sessions) |s| s.destroy();
    e.timers.deinit(e.gpa);
    e.queue.deinit(e.gpa);
    sys.close(e.epfd);
}

pub fn edge(e: *Edge) graph.Edge {
    return .{ .ctx = e, .now_ns = &e.now_ns, .wall_sec = &e.wall_sec, .rng = rand.thread, .sendFn = sendErased, .wakeFn = wakeErased, .quoteFn = if (e.sessions != null) quoteErased else null };
}

fn quoteErased(ctx: *anyopaque, server: na.AddressKey, need: graph.Need) graph.Quote {
    return @as(*Edge, @ptrCast(@alignCast(ctx))).sessions.?.quote(server, need);
}

fn sendErased(ctx: *anyopaque, ex: Exchange) graph.Error!graph.Exposure {
    return @as(*Edge, @ptrCast(@alignCast(ctx))).send(ex);
}

fn wakeErased(ctx: *anyopaque, id: CellId, gen: u32, at_ns: i64) graph.Error!void {
    try @as(*Edge, @ptrCast(@alignCast(ctx))).schedule(at_ns, id, gen, .wake);
}

fn tick(e: *Edge) void {
    e.now_ns = monotonic.nowNs();
    e.wall_sec = monotonic.wallclockSec();
}

pub fn watch(e: *Edge, fd: posix.fd_t, token: u32, events: u32) !void {
    try e.ctl(linux.EPOLL.CTL_ADD, fd, events, client_tag | token);
}

pub fn rewatch(e: *Edge, fd: posix.fd_t, token: u32, events: u32) !void {
    try e.ctl(linux.EPOLL.CTL_MOD, fd, events, client_tag | token);
}

pub fn ctl(e: *Edge, op: u32, fd: posix.fd_t, events: u32, data: u64) !void {
    var ev: linux.epoll_event = .{ .events = events, .data = .{ .u64 = data } };
    if (linux.errno(linux.epoll_ctl(e.epfd, op, fd, &ev)) != .SUCCESS) return error.EpollCtlFailed;
}

fn send(e: *Edge, ex: Exchange) !graph.Exposure {
    if (e.sessions) |s| if (try s.carry(ex)) return .encrypted;
    try e.reserve();
    var flight = e.open(ex) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            e.push(.{ .exchange = .{ .id = ex.id, .completion = .unsent } });
            return .none;
        },
    };
    errdefer e.close(flight);
    flight.seq = e.seq + 1;
    try e.schedule(ex.deadline_ns, ex.id, flight.seq, .timeout);
    try e.flights.put(e.gpa, ex.id, flight);
    return .cleartext;
}

fn open(e: *Edge, ex: Exchange) !Flight {
    try e.timers.ensureUnusedCapacity(e.gpa, 1);
    try e.flights.ensureUnusedCapacity(e.gpa, 1);
    const flags = posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
    if (ex.need == .datagram) {
        const family = std.meta.activeTag(ex.server);
        const rested = e.idle.getPtr(family).pop();
        const fd = rested orelse try sys.socket(na.afU32(ex.server), posix.SOCK.DGRAM | flags, 0);
        errdefer sys.close(fd);
        try na.connectTo(fd, &ex.server);
        _ = try sys.sendto(fd, ex.wire, 0, null, 0);
        try e.ctl(if (rested == null) linux.EPOLL.CTL_ADD else linux.EPOLL.CTL_MOD, fd, linux.EPOLL.IN, ex.id);
        return .{ .fd = fd, .seq = 0, .over = .{ .datagram = family } };
    }
    const fd = try sys.socket(na.afU32(ex.server), posix.SOCK.STREAM | flags, 0);
    errdefer sys.close(fd);
    const t = try e.work.create(Tcp);
    errdefer e.work.destroy(t);
    t.* = .{ .query = try e.work.alloc(u8, 2 + ex.wire.len) };
    errdefer e.work.free(t.query);
    mem.writeInt(u16, t.query[0..2], @intCast(ex.wire.len), .big);
    @memcpy(t.query[2..], ex.wire);
    na.connectTo(fd, &ex.server) catch |err| switch (err) {
        error.WouldBlock => {},
        else => return err,
    };
    try e.ctl(linux.EPOLL.CTL_ADD, fd, linux.EPOLL.OUT, ex.id);
    return .{ .fd = fd, .seq = 0, .over = .{ .stream = t } };
}

fn close(e: *Edge, f: Flight) void {
    switch (f.over) {
        .datagram => |family| e.rest(f.fd, family),
        .stream => |t| {
            sys.close(f.fd);
            t.got.deinit(e.work);
            e.work.free(t.query);
            e.work.destroy(t);
        },
    }
}

fn rest(e: *Edge, fd: posix.fd_t, family: Family) void {
    const idle = e.idle.getPtr(family);
    if (idle.fds.items.len >= e.idle_max or !emptied(fd)) return sys.close(fd);
    idle.fds.append(e.gpa, fd) catch sys.close(fd);
}

/// Call about once a second: a socket idle for a whole tick is closed.
pub fn trim(e: *Edge) void {
    for (&e.idle.values) |*idle| {
        for (0..idle.aged) |_| sys.close(idle.fds.pop().?);
        idle.aged = idle.fds.items.len;
    }
}

fn emptied(fd: posix.fd_t) bool {
    sys.detach(fd) catch return false;
    // A datagram that arrived before the disconnect is still queued, and the
    // socket's next exchange would read it. None can arrive now, and a read
    // of no bytes discards one.
    var none: [0]u8 = .{};
    while (true) switch (linux.errno(linux.recvfrom(fd, &none, 0, linux.MSG.DONTWAIT, null, null))) {
        .SUCCESS, .INTR => {},
        .AGAIN => return true,
        else => return false,
    };
}

fn finish(e: *Edge, id: CellId, completion: Completion) Event {
    e.close(e.flights.fetchSwapRemove(id).?.value);
    return .{ .exchange = .{ .id = id, .completion = completion } };
}

pub fn schedule(e: *Edge, at_ns: i64, id: CellId, gen: u32, kind: Timer.Kind) !void {
    try e.reserve();
    e.seq += 1;
    try e.timers.push(e.gpa, .{ .at_ns = at_ns, .seq = e.seq, .id = id, .gen = gen, .kind = kind });
}

/// Room for one more event than there are timers and queued events: a timer
/// or an exchange yields at most one, so what it owes is always queued.
fn reserve(e: *Edge) !void {
    try e.queue.ensureTotalCapacity(e.gpa, e.queue.items.len + e.timers.count() + 1);
}

pub fn push(e: *Edge, ev: Event) void {
    e.queue.appendAssumeCapacity(ev);
}

fn pop(e: *Edge) ?Event {
    if (e.head == e.queue.items.len) return null;
    const ev = e.queue.items[e.head];
    e.head += 1;
    if (e.head == e.queue.items.len) {
        e.queue.clearRetainingCapacity();
        e.head = 0;
    }
    return ev;
}

pub fn next(e: *Edge, until_ns: i64) !?Event {
    while (true) {
        if (e.pop()) |ev| return ev;
        if (e.batch_at < e.batch_len) {
            const polled = e.batch[e.batch_at];
            e.batch_at += 1;
            if (try e.ready(polled)) |ev| return ev;
            continue;
        }
        if (e.sessions) |s| try s.flush();
        e.tick();
        try e.fire();
        if (e.pop()) |ev| return ev;
        if (e.now_ns >= until_ns) return null;
        var wake_at = until_ns;
        if (e.timers.peek()) |t| wake_at = @min(wake_at, t.at_ns);
        const left = @max(wake_at - e.now_ns, 0);
        const ms: i32 = @intCast(@min(std.math.divCeil(i64, left, std.time.ns_per_ms) catch unreachable, std.math.maxInt(i32)));
        const rc = linux.epoll_wait(e.epfd, &e.batch, e.batch.len, ms);
        e.batch_len = switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .INTR => 0,
            else => return error.EpollWaitFailed,
        };
        e.batch_at = 0;
        e.tick();
    }
}

fn fire(e: *Edge) !void {
    while (e.timers.peek()) |t| {
        if (t.at_ns > e.now_ns) break;
        _ = e.timers.pop();
        switch (t.kind) {
            .wake => e.queue.appendAssumeCapacity(.{ .exchange = .{ .id = t.id, .completion = .{ .wake = t.gen } } }),
            .timeout => if (e.flights.get(t.id)) |f| if (f.seq == t.gen) e.queue.appendAssumeCapacity(e.finish(t.id, .timeout)),
            .carried => try e.sessions.?.flightDue(t.id, t.gen),
            .conn => try e.sessions.?.connDue(t.gen, t.id),
        }
    }
}

fn ready(e: *Edge, ev: linux.epoll_event) !?Event {
    const d = ev.data.u64;
    if (d & client_tag != 0) return .{ .client = .{ .token = @truncate(d), .events = ev.events } };
    if (d & session_tag != 0) {
        try e.sessions.?.ready(@truncate(d), ev.events);
        return null;
    }
    const id: CellId = @truncate(d);
    const f = e.flights.getPtr(id) orelse return null;
    switch (f.over) {
        .datagram => {},
        .stream => |t| return e.readyTcp(id, f.fd, t),
    }
    const rc = linux.recvfrom(f.fd, &e.rx, e.rx.len, linux.MSG.DONTWAIT, null, null);
    return switch (linux.errno(rc)) {
        .SUCCESS => e.finish(id, .{ .reply = .{ .bytes = e.rx[0..rc] } }),
        .AGAIN, .INTR => null,
        else => e.finish(id, .timeout),
    };
}

fn readyTcp(e: *Edge, id: CellId, fd: posix.fd_t, t: *Tcp) !?Event {
    if (t.written < t.query.len) {
        const rc = linux.write(fd, t.query[t.written..].ptr, t.query.len - t.written);
        switch (linux.errno(rc)) {
            .SUCCESS => t.written += rc,
            .AGAIN, .INTR => return null,
            else => return e.finish(id, .timeout),
        }
        if (t.written == t.query.len) try e.ctl(linux.EPOLL.CTL_MOD, fd, linux.EPOLL.IN, id);
        return null;
    }
    const rc = linux.read(fd, &e.rx, e.rx.len);
    switch (linux.errno(rc)) {
        .SUCCESS => if (rc == 0) return e.finish(id, .timeout),
        .AGAIN, .INTR => return null,
        else => return e.finish(id, .timeout),
    }
    var held: []const u8 = e.rx[0..rc];
    if (t.got.items.len > 0 or framed(held) == null) {
        try t.got.appendSlice(e.work, held);
        held = t.got.items;
    }
    const reply = framed(held) orelse return null;
    // Copied out before `finish` frees the buffer.
    mem.copyForwards(u8, e.rx[0..reply.len], reply);
    return e.finish(id, .{ .reply = .{ .bytes = e.rx[0..reply.len], .stream = true } });
}

fn framed(bytes: []const u8) ?[]const u8 {
    if (bytes.len < 2) return null;
    const len = mem.readInt(u16, bytes[0..2], .big);
    return if (bytes.len < 2 + @as(usize, len)) null else bytes[2..][0..len];
}

test "a consumer that stops between events leaves nothing behind" {
    var e = try Edge.init(std.testing.allocator);
    defer e.deinit();

    const server = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer sys.close(server);
    try na.bindTo(server, &na.initIp4(.{ 127, 0, 0, 1 }, 0));
    var sa: na.PosixAddress = undefined;
    var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    _ = linux.getsockname(server, &sa.any, &sa_len);
    _ = try e.send(.{ .id = 1, .server = na.fromSockaddr(&sa), .need = .datagram, .wire = "ask", .deadline_ns = std.math.maxInt(i64) });

    var stop: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&stop, .{ .CLOEXEC = true })) != .SUCCESS) return error.PipeFailed;
    defer for (stop) |fd| sys.close(fd);
    try e.watch(stop[0], 0, linux.EPOLL.IN);
    _ = try sys.write(stop[1], "x");

    var buf: [8]u8 = undefined;
    const n = linux.recvfrom(server, &buf, buf.len, 0, &sa.any, &sa_len);
    if (linux.errno(n) != .SUCCESS) return error.RecvFailed;
    _ = try sys.sendto(server, "reply", 0, &sa.any, sa_len);
    var pfd: [1]linux.pollfd = .{.{ .fd = e.flights.get(1).?.fd, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.errno(linux.poll(&pfd, 1, -1)) != .SUCCESS) return error.PollFailed;

    try std.testing.expect((try e.next(std.math.maxInt(i64))).? == .client);
    try std.testing.expectEqual(2, e.batch_len);
}

const Peer = struct {
    fd: posix.fd_t,
    addr: na.Address,

    fn init() !Peer {
        const fd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
        errdefer sys.close(fd);
        try na.bindTo(fd, &na.initIp4(.{ 127, 0, 0, 1 }, 0));
        var sa: na.PosixAddress = undefined;
        var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
        _ = linux.getsockname(fd, &sa.any, &sa_len);
        return .{ .fd = fd, .addr = na.fromSockaddr(&sa) };
    }

    fn hear(p: Peer) !na.PosixAddress {
        var buf: [8]u8 = undefined;
        var sa: na.PosixAddress = undefined;
        var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
        if (linux.errno(linux.recvfrom(p.fd, &buf, buf.len, 0, &sa.any, &sa_len)) != .SUCCESS) return error.RecvFailed;
        return sa;
    }

    fn tell(p: Peer, to: *const na.PosixAddress, bytes: []const u8) !void {
        _ = try sys.sendto(p.fd, bytes, 0, &to.any, @sizeOf(posix.sockaddr.in));
    }
};

test "no query leaves from the port of the one before it" {
    var e = try Edge.init(std.testing.allocator);
    defer e.deinit();
    const peer = try Peer.init();
    defer sys.close(peer.fd);

    var last: u16 = 0;
    var repeats: usize = 0;
    for (1..9) |id| {
        _ = try e.send(.{ .id = @intCast(id), .server = peer.addr, .need = .datagram, .wire = "ask", .deadline_ns = std.math.maxInt(i64) });
        const asker = try peer.hear();
        try peer.tell(&asker, "reply");
        const ev = ((try e.next(std.math.maxInt(i64))) orelse return error.TestUnexpectedResult).exchange;
        try std.testing.expect(ev.id == id and ev.completion == .reply);
        if (asker.in.port == last) repeats += 1;
        last = asker.in.port;
    }
    // The kernel draws from about 28,000 ports, so one chance repeat is allowed.
    try std.testing.expect(repeats <= 1);
}

test "a socket carries its next exchange deaf to what was sent to its last" {
    var e = try Edge.init(std.testing.allocator);
    defer e.deinit();
    const first = try Peer.init();
    defer sys.close(first.fd);
    const second = try Peer.init();
    defer sys.close(second.fd);

    _ = try e.send(.{ .id = 1, .server = first.addr, .need = .datagram, .wire = "ask", .deadline_ns = std.math.maxInt(i64) });
    const fd = e.flights.get(1).?.fd;
    const asker = try first.hear();
    try first.tell(&asker, "reply");
    try first.tell(&asker, "again");
    const heard = ((try e.next(std.math.maxInt(i64))) orelse return error.TestUnexpectedResult).exchange;
    try std.testing.expect(heard.id == 1 and heard.completion == .reply);

    _ = try e.send(.{ .id = 2, .server = second.addr, .need = .datagram, .wire = "ask", .deadline_ns = e.now_ns + 20 * std.time.ns_per_ms });
    try std.testing.expectEqual(fd, e.flights.get(2).?.fd);
    const unheard = ((try e.next(std.math.maxInt(i64))) orelse return error.TestUnexpectedResult).exchange;
    try std.testing.expect(unheard.id == 2 and unheard.completion == .timeout);
}

test "a stream reply holds what has arrived" {
    var counted: std.testing.FailingAllocator = .init(std.testing.allocator, .{});
    var e = try Edge.init(std.testing.allocator);
    defer e.deinit();
    e.work = counted.allocator();

    const listener = try sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer sys.close(listener);
    try na.bindTo(listener, &na.initIp4(.{ 127, 0, 0, 1 }, 0));
    if (linux.errno(linux.listen(listener, 1)) != .SUCCESS) return error.ListenFailed;
    var sa: na.PosixAddress = undefined;
    var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    _ = linux.getsockname(listener, &sa.any, &sa_len);

    _ = try e.send(.{ .id = 1, .server = na.fromSockaddr(&sa), .need = .stream, .wire = "ask", .deadline_ns = std.math.maxInt(i64) });
    const rc = linux.accept4(listener, null, null, posix.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.AcceptFailed;
    const server: posix.fd_t = @intCast(rc);
    defer sys.close(server);
    try std.testing.expectEqual(null, try e.next(e.now_ns + 20 * std.time.ns_per_ms));
    var query: [5]u8 = undefined;
    try std.testing.expectEqual(query.len, linux.read(server, &query, query.len));
    try std.testing.expectEqualStrings("\x00\x03ask", &query);

    _ = try sys.write(server, "\x00\x05re");
    try std.testing.expectEqual(null, try e.next(e.now_ns + 20 * std.time.ns_per_ms));
    try std.testing.expect(counted.allocated_bytes - counted.freed_bytes < 1024);

    _ = try sys.write(server, "ply");
    const heard = ((try e.next(std.math.maxInt(i64))) orelse return error.TestUnexpectedResult).exchange;
    try std.testing.expect(heard.id == 1 and heard.completion.reply.stream);
    try std.testing.expectEqualStrings("reply", heard.completion.reply.bytes);
}
