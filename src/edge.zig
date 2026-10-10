//! The live edge: one epoll, a socket per exchange, a timer heap.
//! Listener fds ride the same epoll under a token.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");
const monotonic = @import("monotonic.zig");
const rand = @import("rand.zig");
const graph = @import("graph.zig");

const CellId = graph.CellId;
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
    /// The cell's generation for a wake, the flight's sequence for a timeout.
    gen: u32,
    kind: enum { timeout, wake },

    fn before(_: void, a: Timer, b: Timer) std.math.Order {
        return switch (std.math.order(a.at_ns, b.at_ns)) {
            .eq => std.math.order(a.seq, b.seq),
            else => |o| o,
        };
    }
};

/// Ids recycle: a flight is told from its predecessors by its timer's sequence.
const Flight = struct {
    fd: posix.fd_t,
    tcp: ?*Tcp = null,
    seq: u32,
};

const Tcp = struct {
    query: []u8,
    written: usize = 0,
    reply: [2 + @as(usize, dns.max_message_len)]u8 = undefined,
    got: usize = 0,
};

/// Tells a token from a cell id.
const client_tag: u64 = 1 << 32;

gpa: Allocator,
/// TCP buffers are work in progress: the graph's `Work` counts them.
work: Allocator,
epfd: posix.fd_t,
now_ns: i64 = 0,
wall_sec: i64 = 0,
timers: std.PriorityQueue(Timer, void, Timer.before) = .empty,
seq: u32 = 0,
flights: std.AutoHashMapUnmanaged(CellId, Flight) = .empty,
/// Events that own nothing.
queue: std.ArrayList(Event) = .empty,
head: usize = 0,
/// A reply is read only when its turn comes, so the consumer may stop at
/// any event.
batch: [64]linux.epoll_event = undefined,
batch_len: usize = 0,
batch_at: usize = 0,
rx: [dns.max_message_len]u8 = undefined,

pub fn init(gpa: Allocator) !Edge {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.EpollCreateFailed;
    var e: Edge = .{ .gpa = gpa, .work = gpa, .epfd = @intCast(rc) };
    e.tick();
    return e;
}

pub fn deinit(e: *Edge) void {
    var it = e.flights.valueIterator();
    while (it.next()) |f| e.close(f.*);
    e.flights.deinit(e.gpa);
    e.timers.deinit(e.gpa);
    e.queue.deinit(e.gpa);
    sys.close(e.epfd);
}

pub fn edge(e: *Edge) graph.Edge {
    return .{ .ctx = e, .now_ns = &e.now_ns, .wall_sec = &e.wall_sec, .rng = rand.thread, .sendFn = sendErased, .wakeFn = wakeErased };
}

fn sendErased(ctx: *anyopaque, ex: Exchange) anyerror!void {
    return @as(*Edge, @ptrCast(@alignCast(ctx))).send(ex);
}

fn wakeErased(ctx: *anyopaque, id: CellId, gen: u32, at_ns: i64) anyerror!void {
    _ = try @as(*Edge, @ptrCast(@alignCast(ctx))).schedule(at_ns, id, gen, .wake);
}

/// Time is read once per event: rules see one instant.
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

fn ctl(e: *Edge, op: u32, fd: posix.fd_t, events: u32, data: u64) !void {
    var ev: linux.epoll_event = .{ .events = events, .data = .{ .u64 = data } };
    if (linux.errno(linux.epoll_ctl(e.epfd, op, fd, &ev)) != .SUCCESS) return error.EpollCtlFailed;
}

fn send(e: *Edge, ex: Exchange) !void {
    var flight = e.open(ex) catch |err| {
        const completion: Completion = switch (err) {
            error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources, error.OutOfMemory, error.WouldBlock, error.EpollCtlFailed => .unsent,
            // Unreachable from here: the server's to answer for.
            else => .timeout,
        };
        return e.push(.{ .exchange = .{ .id = ex.id, .completion = completion } });
    };
    flight.seq = e.seq + 1;
    _ = try e.schedule(ex.deadline_ns, ex.id, flight.seq, .timeout);
    try e.flights.put(e.gpa, ex.id, flight);
}

fn open(e: *Edge, ex: Exchange) !Flight {
    // Reserved before the fd exists, so nothing after registering it can fail.
    try e.timers.ensureUnusedCapacity(e.gpa, 1);
    try e.flights.ensureUnusedCapacity(e.gpa, 1);
    const kind: u32 = if (ex.transport == .udp) posix.SOCK.DGRAM else posix.SOCK.STREAM;
    const fd = try sys.socket(na.afU32(ex.server), kind | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    errdefer sys.close(fd);
    if (ex.transport == .udp) {
        try na.connectTo(fd, &ex.server);
        _ = try sys.sendto(fd, ex.wire, 0, null, 0);
        try e.ctl(linux.EPOLL.CTL_ADD, fd, linux.EPOLL.IN, ex.id);
        return .{ .fd = fd, .seq = 0 };
    }
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
    return .{ .fd = fd, .tcp = t, .seq = 0 };
}

fn close(e: *Edge, f: Flight) void {
    sys.close(f.fd);
    if (f.tcp) |t| {
        e.work.free(t.query);
        e.work.destroy(t);
    }
}

fn finish(e: *Edge, id: CellId, completion: Completion) Event {
    e.close(e.flights.fetchRemove(id).?.value);
    return .{ .exchange = .{ .id = id, .completion = completion } };
}

fn schedule(e: *Edge, at_ns: i64, id: CellId, gen: u32, kind: @FieldType(Timer, "kind")) !u32 {
    e.seq += 1;
    try e.timers.push(e.gpa, .{ .at_ns = at_ns, .seq = e.seq, .id = id, .gen = gen, .kind = kind });
    return e.seq;
}

fn push(e: *Edge, ev: Event) !void {
    try e.queue.append(e.gpa, ev);
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

/// The next event, or null once `until_ns` passes with nothing due.
pub fn next(e: *Edge, until_ns: i64) !?Event {
    while (true) {
        if (e.pop()) |ev| return ev;
        while (e.batch_at < e.batch_len) {
            const polled = e.batch[e.batch_at];
            e.batch_at += 1;
            if (try e.ready(polled)) |ev| return ev;
        }
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

/// A timeout for a finished flight, or a later one under its recycled id,
/// is stale; a wake carries its cell's generation for the graph to check.
fn fire(e: *Edge) !void {
    while (e.timers.peek()) |t| {
        if (t.at_ns > e.now_ns) break;
        // Reserved before the timer leaves the heap, so its event can't be lost.
        try e.queue.ensureUnusedCapacity(e.gpa, 1);
        _ = e.timers.pop();
        switch (t.kind) {
            .wake => e.queue.appendAssumeCapacity(.{ .exchange = .{ .id = t.id, .completion = .{ .wake = t.gen } } }),
            .timeout => if (e.flights.get(t.id)) |f| if (f.seq == t.gen) e.queue.appendAssumeCapacity(e.finish(t.id, .timeout)),
        }
    }
}

fn ready(e: *Edge, ev: linux.epoll_event) !?Event {
    const d = ev.data.u64;
    if (d & client_tag != 0) return .{ .client = .{ .token = @truncate(d), .events = ev.events } };
    const id: CellId = @truncate(d);
    const f = e.flights.getPtr(id) orelse return null;
    if (f.tcp) |t| return e.readyTcp(id, f.fd, t);
    const rc = linux.recvfrom(f.fd, &e.rx, e.rx.len, linux.MSG.DONTWAIT, null, null);
    return switch (linux.errno(rc)) {
        .SUCCESS => e.finish(id, .{ .reply = e.rx[0..rc] }),
        .AGAIN, .INTR => null,
        // ICMP unreachable and kin: nobody there.
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
    const rc = linux.read(fd, t.reply[t.got..].ptr, t.reply.len - t.got);
    switch (linux.errno(rc)) {
        .SUCCESS => {
            if (rc == 0) return e.finish(id, .timeout);
            t.got += rc;
        },
        .AGAIN, .INTR => return null,
        else => return e.finish(id, .timeout),
    }
    if (t.got < 2) return null;
    const len = mem.readInt(u16, t.reply[0..2], .big);
    if (t.got < 2 + @as(usize, len)) return null;
    // Copied out before `finish` frees the buffer.
    @memcpy(e.rx[0..len], t.reply[2..][0..len]);
    return e.finish(id, .{ .reply = e.rx[0..len] });
}

test "a consumer that stops between events leaves nothing behind" {
    var e = try Edge.init(std.testing.allocator);
    defer e.deinit();

    const server = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer sys.close(server);
    try na.bindTo(server, &na.initIp4(.{ 127, 0, 0, 1 }, 0));
    var sa: na.PosixAddress = undefined;
    var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    try sys.getsockname(server, &sa.any, &sa_len);
    try e.send(.{ .id = 1, .server = na.fromSockaddr(&sa), .transport = .udp, .wire = "ask", .deadline_ns = std.math.maxInt(i64) });

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

test "a timer whose event can't be queued stays due" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var e = try Edge.init(failing.allocator());
    defer e.deinit();

    const server = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer sys.close(server);
    try na.bindTo(server, &na.initIp4(.{ 127, 0, 0, 1 }, 0));
    var sa: na.PosixAddress = undefined;
    var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    try sys.getsockname(server, &sa.any, &sa_len);
    try e.send(.{ .id = 1, .server = na.fromSockaddr(&sa), .transport = .udp, .wire = "ask", .deadline_ns = 0 });

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, e.next(0));
    failing.fail_index = std.math.maxInt(usize);
    const ev = ((try e.next(0)) orelse return error.TestUnexpectedResult).exchange;
    try std.testing.expect(ev.id == 1 and ev.completion == .timeout);
}
