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
    /// Reply bytes are the consumer's to free.
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
queue: std.ArrayList(Event) = .empty,
head: usize = 0,

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
    e.now_ns = @intCast(monotonic.nowNs());
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

fn finish(e: *Edge, id: CellId, completion: Completion) !void {
    const f = e.flights.fetchRemove(id) orelse return;
    e.close(f.value);
    try e.push(.{ .exchange = .{ .id = id, .completion = completion } });
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
        e.tick();
        try e.fire();
        if (e.pop()) |ev| return ev;
        if (e.now_ns >= until_ns) return null;
        var wake_at = until_ns;
        if (e.timers.peek()) |t| wake_at = @min(wake_at, t.at_ns);
        const left = @max(wake_at - e.now_ns, 0);
        const ms: i32 = @intCast(@min(std.math.divCeil(i64, left, std.time.ns_per_ms) catch unreachable, std.math.maxInt(i32)));
        var evs: [64]linux.epoll_event = undefined;
        const rc = linux.epoll_wait(e.epfd, &evs, evs.len, ms);
        const n: usize = switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .INTR => 0,
            else => return error.EpollWaitFailed,
        };
        e.tick();
        for (evs[0..n]) |ev| try e.ready(ev);
    }
}

/// A timeout for a finished flight, or a later one under its recycled id,
/// is stale; a wake carries its cell's generation for the graph to check.
fn fire(e: *Edge) !void {
    while (e.timers.peek()) |t| {
        if (t.at_ns > e.now_ns) break;
        _ = e.timers.pop();
        switch (t.kind) {
            .wake => try e.push(.{ .exchange = .{ .id = t.id, .completion = .{ .wake = t.gen } } }),
            .timeout => if (e.flights.get(t.id)) |f| if (f.seq == t.gen) try e.finish(t.id, .timeout),
        }
    }
}

fn ready(e: *Edge, ev: linux.epoll_event) !void {
    const d = ev.data.u64;
    if (d & client_tag != 0) return e.push(.{ .client = .{ .token = @truncate(d), .events = ev.events } });
    const id: CellId = @truncate(d);
    const f = e.flights.getPtr(id) orelse return;
    if (f.tcp) |t| return e.readyTcp(id, f.fd, t);
    var buf: [dns.max_message_len]u8 = undefined;
    const rc = linux.recvfrom(f.fd, &buf, buf.len, linux.MSG.DONTWAIT, null, null);
    switch (linux.errno(rc)) {
        .SUCCESS => try e.finish(id, .{ .reply = try e.gpa.dupe(u8, buf[0..rc]) }),
        .AGAIN, .INTR => {},
        // ICMP unreachable and kin: nobody there.
        else => try e.finish(id, .timeout),
    }
}

fn readyTcp(e: *Edge, id: CellId, fd: posix.fd_t, t: *Tcp) !void {
    if (t.written < t.query.len) {
        const rc = linux.write(fd, t.query[t.written..].ptr, t.query.len - t.written);
        switch (linux.errno(rc)) {
            .SUCCESS => t.written += rc,
            .AGAIN, .INTR => return,
            else => return e.finish(id, .timeout),
        }
        if (t.written == t.query.len) try e.ctl(linux.EPOLL.CTL_MOD, fd, linux.EPOLL.IN, id);
        return;
    }
    const rc = linux.read(fd, t.reply[t.got..].ptr, t.reply.len - t.got);
    switch (linux.errno(rc)) {
        .SUCCESS => {
            if (rc == 0) return e.finish(id, .timeout);
            t.got += rc;
        },
        .AGAIN, .INTR => return,
        else => return e.finish(id, .timeout),
    }
    if (t.got < 2) return;
    const len = mem.readInt(u16, t.reply[0..2], .big);
    if (t.got >= 2 + @as(usize, len)) try e.finish(id, .{ .reply = try e.gpa.dupe(u8, t.reply[2..][0..len]) });
}
