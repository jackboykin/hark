//! RFC 9539's policy: whether an exchange goes plain or over an encrypted
//! session, and what becomes of the exchanges a session holds.

edge: *Edge,
plain_port: u16,
dot_port: u16,
standing: *ns_rtt.ServerTable(Standing),
conns: std.ArrayList(*Conn) = .empty,
flights: std.array_hash_map.Auto(CellId, *Carried) = .empty,
next_token: u32 = 0,
stats: Stats = .{},
shared: Socket.Shared = .{},
/// Whose queries wait in `shared.out`, to leave in one write.
unflushed: ?*Conn = null,

const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const mem = std.mem;
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");
const graph = @import("graph.zig");
const ns_rtt = @import("ns_rtt.zig");
const dot = @import("dot.zig");
const tls13 = @import("tls13.zig");
const Edge = @import("edge.zig");
const Socket = @import("dot_socket.zig");

const CellId = graph.CellId;
const Exchange = graph.Exchange;
const Event = Edge.Event;

const Sessions = @This();

/// RFC 9539 §4.3's defaults.
const persistence_ns: i64 = 3 * std.time.ns_per_day;
const damping_ns: i64 = std.time.ns_per_day;
const dial_timeout_ns: i64 = 4 * std.time.ns_per_s;

const Standing = struct {
    until_ns: i64,
    capable: bool,

    pub const unknown: Standing = .{ .until_ns = 0, .capable = false };

    const Status = enum { unknown, capable, damped };

    fn status(s: Standing, now_ns: i64) Status {
        if (now_ns >= s.until_ns) return .unknown;
        return if (s.capable) .capable else .damped;
    }
};

const Stats = struct {
    dials: u64 = 0,
    established: u64 = 0,
    failed: u64 = 0,
    closed: u64 = 0,
    carried: u64 = 0,
    answered: u64 = 0,
    moved: u64 = 0,
    timed_out: u64 = 0,
};

const Carried = struct {
    conn: *Conn,
    id: CellId,
    seq: u32,
    wire: []const u8,
    asked_ns: i64,
    wire_id: ?Socket.QueryId = null,
    queued_ns: i64 = 0,
};

const Conn = struct {
    key: na.AddressKey,
    socket: Socket,
    queued: std.ArrayList(*Carried) = .empty,
    pending: std.array_hash_map.Auto(Socket.QueryId, *Carried) = .empty,
    last_reply_ns: ?i64 = null,
    /// Dialing, it held a question past its wait: until it is done, questions
    /// go plain rather than queue on it for the rest of its 4 s.
    overdue: bool = false,
    last_ns: i64,
};

const max_conns = 64;
const idle_ns: i64 = 30 * std.time.ns_per_s;

pub fn create(edge: *Edge, plain_port: u16, dot_port: u16) !*Sessions {
    const s = try edge.gpa.create(Sessions);
    errdefer edge.gpa.destroy(s);
    s.* = .{ .edge = edge, .plain_port = plain_port, .dot_port = dot_port, .standing = try .create(edge.gpa) };
    return s;
}

pub fn destroy(s: *Sessions) void {
    const e = s.edge;
    for (s.flights.values()) |at| e.work.destroy(at);
    s.flights.deinit(e.gpa);
    for (s.conns.items) |c| s.closeConn(c);
    s.conns.deinit(e.gpa);
    e.gpa.destroy(s.standing);
    e.gpa.destroy(s);
}

const Route = union(enum) {
    plain,
    probe,
    dial,
    session: *Conn,
};

fn route(s: *const Sessions, key: na.AddressKey) Route {
    // A server told at another port: nothing says what its 853 is.
    if (key.port != s.plain_port) return .plain;
    const standing = s.standing.get(key) orelse return .probe;
    return switch (standing.status(s.edge.now_ns)) {
        .damped => .plain,
        .unknown => .probe,
        .capable => {
            const c = s.find(key) orelse return .dial;
            if (c.socket.spent()) return .dial;
            return if (c.overdue) .plain else .{ .session = c };
        },
    };
}

pub fn quote(s: *const Sessions, server: na.AddressKey, need: graph.Need) graph.Quote {
    return switch (s.route(server)) {
        .plain, .probe => .{ .rounds = need.plainRounds(), .exposure = .cleartext },
        .dial => .{ .rounds = Socket.dial_rounds, .exposure = .encrypted },
        .session => |c| .{ .rounds = c.socket.rounds(), .exposure = .encrypted },
    };
}

pub fn carry(s: *Sessions, ex: Exchange) !bool {
    const key: na.AddressKey = .fromAddress(ex.server);
    const c = switch (s.route(key)) {
        .plain => return false,
        .probe => {
            // Nobody else's dial starts while this one is out, or for as long
            // if it could not start.
            s.setStanding(key, dial_timeout_ns, false);
            _ = s.dial(ex.server, key) catch return false;
            return false;
        },
        .dial => blk: {
            if (s.find(key)) |old| try s.drop(old, .closed);
            break :blk s.dial(ex.server, key) catch return false;
        },
        .session => |c| c,
    };
    const e = s.edge;
    try e.timers.ensureUnusedCapacity(e.gpa, 1);
    try s.flights.ensureUnusedCapacity(e.gpa, 1);
    try c.queued.ensureUnusedCapacity(e.gpa, 1);
    try c.pending.ensureUnusedCapacity(e.gpa, 1);
    const at = try e.work.create(Carried);
    const seq = e.seq + 1;
    try e.schedule(ex.deadline_ns, ex.id, seq, .carried);
    at.* = .{ .conn = c, .id = ex.id, .seq = seq, .wire = ex.wire, .asked_ns = e.now_ns };
    s.flights.putAssumeCapacity(ex.id, at);
    s.stats.carried += 1;
    if (!c.socket.established()) {
        c.queued.appendAssumeCapacity(at);
        return true;
    }
    if (s.unflushed != c) try s.flush();
    if (try s.send(c, at)) s.unflushed = c else try s.drop(c, .closed);
    return true;
}

/// What a turn sealed for a session leaves now, so its queries share
/// segments: one segment each would spend a busy session's window.
pub fn flush(s: *Sessions) !void {
    const c = s.unflushed orelse return;
    s.unflushed = null;
    if (!try c.socket.flush(&s.shared)) try s.drop(c, .closed);
}

/// Room in `pending` and `queued` is the caller's to have made. A query is in
/// one list at a time, so one the socket can't take stays queued. False: gone.
fn send(s: *Sessions, c: *Conn, at: *Carried) !bool {
    const id = try c.socket.query(&s.shared, at.wire) orelse {
        c.queued.appendAssumeCapacity(at);
        return false;
    };
    c.pending.putAssumeCapacity(id, at);
    at.wire_id = id;
    at.queued_ns = s.edge.now_ns - at.asked_ns;
    c.last_ns = s.edge.now_ns;
    return true;
}

fn dial(s: *Sessions, server: na.Address, key: na.AddressKey) !*Conn {
    const e = s.edge;
    if (s.conns.items.len >= max_conns and !try s.evictIdle()) return error.TooManySessions;
    try s.conns.ensureUnusedCapacity(e.gpa, 1);
    try e.timers.ensureUnusedCapacity(e.gpa, 1);
    const c = try e.gpa.create(Conn);
    errdefer e.gpa.destroy(c);
    s.next_token +%= 1;
    c.* = .{ .key = key, .socket = try .open(e, server, s.dot_port, s.next_token), .last_ns = e.now_ns };
    s.conns.appendAssumeCapacity(c);
    try e.schedule(e.now_ns + dial_timeout_ns, 0, c.socket.token, .conn);
    s.stats.dials += 1;
    return c;
}

fn setStanding(s: *Sessions, key: na.AddressKey, for_ns: i64, capable: bool) void {
    const now = s.edge.now_ns;
    s.standing.write(key, @divTrunc(now, std.time.ns_per_ms)).* = .{ .until_ns = now + for_ns, .capable = capable };
}

fn find(s: *const Sessions, key: na.AddressKey) ?*Conn {
    for (s.conns.items) |c| if (c.key.eql(key)) return c;
    return null;
}

fn byToken(s: *const Sessions, token: u32) ?*Conn {
    for (s.conns.items) |c| if (c.socket.token == token) return c;
    return null;
}

fn evictIdle(s: *Sessions) !bool {
    var oldest: ?*Conn = null;
    for (s.conns.items) |c| {
        if (!c.socket.established() or c.pending.count() > 0) continue;
        if (oldest == null or c.last_ns < oldest.?.last_ns) oldest = c;
    }
    try s.drop(oldest orelse return false, .closed);
    return true;
}

/// What it held moves: the walk asks again, and by then its standing says how.
fn drop(s: *Sessions, c: *Conn, how: Socket.End) !void {
    const e = s.edge;
    try e.queue.ensureUnusedCapacity(e.gpa, c.pending.count() + c.queued.items.len);
    _ = s.conns.swapRemove(mem.findScalar(*Conn, s.conns.items, c).?);
    if (s.unflushed == c) {
        s.unflushed = null;
        s.shared.out_len = 0;
    }
    // A handshake that ended failed, however it ended, and so did a session
    // that took queries and answered none: only that keeps asking again from
    // going round forever on a server that hangs up.
    if (how == .failed or !c.socket.established() or (c.pending.count() > 0 and c.last_reply_ns == null)) {
        s.setStanding(c.key, damping_ns, false);
        s.stats.failed += 1;
        var ab: [64]u8 = undefined;
        log.debug("dot server={s} damped: {t}, {d} pending, {s}", .{ na.format(c.key.toAddress(), &ab), c.socket.state, c.pending.count(), c.socket.fault });
    } else {
        s.stats.closed += 1;
        // §4.6.7: what a close leaves pending goes plain. A dial for it would
        // have a server that answers once a connection serve one query a dial.
        if (c.pending.count() > 0) s.setStanding(c.key, dial_timeout_ns, false);
    }
    s.stats.moved += c.pending.count() + c.queued.items.len;
    for (c.pending.values()) |at| e.queue.appendAssumeCapacity(s.completed(at, .moved));
    for (c.queued.items) |at| e.queue.appendAssumeCapacity(s.completed(at, .moved));
    s.closeConn(c);
}

fn completed(s: *Sessions, at: *Carried, completion: graph.Completion) Event {
    const id = at.id;
    _ = s.flights.swapRemove(id);
    s.edge.work.destroy(at);
    return .{ .exchange = .{ .id = id, .completion = completion } };
}

fn closeConn(s: *Sessions, c: *Conn) void {
    const e = s.edge;
    c.socket.close();
    c.queued.deinit(e.gpa);
    c.pending.deinit(e.gpa);
    e.gpa.destroy(c);
}

pub fn ready(s: *Sessions, token: u32, events: u32) !void {
    try s.flush();
    const c = s.byToken(token) orelse return;
    switch (try c.socket.ready(&s.shared, events)) {
        .nothing => {},
        .ended => |how| try s.drop(c, how),
        .read => while (try c.socket.next(&s.shared)) |ev| switch (ev) {
            .established => if (!try s.onEstablished(c)) return s.drop(c, .closed),
            .ended => |how| return s.drop(c, how),
            .reply => |r| {
                const at = (c.pending.fetchSwapRemove(r.id) orelse continue).value;
                @memcpy(r.bytes[0..2], at.wire[0..2]);
                c.last_ns = s.edge.now_ns;
                c.last_reply_ns = s.edge.now_ns;
                s.stats.answered += 1;
                s.setStanding(c.key, persistence_ns, true);
                try s.edge.push(s.completed(at, .{ .reply = .{ .bytes = r.bytes, .stream = true, .queued_ns = at.queued_ns } }));
            },
        },
    }
}

/// False: gone.
fn onEstablished(s: *Sessions, c: *Conn) !bool {
    try c.pending.ensureUnusedCapacity(s.edge.gpa, c.queued.items.len);
    c.overdue = false;
    c.last_ns = s.edge.now_ns;
    s.stats.established += 1;
    s.setStanding(c.key, persistence_ns, true);
    // Left idle, a probe would meet the server's idle timer, and a first query
    // crossing that close would damp the server for a day.
    const asked = c.queued.items.len != 0;
    while (c.queued.pop()) |at| if (!try s.send(c, at)) return false;
    return try c.socket.flush(&s.shared) and asked;
}

pub fn flightDue(s: *Sessions, id: CellId, seq: u32) !void {
    const at = s.flights.get(id) orelse return;
    if (at.seq != seq) return;
    const c = at.conn;
    const queue = &s.edge.queue;
    if (!c.socket.established()) {
        c.overdue = true;
        _ = c.queued.swapRemove(mem.findScalar(*Carried, c.queued.items, at).?);
        s.stats.moved += 1;
        return queue.appendAssumeCapacity(s.completed(at, .moved));
    }
    const left_ns = at.asked_ns + at.queued_ns;
    _ = c.pending.swapRemove(at.wire_id.?);
    s.stats.timed_out += 1;
    queue.appendAssumeCapacity(s.completed(at, .timeout));
    // A handshake can front a backend that never answers.
    const heard = c.last_reply_ns orelse return s.drop(c, .failed);
    if (heard < left_ns) return s.drop(c, .closed);
}

pub fn connDue(s: *Sessions, token: u32) !void {
    const c = s.byToken(token) orelse return;
    if (!c.socket.established()) return s.drop(c, .failed);
    const due = c.last_ns + idle_ns;
    if (s.edge.now_ns < due or c.pending.count() > 0) {
        return s.edge.schedule(@max(due, s.edge.now_ns + std.time.ns_per_s), 0, token, .conn);
    }
    return s.drop(c, .closed);
}

test "a write lost while queries leave the handshake moves each query once" {
    const testing = std.testing;
    var e = try Edge.init(testing.allocator);
    defer e.deinit();
    try e.enableSessions(53, 853);
    const s = e.sessions.?;
    var pair: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &pair)) != .SUCCESS) return error.SocketPairFailed;
    sys.close(pair[1]);

    const secret: tls13.Secret = @splat(1);
    const c = try testing.allocator.create(Conn);
    c.* = .{
        .key = .fromAddress(na.initIp4(.{ 192, 0, 2, 1 }, 53)),
        .socket = .{
            .edge = &e,
            .token = 1,
            .fd = pair[0],
            .state = .established,
            .session = .{ .gpa = testing.allocator, .handshake = null, .phase = .application, .read = .of(&secret), .write = .of(&secret) },
        },
        .last_ns = 0,
    };
    try s.conns.append(testing.allocator, c);
    const wire = [_]u8{ 0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0 };
    // More than one write's worth, so the write that fails finds some sealed.
    const queries = 2 * s.shared.out.len / dot.max_sealed * 8;
    for (0..queries) |i| {
        const at = try testing.allocator.create(Carried);
        at.* = .{ .conn = c, .id = @intCast(i), .seq = 0, .wire = &wire, .asked_ns = 0 };
        try s.flights.put(testing.allocator, at.id, at);
        try c.queued.append(testing.allocator, at);
    }
    try testing.expect(!try s.onEstablished(c));
    try s.drop(c, .closed);
    try testing.expectEqual(queries, e.queue.items.len);
    try testing.expectEqual(0, s.flights.count());
}
