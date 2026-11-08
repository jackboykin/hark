//! RFC 9539's policy: whether an exchange goes plain or over an encrypted
//! session, and what becomes of the exchanges a session holds.

edge: *Edge,
plain_port: u16,
dot_port: u16,
standing: *ns_rtt.ServerTable(Standings),
conns: std.ArrayList(*Conn) = .empty,
/// Each server's sessions, by carrier.
by_server: std.HashMapUnmanaged(na.AddressKey, std.EnumArray(Kind, ?*Conn), na.AddressKey.HashCtx, 80) = .empty,
flights: std.array_hash_map.Auto(CellId, *Carried) = .empty,
next_token: u32 = 0,
stats: std.EnumArray(Kind, Stats) = .initFill(.{}),
shared: carrier.Shared = .{},
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
const carrier = @import("carrier.zig");

const Carrier = carrier.Carrier;
const Kind = carrier.Kind;
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

/// RFC 9539 §4.5: a server's standing is per transport.
const Standings = struct {
    by: std.EnumArray(Kind, Standing) = .initFill(.unknown),

    pub const unknown: Standings = .{};
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
    refused: u64 = 0,
};

const Carried = struct {
    conn: *Conn,
    id: CellId,
    seq: u32,
    wire: []const u8,
    asked_ns: i64,
    wire_id: ?carrier.QueryId = null,
    queued_ns: i64 = 0,
};

const Conn = struct {
    key: na.AddressKey,
    carrier: Carrier,
    queued: std.ArrayList(*Carried) = .empty,
    pending: std.array_hash_map.Auto(carrier.QueryId, *Carried) = .empty,
    last_reply_ns: ?i64 = null,
    /// It held a question past its wait, dialing or out of streams: until it
    /// can take questions, they go plain rather than queue on it.
    overdue: bool = false,
    last_ns: i64,
    dial_by_ns: i64,
    /// The one wake of its that stands: earlier ones are stale.
    wake_ns: i64 = std.math.maxInt(i64),
    wake_seq: u32 = 0,
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
    s.shared.doq.deinit(e.work);
    for (s.flights.values()) |at| e.work.destroy(at);
    s.flights.deinit(e.gpa);
    for (s.conns.items) |c| s.closeConn(c);
    s.conns.deinit(e.gpa);
    s.by_server.deinit(e.gpa);
    e.gpa.destroy(s.standing);
    e.gpa.destroy(s);
}

const Way = union(enum) {
    plain,
    dial: Kind,
    session: *Conn,
};

const Best = struct { way: Way, known: u32 };

/// The fewest round trips over a carrier known to work, and the fewest a
/// dial over one would take.
fn best(s: *const Sessions, key: na.AddressKey, standings: ?*const Standings) Best {
    var b: Best = .{ .way = .plain, .known = std.math.maxInt(u32) };
    // A server told at another port: nothing says what its 853 is.
    if (key.port != s.plain_port) return b;
    var fewest: u32 = std.math.maxInt(u32);
    for (std.enums.values(Kind)) |kind| {
        const standing = if (standings) |st| st.by.get(kind) else Standing.unknown;
        if (standing.status(s.edge.now_ns) != .capable) continue;
        const dial_rounds = carrier.dialRounds(kind);
        b.known = @min(b.known, dial_rounds);
        var way: Way = .{ .dial = kind };
        var rounds = dial_rounds;
        if (s.find(key, kind)) |c| if (!c.carrier.spent()) {
            if (c.overdue) continue;
            way = .{ .session = c };
            rounds = c.carrier.rounds();
        };
        if (rounds < fewest) {
            fewest = rounds;
            b.way = way;
        }
    }
    return b;
}

pub fn quote(s: *const Sessions, server: na.AddressKey, need: graph.Need) graph.Quote {
    return switch (s.best(server, s.standing.get(server)).way) {
        .plain => .{ .rounds = need.plainRounds(), .exposure = .cleartext },
        .dial => |kind| .{ .rounds = carrier.dialRounds(kind), .exposure = .encrypted },
        .session => |c| .{ .rounds = c.carrier.rounds(), .exposure = .encrypted },
    };
}

pub fn carry(s: *Sessions, ex: Exchange) !bool {
    const key: na.AddressKey = .fromAddress(ex.server);
    if (key.port != s.plain_port) return false;
    const standings = s.standing.get(key);
    const r = s.best(key, standings);
    // An unknown carrier is probed only while its dial would beat every
    // carrier known to work.
    for (std.enums.values(Kind)) |kind| {
        const standing = if (standings) |st| st.by.get(kind) else Standing.unknown;
        if (standing.status(s.edge.now_ns) != .unknown or carrier.dialRounds(kind) >= r.known) continue;
        // Nobody else's dial starts while this one is out, or for as long
        // if it could not start.
        s.setStanding(key, kind, dial_timeout_ns, false);
        _ = s.dial(kind, ex.server, key) catch {};
    }
    const c = switch (r.way) {
        .plain => return false,
        .dial => |kind| blk: {
            if (s.find(key, kind)) |old| try s.drop(old, .closed);
            break :blk s.dial(kind, ex.server, key) catch return false;
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
    s.stats.getPtr(c.carrier).carried += 1;
    if (!c.carrier.established() or c.queued.items.len > 0) {
        c.queued.appendAssumeCapacity(at);
        return true;
    }
    if (s.unflushed != c) try s.flush();
    switch (try s.send(c, at)) {
        .sent => s.unflushed = c,
        .later => c.queued.appendAssumeCapacity(at),
        .gone => try s.drop(c, .closed),
    }
    return true;
}

/// What a turn sealed for a session leaves now, so its queries share
/// segments: one segment each would spend a busy session's window.
pub fn flush(s: *Sessions) !void {
    const c = s.unflushed orelse return;
    s.unflushed = null;
    if (!try c.carrier.flush(&s.shared)) return s.drop(c, .closed);
    try s.rearm(c);
}

/// Room in `pending` is the caller's to have made. What isn't sent, the
/// caller keeps queued.
fn send(s: *Sessions, c: *Conn, at: *Carried) !carrier.Taken {
    const taken = try c.carrier.query(&s.shared, at.wire);
    if (taken != .sent) return taken;
    c.pending.putAssumeCapacity(taken.sent, at);
    at.wire_id = taken.sent;
    at.queued_ns = s.edge.now_ns - at.asked_ns;
    c.last_ns = s.edge.now_ns;
    return taken;
}

/// False: gone.
fn drain(s: *Sessions, c: *Conn) !bool {
    try c.pending.ensureUnusedCapacity(s.edge.gpa, c.queued.items.len);
    c.overdue = false;
    while (c.queued.items.len > 0) switch (try s.send(c, c.queued.items[0])) {
        .sent => _ = c.queued.orderedRemove(0),
        .later => break,
        .gone => return false,
    };
    return true;
}

fn rearm(s: *Sessions, c: *Conn) !void {
    const now = s.edge.now_ns;
    var at = if (!c.carrier.established()) c.dial_by_ns else blk: {
        const idle = c.last_ns + idle_ns;
        break :blk if (c.pending.count() > 0) @max(idle, now + std.time.ns_per_s) else idle;
    };
    if (c.carrier.due()) |d| at = @min(at, d);
    if (c.wake_ns > now and c.wake_ns <= at) return;
    c.wake_ns = at;
    c.wake_seq +%= 1;
    try s.edge.schedule(at, c.wake_seq, c.carrier.token(), .conn);
}

fn dial(s: *Sessions, kind: Kind, server: na.Address, key: na.AddressKey) !*Conn {
    const e = s.edge;
    if (s.conns.items.len >= max_conns and !try s.evictIdle()) return error.TooManySessions;
    try s.conns.ensureUnusedCapacity(e.gpa, 1);
    try s.by_server.ensureUnusedCapacity(e.gpa, 1);
    try e.timers.ensureUnusedCapacity(e.gpa, 1);
    const c = try e.gpa.create(Conn);
    errdefer e.gpa.destroy(c);
    s.next_token +%= 1;
    c.* = .{
        .key = key,
        .carrier = try .open(kind, e, &s.shared, server, s.dot_port, s.next_token),
        .last_ns = e.now_ns,
        .dial_by_ns = e.now_ns + dial_timeout_ns,
    };
    s.conns.appendAssumeCapacity(c);
    const of = s.by_server.getOrPutAssumeCapacity(key);
    if (!of.found_existing) of.value_ptr.* = .initFill(null);
    of.value_ptr.set(kind, c);
    try s.rearm(c);
    s.stats.getPtr(kind).dials += 1;
    return c;
}

fn setStanding(s: *Sessions, key: na.AddressKey, kind: Kind, for_ns: i64, capable: bool) void {
    const now = s.edge.now_ns;
    s.standing.write(key, @divTrunc(now, std.time.ns_per_ms)).by.set(kind, .{ .until_ns = now + for_ns, .capable = capable });
}

fn find(s: *const Sessions, key: na.AddressKey, kind: Kind) ?*Conn {
    return (s.by_server.get(key) orelse return null).get(kind);
}

fn byToken(s: *const Sessions, token: u32) ?*Conn {
    for (s.conns.items) |c| if (c.carrier.token() == token) return c;
    return null;
}

fn evictIdle(s: *Sessions) !bool {
    var oldest: ?*Conn = null;
    for (s.conns.items) |c| {
        if (!c.carrier.established() or c.pending.count() > 0) continue;
        if (oldest == null or c.last_ns < oldest.?.last_ns) oldest = c;
    }
    try s.drop(oldest orelse return false, .closed);
    return true;
}

/// What it held moves: the walk asks again, and by then its standing says how.
fn drop(s: *Sessions, c: *Conn, how: carrier.End) !void {
    const e = s.edge;
    try e.queue.ensureUnusedCapacity(e.gpa, c.pending.count() + c.queued.items.len);
    _ = s.conns.swapRemove(mem.findScalar(*Conn, s.conns.items, c).?);
    if (s.by_server.getPtr(c.key)) |of| if (of.get(c.carrier) == c) {
        of.set(c.carrier, null);
        for (of.values) |o| {
            if (o != null) break;
        } else _ = s.by_server.remove(c.key);
    };
    if (s.unflushed == c) {
        s.unflushed = null;
        c.carrier.unflush(&s.shared);
    }
    const kind: Kind = c.carrier;
    // A handshake that ended failed, however it ended, and so did a session
    // that took queries and answered none: only that keeps asking again from
    // going round forever on a server that hangs up.
    if (how == .failed or !c.carrier.established() or (c.pending.count() > 0 and c.last_reply_ns == null)) {
        s.setStanding(c.key, kind, damping_ns, false);
        s.stats.getPtr(kind).failed += 1;
        var ab: [64]u8 = undefined;
        log.debug("{t} server={s} damped: {s}, {d} pending, {s}", .{ kind, na.format(c.key.toAddress(), &ab), c.carrier.stage(), c.pending.count(), c.carrier.fault() });
    } else {
        s.stats.getPtr(kind).closed += 1;
        // §4.6.7: what a close leaves pending goes plain. A dial for it would
        // have a server that answers once a connection serve one query a dial.
        if (c.pending.count() > 0) s.setStanding(c.key, kind, dial_timeout_ns, false);
    }
    s.stats.getPtr(kind).moved += c.pending.count() + c.queued.items.len;
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
    c.carrier.close();
    c.queued.deinit(e.gpa);
    c.pending.deinit(e.gpa);
    e.gpa.destroy(c);
}

pub fn ready(s: *Sessions, token: u32, events: u32) !void {
    try s.flush();
    const c = s.byToken(token) orelse return;
    try s.onNews(c, try c.carrier.ready(&s.shared, events));
}

/// Replies borrow the carrier's buffers, which no read touches until they
/// have left.
fn onNews(s: *Sessions, c: *Conn, news: carrier.News) !void {
    switch (news) {
        .nothing => {},
        .ended => |how| return s.drop(c, how),
        .read => while (try c.carrier.next(&s.shared)) |ev| switch (ev) {
            .established => if (!try s.onEstablished(c)) return s.drop(c, .closed),
            .room => {
                if (!try s.drain(c)) return s.drop(c, .closed);
                if (s.unflushed != c) try s.flush();
                s.unflushed = c;
            },
            .ended => |how| return s.drop(c, how),
            .reply => |r| {
                const at = (c.pending.fetchSwapRemove(r.id) orelse continue).value;
                @memcpy(r.bytes[0..2], at.wire[0..2]);
                c.last_ns = s.edge.now_ns;
                c.last_reply_ns = s.edge.now_ns;
                s.stats.getPtr(c.carrier).answered += 1;
                s.setStanding(c.key, c.carrier, persistence_ns, true);
                try s.edge.push(s.completed(at, .{ .reply = .{ .bytes = r.bytes, .stream = true, .queued_ns = at.queued_ns } }));
            },
            // The server turned the question down, as a refusing port does.
            .refused => |id| {
                const at = (c.pending.fetchSwapRemove(id) orelse continue).value;
                s.stats.getPtr(c.carrier).refused += 1;
                try s.edge.push(s.completed(at, .timeout));
            },
        },
    }
    try s.rearm(c);
}

/// False: gone.
fn onEstablished(s: *Sessions, c: *Conn) !bool {
    c.last_ns = s.edge.now_ns;
    s.stats.getPtr(c.carrier).established += 1;
    s.setStanding(c.key, c.carrier, persistence_ns, true);
    // Left idle, a probe would meet the server's idle timer, and a first query
    // crossing that close would damp the server for a day.
    const asked = c.queued.items.len != 0;
    if (!try s.drain(c)) return false;
    return try c.carrier.flush(&s.shared) and asked;
}

pub fn flightDue(s: *Sessions, id: CellId, seq: u32) !void {
    const at = s.flights.get(id) orelse return;
    if (at.seq != seq) return;
    const c = at.conn;
    const queue = &s.edge.queue;
    const wire_id = at.wire_id orelse {
        c.overdue = true;
        _ = c.queued.orderedRemove(mem.findScalar(*Carried, c.queued.items, at).?);
        s.stats.getPtr(c.carrier).moved += 1;
        return queue.appendAssumeCapacity(s.completed(at, .moved));
    };
    const left_ns = at.asked_ns + at.queued_ns;
    _ = c.pending.swapRemove(wire_id);
    c.carrier.cancel(wire_id);
    s.stats.getPtr(c.carrier).timed_out += 1;
    queue.appendAssumeCapacity(s.completed(at, .timeout));
    // A handshake can front a backend that never answers.
    const heard = c.last_reply_ns orelse return s.drop(c, .failed);
    if (heard < left_ns) return s.drop(c, .closed);
    if (s.unflushed != c) try s.flush();
    s.unflushed = c;
}

pub fn connDue(s: *Sessions, token: u32, seq: u32) !void {
    const c = s.byToken(token) orelse return;
    if (seq != c.wake_seq) return;
    c.wake_ns = std.math.maxInt(i64);
    const now = s.edge.now_ns;
    if (!c.carrier.established() and now >= c.dial_by_ns) return s.drop(c, .failed);
    if (c.carrier.established() and now >= c.last_ns + idle_ns and c.pending.count() == 0) return s.drop(c, .closed);
    try s.onNews(c, try c.carrier.fire(&s.shared));
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
        .carrier = .{ .dot = .{
            .edge = &e,
            .token = 1,
            .fd = pair[0],
            .state = .established,
            .session = .{ .gpa = testing.allocator, .handshake = null, .phase = .application, .read = .of(&secret), .write = .of(&secret) },
        } },
        .last_ns = 0,
        .dial_by_ns = 0,
    };
    try s.conns.append(testing.allocator, c);
    const wire = [_]u8{ 0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0 };
    // More than one write's worth, so the write that fails finds some sealed.
    const queries = 2 * s.shared.dot.out.len / dot.max_sealed * 8;
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
