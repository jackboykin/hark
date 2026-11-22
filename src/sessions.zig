//! RFC 9539's policy: whether an exchange goes plain or over an encrypted
//! session, and what becomes of the exchanges a session holds.

edge: *Edge,
plain_port: u16,
dot_port: u16,
standing: *ns_rtt.ServerTable(Standings),
conns: std.ArrayList(*Conn) = .empty,
by_server: std.HashMapUnmanaged(na.AddressKey, std.EnumArray(Kind, ?*Conn), na.AddressKey.HashCtx, 80) = .empty,
flights: std.array_hash_map.Auto(CellId, *Carried) = .empty,
next_token: u32 = 0,
stats: std.EnumArray(Kind, Stats) = .initFill(.{}),
shared: carrier.Shared = .{},
unflushed: ?*Conn = null,

const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const mem = std.mem;
const na = @import("net_address.zig");
const sys = @import("sys.zig");
const graph = @import("graph.zig");
const model = @import("model.zig");
const ns_rtt = @import("ns_rtt.zig");
const dot = @import("dot.zig");
const tls13 = @import("tls13.zig");
const Edge = @import("edge.zig");
const carrier = @import("carrier.zig");

const Carrier = carrier.Carrier;
const Kind = carrier.Kind;
const CellId = model.CellId;
const Exchange = graph.Exchange;
const Event = Edge.Event;

const Sessions = @This();

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
    overdue: bool = false,
    last_ns: i64,
    dial_by_ns: i64,
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

fn best(s: *const Sessions, key: na.AddressKey, standings: ?*const Standings) Best {
    var b: Best = .{ .way = .plain, .known = std.math.maxInt(u32) };
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
    const b = s.best(key, standings);
    // Last, once the exchange is queued: a probe's dial evicts only idle sessions.
    defer s.probe(ex.server, key, standings, b.known);
    const c = switch (b.way) {
        .plain => return false,
        .dial => |kind| blk: {
            if (s.find(key, kind)) |old| s.retire(old);
            break :blk s.dial(kind, ex.server, key) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                else => return false,
            };
        },
        .session => |c| c,
    };
    const e = s.edge;
    try e.timers.ensureUnusedCapacity(e.gpa, 1);
    try s.flights.ensureUnusedCapacity(e.gpa, 1);
    try c.queued.ensureUnusedCapacity(e.gpa, 1);
    // Room for every queued exchange, so drain allocates nothing.
    try c.pending.ensureUnusedCapacity(e.gpa, c.queued.items.len + 1);
    const at = try e.work.create(Carried);
    errdefer e.work.destroy(at);
    const seq = try e.schedule(ex.deadline_ns, .{ .carried = ex.id });
    at.* = .{ .conn = c, .id = ex.id, .seq = seq, .wire = ex.wire, .asked_ns = e.now_ns };
    s.flights.putAssumeCapacity(ex.id, at);
    s.stats.getPtr(c.carrier).carried += 1;
    c.queued.appendAssumeCapacity(at);
    if (!c.carrier.established() or c.queued.items.len > 1) return true;
    s.start(c) catch s.drop(c, .closed);
    return true;
}

fn probe(s: *Sessions, server: na.Address, key: na.AddressKey, standings: ?*const Standings, known: u32) void {
    for (std.enums.values(Kind)) |kind| {
        const standing = if (standings) |st| st.by.get(kind) else Standing.unknown;
        if (standing.status(s.edge.now_ns) != .unknown or carrier.dialRounds(kind) >= known) continue;
        // Damped while the dial is out, so no second probe starts beside it.
        s.setStanding(key, kind, dial_timeout_ns, false);
        _ = s.dial(kind, server, key) catch {};
    }
}

fn start(s: *Sessions, c: *Conn) !void {
    if (s.unflushed != c) s.flush();
    if (try s.drain(c)) s.unflushed = c else s.drop(c, .closed);
}

pub fn flush(s: *Sessions) void {
    const c = s.unflushed orelse return;
    s.unflushed = null;
    s.flushOne(c) catch s.drop(c, .closed);
}

fn flushOne(s: *Sessions, c: *Conn) !void {
    if (!try c.carrier.flush(&s.shared)) return s.drop(c, .closed);
    try s.rearm(c);
}

fn send(s: *Sessions, c: *Conn, at: *Carried) !carrier.Taken {
    const taken = try c.carrier.query(&s.shared, at.wire, &c.pending);
    if (taken != .sent) return taken;
    c.pending.putAssumeCapacity(taken.sent, at);
    at.wire_id = taken.sent;
    at.queued_ns = s.edge.now_ns - at.asked_ns;
    c.last_ns = s.edge.now_ns;
    return taken;
}

fn drain(s: *Sessions, c: *Conn) !bool {
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
    c.wake_seq = try s.edge.schedule(at, .{ .conn = c.carrier.token() });
}

fn dial(s: *Sessions, kind: Kind, server: na.Address, key: na.AddressKey) !*Conn {
    const e = s.edge;
    if (s.conns.items.len >= max_conns and !try s.evictIdle()) return error.TooManySessions;
    try s.conns.ensureUnusedCapacity(e.gpa, 1);
    try s.by_server.ensureUnusedCapacity(e.gpa, 1);
    const c = try e.gpa.create(Conn);
    errdefer e.gpa.destroy(c);
    s.next_token +%= 1;
    c.* = .{
        .key = key,
        .carrier = try .open(kind, e, &s.shared, server, s.dot_port, s.next_token),
        .last_ns = e.now_ns,
        .dial_by_ns = e.now_ns + dial_timeout_ns,
    };
    errdefer c.carrier.close();
    try s.rearm(c);
    s.conns.appendAssumeCapacity(c);
    const of = s.by_server.getOrPutAssumeCapacity(key);
    if (!of.found_existing) of.value_ptr.* = .initFill(null);
    of.value_ptr.set(kind, c);
    s.stats.getPtr(kind).dials += 1;
    return c;
}

fn setStanding(s: *Sessions, key: na.AddressKey, kind: Kind, for_ns: i64, capable: bool) void {
    const now = s.edge.now_ns;
    const of = &s.standing.write(key, @divTrunc(now, std.time.ns_per_ms)).by;
    if (capable and of.get(kind).status(now) != .capable) {
        log.info("{t} server={f} capable", .{ kind, s.dialed(key) });
    }
    of.set(kind, .{ .until_ns = now + for_ns, .capable = capable });
}

fn dialed(s: *const Sessions, key: na.AddressKey) na.Address {
    var to = key.toAddress();
    to.setPort(s.dot_port);
    return to;
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
        if (!c.carrier.established() or c.pending.count() > 0 or c.queued.items.len > 0) continue;
        if (oldest == null or c.last_ns < oldest.?.last_ns) oldest = c;
    }
    s.drop(oldest orelse return false, .closed);
    return true;
}

/// Every carried query's timer reserved room for the event it ends with,
/// so moving them all allocates nothing.
fn retire(s: *Sessions, c: *Conn) void {
    if (c.pending.count() == 0) return s.drop(c, .closed);
    const e = s.edge;
    s.unlist(c);
    s.stats.getPtr(c.carrier).moved += c.queued.items.len;
    for (c.queued.items) |at| e.queue.appendAssumeCapacity(s.completed(at, .moved));
    c.queued.clearRetainingCapacity();
}

fn retired(s: *const Sessions, c: *const Conn) bool {
    return c.pending.count() == 0 and s.find(c.key, c.carrier) != c;
}

fn unlist(s: *Sessions, c: *const Conn) void {
    const of = s.by_server.getPtr(c.key) orelse return;
    if (of.get(c.carrier) != c) return;
    of.set(c.carrier, null);
    for (of.values) |o| {
        if (o != null) return;
    }
    _ = s.by_server.remove(c.key);
}

fn drop(s: *Sessions, c: *Conn, how: carrier.End) void {
    const e = s.edge;
    _ = s.conns.swapRemove(mem.findScalar(*Conn, s.conns.items, c).?);
    s.unlist(c);
    if (s.unflushed == c) {
        s.unflushed = null;
        c.carrier.unflush(&s.shared);
    }
    const kind: Kind = c.carrier;
    // A handshake that ended has failed, however it ended, and so has a
    // session that took queries and answered none: otherwise a server that
    // hangs up would be asked again forever.
    if (how == .failed or !c.carrier.established() or (c.pending.count() > 0 and c.last_reply_ns == null)) {
        s.setStanding(c.key, kind, damping_ns, false);
        s.stats.getPtr(kind).failed += 1;
        if (c.carrier.heard()) {
            log.info("{t} server={f} damped: {s}, {d} pending, {s}", .{ kind, s.dialed(c.key), c.carrier.stage(), c.pending.count(), c.carrier.fault() });
        }
    } else {
        s.stats.getPtr(kind).closed += 1;
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

pub fn ready(s: *Sessions, token: u32, events: u32) void {
    s.flush();
    const c = s.byToken(token) orelse return;
    s.onReady(c, events) catch s.drop(c, .closed);
}

fn onReady(s: *Sessions, c: *Conn, events: u32) !void {
    try s.onNews(c, try c.carrier.ready(&s.shared, events));
}

fn onNews(s: *Sessions, c: *Conn, news: carrier.News) !void {
    switch (news) {
        .nothing => {},
        .ended => |how| return s.drop(c, how),
        .read => while (try c.carrier.next(&s.shared)) |ev| switch (ev) {
            .established => if (!try s.onEstablished(c)) return s.drop(c, .closed),
            .room => if (!try s.drain(c)) return s.drop(c, .closed),
            .ended => |how| return s.drop(c, how),
            .reply => |r| {
                const at = (c.pending.fetchSwapRemove(r.id) orelse continue).value;
                @memcpy(r.bytes[0..2], at.wire[0..2]);
                c.last_ns = s.edge.now_ns;
                c.last_reply_ns = s.edge.now_ns;
                s.stats.getPtr(c.carrier).answered += 1;
                s.setStanding(c.key, c.carrier, persistence_ns, true);
                s.edge.push(s.completed(at, .{ .reply = .{ .bytes = r.bytes, .stream = true, .queued_ns = at.queued_ns } }));
            },
            .refused => |id| {
                const at = (c.pending.fetchSwapRemove(id) orelse continue).value;
                s.stats.getPtr(c.carrier).refused += 1;
                s.edge.push(s.completed(at, .timeout));
            },
        },
    }
    if (s.retired(c)) return s.drop(c, .closed);
    if (s.unflushed != c) s.flush();
    s.unflushed = c;
    try s.rearm(c);
}

fn onEstablished(s: *Sessions, c: *Conn) !bool {
    c.last_ns = s.edge.now_ns;
    s.stats.getPtr(c.carrier).established += 1;
    s.setStanding(c.key, c.carrier, persistence_ns, true);
    // False with nothing to ask, which closes the probe: left idle, a first
    // query crossing the server's idle close would damp it for a day.
    const asked = c.queued.items.len != 0;
    if (!try s.drain(c)) return false;
    return try c.carrier.flush(&s.shared) and asked;
}

pub fn flightDue(s: *Sessions, id: CellId, seq: u32) void {
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
    const heard = c.last_reply_ns orelse return s.drop(c, .failed);
    if (heard < left_ns or s.retired(c)) return s.drop(c, .closed);
    if (s.unflushed != c) s.flush();
    s.unflushed = c;
}

pub fn connDue(s: *Sessions, token: u32, seq: u32) void {
    const c = s.byToken(token) orelse return;
    if (seq != c.wake_seq) return;
    c.wake_ns = std.math.maxInt(i64);
    const now = s.edge.now_ns;
    if (!c.carrier.established() and now >= c.dial_by_ns) return s.drop(c, .failed);
    if (c.carrier.established() and now >= c.last_ns + idle_ns and c.pending.count() == 0) return s.drop(c, .closed);
    s.onFire(c) catch s.drop(c, .closed);
}

fn onFire(s: *Sessions, c: *Conn) !void {
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
    const queries = 2 * s.shared.dot.out.len / dot.max_sealed * 8;
    try c.pending.ensureUnusedCapacity(testing.allocator, queries);
    for (0..queries) |i| {
        const at = try testing.allocator.create(Carried);
        at.* = .{ .conn = c, .id = @intCast(i), .seq = 0, .wire = &wire, .asked_ns = 0 };
        try s.flights.put(testing.allocator, at.id, at);
        try c.queued.append(testing.allocator, at);
    }
    try e.queue.ensureUnusedCapacity(e.gpa, queries);
    try testing.expect(!try s.onEstablished(c));
    s.drop(c, .closed);
    try testing.expectEqual(queries, e.queue.items.len);
    try testing.expectEqual(0, s.flights.count());
}

test "a handshake establishing under a full allocator leaves the DoT out buffer clear" {
    const testing = std.testing;
    const tls = std.crypto.tls;
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var failing: testing.FailingAllocator = .init(testing.allocator, .{});
    var e = try Edge.init(failing.allocator());
    defer e.deinit();
    try e.enableSessions(53, 853);
    const s = e.sessions.?;

    var pair: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &pair)) != .SUCCESS) return error.SocketPairFailed;
    defer sys.close(pair[1]);

    const secret: tls13.Secret = @splat(1);
    const server = na.initIp4(.{ 192, 0, 2, 1 }, 53);
    const h = try e.work.create(tls13.Handshake);
    h.* = .{
        .shares = .{ .x25519 = @splat(0), .p256 = @splat(0), .ml_kem = @splat(0) },
        .offer = .{ .alpn = "dot" },
        .stage = .finished,
        .handshake_secret = secret,
        .traffic = .{ .client = secret, .server = secret },
    };
    const c = try e.gpa.create(Conn);
    c.* = .{
        .key = .fromAddress(server),
        .carrier = .{ .dot = .{
            .edge = &e,
            .token = 1,
            .fd = pair[0],
            .state = .handshaking,
            .session = .{ .gpa = e.work, .handshake = h, .phase = .handshake, .read = .of(&secret), .write = .of(&secret) },
        } },
        .last_ns = e.now_ns,
        .dial_by_ns = e.now_ns + dial_timeout_ns,
        .wake_ns = e.now_ns + dial_timeout_ns,
    };
    try s.conns.append(e.gpa, c);
    try s.by_server.put(e.gpa, c.key, .init(.{ .dot = c, .doq = null }));
    s.setStanding(c.key, .dot, persistence_ns, true);
    s.setStanding(c.key, .doq, damping_ns, false);

    const wire = [_]u8{ 0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0 };
    const queries = std.atomic.cache_line / @sizeOf(carrier.QueryId) + 1;
    for (1..queries + 1) |id| {
        try testing.expect(try s.carry(.{ .id = @intCast(id), .server = server, .need = .datagram, .wire = &wire, .deadline_ns = e.now_ns + std.time.ns_per_s }));
    }

    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;

    const empty = tls.emptyHash(std.crypto.hash.sha2.Sha256);
    const fin_key = tls.hkdfExpandLabel(Hkdf, secret, "finished", "", Hmac.key_length);
    const finished = [_]u8{@backingInt(tls.HandshakeType.finished)} ++ tls.int(u24, Hmac.mac_length) ++ tls.hmac(Hmac, &empty, fin_key);
    var srv: tls13.Keys = .of(&secret);
    var rec: [tls13.overhead + finished.len]u8 = undefined;
    _ = try sys.write(pair[1], srv.seal(&rec, .handshake, &finished));
    s.ready(1, linux.EPOLL.IN);

    try testing.expectEqual(0, s.shared.dot.out_len);
    try testing.expectEqual(queries, c.pending.count());
}

test "a spent session keeps its pending to the end while a successor takes the rest" {
    const testing = std.testing;
    var e = try Edge.init(testing.allocator);
    defer e.deinit();
    try e.enableSessions(53, 853);
    const s = e.sessions.?;
    var pair: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &pair)) != .SUCCESS) return error.SocketPairFailed;
    defer sys.close(pair[1]);
    const secret: tls13.Secret = @splat(1);
    const server = na.initIp4(.{ 192, 0, 2, 1 }, 53);
    const c = try testing.allocator.create(Conn);
    c.* = .{
        .key = .fromAddress(server),
        .carrier = .{ .dot = .{
            .edge = &e,
            .token = 0,
            .fd = pair[0],
            .state = .established,
            .session = .{ .gpa = testing.allocator, .handshake = null, .phase = .application, .read = .of(&secret), .write = .of(&secret) },
        } },
        .last_ns = 0,
        .dial_by_ns = 0,
    };
    try s.conns.append(testing.allocator, c);
    try s.by_server.put(testing.allocator, c.key, .init(.{ .dot = c, .doq = null }));
    s.setStanding(c.key, .dot, persistence_ns, true);
    s.setStanding(c.key, .doq, damping_ns, false);
    const wire = [_]u8{ 0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0 };
    const deadline = e.now_ns + std.time.ns_per_s;
    try testing.expect(try s.carry(.{ .id = 1, .server = server, .need = .datagram, .wire = &wire, .deadline_ns = deadline }));
    s.flush();
    c.carrier.dot.session.write.seq = 1 << 24;
    try testing.expect(try s.carry(.{ .id = 2, .server = server, .need = .datagram, .wire = &wire, .deadline_ns = deadline }));
    try testing.expect(mem.findScalar(*Conn, s.conns.items, c) != null);
    try testing.expect(s.find(c.key, .dot) != c);
    try testing.expectEqual(1, c.pending.count());
    try testing.expectEqual(0, e.queue.items.len);

    var frame = [_]u8{ 0, 12 } ++ @as([12]u8, @splat(0));
    var keys: tls13.Keys = .of(&secret);
    var record: [64]u8 = undefined;
    _ = try sys.write(pair[1], keys.seal(&record, .application_data, &frame));
    s.ready(0, linux.EPOLL.IN);
    try testing.expect(mem.findScalar(*Conn, s.conns.items, c) == null);
    try testing.expectEqual(1, e.queue.items.len);
    try testing.expect(e.queue.items[0].exchange.completion == .reply);
}
