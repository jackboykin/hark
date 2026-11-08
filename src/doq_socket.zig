//! A DNS over QUIC session's socket, from its first Initial to close.

edge: *Edge,
token: u32,
fd: posix.fd_t,
conn: quic.Conn,
errno: ?[]const u8 = null,

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const crypto = std.crypto;
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");
const rand = @import("rand.zig");
const tls13 = @import("tls13.zig");
const quic = @import("quic.zig");
const Edge = @import("edge.zig");
const carrier = @import("carrier.zig");

const Socket = @This();

/// The handshake, then the question: it leaves with hark's Finished.
pub const dial_rounds = 2;

/// Datagrams a read takes at most.
const batch = 16;

pub const Shared = struct {
    rx: [batch][quic.max_received]u8 = undefined,
    tx: [quic.burst][quic.max_datagram]u8 = undefined,
    /// Replies put together from several packets; the edge has taken them by the next read.
    delivered: std.ArrayList([]u8) = .empty,

    pub fn deinit(sh: *Shared, gpa: std.mem.Allocator) void {
        for (sh.delivered.items) |b| gpa.free(b);
        sh.delivered.deinit(gpa);
    }
};

/// A connected socket: the kernel says whose a datagram is, and closing it
/// ends closing and draining (RFC 9000 §10.2).
pub fn open(edge: *Edge, sh: *Shared, server: na.Address, port: u16, token: u32) !Socket {
    const fd = try sys.socket(na.afU32(server), posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    errdefer sys.close(fd);
    // RFC 9000 §14: never fragmented, and hark's datagrams fit any path.
    const probe: i32 = linux.IP.PMTUDISC_PROBE;
    if (server == .ip4) {
        _ = linux.setsockopt(fd, linux.IPPROTO.IP, linux.IP.MTU_DISCOVER, std.mem.asBytes(&probe), @sizeOf(i32));
    } else {
        _ = linux.setsockopt(fd, linux.IPPROTO.IPV6, linux.IPV6.MTU_DISCOVER, std.mem.asBytes(&probe), @sizeOf(i32));
    }
    var to = server;
    to.setPort(port);
    try na.connectTo(fd, &to);
    var entropy: [tls13.entropy_len + 8]u8 = undefined;
    rand.thread.bytes(&entropy);
    defer crypto.secureZero(u8, &entropy);
    var sock: Socket = .{ .edge = edge, .token = token, .fd = fd, .conn = try .begin(edge.work, &entropy, edge.now_ns) };
    errdefer sock.conn.deinit();
    try edge.ctl(linux.EPOLL.CTL_ADD, fd, linux.EPOLL.IN, Edge.session_tag | token);
    if (!try sock.flush(sh)) return error.Unsent;
    return sock;
}

pub fn close(sock: *Socket) void {
    var buf: [quic.max_datagram]u8 = undefined;
    if (sock.conn.closing(&buf)) |d| _ = linux.write(sock.fd, d.ptr, d.len);
    sys.close(sock.fd);
    sock.conn.deinit();
}

pub fn established(sock: *const Socket) bool {
    return sock.conn.established();
}

pub fn rounds(sock: *const Socket) u32 {
    return sock.conn.rounds();
}

pub fn spent(sock: *const Socket) bool {
    return sock.conn.spent(sock.edge.now_ns);
}

pub fn heard(sock: *const Socket) bool {
    return sock.conn.heard;
}

pub fn stage(sock: *const Socket) []const u8 {
    return @tagName(sock.conn.phase);
}

pub fn fault(sock: *const Socket) []const u8 {
    return sock.errno orelse sock.conn.fault;
}

pub fn query(sock: *Socket, _: *Shared, wire: []const u8) !carrier.Taken {
    return switch (try sock.conn.query(wire)) {
        .id => |id| .{ .sent = id },
        .later => .later,
    };
}

pub fn cancel(sock: *Socket, id: carrier.QueryId) void {
    sock.conn.cancel(id);
}

pub fn unflush(_: *const Socket, _: *Shared) void {}

pub fn due(sock: *const Socket) ?i64 {
    return sock.conn.due(sock.edge.now_ns);
}

pub fn fire(sock: *Socket, sh: *Shared) !carrier.News {
    try sock.conn.fire(sock.edge.now_ns);
    return sock.news(sh);
}

/// After its timers: what the connection owes leaves, and whatever it said
/// waits for `next`.
fn news(sock: *Socket, sh: *Shared) !carrier.News {
    if (sock.conn.ended == null and !try sock.flush(sh)) return .{ .ended = .closed };
    return sock.said();
}

fn said(sock: *const Socket) carrier.News {
    return if (sock.conn.event_at < sock.conn.events.items.len) .read else .nothing;
}

/// What has come, a batch of datagrams in one call, each in a buffer of
/// its own: a reply may point into one until the edge has taken it. What
/// the connection owes leaves with the turn's other sends.
pub fn ready(sock: *Socket, sh: *Shared, _: u32) !carrier.News {
    for (sh.delivered.items) |b| sock.edge.work.free(b);
    sh.delivered.clearRetainingCapacity();
    var msgs: [batch]linux.mmsghdr = undefined;
    var iov: [batch]posix.iovec = undefined;
    for (&msgs, &iov, &sh.rx) |*m, *v, *b| {
        v.* = .{ .base = b, .len = b.len };
        m.* = .{ .hdr = .{ .name = null, .namelen = 0, .iov = v[0..1].ptr, .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
    }
    const rc = linux.recvmmsg(sock.fd, &msgs, batch, linux.MSG.DONTWAIT, null);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR => return sock.said(),
        // ICMP unreachable and kin: nobody speaks QUIC there.
        else => |err| {
            sock.errno = std.enums.tagName(linux.E, err) orelse "unnamed errno";
            return .{ .ended = .failed };
        },
    }
    for (msgs[0..rc], sh.rx[0..rc]) |m, *b| {
        // Past what the server was told it may send: lost, as on the wire.
        if (m.hdr.flags & linux.MSG.TRUNC != 0) continue;
        try sock.conn.input(b[0..m.len], sock.edge.now_ns, &sh.delivered);
        if (sock.conn.ended != null) break;
    }
    return sock.said();
}

pub fn next(sock: *Socket, _: *Shared) !?carrier.Event {
    const ev = sock.conn.next() orelse return null;
    return switch (ev) {
        .established => .established,
        .reply => |r| .{ .reply = .{ .id = r.id, .bytes = r.bytes } },
        .refused => |id| .{ .refused = id },
        .room => .room,
        .ended => |how| .{ .ended = switch (how) {
            .failed => .failed,
            .closed => .closed,
        } },
    };
}

/// False: gone.
pub fn flush(sock: *Socket, sh: *Shared) !bool {
    var msgs: [quic.burst]linux.mmsghdr = undefined;
    var iov: [quic.burst]posix.iovec = undefined;
    var n: usize = 0;
    while (n < quic.burst) : (n += 1) {
        const d = sock.conn.output(&sh.tx[n], sock.edge.now_ns) orelse break;
        iov[n] = .{ .base = d.ptr, .len = d.len };
        msgs[n] = .{ .hdr = .{ .name = null, .namelen = 0, .iov = iov[n..].ptr, .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
    }
    if (n == 0) return true;
    const rc = linux.sendmmsg(sock.fd, &msgs, @intCast(n), 0);
    switch (linux.errno(rc)) {
        // What the kernel didn't take is lost as on the wire, and recovered so.
        .SUCCESS, .AGAIN, .INTR, .NOBUFS => return true,
        else => |err| {
            sock.errno = std.enums.tagName(linux.E, err) orelse "unnamed errno";
            return false;
        },
    }
}
