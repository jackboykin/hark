//! A DNS over TLS session's socket, from connect to close.

edge: *Edge,
token: u32,
fd: posix.fd_t,
state: enum { connecting, handshaking, established } = .connecting,
session: dot.Session = undefined,
held: []u8 = &.{},
unsent: std.ArrayList(u8) = .empty,
fault: []const u8 = "silence",

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const crypto = std.crypto;
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");
const rand = @import("rand.zig");
const dot = @import("dot.zig");
const tls13 = @import("tls13.zig");
const Edge = @import("edge.zig");

const Socket = @This();

/// How a query is told from its neighbours on a socket.
pub const QueryId = u16;

/// TCP and TLS, then the question: hark's Finished and the query leave
/// together, so a dial costs a reply three round trips.
pub const dial_rounds = 3;

pub const Shared = struct {
    rx: [dot.Rx.min_buf]u8 = undefined,
    read: dot.Rx = undefined,
    out: [16 * 1024]u8 = undefined,
    out_len: usize = 0,
};

pub const End = enum { failed, closed };

pub const Event = union(enum) {
    /// Queries may go; those before the next flush leave with its Finished.
    established,
    reply: struct { id: QueryId, bytes: []u8 },
    ended: End,
};

pub fn open(edge: *Edge, server: na.Address, port: u16, token: u32) !Socket {
    const fd = try sys.socket(na.afU32(server), posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    errdefer sys.close(fd);
    const on: i32 = 1;
    _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, mem.asBytes(&on), @sizeOf(i32));
    var to = server;
    to.setPort(port);
    na.connectTo(fd, &to) catch |err| switch (err) {
        error.WouldBlock => {},
        else => return err,
    };
    try edge.ctl(linux.EPOLL.CTL_ADD, fd, linux.EPOLL.OUT, Edge.session_tag | token);
    return .{ .edge = edge, .token = token, .fd = fd };
}

pub fn close(sock: *Socket) void {
    const e = sock.edge;
    sys.close(sock.fd);
    if (sock.state != .connecting) sock.session.deinit();
    sock.unsent.deinit(e.gpa);
    if (sock.held.len != 0) e.work.free(sock.held);
}

pub fn established(sock: *const Socket) bool {
    return sock.state == .established;
}

/// AES-128-GCM's safe limit for one key (RFC 8446 §5.5 points at 2^24.5):
/// rather than turn the key, a session this old is left for a new one.
pub fn spent(sock: *const Socket) bool {
    return sock.established() and sock.session.write.seq >= 1 << 24;
}

pub const News = union(enum) {
    nothing,
    /// `next` has events to take.
    read,
    ended: End,
};

pub fn ready(sock: *Socket, sh: *Shared, events: u32) !News {
    if (sock.state == .connecting) return sock.connected();
    if (sock.unsent.items.len != 0 and events & linux.EPOLL.OUT != 0) {
        if (!try sock.flushUnsent()) return .{ .ended = .closed };
    }
    if (events & (linux.EPOLL.IN | linux.EPOLL.HUP | linux.EPOLL.ERR | linux.EPOLL.RDHUP) == 0) return .nothing;
    const held = sock.held.len;
    const rc = linux.read(sock.fd, sh.rx[held..].ptr, sh.rx.len - held);
    switch (linux.errno(rc)) {
        .SUCCESS => if (rc == 0) {
            sock.fault = "eof";
            return .{ .ended = .closed };
        },
        .AGAIN, .INTR => return .nothing,
        else => |err| {
            sock.sawErrno(err);
            return .{ .ended = .closed };
        },
    }
    @memcpy(sh.rx[0..held], sock.held);
    sh.read = sock.session.reader(&sh.rx, held);
    sh.read.end += rc;
    if (held != 0) sock.edge.work.free(sock.held);
    sock.held = &.{};
    return .read;
}

fn sawErrno(sock: *Socket, err: linux.E) void {
    sock.fault = std.enums.tagName(linux.E, err) orelse "unnamed errno";
}

fn connected(sock: *Socket) !News {
    var err: i32 = 0;
    var len: posix.socklen_t = @sizeOf(i32);
    if (linux.errno(linux.getsockopt(sock.fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&err), &len)) != .SUCCESS or err != 0) {
        sock.sawErrno(@fromBackingInt(@intCast(err)));
        return .{ .ended = .failed };
    }
    // Keys only now: nearly every first dial meets a closed port, and the
    // shares cost ~200 µs.
    var entropy: [tls13.entropy_len]u8 = undefined;
    rand.thread.bytes(&entropy);
    defer crypto.secureZero(u8, &entropy);
    var hello: [tls13.header_len + tls13.max_hello]u8 = undefined;
    sock.session, const bytes = dot.Session.begin(sock.edge.work, &hello, &entropy) catch return .{ .ended = .failed };
    sock.state = .handshaking;
    try sock.edge.ctl(linux.EPOLL.CTL_MOD, sock.fd, linux.EPOLL.IN, Edge.session_tag | sock.token);
    if (!try sock.put(bytes)) return .{ .ended = .failed };
    return .nothing;
}

/// What the read in `sh` holds, an event at a time; null once it is spent.
pub fn next(sock: *Socket, sh: *Shared) !?Event {
    std.debug.assert(sh.out_len == 0);
    while (true) {
        const ev = sock.session.next(&sh.read, &sh.out) catch |err| {
            sock.fault = @errorName(err);
            if (err != error.AlertHeard) _ = sock.put(sock.session.alert(&sh.out, tls13.alert(@errorCast(err)))) catch {};
            return .{ .ended = .failed };
        } orelse {
            const left = sock.session.leftover(&sh.read);
            if (left.plain.len + left.sealed.len != 0) {
                sock.held = try sock.edge.work.alloc(u8, left.plain.len + left.sealed.len);
                @memcpy(sock.held[0..left.plain.len], left.plain);
                @memcpy(sock.held[left.plain.len..], left.sealed);
            }
            return null;
        };
        switch (ev) {
            .established => |flight| {
                std.debug.assert(flight.ptr == &sh.out);
                sock.state = .established;
                sh.out_len = flight.len;
                return .established;
            },
            .send => |bytes| if (!try sock.put(bytes)) return .{ .ended = .closed },
            .closed => {
                sock.fault = "close_notify";
                return .{ .ended = .closed };
            },
            .reply => |m| return .{ .reply = .{ .id = mem.readInt(u16, m[0..2], .big), .bytes = m } },
        }
    }
}

/// `wire` readied to leave at the next flush, or sooner if there's no room.
/// Null: gone.
pub fn query(sock: *Socket, sh: *Shared, wire: []const u8) !?QueryId {
    if (sh.out_len + dot.max_sealed > sh.out.len and !try sock.flush(sh)) return null;
    const q = sock.session.query(sh.out[sh.out_len..], wire);
    sh.out_len += q.sealed.len;
    return q.id;
}

/// False: gone.
pub fn flush(sock: *Socket, sh: *Shared) !bool {
    defer sh.out_len = 0;
    return sock.put(sh.out[0..sh.out_len]);
}

pub fn closeNotify(sock: *Socket, sh: *Shared) void {
    std.debug.assert(sh.out_len == 0);
    _ = sock.put(sock.session.alert(&sh.out, .close_notify)) catch {};
}

/// Written whole, or kept to write when the socket takes it. False: gone.
fn put(sock: *Socket, bytes: []const u8) !bool {
    var rest = bytes;
    if (sock.unsent.items.len == 0) {
        const rc = linux.write(sock.fd, rest.ptr, rest.len);
        switch (linux.errno(rc)) {
            .SUCCESS => rest = rest[rc..],
            .AGAIN, .INTR => {},
            else => |err| {
                sock.sawErrno(err);
                return false;
            },
        }
        if (rest.len == 0) return true;
        try sock.edge.ctl(linux.EPOLL.CTL_MOD, sock.fd, linux.EPOLL.IN | linux.EPOLL.OUT, Edge.session_tag | sock.token);
    }
    try sock.unsent.appendSlice(sock.edge.gpa, rest);
    return true;
}

fn flushUnsent(sock: *Socket) !bool {
    const rc = linux.write(sock.fd, sock.unsent.items.ptr, sock.unsent.items.len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR => return true,
        else => |err| {
            sock.sawErrno(err);
            return false;
        },
    }
    sock.unsent.replaceRangeAssumeCapacity(0, rc, &.{});
    if (sock.unsent.items.len == 0) try sock.edge.ctl(linux.EPOLL.CTL_MOD, sock.fd, linux.EPOLL.IN, Edge.session_tag | sock.token);
    return true;
}
