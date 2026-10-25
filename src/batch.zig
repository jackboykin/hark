//! UDP by the batch: the datagrams already queued, received or sent in one
//! syscall. Nothing waits to fill a batch.
hdrs: [max]linux.mmsghdr,
iovs: [max]posix.iovec,
addrs: [max]na.PosixAddress,
infos: [max]PktInfo,
bytes: []u8,
size: usize,
n: usize = 0,
fd: posix.fd_t = -1,

const Batch = @This();
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");

/// A syscall a datagram pays the kernel's entry and exit each time; eight
/// to a call takes most of the saving.
pub const max = 8;

/// The address a datagram was sent to, in its sender's family: an IPv4 one
/// fills the first four bytes.
pub const Local = [16]u8;

const PktInfo = extern struct {
    hdr: linux.cmsghdr,
    info: extern union { v4: linux.in_pktinfo, v6: linux.in6_pktinfo },

    /// Interface 0: routing picks the way out. Unpadded: past 36 bytes the
    /// kernel allocates to copy it in.
    fn set(p: *PktInfo, to: na.Address, source: Local) usize {
        p.* = switch (to) {
            .ip4 => .{
                .hdr = .{ .len = @offsetOf(PktInfo, "info") + @sizeOf(linux.in_pktinfo), .level = linux.IPPROTO.IP, .type = linux.IP.PKTINFO },
                .info = .{ .v4 = .{ .ifindex = 0, .spec_dst = @bitCast(source[0..4].*), .addr = 0 } },
            },
            .ip6 => .{
                .hdr = .{ .len = @offsetOf(PktInfo, "info") + @sizeOf(linux.in6_pktinfo), .level = linux.IPPROTO.IPV6, .type = linux.IPV6.PKTINFO },
                .info = .{ .v6 = .{ .addr = source, .ifindex = 0 } },
            },
        };
        return p.hdr.len;
    }
};

comptime {
    assert(@offsetOf(PktInfo, "info") == mem.alignForward(usize, @sizeOf(linux.cmsghdr), linux.cmsg_align));
}

/// For a wildcard socket, whose reply would otherwise leave from whichever
/// address routing picks, and a client that asked another drops it
/// (RFC 1123 §2.3).
pub fn tellLocal(fd: posix.fd_t, af: u32) !void {
    const one: c_int = 1;
    if (af == posix.AF.INET)
        try posix.setsockopt(fd, posix.SOL.IP, linux.IP.PKTINFO, &mem.toBytes(one))
    else
        try posix.setsockopt(fd, posix.SOL.IPV6, linux.IPV6.RECVPKTINFO, &mem.toBytes(one));
}

/// Its headers point into it, so a batch lives on the heap and never moves.
pub fn create(gpa: Allocator, size: usize) !*Batch {
    const b = try gpa.create(Batch);
    errdefer gpa.destroy(b);
    const bytes = try gpa.alloc(u8, max * size);
    b.* = .{ .hdrs = undefined, .iovs = undefined, .addrs = undefined, .infos = undefined, .bytes = bytes, .size = size };
    for (&b.hdrs, &b.iovs, &b.addrs, &b.infos, 0..) |*h, *iov, *addr, *info, i| {
        iov.* = .{ .base = bytes[i * size ..].ptr, .len = size };
        h.* = .{ .hdr = .{ .name = &addr.any, .namelen = 0, .iov = @ptrCast(iov), .iovlen = 1, .control = info, .controllen = 0, .flags = 0 }, .len = 0 };
    }
    return b;
}

pub fn destroy(b: *Batch, gpa: Allocator) void {
    gpa.free(b.bytes);
    gpa.destroy(b);
}

pub fn recv(b: *Batch, fd: posix.fd_t, want: usize) usize {
    // The kernel writes the lengths it used over the room it was given.
    for (b.hdrs[0..want]) |*h| {
        h.hdr.namelen = @sizeOf(na.PosixAddress);
        h.hdr.controllen = @sizeOf(PktInfo);
    }
    const rc = linux.recvmmsg(fd, &b.hdrs, @intCast(want), linux.MSG.DONTWAIT, null);
    return if (linux.errno(rc) == .SUCCESS) rc else 0;
}

pub fn datagram(b: *Batch, i: usize) []u8 {
    return b.bytes[i * b.size ..][0..b.hdrs[i].len];
}

pub fn from(b: *const Batch, i: usize) na.Address {
    return na.fromSockaddr(&b.addrs[i]);
}

pub fn local(b: *const Batch, i: usize) Local {
    assert(b.hdrs[i].hdr.controllen != 0);
    const p = &b.infos[i];
    var l: Local = @splat(0);
    switch (p.hdr.level) {
        linux.IPPROTO.IP => l[0..4].* = @bitCast(p.info.v4.spec_dst),
        linux.IPPROTO.IPV6 => l = p.info.v6.addr,
        else => unreachable,
    }
    return l;
}

pub fn next(b: *Batch, fd: posix.fd_t) []u8 {
    if (b.fd != fd) b.flush();
    b.fd = fd;
    return b.bytes[b.n * b.size ..][0..b.size];
}

pub fn push(b: *Batch, len: usize, to: *const na.Address) void {
    b.put(len, to, 0);
}

pub fn pushFrom(b: *Batch, len: usize, to: *const na.Address, source: Local) void {
    b.put(len, to, b.infos[b.n].set(to.*, source));
}

fn put(b: *Batch, len: usize, to: *const na.Address, controllen: usize) void {
    b.iovs[b.n].len = len;
    b.hdrs[b.n].hdr.namelen = na.toSockaddr(to, &b.addrs[b.n]);
    b.hdrs[b.n].hdr.controllen = controllen;
    b.n += 1;
    if (b.n == max) b.flush();
}

pub fn flush(b: *Batch) void {
    var at: usize = 0;
    while (at < b.n) {
        const rc = linux.sendmmsg(b.fd, b.hdrs[at..].ptr, @intCast(b.n - at), linux.MSG.DONTWAIT);
        at += switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .INTR => 0,
            // Refused: dropped as if lost on the way, and the rest still go.
            else => 1,
        };
    }
    b.n = 0;
}

test "datagrams come in and go out by the batch, each to its sender" {
    const any4 = na.initIp4(@splat(0), 0);
    const lo4 = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    const any6 = na.initIp6(@splat(0), 0, 0, 0);
    const lo6 = na.initIp6(@as([15]u8, @splat(0)) ++ [_]u8{1}, 0, 0, 0);
    for ([_][2]na.Address{ .{ lo4, lo4 }, .{ any4, lo4 }, .{ lo6, lo6 }, .{ any6, lo6 } }) |pair| try roundTrip(pair[0], pair[1]);
}

fn roundTrip(bound: na.Address, lo: na.Address) !void {
    const gpa = std.testing.allocator;
    const in = try Batch.create(gpa, 64);
    defer in.destroy(gpa);
    const out = try Batch.create(gpa, 64);
    defer out.destroy(gpa);

    const af = na.afU32(bound);
    const server = try sys.socket(af, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer sys.close(server);
    const wildcard = na.isUnspecified(bound);
    if (wildcard) try tellLocal(server, af);
    try na.bindTo(server, &bound);
    var sa: na.PosixAddress = undefined;
    var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    try sys.getsockname(server, &sa.any, &sa_len);
    var at = lo;
    at.setPort(na.fromSockaddr(&sa).getPort());
    sa_len = na.toSockaddr(&at, &sa);

    const count = max + 3;
    var clients: [count]posix.fd_t = undefined;
    for (&clients, 0..) |*c, i| {
        c.* = try sys.socket(af, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
        try sys.connect(c.*, &sa.any, sa_len);
        var ask: [count]u8 = @splat(@intCast(i));
        _ = try sys.sendto(c.*, ask[0 .. 1 + i], 0, null, 0);
    }
    defer for (clients) |c| sys.close(c);

    var seen: usize = 0;
    for ([_]usize{ max, 3, 0 }) |expect| {
        const got = in.recv(server, max);
        try std.testing.expectEqual(expect, got);
        for (0..got) |i| {
            const ask = in.datagram(i);
            try std.testing.expectEqual(1 + seen, ask.len);
            for (ask) |byte| try std.testing.expectEqual(seen, byte);
            const room = out.next(server);
            @memset(room[0..2], ask[0]);
            if (wildcard) out.pushFrom(2, &in.from(i), in.local(i)) else out.push(2, &in.from(i));
            seen += 1;
        }
        out.flush();
    }
    for (clients, 0..) |c, i| {
        var reply: [8]u8 = undefined;
        const rc = linux.recvfrom(c, &reply, reply.len, linux.MSG.DONTWAIT, null, null);
        try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
        try std.testing.expectEqualSlices(u8, &.{ @intCast(i), @intCast(i) }, reply[0..rc]);
    }
}

test "a datagram the kernel refuses is dropped and the rest are sent" {
    const gpa = std.testing.allocator;
    const out = try Batch.create(gpa, 8);
    defer out.destroy(gpa);
    const server = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer sys.close(server);
    try na.bindTo(server, &na.initIp4(.{ 127, 0, 0, 1 }, 0));
    const client = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer sys.close(client);
    try na.bindTo(client, &na.initIp4(.{ 127, 0, 0, 1 }, 0));
    var sa: na.PosixAddress = undefined;
    var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    try sys.getsockname(client, &sa.any, &sa_len);
    const to = na.fromSockaddr(&sa);

    for ([_]na.Address{ to, na.initIp4(.{ 127, 0, 0, 1 }, 0), to }, "abc") |addr, byte| {
        out.next(server)[0] = byte;
        out.push(1, &addr);
    }
    out.flush();
    var got: [2]u8 = undefined;
    for (&got) |*byte| {
        const rc = linux.recvfrom(client, @ptrCast(byte), 1, linux.MSG.DONTWAIT, null, null);
        try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
    }
    try std.testing.expectEqualSlices(u8, "ac", &got);
}
