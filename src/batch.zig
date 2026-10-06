//! UDP by the batch: a syscall a datagram pays the kernel's entry and exit
//! each time, so what is already queued moves in one. Nothing waits to
//! fill a batch.
//!
//! Its headers point into it, so a batch lives on the heap and never moves.
const Batch = @This();
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");

/// Eight takes most of the saving.
pub const max = 8;

hdrs: [max]linux.mmsghdr,
iovs: [max]posix.iovec,
addrs: [max]na.PosixAddress,
bytes: []u8,
size: usize,
n: usize = 0,
fd: posix.fd_t = -1,

pub fn create(gpa: Allocator, size: usize) !*Batch {
    const b = try gpa.create(Batch);
    errdefer gpa.destroy(b);
    const bytes = try gpa.alloc(u8, max * size);
    b.* = .{ .hdrs = undefined, .iovs = undefined, .addrs = undefined, .bytes = bytes, .size = size };
    for (&b.hdrs, &b.iovs, &b.addrs, 0..) |*h, *iov, *addr, i| {
        iov.* = .{ .base = bytes[i * size ..].ptr, .len = size };
        h.* = .{ .hdr = .{ .name = &addr.any, .namelen = 0, .iov = @ptrCast(iov), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
    }
    return b;
}

pub fn destroy(b: *Batch, gpa: Allocator) void {
    gpa.free(b.bytes);
    gpa.destroy(b);
}

pub fn recv(b: *Batch, fd: posix.fd_t, want: usize) usize {
    // The kernel writes each sender's length over the room it was given.
    for (b.hdrs[0..want]) |*h| h.hdr.namelen = @sizeOf(na.PosixAddress);
    const rc = linux.recvmmsg(fd, &b.hdrs, @intCast(want), linux.MSG.DONTWAIT, null);
    return if (linux.errno(rc) == .SUCCESS) rc else 0;
}

pub fn datagram(b: *Batch, i: usize) []u8 {
    return b.bytes[i * b.size ..][0..b.hdrs[i].len];
}

pub fn from(b: *const Batch, i: usize) na.Address {
    return na.fromSockaddr(&b.addrs[i]);
}

pub fn next(b: *Batch, fd: posix.fd_t) []u8 {
    if (b.fd != fd) b.flush();
    b.fd = fd;
    return b.bytes[b.n * b.size ..][0..b.size];
}

pub fn push(b: *Batch, len: usize, to: *const na.Address) void {
    b.iovs[b.n].len = len;
    b.hdrs[b.n].hdr.namelen = na.toSockaddr(to, &b.addrs[b.n]);
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
    const gpa = std.testing.allocator;
    const in = try Batch.create(gpa, 64);
    defer in.destroy(gpa);
    const out = try Batch.create(gpa, 64);
    defer out.destroy(gpa);

    const server = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer sys.close(server);
    try na.bindTo(server, &na.initIp4(.{ 127, 0, 0, 1 }, 0));
    var sa: na.PosixAddress = undefined;
    var sa_len: posix.socklen_t = @sizeOf(na.PosixAddress);
    try sys.getsockname(server, &sa.any, &sa_len);

    const count = max + 3;
    var clients: [count]posix.fd_t = undefined;
    for (&clients, 0..) |*c, i| {
        c.* = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
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
            out.push(2, &in.from(i));
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
