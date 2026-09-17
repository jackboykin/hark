//! epoll backend. Readiness drives the op's own syscall: accept4, read, or
//! one recvmmsg batch for UDP. UDP stays level-triggered and armed; the
//! rest are one-shot, and EAGAIN on a spurious wake re-arms silently.
//! Timers live in the slot table and bound the epoll_wait timeout.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");
const event_loop = @import("event_loop.zig");
const log = std.log.scoped(.event_loop);

const EventLoop = event_loop.EventLoop;
const Completion = event_loop.Completion;
const OperationId = event_loop.OperationId;
const Slot = event_loop.Slot;
const max_operations = event_loop.max_operations;
const udp_payload_max = event_loop.udp_payload_max;
const no_addr = event_loop.no_addr;

const Epoll = @This();

fd: posix.fd_t,
/// `max_operations` buffers suffice: a tick's recvs are released
/// before the next.
buffers: []u8,
free: [max_operations]u16,
free_count: u16,

pub fn init(allocator: std.mem.Allocator) !Epoll {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) {
        log.err("failed to create epoll instance ({t})", .{linux.errno(rc)});
        return error.EpollCreateFailed;
    }
    const fd: posix.fd_t = @intCast(rc);
    errdefer sys.close(fd);
    var e: Epoll = .{
        .fd = fd,
        .buffers = try allocator.alloc(u8, @as(usize, max_operations) * udp_payload_max),
        .free = undefined,
        .free_count = max_operations,
    };
    for (&e.free, 0..) |*b, i| b.* = @intCast(i);
    return e;
}

pub fn deinit(e: *Epoll, allocator: std.mem.Allocator) void {
    sys.close(e.fd);
    allocator.free(e.buffers);
}

/// UDP stays level-triggered and armed; everything else is one-shot.
pub fn arm(e: *Epoll, slot: *Slot, id: OperationId) !void {
    switch (slot.state) {
        .recv_multi => try e.watch(slot.fd, linux.EPOLL.IN, id),
        .timer => |*t| t.deadline_ns = nowNs() + t.ts.sec * std.time.ns_per_s + t.ts.nsec,
        .accept, .read, .stream => try e.watch(slot.fd, linux.EPOLL.IN | linux.EPOLL.ONESHOT, id),
    }
}

fn bufferAt(e: *const Epoll, buffer_id: u16) []u8 {
    return e.buffers[@as(usize, buffer_id) * udp_payload_max ..][0..udp_payload_max];
}

pub fn release(e: *Epoll, buffer_id: u16) void {
    e.free[e.free_count] = buffer_id;
    e.free_count += 1;
}

/// MOD first: steady-state re-arms hit an fd already in the set.
fn watch(e: *Epoll, fd: posix.fd_t, events: u32, id: OperationId) !void {
    var ev: linux.epoll_event = .{ .events = events, .data = .{ .u64 = id } };
    if (linux.errno(linux.epoll_ctl(e.fd, linux.EPOLL.CTL_MOD, fd, &ev)) == .SUCCESS) return;
    if (linux.errno(linux.epoll_ctl(e.fd, linux.EPOLL.CTL_ADD, fd, &ev)) != .SUCCESS) return error.EpollCtlFailed;
}

pub fn tick(e: *Epoll, loop: *EventLoop, buf: *[max_operations]Completion) ![]Completion {
    var events: [max_operations]linux.epoll_event = undefined;
    const rc = linux.epoll_wait(e.fd, &events, max_operations, timeoutMs(loop));
    const ready: usize = switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .INTR => 0,
        else => return error.EpollWaitFailed,
    };

    var out: usize = 0;
    const now = nowNs();
    for (&loop.slots, 0..) |*slot, id| {
        if (slot.active and slot.state == .timer and slot.state.timer.deadline_ns <= now) {
            buf[out] = loop.finish(@intCast(id), 0);
            out += 1;
        }
    }
    // Ready fds and expired timers each hold a slot, so every share is at
    // least one: a flooded socket can't crowd a listener out of the tick.
    for (events[0..ready], 0..) |ev, i| {
        const share = (max_operations - out) / (ready - i);
        std.debug.assert(share > 0);
        out += e.onReady(loop, @intCast(ev.data.u64), buf[out..][0..share]);
    }
    return buf[0..out];
}

fn timeoutMs(loop: *const EventLoop) i32 {
    var next: i64 = std.math.maxInt(i64);
    for (&loop.slots) |*s| if (s.active and s.state == .timer) {
        next = @min(next, s.state.timer.deadline_ns);
    };
    if (next == std.math.maxInt(i64)) return -1;
    const left = @max(next - nowNs(), 0);
    return @intCast(@min(std.math.divCeil(i64, left, std.time.ns_per_ms) catch unreachable, std.math.maxInt(i32)));
}

fn onReady(e: *Epoll, loop: *EventLoop, id: OperationId, out: []Completion) usize {
    const slot = &loop.slots[id];
    if (!slot.active) return 0;
    const rc = switch (slot.state) {
        .recv_multi => return e.drainUdp(slot, out),
        .accept => |*a| linux.accept4(slot.fd, &a.addr.any, &a.addr_len, 0),
        .read => |*r| linux.read(slot.fd, r, r.len),
        .stream => |s| linux.recvfrom(slot.fd, s.ptr, s.len, linux.MSG.DONTWAIT, null, null),
        .timer => return 0,
    };
    switch (linux.errno(rc)) {
        .AGAIN, .INTR => {
            if (e.watch(slot.fd, linux.EPOLL.IN | linux.EPOLL.ONESHOT, id)) return 0 else |_| {
                out[0] = loop.finish(id, -1);
                return 1;
            }
        },
        else => {
            out[0] = loop.finish(id, @bitCast(rc));
            return 1;
        },
    }
}

/// One recvmmsg; what is left stays readable and wakes the next tick.
fn drainUdp(e: *Epoll, slot: *const Slot, out: []Completion) usize {
    const n = @min(out.len, e.free_count);
    if (n == 0) return 0;
    var ids: [max_operations]u16 = undefined;
    var iovs: [max_operations]posix.iovec = undefined;
    var names: [max_operations]na.PosixAddress = undefined;
    var msgs: [max_operations]linux.mmsghdr = undefined;
    for (0..n) |i| {
        ids[i] = e.free[e.free_count - 1 - i];
        iovs[i] = .{ .base = e.bufferAt(ids[i]).ptr, .len = udp_payload_max };
        msgs[i] = .{ .len = 0, .hdr = .{
            .name = &names[i].any,
            .namelen = @sizeOf(na.PosixAddress),
            .iov = iovs[i..].ptr,
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        } };
    }
    const rc = linux.recvmmsg(slot.fd, &msgs, @intCast(n), linux.MSG.DONTWAIT, null);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR => return 0,
        else => {
            out[0] = .{ .context = slot.context, .result = .{ .recv = .{ .data = &.{}, .addr = no_addr, .err = error.RecvFailed } } };
            return 1;
        },
    }
    e.free_count -= @intCast(rc);
    for (msgs[0..rc], ids[0..rc], names[0..rc], out[0..rc]) |m, id, *name, *c| {
        c.* = .{ .context = slot.context, .result = .{ .recv = if (m.hdr.flags & linux.MSG.TRUNC != 0 or m.hdr.namelen == 0) blk: {
            e.release(id);
            break :blk .{ .data = &.{}, .addr = no_addr, .err = error.RecvFailed };
        } else .{ .data = e.bufferAt(id)[0..m.len], .addr = na.fromSockaddr(name), .err = null, .buf_id = id } } };
    }
    return rc;
}

fn nowNs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * std.time.ns_per_s + ts.nsec;
}

test "epoll: a flooded socket cannot crowd a quiet one out of the tick" {
    const loop = try event_loop.createTestLoop(.epoll);
    defer event_loop.destroyTestLoop(loop);

    var socks: [2]posix.fd_t = undefined;
    var ctxs: [2]u8 = .{ 0, 1 };
    for (&socks, &ctxs) |*sock, *ctx| {
        sock.* = try event_loop.bindTestUdp();
        _ = try loop.recvFromMulti(sock.*, @ptrCast(ctx));
    }
    defer for (socks) |sock| sys.close(sock);

    const s = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer sys.close(s);
    var pa: na.PosixAddress = undefined;
    const flood = try na.getSockName(socks[0]);
    for (0..3 * max_operations) |_| _ = try sys.sendto(s, "flood", 0, &pa.any, na.toSockaddr(&flood, &pa));
    const quiet = try na.getSockName(socks[1]);
    _ = try sys.sendto(s, "quiet", 0, &pa.any, na.toSockaddr(&quiet, &pa));

    var completions: [max_operations]Completion = undefined;
    const results = try loop.tick(&completions);
    var per_sock: [2]usize = .{ 0, 0 };
    for (results) |c| {
        per_sock[@as(*u8, @ptrCast(c.context)).*] += 1;
        loop.releaseBuf(c.result.recv.buf_id.?);
    }
    try testing.expectEqual(@as(usize, 1), per_sock[1]);
    try testing.expect(per_sock[0] >= max_operations / 2);

    // The flood's remainder is still readable: level-triggered.
    try testing.expect((try loop.tick(&completions)).len > 0);
}
