const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const na = @import("net_address.zig");
const sys = @import("sys_union.zig");
const log = std.log.scoped(.event_loop);
const Uring = @import("uring.zig");
const Epoll = @import("epoll.zig");

pub const max_operations = 64;

/// Read ops serve only the signalfd — the buffer needs
/// room for a few packed signalfd_siginfo records (128 B each; signalfd
/// coalesces per signo, and excess records stay queued in the fd until
/// the op is re-armed), never packet data. UDP payloads live in the
/// backend's packet buffers instead.
const read_buf_size = 4 * @sizeOf(linux.signalfd_siginfo);

pub const udp_payload_max: u32 = 4096;

pub const no_addr = na.initIp4(.{ 0, 0, 0, 0 }, 0);

pub const OperationId = u16;

pub const Backend = enum { epoll, io_uring };

pub const Completion = struct {
    context: *anyopaque,
    result: Result,
    /// True when the operation is finished and its slot was freed. A
    /// `recvFromMulti` arm stays live across completions until the backend
    /// ends it (io_uring on ENOBUFS; epoll never). The caller must re-arm
    /// iff this is set.
    ///
    /// This travels on the completion rather than being asked of the slot
    /// table afterwards because by then the answer is gone: a batch frees
    /// every terminated slot before the caller sees any completion, the free
    /// list is LIFO, and re-arming one listener mid-batch can hand it the id
    /// another listener just released. Asking "is op N still armed?" would
    /// then inspect a stranger's fresh operation.
    terminated: bool = false,
};

pub const Result = union(enum) {
    recv: RecvResult,
    accept: AcceptResult,
    read: ReadResult,
    /// 0 on close or error.
    stream: usize,
    timer: void,
};

pub const RecvResult = struct {
    data: []const u8,
    addr: na.Address,
    err: ?anyerror,
    /// Non-null for `recvFromMulti` completions. Caller MUST call
    /// `releaseBuf(buf_id)` after processing `data`, or the pool starves.
    buf_id: ?u16 = null,
};

pub const AcceptResult = struct {
    fd: posix.fd_t,
    addr: na.Address,
    err: ?anyerror,
};

pub const ReadResult = struct {
    /// Owned copy of the payload. Read ops carry only tiny signalfd/
    /// eventfd records, so reap copies out of the slot buffer and the
    /// slot can be freed and re-armed mid-batch without invalidating
    /// this completion. (When `data` aliased the slot, any arm that
    /// claimed the freed slot — the LIFO free list makes that likely —
    /// clobbered a not-yet-consumed payload: an accept completion reaped
    /// ahead of a signal completion zeroed the siginfo and turned stats
    /// into shutdown.)
    buf: [read_buf_size]u8,
    len: usize,
    err: ?anyerror,

    pub fn data(self: *const ReadResult) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const Slot = struct {
    context: *anyopaque,
    active: bool,
    /// -1 for timers.
    fd: posix.fd_t,
    /// The kernel writes through pointers into the active variant, so it
    /// and the slot stay put until the op completes.
    state: State,

    const State = union(enum) {
        /// io_uring's multishot recvmsg layout, filled at arm; epoll's
        /// recvmmsg builds its own headers per batch.
        recv_multi: posix.msghdr,
        /// accept owns the peer-address out-params the kernel fills.
        accept: struct { addr: na.PosixAddress, addr_len: posix.socklen_t },
        /// read owns a small buffer — signalfd/eventfd payloads only.
        read: [read_buf_size]u8,
        /// Caller's buffer outlives the op.
        stream: []u8,
        /// io_uring reads `ts`; epoll fills `deadline_ns` at arm.
        timer: struct { ts: linux.kernel_timespec, deadline_ns: i64 = undefined },
    };
};

pub const EventLoop = struct {
    allocator: std.mem.Allocator,
    slots: [max_operations]Slot,
    free_list: [max_operations]OperationId,
    free_count: u16,
    backend: union(Backend) {
        epoll: Epoll,
        io_uring: Uring,
    },

    pub fn create(allocator: std.mem.Allocator, backend: Backend) !*EventLoop {
        const self = try allocator.create(EventLoop);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.free_count = max_operations;
        for (0..max_operations) |i| {
            self.slots[i] = .{ .context = undefined, .active = false, .fd = -1, .state = undefined };
            self.free_list[i] = @intCast(max_operations - 1 - i); // stack order
        }
        self.backend = switch (backend) {
            .epoll => .{ .epoll = try Epoll.init(allocator) },
            .io_uring => .{ .io_uring = try Uring.init(allocator) },
        };
        return self;
    }

    /// Binds the loop to the calling thread; must precede the first tick.
    pub fn enable(self: *EventLoop) !void {
        switch (self.backend) {
            .epoll => {},
            .io_uring => |*u| try u.enable(),
        }
    }

    pub fn destroy(self: *EventLoop) void {
        switch (self.backend) {
            inline else => |*b| b.deinit(self.allocator),
        }
        self.allocator.destroy(self);
    }

    pub fn freeSlot(self: *EventLoop, id: OperationId) void {
        self.slots[id].active = false;
        self.free_list[self.free_count] = id;
        self.free_count += 1;
    }

    fn arm(self: *EventLoop, fd: posix.fd_t, state: Slot.State, context: *anyopaque) !OperationId {
        if (self.free_count == 0) return error.TooManyOperations;
        self.free_count -= 1;
        const id = self.free_list[self.free_count];
        self.slots[id] = .{ .context = context, .active = true, .fd = fd, .state = state };
        errdefer self.freeSlot(id);
        switch (self.backend) {
            inline else => |*b| try b.arm(&self.slots[id], id),
        }
        return id;
    }

    /// One arm yields a completion per datagram until the op terminates
    /// (io_uring only, e.g. ENOBUFS). Callers MUST `releaseBuf` each `buf_id`.
    pub fn recvFromMulti(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        return self.arm(fd, .{ .recv_multi = undefined }, context);
    }

    pub fn releaseBuf(self: *EventLoop, buf_id: u16) void {
        switch (self.backend) {
            inline else => |*b| b.release(buf_id),
        }
    }

    /// `listen_fd` must be non-blocking: a reset can revoke epoll's readiness.
    pub fn accept(self: *EventLoop, listen_fd: posix.fd_t, context: *anyopaque) !OperationId {
        return self.arm(listen_fd, .{ .accept = .{
            .addr = std.mem.zeroes(na.PosixAddress),
            .addr_len = @sizeOf(na.PosixAddress),
        } }, context);
    }

    /// `fd` must be non-blocking, as for `accept`.
    pub fn read(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        return self.arm(fd, .{ .read = undefined }, context);
    }

    pub fn readStream(self: *EventLoop, fd: posix.fd_t, buf: []u8, context: *anyopaque) !OperationId {
        return self.arm(fd, .{ .stream = buf }, context);
    }

    pub fn timer(self: *EventLoop, ms: u32, context: *anyopaque) !OperationId {
        return self.arm(-1, .{ .timer = .{
            .ts = .{ .sec = ms / 1000, .nsec = @as(i64, ms % 1000) * std.time.ns_per_ms },
        } }, context);
    }

    pub fn tick(self: *EventLoop, completions_buf: *[max_operations]Completion) ![]Completion {
        return switch (self.backend) {
            inline else => |*b| b.tick(self, completions_buf),
        };
    }

    /// Frees the slot and builds its one completion from a syscall result.
    pub fn finish(self: *EventLoop, id: OperationId, res: isize) Completion {
        const slot = &self.slots[id];
        defer self.freeSlot(id);
        return .{ .context = slot.context, .terminated = true, .result = switch (slot.state) {
            .recv_multi => unreachable,
            .accept => |*a| .{ .accept = if (res >= 0)
                .{ .fd = @intCast(res), .addr = na.fromSockaddr(&a.addr), .err = null }
            else
                .{ .fd = -1, .addr = no_addr, .err = error.AcceptFailed } },
            .read => |*rbuf| blk: {
                var r: ReadResult = .{ .buf = undefined, .len = 0, .err = null };
                if (res > 0) {
                    r.len = @intCast(res);
                    @memcpy(r.buf[0..r.len], rbuf[0..r.len]);
                } else r.err = if (res == 0) error.EndOfFile else error.ReadFailed;
                break :blk .{ .read = r };
            },
            .stream => .{ .stream = @intCast(@max(res, 0)) },
            .timer => .{ .timer = {} },
        } };
    }
};

pub fn createTestLoop(backend: Backend) !*EventLoop {
    const loop = EventLoop.create(testing.allocator, backend) catch |err| return switch (err) {
        error.PermissionDenied, error.SystemOutdated => error.SkipZigTest,
        else => err,
    };
    watchdog(10);
    try loop.enable();
    return loop;
}

pub fn destroyTestLoop(loop: *EventLoop) void {
    watchdog(0);
    loop.destroy();
}

/// SIGALRM kills a test whose lost completion would hang `tick`. 0 disarms.
fn watchdog(secs: isize) void {
    const t: linux.itimerspec = .{ .it_interval = .{ .sec = 0, .nsec = 0 }, .it_value = .{ .sec = secs, .nsec = 0 } };
    _ = linux.setitimer(@backingInt(linux.ITIMER.REAL), &t, null);
}

fn onBothBackends(f: fn (Backend) anyerror!void) !void {
    try f(.epoll);
    f(.io_uring) catch |err| if (err != error.SkipZigTest) return err;
}

pub fn bindTestUdp() !posix.fd_t {
    const sock = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer sys.close(sock);
    const addr = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var pa: na.PosixAddress = undefined;
    try sys.bind(sock, &pa.any, na.toSockaddr(&addr, &pa));
    return sock;
}

test "Slot stays lean — read ops must not drag packet-sized buffers back in" {
    // The pre-union Slot carried a 4 KiB recv_buf in every slot whether
    // the op needed it or not (~256 KiB/worker dead). Budget: the small
    // read buffer plus header change. If this fires, some variant grew a
    // packet-sized payload — packets belong in the backend's packet buffers.
    try testing.expect(@sizeOf(Slot) <= read_buf_size + 64);
}

test "readStream fills the caller's buffer, EOFs on shutdown; timer ticks" {
    try onBothBackends(struct {
        fn run(backend: Backend) !void {
            const loop = try createTestLoop(backend);
            defer destroyTestLoop(loop);

            var fds: [2]i32 = undefined;
            try testing.expectEqual(@as(usize, 0), linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds));
            defer sys.close(fds[0]);
            defer sys.close(fds[1]);

            var buf: [16]u8 = undefined;
            var rctx: u8 = 1;
            var tctx: u8 = 2;
            _ = try loop.readStream(fds[0], &buf, @ptrCast(&rctx));
            _ = try loop.timer(5, @ptrCast(&tctx));
            _ = try sys.write(fds[1], "hello");

            var got: ?usize = null;
            var ticked = false;
            var completions: [max_operations]Completion = undefined;
            for (0..20) |_| {
                for (try loop.tick(&completions)) |c| switch (c.result) {
                    .stream => |s| got = s,
                    .timer => ticked = true,
                    else => {},
                };
                if (got != null and ticked) break;
            }
            try testing.expectEqualStrings("hello", buf[0..got.?]);
            try testing.expect(ticked);

            _ = try loop.readStream(fds[0], &buf, @ptrCast(&rctx));
            sys.shutdown(fds[1]);
            var eof = false;
            for (0..20) |_| {
                for (try loop.tick(&completions)) |c| switch (c.result) {
                    .stream => |s| eof = s == 0,
                    else => {},
                };
                if (eof) break;
            }
            try testing.expect(eof);
        }
    }.run);
}

test "EventLoop create/destroy" {
    try onBothBackends(struct {
        fn run(backend: Backend) !void {
            const loop = try createTestLoop(backend);
            defer destroyTestLoop(loop);
            try testing.expectEqual(@as(u16, max_operations), loop.free_count);
        }
    }.run);
}

test "EventLoop recvFromMulti receives multiple packets on one arm" {
    try onBothBackends(struct {
        fn run(backend: Backend) !void {
            const loop = try createTestLoop(backend);
            defer destroyTestLoop(loop);

            const sock = try bindTestUdp();
            defer sys.close(sock);
            const server_addr = try na.getSockName(sock);

            var ctx: u8 = 1;
            _ = try loop.recvFromMulti(sock, @ptrCast(&ctx));

            // Send 3 packets from a separate thread — one multishot arm should
            // produce 3 completions without re-arming.
            const payloads = [_][]const u8{ "first", "second", "third" };
            const SenderThread = struct {
                fn run(addr: na.Address, msgs: []const []const u8) void {
                    const s = sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
                    defer sys.close(s);
                    var pa: na.PosixAddress = undefined;
                    const sa_len = na.toSockaddr(&addr, &pa);
                    for (msgs) |m| _ = sys.sendto(s, m, 0, &pa.any, sa_len) catch return;
                }
            };
            const thread = try std.Thread.spawn(.{}, SenderThread.run, .{ server_addr, &payloads });

            var completions: [max_operations]Completion = undefined;
            var seen: [payloads.len]bool = @splat(false);
            var received: usize = 0;
            var still_armed_seen = false;

            for (0..10) |_| {
                const results = try loop.tick(&completions);
                for (results) |c| {
                    switch (c.result) {
                        .recv => |r| {
                            if (r.err == null and r.buf_id != null) {
                                for (payloads, 0..) |p, pi| {
                                    if (std.mem.eql(u8, p, r.data) and !seen[pi]) {
                                        seen[pi] = true;
                                        received += 1;
                                        break;
                                    }
                                }
                                loop.releaseBuf(r.buf_id.?);
                            }
                        },
                        else => {},
                    }
                    // Multishot keeps delivering on one arm: every completion
                    // carrying a payload must report the op as still live, so
                    // no re-registration happens between packets.
                    if (c.result == .recv and c.result.recv.err == null and !c.terminated)
                        still_armed_seen = true;
                }
                if (received == payloads.len) break;
            }

            thread.join();
            try testing.expectEqual(payloads.len, received);
            try testing.expect(still_armed_seen);
        }
    }.run);
}

test "read payload survives an op arming into the freed slot mid-batch" {
    // Regression: reap frees read slots before the caller consumes the
    // batch, and the LIFO free list hands the same slot to the very next
    // arm. When ReadResult aliased the slot buffer, that arm clobbered
    // the payload — a tcp-accept re-arm ahead of a signal completion
    // zeroed the siginfo and classifySignalRead turned stats into
    // shutdown. ReadResult now owns a copy; pin that.
    try onBothBackends(struct {
        fn run(backend: Backend) !void {
            const loop = try createTestLoop(backend);
            defer destroyTestLoop(loop);

            const rc = linux.eventfd(0, linux.EFD.NONBLOCK);
            const sr: isize = @bitCast(rc);
            try testing.expect(sr >= 0);
            const efd: posix.fd_t = @intCast(sr);
            defer sys.close(efd);

            const val: u64 = 0x1122334455667788;
            _ = try sys.write(efd, std.mem.asBytes(&val));

            var ctx: u8 = 7;
            _ = try loop.read(efd, @ptrCast(&ctx));

            var completions: [max_operations]Completion = undefined;
            var saved: ?ReadResult = null;
            for (0..5) |_| {
                const results = try loop.tick(&completions);
                for (results) |c| switch (c.result) {
                    .read => |r| saved = r,
                    else => {},
                };
                if (saved != null) break;
            }
            try testing.expect(saved != null);

            // Arm a recvmsg — the free list pops the just-freed read slot and
            // initOp writes the recv_multi msghdr over the shared union storage.
            const sock = try bindTestUdp();
            defer sys.close(sock);
            _ = try loop.recvFromMulti(sock, @ptrCast(&ctx));

            try testing.expectEqualSlices(u8, std.mem.asBytes(&val), saved.?.data());
        }
    }.run);
}

test "truncated datagram is rejected without tearing down the multishot" {
    // The kernel keeps the multishot live after MSG_TRUNC. Freeing the slot
    // made the server re-arm on top of it: one leaked op per oversized datagram.
    try onBothBackends(struct {
        fn run(backend: Backend) !void {
            const loop = try createTestLoop(backend);
            defer destroyTestLoop(loop);

            const sock = try bindTestUdp();
            defer sys.close(sock);
            const server_addr = try na.getSockName(sock);
            var pa: na.PosixAddress = undefined;
            const sa_len = na.toSockaddr(&server_addr, &pa);

            var ctx: u8 = 1;
            _ = try loop.recvFromMulti(sock, @ptrCast(&ctx));

            const s = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
            defer sys.close(s);
            const big: [udp_payload_max + 1]u8 = @splat('x');
            _ = try sys.sendto(s, &big, 0, &pa.any, sa_len);

            var completions: [max_operations]Completion = undefined;
            const trunc = try loop.tick(&completions);
            try testing.expectEqual(@as(usize, 1), trunc.len);
            try testing.expectEqual(@as(?anyerror, error.RecvFailed), trunc[0].result.recv.err);
            try testing.expect(!trunc[0].terminated);

            _ = try sys.sendto(s, "hello", 0, &pa.any, sa_len);
            const next = try loop.tick(&completions);
            try testing.expectEqual(@as(usize, 1), next.len);
            try testing.expectEqualStrings("hello", next[0].result.recv.data);
            loop.releaseBuf(next[0].result.recv.buf_id.?);

            // Every buffer came back: a rejected datagram must not leak one.
            if (backend == .epoll) try testing.expectEqual(@as(u16, max_operations), loop.backend.epoll.free_count);
        }
    }.run);
}
