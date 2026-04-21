const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const na = @import("net_address.zig");
const sys = @import("sys.zig");

pub const max_operations = 64;
const recv_buf_size = 4096;

// ── Public types ────────────────────────────────────────────────────────

pub const OperationId = u16;

pub const Completion = struct {
    context: *anyopaque,
    result: Result,
};

pub const Result = union(enum) {
    recv: RecvResult,
    accept: AcceptResult,
    read: ReadResult,
};

pub const RecvResult = struct {
    data: []const u8,
    addr: na.Address,
    err: ?anyerror,
};

pub const AcceptResult = struct {
    fd: posix.fd_t,
    addr: na.Address,
    err: ?anyerror,
};

pub const ReadResult = struct {
    bytes_read: usize,
    data: []const u8,
    err: ?anyerror,
};

// ── Operation slot ──────────────────────────────────────────────────────

const OpKind = enum { recv, accept, read };

const Slot = struct {
    kind: OpKind,
    context: *anyopaque,
    active: bool,

    // Storage for recv (must have pointer stability until CQE)
    iov: [1]posix.iovec,
    addr: na.PosixAddress,
    addr_len: posix.socklen_t,
    msghdr: posix.msghdr,
    recv_buf: [recv_buf_size]u8,

    fn init() Slot {
        return .{
            .kind = .recv,
            .context = undefined,
            .active = false,
            .iov = undefined,
            .addr = undefined,
            .addr_len = 0,
            .msghdr = undefined,
            .recv_buf = undefined,
        };
    }
};

// ── EventLoop ───────────────────────────────────────────────────────────

pub const EventLoop = struct {
    allocator: std.mem.Allocator,
    ring: linux.IoUring,
    slots: [max_operations]Slot,
    free_list: [max_operations]OperationId,
    free_count: u16,

    pub fn create(allocator: std.mem.Allocator) !*EventLoop {
        const self = try allocator.create(EventLoop);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        var params = std.mem.zeroes(linux.io_uring_params);
        params.flags = linux.IORING_SETUP_CQSIZE;
        params.cq_entries = max_operations * 4;
        self.ring = try linux.IoUring.init_params(max_operations, &params);
        std.debug.assert(params.features & linux.IORING_FEAT_NODROP != 0);
        self.free_count = max_operations;
        for (0..max_operations) |i| {
            self.slots[i] = Slot.init();
            self.free_list[i] = @intCast(max_operations - 1 - i); // stack order
        }
        return self;
    }

    pub fn destroy(self: *EventLoop) void {
        const allocator = self.allocator;
        self.ring.deinit();
        allocator.destroy(self);
    }

    fn allocSlot(self: *EventLoop) ?OperationId {
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        return self.free_list[self.free_count];
    }

    fn freeSlot(self: *EventLoop, id: OperationId) void {
        self.slots[id].active = false;
        self.free_list[self.free_count] = id;
        self.free_count += 1;
    }

    fn initOp(self: *EventLoop, kind: OpKind, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = kind;
        slot.context = context;
        slot.active = true;
        return id;
    }

    pub fn recvFrom(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = try self.initOp(.recv, context);
        errdefer self.freeSlot(id);
        const slot = &self.slots[id];

        slot.iov[0] = .{ .base = &slot.recv_buf, .len = recv_buf_size };
        slot.addr = std.mem.zeroes(na.PosixAddress);
        slot.addr_len = @sizeOf(na.PosixAddress);

        slot.msghdr = .{
            .name = @ptrCast(&slot.addr),
            .namelen = slot.addr_len,
            .iov = &slot.iov,
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };

        var sqe = try self.ring.get_sqe();
        sqe.prep_recvmsg(fd, &slot.msghdr, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn accept(self: *EventLoop, listen_fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = try self.initOp(.accept, context);
        errdefer self.freeSlot(id);
        const slot = &self.slots[id];
        slot.addr = std.mem.zeroes(na.PosixAddress);
        slot.addr_len = @sizeOf(na.PosixAddress);

        var sqe = try self.ring.get_sqe();
        sqe.prep_accept(listen_fd, @ptrCast(&slot.addr.any), &slot.addr_len, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn read(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = try self.initOp(.read, context);
        errdefer self.freeSlot(id);
        var sqe = try self.ring.get_sqe();
        sqe.prep_read(fd, &self.slots[id].recv_buf, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn cancel(self: *EventLoop, target_id: OperationId) !void {
        var sqe = try self.ring.get_sqe();
        sqe.prep_cancel(@as(u64, target_id), 0);
        // Use a sentinel for cancel SQEs — we don't need a slot for them
        sqe.user_data = std.math.maxInt(u64);
    }

    /// Submit pending SQEs and wait for all active operations to complete.
    pub fn flush(self: *EventLoop) void {
        while (self.free_count < max_operations) {
            _ = self.ring.submit_and_wait(1) catch return;
            var cqes: [max_operations]linux.io_uring_cqe = undefined;
            const count = self.ring.copy_cqes(&cqes, 0) catch return;
            for (cqes[0..count]) |cqe| {
                if (cqe.user_data == std.math.maxInt(u64)) continue;
                if (cqe.user_data < max_operations) {
                    const id: OperationId = @intCast(cqe.user_data);
                    if (self.slots[id].active) {
                        self.freeSlot(id);
                    }
                }
            }
        }
    }

    pub fn tick(self: *EventLoop, completions_buf: []Completion) ![]Completion {
        _ = try self.ring.submit_and_wait(1);
        return self.reapCompletions(completions_buf);
    }

    fn isCancelled(cqe: linux.io_uring_cqe) bool {
        return cqe.res == -@as(i32, @intCast(@intFromEnum(linux.E.CANCELED)));
    }

    fn reapCompletions(self: *EventLoop, buf: []Completion) ![]Completion {
        var cqes: [max_operations]linux.io_uring_cqe = undefined;
        const count = try self.ring.copy_cqes(&cqes, 0);

        var out: usize = 0;
        for (cqes[0..count]) |cqe| {
            // Skip cancel completions
            if (cqe.user_data == std.math.maxInt(u64)) continue;

            const id: OperationId = @intCast(cqe.user_data);
            const slot = &self.slots[id];
            if (!slot.active) continue;

            if (out >= buf.len) {
                self.freeSlot(id);
                continue;
            }

            const completion = &buf[out];
            completion.context = slot.context;

            switch (slot.kind) {
                .recv => {
                    if (cqe.res > 0) {
                        const len: usize = @intCast(cqe.res);
                        completion.result = .{ .recv = .{
                            .data = slot.recv_buf[0..len],
                            .addr = na.fromSockaddr(&slot.addr),
                            .err = null,
                        } };
                    } else if (isCancelled(cqe)) {
                        completion.result = .{ .recv = .{
                            .data = &.{},
                            .addr = na.initIp4(.{ 0, 0, 0, 0 }, 0),
                            .err = error.Cancelled,
                        } };
                    } else {
                        completion.result = .{ .recv = .{
                            .data = &.{},
                            .addr = na.initIp4(.{ 0, 0, 0, 0 }, 0),
                            .err = error.RecvFailed,
                        } };
                    }
                },
                .accept => {
                    if (cqe.res >= 0) {
                        completion.result = .{ .accept = .{
                            .fd = @intCast(cqe.res),
                            .addr = na.fromSockaddr(&slot.addr),
                            .err = null,
                        } };
                    } else if (isCancelled(cqe)) {
                        completion.result = .{ .accept = .{
                            .fd = -1,
                            .addr = na.initIp4(.{ 0, 0, 0, 0 }, 0),
                            .err = error.Cancelled,
                        } };
                    } else {
                        completion.result = .{ .accept = .{
                            .fd = -1,
                            .addr = na.initIp4(.{ 0, 0, 0, 0 }, 0),
                            .err = error.AcceptFailed,
                        } };
                    }
                },
                .read => {
                    if (cqe.res > 0) {
                        const len: usize = @intCast(cqe.res);
                        completion.result = .{ .read = .{
                            .bytes_read = len,
                            .data = slot.recv_buf[0..len],
                            .err = null,
                        } };
                    } else if (cqe.res == 0) {
                        completion.result = .{ .read = .{
                            .bytes_read = 0,
                            .data = &.{},
                            .err = error.EndOfFile,
                        } };
                    } else if (isCancelled(cqe)) {
                        completion.result = .{ .read = .{
                            .bytes_read = 0,
                            .data = &.{},
                            .err = error.Cancelled,
                        } };
                    } else {
                        completion.result = .{ .read = .{
                            .bytes_read = 0,
                            .data = &.{},
                            .err = error.ReadFailed,
                        } };
                    }
                },
            }

            self.freeSlot(id);
            out += 1;
        }

        return buf[0..out];
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

fn createTestLoop() !*EventLoop {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    return EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
}

test "EventLoop create/destroy" {
    const loop = try createTestLoop();
    defer loop.destroy();

    try testing.expectEqual(@as(u16, max_operations), loop.free_count);
}

test "EventLoop recvFrom with external sender (server pattern)" {
    // This test mimics the server's exact pattern: recvFrom + accept + read
    // on a non-seekable fd (pipe, like signalfd), with data from an external source.
    const loop = try createTestLoop();
    defer loop.destroy();

    // Create a "server" UDP socket (like the server does)
    const server_sock = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(server_sock);
    const bind_na = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var bind_pa: na.PosixAddress = undefined;
    const bind_len = na.toSockaddr(&bind_na, &bind_pa);
    try sys.bind(server_sock, &bind_pa.any, bind_len);

    const server_addr = try na.getSockName(server_sock);

    // Also create a TCP listen socket (like server does)
    const tcp_sock = try sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(tcp_sock);
    const tcp_bind_na = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var tcp_bind_pa: na.PosixAddress = undefined;
    const tcp_bind_len = na.toSockaddr(&tcp_bind_na, &tcp_bind_pa);
    try sys.bind(tcp_sock, &tcp_bind_pa.any, tcp_bind_len);
    try sys.listen(tcp_sock, 1);

    // Create a pipe to simulate signalfd (non-seekable fd)
    const pipe_fds = try sys.pipe();
    defer sys.close(pipe_fds[0]);
    defer sys.close(pipe_fds[1]);

    // Submit recvFrom + accept + read (like serveLoop does)
    var recv_ctx: u8 = 1;
    var accept_ctx: u8 = 2;
    var read_ctx: u8 = 3;
    _ = try loop.recvFrom(server_sock, @ptrCast(&recv_ctx));
    _ = try loop.accept(tcp_sock, @ptrCast(&accept_ctx));
    _ = try loop.read(pipe_fds[0], @ptrCast(&read_ctx));

    // Send data from a separate thread using plain posix (external client)
    const payload = "external DNS query";
    const SenderThread = struct {
        fn run(addr: na.Address, data: []const u8) void {
            const sock = sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
            defer sys.close(sock);
            var pa: na.PosixAddress = undefined;
            const sa_len = na.toSockaddr(&addr, &pa);
            _ = sys.sendto(sock, data, 0, &pa.any, sa_len) catch return;
        }
    };
    const thread = try std.Thread.spawn(.{}, SenderThread.run, .{ server_addr, payload });

    // tick() should return with the recvFrom completion (not blocked by pipe/accept)
    var completions: [max_operations]Completion = undefined;
    var got_recv = false;

    for (0..5) |_| {
        const results = try loop.tick(&completions);
        for (results) |c| {
            const tag = @as(*u8, @ptrCast(@alignCast(c.context))).*;
            if (tag == 1) { // recv_ctx
                switch (c.result) {
                    .recv => |r| {
                        if (r.err == null) {
                            try testing.expectEqualStrings(payload, r.data);
                            got_recv = true;
                        }
                    },
                    else => {},
                }
            } else if (tag == 3) { // read_ctx - pipe read completed unexpectedly
                switch (c.result) {
                    .read => |r| {
                        // If the pipe read failed (ESPIPE, etc), this is a bug
                        // that would cause the real server to falsely trigger shutdown
                        if (r.err != null) {
                            std.debug.print("PIPE READ ERROR: {?}\n", .{r.err});
                        }
                    },
                    else => {},
                }
            }
        }
        if (got_recv) break;
    }

    thread.join();
    try testing.expect(got_recv);
}

test "EventLoop cancel pending recvFrom" {
    const loop = try createTestLoop();
    defer loop.destroy();

    const sock = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(sock);
    const bind_na = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var bind_pa: na.PosixAddress = undefined;
    const bind_len = na.toSockaddr(&bind_na, &bind_pa);
    try sys.bind(sock, &bind_pa.any, bind_len);

    var ctx: u8 = 99;
    const recv_id = try loop.recvFrom(sock, @ptrCast(&ctx));
    try loop.cancel(recv_id);

    var completions: [max_operations]Completion = undefined;
    var got_cancelled = false;

    for (0..3) |_| {
        const results = try loop.tick(&completions);
        for (results) |c| {
            switch (c.result) {
                .recv => |r| {
                    if (r.err != null) got_cancelled = true;
                },
                else => {},
            }
        }
        if (got_cancelled) break;
    }

    try testing.expect(got_cancelled);
}
