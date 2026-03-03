const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;

pub const max_operations = 64;
const recv_buf_size = 4096;

// ── Public types ────────────────────────────────────────────────────────

pub const OperationId = u16;

pub const Completion = struct {
    context: *anyopaque,
    result: Result,
};

pub const Result = union(enum) {
    send: SendResult,
    recv: RecvResult,
    timeout: TimeoutResult,
    connect: ConnectResult,
    tcp_send: TcpSendResult,
    tcp_recv: TcpRecvResult,
    accept: AcceptResult,
    read: ReadResult,
};

pub const SendResult = struct {
    bytes_sent: i32,
};

pub const RecvResult = struct {
    data: []const u8,
    addr: std.net.Address,
    err: ?anyerror,
};

pub const TimeoutResult = struct {
    expired: bool, // false if cancelled
};

pub const ConnectResult = struct {
    err: ?anyerror,
};

pub const TcpSendResult = struct {
    bytes_sent: i32,
};

pub const TcpRecvResult = struct {
    data: []const u8,
    err: ?anyerror,
};

pub const AcceptResult = struct {
    fd: posix.fd_t,
    addr: std.net.Address,
    err: ?anyerror,
};

pub const ReadResult = struct {
    bytes_read: usize,
    data: []const u8,
    err: ?anyerror,
};

// ── Operation slot ──────────────────────────────────────────────────────

const OpKind = enum { send, recv, timeout, cancel, connect, tcp_send, tcp_recv, accept, read };

const Slot = struct {
    kind: OpKind,
    context: *anyopaque,
    active: bool,

    // Storage for send/recv (must have pointer stability until CQE)
    iov: [1]posix.iovec,
    iov_const: [1]posix.iovec_const,
    addr: std.net.Address,
    addr_len: posix.socklen_t,
    msghdr: posix.msghdr,
    msghdr_const: posix.msghdr_const,
    recv_buf: [recv_buf_size]u8,

    // Timeout spec
    timeout_spec: linux.kernel_timespec,

    fn init() Slot {
        return .{
            .kind = .timeout,
            .context = undefined,
            .active = false,
            .iov = undefined,
            .iov_const = undefined,
            .addr = undefined,
            .addr_len = 0,
            .msghdr = undefined,
            .msghdr_const = undefined,
            .recv_buf = undefined,
            .timeout_spec = undefined,
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
        self.ring = try linux.IoUring.init(max_operations, 0);
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

    pub fn setTimeout(self: *EventLoop, ms: u32, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = .timeout;
        slot.context = context;
        slot.active = true;
        slot.timeout_spec = .{
            .sec = @intCast(ms / 1000),
            .nsec = @intCast(@as(u64, ms % 1000) * 1_000_000),
        };

        var sqe = try self.ring.get_sqe();
        sqe.prep_timeout(&slot.timeout_spec, 0, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn sendTo(self: *EventLoop, fd: posix.fd_t, data: []const u8, dest: std.net.Address, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = .send;
        slot.context = context;
        slot.active = true;

        slot.iov_const[0] = .{ .base = data.ptr, .len = data.len };
        slot.addr = dest;
        slot.addr_len = dest.getOsSockLen();

        slot.msghdr_const = .{
            .name = @ptrCast(&slot.addr),
            .namelen = slot.addr_len,
            .iov = &slot.iov_const,
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };

        var sqe = try self.ring.get_sqe();
        sqe.prep_sendmsg(fd, &slot.msghdr_const, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn recvFrom(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = .recv;
        slot.context = context;
        slot.active = true;

        slot.iov[0] = .{ .base = &slot.recv_buf, .len = recv_buf_size };
        slot.addr = std.mem.zeroes(std.net.Address);
        slot.addr_len = @sizeOf(std.net.Address);

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

    pub fn connect(self: *EventLoop, fd: posix.fd_t, dest: std.net.Address, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = .connect;
        slot.context = context;
        slot.active = true;
        slot.addr = dest;
        slot.addr_len = dest.getOsSockLen();

        var sqe = try self.ring.get_sqe();
        sqe.prep_connect(fd, &slot.addr.any, slot.addr_len);
        sqe.user_data = id;
        return id;
    }

    pub fn tcpSend(self: *EventLoop, fd: posix.fd_t, data: []const u8, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = .tcp_send;
        slot.context = context;
        slot.active = true;

        var sqe = try self.ring.get_sqe();
        sqe.prep_send(fd, data, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn tcpRecv(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = .tcp_recv;
        slot.context = context;
        slot.active = true;

        var sqe = try self.ring.get_sqe();
        sqe.prep_recv(fd, &slot.recv_buf, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn accept(self: *EventLoop, listen_fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = .accept;
        slot.context = context;
        slot.active = true;
        slot.addr = std.mem.zeroes(std.net.Address);
        slot.addr_len = @sizeOf(std.net.Address);

        var sqe = try self.ring.get_sqe();
        sqe.prep_accept(listen_fd, @ptrCast(&slot.addr.any), &slot.addr_len, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn read(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.kind = .read;
        slot.context = context;
        slot.active = true;

        var sqe = try self.ring.get_sqe();
        sqe.prep_read(fd, &slot.recv_buf, 0);
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

    fn reapCompletions(self: *EventLoop, buf: []Completion) ![]Completion {
        var cqes: [max_operations]linux.io_uring_cqe = undefined;
        const count = try self.ring.copy_cqes(&cqes, 0);
        const n = @min(count, buf.len);

        var out: usize = 0;
        for (cqes[0..count]) |cqe| {
            // Skip cancel completions
            if (cqe.user_data == std.math.maxInt(u64)) continue;
            if (out >= n) break;

            const id: OperationId = @intCast(cqe.user_data);
            const slot = &self.slots[id];
            if (!slot.active) continue;

            const completion = &buf[out];
            completion.context = slot.context;

            switch (slot.kind) {
                .send => {
                    completion.result = .{ .send = .{ .bytes_sent = cqe.res } };
                },
                .recv => {
                    if (cqe.res > 0) {
                        const len: usize = @intCast(cqe.res);
                        completion.result = .{ .recv = .{
                            .data = slot.recv_buf[0..len],
                            .addr = slot.addr,
                            .err = null,
                        } };
                    } else if (cqe.res == -@as(i32, @intCast(@intFromEnum(linux.E.CANCELED)))) {
                        completion.result = .{ .recv = .{
                            .data = &.{},
                            .addr = slot.addr,
                            .err = error.Cancelled,
                        } };
                    } else {
                        completion.result = .{ .recv = .{
                            .data = &.{},
                            .addr = slot.addr,
                            .err = error.RecvFailed,
                        } };
                    }
                },
                .timeout => {
                    const cancelled = cqe.res == -@as(i32, @intCast(@intFromEnum(linux.E.CANCELED)));
                    completion.result = .{ .timeout = .{ .expired = !cancelled } };
                },
                .connect => {
                    if (cqe.res == 0) {
                        completion.result = .{ .connect = .{ .err = null } };
                    } else if (cqe.res == -@as(i32, @intCast(@intFromEnum(linux.E.CANCELED)))) {
                        completion.result = .{ .connect = .{ .err = error.Cancelled } };
                    } else {
                        completion.result = .{ .connect = .{ .err = error.ConnectFailed } };
                    }
                },
                .tcp_send => {
                    completion.result = .{ .tcp_send = .{ .bytes_sent = cqe.res } };
                },
                .tcp_recv => {
                    if (cqe.res > 0) {
                        const len: usize = @intCast(cqe.res);
                        completion.result = .{ .tcp_recv = .{
                            .data = slot.recv_buf[0..len],
                            .err = null,
                        } };
                    } else if (cqe.res == 0) {
                        completion.result = .{ .tcp_recv = .{
                            .data = &.{},
                            .err = error.ConnectionClosed,
                        } };
                    } else if (cqe.res == -@as(i32, @intCast(@intFromEnum(linux.E.CANCELED)))) {
                        completion.result = .{ .tcp_recv = .{
                            .data = &.{},
                            .err = error.Cancelled,
                        } };
                    } else {
                        completion.result = .{ .tcp_recv = .{
                            .data = &.{},
                            .err = error.RecvFailed,
                        } };
                    }
                },
                .accept => {
                    if (cqe.res >= 0) {
                        completion.result = .{ .accept = .{
                            .fd = @intCast(cqe.res),
                            .addr = slot.addr,
                            .err = null,
                        } };
                    } else if (cqe.res == -@as(i32, @intCast(@intFromEnum(linux.E.CANCELED)))) {
                        completion.result = .{ .accept = .{
                            .fd = -1,
                            .addr = slot.addr,
                            .err = error.Cancelled,
                        } };
                    } else {
                        completion.result = .{ .accept = .{
                            .fd = -1,
                            .addr = slot.addr,
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
                    } else if (cqe.res == -@as(i32, @intCast(@intFromEnum(linux.E.CANCELED)))) {
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
                .cancel => {},
            }

            self.freeSlot(id);
            out += 1;
        }

        return buf[0..out];
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

fn isLinuxIoUringAvailable() bool {
    if (comptime @import("builtin").os.tag != .linux) return false;
    return true;
}

test "EventLoop create/destroy" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    try testing.expectEqual(@as(u16, max_operations), loop.free_count);
}

test "EventLoop setTimeout fires" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var ctx: u8 = 42;
    _ = try loop.setTimeout(10, @ptrCast(&ctx));

    var completions: [max_operations]Completion = undefined;
    const results = try loop.tick(&completions);
    try testing.expectEqual(@as(usize, 1), results.len);
    try testing.expect(results[0].result.timeout.expired);
    try testing.expectEqual(@as(u8, 42), @as(*u8, @ptrCast(@alignCast(results[0].context))).*);
}

test "EventLoop sendTo/recvFrom loopback" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Create two UDP sockets
    const sock_a = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sock_a);
    const sock_b = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sock_b);

    // Bind sock_b to localhost ephemeral port
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try posix.bind(sock_b, &bind_addr.any, bind_addr.getOsSockLen());

    // Get the actual port assigned
    var dest_addr: std.net.Address = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(sock_b, @ptrCast(&dest_addr), &addr_len);

    const payload = "hello io_uring";
    var send_ctx: u8 = 1;
    var recv_ctx: u8 = 2;

    // Queue both operations
    _ = try loop.recvFrom(sock_b, @ptrCast(&recv_ctx));
    _ = try loop.sendTo(sock_a, payload, dest_addr, @ptrCast(&send_ctx));

    var completions: [max_operations]Completion = undefined;
    var got_send = false;
    var got_recv = false;

    // May take two ticks
    for (0..2) |_| {
        const results = try loop.tick(&completions);
        for (results) |c| {
            switch (c.result) {
                .send => {
                    got_send = true;
                    try testing.expect(c.result.send.bytes_sent > 0);
                },
                .recv => {
                    got_recv = true;
                    try testing.expectEqualStrings(payload, c.result.recv.data);
                    try testing.expectEqual(@as(?anyerror, null), c.result.recv.err);
                },
                else => {},
            }
        }
        if (got_send and got_recv) break;
    }

    try testing.expect(got_send);
    try testing.expect(got_recv);
}

test "EventLoop recvFrom with external sender (server pattern)" {
    // This test mimics the server's exact pattern: recvFrom + accept + read
    // on a non-seekable fd (pipe, like signalfd), with data from an external source.
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Create a "server" UDP socket (like the server does)
    const server_sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(server_sock);
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try posix.bind(server_sock, &bind_addr.any, bind_addr.getOsSockLen());

    var server_addr: std.net.Address = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(server_sock, @ptrCast(&server_addr), &addr_len);

    // Also create a TCP listen socket (like server does)
    const tcp_sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(tcp_sock);
    const tcp_bind = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try posix.bind(tcp_sock, &tcp_bind.any, tcp_bind.getOsSockLen());
    try posix.listen(tcp_sock, 1);

    // Create a pipe to simulate signalfd (non-seekable fd)
    const pipe_fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

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
        fn run(addr: std.net.Address, data: []const u8) void {
            const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
            defer posix.close(sock);
            _ = posix.sendto(sock, data, 0, &addr.any, addr.getOsSockLen()) catch return;
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
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sock);
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());

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

test "EventLoop TCP connect/send/recv loopback" {
    if (!isLinuxIoUringAvailable()) return error.SkipZigTest;
    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Create a TCP listener
    const listener = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(listener);
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try posix.bind(listener, &bind_addr.any, bind_addr.getOsSockLen());
    try posix.listen(listener, 1);

    var server_addr: std.net.Address = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(listener, @ptrCast(&server_addr), &addr_len);

    // Server thread: accept, read, echo back, close
    const ServerThread = struct {
        fn run(sock: posix.fd_t) void {
            var polls = [1]std.posix.pollfd{.{
                .fd = sock,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const poll_result = std.posix.poll(&polls, 2000) catch return;
            if (poll_result == 0) return;

            var client_addr: std.net.Address = std.mem.zeroes(std.net.Address);
            var client_len: posix.socklen_t = @sizeOf(std.net.Address);
            const client = posix.accept(sock, @ptrCast(&client_addr), &client_len, 0) catch return;
            defer posix.close(client);

            var buf: [4096]u8 = undefined;
            // Poll for data on the accepted connection
            var cpoll = [1]std.posix.pollfd{.{
                .fd = client,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const cpoll_result = std.posix.poll(&cpoll, 2000) catch return;
            if (cpoll_result == 0) return;

            const n = posix.read(client, &buf) catch return;
            if (n == 0) return;
            _ = posix.write(client, buf[0..n]) catch return;
        }
    };

    const thread = try std.Thread.spawn(.{}, ServerThread.run, .{listener});

    // Client: connect, send, recv
    const client = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(client);

    var connect_ctx: u8 = 1;
    var send_ctx: u8 = 2;
    var recv_ctx: u8 = 3;

    _ = try loop.connect(client, server_addr, @ptrCast(&connect_ctx));

    var completions: [max_operations]Completion = undefined;

    // Wait for connect
    var connected = false;
    for (0..5) |_| {
        const results = try loop.tick(&completions);
        for (results) |c| {
            switch (c.result) {
                .connect => |r| {
                    try testing.expectEqual(@as(?anyerror, null), r.err);
                    connected = true;
                },
                else => {},
            }
        }
        if (connected) break;
    }
    try testing.expect(connected);

    // Send data
    const payload = "hello TCP io_uring";
    _ = try loop.tcpSend(client, payload, @ptrCast(&send_ctx));

    var sent = false;
    for (0..5) |_| {
        const results = try loop.tick(&completions);
        for (results) |c| {
            switch (c.result) {
                .tcp_send => |r| {
                    try testing.expect(r.bytes_sent > 0);
                    sent = true;
                },
                else => {},
            }
        }
        if (sent) break;
    }
    try testing.expect(sent);

    // Recv echo
    _ = try loop.tcpRecv(client, @ptrCast(&recv_ctx));

    var got_data = false;
    for (0..5) |_| {
        const results = try loop.tick(&completions);
        for (results) |c| {
            switch (c.result) {
                .tcp_recv => |r| {
                    try testing.expectEqual(@as(?anyerror, null), r.err);
                    try testing.expectEqualStrings(payload, r.data);
                    got_data = true;
                },
                else => {},
            }
        }
        if (got_data) break;
    }
    try testing.expect(got_data);

    thread.join();
}
