const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const na = @import("net_address.zig");
const sys = @import("sys.zig");
const log = std.log.scoped(.event_loop);

pub const max_operations = 64;

/// Read ops serve only the signalfd and wake eventfd — the buffer needs
/// room for a few packed signalfd_siginfo records (128 B each; signalfd
/// coalesces per signo, and excess records stay queued in the fd until
/// the op is re-armed), never packet data. UDP payloads ride the
/// multishot buffer ring instead.
const read_buf_size = 4 * @sizeOf(linux.signalfd_siginfo);

/// Buffer group for multishot UDP recvmsg. 256 buffers × (header + name +
/// payload) ≈ 1 MiB per worker. Sized to absorb short bursts without
/// ENOBUFS while the tick loop drains and releases buffers.
const multishot_group_id: u16 = 0;
const multishot_buf_count: u16 = 256;
const multishot_name_reserve: u32 = 28; // sockaddr_in6 max
const multishot_payload_max: u32 = 4096;
/// io_uring_recvmsg_out header + reserved name + payload.
const multishot_buf_size: u32 = @sizeOf(linux.io_uring_recvmsg_out) + multishot_name_reserve + multishot_payload_max;

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
    /// Non-null for multishot recv completions. Caller MUST call
    /// `releaseBuf(buf_id)` after processing `data`, or the buffer ring
    /// will starve and further recvs will fail with ENOBUFS.
    buf_id: ?u16 = null,
};

pub const AcceptResult = struct {
    fd: posix.fd_t,
    addr: na.Address,
    err: ?anyerror,
};

pub const ReadResult = struct {
    /// Aliases the op's slot buffer, which is recycled as soon as any new
    /// op is armed: consume `data` before arming ops (arming can claim
    /// this completion's freed slot even within the same batch).
    data: []const u8,
    err: ?anyerror,
};

// ── Operation slot ──────────────────────────────────────────────────────

const Slot = struct {
    context: *anyopaque,
    active: bool,
    /// Kernel-visible per-kind storage: io_uring reads/writes through
    /// pointers into the active variant while the op is in flight, so
    /// the variant must stay untouched (and the slot unmoved) until its
    /// CQE frees the slot.
    state: State,

    const State = union(enum) {
        /// Multishot recvmsg owns msghdr (kernel reads namelen/iovlen at
        /// submit time; payloads arrive via the buffer ring).
        recv_multi: posix.msghdr,
        /// accept owns the peer-address out-params the kernel fills.
        accept: struct { addr: na.PosixAddress, addr_len: posix.socklen_t },
        /// read owns a small buffer — signalfd/eventfd payloads only.
        read: [read_buf_size]u8,
    };

    fn init() Slot {
        return .{
            .context = undefined,
            .active = false,
            .state = .{ .recv_multi = undefined },
        };
    }
};

// ── EventLoop ───────────────────────────────────────────────────────────

/// Non-incremental buffer ring for multishot recvmsg. Each CQE consumes
/// one buffer fully; we reset and re-add it to the ring in `releaseBuf`.
/// (Zig std's BufferGroup hardcodes `.inc = true`, which is wrong for
/// per-packet consumption — the kernel would pack multiple messages
/// into the same buffer.)
const UdpBufRing = struct {
    br: *align(std.heap.page_size_min) linux.io_uring_buf_ring,
    buffers: []u8,
    buffer_size: u32,
    buffers_count: u16,
    group_id: u16,

    fn init(ring_fd: linux.fd_t, allocator: std.mem.Allocator) !UdpBufRing {
        const buffers = try allocator.alloc(u8, multishot_buf_size * multishot_buf_count);
        errdefer allocator.free(buffers);
        const br = try linux.IoUring.setup_buf_ring(ring_fd, multishot_buf_count, multishot_group_id, .{ .inc = false });
        linux.IoUring.buf_ring_init(br);
        const mask = linux.IoUring.buf_ring_mask(multishot_buf_count);
        var i: u16 = 0;
        while (i < multishot_buf_count) : (i += 1) {
            const pos: usize = @as(usize, multishot_buf_size) * i;
            const buf = buffers[pos .. pos + multishot_buf_size];
            linux.IoUring.buf_ring_add(br, buf, i, mask, i);
        }
        linux.IoUring.buf_ring_advance(br, multishot_buf_count);
        return .{
            .br = br,
            .buffers = buffers,
            .buffer_size = multishot_buf_size,
            .buffers_count = multishot_buf_count,
            .group_id = multishot_group_id,
        };
    }

    fn deinit(self: *UdpBufRing, ring_fd: linux.fd_t, allocator: std.mem.Allocator) void {
        linux.IoUring.free_buf_ring(ring_fd, self.br, self.buffers_count, self.group_id);
        allocator.free(self.buffers);
    }

    fn bufferAt(self: *const UdpBufRing, buffer_id: u16) []u8 {
        const pos: usize = @as(usize, self.buffer_size) * buffer_id;
        return self.buffers[pos .. pos + self.buffer_size];
    }

    fn release(self: *UdpBufRing, buffer_id: u16) void {
        const mask = linux.IoUring.buf_ring_mask(self.buffers_count);
        linux.IoUring.buf_ring_add(self.br, self.bufferAt(buffer_id), buffer_id, mask, 0);
        linux.IoUring.buf_ring_advance(self.br, 1);
    }
};

pub const EventLoop = struct {
    allocator: std.mem.Allocator,
    ring: linux.IoUring,
    slots: [max_operations]Slot,
    free_list: [max_operations]OperationId,
    free_count: u16,
    /// Buffer ring backing multishot recvmsg. Required — needs kernel
    /// 5.19+ for `IORING_REGISTER_PBUF_RING`.
    udp_buf_ring: UdpBufRing,

    pub fn create(allocator: std.mem.Allocator) !*EventLoop {
        const self = try allocator.create(EventLoop);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        var params = std.mem.zeroes(linux.io_uring_params);
        // COOP_TASKRUN: skip kernel→user IPI when the task is already running
        //   (each worker owns its ring; CQEs are processed at next
        //   submit_and_wait, no urgent preemption needed). Kernel 5.18+.
        // SINGLE_ISSUER: only this thread submits SQEs to this ring; enables
        //   the kernel's lock-free SQ optimizations. Kernel 6.0+.
        // DEFER_TASKRUN: run task_work only at io_uring_enter (submit_and_wait
        //   in our tick loop). Without this, every non-io_uring syscall
        //   (sendto, fcntl, etc.) drains task_work and breaks completion
        //   batching. Requires SINGLE_ISSUER. Kernel 6.1+.
        params.flags = linux.IORING_SETUP_CQSIZE |
            linux.IORING_SETUP_COOP_TASKRUN |
            linux.IORING_SETUP_SINGLE_ISSUER |
            linux.IORING_SETUP_DEFER_TASKRUN;
        params.cq_entries = max_operations * 4;
        self.ring = linux.IoUring.init_params(max_operations, &params) catch |err| {
            log.err(
                "failed to create io_uring ({s}); hark requires Linux 6.1+",
                .{@errorName(err)},
            );
            return err;
        };
        errdefer self.ring.deinit();
        std.debug.assert(params.features & linux.IORING_FEAT_NODROP != 0);
        self.free_count = max_operations;
        for (0..max_operations) |i| {
            self.slots[i] = Slot.init();
            self.free_list[i] = @intCast(max_operations - 1 - i); // stack order
        }
        self.udp_buf_ring = UdpBufRing.init(self.ring.fd, allocator) catch |err| {
            log.err(
                "failed to register io_uring buffer ring ({s}); hark requires Linux 6.1+",
                .{@errorName(err)},
            );
            return err;
        };
        return self;
    }

    pub fn destroy(self: *EventLoop) void {
        const allocator = self.allocator;
        self.udp_buf_ring.deinit(self.ring.fd, allocator);
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

    fn initOp(self: *EventLoop, state: Slot.State, context: *anyopaque) !OperationId {
        const id = self.allocSlot() orelse return error.TooManyOperations;
        const slot = &self.slots[id];
        slot.state = state;
        slot.context = context;
        slot.active = true;
        return id;
    }

    /// Arm a multishot recvmsg on `fd`. One SQE produces CQEs for every
    /// inbound packet until the kernel stops the op (e.g. ENOBUFS).
    /// Callers receive a `RecvResult` with `buf_id` set and MUST call
    /// `releaseBuf` after processing the payload.
    pub fn recvFromMulti(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        // msghdr configures the kernel's output layout. iov is ignored
        // (buffer selected from the ring). namelen/controllen tell the
        // kernel how many bytes to reserve for sender address / control
        // msgs; we reserve multishot_name_reserve (sockaddr_in6) and 0
        // control since DNS doesn't need CMSG.
        const id = try self.initOp(.{ .recv_multi = .{
            .name = null,
            .namelen = multishot_name_reserve,
            .iov = undefined,
            .iovlen = 0,
            .control = null,
            .controllen = 0,
            .flags = 0,
        } }, context);
        errdefer self.freeSlot(id);

        var sqe = try self.ring.get_sqe();
        sqe.prep_recvmsg(fd, &self.slots[id].state.recv_multi, 0);
        sqe.ioprio |= linux.IORING_RECV_MULTISHOT;
        sqe.flags |= linux.IOSQE_BUFFER_SELECT;
        sqe.buf_index = self.udp_buf_ring.group_id;
        sqe.user_data = id;
        return id;
    }

    /// Release a multishot recv buffer back to the buffer ring so the
    /// kernel can reuse it for a subsequent packet.
    pub fn releaseBuf(self: *EventLoop, buf_id: u16) void {
        self.udp_buf_ring.release(buf_id);
    }

    /// True iff `op_id` refers to a multishot op whose slot the kernel
    /// still holds (IORING_CQE_F_MORE was set on the most recent CQE).
    /// Callers use this after processing a CQE to decide whether to
    /// re-arm the op.
    pub fn stillArmed(self: *const EventLoop, op_id: ?OperationId) bool {
        const id = op_id orelse return false;
        const slot = &self.slots[id];
        return slot.active and slot.state == .recv_multi;
    }

    pub fn accept(self: *EventLoop, listen_fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = try self.initOp(.{ .accept = .{
            .addr = std.mem.zeroes(na.PosixAddress),
            .addr_len = @sizeOf(na.PosixAddress),
        } }, context);
        errdefer self.freeSlot(id);
        const a = &self.slots[id].state.accept;

        var sqe = try self.ring.get_sqe();
        sqe.prep_accept(listen_fd, @ptrCast(&a.addr.any), &a.addr_len, 0);
        sqe.user_data = id;
        return id;
    }

    pub fn read(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = try self.initOp(.{ .read = undefined }, context);
        errdefer self.freeSlot(id);
        var sqe = try self.ring.get_sqe();
        sqe.prep_read(fd, &self.slots[id].state.read, 0);
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
        return cqe.res == -@as(i32, @intCast(@backingInt(linux.E.CANCELED)));
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

            // Multishot ops keep the slot alive as long as F_MORE is set;
            // the kernel will produce more CQEs for the same user_data.
            var free_after = true;

            switch (slot.state) {
                .recv_multi => {
                    // When F_MORE is clear, the kernel has terminated the
                    // multishot (e.g. on ENOBUFS); the slot must be freed
                    // so the caller can re-arm it.
                    free_after = cqe.flags & linux.IORING_CQE_F_MORE == 0;
                    if (parseMultishotRecv(self, cqe)) |parsed| {
                        completion.result = .{ .recv = .{
                            .data = parsed.payload,
                            .addr = parsed.addr,
                            .err = null,
                            .buf_id = parsed.buf_id,
                        } };
                    } else |err| {
                        completion.result = .{ .recv = .{
                            .data = &.{},
                            .addr = na.initIp4(.{ 0, 0, 0, 0 }, 0),
                            .err = err,
                        } };
                        // io_uring clears F_MORE on error CQEs (see
                        // io_req_set_res in kernel/io_uring), so
                        // free_after is already true on the ENOBUFS /
                        // CANCELED paths. We force it here for the
                        // defensive in-process parse-failure paths too:
                        // a malformed header would otherwise leave the
                        // slot active with no way to recover it.
                        free_after = true;
                    }
                },
                .accept => |*a| {
                    if (cqe.res >= 0) {
                        completion.result = .{ .accept = .{
                            .fd = @intCast(cqe.res),
                            .addr = na.fromSockaddr(&a.addr),
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
                .read => |*rbuf| {
                    if (cqe.res > 0) {
                        const len: usize = @intCast(cqe.res);
                        completion.result = .{ .read = .{
                            .data = rbuf[0..len],
                            .err = null,
                        } };
                    } else if (cqe.res == 0) {
                        completion.result = .{ .read = .{
                            .data = &.{},
                            .err = error.EndOfFile,
                        } };
                    } else if (isCancelled(cqe)) {
                        completion.result = .{ .read = .{
                            .data = &.{},
                            .err = error.Cancelled,
                        } };
                    } else {
                        completion.result = .{ .read = .{
                            .data = &.{},
                            .err = error.ReadFailed,
                        } };
                    }
                },
            }

            if (free_after) self.freeSlot(id);
            out += 1;
        }

        return buf[0..out];
    }

    const MultishotParsed = struct {
        addr: na.Address,
        payload: []const u8,
        buf_id: u16,
    };

    /// Parse a multishot recvmsg CQE: extract the selected buffer,
    /// destructure the `io_uring_recvmsg_out` header, and return the
    /// sender address + payload slice (both aliased into the buffer).
    fn parseMultishotRecv(self: *EventLoop, cqe: linux.io_uring_cqe) !MultishotParsed {
        const ring = &self.udp_buf_ring;
        if (cqe.res < 0) {
            const errno: linux.E = @fromBackingInt(@intCast(@as(u31, @intCast(-cqe.res))));
            return switch (errno) {
                .NOBUFS => error.NoBuffers,
                .CANCELED => error.Cancelled,
                else => error.RecvFailed,
            };
        }
        const buf_id = try cqe.buffer_id();
        // Past this point the kernel has claimed a buffer; any parse
        // failure must return it to the ring, or malformed-packet
        // bursts will starve the ring to ENOBUFS.
        errdefer ring.release(buf_id);

        const used_len: usize = @intCast(cqe.res);
        const buf = ring.bufferAt(buf_id)[0..used_len];

        // Kernel writes: [io_uring_recvmsg_out][name (reserved)][control][payload]
        if (buf.len < @sizeOf(linux.io_uring_recvmsg_out)) return error.RecvFailed;
        const out: *const linux.io_uring_recvmsg_out = @ptrCast(@alignCast(buf.ptr));
        const name_off = @sizeOf(linux.io_uring_recvmsg_out);
        const payload_off = name_off + multishot_name_reserve;
        if (out.namelen == 0 or out.namelen > multishot_name_reserve) return error.RecvFailed;
        if (payload_off + out.payloadlen > buf.len) return error.RecvFailed;

        // Reinterpret the name bytes as a sockaddr — same storage as
        // `na.PosixAddress`, populated by the kernel.
        const addr_ptr: *const na.PosixAddress = @ptrCast(@alignCast(buf.ptr + name_off));
        return .{
            .addr = na.fromSockaddr(addr_ptr),
            .payload = buf[payload_off..][0..out.payloadlen],
            .buf_id = buf_id,
        };
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

test "Slot stays lean — read ops must not drag packet-sized buffers back in" {
    // The pre-union Slot carried a 4 KiB recv_buf in every slot whether
    // the op needed it or not (~256 KiB/worker dead). Budget: the small
    // read buffer plus header change. If this fires, some variant grew a
    // packet-sized payload — packets belong in the multishot buffer ring.
    try testing.expect(@sizeOf(Slot) <= read_buf_size + 64);
}

test "EventLoop create/destroy" {
    const loop = try createTestLoop();
    defer loop.destroy();

    try testing.expectEqual(@as(u16, max_operations), loop.free_count);
}

test "EventLoop recvFromMulti receives multiple packets on one SQE" {
    const loop = try createTestLoop();
    defer loop.destroy();

    const sock = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(sock);
    const bind_na = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var bind_pa: na.PosixAddress = undefined;
    const bind_len = na.toSockaddr(&bind_na, &bind_pa);
    try sys.bind(sock, &bind_pa.any, bind_len);
    const server_addr = try na.getSockName(sock);

    var ctx: u8 = 1;
    const op_id = try loop.recvFromMulti(sock, @ptrCast(&ctx));

    // Send 3 packets from a separate thread — one multishot SQE should
    // produce 3 CQEs without re-arming.
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
        }
        // After the first CQE, the SQE should still be armed (F_MORE);
        // slot stays active with no re-registration.
        if (received > 0 and loop.stillArmed(op_id)) still_armed_seen = true;
        if (received == payloads.len) break;
    }

    thread.join();
    try testing.expectEqual(payloads.len, received);
    try testing.expect(still_armed_seen);

    // Tear down the multishot SQE before destroy so the kernel doesn't
    // keep it armed against a torn-down buffer ring.
    try loop.cancel(op_id);
    loop.flush();
}

test "EventLoop cancel pending recvFromMulti" {
    const loop = try createTestLoop();
    defer loop.destroy();

    const sock = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(sock);
    const bind_na = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    var bind_pa: na.PosixAddress = undefined;
    const bind_len = na.toSockaddr(&bind_na, &bind_pa);
    try sys.bind(sock, &bind_pa.any, bind_len);

    var ctx: u8 = 99;
    const recv_id = try loop.recvFromMulti(sock, @ptrCast(&ctx));
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
