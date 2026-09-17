//! io_uring backend: completion-based, multishot UDP recv over a provided
//! buffer ring. Linux 6.1+.
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
const multishot_payload_max = event_loop.multishot_payload_max;
const no_addr = event_loop.no_addr;

const Uring = @This();

ring: linux.IoUring,
/// Needs kernel 5.19+ for `IORING_REGISTER_PBUF_RING`.
udp_buf_ring: UdpBufRing,

/// Buffer group for multishot UDP recvmsg. 256 buffers × (header + name +
/// payload) ≈ 1 MiB per worker. Sized to absorb short bursts without
/// ENOBUFS while the tick loop drains and releases buffers.
const multishot_group_id: u16 = 0;
const multishot_buf_count: u16 = 256;
const multishot_name_reserve: u32 = 28; // sockaddr_in6 max
/// io_uring_recvmsg_out header + reserved name + payload.
const multishot_buf_size: u32 = @sizeOf(linux.io_uring_recvmsg_out) + multishot_name_reserve + multishot_payload_max;

/// PermissionDenied and SystemOutdated come back unlogged: the caller
/// decides whether they mean "fall back".
pub fn init(allocator: std.mem.Allocator) !Uring {
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
    // R_DISABLED: the issuer is whoever calls `enable`, not the creator
    //   — rings are built on the main thread while it still holds
    //   privilege, then handed to their workers.
    params.flags = linux.IORING_SETUP_CQSIZE |
        linux.IORING_SETUP_COOP_TASKRUN |
        linux.IORING_SETUP_SINGLE_ISSUER |
        linux.IORING_SETUP_DEFER_TASKRUN |
        linux.IORING_SETUP_R_DISABLED;
    params.cq_entries = max_operations * 4;
    var ring = linux.IoUring.init_params(max_operations, &params) catch |err| switch (err) {
        error.PermissionDenied, error.SystemOutdated => return err,
        else => {
            log.err("failed to create io_uring ({s}); hark requires Linux 6.1+", .{@errorName(err)});
            return err;
        },
    };
    errdefer ring.deinit();
    std.debug.assert(params.features & linux.IORING_FEAT_NODROP != 0);
    var udp_buf_ring = UdpBufRing.init(ring.fd, allocator) catch |err| {
        log.err("failed to register io_uring buffer ring ({s}); hark requires Linux 6.1+", .{@errorName(err)});
        return err;
    };
    errdefer udp_buf_ring.deinit(allocator);
    try restrict(ring.fd);
    return .{ .ring = ring, .udp_buf_ring = udp_buf_ring };
}

pub fn deinit(u: *Uring, allocator: std.mem.Allocator) void {
    u.udp_buf_ring.deinit(allocator);
    u.ring.deinit();
}

/// Irreversible from `enable`. std's io_uring_restriction is 24 B, the
/// kernel's 16, hence the local struct.
fn restrict(fd: linux.fd_t) !void {
    const R = extern struct { opcode: linux.IORING_RESTRICTION, arg: u8, resv: u8 = 0, resv2: [3]u32 = .{ 0, 0, 0 } };
    const rs = [_]R{
        .{ .opcode = .SQE_OP, .arg = @backingInt(linux.IORING_OP.RECVMSG) },
        .{ .opcode = .SQE_OP, .arg = @backingInt(linux.IORING_OP.ACCEPT) },
        .{ .opcode = .SQE_OP, .arg = @backingInt(linux.IORING_OP.READ) },
        .{ .opcode = .SQE_OP, .arg = @backingInt(linux.IORING_OP.TIMEOUT) },
        .{ .opcode = .SQE_OP, .arg = @backingInt(linux.IORING_OP.ASYNC_CANCEL) },
        .{ .opcode = .SQE_FLAGS_ALLOWED, .arg = linux.IOSQE_BUFFER_SELECT },
        // Activates the register allowlist (tracked apart from SQE ops on
        // 7.0+) permitting only ENABLE_RINGS, which EBADFDs post-enable.
        .{ .opcode = .REGISTER_OP, .arg = @backingInt(linux.IORING_REGISTER.REGISTER_ENABLE_RINGS) },
    };
    const rc = linux.io_uring_register(fd, .REGISTER_RESTRICTIONS, &rs, rs.len);
    if (linux.errno(rc) != .SUCCESS) {
        log.err("failed to restrict io_uring ({t})", .{linux.errno(rc)});
        return error.RestrictFailed;
    }
}

pub fn enable(u: *Uring) !void {
    const rc = linux.io_uring_register(u.ring.fd, .REGISTER_ENABLE_RINGS, null, 0);
    if (linux.errno(rc) != .SUCCESS) return error.EnableRingsFailed;
}

/// `slot` stays put until the op completes: the kernel writes through
/// pointers into its state.
pub fn arm(u: *Uring, slot: *Slot, id: OperationId) !void {
    const s = try u.ring.get_sqe();
    switch (slot.state) {
        .recv_multi => |*msg| {
            // msghdr configures the kernel's output layout. iov is ignored
            // (buffer selected from the ring). namelen/controllen tell the
            // kernel how many bytes to reserve for sender address / control
            // msgs; we reserve multishot_name_reserve (sockaddr_in6) and 0
            // control since DNS doesn't need CMSG.
            msg.* = .{
                .name = null,
                .namelen = multishot_name_reserve,
                .iov = undefined,
                .iovlen = 0,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
            s.prep_recvmsg(slot.fd, msg, 0);
            s.ioprio |= linux.IORING_RECV_MULTISHOT;
            s.flags |= linux.IOSQE_BUFFER_SELECT;
            s.buf_index = u.udp_buf_ring.group_id;
        },
        .accept => |*a| s.prep_accept(slot.fd, @ptrCast(&a.addr.any), &a.addr_len, 0),
        .read => |*r| s.prep_read(slot.fd, r, 0),
        .stream => |b| s.prep_read(slot.fd, b, 0),
        .timer => |*t| s.prep_timeout(&t.ts, 0, 0),
    }
    // std's `prep_*` rewrite the whole SQE: tag it with `id` after.
    s.user_data = id;
}

pub fn release(u: *Uring, buf_id: u16) void {
    u.udp_buf_ring.release(buf_id);
}

/// Test-only: the one way to force a multishot termination on demand.
/// Production never cancels; the process exits with its ops armed.
fn cancel(u: *Uring, target_id: OperationId) !void {
    var s = try u.ring.get_sqe();
    s.prep_cancel(@as(u64, target_id), 0);
    s.user_data = std.math.maxInt(u64);
}

pub fn tick(u: *Uring, loop: *EventLoop, buf: *[max_operations]Completion) ![]Completion {
    _ = try u.ring.submit_and_wait(1);
    var cqes: [max_operations]linux.io_uring_cqe = undefined;
    const count = try u.ring.copy_cqes(&cqes, 0);

    var out: usize = 0;
    for (cqes[0..count]) |cqe| {
        // The test-only cancel SQE carries a sentinel user_data.
        if (cqe.user_data == std.math.maxInt(u64)) continue;

        const id: OperationId = @intCast(cqe.user_data);
        const slot = &loop.slots[id];
        if (!slot.active) continue;

        if (slot.state != .recv_multi) {
            buf[out] = loop.finish(id, cqe.res);
            out += 1;
            continue;
        }

        // Multishot ops keep the slot alive as long as F_MORE is set;
        // the kernel will produce more CQEs for the same user_data.
        // When it is clear the kernel has terminated the multishot (e.g.
        // on ENOBUFS); the slot must be freed so the caller can re-arm it.
        const terminated = cqe.flags & linux.IORING_CQE_F_MORE == 0;
        buf[out] = .{ .context = slot.context, .terminated = terminated, .result = .{ .recv = if (u.parseMultishotRecv(cqe)) |parsed|
            .{ .data = parsed.payload, .addr = parsed.addr, .err = null, .buf_id = parsed.buf_id }
        else |err|
            .{ .data = &.{}, .addr = no_addr, .err = err } } };
        if (terminated) loop.freeSlot(id);
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
fn parseMultishotRecv(u: *Uring, cqe: linux.io_uring_cqe) !MultishotParsed {
    const ring = &u.udp_buf_ring;
    if (cqe.res < 0) {
        const errno: linux.E = @fromBackingInt(@intCast(@as(u31, @intCast(-cqe.res))));
        return switch (errno) {
            .NOBUFS => error.NoBuffers,
            else => error.RecvFailed,
        };
    }
    const buf_id = try cqe.buffer_id();
    if (buf_id >= ring.buffers_count) return error.RecvFailed;
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
    if (out.flags & linux.MSG.TRUNC != 0) return error.RecvFailed;

    // Reinterpret the name bytes as a sockaddr — same storage as
    // `na.PosixAddress`, populated by the kernel.
    const addr_ptr: *const na.PosixAddress = @ptrCast(@alignCast(buf.ptr + name_off));
    return .{
        .addr = na.fromSockaddr(addr_ptr),
        .payload = buf[payload_off..][0..out.payloadlen],
        .buf_id = buf_id,
    };
}

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

    fn deinit(self: *UdpBufRing, allocator: std.mem.Allocator) void {
        // Not std.free_buf_ring: its unregister is denied post-restriction
        // and unexpectedErrno dumps a trace in Debug. Ring teardown frees it.
        var mmap: []align(std.heap.page_size_min) u8 = undefined;
        mmap.ptr = @ptrCast(self.br);
        mmap.len = self.buffers_count * @sizeOf(linux.io_uring_buf);
        posix.munmap(mmap);
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

test "ring refuses opcodes outside the allowlist" {
    const loop = try event_loop.createTestLoop(.io_uring);
    defer event_loop.destroyTestLoop(loop);
    const ring = &loop.backend.io_uring.ring;

    var s = try ring.get_sqe();
    s.prep_nop();
    s.user_data = 7;
    _ = try ring.submit_and_wait(1);
    var cqes: [1]linux.io_uring_cqe = undefined;
    try testing.expectEqual(@as(u32, 1), try ring.copy_cqes(&cqes, 1));
    try testing.expectEqual(@as(u64, 7), cqes[0].user_data);
    try testing.expectEqual(@as(i32, -@as(i32, @backingInt(linux.E.ACCES))), cqes[0].res);
    const rc = linux.io_uring_register(ring.fd, .REGISTER_PROBE, null, 0);
    try testing.expectEqual(linux.E.ACCES, linux.errno(rc));
}

test "termination is reported per-CQE, not by asking the recycled slot table" {
    // Two multishot listeners terminate in one batch — flood-triggerable for
    // real via ENOBUFS on the shared buffer ring; here via cancel. reap frees
    // both slots before the caller sees either completion, and the free list
    // is LIFO, so re-arming the first listener mid-batch hands it the id the
    // second just released.
    //
    // The old code then asked the slot table "is listener 2 still armed?",
    // saw listener 1's fresh op sitting in that id, and answered yes — so
    // listener 2 was never re-armed, and because its op id stayed non-null
    // the repair loop skipped it too. A permanently deaf UDP listener, with
    // SO_REUSEPORT still hashing traffic to it, silent until restart.
    const loop = try event_loop.createTestLoop(.io_uring);
    defer event_loop.destroyTestLoop(loop);

    var socks: [2]posix.fd_t = undefined;
    var ctxs: [2]u8 = .{ 1, 2 };
    var ops: [2]?OperationId = undefined;
    for (&socks, 0..) |*s, i| {
        s.* = try event_loop.bindTestUdp();
        ops[i] = try loop.recvFromMulti(s.*, @ptrCast(&ctxs[i]));
    }
    defer for (socks) |s| sys.close(s);

    for (ops) |op| try loop.backend.io_uring.cancel(op.?);

    var completions: [max_operations]Completion = undefined;
    var terminations: usize = 0;
    var rearmed_mid_batch = false;

    for (0..5) |_| {
        const results = try loop.tick(&completions);
        for (results) |c| {
            if (c.result != .recv) continue;
            // Every cancelled multishot must report termination. The second
            // one in the batch is the one the ABA used to swallow.
            try testing.expect(c.terminated);
            terminations += 1;
            // Re-arm into the just-freed id while the rest of the batch is
            // still unread — this is the step that used to corrupt the answer
            // for everyone after it.
            if (!rearmed_mid_batch) {
                rearmed_mid_batch = true;
                const idx: usize = @as(*u8, @ptrCast(@alignCast(c.context))).* - 1;
                ops[idx] = try loop.recvFromMulti(socks[idx], @ptrCast(&ctxs[idx]));
            }
        }
        if (terminations >= 2) break;
    }

    try testing.expectEqual(@as(usize, 2), terminations);
    try testing.expect(rearmed_mid_batch);
}
