const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const na = @import("net_address.zig");
const sys = @import("sys.zig");
const log = std.log.scoped(.event_loop);

pub const max_operations = 64;

/// Read ops serve only the signalfd — the buffer needs
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
pub const multishot_payload_max: u32 = 4096;
/// io_uring_recvmsg_out header + reserved name + payload.
const multishot_buf_size: u32 = @sizeOf(linux.io_uring_recvmsg_out) + multishot_name_reserve + multishot_payload_max;

const no_addr = na.initIp4(.{ 0, 0, 0, 0 }, 0);

pub const OperationId = u16;

pub const Backend = enum { io_uring, epoll };

pub const Completion = struct {
    context: *anyopaque,
    result: Result,
    /// True when the kernel finished with this operation and its slot was
    /// freed — for multishot, when IORING_CQE_F_MORE was clear. The caller
    /// must re-arm iff this is set.
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
    /// Non-null for multishot recv completions. Caller MUST call
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
    /// clobbered a not-yet-consumed payload: an accept CQE reaped ahead
    /// of a signal CQE zeroed the siginfo and turned stats into shutdown.)
    buf: [read_buf_size]u8,
    len: usize,
    err: ?anyerror,

    pub fn data(self: *const ReadResult) []const u8 {
        return self.buf[0..self.len];
    }
};

const Slot = struct {
    context: *anyopaque,
    active: bool,
    /// What epoll watches; io_uring carries it in the SQE.
    fd: posix.fd_t,
    /// io_uring writes through pointers into the active variant, so it and
    /// the slot stay put until the op completes.
    state: State,

    const State = union(enum) {
        /// Multishot recvmsg owns msghdr (kernel reads namelen/iovlen at
        /// submit time; payloads arrive via the buffer ring).
        recv_multi: posix.msghdr,
        /// accept owns the peer-address out-params the kernel fills.
        accept: struct { addr: na.PosixAddress, addr_len: posix.socklen_t },
        /// read owns a small buffer — signalfd/eventfd payloads only.
        read: [read_buf_size]u8,
        /// Caller's buffer outlives the op.
        stream: []u8,
        timer: struct { ts: linux.kernel_timespec, deadline_ns: i64 },
    };
};

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

/// Readiness fallback where io_uring is refused: an event runs the syscall
/// the SQE would have, a spurious wake re-arms silently.
const Epoll = struct {
    fd: posix.fd_t,
    /// `max_operations` buffers suffice: a tick's recvs are released
    /// before the next.
    buffers: []u8,
    free: [max_operations]u16,
    free_count: u16,

    fn bufferAt(self: *const Epoll, buffer_id: u16) []u8 {
        return self.buffers[@as(usize, buffer_id) * multishot_payload_max ..][0..multishot_payload_max];
    }

    fn release(self: *Epoll, buffer_id: u16) void {
        self.free[self.free_count] = buffer_id;
        self.free_count += 1;
    }

    /// MOD first: steady-state re-arms hit an fd already in the set.
    fn watch(self: *Epoll, fd: posix.fd_t, events: u32, id: OperationId) !void {
        var ev: linux.epoll_event = .{ .events = events, .data = .{ .u64 = id } };
        if (linux.errno(linux.epoll_ctl(self.fd, linux.EPOLL.CTL_MOD, fd, &ev)) == .SUCCESS) return;
        if (linux.errno(linux.epoll_ctl(self.fd, linux.EPOLL.CTL_ADD, fd, &ev)) != .SUCCESS) return error.EpollCtlFailed;
    }
};

pub const EventLoop = struct {
    allocator: std.mem.Allocator,
    slots: [max_operations]Slot,
    free_list: [max_operations]OperationId,
    free_count: u16,
    backend: union(Backend) {
        io_uring: struct {
            ring: linux.IoUring,
            /// Needs kernel 5.19+ for `IORING_REGISTER_PBUF_RING`.
            udp_buf_ring: UdpBufRing,
        },
        epoll: Epoll,
    },

    /// Epoll only when preferred or the kernel refuses io_uring outright:
    /// a misconfigured ring is fatal, not a sandbox.
    pub fn create(allocator: std.mem.Allocator, prefer: Backend) !*EventLoop {
        const self = try allocator.create(EventLoop);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.free_count = max_operations;
        for (0..max_operations) |i| {
            self.slots[i] = .{ .context = undefined, .active = false, .fd = -1, .state = undefined };
            self.free_list[i] = @intCast(max_operations - 1 - i); // stack order
        }
        if (prefer == .io_uring) {
            if (self.initUring()) return self else |err| switch (err) {
                error.PermissionDenied => log.warn("io_uring refused (EPERM: seccomp, container runtime or kernel.io_uring_disabled); using epoll", .{}),
                error.SystemOutdated => log.warn("io_uring unavailable (ENOSYS: kernel built without it); using epoll", .{}),
                else => return err,
            }
        }
        try self.initEpoll();
        return self;
    }

    fn initUring(self: *EventLoop) !void {
        self.backend = .{ .io_uring = undefined };
        const u = &self.backend.io_uring;
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
        u.ring = linux.IoUring.init_params(max_operations, &params) catch |err| switch (err) {
            error.PermissionDenied, error.SystemOutdated => return err,
            else => {
                log.err("failed to create io_uring ({s}); hark requires Linux 6.1+", .{@errorName(err)});
                return err;
            },
        };
        errdefer u.ring.deinit();
        std.debug.assert(params.features & linux.IORING_FEAT_NODROP != 0);
        u.udp_buf_ring = UdpBufRing.init(u.ring.fd, self.allocator) catch |err| {
            log.err("failed to register io_uring buffer ring ({s}); hark requires Linux 6.1+", .{@errorName(err)});
            return err;
        };
        errdefer u.udp_buf_ring.deinit(self.allocator);
        try restrict(u.ring.fd);
    }

    fn initEpoll(self: *EventLoop) !void {
        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) {
            log.err("failed to create epoll instance ({t})", .{linux.errno(rc)});
            return error.EpollCreateFailed;
        }
        const fd: posix.fd_t = @intCast(rc);
        errdefer sys.close(fd);
        self.backend = .{ .epoll = .{
            .fd = fd,
            .buffers = try self.allocator.alloc(u8, @as(usize, max_operations) * multishot_payload_max),
            .free = undefined,
            .free_count = max_operations,
        } };
        for (&self.backend.epoll.free, 0..) |*b, i| b.* = @intCast(i);
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

    /// Binds a ring to the calling thread; must precede the first submit.
    pub fn enable(self: *EventLoop) !void {
        switch (self.backend) {
            .io_uring => |*u| {
                const rc = linux.io_uring_register(u.ring.fd, .REGISTER_ENABLE_RINGS, null, 0);
                if (linux.errno(rc) != .SUCCESS) return error.EnableRingsFailed;
            },
            .epoll => {},
        }
    }

    pub fn destroy(self: *EventLoop) void {
        const allocator = self.allocator;
        switch (self.backend) {
            .io_uring => |*u| {
                u.udp_buf_ring.deinit(allocator);
                u.ring.deinit();
            },
            .epoll => |*e| {
                sys.close(e.fd);
                allocator.free(e.buffers);
            },
        }
        allocator.destroy(self);
    }

    fn freeSlot(self: *EventLoop, id: OperationId) void {
        self.slots[id].active = false;
        self.free_list[self.free_count] = id;
        self.free_count += 1;
    }

    fn initOp(self: *EventLoop, fd: posix.fd_t, state: Slot.State, context: *anyopaque) !OperationId {
        if (self.free_count == 0) return error.TooManyOperations;
        self.free_count -= 1;
        const id = self.free_list[self.free_count];
        self.slots[id] = .{ .context = context, .active = true, .fd = fd, .state = state };
        return id;
    }

    /// std's `prep_*` rewrite the whole SQE: tag it with `id` after.
    fn sqe(self: *EventLoop) !*linux.io_uring_sqe {
        return self.backend.io_uring.ring.get_sqe();
    }

    /// One arm yields a completion per datagram until the op terminates
    /// (io_uring only, e.g. ENOBUFS). Callers MUST `releaseBuf` each `buf_id`.
    pub fn recvFromMulti(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        // msghdr configures the kernel's output layout. iov is ignored
        // (buffer selected from the ring). namelen/controllen tell the
        // kernel how many bytes to reserve for sender address / control
        // msgs; we reserve multishot_name_reserve (sockaddr_in6) and 0
        // control since DNS doesn't need CMSG.
        const id = try self.initOp(fd, .{ .recv_multi = .{
            .name = null,
            .namelen = multishot_name_reserve,
            .iov = undefined,
            .iovlen = 0,
            .control = null,
            .controllen = 0,
            .flags = 0,
        } }, context);
        errdefer self.freeSlot(id);
        switch (self.backend) {
            .io_uring => |*u| {
                const s = try self.sqe();
                s.prep_recvmsg(fd, &self.slots[id].state.recv_multi, 0);
                s.ioprio |= linux.IORING_RECV_MULTISHOT;
                s.flags |= linux.IOSQE_BUFFER_SELECT;
                s.buf_index = u.udp_buf_ring.group_id;
                s.user_data = id;
            },
            .epoll => |*e| try e.watch(fd, linux.EPOLL.IN, id),
        }
        return id;
    }

    pub fn releaseBuf(self: *EventLoop, buf_id: u16) void {
        switch (self.backend) {
            .io_uring => |*u| u.udp_buf_ring.release(buf_id),
            .epoll => |*e| e.release(buf_id),
        }
    }

    /// `listen_fd` must be non-blocking: a reset can revoke epoll's readiness.
    pub fn accept(self: *EventLoop, listen_fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = try self.initOp(listen_fd, .{ .accept = .{
            .addr = std.mem.zeroes(na.PosixAddress),
            .addr_len = @sizeOf(na.PosixAddress),
        } }, context);
        errdefer self.freeSlot(id);
        switch (self.backend) {
            .io_uring => {
                const a = &self.slots[id].state.accept;
                const s = try self.sqe();
                s.prep_accept(listen_fd, @ptrCast(&a.addr.any), &a.addr_len, 0);
                s.user_data = id;
            },
            .epoll => |*e| try e.watch(listen_fd, linux.EPOLL.IN | linux.EPOLL.ONESHOT, id),
        }
        return id;
    }

    /// `fd` must be non-blocking, as for `accept`.
    pub fn read(self: *EventLoop, fd: posix.fd_t, context: *anyopaque) !OperationId {
        const id = try self.initOp(fd, .{ .read = undefined }, context);
        errdefer self.freeSlot(id);
        switch (self.backend) {
            .io_uring => {
                const s = try self.sqe();
                s.prep_read(fd, &self.slots[id].state.read, 0);
                s.user_data = id;
            },
            .epoll => |*e| try e.watch(fd, linux.EPOLL.IN | linux.EPOLL.ONESHOT, id),
        }
        return id;
    }

    pub fn readStream(self: *EventLoop, fd: posix.fd_t, buf: []u8, context: *anyopaque) !OperationId {
        const id = try self.initOp(fd, .{ .stream = buf }, context);
        errdefer self.freeSlot(id);
        switch (self.backend) {
            .io_uring => {
                const s = try self.sqe();
                s.prep_read(fd, buf, 0);
                s.user_data = id;
            },
            .epoll => |*e| try e.watch(fd, linux.EPOLL.IN | linux.EPOLL.ONESHOT, id),
        }
        return id;
    }

    pub fn timer(self: *EventLoop, ms: u32, context: *anyopaque) !OperationId {
        const id = try self.initOp(-1, .{ .timer = .{
            .ts = .{ .sec = ms / 1000, .nsec = @as(i64, ms % 1000) * std.time.ns_per_ms },
            .deadline_ns = nowNs() + @as(i64, ms) * std.time.ns_per_ms,
        } }, context);
        errdefer self.freeSlot(id);
        switch (self.backend) {
            .io_uring => {
                const s = try self.sqe();
                s.prep_timeout(&self.slots[id].state.timer.ts, 0, 0);
                s.user_data = id;
            },
            .epoll => {},
        }
        return id;
    }

    /// Test-only: the one way to force a multishot termination on demand.
    /// Production never cancels; the process exits with its ops armed.
    /// io_uring only — epoll's multishot cannot terminate.
    fn cancel(self: *EventLoop, target_id: OperationId) !void {
        var s = try self.backend.io_uring.ring.get_sqe();
        s.prep_cancel(@as(u64, target_id), 0);
        s.user_data = std.math.maxInt(u64);
    }

    pub fn tick(self: *EventLoop, completions_buf: *[max_operations]Completion) ![]Completion {
        switch (self.backend) {
            .io_uring => |*u| {
                _ = try u.ring.submit_and_wait(1);
                return self.reapCompletions(completions_buf);
            },
            .epoll => return self.pollCompletions(completions_buf),
        }
    }

    fn finish(self: *EventLoop, id: OperationId, res: isize) Completion {
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

    fn reapCompletions(self: *EventLoop, buf: *[max_operations]Completion) ![]Completion {
        var cqes: [max_operations]linux.io_uring_cqe = undefined;
        const count = try self.backend.io_uring.ring.copy_cqes(&cqes, 0);

        var out: usize = 0;
        for (cqes[0..count]) |cqe| {
            // The test-only cancel SQE carries a sentinel user_data.
            if (cqe.user_data == std.math.maxInt(u64)) continue;

            const id: OperationId = @intCast(cqe.user_data);
            const slot = &self.slots[id];
            if (!slot.active) continue;

            if (slot.state != .recv_multi) {
                buf[out] = self.finish(id, cqe.res);
                out += 1;
                continue;
            }

            // Multishot ops keep the slot alive as long as F_MORE is set;
            // the kernel will produce more CQEs for the same user_data.
            // When it is clear the kernel has terminated the multishot (e.g.
            // on ENOBUFS); the slot must be freed so the caller can re-arm it.
            const terminated = cqe.flags & linux.IORING_CQE_F_MORE == 0;
            buf[out] = .{ .context = slot.context, .terminated = terminated, .result = .{ .recv = if (self.parseMultishotRecv(cqe)) |parsed|
                .{ .data = parsed.payload, .addr = parsed.addr, .err = null, .buf_id = parsed.buf_id }
            else |err|
                .{ .data = &.{}, .addr = no_addr, .err = err } } };
            if (terminated) self.freeSlot(id);
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
        const ring = &self.backend.io_uring.udp_buf_ring;
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

    fn pollCompletions(self: *EventLoop, buf: *[max_operations]Completion) ![]Completion {
        var events: [max_operations]linux.epoll_event = undefined;
        const rc = linux.epoll_wait(self.backend.epoll.fd, &events, max_operations, self.epollTimeoutMs());
        const ready: usize = switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .INTR => 0,
            else => return error.EpollWaitFailed,
        };

        var out: usize = 0;
        const now = nowNs();
        for (&self.slots, 0..) |*slot, id| {
            if (slot.active and slot.state == .timer and slot.state.timer.deadline_ns <= now) {
                buf[out] = self.finish(@intCast(id), 0);
                out += 1;
            }
        }
        // Ready fds and expired timers each hold a slot, so every share is at
        // least one: a flooded socket can't crowd a listener out of the tick.
        for (events[0..ready], 0..) |ev, i| {
            const share = (max_operations - out) / (ready - i);
            std.debug.assert(share > 0);
            out += self.onReady(@intCast(ev.data.u64), buf[out..][0..share]);
        }
        return buf[0..out];
    }

    fn epollTimeoutMs(self: *const EventLoop) i32 {
        var next: i64 = std.math.maxInt(i64);
        for (&self.slots) |*s| if (s.active and s.state == .timer) {
            next = @min(next, s.state.timer.deadline_ns);
        };
        if (next == std.math.maxInt(i64)) return -1;
        const left = @max(next - nowNs(), 0);
        return @intCast(@min(std.math.divCeil(i64, left, std.time.ns_per_ms) catch unreachable, std.math.maxInt(i32)));
    }

    fn onReady(self: *EventLoop, id: OperationId, out: []Completion) usize {
        const slot = &self.slots[id];
        if (!slot.active) return 0;
        const rc = switch (slot.state) {
            .recv_multi => return self.drainUdp(slot, out),
            .accept => |*a| linux.accept4(slot.fd, &a.addr.any, &a.addr_len, 0),
            .read => |*r| linux.read(slot.fd, r, r.len),
            .stream => |s| linux.recvfrom(slot.fd, s.ptr, s.len, linux.MSG.DONTWAIT, null, null),
            .timer => return 0,
        };
        switch (linux.errno(rc)) {
            .AGAIN, .INTR => {
                if (self.backend.epoll.watch(slot.fd, linux.EPOLL.IN | linux.EPOLL.ONESHOT, id)) return 0 else |_| {
                    out[0] = self.finish(id, -1);
                    return 1;
                }
            },
            else => {
                out[0] = self.finish(id, @bitCast(rc));
                return 1;
            },
        }
    }

    /// One recvmmsg; what is left stays readable and wakes the next tick.
    fn drainUdp(self: *EventLoop, slot: *const Slot, out: []Completion) usize {
        const e = &self.backend.epoll;
        const n = @min(out.len, e.free_count);
        if (n == 0) return 0;
        var ids: [max_operations]u16 = undefined;
        var iovs: [max_operations]posix.iovec = undefined;
        var names: [max_operations]na.PosixAddress = undefined;
        var msgs: [max_operations]linux.mmsghdr = undefined;
        for (0..n) |i| {
            ids[i] = e.free[e.free_count - 1 - i];
            iovs[i] = .{ .base = e.bufferAt(ids[i]).ptr, .len = multishot_payload_max };
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
};

fn nowNs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * std.time.ns_per_s + ts.nsec;
}

fn createTestLoop(backend: Backend) !*EventLoop {
    const loop = try EventLoop.create(testing.allocator, backend);
    if (loop.backend != backend) {
        loop.destroy();
        return error.SkipZigTest;
    }
    watchdog(10);
    try loop.enable();
    return loop;
}

fn destroyTestLoop(loop: *EventLoop) void {
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

fn bindTestUdp() !posix.fd_t {
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
    // packet-sized payload — packets belong in the multishot buffer ring.
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

test "ring refuses opcodes outside the allowlist" {
    const loop = try createTestLoop(.io_uring);
    defer destroyTestLoop(loop);
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
    const loop = try createTestLoop(.io_uring);
    defer destroyTestLoop(loop);

    var socks: [2]posix.fd_t = undefined;
    var ctxs: [2]u8 = .{ 1, 2 };
    var ops: [2]?OperationId = undefined;
    for (&socks, 0..) |*s, i| {
        s.* = try bindTestUdp();
        ops[i] = try loop.recvFromMulti(s.*, @ptrCast(&ctxs[i]));
    }
    defer for (socks) |s| sys.close(s);

    for (ops) |op| try loop.cancel(op.?);

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
            const big: [multishot_payload_max + 1]u8 = @splat('x');
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

test "epoll: a flooded socket cannot crowd a quiet one out of the tick" {
    const loop = try createTestLoop(.epoll);
    defer destroyTestLoop(loop);

    var socks: [2]posix.fd_t = undefined;
    var ctxs: [2]u8 = .{ 0, 1 };
    for (&socks, &ctxs) |*sock, *ctx| {
        sock.* = try bindTestUdp();
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
