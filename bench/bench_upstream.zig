//! Persistent per-thread UDP socket. Launches a minimal loopback echo server
//! that flips QR bit on any query, and measures `BlockingUdpTransport.query`
//! wall time across iterations. The syscall-count reduction shows up under
//! `strace -c`.
//!
//! Two variants: one reuses a single transport (persistent socket), the
//! other constructs a fresh transport per call (fresh socket).

const std = @import("std");
const Io = std.Io;
const hark = @import("hark");
const dns = hark.dns;
const monotonic = hark.monotonic;
const na = hark.net_address;
const BlockingUdpTransport = hark.blocking_transport.BlockingUdpTransport;
const BenchResult = @import("main.zig").BenchResult;

const bench_iters: usize = 5_000;
const warmup: usize = 200;

fn echoServer(server_sock: Io.net.Socket, io: Io, stop: *std.atomic.Value(bool)) void {
    // Short timeout so the loop can notice `stop` within a few ms.
    var buf: [4096]u8 = undefined;
    while (!stop.load(.acquire)) {
        const msg = server_sock.receiveTimeout(
            io,
            &buf,
            .{ .duration = .{ .raw = .fromMilliseconds(5), .clock = .awake } },
        ) catch |err| switch (err) {
            error.Timeout => continue,
            else => return,
        };
        if (msg.data.len < 12) continue;
        // Flip the QR bit to make it a response; preserve query ID.
        msg.data[2] |= 0x80;
        server_sock.send(io, &msg.from, msg.data) catch continue;
    }
}

const Setup = struct {
    server_sock: Io.net.Socket,
    server_addr: na.Address,
    stop: *std.atomic.Value(bool),
    thread: std.Thread,
    wire: []u8,
    io: Io,
    backing: std.mem.Allocator,

    fn deinit(self: Setup) void {
        self.stop.store(true, .release);
        self.thread.join();
        self.server_sock.close(self.io);
        self.backing.free(self.wire);
        self.backing.destroy(self.stop);
    }
};

fn setup(allocator: std.mem.Allocator, io: Io) !Setup {
    const bind_addr = na.initIp4(.{ 127, 0, 0, 1 }, 0);
    const server_sock = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    errdefer server_sock.close(io);
    const server_addr = server_sock.address;

    const stop = try allocator.create(std.atomic.Value(bool));
    stop.* = std.atomic.Value(bool).init(false);
    errdefer allocator.destroy(stop);

    const thread = try std.Thread.spawn(.{}, echoServer, .{ server_sock, io, stop });

    // Build one wire query; reuse across iterations (query ID patched each call).
    const msg = try dns.buildQuery(allocator, 0, "bench.test", .a, .{});
    defer dns.freeMessage(allocator, msg);
    var tmp: [dns.max_udp_payload]u8 = undefined;
    const w = try dns.serializeMessage(&tmp, msg);
    const wire = try allocator.dupe(u8, w);

    return .{
        .server_sock = server_sock,
        .server_addr = server_addr,
        .stop = stop,
        .thread = thread,
        .wire = wire,
        .io = io,
        .backing = allocator,
    };
}

/// Single persistent socket reused across all queries.
pub fn runPersistent(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    const s = try setup(allocator, io);
    defer s.deinit();

    var transport = BlockingUdpTransport.init(.{ .timeout_ms = 2000, .retransmit_count = 1 }, io);
    defer transport.deinit();
    var response_buf: [dns.edns_udp_payload]u8 = undefined;

    for (0..warmup) |i| {
        std.mem.writeInt(u16, s.wire[0..2], @intCast(i & 0xffff), .big);
        const resp = try transport.query(s.wire, @intCast(i & 0xffff), s.server_addr, &response_buf);
        std.mem.doNotOptimizeAway(resp.ptr);
    }

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        const qid: u16 = @intCast(i & 0xffff);
        std.mem.writeInt(u16, s.wire[0..2], qid, .big);
        const t0 = monotonic.nowNs();
        const resp = try transport.query(s.wire, qid, s.server_addr, &response_buf);
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
        std.mem.doNotOptimizeAway(resp.ptr);
    }

    return .{ .samples_ns = samples, .label = "persistent socket" };
}

/// Fresh transport (and thus fresh socket) per query.
pub fn runPerQuery(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    const s = try setup(allocator, io);
    defer s.deinit();
    var response_buf: [dns.edns_udp_payload]u8 = undefined;

    for (0..warmup) |i| {
        var transport = BlockingUdpTransport.init(.{ .timeout_ms = 2000, .retransmit_count = 1 }, io);
        defer transport.deinit();
        std.mem.writeInt(u16, s.wire[0..2], @intCast(i & 0xffff), .big);
        const resp = try transport.query(s.wire, @intCast(i & 0xffff), s.server_addr, &response_buf);
        std.mem.doNotOptimizeAway(resp.ptr);
    }

    const samples = try allocator.alloc(i64, bench_iters);
    for (0..bench_iters) |i| {
        const qid: u16 = @intCast(i & 0xffff);
        std.mem.writeInt(u16, s.wire[0..2], qid, .big);
        const t0 = monotonic.nowNs();
        var transport = BlockingUdpTransport.init(.{ .timeout_ms = 2000, .retransmit_count = 1 }, io);
        const resp = try transport.query(s.wire, qid, s.server_addr, &response_buf);
        transport.deinit();
        const t1 = monotonic.nowNs();
        samples[i] = @intCast(t1 - t0);
        std.mem.doNotOptimizeAway(resp.ptr);
    }

    return .{ .samples_ns = samples, .label = "fresh transport per query" };
}
