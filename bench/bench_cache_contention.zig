//! Multithreaded RRsetCache contention sweep.
//!
//!   ro: N readers hammer cache.lookup over overlapping name slices.
//!       Mixes shared-lock CAS contention (single state-word cmpxchg)
//!       with hash-bucket coherence pressure. Both improve under sharding.
//!   rw: 1 writer + (N-1) readers; writer re-stores existing entries at
//!       ~iters/100, forcing readers through the mutex fallback in
//!       lockSharedUncancelable.
//!
//! Sweep extends to 32 (SMT region) and 64 (oversubscribed). With 16 shards
//! the rwlock contention should stay flat past physical cores; t=64 stresses
//! the kernel scheduler and shard distribution under heavy oversubscription.
//! Aggregate QPS is the primary metric — compare before/after sharding.
//! Per-iter samples include ~30-60ns of clock-read overhead; treat p50/p99
//! as upper-bound estimates of lookup latency under load.

const std = @import("std");
const hark = @import("hark");
const monotonic = hark.monotonic;
const dns = hark.dns;
const RRsetCache = hark.cache.RRsetCache;
const bench_common = @import("bench_common.zig");
const main_mod = @import("main.zig");
const BenchResult = main_mod.BenchResult;
const Benchmark = main_mod.Benchmark;

const n_entries: u32 = 2000;
const iters_per_thread: u32 = 200_000;
const writer_period: u32 = 100;
const arena_warmup: u32 = 256;
const max_threads: usize = 64;

const Mode = enum { ro, rw };

fn readerWorker(
    cache: *RRsetCache,
    names: []const []const u8,
    ready: *std.atomic.Value(u32),
    start_flag: *const std.atomic.Value(bool),
    samples: []i64,
    thread_idx: u32,
    n_threads: u32,
) void {
    const backing = std.heap.page_allocator;
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();

    const len_u32: u32 = @intCast(names.len);

    for (0..arena_warmup) |i| {
        _ = arena.reset(.retain_capacity);
        const name = names[(thread_idx +% @as(u32, @intCast(i))) % len_u32];
        if (cache.lookup(arena.allocator(), name, .a, .in)) |r| std.mem.doNotOptimizeAway(r);
    }

    _ = ready.fetchAdd(1, .release);
    while (!start_flag.load(.acquire)) {}

    const stride: u32 = len_u32 / n_threads;
    const base: u32 = thread_idx * stride;
    for (samples, 0..) |*s, i| {
        _ = arena.reset(.retain_capacity);
        const name = names[(base + @as(u32, @intCast(i))) % len_u32];
        const t0 = monotonic.nowNs();
        const r = cache.lookup(arena.allocator(), name, .a, .in);
        const t1 = monotonic.nowNs();
        s.* = @intCast(t1 - t0);
        std.mem.doNotOptimizeAway(r);
    }
}

fn writerWorker(
    cache: *RRsetCache,
    names: []const []const u8,
    ready: *std.atomic.Value(u32),
    start_flag: *const std.atomic.Value(bool),
    samples: []i64,
    thread_idx: u32,
    n_threads: u32,
) void {
    _ = thread_idx;
    _ = n_threads;
    const backing = std.heap.page_allocator;
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();

    const len_u32: u32 = @intCast(names.len);
    const root = dns.Name{ .labels = &.{} };

    for (0..16) |i| {
        const idx: u32 = @as(u32, @intCast(i)) % len_u32;
        const msg = bench_common.makeAResponse(arena.allocator(), idx, &bench_common.host_labels_spec, .{
            10, 0, @intCast((idx >> 8) & 0xff), @intCast(idx & 0xff),
        }) catch return;
        cache.storeResponse(msg, root, .unchecked);
    }
    _ = arena.reset(.retain_capacity);

    _ = ready.fetchAdd(1, .release);
    while (!start_flag.load(.acquire)) {}

    for (samples, 0..) |*s, i| {
        _ = arena.reset(.retain_capacity);
        const idx: u32 = @as(u32, @intCast(i)) % len_u32;
        const msg = bench_common.makeAResponse(arena.allocator(), idx, &bench_common.host_labels_spec, .{
            10, 0, @intCast((idx >> 8) & 0xff), @intCast(idx & 0xff),
        }) catch {
            s.* = 0;
            continue;
        };
        const t0 = monotonic.nowNs();
        cache.storeResponse(msg, root, .unchecked);
        const t1 = monotonic.nowNs();
        s.* = @intCast(t1 - t0);
    }
}

fn runSweep(
    allocator: std.mem.Allocator,
    io: std.Io,
    comptime n_threads: u32,
    comptime mode: Mode,
) !BenchResult {
    const backing = std.heap.page_allocator;
    var cache = RRsetCache.init(.{
        .backing = backing,
        .max_bytes = 64 * 1024 * 1024,
        .max_entries = n_entries * 2,
        .io = io,
    });
    defer cache.deinit();

    var setup_arena = std.heap.ArenaAllocator.init(backing);
    defer setup_arena.deinit();

    const lookup_names = try bench_common.populateHostCache(&cache, setup_arena.allocator(), allocator, n_entries);
    defer {
        for (lookup_names) |n| allocator.free(n);
        allocator.free(lookup_names);
    }

    var ready = std.atomic.Value(u32).init(0);
    var start_flag = std.atomic.Value(bool).init(false);

    const has_writer = mode == .rw and n_threads > 1;
    const writer_iters = iters_per_thread / writer_period;

    var thread_samples: [max_threads][]i64 = undefined;
    var threads: [max_threads]std.Thread = undefined;

    var allocated: u32 = 0;
    defer for (thread_samples[0..allocated]) |s| allocator.free(s);

    for (0..n_threads) |i| {
        const iters = if (has_writer and i == 0) writer_iters else iters_per_thread;
        thread_samples[i] = try allocator.alloc(i64, iters);
        allocated = @as(u32, @intCast(i)) + 1;
    }

    for (0..n_threads) |i| {
        const args = .{ &cache, lookup_names, &ready, &start_flag, thread_samples[i], @as(u32, @intCast(i)), n_threads };
        threads[i] = if (has_writer and i == 0)
            std.Thread.spawn(.{}, writerWorker, args) catch @panic("thread spawn failed")
        else
            std.Thread.spawn(.{}, readerWorker, args) catch @panic("thread spawn failed");
    }

    while (ready.load(.acquire) < n_threads) {}
    const t_start = monotonic.nowNs();
    start_flag.store(true, .release);

    for (0..n_threads) |i| threads[i].join();
    const t_end = monotonic.nowNs();

    const reader_start: usize = if (has_writer) 1 else 0;
    var combined_len: usize = 0;
    for (thread_samples[reader_start..n_threads]) |s| combined_len += s.len;
    const combined = try allocator.alloc(i64, combined_len);
    var off: usize = 0;
    for (thread_samples[reader_start..n_threads]) |s| {
        @memcpy(combined[off..][0..s.len], s);
        off += s.len;
    }

    const elapsed_ns: u64 = @intCast(t_end - t_start);
    const qps: u64 = if (elapsed_ns == 0) 0 else (combined_len * std.time.ns_per_s) / elapsed_ns;

    const label = try std.fmt.allocPrint(
        allocator,
        "threads={d} qps={d} reader_iters={d} elapsed_ms={d}",
        .{ n_threads, qps, combined_len, elapsed_ns / std.time.ns_per_ms },
    );

    return .{
        .samples_ns = combined,
        .label = label,
        .label_owner = allocator,
    };
}

fn makeRun(
    comptime n_threads: u32,
    comptime mode: Mode,
) *const fn (std.mem.Allocator, std.Io) anyerror!BenchResult {
    return struct {
        fn r(alloc: std.mem.Allocator, io: std.Io) anyerror!BenchResult {
            return runSweep(alloc, io, n_threads, mode);
        }
    }.r;
}

const ro_counts = [_]u32{ 1, 2, 4, 8, 16, 32, 64 };
const rw_counts = [_]u32{ 2, 4, 8, 16, 32, 64 };

pub const benchmarks = blk: {
    var list: [ro_counts.len + rw_counts.len]Benchmark = undefined;
    var i: usize = 0;
    for (ro_counts) |n| {
        list[i] = .{ .name = std.fmt.comptimePrint("cache_contention_ro/t={d}", .{n}), .run = makeRun(n, .ro) };
        i += 1;
    }
    for (rw_counts) |n| {
        list[i] = .{ .name = std.fmt.comptimePrint("cache_contention_rw/t={d}", .{n}), .run = makeRun(n, .rw) };
        i += 1;
    }
    break :blk list;
};
