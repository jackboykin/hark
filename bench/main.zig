const std = @import("std");
const hark = @import("hark");
const monotonic = hark.monotonic;

pub const BenchResult = struct {
    samples_ns: []i64,
    alloc_bytes: u64 = 0,
    alloc_count: u64 = 0,
    label: ?[]const u8 = null,
    label_owner: ?std.mem.Allocator = null,
};

pub const Benchmark = struct {
    name: []const u8,
    run: *const fn (std.mem.Allocator, std.Io) anyerror!BenchResult,
};

const self_test = @import("bench_self_test.zig");
const arena = @import("bench_arena.zig");
const sieve = @import("bench_sieve.zig");
const cache_hit = @import("bench_cache_hit.zig");
const dedup = @import("bench_dedup.zig");
const upstream = @import("bench_upstream.zig");
const delegation = @import("bench_delegation.zig");
const cache_contention = @import("bench_cache_contention.zig");
const cache_write = @import("bench_cache_write.zig");

const benchmarks = [_]Benchmark{
    .{ .name = "self_test", .run = self_test.run },
    .{ .name = "arena_fresh", .run = arena.runFreshArena },
    .{ .name = "arena_reset", .run = arena.runResetArena },
    .{ .name = "sieve_worst", .run = sieve.runWorstCase },
    .{ .name = "cache_hit", .run = cache_hit.run },
    .{ .name = "dedup_with", .run = dedup.runWithDedup },
    .{ .name = "dedup_without", .run = dedup.runWithoutDedup },
    .{ .name = "dedup_f01", .run = dedup.runF01 },
    .{ .name = "upstream_perquery", .run = upstream.runPerQuery },
    .{ .name = "upstream_persistent", .run = upstream.runPersistent },
    .{ .name = "delegation", .run = delegation.run },
} ++ cache_contention.benchmarks ++ cache_write.benchmarks;

fn percentile(sorted: []const i64, p: f64) i64 {
    const idx_f = @as(f64, @floatFromInt(sorted.len)) * p;
    const idx: usize = @intFromFloat(idx_f);
    return sorted[@min(idx, sorted.len - 1)];
}

fn mean(samples: []const i64) i64 {
    var sum: i128 = 0;
    for (samples) |s| sum += s;
    return @intCast(@divFloor(sum, @as(i128, @intCast(samples.len))));
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    _ = args_iter.next();
    const filter_opt = args_iter.next();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    var matched: u32 = 0;
    for (benchmarks) |b| {
        if (filter_opt) |f| {
            if (std.mem.indexOf(u8, b.name, f) == null) continue;
        }
        matched += 1;

        const result = try b.run(allocator, io);
        defer allocator.free(result.samples_ns);
        defer if (result.label_owner) |a| a.free(result.label.?);

        std.mem.sort(i64, result.samples_ns, {}, std.sort.asc(i64));

        const p50 = percentile(result.samples_ns, 0.50);
        const p99 = percentile(result.samples_ns, 0.99);
        const avg = mean(result.samples_ns);
        const mn = result.samples_ns[0];
        const mx = result.samples_ns[result.samples_ns.len - 1];

        try stdout.print(
            "[{s}] p50={d}ns p99={d}ns mean={d}ns min={d}ns max={d}ns n={d}",
            .{ b.name, p50, p99, avg, mn, mx, result.samples_ns.len },
        );
        if (result.alloc_count > 0 or result.alloc_bytes > 0) {
            try stdout.print(" allocs={d} bytes={d}", .{ result.alloc_count, result.alloc_bytes });
        }
        try stdout.print("\n", .{});
        if (result.label) |lbl| try stdout.print("  {s}\n", .{lbl});
    }

    if (filter_opt != null and matched == 0) {
        try stdout.print("no benchmarks matched filter: {s}\n", .{filter_opt.?});
    }
    try stdout.flush();
}
