//! Thread-local arena reuse across queries. Two variants:
//!   fresh_arena:  ArenaAllocator.init / deinit per iteration
//!   reset_arena:  one arena, reset(.retain_capacity) per iteration
//!
//! Each iteration does a representative burst of small allocations mimicking
//! what a cache-hit query arena sees: a labels slice + a few dupes + a
//! ResourceRecord slice.

const std = @import("std");
const hark = @import("hark");
const monotonic = hark.monotonic;
const BenchResult = @import("main.zig").BenchResult;

const iters = 50_000;
const warmup = 1_000;

fn doAllocWork(arena_alloc: std.mem.Allocator) !void {
    const labels = try arena_alloc.alloc([]const u8, 3);
    labels[0] = try arena_alloc.dupe(u8, "www");
    labels[1] = try arena_alloc.dupe(u8, "example");
    labels[2] = try arena_alloc.dupe(u8, "com");
    const rec = try arena_alloc.alloc(u8, 48);
    @memset(rec, 0);
    std.mem.doNotOptimizeAway(labels.ptr);
    std.mem.doNotOptimizeAway(rec.ptr);
}

pub fn runFreshArena(allocator: std.mem.Allocator, _: std.Io) !BenchResult {
    const backing = std.heap.page_allocator;

    for (0..warmup) |_| {
        var arena = std.heap.ArenaAllocator.init(backing);
        defer arena.deinit();
        try doAllocWork(arena.allocator());
    }

    const samples = try allocator.alloc(i64, iters);
    for (samples) |*s| {
        const t0 = monotonic.nowNs();
        var arena = std.heap.ArenaAllocator.init(backing);
        try doAllocWork(arena.allocator());
        arena.deinit();
        const t1 = monotonic.nowNs();
        s.* = @intCast(t1 - t0);
    }
    return .{ .samples_ns = samples, .label = "fresh ArenaAllocator per iter" };
}

pub fn runResetArena(allocator: std.mem.Allocator, _: std.Io) !BenchResult {
    const backing = std.heap.page_allocator;

    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();

    for (0..warmup) |_| {
        _ = arena.reset(.retain_capacity);
        try doAllocWork(arena.allocator());
    }

    const samples = try allocator.alloc(i64, iters);
    for (samples) |*s| {
        const t0 = monotonic.nowNs();
        _ = arena.reset(.retain_capacity);
        try doAllocWork(arena.allocator());
        const t1 = monotonic.nowNs();
        s.* = @intCast(t1 - t0);
    }
    return .{ .samples_ns = samples, .label = "reuse + reset(.retain_capacity)" };
}
