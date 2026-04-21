const std = @import("std");
const hark = @import("hark");
const monotonic = hark.monotonic;
const BenchResult = @import("main.zig").BenchResult;

pub fn run(allocator: std.mem.Allocator, _: std.Io) !BenchResult {
    const iters = 10_000;
    const warmup = 100;

    var sink: u64 = 0;
    for (0..warmup) |i| sink +%= i;

    const samples = try allocator.alloc(i64, iters);
    for (samples) |*s| {
        const t0 = monotonic.nowNs();
        for (0..100) |j| sink +%= j *% 31;
        const t1 = monotonic.nowNs();
        s.* = @intCast(t1 - t0);
    }

    std.mem.doNotOptimizeAway(sink);

    return .{ .samples_ns = samples };
}
