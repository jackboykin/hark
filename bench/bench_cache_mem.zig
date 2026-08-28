const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const RRsetCache = hark.cache.RRsetCache;
const bench_common = @import("bench_common.zig");
const BenchResult = @import("main.zig").BenchResult;

const n: u32 = 10_000;

pub fn run(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    const backing = std.heap.page_allocator;
    var cache = RRsetCache.init(.{ .backing = backing, .max_bytes = 64 * 1024 * 1024, .max_entries = n * 2, .io = io });
    defer cache.deinit();
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    const root = dns.Name{ .labels = &.{} };
    for (0..n) |i| {
        const idx: u32 = @intCast(i);
        const labels = try a.alloc([]const u8, 3);
        labels[0] = try std.fmt.allocPrint(a, "host{d}", .{idx});
        labels[1] = "example";
        labels[2] = "com";
        const name = dns.Name{ .labels = labels };
        const pct = idx % 100;
        const rr: dns.ResourceRecord = if (pct < 56) .{
            .name = name,
            .rtype = .a,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .a = .{ 10, 0, @intCast(idx >> 8 & 0xff), @intCast(idx & 0xff) } },
        } else if (pct < 81) .{
            .name = name,
            .rtype = .aaaa,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .aaaa = .{ 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 } },
        } else blk: {
            const strs = try a.alloc([]const u8, 1);
            strs[0] = try std.fmt.allocPrint(a, "v=spf1 include:_spf.example.com ~all {d}", .{idx});
            break :blk .{ .name = name, .rtype = .txt, .rclass = .in, .ttl = 3600, .rdata = .{ .txt = .{ .strings = strs } } };
        };
        cache.storeResponse(try bench_common.singleAnswerMessage(a, rr), root, .unchecked, std.math.maxInt(u32));
    }
    const st = cache.getStats();
    std.debug.print("  entries={d} memory_bytes={d} B/entry={d} sizeof CachedRecord={d} Pack={d} CacheEntry={d}\n", .{ st.entries, st.memory_bytes, st.memory_bytes / st.entries, @sizeOf(hark.cache.CachedRecord), @sizeOf(hark.cache.Pack), @sizeOf(hark.cache.CacheEntry) });
    const samples = try allocator.alloc(i64, 1);
    samples[0] = 0;
    return .{ .samples_ns = samples, .label = "memory probe" };
}
