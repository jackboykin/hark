//! B/entry unsigned and signed with the two signature sizes that dominate
//! public DNS; signed is what dnssec=true sees.

const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const RRsetCache = hark.cache.RRsetCache;
const bench_common = @import("bench_common.zig");
const BenchResult = @import("main.zig").BenchResult;

const n: u32 = 10_000;

const Signing = enum {
    none,
    p256,
    rsa2048,

    fn sigLen(self: Signing) usize {
        return switch (self) {
            .none => 0,
            .p256 => 64,
            .rsa2048 => 256,
        };
    }
};

fn bytesPerEntry(io: std.Io, signing: Signing) !usize {
    const backing = std.heap.page_allocator;
    var cache = RRsetCache.init(.{ .backing = backing, .max_bytes = 64 * 1024 * 1024, .max_entries = n * 2, .io = io });
    defer cache.deinit();
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    const root = dns.Name{ .labels = &.{} };
    const signer = dns.Name{ .labels = &.{ "example", "com" } };
    const signature = try a.alloc(u8, signing.sigLen());
    @memset(signature, 0xAB);
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
        if (signing == .none) {
            cache.storeResponse(try bench_common.singleAnswerMessage(a, rr), root, .unchecked, std.math.maxInt(u32));
            continue;
        }
        const answers = try a.alloc(dns.ResourceRecord, 2);
        answers[0] = rr;
        answers[1] = .{ .name = name, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = .{
            .type_covered = rr.rtype,
            .algorithm = if (signing == .p256) .ecdsap256sha256 else .rsasha256,
            .labels = 3,
            .original_ttl = 3600,
            .sig_expiration = std.math.maxInt(u32),
            .sig_inception = 0,
            .key_tag = 12345,
            .signer_name = signer,
            .signature = signature,
        } } };
        var msg = bench_common.single_answer_header;
        msg.an_count = 2;
        cache.storeResponse(.{ .header = msg, .questions = &.{}, .answers = answers }, root, .secure, std.math.maxInt(u32));
    }
    const st = cache.getStats();
    if (st.entries != n) return error.StoreRefused;
    return st.memory_bytes / st.entries;
}

pub fn run(allocator: std.mem.Allocator, io: std.Io) !BenchResult {
    std.debug.print("  sizeof CachedRecord={d} Pack={d} CacheEntry={d}\n", .{ @sizeOf(hark.cache.CachedRecord), @sizeOf(hark.cache.Pack), @sizeOf(hark.cache.CacheEntry) });
    inline for (std.meta.tags(Signing)) |signing| {
        std.debug.print("  {s}: {d} B/entry\n", .{ @tagName(signing), try bytesPerEntry(io, signing) });
    }
    const samples = try allocator.alloc(i64, 1);
    samples[0] = 0;
    return .{ .samples_ns = samples, .label = "memory probe" };
}
