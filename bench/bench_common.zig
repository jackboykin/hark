//! Shared helpers for benchmarks.

const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;
const RRsetCache = hark.cache.RRsetCache;

pub const host_labels_spec = [_][]const u8{ "host{d}", "example", "com" };

/// Header for a one-record authoritative answer.
pub const single_answer_header: dns.Header = .{
    .id = 0,
    .flags = .{
        .qr = true,
        .opcode = .query,
        .aa = true,
        .tc = false,
        .rd = false,
        .ra = false,
        .z = 0,
        .ad = false,
        .cd = false,
        .rcode = .no_error,
    },
    .qd_count = 0,
    .an_count = 1,
    .ns_count = 0,
    .ar_count = 0,
};

/// Wrap a single resource record into a minimal authoritative message.
pub fn singleAnswerMessage(alloc: std.mem.Allocator, rr: dns.ResourceRecord) !dns.Message {
    const recs = try alloc.alloc(dns.ResourceRecord, 1);
    recs[0] = rr;
    return .{ .header = single_answer_header, .questions = &.{}, .answers = recs };
}

/// Duplicate a slice of string literals into an owned labels slice.
pub fn dupeLabels(alloc: std.mem.Allocator, parts: []const []const u8) ![][]const u8 {
    const labels = try alloc.alloc([]const u8, parts.len);
    for (parts, 0..) |p, i| labels[i] = try alloc.dupe(u8, p);
    return labels;
}

/// Build a minimal authoritative A-record response message with a two- or
/// three-label name. Used by cache/dedup/sieve benches to populate a cache
/// with synthetic entries.
pub fn makeAResponse(
    alloc: std.mem.Allocator,
    idx: u32,
    comptime labels_spec: []const []const u8,
    rdata_a: [4]u8,
) !dns.Message {
    std.debug.assert(labels_spec.len >= 2);
    const labels = try alloc.alloc([]const u8, labels_spec.len);
    // First label is parameterized by idx; the rest are literal.
    labels[0] = try std.fmt.allocPrint(alloc, labels_spec[0], .{idx});
    inline for (labels_spec[1..], 1..) |lit, i| {
        labels[i] = try alloc.dupe(u8, lit);
    }

    return singleAnswerMessage(alloc, .{
        .name = dns.Name{ .labels = labels },
        .rtype = .a,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .a = rdata_a },
    });
}

/// Populate `cache` with `n` synthetic A records (hostN.example.com → 10.0.N.N)
/// and return a `names_alloc`-owned slice of lookup strings ("hostN.example.com").
/// `setup_alloc` is typically an arena scoped to cache population; the returned
/// names outlive it and must be freed by the caller.
pub fn populateHostCache(
    cache: *RRsetCache,
    setup_alloc: std.mem.Allocator,
    names_alloc: std.mem.Allocator,
    n: u32,
) ![][]const u8 {
    const root_zone = dns.Name{ .labels = &.{} };
    const names = try names_alloc.alloc([]const u8, n);
    errdefer names_alloc.free(names);
    var filled: usize = 0;
    errdefer for (names[0..filled]) |name| names_alloc.free(name);

    for (0..n) |i| {
        const idx: u32 = @intCast(i);
        const msg = try makeAResponse(setup_alloc, idx, &host_labels_spec, .{
            10, 0, @intCast((idx >> 8) & 0xff), @intCast(idx & 0xff),
        });
        cache.storeResponse(msg, root_zone, .unchecked);
        names[i] = try std.fmt.allocPrint(names_alloc, "host{d}.example.com", .{i});
        filled = i + 1;
    }
    return names;
}
