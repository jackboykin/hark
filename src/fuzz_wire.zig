//! Structured wire fuzzing. Random bytes die in the first parseName, so Smith
//! draws headers, hostile labels, backward compression pointers and lying
//! rdlengths field by field, where coverage guidance can steer.
const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const dns = @import("dns.zig");
const dns_print = @import("dns_print.zig");
const special_use = @import("special_use.zig");
const rebinding = @import("rebinding.zig");
const cache = @import("cache.zig");
const config = @import("config.zig");

const types = [_]u16{ 1, 2, 5, 6, 12, 15, 16, 28, 39, 41, 43, 46, 47, 48, 50, 51, 64, 65, 99, 257, 0, 65535 };

const Wire = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,

    fn put(w: *Wire, bytes: []const u8) void {
        const n = @min(bytes.len, w.buf.len - w.len);
        @memcpy(w.buf[w.len..][0..n], bytes[0..n]);
        w.len += n;
    }
    fn u16be(w: *Wire, v: u16) void {
        w.put(&std.mem.toBytes(std.mem.nativeToBig(u16, v)));
    }
    fn fill(w: *Wire, s: *Smith, max: u8) void {
        var tmp: [64]u8 = undefined;
        w.put(tmp[0..s.slice(tmp[0..max])]);
    }
};

fn genName(s: *Smith, w: *Wire) void {
    var labels = s.valueRangeAtMost(u8, 0, 8);
    while (labels > 0) : (labels -= 1) {
        if (w.len > 2 and s.boolWeighted(9, 1)) {
            w.u16be(0xC000 | s.valueRangeLessThan(u16, 0, @intCast(w.len)));
            return;
        }
        const len: u8 = switch (s.valueRangeAtMost(u8, 0, 8)) {
            0 => 63,
            1 => 64,
            2 => 0xC0,
            3 => 0x40,
            else => s.valueRangeAtMost(u8, 1, 8),
        };
        w.put(&.{len});
        var n: u8 = len & 0x3F;
        while (n > 0) : (n -= 1) w.put(&.{switch (s.valueRangeAtMost(u8, 0, 5)) {
            0 => '.',
            1 => '\\',
            2 => 0,
            3 => 0xFF,
            else => s.valueRangeAtMost(u8, 'a', 'z'),
        }});
    }
    w.put(&.{0});
}

fn genRR(s: *Smith, w: *Wire) void {
    genName(s, w);
    w.u16be(types[s.index(types.len)]);
    w.u16be(if (s.boolWeighted(1, 1)) 1 else s.value(u16));
    w.put(&std.mem.toBytes(s.value(u32)));
    const rdlen_at = w.len;
    w.u16be(0);
    const start = w.len;
    switch (s.valueRangeAtMost(u8, 0, 3)) {
        0 => genName(s, w),
        1 => {
            genName(s, w);
            w.fill(s, 40);
        },
        else => w.fill(s, 60),
    }
    const real: u16 = @intCast(w.len - start);
    const declared: u16 = switch (s.valueRangeAtMost(u8, 0, 7)) {
        0 => s.value(u16),
        1 => real +| 1,
        2 => real -| 1,
        else => real,
    };
    if (rdlen_at + 2 <= w.len) std.mem.writeInt(u16, w.buf[rdlen_at..][0..2], declared, .big);
}

fn genMessage(s: *Smith, w: *Wire) []const u8 {
    w.len = 0;
    w.u16be(s.value(u16));
    w.u16be(s.value(u16));
    const counts = [4]u8{ s.valueRangeAtMost(u8, 0, 2), s.valueRangeAtMost(u8, 0, 3), s.valueRangeAtMost(u8, 0, 3), s.valueRangeAtMost(u8, 0, 3) };
    for (counts) |c| w.u16be(if (s.boolWeighted(15, 1)) s.value(u16) else c);
    for (0..counts[0]) |_| {
        genName(s, w);
        w.u16be(types[s.index(types.len)]);
        w.u16be(1);
    }
    for (0..@as(usize, counts[1]) + counts[2] + counts[3]) |_| genRR(s, w);
    if (w.len > 12 and s.boolWeighted(9, 1)) w.len = 12 + s.index(w.len - 11);
    return w.buf[0..w.len];
}

/// Injectivity: a name that survives the printer must reparse to itself.
fn checkName(alloc: std.mem.Allocator, name: dns.Name) !void {
    var buf: [dns.max_dotted_len + 1]u8 = undefined;
    if (dns.parseDottedName(alloc, name.formatInto(&buf))) |rt| {
        if (!rt.eqlExact(name)) return error.NotInjective;
    } else |_| {}
    _ = name.formatLower(&buf);
}

const scrub_cfg: rebinding.Config = .{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} };

fn chain(alloc: std.mem.Allocator, input: []const u8) !void {
    const msg = dns.parseMessage(alloc, input) catch return;
    var buf: [dns.max_dotted_len + 1]u8 = undefined;
    for (msg.questions) |q| {
        try checkName(alloc, q.name);
        _ = special_use.classify(q.name.formatLower(&buf), q.qtype);
    }
    for ([_][]const dns.ResourceRecord{ msg.answers, msg.authorities, msg.additionals }) |sec| for (sec) |rr| {
        try checkName(alloc, rr.name);
        switch (rr.rdata) {
            .ns, .cname, .dname, .ptr => |n| try checkName(alloc, n),
            .rrsig => |x| try checkName(alloc, x.signer_name),
            .mx => |x| try checkName(alloc, x.exchange),
            .soa => |x| {
                try checkName(alloc, x.mname);
                try checkName(alloc, x.rname);
            },
            .nsec => |x| {
                try checkName(alloc, x.next_domain_name);
                for (types) |t| _ = dns.typeBitmapContains(x.type_bit_maps, @fromBackingInt(@intCast(t)));
            },
            .nsec3 => |x| {
                for (types) |t| _ = dns.typeBitmapContains(x.type_bit_maps, @fromBackingInt(@intCast(t)));
                var eb: [256]u8 = undefined;
                if (x.next_hashed_owner.len <= 40) _ = dns.base32HexEncode(&eb, x.next_hashed_owner);
            },
            else => {},
        }
        var lb: [dns.max_label_count + 1][]const u8 = undefined;
        if (dns.makeWildcardName(&lb, rr.name)) |wn| _ = wn.formatInto(&buf);
        for (msg.answers) |o| if (o.rdata == .dname and rr.name.isSubdomainOf(o.name)) {
            if (try dns.substituteSuffix(alloc, rr.name, o.name, o.rdata.dname)) |sub| _ = sub.formatInto(&buf);
        };
    };

    var out: [70000]u8 = undefined;
    if (dns.serializeMessage(&out, msg)) |wire| {
        var again: [70000]u8 = undefined;
        const wire2 = try dns.serializeMessage(&again, try dns.parseMessage(alloc, wire));
        if (!std.mem.eql(u8, wire, wire2)) return error.RoundtripDrift;
        _ = dns.extractKeepaliveTimeout(wire);
    } else |_| {}
    var small: [dns.max_udp_payload]u8 = undefined;
    _ = dns.serializeMessage(&small, msg) catch {};
    _ = dns.extractKeepaliveTimeout(input);
    _ = dns.hasTcBit(input);

    var sink: [1 << 16]u8 = undefined;
    var w = std.Io.Writer.fixed(&sink);
    dns_print.printMessage(msg, &w) catch {};

    const once = try rebinding.scrub(alloc, msg.answers, scrub_cfg);
    if ((try rebinding.scrub(alloc, once, scrub_cfg)).len != once.len) return error.ScrubNotIdempotent;
    _ = try rebinding.scrub(alloc, msg.additionals, scrub_cfg);
}

test "fuzz: wire message chain" {
    try testing.fuzz({}, struct {
        fn one(_: void, s: *Smith) anyerror!void {
            var w: Wire = .{};
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            try chain(arena.allocator(), genMessage(s, &w));
        }
    }.one, .{});
}

// Global so state accumulates across inputs; the small budget keeps eviction
// and the counting allocator's refusal path hot.
var shared_cache: ?cache.RRsetCache = null;

test "fuzz: cache store and lookup" {
    try testing.fuzz({}, struct {
        fn one(_: void, s: *Smith) anyerror!void {
            var w: Wire = .{};
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            const alloc = arena.allocator();
            const msg = dns.parseMessage(alloc, genMessage(s, &w)) catch return;
            if (shared_cache == null) shared_cache = cache.RRsetCache.init(.{ .backing = std.heap.smp_allocator, .max_bytes = 64 * 1024, .io = testing.io });
            const c = &shared_cache.?;
            var buf: [dns.max_dotted_len + 1]u8 = undefined;
            for ([_][]const dns.ResourceRecord{ msg.answers, msg.authorities }) |sec| for (sec) |rr| {
                c.storeResponse(msg, rr.name, .unchecked, std.math.maxInt(u32));
                const name = rr.name.formatLower(&buf);
                c.storeNegative(name, rr.rtype, .in, .name_error, msg.authorities, rr.name, .unchecked, std.math.maxInt(u32));
                if (c.lookup(alloc, name, rr.rtype, .in)) |_| {}
                _ = c.containsFresh(name, rr.rtype, .in);
            };
            for (msg.questions) |q| if (c.lookup(alloc, q.name.formatLower(&buf), q.qtype, .in)) |_| {};
        }
    }.one, .{});
}

test "fuzz: config" {
    try testing.fuzz({}, struct {
        fn one(_: void, s: *Smith) anyerror!void {
            var buf: [2048]u8 = undefined;
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            _ = config.parseConfig(arena.allocator(), buf[0..s.slice(&buf)]) catch {};
        }
    }.one, .{ .corpus = &.{&config_seed} });
}

// Smith's slice encoding: little-endian u32 length, then the bytes.
const config_seed = std.mem.toBytes(@as(u32, config_toml.len)) ++ config_toml.*;
const config_toml =
    \\[server]
    \\listen = ["127.0.0.1:5354"]
    \\workers = 4
    \\resolution-threads = 16
    \\
    \\[resolver]
    \\dnssec = true
    \\qname-minimization = true
    \\case-randomization = true
    \\
    \\[cache]
    \\size = 268435456
    \\entries = 200000
    \\
    \\[logging]
    \\queries = false
;
