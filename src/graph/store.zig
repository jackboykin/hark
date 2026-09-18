//! Facts as immutable refcounted blobs keyed outside the graph: a header
//! read in place, then scalars, uncompressed names and record wire parsed
//! back through dns.zig. Blob identity is pointer identity.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("../dns.zig");
const na = @import("../net_address.zig");
const dnssec = @import("../dnssec.zig");
const graph = @import("graph.zig");
const trust = @import("trust.zig");

const Kind = graph.Kind;
const Key = graph.Key;
const Value = graph.Value;
const RR = dns.ResourceRecord;

/// `secure(rrset)` over exactly these bytes.
pub const Verdict = extern struct {
    status: u8 = @backingInt(dnssec.SecurityStatus.unchecked),
    _pad: [7]u8 = @splat(0),
    proven_until_ns: i64 = 0,
    until_ns: i64 = 0,
};

pub const Blob = extern struct {
    refs: u32,
    len: u32,
    kind: u8,
    _pad: [7]u8 = @splat(0),
    verdict: Verdict = .{},

    pub fn bytes(b: *Blob) []align(8) u8 {
        return @as([*]align(8) u8, @ptrCast(b))[0..b.len];
    }

    fn payload(b: *Blob) []const u8 {
        return b.bytes()[@sizeOf(Blob)..];
    }

    pub fn ref(b: *Blob) *Blob {
        b.refs += 1;
        return b;
    }
};

const Entry = struct { blob: *Blob, expires_ns: i64 };

const KeyContext = struct {
    pub fn hash(_: KeyContext, k: Key) u32 {
        return @truncate(Key.hash(k));
    }
    pub fn eql(_: KeyContext, a: Key, b: Key, _: usize) bool {
        return Key.eql(a, b);
    }
};

pub const Store = struct {
    gpa: Allocator,
    map: std.ArrayHashMapUnmanaged(Key, Entry, KeyContext, true) = .empty,
    /// Every live blob's bytes, whoever holds it.
    bytes: usize = 0,
    /// A blob is built here and copied out at its exact size.
    stage: []u8,

    pub fn init(gpa: Allocator) !Store {
        return .{ .gpa = gpa, .stage = try gpa.alloc(u8, 2 * @as(usize, dns.max_message_len)) };
    }

    pub fn deinit(s: *Store) void {
        for (s.map.keys(), s.map.values()) |k, e| {
            s.gpa.free(k.name);
            s.unref(e.blob);
        }
        s.map.deinit(s.gpa);
        s.gpa.free(s.stage);
    }

    pub fn unref(s: *Store, b: *Blob) void {
        b.refs -= 1;
        if (b.refs > 0) return;
        s.bytes -= b.len;
        s.gpa.free(b.bytes());
    }

    /// The fresh fact under `key`, borrowed.
    pub fn get(s: *Store, key: Key, now_ns: i64) ?*Blob {
        const e = s.map.get(key) orelse return null;
        return if (e.expires_ns > now_ns) e.blob else null;
    }

    /// Takes one reference; replaces any older version.
    pub fn put(s: *Store, key: Key, blob: *Blob, expires_ns: i64) !void {
        const gop = try s.map.getOrPut(s.gpa, key);
        if (gop.found_existing) {
            s.unref(gop.value_ptr.blob);
        } else {
            gop.key_ptr.name = s.gpa.dupe(u8, key.name) catch |e| {
                s.map.swapRemoveAt(gop.index);
                return e;
            };
        }
        gop.value_ptr.* = .{ .blob = blob, .expires_ns = expires_ns };
    }

    pub fn remove(s: *Store, key: Key) void {
        const kv = s.map.fetchSwapRemove(key) orelse return;
        s.gpa.free(kv.key.name);
        s.unref(kv.value.blob);
    }

    /// One reference, the caller's.
    pub fn build(s: *Store, value: Value) !*Blob {
        var w: Writer = .{ .buf = s.stage, .pos = @sizeOf(Blob) };
        switch (value) {
            .cut => |c| {
                try w.name(c.zone);
                try w.int(u8, @intFromBool(c.stop) | @as(u8, @intFromBool(c.failed)) << 1);
                try w.int(u8, c.probes);
            },
            .ns => |n| {
                try w.int(u16, @intCast(n.names.len));
                for (n.names) |name| try w.name(name);
            },
            .addr => |a| {
                try w.int(u8, @intFromBool(a.provisional));
                try w.int(u16, @intCast(a.addrs.len));
                for (a.addrs) |addr| {
                    const k = na.AddressKey.fromAddress(addr);
                    try w.int(u8, k.family);
                    try w.int(u16, k.port);
                    try w.slice(&k.addr);
                }
            },
            .rrset => |r| {
                try w.int(u8, @backingInt(r.kind));
                try w.int(u8, @backingInt(r.rcode));
                try w.int(u8, @intFromBool(r.aa) | @as(u8, @intFromBool(r.ede != null)) << 1);
                try w.int(u16, if (r.ede) |e| @backingInt(e) else 0);
                try w.int(u32, r.ttl);
                try w.int(i64, r.stored_ns);
                try w.name(r.target);
                try w.name(r.zone);
                for ([_][]const RR{ r.answers, r.authorities, r.additionals }) |sec| try w.int(u16, @intCast(sec.len));
                for ([_][]const RR{ r.answers, r.authorities, r.additionals }) |sec| try w.records(sec);
            },
            .ds, .dnskey => |c| {
                try w.int(u8, @backingInt(c.status));
                try w.int(i64, c.proven_until_ns);
                try w.int(u16, @intCast(c.records.len));
                try w.records(c.records);
            },
            .answer, .secure, .exchange => unreachable,
        }
        const out = try s.gpa.alignedAlloc(u8, .fromByteUnits(8), w.pos);
        @memcpy(out, s.stage[0..w.pos]);
        const b: *Blob = @ptrCast(out.ptr);
        b.* = .{ .refs = 1, .len = @intCast(w.pos), .kind = @backingInt(std.meta.activeTag(value)) };
        s.bytes += w.pos;
        return b;
    }

    pub fn parse(arena: Allocator, b: *Blob) !Value {
        var r: Reader = .{ .buf = try arena.dupe(u8, b.payload()), .arena = arena };
        return switch (@as(Kind, @fromBackingInt(b.kind))) {
            .cut => blk: {
                const zone = try r.name();
                const flags = try r.int(u8);
                break :blk .{ .cut = .{ .zone = zone, .stop = flags & 1 != 0, .failed = flags & 2 != 0, .probes = try r.int(u8) } };
            },
            .ns => blk: {
                const names = try arena.alloc(dns.Name, try r.int(u16));
                for (names) |*n| n.* = try r.name();
                break :blk .{ .ns = .{ .names = names } };
            },
            .addr => blk: {
                const provisional = try r.int(u8) != 0;
                const addrs = try arena.alloc(na.Address, try r.int(u16));
                for (addrs) |*a| {
                    const family = try r.int(u8);
                    const port = try r.int(u16);
                    const raw = try r.slice(16);
                    a.* = if (family == std.posix.AF.INET) na.initIp4(raw[0..4].*, port) else na.initIp6(raw[0..16].*, port, 0, 0);
                }
                break :blk .{ .addr = .{ .addrs = addrs, .provisional = provisional } };
            },
            .rrset => blk: {
                var reply: graph.Reply = .{
                    .kind = @fromBackingInt(@as(u3, @intCast(try r.int(u8)))),
                    .rcode = @fromBackingInt(@as(u4, @intCast(try r.int(u8)))),
                    .aa = undefined,
                };
                const flags = try r.int(u8);
                reply.aa = flags & 1 != 0;
                const ede = try r.int(u16);
                if (flags & 2 != 0) reply.ede = @fromBackingInt(ede);
                reply.ttl = try r.int(u32);
                reply.stored_ns = try r.int(i64);
                reply.target = try r.name();
                reply.zone = try r.name();
                const an = try r.int(u16);
                const ns = try r.int(u16);
                const ar = try r.int(u16);
                reply.answers = try r.records(an);
                reply.authorities = try r.records(ns);
                reply.additionals = try r.records(ar);
                break :blk .{ .rrset = reply };
            },
            .ds, .dnskey => |kind| blk: {
                var c: trust.Chain = .{ .status = @fromBackingInt(@as(u2, @intCast(try r.int(u8)))) };
                c.proven_until_ns = try r.int(i64);
                c.records = try r.records(try r.int(u16));
                break :blk if (kind == .ds) .{ .ds = c } else .{ .dnskey = c };
            },
            .answer, .secure, .exchange => unreachable,
        };
    }
};

const Writer = struct {
    buf: []u8,
    pos: usize,

    fn int(w: *Writer, comptime T: type, v: T) !void {
        if (w.pos + @sizeOf(T) > w.buf.len) return error.EndOfData;
        mem.writeInt(T, w.buf[w.pos..][0..@sizeOf(T)], v, .little);
        w.pos += @sizeOf(T);
    }

    fn slice(w: *Writer, s: []const u8) !void {
        if (w.pos + s.len > w.buf.len) return error.EndOfData;
        @memcpy(w.buf[w.pos..][0..s.len], s);
        w.pos += s.len;
    }

    fn name(w: *Writer, n: dns.Name) !void {
        w.pos += try dns.writeNameWire(w.buf[w.pos..], n);
    }

    fn records(w: *Writer, rrs: []const RR) !void {
        for (rrs) |rr| w.pos += (try dns.buildResourceRecordWire(w.buf[w.pos..], rr)).bytes.len;
    }
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,
    arena: Allocator,

    fn int(r: *Reader, comptime T: type) !T {
        if (r.pos + @sizeOf(T) > r.buf.len) return error.EndOfData;
        defer r.pos += @sizeOf(T);
        return mem.readInt(T, r.buf[r.pos..][0..@sizeOf(T)], .little);
    }

    fn slice(r: *Reader, n: usize) ![]const u8 {
        if (r.pos + n > r.buf.len) return error.EndOfData;
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }

    fn name(r: *Reader) !dns.Name {
        return dns.readNameWire(r.arena, r.buf, &r.pos);
    }

    fn records(r: *Reader, n: u16) ![]RR {
        return dns.readRecordsWire(r.arena, r.buf, &r.pos, n);
    }
};

test "a fact survives the blob byte for byte" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var s = try Store.init(testing.allocator);
    defer s.deinit();

    const owner = try dns.parseDottedName(arena, "www.example.com.");
    const zone = try dns.parseDottedName(arena, "example.com.");
    const rrs = [_]RR{
        .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 0, 2, 1 } } },
        .{ .name = owner, .rtype = .rrsig, .rclass = .in, .ttl = 300, .rdata = .{ .rrsig = .{
            .type_covered = .a,
            .algorithm = @fromBackingInt(13),
            .labels = 3,
            .original_ttl = 300,
            .sig_expiration = 2,
            .sig_inception = 1,
            .key_tag = 7,
            .signer_name = zone,
            .signature = "sig",
        } } },
    };
    const soa = [_]RR{.{ .name = zone, .rtype = .soa, .rclass = .in, .ttl = 60, .rdata = .{ .soa = .{
        .mname = owner,
        .rname = zone,
        .serial = 1,
        .refresh = 2,
        .retry = 3,
        .expire = 4,
        .minimum = 5,
    } } }};
    const reply: graph.Reply = .{ .kind = .answer, .rcode = .no_error, .aa = true, .answers = &rrs, .authorities = &soa, .target = owner, .zone = zone, .ede = .other, .stored_ns = 123, .ttl = 300 };
    const key: Key = .{ .kind = .rrset, .rtype = .a, .name = "www.example.com" };

    const blob = try s.build(.{ .rrset = reply });
    try s.put(key, blob, 1000);
    try testing.expectEqual(blob, s.get(key, 999));
    try testing.expectEqual(null, s.get(key, 1000));
    try testing.expectEqual(blob.len, s.bytes);

    const back = (try Store.parse(arena, blob)).rrset;
    try testing.expectEqual(reply.kind, back.kind);
    try testing.expectEqual(reply.rcode, back.rcode);
    try testing.expectEqual(reply.aa, back.aa);
    try testing.expectEqual(reply.ede, back.ede);
    try testing.expectEqual(reply.ttl, back.ttl);
    try testing.expectEqual(reply.stored_ns, back.stored_ns);
    try testing.expect(back.target.eqlExact(owner) and back.zone.eqlExact(zone));
    try testing.expectEqual(0, back.additionals.len);
    for ([_][]const RR{ reply.answers, reply.authorities }, [_][]const RR{ back.answers, back.authorities }) |want, got| {
        try testing.expectEqual(want.len, got.len);
        for (want, got) |a, b| {
            var wa: [4096]u8 = undefined;
            var wb: [4096]u8 = undefined;
            try testing.expectEqualSlices(u8, (try dns.buildResourceRecordWire(&wa, a)).bytes, (try dns.buildResourceRecordWire(&wb, b)).bytes);
        }
    }

    _ = blob.ref();
    const newer = try s.build(.{ .addr = .{ .addrs = &.{ na.initIp4(.{ 10, 0, 0, 1 }, 53), na.initIp6(@splat(1), 853, 0, 0) }, .provisional = true } });
    try s.put(key, newer, 2000);
    try testing.expectEqual(1, blob.refs);
    const addr = (try Store.parse(arena, newer)).addr;
    try testing.expect(addr.provisional and addr.addrs.len == 2 and na.ipEqual(addr.addrs[1], na.initIp6(@splat(1), 853, 0, 0)));
    s.unref(blob);
    try testing.expectEqual(newer.len, s.bytes);

    const cut_blob = try s.build(.{ .cut = .{ .zone = zone, .stop = true, .probes = 3 } });
    defer s.unref(cut_blob);
    const cut = (try Store.parse(arena, cut_blob)).cut;
    try testing.expect(cut.zone.eqlExact(zone) and cut.stop and !cut.failed and cut.probes == 3);
}
