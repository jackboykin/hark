//! Facts as immutable refcounted blobs keyed outside the graph: a header
//! read in place, then scalars, uncompressed names and record wire parsed
//! back through dns.zig. Blob identity is pointer identity.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const dnssec = @import("dnssec.zig");
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

    pub fn stamp(v: *Verdict, c: trust.Chain, until_ns: i64) void {
        v.* = .{ .status = @backingInt(c.status), .proven_until_ns = c.proven_until_ns, .until_ns = until_ns };
    }

    pub fn chain(v: Verdict) trust.Chain {
        return .{ .status = @fromBackingInt(@as(u2, @intCast(v.status))), .proven_until_ns = v.proven_until_ns };
    }
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

pub const Entry = struct {
    blob: *Blob,
    expires_ns: i64,
    stored_ns: i64 = 0,
    /// A failed refresh holds the expired fact until then (RFC 8767 §5).
    hold_until_ns: i64 = 0,
};

const KeyContext = struct {
    pub fn hash(_: KeyContext, k: Key) u32 {
        return @truncate(Key.hash(k));
    }
    pub fn eql(_: KeyContext, a: Key, b: Key, _: usize) bool {
        return Key.eql(a, b);
    }
};

pub const OnEvict = struct { ctx: *anyopaque, f: *const fn (*anyopaque, Key) void };

pub const Store = struct {
    gpa: Allocator,
    map: std.ArrayHashMapUnmanaged(Key, Entry, KeyContext, true) = .empty,
    /// Every live blob's bytes, whoever holds it.
    bytes: usize = 0,
    /// What the map holds; the cap is on this.
    held: usize = 0,
    cap: usize,
    visited: std.DynamicBitSetUnmanaged = .{},
    hand: usize = 0,
    /// Over the cap a key is turned away the first time and admitted the
    /// next, so a flood of names never seen twice evicts nothing.
    door: [door_bits / 8]u8 = @splat(0),
    door_set: u32 = 0,
    evictions: u64 = 0,
    refusals: u64 = 0,
    on_evict: ?OnEvict = null,
    stage: []u8,

    const door_bits = 1 << 16;

    pub fn init(gpa: Allocator, cap: usize) !Store {
        return .{ .gpa = gpa, .cap = cap, .stage = try gpa.alloc(u8, 2 * @as(usize, dns.max_message_len)) };
    }

    pub fn deinit(s: *Store) void {
        for (s.map.keys(), s.map.values()) |k, e| {
            s.gpa.free(k.name);
            s.unref(e.blob);
        }
        s.map.deinit(s.gpa);
        s.visited.deinit(s.gpa);
        s.gpa.free(s.stage);
    }

    pub fn unref(s: *Store, b: *Blob) void {
        b.refs -= 1;
        if (b.refs > 0) return;
        s.bytes -= b.len;
        s.gpa.free(b.bytes());
    }

    pub fn get(s: *Store, key: Key, now_ns: i64) ?Entry {
        const i = s.map.getIndex(key) orelse return null;
        const e = s.map.values()[i];
        if (e.expires_ns <= now_ns) return null;
        if (i < s.visited.capacity()) s.visited.set(i);
        return e;
    }

    /// Any age; not a SIEVE hit.
    pub fn any(s: *Store, key: Key) ?Entry {
        return s.map.get(key);
    }

    pub fn hold(s: *Store, key: Key, until_ns: i64) void {
        if (s.map.getPtr(key)) |e| e.hold_until_ns = until_ns;
    }

    /// Takes one reference. A new key over the cap must have knocked before.
    /// Takes the caller's reference on success; on any error it stays theirs.
    pub fn put(s: *Store, key: Key, blob: *Blob, expires_ns: i64, now_ns: i64) !void {
        const gop = try s.map.getOrPut(s.gpa, key);
        if (gop.found_existing) {
            s.held -= gop.value_ptr.blob.len;
            s.unref(gop.value_ptr.blob);
        } else {
            errdefer s.map.swapRemoveAt(gop.index);
            if (s.held + blob.len > s.cap and !s.knock(key)) {
                s.refusals += 1;
                return error.Refused;
            }
            gop.key_ptr.name = try s.gpa.dupe(u8, key.name);
            // Runs before the swapRemoveAt above, while the key is still in place.
            errdefer s.gpa.free(gop.key_ptr.name);
            if (s.visited.capacity() < s.map.capacity()) try s.visited.resize(s.gpa, s.map.capacity(), false);
        }
        // A new version drops any hold.
        gop.value_ptr.* = .{ .blob = blob, .expires_ns = expires_ns, .stored_ns = now_ns };
        s.held += blob.len;
        s.visited.set(gop.index);
        while (s.held > s.cap and s.map.count() > 1) s.evict();
    }

    pub fn remove(s: *Store, key: Key) void {
        const i = s.map.getIndex(key) orelse return;
        s.removeAt(i);
    }

    fn removeAt(s: *Store, i: usize) void {
        const last = s.map.count() - 1;
        if (i != last) s.visited.setValue(i, s.visited.isSet(last));
        const key = s.map.keys()[i];
        const e = s.map.values()[i];
        s.map.swapRemoveAt(i);
        s.held -= e.blob.len;
        s.gpa.free(key.name);
        s.unref(e.blob);
        if (s.hand > i) s.hand -= 1;
    }

    /// SIEVE, its scan capped; past the cap the entry at the hand goes.
    fn evict(s: *Store) void {
        const n = s.map.count();
        var probes: usize = 0;
        while (probes < @min(n, 64)) : (probes += 1) {
            if (s.hand >= n) s.hand = 0;
            if (!s.visited.isSet(s.hand)) break;
            s.visited.unset(s.hand);
            s.hand += 1;
        }
        if (s.hand >= n) s.hand = 0;
        if (s.on_evict) |h| h.f(h.ctx, s.map.keys()[s.hand]);
        s.removeAt(s.hand);
        s.evictions += 1;
    }

    fn knock(s: *Store, key: Key) bool {
        const h = key.hash();
        const a: u32 = @truncate(h % door_bits);
        const b: u32 = @truncate((h >> 32) % door_bits);
        const seen = s.door[a / 8] & (@as(u8, 1) << @intCast(a % 8)) != 0 and s.door[b / 8] & (@as(u8, 1) << @intCast(b % 8)) != 0;
        if (seen) return true;
        if (s.door_set >= door_bits / 2) {
            @memset(&s.door, 0);
            s.door_set = 0;
        }
        s.door[a / 8] |= @as(u8, 1) << @intCast(a % 8);
        s.door[b / 8] |= @as(u8, 1) << @intCast(b % 8);
        s.door_set += 2;
        return false;
    }

    /// One reference, the caller's.
    pub fn build(s: *Store, value: Value) !*Blob {
        var w: Writer = .{ .buf = s.stage, .pos = @sizeOf(Blob) };
        switch (value) {
            .cut => |c| {
                try w.name(c.zone);
                try w.int(u8, @intFromBool(c.stop) | @as(u8, @intFromBool(c.failed)) << 1);
                try w.int(u8, c.probes);
                try w.addrs(c.addrs);
            },
            .ns => |n| {
                try w.int(u16, @intCast(n.names.len));
                for (n.names) |name| try w.name(name);
            },
            .addr => |a| {
                try w.int(u8, @intFromBool(a.provisional));
                try w.addrs(a.addrs);
            },
            .rrset => |r| {
                // `rrsetLife` reads these in place.
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
            // A failed answer alone, for its SERVFAIL window.
            .answer => |a| {
                try w.int(u8, @backingInt(a.status));
                try w.int(u8, @intFromBool(a.broken));
            },
            .secure, .exchange, .refresh => unreachable,
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
                break :blk .{ .cut = .{ .zone = zone, .stop = flags & 1 != 0, .failed = flags & 2 != 0, .probes = try r.int(u8), .addrs = try r.addrs() } };
            },
            .ns => blk: {
                const names = try arena.alloc(dns.Name, try r.int(u16));
                for (names) |*n| n.* = try r.name();
                break :blk .{ .ns = .{ .names = names } };
            },
            .addr => blk: {
                const provisional = try r.int(u8) != 0;
                break :blk .{ .addr = .{ .addrs = try r.addrs(), .provisional = provisional } };
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
            .answer => blk: {
                const status: dnssec.SecurityStatus = @fromBackingInt(@as(u2, @intCast(try r.int(u8))));
                break :blk .{ .answer = .{ .hops = &.{}, .status = status, .broken = try r.int(u8) != 0 } };
            },
            .secure, .exchange, .refresh => unreachable,
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

    fn addrs(w: *Writer, list: []const na.Address) !void {
        try w.int(u16, @intCast(list.len));
        for (list) |addr| {
            const k = na.AddressKey.fromAddress(addr);
            try w.int(u8, k.family);
            try w.int(u16, k.port);
            try w.slice(&k.addr);
        }
    }

    fn records(w: *Writer, rrs: []const RR) !void {
        for (rrs) |rr| w.pos += (try dns.buildResourceRecordWire(w.buf[w.pos..], rr)).bytes.len;
    }
};

/// Read in place, no parse.
pub const RrsetLife = struct { servfail: bool, expires_ns: i64 };

pub fn rrsetLife(b: *Blob) !RrsetLife {
    if (b.kind != @backingInt(Kind.rrset)) return error.EndOfData;
    var r: Reader = .{ .buf = b.payload(), .arena = undefined };
    const kind = try r.int(u8);
    _ = try r.int(u8);
    _ = try r.int(u8);
    _ = try r.int(u16);
    const ttl = try r.int(u32);
    const stored_ns = try r.int(i64);
    return .{ .servfail = kind == @backingInt(@as(@FieldType(graph.Reply, "kind"), .servfail)), .expires_ns = stored_ns + @as(i64, ttl) * std.time.ns_per_s };
}

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

    fn addrs(r: *Reader) ![]na.Address {
        const list = try r.arena.alloc(na.Address, try r.int(u16));
        for (list) |*a| {
            const family = try r.int(u8);
            const port = try r.int(u16);
            const raw = try r.slice(16);
            a.* = if (family == std.posix.AF.INET) na.initIp4(raw[0..4].*, port) else na.initIp6(raw[0..16].*, port, 0, 0);
        }
        return list;
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
    var s = try Store.init(testing.allocator, 1 << 20);
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
    try s.put(key, blob, 1000, 0);
    try testing.expectEqual(blob, s.get(key, 999).?.blob);
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
    try s.put(key, newer, 2000, 0);
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

test "the cap holds by eviction and admission" {
    const testing = std.testing;
    var s = try Store.init(testing.allocator, 2048);
    defer s.deinit();
    const zone: dns.Name = .{ .labels = &.{"x"} };
    var names: [64][8]u8 = undefined;
    for (0..64) |i| {
        _ = try std.fmt.bufPrint(&names[i], "k{d}", .{i});
        const key: Key = .{ .kind = .cut, .name = std.mem.sliceTo(&names[i], 0)[0..if (i < 10) 2 else 3] };
        const blob = try s.build(.{ .cut = .{ .zone = zone } });
        s.put(key, blob, 10, 0) catch |err| {
            try testing.expectEqual(error.Refused, err);
            try s.put(key, blob, 10, 0);
        };
    }
    try testing.expect(s.held <= 2048);
    try testing.expect(s.evictions > 0);
    try testing.expect(s.refusals > 0);
    const key: Key = .{ .kind = .cut, .name = "again" };
    const again = try s.build(.{ .cut = .{ .zone = zone } });
    try testing.expectError(error.Refused, s.put(key, again, 10, 0));
    try s.put(key, again, 10, 0);
    try testing.expect(s.get(key, 0) != null);
    try testing.expectEqual(s.held, s.bytes);
}
