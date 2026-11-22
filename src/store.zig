//! Facts as immutable refcounted blobs keyed outside the graph: a header
//! read in place, then scalars, canonical names and records as wire.
//! Blob identity is pointer identity.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const model = @import("model.zig");
const Share = @import("share.zig");

const Kind = model.Kind;
const Key = model.Key;
const Value = model.Value;
const RR = dns.ResourceRecord;

pub const Verdict = extern struct {
    /// Read it through `standing`: 0 decodes to secure, and a zeroed verdict is
    /// unjudged.
    status: u8 = 0,
    _pad: [3]u8 = @splat(0),
    judged_s: u32 = 0,
    proven_until_ns: i64 = 0,
    until_ns: i64 = 0,

    pub fn stamp(v: *Verdict, c: model.Chain, until_ns: i64, now_ns: i64) void {
        const judged_s = if (v.until_ns == until_ns) v.judged_s else @as(u32, @intCast(@divFloor(now_ns, std.time.ns_per_s)));
        v.* = .{ .status = @backingInt(c.status), .judged_s = judged_s, .proven_until_ns = c.proven_until_ns, .until_ns = until_ns };
    }

    pub fn judged(v: Verdict) bool {
        return v.until_ns != 0;
    }

    pub fn end(v: Verdict, expires_ns: i64) i64 {
        return if (v.judged()) @min(expires_ns, v.until_ns) else expires_ns;
    }

    pub fn standing(v: Verdict, instant_ns: i64) ?model.Chain {
        if (!v.judged() or v.until_ns <= instant_ns) return null;
        return .{ .status = @fromBackingInt(v.status), .proven_until_ns = v.proven_until_ns };
    }
};

/// One version of a key's value, in one allocation: this header, the key's
/// name, then the value as `build` writes it.
pub const Blob = extern struct {
    refs: u32,
    len: u32,
    name_hash: u32,
    rtype: u16,
    kind: u8,
    name_len: u8,
    expires_ns: i64,
    verdict: Verdict = .{},

    pub fn bytes(b: *Blob) []align(8) u8 {
        return @as([*]align(8) u8, @ptrCast(b))[0..b.len];
    }

    pub fn key(b: *Blob) Key {
        return .{ .kind = @fromBackingInt(b.kind), .rtype = @fromBackingInt(b.rtype), .name = b.payload()[0..b.name_len], .name_hash = b.name_hash };
    }

    fn payload(b: *Blob) []const u8 {
        return b.bytes()[@sizeOf(Blob)..];
    }

    pub fn ref(b: *Blob) *Blob {
        b.refs += 1;
        return b;
    }

    pub fn shorten(b: *Blob, until_ns: i64) void {
        b.expires_ns = @min(b.expires_ns, until_ns);
    }

    pub fn end(b: *Blob) i64 {
        return b.verdict.end(b.expires_ns);
    }
};

fn isReply(b: *Blob) bool {
    const kind: Kind = @fromBackingInt(b.kind);
    return kind == .rrset or kind == .stub or kind == .span;
}

pub const Life = struct {
    start_ns: i64,
    end_ns: i64,

    pub fn of(stored_ns: i64, expires_ns: i64, v: Verdict) Life {
        const end_ns = v.end(expires_ns);
        return .{ .start_ns = if (end_ns < expires_ns) @as(i64, v.judged_s) * std.time.ns_per_s else stored_ns, .end_ns = end_ns };
    }

    pub fn inLastTenth(l: Life, now_ns: i64) bool {
        return now_ns < l.end_ns and l.end_ns - now_ns <= @divTrunc(l.end_ns - l.start_ns, 10);
    }
};

const OnEvict = *const fn (*Store, *Blob) void;

pub const Facts = struct { allocator: Allocator, share: *const Share };

pub const Store = struct {
    gpa: Allocator,
    map: std.array_hash_map.Custom(Ref, void, ByRef, false) = .empty,
    /// Every live blob's bytes, whoever holds a reference.
    bytes: usize = 0,
    /// The bytes of the blobs the map holds.
    held: usize = 0,
    cap: usize,
    share: ?*const Share = null,
    visited: std.bit_set.Dynamic = .{},
    hand: usize = 0,
    /// Over the cap a new key is turned away the first time and admitted the
    /// next, so a flood of names never seen twice evicts nothing.
    door: [door_bits / 8]u8 = @splat(0),
    door_set: u32 = 0,
    evictions: u64 = 0,
    unadmitted: u64 = 0,
    on_evict: ?OnEvict = null,

    const door_bits = 1 << 16;

    /// A blob's address with its key's fingerprint in the 16 bits a user address
    /// leaves free: Linux maps above 2^48 only when a hint asks for it.
    const Ref = packed struct(u64) {
        addr: u48,
        tag: u16,

        fn of(b: *Blob, h: u64) Ref {
            const addr = std.math.cast(u48, @intFromPtr(b)) orelse @panic("blob mapped above 2^48");
            return .{ .addr = addr, .tag = tagOf(h) };
        }

        fn blob(r: Ref) *Blob {
            return @ptrFromInt(r.addr);
        }
    };

    fn tagOf(h: u64) u16 {
        return @truncate(h >> 48);
    }

    const ByRef = struct {
        pub fn hash(_: ByRef, r: Ref) u32 {
            return @truncate(r.blob().key().hash());
        }
        pub fn eql(_: ByRef, a: Ref, b: Ref, _: usize) bool {
            return a.tag == b.tag and a.blob().key().eql(b.blob().key());
        }
    };

    const Probe = struct {
        key: Key,
        h: u64,

        fn of(key: Key) Probe {
            return .{ .key = key, .h = key.hash() };
        }
    };

    const ByKey = struct {
        pub fn hash(_: ByKey, p: Probe) u32 {
            return @truncate(p.h);
        }
        pub fn eql(_: ByKey, p: Probe, r: Ref, _: usize) bool {
            return tagOf(p.h) == r.tag and p.key.eql(r.blob().key());
        }
    };

    fn find(s: *Store, key: Key) ?usize {
        return s.map.getIndexAdapted(Probe.of(key), ByKey{});
    }

    pub fn init(gpa: Allocator, cap: usize, share: ?*const Share) Store {
        return .{ .gpa = gpa, .cap = cap, .share = share };
    }

    /// What the store holds that eviction can give back: all its tenant holds
    /// but blobs only others still read.
    fn footprint(s: *const Store) usize {
        const sh = s.share orelse return s.held;
        return sh.held - (s.bytes - s.held);
    }

    pub fn deinit(s: *Store) void {
        for (s.map.keys()) |r| s.letGo(r.blob());
        s.map.deinit(s.gpa);
        s.visited.deinit(s.gpa);
    }

    pub fn unref(s: *Store, b: *Blob) void {
        b.refs -= 1;
        if (b.refs > 0) return;
        s.bytes -= b.len;
        s.gpa.free(b.bytes());
    }

    pub fn get(s: *Store, key: Key, now_ns: i64) ?*Blob {
        const i = s.find(key) orelse return null;
        const b = s.map.keys()[i].blob();
        if (b.expires_ns <= now_ns) return null;
        if (i < s.visited.capacity()) s.visited.set(i);
        return b;
    }

    pub fn any(s: *Store, key: Key) ?*Blob {
        return s.map.keys()[s.find(key) orelse return null].blob();
    }

    pub fn drop(s: *Store, blob: *Blob) void {
        const i = s.find(blob.key()) orelse return;
        if (s.map.keys()[i].blob() == blob) s.removeAt(i);
    }

    /// Takes the caller's reference on success; on any error it stays theirs.
    pub fn put(s: *Store, blob: *Blob) error{ OutOfMemory, Refused }!void {
        const probe: Probe = .of(blob.key());
        const index, const old: ?*Blob = if (s.map.getIndexAdapted(probe, ByKey{})) |i|
            .{ i, s.map.keys()[i].blob() }
        else blk: {
            if (s.footprint() + blob.len > s.cap and !s.knock(probe.h)) {
                s.unadmitted += 1;
                return error.Refused;
            }
            try s.map.ensureUnusedCapacity(s.gpa, 1);
            if (s.visited.capacity() < s.map.capacity()) try s.visited.resize(s.gpa, s.map.capacity(), false);
            const gop = s.map.getOrPutAssumeCapacityAdapted(probe, ByKey{});
            std.debug.assert(!gop.found_existing);
            break :blk .{ gop.index, null };
        };
        s.map.keys()[index] = .of(blob, probe.h);
        s.held += blob.len;
        s.visited.set(index);
        if (old) |o| {
            if (s.on_evict) |f| f(s, o);
            s.letGo(o);
        }
        while (s.footprint() > s.cap and s.map.count() > 1) s.evict();
    }

    fn letGo(s: *Store, b: *Blob) void {
        s.held -= b.len;
        s.unref(b);
    }

    fn removeAt(s: *Store, i: usize) void {
        const last = s.map.count() - 1;
        // swapRemove moves the last entry into `i`: its visited bit and the hand
        // follow it.
        if (i != last) s.visited.setValue(i, s.visited.isSet(last));
        const b = s.map.keys()[i].blob();
        if (s.on_evict) |f| f(s, b);
        s.map.swapRemoveAt(i);
        s.letGo(b);
        if (s.hand == last) s.hand = i;
    }

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
        s.removeAt(s.hand);
        s.evictions += 1;
    }

    fn knock(s: *Store, h: u64) bool {
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

    /// Rdata names arrive compressed and are stored whole, so no message size
    /// bounds a blob: it is measured, then written.
    pub fn build(s: *Store, key: Key, value: Value, expires_ns: i64) Allocator.Error!*Blob {
        std.debug.assert(std.meta.activeTag(value) == if (key.kind == .span) .rrset else key.kind);
        var measure: Writer(true) = .{ .buf = {} };
        encode(true, &measure, key, value);
        const out = try s.gpa.alignedAlloc(u8, .fromByteUnits(8), measure.pos);
        var w: Writer(false) = .{ .buf = out };
        encode(false, &w, key, value);
        std.debug.assert(w.pos == out.len);
        const b: *Blob = @ptrCast(out.ptr);
        b.* = header(key, out.len, expires_ns);
        s.bytes += out.len;
        return b;
    }

    fn encode(comptime measuring: bool, w: *Writer(measuring), key: Key, value: Value) void {
        w.slice(key.name);
        w.anchors[0] = .{ .at = 0, .wire = key.name };
        switch (value) {
            .cut => |c| {
                w.name(c.zone);
                w.int(i64, c.placed_until_ns);
                w.int(u16, @intCast(c.servers.len));
                var glue: usize = 0;
                for (c.servers) |server| glue += server.glue.len;
                w.int(u16, @intCast(glue));
                for (c.servers) |server| {
                    w.int(u16, @intCast(server.key.name.len));
                    w.slice(server.key.name);
                    w.int(u32, server.key.name_hash);
                    w.int(u16, @intCast(server.glue.len));
                }
                for (c.servers) |server| for (server.glue) |gl| w.addr(gl);
            },
            .rrset, .stub => |r| {
                // `Rrset.read` reads this layout in place.
                w.int(u8, @backingInt(r.kind));
                w.int(u8, @intFromBool(r.aa) | (@as(u8, @intFromBool(r.ede != null)) << 1));
                w.int(u16, if (r.ede) |e| @backingInt(e) else 0);
                w.int(u32, r.ttl);
                w.int(i64, r.stored_ns);
                w.name(r.target);
                w.name(r.zone);
                for ([_][]const RR{ r.answers, r.authorities, r.additionals }) |sec| w.int(u16, @intCast(sec.len));
                for ([_][]const RR{ r.answers, r.authorities, r.additionals }) |sec| w.records(sec);
            },
            .ds, .dnskey => |c| {
                w.int(u8, @backingInt(c.status));
                w.int(i64, c.proven_until_ns);
                w.int(u16, @intCast(c.records.len));
                w.records(c.records);
            },
            .addr, .answer, .secure, .exchange, .refresh, .ahead, .span => unreachable,
        }
    }

    fn header(key: Key, len: usize, expires_ns: i64) Blob {
        return .{ .refs = 1, .len = @intCast(len), .name_hash = key.name_hash, .rtype = @backingInt(key.rtype), .kind = @backingInt(key.kind), .name_len = @intCast(key.name.len), .expires_ns = expires_ns };
    }

    /// The names and records returned point into `b`, which must outlive them.
    pub fn parse(arena: Allocator, b: *Blob) Allocator.Error!Value {
        var r: Reader = .{ .buf = b.payload(), .pos = b.name_len };
        return switch (@as(Kind, @fromBackingInt(b.kind))) {
            .cut => blk: {
                const zone = r.name();
                const placed_until_ns = r.int(i64);
                const servers = try arena.alloc(model.Server, r.int(u16));
                const glue = try arena.alloc(na.AddressKey, r.int(u16));
                var at: usize = 0;
                for (servers) |*server| {
                    const name = r.slice(r.int(u16));
                    server.key = .{ .kind = .addr, .rtype = .a, .name = name, .name_hash = r.int(u32) };
                    const n = r.int(u16);
                    server.glue = glue[at..][0..n];
                    at += n;
                }
                for (glue) |*gl| gl.* = r.addr();
                break :blk .{ .cut = .{ .zone = zone, .servers = servers, .placed_until_ns = placed_until_ns } };
            },
            .rrset, .stub, .span => |kind| blk: {
                const rrset = Rrset.read(&r);
                const reply: model.Reply = .{
                    .kind = rrset.kind,
                    .aa = rrset.aa,
                    .answers = try r.records(arena, rrset.counts[0]),
                    .authorities = try r.records(arena, rrset.counts[1]),
                    .additionals = try r.records(arena, rrset.counts[2]),
                    .target = .of(rrset.target),
                    .zone = .of(rrset.zone),
                    .ede = rrset.ede,
                    .stored_ns = rrset.stored_ns,
                    .ttl = rrset.ttl,
                };
                break :blk if (kind == .stub) .{ .stub = reply } else .{ .rrset = reply };
            },
            .ds, .dnskey => |kind| blk: {
                var c: model.Chain = .{ .status = @fromBackingInt(r.int(u8)) };
                c.proven_until_ns = r.int(i64);
                c.records = try r.records(arena, r.int(u16));
                break :blk if (kind == .ds) .{ .ds = c } else .{ .dnskey = c };
            },
            .addr, .answer, .secure, .exchange, .refresh, .ahead => unreachable,
        };
    }
};

pub const Rrset = struct {
    kind: model.Reply.Of,
    aa: bool,
    ede: ?dns.Ede.Code,
    ttl: u32,
    stored_ns: i64,
    target: []const u8,
    zone: []const u8,
    counts: [3]u16,
    payload: []const u8,
    records_at: usize,

    pub fn of(b: *Blob) Rrset {
        std.debug.assert(isReply(b));
        var r: Reader = .{ .buf = b.payload(), .pos = b.name_len };
        return read(&r);
    }

    pub fn answered(b: *Blob) ?Records.Iterator {
        const r = of(b);
        return if (r.kind == .answer) r.section(0).iterator() else null;
    }

    pub fn section(r: Rrset, index: usize) Records {
        const n = r.counts[index];
        if (n == 0) return .{ .payload = r.payload, .start = r.records_at, .len = 0 };
        var pos = r.records_at;
        for (r.counts[0..index]) |count| {
            var it: Records.Iterator = .{ .payload = r.payload, .pos = pos, .left = count };
            while (it.next() != null) {}
            pos = it.pos;
        }
        return .{ .payload = r.payload, .start = pos, .len = n };
    }

    fn read(r: *Reader) Rrset {
        var v: Rrset = .{
            .kind = @fromBackingInt(@as(u3, @intCast(r.int(u8)))),
            .aa = undefined,
            .ede = null,
            .ttl = undefined,
            .stored_ns = undefined,
            .target = undefined,
            .zone = undefined,
            .counts = undefined,
            .payload = r.buf,
            .records_at = undefined,
        };
        const flags = r.int(u8);
        v.aa = flags & 1 != 0;
        const ede = r.int(u16);
        if (flags & 2 != 0) v.ede = @fromBackingInt(ede);
        v.ttl = r.int(u32);
        v.stored_ns = r.int(i64);
        v.target = r.wireName();
        v.zone = r.wireName();
        for (&v.counts) |*n| n.* = r.int(u16);
        v.records_at = r.pos;
        return v;
    }
};

pub const Records = struct {
    payload: []const u8,
    start: usize,
    len: u16,

    pub fn iterator(r: Records) Iterator {
        return .{ .payload = r.payload, .pos = r.start, .left = r.len };
    }

    pub const Iterator = struct {
        payload: []const u8,
        pos: usize,
        left: u16,

        pub fn next(it: *Iterator) ?dns.ResourceRecord {
            if (it.left == 0) return null;
            it.left -= 1;
            const owner = stored(it.payload, it.pos);
            const fixed = it.payload[it.pos + owner.len ..][0..10];
            const rdata = it.payload[it.pos + owner.len + 10 ..][0..mem.readInt(u16, fixed[8..10], .big)];
            it.pos += owner.len + 10 + rdata.len;
            return .{
                .name = .of(owner.name),
                .rtype = @fromBackingInt(mem.readInt(u16, fixed[0..2], .big)),
                .rclass = @fromBackingInt(mem.readInt(u16, fixed[2..4], .big)),
                .ttl = mem.readInt(u32, fixed[4..8], .big),
                .rdata = rdata,
            };
        }
    };
};

/// A name stored whole, or a two-byte pointer (offset from the payload's
/// start) to a suffix of one stored whole, so either reads as one slice.
fn stored(payload: []const u8, at: usize) struct { name: []const u8, len: usize } {
    if (payload[at] < 0xc0) {
        const n = dns.wireNameLen(payload[at..]);
        return .{ .name = payload[at..][0..n], .len = n };
    }
    const to = (@as(usize, payload[at] & 0x3f) << 8) | payload[at + 1];
    return .{ .name = payload[to..][0..dns.wireNameLen(payload[to..])], .len = 2 };
}

/// Writes a payload after the blob's header, or only counts its length.
fn Writer(comptime measuring: bool) type {
    return struct {
        buf: if (measuring) void else []u8,
        pos: usize = payload_at,
        anchors: [3]?Anchor = @splat(null),

        const W = @This();
        const payload_at = @sizeOf(Blob);
        /// A name stored whole at `at` in the payload, as the value spells it.
        const Anchor = struct { at: usize, wire: []const u8 };

        fn int(w: *W, comptime T: type, v: T) void {
            if (!measuring) mem.writeInt(T, w.buf[w.pos..][0..@sizeOf(T)], v, .little);
            w.pos += @sizeOf(T);
        }

        fn slice(w: *W, s: []const u8) void {
            if (!measuring) @memcpy(w.buf[w.pos..][0..s.len], s);
            w.pos += s.len;
        }

        fn name(w: *W, n: dns.Name) void {
            if (n.wire.len > 2) for (w.anchors) |anchor| {
                const a = anchor orelse continue;
                const at = a.at + (suffixAt(a.wire, n.wire) orelse continue);
                if (at >= 1 << 14) continue;
                return w.slice(&.{ 0xc0 | @as(u8, @intCast(at >> 8)), @truncate(at) });
            };
            const a: Anchor = .{ .at = w.pos - payload_at, .wire = n.wire };
            w.slice(n.wire);
            if (w.anchors[1] == null) w.anchors[1] = a;
            w.anchors[2] = a;
        }

        fn suffixAt(whole: []const u8, n: []const u8) ?usize {
            var at: usize = 0;
            while (whole.len - at > n.len) at += @as(usize, whole[at]) + 1;
            return if (mem.eql(u8, whole[at..], n)) at else null;
        }

        fn addr(w: *W, k: na.AddressKey) void {
            w.int(u8, @backingInt(k.family));
            w.int(u16, k.port);
            w.slice(&k.addr);
        }

        fn records(w: *W, rrs: []const RR) void {
            for (rrs) |rr| {
                w.name(rr.name);
                w.slice(&rr.fixed());
                w.slice(rr.rdata);
            }
        }
    };
}

/// Reads a payload only as `build` wrote it, so a read never runs short.
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn int(r: *Reader, comptime T: type) T {
        defer r.pos += @sizeOf(T);
        return mem.readInt(T, r.buf[r.pos..][0..@sizeOf(T)], .little);
    }

    fn slice(r: *Reader, n: usize) []const u8 {
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }

    fn name(r: *Reader) dns.Name {
        return .of(r.wireName());
    }

    fn wireName(r: *Reader) []const u8 {
        const n = stored(r.buf, r.pos);
        r.pos += n.len;
        return n.name;
    }

    fn addr(r: *Reader) na.AddressKey {
        const family: na.Family = @fromBackingInt(@intCast(r.int(u8)));
        const port = r.int(u16);
        return .{ .family = family, .port = port, .addr = r.slice(16)[0..16].* };
    }

    fn records(r: *Reader, arena: Allocator, n: u16) Allocator.Error![]RR {
        const out = try arena.alloc(RR, n);
        var it: Records.Iterator = .{ .payload = r.buf, .pos = r.pos, .left = n };
        for (out) |*rr| rr.* = it.next().?;
        r.pos = it.pos;
        return out;
    }
};

test "a blob holds an rrset larger than any message" {
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var s: Store = .init(testing.allocator, 1 << 20, null);
    defer s.deinit();

    // A reply spells each 255-octet target in two octets past the first.
    const long = [_]u8{63} ++ @as([63]u8, @splat('z'));
    const spelled = [_]u8{ 2, 'a', 'a' } ++ long ++ long ++ long ++ [_]u8{58} ++ @as([58]u8, @splat('y')) ++ [_]u8{0};
    const zone: dns.Name = .lit("zone");
    const rrs = try arena.alloc(RR, 600);
    for (rrs, 0..) |*rr, i| {
        const target = try arena.dupe(u8, &spelled);
        target[1] = 'a' + @as(u8, @intCast(i / 26));
        target[2] = 'a' + @as(u8, @intCast(i % 26));
        rr.* = .{ .name = zone, .rtype = .ns, .rclass = .in, .ttl = 300, .rdata = target };
    }
    const reply: model.Reply = .{ .kind = .answer, .aa = true, .answers = rrs, .target = zone, .zone = zone, .ttl = 300 };
    const blob = try s.build(.of(.rrset, zone, .ns), .{ .rrset = reply }, 10);
    defer s.unref(blob);
    try testing.expect(blob.len > 2 * @as(usize, dns.max_message_len));
    const back = (try Store.parse(arena, blob)).rrset;
    try testing.expectEqual(rrs.len, back.answers.len);
    for (rrs, back.answers) |want, got| try testing.expectEqualSlices(u8, want.rdata, got.rdata);
}

test "the cap holds by eviction and admission" {
    const testing = std.testing;
    var s: Store = .init(testing.allocator, 2048, null);
    defer s.deinit();
    var names: [64][5]u8 = undefined;
    for (&names, 0..) |*buf, i| {
        const zone: dns.Name = .of(try std.mem.print(buf, "{c}k{d}\x00", .{ @as(u8, if (i < 10) 2 else 3), i }));
        const blob = try s.build(.of(.cut, zone, .a), .{ .cut = .{ .zone = zone } }, 10);
        s.put(blob) catch |err| {
            try testing.expectEqual(error.Refused, err);
            try s.put(blob);
        };
    }
    try testing.expect(s.held <= 2048);
    try testing.expect(s.evictions > 0);
    try testing.expect(s.unadmitted > 0);
    const zone: dns.Name = .lit("again");
    const key: Key = .of(.cut, zone, .a);
    const again = try s.build(key, .{ .cut = .{ .zone = zone } }, 10);
    try testing.expectError(error.Refused, s.put(again));
    try s.put(again);
    try testing.expect(s.get(key, 0) != null);
    try testing.expectEqual(s.held, s.bytes);

    s.cap = std.math.maxInt(usize);
    var fill: usize = 0;
    while (s.map.count() < s.map.capacity()) : (fill += 1) {
        var buf: [8]u8 = undefined;
        const n = try std.mem.print(buf[1..], "f{d}\x00", .{fill});
        buf[0] = @intCast(n.len - 1);
        const fzone: dns.Name = .of(buf[0 .. n.len + 1]);
        try s.put(try s.build(.of(.cut, fzone, .a), .{ .cut = .{ .zone = fzone } }, 10));
    }
    s.cap = s.held;

    const colder = try s.build(.of(.cut, .lit("colder"), .a), .{ .cut = .{ .zone = .lit("colder") } }, 10);
    defer s.unref(colder);
    {
        const saved = s.gpa;
        s.gpa = testing.failing_allocator;
        defer s.gpa = saved;
        try testing.expectError(error.Refused, s.put(colder));
    }
    const unadmitted = s.unadmitted;
    const replace = try s.build(key, .{ .cut = .{ .zone = zone } }, 10);
    try s.put(replace);
    try testing.expectEqual(unadmitted, s.unadmitted);
    try testing.expectEqual(replace, s.get(key, 0).?);
}

test "a store on a share evicts for all it holds but what only others read" {
    const testing = std.testing;
    const slab = @import("slab.zig");
    var reserve: slab.Reserve = .{};
    defer reserve.deinit();
    var kept: Share = .{};
    var facts: slab.Tenant = .in(&reserve, &kept);
    var s: Store = .init(facts.allocator(), 4096, &kept);
    var read: [64]*Blob = undefined;
    var names: [64][5]u8 = undefined;
    for (&names, &read, 0..) |*buf, *r, i| {
        const zone: dns.Name = .of(try std.mem.print(buf, "{c}k{d}\x00", .{ @as(u8, if (i < 10) 2 else 3), i }));
        const blob = try s.build(.of(.cut, zone, .a), .{ .cut = .{ .zone = zone } }, 10);
        r.* = blob.ref();
        s.put(blob) catch {
            try s.put(blob);
        };
    }
    try testing.expect(s.evictions > 0);
    try testing.expect(s.footprint() <= s.cap);
    try testing.expect(kept.held > s.cap);
    try testing.expect(s.map.count() > 1);
    for (read) |b| s.unref(b);
    s.deinit();
    reserve.drain();
    try testing.expectEqual(0, kept.held);
}

test "a replaced version leaves as one evicted" {
    const testing = std.testing;
    const Watched = struct {
        store: Store,
        n: u32 = 0,
        last: ?*Blob = null,
        fn evicted(s: *Store, b: *Blob) void {
            const w: *@This() = @fieldParentPtr("store", s);
            w.n += 1;
            w.last = b;
        }
    };
    var w: Watched = .{ .store = .init(testing.allocator, 1 << 16, null) };
    defer w.store.deinit();
    w.store.on_evict = Watched.evicted;
    const zone: dns.Name = .lit("x");
    const key: Key = .of(.cut, zone, .a);
    const first = try w.store.build(key, .{ .cut = .{ .zone = zone } }, 10);
    try w.store.put(first);
    try testing.expectEqual(0, w.n);
    try w.store.put(try w.store.build(key, .{ .cut = .{ .zone = zone } }, 10));
    try testing.expectEqual(1, w.n);
    try testing.expectEqual(first, w.last.?);
}
