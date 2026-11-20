//! A model authority. One small signed zone at the root, drawn from a seed
//! and written out as a scenario: each question of a small universe with
//! the reply RFC 4035 §3.1.3 has the zone give, then questions in a drawn
//! order, each checked against the zone's answer followed down its
//! aliases. Names, their order and the replies are worked out here from
//! labels alone, sharing nothing with the code they test.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Labels from the root down. The root has none.
const Name = []const []const u8;

const alphabet = [_][]const u8{ "*", "a", "b" };
const max_depth = 3;
const ns_host: Name = &.{"ns"};
const questions = 48;
const max_hops = 8;

const Type = enum {
    a,
    txt,
    cname,
    ns,

    fn text(t: Type) []const u8 {
        return switch (t) {
            .a => "A",
            .txt => "TXT",
            .cname => "CNAME",
            .ns => "NS",
        };
    }
};

const Owner = struct {
    name: Name,
    a: bool = false,
    txt: bool = false,
    cname: ?Name = null,
    /// Tells its rdata from every other owner's.
    n: usize = 0,

    /// The set of this owner that answers a question of type `t`.
    fn answers(o: *const Owner, t: Type) ?Type {
        if (o.cname != null) return .cname;
        const held = switch (t) {
            .a => o.a,
            .txt => o.txt,
            .cname => false,
            .ns => o.name.len == 0,
        };
        return if (held) t else null;
    }

    fn before(_: void, x: Owner, y: Owner) bool {
        return order(x.name, y.name) == .lt;
    }
};

/// RFC 4034 §6.1: by label from the root, each as its octets, the shorter first.
fn order(x: Name, y: Name) std.math.Order {
    const shared = @min(x.len, y.len);
    for (x[0..shared], y[0..shared]) |p, q| {
        const o = mem.order(u8, p, q);
        if (o != .eq) return o;
    }
    return std.math.order(x.len, y.len);
}

const Reply = struct {
    nxdomain: bool = false,
    answer: ?struct { from: *const Owner, type: Type } = null,
    soa: bool = false,
    /// The owners whose NSEC the reply carries.
    proofs: [2]?*const Owner = .{ null, null },
    /// The wildcard the answer was expanded from.
    wildcard: ?Name = null,

    fn both(x: *const Owner, y: *const Owner) [2]?*const Owner {
        return .{ x, if (x == y) null else y };
    }
};

const Zone = struct {
    /// In canonical order, so the apex leads.
    owners: []const Owner,
    /// Every name a question may hold.
    asked: []const Name,

    fn draw(arena: Allocator, random: std.Random) !Zone {
        var asked: std.ArrayList(Name) = .empty;
        try asked.append(arena, &.{});
        var from: usize = 0;
        for (0..max_depth) |_| {
            const until = asked.items.len;
            for (from..until) |i| for (alphabet) |label| {
                const child = try mem.concat(arena, []const u8, &.{ asked.items[i], &.{label} });
                try asked.append(arena, child);
            };
            from = until;
        }
        var owners: std.ArrayList(Owner) = .empty;
        try owners.append(arena, .{ .name = &.{} });
        try owners.append(arena, .{ .name = ns_host, .a = true });
        const sparse = 4 + random.uintLessThan(u8, 28);
        for (asked.items[1..]) |name| switch (random.uintLessThan(u8, sparse)) {
            0 => try owners.append(arena, .{ .name = name, .a = true }),
            1 => try owners.append(arena, .{ .name = name, .txt = true }),
            2 => try owners.append(arena, .{ .name = name, .a = true, .txt = true }),
            3 => try owners.append(arena, .{ .name = name, .cname = asked.items[random.uintLessThan(usize, asked.items.len)] }),
            else => {},
        };
        try asked.append(arena, ns_host);
        mem.sort(Owner, owners.items, {}, Owner.before);
        for (owners.items, 0..) |*o, i| o.n = i;
        return .{ .owners = owners.items, .asked = asked.items };
    }

    fn at(z: *const Zone, name: Name) ?*const Owner {
        for (z.owners) |*o| if (order(o.name, name) == .eq) return o;
        return null;
    }

    /// An owner, or a name above one (RFC 4592 §2.2.2).
    fn exists(z: *const Zone, name: Name) bool {
        for (z.owners) |o| if (o.name.len >= name.len and order(o.name[0..name.len], name) == .eq) return true;
        return false;
    }

    fn covers(z: *const Zone, name: Name) *const Owner {
        var last = &z.owners[0];
        for (z.owners) |*o| if (order(o.name, name) == .lt) {
            last = o;
        };
        return last;
    }

    fn next(z: *const Zone, o: *const Owner) *const Owner {
        return &z.owners[(o.n + 1) % z.owners.len];
    }

    fn reply(z: *const Zone, arena: Allocator, name: Name, t: Type) !Reply {
        if (z.at(name)) |o| {
            if (o.answers(t)) |set| return .{ .answer = .{ .from = o, .type = set } };
            return .{ .soa = true, .proofs = .{ o, null } };
        }
        const cover = z.covers(name);
        if (z.exists(name)) return .{ .soa = true, .proofs = .{ cover, null } };
        var encloser = name;
        while (!z.exists(encloser)) encloser = encloser[0 .. encloser.len - 1];
        const wildcard = try mem.concat(arena, []const u8, &.{ encloser, &.{"*"} });
        if (z.at(wildcard)) |o| {
            if (o.answers(t)) |set| return .{ .answer = .{ .from = o, .type = set }, .proofs = .{ cover, null }, .wildcard = wildcard };
            return .{ .soa = true, .proofs = Reply.both(o, cover) };
        }
        return .{ .nxdomain = !z.exists(wildcard), .soa = true, .proofs = Reply.both(cover, z.covers(wildcard)) };
    }
};

const Writer = struct {
    arena: Allocator,
    z: *const Zone,
    out: std.ArrayList(u8) = .empty,

    fn line(w: *Writer, comptime fmt: []const u8, args: anytype) !void {
        try w.out.print(w.arena, fmt ++ "\n", args);
    }

    fn dotted(w: *Writer, name: Name) ![]const u8 {
        if (name.len == 0) return ".";
        var text: std.ArrayList(u8) = .empty;
        var i = name.len;
        while (i > 0) : (i -= 1) {
            try text.appendSlice(w.arena, name[i - 1]);
            try text.append(w.arena, '.');
        }
        return text.items;
    }

    fn record(w: *Writer, name: Name, from: *const Owner, t: Type) !void {
        const owner = try w.dotted(name);
        switch (t) {
            .a => if (order(from.name, ns_host) == .eq) try w.line("{s} 3600 IN A 127.0.10.1", .{owner}) else try w.line("{s} 3600 IN A 192.0.2.{d}", .{ owner, from.n }),
            .txt => try w.line("{s} 3600 IN TXT t{d}", .{ owner, from.n }),
            .cname => try w.line("{s} 3600 IN CNAME {s}", .{ owner, try w.dotted(from.cname.?) }),
            .ns => try w.line("{s} 3600 IN NS ns.", .{owner}),
        }
    }

    fn nsec(w: *Writer, o: *const Owner) !void {
        const owner = try w.dotted(o.name);
        const after = try w.dotted(w.z.next(o).name);
        if (o.name.len == 0) return w.line("{s} 3600 IN NSEC {s} NS SOA RRSIG NSEC DNSKEY", .{ owner, after });
        try w.line("{s} 3600 IN NSEC {s}{s}{s}{s} RRSIG NSEC", .{ owner, after, if (o.a) " A" else "", if (o.txt) " TXT" else "", if (o.cname != null) " CNAME" else "" });
    }

    fn question(w: *Writer, name: Name, t: Type) !void {
        try w.line("SECTION QUESTION", .{});
        try w.line("{s} IN {s}", .{ try w.dotted(name), t.text() });
    }

    fn entry(w: *Writer, name: Name, t: Type) !void {
        const r = try w.z.reply(w.arena, name, t);
        try w.line("ENTRY_BEGIN", .{});
        try w.line("MATCH opcode qname qtype", .{});
        try w.line("ADJUST copy_id copy_query", .{});
        try w.line("REPLY QR AA {s}", .{if (r.nxdomain) "NXDOMAIN" else "NOERROR"});
        if (r.wildcard) |wildcard| try w.line("WILDCARD {s}", .{try w.dotted(wildcard)});
        try w.question(name, t);
        if (r.answer) |a| {
            try w.line("SECTION ANSWER", .{});
            try w.record(name, a.from, a.type);
        }
        try w.line("SECTION AUTHORITY", .{});
        if (r.soa) try w.line(". 3600 IN SOA ns. nobody.invalid. 1 7200 3600 86400 3600", .{});
        for (r.proofs) |proof| if (proof) |o| try w.nsec(o);
        try w.line("ENTRY_END", .{});
    }

    /// A question and the answer a client is owed. False, with nothing
    /// written, where the aliases run on: how long a chain may be is the
    /// resolver's to say.
    fn step(w: *Writer, n: u32, name: Name, t: Type) !bool {
        const start = w.out.items.len;
        try w.line("STEP {d} QUERY", .{n});
        try w.line("ENTRY_BEGIN", .{});
        try w.line("REPLY RD DO", .{});
        try w.question(name, t);
        try w.line("ENTRY_END", .{});
        try w.line("STEP {d} CHECK_ANSWER", .{n + 1});
        try w.line("ENTRY_BEGIN", .{});
        try w.line("MATCH flags question answer", .{});
        const flags = w.out.items.len;
        try w.question(name, t);
        try w.line("SECTION ANSWER", .{});
        var hop = name;
        var hops: usize = 0;
        const last = while (true) : (hops += 1) {
            const r = try w.z.reply(w.arena, hop, t);
            const a = r.answer orelse break r;
            try w.record(hop, a.from, a.type);
            if (a.type == t) break r;
            if (hops == max_hops) {
                w.out.shrinkRetainingCapacity(start);
                return false;
            }
            hop = a.from.cname.?;
        };
        try w.line("ENTRY_END", .{});
        const reply = try w.arena.print("REPLY QR RD RA AD {s}\n", .{if (last.nxdomain) "NXDOMAIN" else "NOERROR"});
        try w.out.insertSlice(w.arena, flags, reply);
        return true;
    }
};

pub fn scenario(arena: Allocator, seed: u64) ![]const u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    const z: Zone = try .draw(arena, random);
    var w: Writer = .{ .arena = arena, .z = &z };
    try w.line("; hark: root-hints = 127.0.10.1", .{});
    try w.line("; hark: dnssec-zone = .", .{});
    try w.line("SCENARIO_BEGIN a drawn zone, seed {d}", .{seed});
    try w.line("RANGE_BEGIN 0 {d}", .{2 * questions});
    try w.line("ADDRESS 127.0.10.1", .{});
    for (z.asked) |name| for (std.enums.values(Type)) |t| try w.entry(name, t);
    try w.line("RANGE_END", .{});
    var n: u32 = 1;
    for (0..questions) |_| {
        const name = z.asked[random.uintLessThan(usize, z.asked.len)];
        if (try w.step(n, name, random.enumValue(Type))) n += 2;
    }
    try w.line("SCENARIO_END", .{});
    return w.out.items;
}
