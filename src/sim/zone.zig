//! A model authority. A small signed root zone drawn from a seed, with up
//! to two zones delegated from it, signed or not, written out as a
//! scenario: each question of a small universe with the reply RFC 4035
//! §3.1 has each zone's server give, then questions in a drawn order, each
//! checked against the answer a client is owed. Names, their order and the
//! replies are worked out here from labels alone, sharing nothing with the
//! code they test.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Labels from the root down. The root has none.
const Name = []const []const u8;

const alphabet = [_][]const u8{ "*", "a", "b" };
const max_depth = 3;
const max_cuts = 2;
const questions = 48;
const max_hops = 8;

const Type = enum {
    a,
    txt,
    cname,
    ns,
    ds,

    /// What a client asks. A DS is the resolver's own question.
    const asked = [_]Type{ .a, .txt, .cname, .ns };

    fn text(t: Type) []const u8 {
        return switch (t) {
            .a => "A",
            .txt => "TXT",
            .cname => "CNAME",
            .ns => "NS",
            .ds => "DS",
        };
    }
};

const Owner = struct {
    name: Name,
    a: bool = false,
    txt: bool = false,
    cname: ?Name = null,
    cut: ?*const Zone = null,
    /// Its place in the zone's order, which also tells its rdata apart.
    n: usize = 0,

    fn answers(o: *const Owner, zone: *const Zone, t: Type) ?Type {
        if (o.cname != null) return .cname;
        const held = switch (t) {
            .a => o.a,
            .txt => o.txt,
            .ns => o == &zone.owners[0],
            .cname, .ds => false,
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

fn under(name: Name, above: Name) bool {
    return name.len >= above.len and order(name[0..above.len], above) == .eq;
}

fn child(arena: Allocator, name: Name, label: []const u8) !Name {
    return mem.concat(arena, []const u8, &.{ name, &.{label} });
}

const Reply = struct {
    nxdomain: bool = false,
    answer: ?struct { from: *const Owner, type: Type } = null,
    soa: bool = false,
    /// The owners whose NSEC the reply carries.
    proofs: [2]?*const Owner = .{ null, null },
    /// The wildcard the answer was expanded from.
    wildcard: ?Name = null,
    referral: ?*const Owner = null,

    fn both(x: *const Owner, y: *const Owner) [2]?*const Owner {
        return .{ x, if (x == y) null else y };
    }
};

const Zone = struct {
    apex: Name,
    signed: bool,
    /// The last octet of its server's address, and the third of its A sets.
    address: u8,
    /// In canonical order, so the apex leads.
    owners: []Owner = &.{},
    /// Which owner is its server's name.
    host: usize = 0,

    fn at(z: *const Zone, name: Name) ?*const Owner {
        for (z.owners) |*o| if (order(o.name, name) == .eq) return o;
        return null;
    }

    /// An owner, or a name above one (RFC 4592 §2.2.2).
    fn exists(z: *const Zone, name: Name) bool {
        for (z.owners) |o| if (under(o.name, name)) return true;
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
        for (z.owners) |*o| if (o.cut) |below| if (under(name, o.name)) {
            // Only its DS is the parent's to answer at a cut (RFC 4035 §3.1.4.1).
            if (t != .ds or name.len != o.name.len) return .{ .referral = o };
            if (below.signed) return .{ .answer = .{ .from = o, .type = .ds } };
            return .{ .soa = true, .proofs = .{ o, null } };
        };
        if (z.at(name)) |o| {
            if (o.answers(z, t)) |set| return .{ .answer = .{ .from = o, .type = set } };
            return .{ .soa = true, .proofs = .{ o, null } };
        }
        const cover = z.covers(name);
        if (z.exists(name)) return .{ .soa = true, .proofs = .{ cover, null } };
        var encloser = name;
        while (!z.exists(encloser)) encloser = encloser[0 .. encloser.len - 1];
        const wildcard = try child(arena, encloser, "*");
        if (z.at(wildcard)) |o| {
            if (o.answers(z, t)) |set| return .{ .answer = .{ .from = o, .type = set }, .proofs = .{ cover, null }, .wildcard = wildcard };
            return .{ .soa = true, .proofs = Reply.both(o, cover) };
        }
        return .{ .nxdomain = !z.exists(wildcard), .soa = true, .proofs = Reply.both(cover, z.covers(wildcard)) };
    }
};

const World = struct {
    /// The root, then the zones it delegates.
    zones: []Zone,
    asked: []const Name,

    fn draw(arena: Allocator, random: std.Random) !World {
        var names: std.ArrayList(Name) = .empty;
        try names.append(arena, &.{});
        var from: usize = 0;
        for (0..max_depth) |_| {
            const until = names.items.len;
            for (from..until) |i| for (alphabet) |label| try names.append(arena, try child(arena, names.items[i], label));
            from = until;
        }
        var zones: std.ArrayList(Zone) = try .initCapacity(arena, 1 + max_cuts);
        zones.appendAssumeCapacity(.{ .apex = &.{}, .signed = true, .address = 1 });
        cuts: for (0..random.uintAtMost(u8, max_cuts)) |_| {
            const apex = names.items[1 + random.uintLessThan(usize, alphabet.len * (1 + alphabet.len))];
            // What NS at a wildcard means is left open (RFC 4592 §4.2).
            if (mem.eql(u8, apex[apex.len - 1], "*")) continue;
            for (zones.items[1..]) |z| if (under(apex, z.apex) or under(z.apex, apex)) continue :cuts;
            zones.appendAssumeCapacity(.{ .apex = apex, .signed = random.boolean(), .address = @intCast(1 + zones.items.len) });
        }
        const sparse = 4 + random.uintLessThan(u8, 28);
        for (zones.items) |*z| {
            var owners: std.ArrayList(Owner) = .empty;
            try owners.append(arena, .{ .name = z.apex });
            try owners.append(arena, .{ .name = try child(arena, z.apex, "ns"), .a = true });
            if (z.apex.len == 0) for (zones.items[1..]) |*below| try owners.append(arena, .{ .name = below.apex, .cut = below });
            for (names.items[1..]) |name| {
                if (holder(zones.items, name) != z or name.len == z.apex.len) continue;
                switch (random.uintLessThan(u8, sparse)) {
                    0 => try owners.append(arena, .{ .name = name, .a = true }),
                    1 => try owners.append(arena, .{ .name = name, .txt = true }),
                    2 => try owners.append(arena, .{ .name = name, .a = true, .txt = true }),
                    3 => try owners.append(arena, .{ .name = name, .cname = names.items[random.uintLessThan(usize, names.items.len)] }),
                    else => {},
                }
            }
            mem.sort(Owner, owners.items, {}, Owner.before);
            for (owners.items, 0..) |*o, i| {
                o.n = i;
                if (o.name.len == z.apex.len + 1 and mem.eql(u8, o.name[z.apex.len], "ns")) z.host = i;
            }
            z.owners = owners.items;
        }
        for (zones.items) |z| try names.append(arena, try child(arena, z.apex, "ns"));
        return .{ .zones = zones.items, .asked = names.items };
    }

    fn holder(zones: []const Zone, name: Name) *const Zone {
        for (zones[1..]) |*z| if (under(name, z.apex)) return z;
        return &zones[0];
    }
};

const Writer = struct {
    arena: Allocator,
    w: *const World,
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

    fn record(w: *Writer, z: *const Zone, name: Name, from: *const Owner, t: Type) !void {
        const owner = try w.dotted(name);
        const host = try w.dotted(z.owners[z.host].name);
        switch (t) {
            .a => if (from.n == z.host) try w.line("{s} 3600 IN A 127.0.10.{d}", .{ owner, z.address }) else try w.line("{s} 3600 IN A 192.0.{d}.{d}", .{ owner, z.address, from.n }),
            .txt => try w.line("{s} 3600 IN TXT t{d}-{d}", .{ owner, z.address, from.n }),
            .cname => try w.line("{s} 3600 IN CNAME {s}", .{ owner, try w.dotted(from.cname.?) }),
            .ns => try w.line("{s} 3600 IN NS {s}", .{ owner, host }),
            .ds => try w.line("{s} 3600 IN DS placeholder", .{owner}),
        }
    }

    fn nsec(w: *Writer, z: *const Zone, o: *const Owner) !void {
        const owner = try w.dotted(o.name);
        const after = try w.dotted(z.next(o).name);
        if (o.n == 0) return w.line("{s} 3600 IN NSEC {s} NS SOA RRSIG NSEC DNSKEY", .{ owner, after });
        if (o.cut) |below| return w.line("{s} 3600 IN NSEC {s} NS{s} RRSIG NSEC", .{ owner, after, if (below.signed) " DS" else "" });
        try w.line("{s} 3600 IN NSEC {s}{s}{s}{s} RRSIG NSEC", .{ owner, after, if (o.a) " A" else "", if (o.txt) " TXT" else "", if (o.cname != null) " CNAME" else "" });
    }

    fn question(w: *Writer, name: Name, t: Type) !void {
        try w.line("SECTION QUESTION", .{});
        try w.line("{s} IN {s}", .{ try w.dotted(name), t.text() });
    }

    fn referral(w: *Writer, z: *const Zone, cut: *const Owner) !void {
        const below = cut.cut.?;
        try w.line("SECTION AUTHORITY", .{});
        try w.record(below, cut.name, &below.owners[0], .ns);
        if (below.signed) try w.record(z, cut.name, cut, .ds) else try w.nsec(z, cut);
        try w.line("SECTION ADDITIONAL", .{});
        try w.record(below, below.owners[below.host].name, &below.owners[below.host], .a);
    }

    fn entry(w: *Writer, z: *const Zone, name: Name, t: Type) !void {
        const r = try z.reply(w.arena, name, t);
        try w.line("ENTRY_BEGIN", .{});
        try w.line("MATCH opcode qname qtype", .{});
        try w.line("ADJUST copy_id copy_query{s}", .{if (z.signed) "" else " unsigned"});
        try w.line("REPLY QR{s} {s}", .{ if (r.referral == null) " AA" else "", if (r.nxdomain) "NXDOMAIN" else "NOERROR" });
        if (r.wildcard) |wildcard| try w.line("WILDCARD {s}", .{try w.dotted(wildcard)});
        // A signed cut's NSEC is its parent's to sign, which the signer
        // only knows of a referral.
        for (r.proofs) |proof| if (proof) |o| if (o.cut) |below| if (below.signed) try w.line("SIGN_AS {s}", .{try w.dotted(z.apex)});
        try w.question(name, t);
        if (r.referral) |cut| {
            try w.referral(z, cut);
            return w.line("ENTRY_END", .{});
        }
        if (r.answer) |a| {
            try w.line("SECTION ANSWER", .{});
            try w.record(z, name, a.from, a.type);
        }
        try w.line("SECTION AUTHORITY", .{});
        if (r.soa) try w.line("{s} 3600 IN SOA {s} nobody.invalid. 1 7200 3600 86400 3600", .{ try w.dotted(z.apex), try w.dotted(z.owners[z.host].name) });
        if (z.signed) for (r.proofs) |proof| if (proof) |o| try w.nsec(z, o);
        try w.line("ENTRY_END", .{});
    }

    /// A question and the answer a client is owed, authentic if every zone
    /// on the way is signed. False, with nothing written, where the aliases
    /// run on: how long a chain may be is the resolver's to say.
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
        var authentic = true;
        const last = while (true) : (hops += 1) {
            const z = World.holder(w.w.zones, hop);
            authentic = authentic and z.signed;
            const r = try z.reply(w.arena, hop, t);
            const a = r.answer orelse break r;
            try w.record(z, hop, a.from, a.type);
            if (a.type == t) break r;
            if (hops == max_hops) {
                w.out.shrinkRetainingCapacity(start);
                return false;
            }
            hop = a.from.cname.?;
        };
        try w.line("ENTRY_END", .{});
        const reply = try w.arena.print("REPLY QR RD RA{s} {s}\n", .{ if (authentic) " AD" else "", if (last.nxdomain) "NXDOMAIN" else "NOERROR" });
        try w.out.insertSlice(w.arena, flags, reply);
        return true;
    }
};

pub fn scenario(arena: Allocator, seed: u64) ![]const u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    const world: World = try .draw(arena, random);
    var w: Writer = .{ .arena = arena, .w = &world };
    try w.line("; hark: root-hints = 127.0.10.1", .{});
    for (world.zones) |z| if (z.signed) try w.line("; hark: dnssec-zone = {s}", .{try w.dotted(z.apex)});
    try w.line("SCENARIO_BEGIN a drawn zone, seed {d}", .{seed});
    for (world.zones) |*z| {
        try w.line("RANGE_BEGIN 0 {d}", .{2 * questions});
        try w.line("ADDRESS 127.0.10.{d}", .{z.address});
        for (world.asked) |name| if (under(name, z.apex)) for (std.enums.values(Type)) |t| try w.entry(z, name, t);
        try w.line("RANGE_END", .{});
    }
    var n: u32 = 1;
    for (0..questions) |_| {
        const name = world.asked[random.uintLessThan(usize, world.asked.len)];
        if (try w.step(n, name, Type.asked[random.uintLessThan(usize, Type.asked.len)])) n += 2;
    }
    try w.line("SCENARIO_END", .{});
    return w.out.items;
}
