//! The simulator's chaos: seeded draws over the choices hark is free to
//! make, at each `Site`, and the events that drew, for shrinking a failure.
const std = @import("std");
const dns = @import("dns.zig");
const model = @import("model.zig");
const na = @import("net_address.zig");

pub const Site = enum(u8) { settle, pick, gather, stagger, memo, ahead, prefetch, payer, tie, budget, rto, dead, forget, keep, carrier };

pub const Events = std.array_hash_map.Auto(u64, void);

const About = union(enum) {
    key: model.Key,
    server: na.AddressKey,
    none,
};

pub const Chaos = struct {
    gpa: std.mem.Allocator,
    seed: u64,
    decided: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    forgot: bool = false,
    only: ?*const Events = null,
    left: Events = .empty,
    fired: std.EnumArray(Site, u32) = .initFill(0),
    told: ?std.ArrayList([]const u8) = null,

    pub fn deinit(c: *Chaos) void {
        c.decided.deinit(c.gpa);
        c.left.deinit(c.gpa);
        if (c.told) |*t| {
            for (t.items) |s| c.gpa.free(s);
            t.deinit(c.gpa);
        }
    }

    pub fn live(c: *const Chaos, site: Site) bool {
        return std.hash.Wyhash.hash(c.seed, std.mem.asBytes(&site)) & 1 == 1;
    }

    pub fn peek(c: *const Chaos, site: Site, key: model.Key) u64 {
        const of = c.keyed(site, key);
        return c.named(site, of ^ @as(u64, c.decided.get(of) orelse 0));
    }

    pub fn spend(c: *Chaos, site: Site, key: model.Key) !void {
        const n = try c.decided.getOrPut(c.gpa, c.keyed(site, key));
        n.value_ptr.* = if (n.found_existing) n.value_ptr.* + 1 else 1;
    }

    pub fn named(c: *const Chaos, site: Site, name: u64) u64 {
        var h = std.hash.Wyhash.init(c.seed);
        h.update(std.mem.asBytes(&site));
        h.update(std.mem.asBytes(&name));
        return h.final();
    }

    fn keyed(c: *const Chaos, site: Site, key: model.Key) u64 {
        var h = std.hash.Wyhash.init(c.seed);
        h.update(std.mem.asBytes(&site));
        h.update(std.mem.asBytes(&key.kind));
        h.update(std.mem.asBytes(&key.rtype));
        h.update(key.name);
        return h.final();
    }

    /// A draw of 0 is what hark does without chaos: every caller relies on it.
    fn draw(c: *const Chaos, event: u64, n: u64) u64 {
        if (c.only) |only| if (!only.contains(event)) return 0;
        return @intCast(std.math.mulWide(u64, std.hash.Wyhash.hash(event, "draw"), n) >> 64);
    }

    /// Fails having noted nothing, so a caller that takes 0 on failure
    /// decides what a replay without this event decides.
    pub fn choose(c: *Chaos, site: Site, event: u64, n: u64, about: About) !u64 {
        const v = c.draw(event, n);
        if (v != 0) try c.note(site, event, about);
        return v;
    }

    fn note(c: *Chaos, site: Site, event: u64, about: About) !void {
        if (c.left.contains(event)) return;
        try c.left.ensureUnusedCapacity(c.gpa, 1);
        if (c.told) |*told| {
            try told.ensureUnusedCapacity(c.gpa, 1);
            var buf: [64]u8 = undefined;
            var nb: [dns.max_dotted_len + 1]u8 = undefined;
            told.appendAssumeCapacity(switch (about) {
                .key => |k| try c.gpa.print("{t} {t}({s} {f})", .{ site, k.kind, k.shown(&nb), dns.tag(k.rtype) }),
                .server => |s| try c.gpa.print("{t} {s}", .{ site, na.format(s.toAddress(), &buf) }),
                .none => try c.gpa.print("{t}", .{site}),
            });
        }
        c.left.putAssumeCapacity(event, {});
        c.fired.getPtr(site).* += 1;
    }
};
