//! Draws are keyed by the event they decide, not by draw order, so a run
//! that decides one thing differently decides no other live site's
//! differently. A site that is off and random by design (pick, gather,
//! prefetch) draws from the edge's rng in order, as without chaos.
//! A draw of 0 is what hark does without chaos, or, where hark draws
//! too, the first.
const std = @import("std");
const graph = @import("graph.zig");
const na = @import("net_address.zig");

pub const Site = enum(u8) { settle, pick, gather, stagger, memo, ahead, prefetch, payer, tie, budget, rto, dead, forget, keep };

pub const Events = std.AutoArrayHashMapUnmanaged(u64, void);

/// What an event decided about, for a shrunk failure's report.
pub const About = union(enum) {
    key: graph.Key,
    server: na.AddressKey,
    none,
};

pub const Chaos = struct {
    gpa: std.mem.Allocator,
    seed: u64,
    decided: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    /// Hark forgot something it would have held: a limit, unseen by any
    /// one answer.
    forgot: bool = false,
    /// Shrinking: only these events may draw other than 0.
    only: ?*const Events = null,
    /// Every event that drew other than 0.
    left: Events = .empty,
    fired: std.EnumArray(Site, u32) = .initFill(0),
    /// Names each event that left, gpa-owned.
    told: ?std.ArrayList([]const u8) = null,

    pub fn deinit(c: *Chaos) void {
        c.decided.deinit(c.gpa);
        c.left.deinit(c.gpa);
        if (c.told) |*t| {
            for (t.items) |s| c.gpa.free(s);
            t.deinit(c.gpa);
        }
    }

    /// Each site is on or off for the whole run (swarm testing): a
    /// feature left off cannot hide a bug the others reach.
    pub fn live(c: *const Chaos, site: Site) bool {
        return std.hash.Wyhash.hash(c.seed, std.mem.asBytes(&site)) & 1 == 1;
    }

    /// The event of `key`'s next decision at `site`.
    pub fn peek(c: *const Chaos, site: Site, key: graph.Key) u64 {
        const of = c.keyed(site, key);
        return c.named(site, of ^ @as(u64, c.decided.get(of) orelse 0));
    }

    /// After which `key` decides afresh.
    pub fn spend(c: *Chaos, site: Site, key: graph.Key) !void {
        const n = try c.decided.getOrPut(c.gpa, c.keyed(site, key));
        n.value_ptr.* = if (n.found_existing) n.value_ptr.* + 1 else 1;
    }

    /// The event at `site` that `name` stands for: a key's nth decision,
    /// or what a draw no key decides is about.
    pub fn named(c: *const Chaos, site: Site, name: u64) u64 {
        var h = std.hash.Wyhash.init(c.seed);
        h.update(std.mem.asBytes(&site));
        h.update(std.mem.asBytes(&name));
        return h.final();
    }

    fn keyed(c: *const Chaos, site: Site, key: graph.Key) u64 {
        var h = std.hash.Wyhash.init(c.seed);
        h.update(std.mem.asBytes(&site));
        h.update(std.mem.asBytes(&key.kind));
        h.update(std.mem.asBytes(&key.rtype));
        h.update(key.name);
        return h.final();
    }

    /// One of `n` for `event`, unnoted; the bias, n / 2^64, never shows.
    pub fn draw(c: *const Chaos, event: u64, n: u64) u64 {
        if (c.only) |only| if (!only.contains(event)) return 0;
        return @intCast(std.math.mulWide(u64, std.hash.Wyhash.hash(event, "draw"), n) >> 64);
    }

    /// Fails having noted nothing, so a caller that takes 0 on failure
    /// decided what a replay without this event decides.
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
            told.appendAssumeCapacity(switch (about) {
                .key => |k| try std.fmt.allocPrint(c.gpa, "{t} {t}({s} {t})", .{ site, k.kind, k.name, k.rtype }),
                .server => |s| try std.fmt.allocPrint(c.gpa, "{t} {s}", .{ site, na.format(s.toAddress(), &buf) }),
                .none => try std.fmt.allocPrint(c.gpa, "{t}", .{site}),
            });
        }
        c.left.putAssumeCapacity(event, {});
        c.fired.getPtr(site).* += 1;
    }
};
