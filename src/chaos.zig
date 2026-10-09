//! Draws are keyed by the event they decide, not by draw order, so a run
//! that decides one thing differently decides nothing else differently.
const std = @import("std");
const graph = @import("graph.zig");

pub const Site = enum(u8) { settle };

pub const Chaos = struct {
    gpa: std.mem.Allocator,
    seed: u64,
    decided: std.AutoHashMapUnmanaged(u64, u32) = .empty,

    pub fn deinit(c: *Chaos) void {
        c.decided.deinit(c.gpa);
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
};

/// One of `n` for `event`; the bias, n / 2^64, never shows.
pub fn draw(event: u64, n: u64) u64 {
    return @intCast(std.math.mulWide(u64, std.hash.Wyhash.hash(event, "draw"), n) >> 64);
}
