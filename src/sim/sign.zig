//! The simulator's signer: test/harness/dnssec.py and the responder's
//! pre-baking, from the seed. One ECDSA P-256 key per declared zone (RFC
//! 6605, flags 256, SHA-256 DS); a placeholder DS takes the child's digest;
//! every RRset gets an RRSIG from the zone the cut rules say owns it,
//! inception a day back, expiry a year out.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("../dns.zig");
const dnssec = @import("../dnssec.zig");
const na = @import("../net_address.zig");
const rpl = @import("rpl.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const RR = dns.ResourceRecord;

pub const Key = struct {
    zone: dns.Name,
    pair: Ecdsa.KeyPair,
    dnskey: dns.DnskeyData,
    key_tag: u16,
    ds: dns.DsData,

    fn init(arena: Allocator, zone: dns.Name, seed: u64) !Key {
        var h = Sha256.init(.{});
        h.update(mem.asBytes(&seed));
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        h.update(zone.formatLower(&buf));
        const pair = try Ecdsa.KeyPair.generateDeterministic(h.finalResult());
        // RFC 6605 §4: the uncompressed point without its 0x04 prefix.
        const sec1 = pair.public_key.toUncompressedSec1();
        const dnskey: dns.DnskeyData = .{ .flags = 256, .protocol = 3, .algorithm = .ecdsap256sha256, .public_key = try arena.dupe(u8, sec1[1..]) };
        const tag = dnssec.keyTag(dnskey);
        return .{
            .zone = zone,
            .pair = pair,
            .dnskey = dnskey,
            .key_tag = tag,
            .ds = .{ .key_tag = tag, .algorithm = .ecdsap256sha256, .digest_type = .sha256, .digest = try arena.dupe(u8, &try dnssec.dsDigest(Sha256, zone, dnskey)) },
        };
    }
};

pub const Signer = struct {
    arena: Allocator,
    keys: []Key,
    /// Wall seconds at minting.
    now: i64,
    /// Where each zone signed something: the addresses answering its
    /// DNSKEY. A forced signer (SIGN_AS) registers nothing.
    served: std.ArrayList(Served) = .empty,

    const Served = struct { address: na.Address, key: *const Key };

    pub fn init(arena: Allocator, scenario: *const rpl.Scenario, seed: u64, wall_sec: i64) !Signer {
        const keys = try arena.alloc(Key, scenario.dnssec_zones.len);
        for (keys, scenario.dnssec_zones) |*k, z| k.* = try Key.init(arena, try dns.parseDottedName(arena, z), seed);
        return .{ .arena = arena, .keys = keys, .now = wall_sec };
    }

    /// The first declared zone's DS: the root, by the loader's rule.
    pub fn anchor(self: *const Signer) ?dns.DsData {
        return if (self.keys.len > 0) self.keys[0].ds else null;
    }

    /// The ranges with placeholder DS records filled in and RRSIGs appended.
    pub fn bake(self: *Signer, ranges: []const rpl.Range) ![]const rpl.Range {
        if (self.keys.len == 0) return ranges;
        const out = try self.arena.dupe(rpl.Range, ranges);
        for (out) |*r| {
            const entries = try self.arena.dupe(rpl.Entry, r.entries);
            for (entries) |*e| try self.bakeEntry(e, r.address);
            r.entries = entries;
        }
        return out;
    }

    /// responder.py `_delegation_cuts`: a DS owner is a cut; a referral
    /// (empty answer, NS and no SOA in authority) cuts at the NS owner too.
    fn bakeEntry(self: *Signer, e: *rpl.Entry, address: na.Address) !void {
        const forced = if (e.sign_as) |z| self.keyNamed(z) else null;
        var cuts: std.ArrayList(dns.Name) = .empty;
        for ([_][]const RR{ e.answers, e.authorities, e.additionals }) |sec| for (sec) |rr| if (rr.rtype == .ds) try addName(self.arena, &cuts, rr.name);
        var soa = false;
        for (e.authorities) |rr| soa = soa or rr.rtype == .soa;
        if (e.answers.len == 0 and !soa) for (e.authorities) |rr| if (rr.rtype == .ns) try addName(self.arena, &cuts, rr.name);
        e.answers = try self.bakeSection(e.answers, e.ds_from, cuts.items, forced, address, e.wildcard);
        e.authorities = try self.bakeSection(e.authorities, e.ds_from, cuts.items, forced, address, null);
        e.additionals = try self.bakeSection(e.additionals, e.ds_from, cuts.items, forced, address, null);
    }

    fn bakeSection(self: *Signer, rrs: []const RR, ds_from: []const rpl.DsFrom, cuts: []const dns.Name, forced: ?*const Key, address: na.Address, wildcard: ?dns.Name) ![]const RR {
        var out: std.ArrayList(RR) = .empty;
        try out.appendSlice(self.arena, rrs);
        // Key tag 0: a placeholder DS.
        for (out.items) |*rr| if (rr.rtype == .ds and rr.rdata.ds.key_tag == 0) {
            var zone = rr.name;
            for (ds_from) |d| if (d.owner.eql(rr.name)) {
                zone = d.zone;
            };
            const key = self.keyNamed(zone) orelse return error.PlaceholderDsWithoutKey;
            rr.rdata = .{ .ds = key.ds };
        };
        const originals = out.items[0..out.items.len];
        for (originals, 0..) |head, i| {
            if (head.rtype == .rrsig) continue;
            var first = true;
            for (originals[0..i]) |prev| first = first and !(prev.rtype == head.rtype and prev.name.eql(head.name));
            if (!first) continue;
            // RFC 6672 §5.3.1: a CNAME synthesised under a DNAME travels
            // unsigned.
            var synthesised = false;
            if (head.rtype == .cname) for (originals) |o| {
                synthesised = synthesised or (o.rtype == .dname and !head.name.eql(o.name) and head.name.isSubdomainOf(o.name));
            };
            if (synthesised) continue;
            const key = forced orelse self.keyFor(head.name, head.rtype, cuts) orelse continue;
            if (forced == null) try self.register(address, key);
            var covered = false;
            for (originals) |o| covered = covered or (o.rtype == .rrsig and o.name.eql(head.name) and o.rdata.rrsig.type_covered == head.rtype);
            if (covered) continue;
            var set: [dnssec.SignedData.max_entries]RR = undefined;
            var n: usize = 0;
            for (originals) |rr| if (rr.rtype == head.rtype and rr.name.eql(head.name)) {
                set[n] = rr;
                n += 1;
            };
            try out.append(self.arena, try self.sign(key, set[0..n], wildcard));
        }
        return out.items;
    }

    /// responder.py `_signer_for`: the deepest signed zone enclosing the
    /// owner; a DS, or an NSEC exactly at a cut, is the parent's; anything
    /// else at or below a cut is nobody's here.
    fn keyFor(self: *const Signer, owner: dns.Name, rtype: dns.RType, cuts: []const dns.Name) ?*const Key {
        if (rtype == .ds) return self.deepest(owner, true);
        for (cuts) |c| if (c.eql(owner) and rtype == .nsec) return self.deepest(owner, true);
        for (cuts) |c| if (owner.isSubdomainOf(c)) return null;
        return self.deepest(owner, false);
    }

    fn deepest(self: *const Signer, owner: dns.Name, strictly_above: bool) ?*const Key {
        var best: ?*const Key = null;
        for (self.keys) |*k| {
            if (!owner.isSubdomainOf(k.zone) or (strictly_above and k.zone.eql(owner))) continue;
            if (best == null or k.zone.labels.len > best.?.zone.labels.len) best = k;
        }
        return best;
    }

    fn keyNamed(self: *const Signer, zone: dns.Name) ?*const Key {
        for (self.keys) |*k| if (k.zone.eql(zone)) return k;
        return null;
    }

    fn register(self: *Signer, address: na.Address, key: *const Key) !void {
        for (self.served.items) |s| if (s.key == key and na.ipEqual(s.address, address)) return;
        try self.served.append(self.arena, .{ .address = address, .key = key });
    }

    /// One RRSIG over `set` (one owner, type and TTL); with `wildcard`, as
    /// an expansion of that owner.
    pub fn sign(self: *Signer, key: *const Key, set: []const RR, wildcard: ?dns.Name) !RR {
        const head = set[0];
        var rrsig: dns.RrsigData = .{
            .type_covered = head.rtype,
            .algorithm = .ecdsap256sha256,
            .labels = @intCast(dnssec.signedLabels(wildcard orelse head.name)),
            .original_ttl = head.ttl,
            .sig_expiration = @intCast(self.now + 365 * 86400),
            .sig_inception = @intCast(self.now - 86400),
            .key_tag = key.key_tag,
            .signer_name = key.zone,
            .signature = &.{},
        };
        var buf: [8192]u8 = undefined;
        const data = try dnssec.buildSignedData(&buf, rrsig, set);
        var s = try key.pair.signer(null);
        data.feed(&s);
        const sig = try s.finalize();
        rrsig.signature = try self.arena.dupe(u8, &sig.toBytes());
        return .{ .name = head.name, .rtype = .rrsig, .rclass = .in, .ttl = head.ttl, .rdata = .{ .rrsig = rrsig } };
    }

    /// An unmatched DNSKEY question: the zone's key, self-signed, from an
    /// address that signs as it.
    pub fn dnskeyAnswer(self: *Signer, address: na.Address, q: dns.Question) !?[]const RR {
        if (q.qtype != .dnskey) return null;
        for (self.served.items) |s| {
            if (!na.ipEqual(s.address, address) or !s.key.zone.eql(q.name)) continue;
            const rrs = try self.arena.alloc(RR, 2);
            rrs[0] = .{ .name = s.key.zone, .rtype = .dnskey, .rclass = .in, .ttl = 3600, .rdata = .{ .dnskey = s.key.dnskey } };
            rrs[1] = try self.sign(s.key, rrs[0..1], null);
            return rrs;
        }
        return null;
    }
};

fn addName(arena: Allocator, list: *std.ArrayList(dns.Name), name: dns.Name) !void {
    for (list.items) |n| if (n.eql(name)) return;
    try list.append(arena, name);
}

test "what the signer mints, the validator accepts" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const scenario: rpl.Scenario = .{ .dnssec_zones = &.{ ".", "example." } };
    var signer = try Signer.init(arena, &scenario, 7, 1_800_000_000);
    const zone = signer.keys[1].zone;
    const owner = try dns.parseDottedName(arena, "www.example.");
    const a: RR = .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 0, 2, 1 } } };
    const sig = try signer.sign(&signer.keys[1], &.{a}, null);
    const dnskey: RR = .{ .name = zone, .rtype = .dnskey, .rclass = .in, .ttl = 3600, .rdata = .{ .dnskey = signer.keys[1].dnskey } };
    const keysig = try signer.sign(&signer.keys[1], &.{dnskey}, null);
    var budget: dnssec.ValidationBudget = .{};
    try std.testing.expect(dnssec.validateRrset(&.{ a, sig }, owner, .a, &.{dnskey}, 1_800_000_000, &budget) != null);
    _ = try dnssec.validateDnskeyRrset(&.{ dnskey, keysig }, &.{signer.keys[1].ds}, zone, 1_800_000_000, &budget);
    // Same seed, same key: the query log stays reproducible.
    const again = try Signer.init(arena, &scenario, 7, 1_800_000_000);
    try std.testing.expectEqualSlices(u8, signer.keys[1].ds.digest, again.keys[1].ds.digest);
}
