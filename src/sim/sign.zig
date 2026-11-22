//! The simulator's signer. One ECDSA P-256 key per declared zone, from its name (RFC
//! 6605, flags 256, SHA-256 DS); a placeholder DS takes the child's digest;
//! every RRset gets an RRSIG from the zone the cut rules say owns it,
//! inception a day back, expiry a year out unless `sig-validity` says, its
//! original TTL the set's own unless `sig-original-ttl` caps it.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const dns = @import("../dns.zig");
const dnssec = @import("../dnssec.zig");
const rrsig = @import("../rrsig.zig");
const na = @import("../net_address.zig");
const rpl = @import("rpl.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const RR = dns.ResourceRecord;

const Key = struct {
    zone: dns.Name,
    pair: Ecdsa.KeyPair,
    dnskey: dns.DnskeyData,
    key_tag: u16,
    ds: dns.DsData,

    fn init(arena: Allocator, zone: dns.Name) !Key {
        var h = Sha256.init(.{});
        var buf: [dns.max_dotted_len + 1]u8 = undefined;
        h.update(zone.formatInto(&buf));
        const pair = try Ecdsa.KeyPair.generateDeterministic(h.finalResult());
        const sec1 = pair.public_key.toUncompressedSec1();
        const dnskey: dns.DnskeyData = .{ .flags = dns.DnskeyData.zone_flag, .protocol = 3, .algorithm = .ecdsap256sha256, .public_key = try arena.dupe(u8, sec1[1..]) };
        const tag = rrsig.keyTag(dnskey);
        return .{
            .zone = zone,
            .pair = pair,
            .dnskey = dnskey,
            .key_tag = tag,
            .ds = .{ .key_tag = tag, .algorithm = .ecdsap256sha256, .digest_type = .sha256, .digest = try arena.dupe(u8, &dnssec.dsDigest(Sha256, zone, dnskey)) },
        };
    }
};

pub const Mint = struct {
    arena: Allocator,
    keys: []Key,
    signatures: std.AutoHashMapUnmanaged([32]u8, [64]u8) = .empty,

    pub fn init(arena: Allocator, scenario: *const rpl.Scenario) !Mint {
        const keys = try arena.alloc(Key, scenario.dnssec_zones.len);
        for (keys, scenario.dnssec_zones) |*k, z| k.* = try Key.init(arena, try dns.parseDottedName(arena, z));
        return .{ .arena = arena, .keys = keys };
    }
};

pub const Signer = struct {
    arena: Allocator,
    mint: *Mint,
    now: i64,
    validity: i64,
    original_ttl: ?u32,
    served: std.ArrayList(Served) = .empty,

    const Served = struct { address: na.Address, key: *const Key };

    pub fn init(arena: Allocator, scenario: *const rpl.Scenario, mint: *Mint, wall_sec: i64) Signer {
        return .{ .arena = arena, .mint = mint, .now = wall_sec, .validity = scenario.sig_validity orelse (365 * 86400), .original_ttl = scenario.sig_original_ttl };
    }

    /// The parser makes the first declared zone the root.
    pub fn anchor(self: *const Signer) ?[]const dns.DsData {
        return if (self.mint.keys.len > 0) (&self.mint.keys[0].ds)[0..1] else null;
    }

    pub fn bake(self: *Signer, ranges: []const rpl.Range) ![]const rpl.Range {
        if (self.mint.keys.len == 0) return ranges;
        const out = try self.arena.dupe(rpl.Range, ranges);
        for (out) |*r| {
            const entries = try self.arena.dupe(rpl.Entry, r.entries);
            for (entries) |*e| try self.bakeEntry(e, r.address);
            r.entries = entries;
        }
        return out;
    }

    /// A DS owner is a cut; a referral (empty answer, NS and no SOA in
    /// authority) cuts at the NS owner too.
    fn bakeEntry(self: *Signer, e: *rpl.Entry, address: na.Address) !void {
        if (e.unsigned) return;
        const forced = if (e.sign_as) |z| self.keyNamed(z) else null;
        var cuts: std.ArrayList(dns.Name) = .empty;
        for ([_][]const rpl.Record{ e.answers, e.authorities, e.additionals }) |sec| for (sec) |r| if (r.rr.rtype == .ds) try addName(self.arena, &cuts, r.rr.name);
        var soa = false;
        for (e.authorities) |r| soa = soa or r.rr.rtype == .soa;
        if (e.answers.len == 0 and !soa) for (e.authorities) |r| if (r.rr.rtype == .ns) try addName(self.arena, &cuts, r.rr.name);
        e.answers = try self.bakeSection(e.answers, e.ds_from, cuts.items, forced, address, e.wildcard);
        e.authorities = try self.bakeSection(e.authorities, e.ds_from, cuts.items, forced, address, null);
        e.additionals = try self.bakeSection(e.additionals, e.ds_from, cuts.items, forced, address, null);
    }

    fn bakeSection(self: *Signer, records: []const rpl.Record, ds_from: []const rpl.DsFrom, cuts: []const dns.Name, forced: ?*const Key, address: na.Address, wildcard: ?dns.Name) ![]const rpl.Record {
        var out: std.ArrayList(rpl.Record) = .empty;
        try out.appendSlice(self.arena, records);
        for (ds_from) |d| for (out.items) |*r| if (r.rr.rtype == .ds and r.rr.name.eql(d.owner)) {
            const key = self.keyNamed(d.zone) orelse return error.PlaceholderDsWithoutKey;
            const ds: RR = try .init(self.arena, .{ .name = r.rr.name, .rtype = .ds, .rclass = r.rr.rclass, .ttl = r.rr.ttl, .rdata = .{ .ds = key.ds } });
            r.* = .{ .rr = ds, .owner = r.owner, .rdata = ds.rdata };
        };
        // Signing appends to `out`, which may move it.
        const originals = try self.arena.alloc(RR, out.items.len);
        for (originals, out.items) |*rr, r| rr.* = r.rr;
        for (originals, 0..) |head, i| {
            if (head.rtype == .rrsig or head.rclass != .in) continue;
            var first = true;
            for (originals[0..i]) |prev| first = first and !(prev.rclass == .in and prev.rtype == head.rtype and prev.name.eql(head.name));
            if (!first) continue;
            // RFC 6672 §5.3.1: a CNAME synthesised under a DNAME travels unsigned.
            var synthesised = false;
            if (head.rtype == .cname) for (originals) |o| {
                synthesised = synthesised or (o.rclass == .in and o.rtype == .dname and !head.name.eql(o.name) and head.name.isSubdomainOf(o.name));
            };
            if (synthesised) continue;
            const key = forced orelse self.keyFor(head.name, head.rtype, cuts) orelse continue;
            if (forced == null) try self.register(address, key);
            // A scenario's own RRSIG stands in for ours, unless it is by another zone or
            // of a reserved algorithm (123-251, RFC 6014 §4): that is stuffing.
            var covered = false;
            for (originals) |o| covered = covered or (o.rclass == .in and o.rtype == .rrsig and o.name.eql(head.name) and o.rrsig().type_covered == head.rtype and o.rrsig().signer_name.eql(key.zone) and !reservedAlgorithm(@backingInt(o.rrsig().algorithm)));
            if (covered) continue;
            var set: std.ArrayList(RR) = .empty;
            for (originals) |rr| if (rr.rclass == .in and rr.rtype == head.rtype and rr.name.eql(head.name)) try set.append(self.arena, rr);
            const sig = try self.sign(key, .sort(set.items), if (self.expands(wildcard, head.name, key, forced)) wildcard else null);
            try out.append(self.arena, .{ .rr = sig, .owner = out.items[i].owner, .rdata = sig.rdata });
        }
        return out.items;
    }

    /// A DS, or an NSEC exactly at a cut, is the parent's to sign; anything
    /// else at or below a cut is the child's or glue, and unsigned here.
    fn keyFor(self: *const Signer, owner: dns.Name, rtype: dns.RType, cuts: []const dns.Name) ?*const Key {
        if (rtype == .ds) return self.deepest(owner, true);
        for (cuts) |c| if (c.eql(owner) and rtype == .nsec) return self.deepest(owner, true);
        for (cuts) |c| if (owner.isSubdomainOf(c)) return null;
        return self.deepest(owner, false);
    }

    fn expands(self: *const Signer, wildcard: ?dns.Name, owner: dns.Name, key: *const Key, forced: ?*const Key) bool {
        const w = wildcard orelse return false;
        const parent = w.parent().?;
        return owner.isSubdomainOf(parent) and !owner.eql(parent) and (forced != null or key == self.deepest(w, false));
    }

    fn reservedAlgorithm(algorithm: u8) bool {
        return algorithm >= 123 and algorithm <= 251;
    }

    fn deepest(self: *const Signer, owner: dns.Name, strictly_above: bool) ?*const Key {
        var best: ?*const Key = null;
        for (self.mint.keys) |*k| {
            if (!owner.isSubdomainOf(k.zone) or (strictly_above and k.zone.eql(owner))) continue;
            if (best == null or k.zone.depth() > best.?.zone.depth()) best = k;
        }
        return best;
    }

    fn keyNamed(self: *const Signer, zone: dns.Name) ?*const Key {
        for (self.mint.keys) |*k| if (k.zone.eql(zone)) return k;
        return null;
    }

    fn register(self: *Signer, address: na.Address, key: *const Key) !void {
        for (self.served.items) |s| if (s.key == key and na.ipEqual(s.address, address)) return;
        try self.served.append(self.arena, .{ .address = address, .key = key });
    }

    fn sign(self: *Signer, key: *const Key, set: rrsig.Canonical, wildcard: ?dns.Name) !RR {
        const head = set.records[0];
        var sig: dns.RrsigData = .{
            .type_covered = head.rtype,
            .algorithm = .ecdsap256sha256,
            .labels = rrsig.signedLabels(wildcard orelse head.name),
            .original_ttl = @min(head.ttl, self.original_ttl orelse head.ttl),
            .sig_expiration = @intCast(self.now + self.validity),
            .sig_inception = @intCast(self.now - 86400),
            .key_tag = key.key_tag,
            .signer_name = key.zone,
            .signature = &.{},
        };
        const data = rrsig.buildSignedData(sig, set);
        var h = Sha256.init(.{});
        data.feed(&h);
        const minted = try self.mint.signatures.getOrPut(self.mint.arena, h.finalResult());
        if (!minted.found_existing) {
            // A minted P-256 pair always signs: std's errors guard a bad one.
            var s = key.pair.signer(null) catch unreachable;
            data.feed(&s);
            minted.value_ptr.* = (s.finalize() catch unreachable).toBytes();
        }
        sig.signature = try self.arena.dupe(u8, minted.value_ptr);
        return .init(self.arena, .{ .name = head.name, .rtype = .rrsig, .rclass = .in, .ttl = head.ttl, .rdata = .{ .rrsig = sig } });
    }

    pub fn dnskeyAnswer(self: *Signer, address: na.Address, q: dns.Question) !?[]const rpl.Record {
        if (q.qtype != .dnskey) return null;
        for (self.served.items) |s| {
            if (!na.ipEqual(s.address, address) or !s.key.zone.eql(q.name)) continue;
            var key: [1]RR = .{try .init(self.arena, .{ .name = s.key.zone, .rtype = .dnskey, .rclass = .in, .ttl = 3600, .rdata = .{ .dnskey = s.key.dnskey } })};
            const records = try self.arena.alloc(rpl.Record, 2);
            records[0] = .of(key[0]);
            records[1] = .of(try self.sign(s.key, .sort(&key), null));
            return records;
        }
        return null;
    }
};

fn addName(arena: Allocator, list: *std.ArrayList(dns.Name), name: dns.Name) !void {
    for (list.items) |n| if (n.eql(name)) return;
    try list.append(arena, name);
}
