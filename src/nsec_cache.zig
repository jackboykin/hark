const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const cache_mod = @import("cache.zig");
const CountingAllocator = @import("counting_allocator.zig").CountingAllocator;

/// Maximum effective TTL for synthesized responses (RFC 9077 §3).
const max_aggressive_ttl: u32 = 10800;

// ── NsecEntry ─────────────────────────────────────────────────────────

const NsecEntry = struct {
    owner: dns.Name,
    next_domain: dns.Name,
    type_bit_maps: []const u8,
    expires_at: i64,
};

// ── Zone NSEC list ────────────────────────────────────────────────────
// Sorted by canonical name order for binary search.

/// Deep-clone a SOA ResourceRecord.
fn cloneSoaRecord(alloc: Allocator, rr: dns.ResourceRecord) !dns.ResourceRecord {
    const name = try dns.cloneName(alloc, rr.name);
    errdefer dns.freeName(alloc, name);
    const rdata = try cache_mod.cloneRData(alloc, rr.rdata);
    return .{ .name = name, .rtype = .soa, .rclass = .in, .ttl = rr.ttl, .rdata = rdata };
}

fn freeSoaRecord(alloc: Allocator, rr: *dns.ResourceRecord) void {
    dns.freeName(alloc, rr.name);
    dns.freeRData(alloc, rr.rdata);
}

const ZoneNsecList = struct {
    entries: []NsecEntry,
    len: usize,
    soa: ?dns.ResourceRecord,

    fn init(alloc: Allocator, max_entries: usize) !ZoneNsecList {
        const entries = try alloc.alloc(NsecEntry, max_entries);
        return .{ .entries = entries, .len = 0, .soa = null };
    }

    fn capacity(self: *const ZoneNsecList) usize {
        return self.entries.len;
    }

    fn deinit(self: *ZoneNsecList, alloc: Allocator) void {
        for (self.entries[0..self.len]) |*e| freeEntry(alloc, e);
        alloc.free(self.entries);
        if (self.soa) |*s| freeSoaRecord(alloc, s);
    }

    /// Insert maintaining sorted order. Replaces existing entry with same owner.
    fn insert(self: *ZoneNsecList, alloc: Allocator, entry: NsecEntry, now: i64) void {
        var pos = self.findInsertPos(entry.owner);

        if (pos < self.len and self.entries[pos].owner.eql(entry.owner)) {
            freeEntry(alloc, &self.entries[pos]);
            self.entries[pos] = entry;
            return;
        }

        if (self.len >= self.capacity()) {
            // Try expiring stale entries first; fall back to evicting oldest
            self.evictExpired(alloc, now);
            if (self.len >= self.capacity()) {
                _ = self.evictOldest(alloc);
            }
            // Re-find after compaction shifted entries
            pos = self.findInsertPos(entry.owner);
        }

        self.shiftAndInsert(pos, entry);
    }

    fn shiftAndInsert(self: *ZoneNsecList, pos: usize, entry: NsecEntry) void {
        if (pos < self.len) {
            mem.copyBackwards(NsecEntry, self.entries[pos + 1 .. self.len + 1], self.entries[pos..self.len]);
        }
        self.entries[pos] = entry;
        self.len += 1;
    }

    /// Evict the entry with the earliest expiration. Returns evicted index.
    fn evictOldest(self: *ZoneNsecList, alloc: Allocator) usize {
        var oldest_idx: usize = 0;
        var oldest_expires: i64 = self.entries[0].expires_at;
        for (self.entries[1..self.len], 1..) |e, i| {
            if (e.expires_at < oldest_expires) {
                oldest_expires = e.expires_at;
                oldest_idx = i;
            }
        }
        self.removeAt(alloc, oldest_idx);
        return oldest_idx;
    }

    fn evictExpired(self: *ZoneNsecList, alloc: Allocator, now: i64) void {
        var write: usize = 0;
        for (self.entries[0..self.len]) |*e| {
            if (e.expires_at <= now) {
                freeEntry(alloc, e);
            } else {
                self.entries[write] = e.*;
                write += 1;
            }
        }
        self.len = write;
    }

    fn removeAt(self: *ZoneNsecList, alloc: Allocator, idx: usize) void {
        freeEntry(alloc, &self.entries[idx]);
        if (idx + 1 < self.len) {
            mem.copyForwards(NsecEntry, self.entries[idx .. self.len - 1], self.entries[idx + 1 .. self.len]);
        }
        self.len -= 1;
    }

    fn findInsertPos(self: *const ZoneNsecList, name: dns.Name) usize {
        var lo: usize = 0;
        var hi: usize = self.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (dnssec.canonicalNameOrder(self.entries[mid].owner, name) == .lt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    /// Find NSEC that covers qname: owner < qname < next_domain (with wrap).
    /// Binary search for insertion point, then check the entry just before it
    /// (which has the largest owner < qname). Falls back to last entry for wrap.
    fn findCovering(self: *const ZoneNsecList, qname: dns.Name, now: i64) ?*const NsecEntry {
        if (self.len == 0) return null;
        const pos = self.findInsertPos(qname);
        const primary = if (pos > 0) pos - 1 else self.len - 1;
        if (self.checkCovering(primary, qname, now)) |e| return e;
        // Wrap-around: last entry may cover names that sort before all owners
        if (primary != self.len - 1) {
            if (self.checkCovering(self.len - 1, qname, now)) |e| return e;
        }
        return null;
    }

    fn checkCovering(self: *const ZoneNsecList, idx: usize, qname: dns.Name, now: i64) ?*const NsecEntry {
        const e = &self.entries[idx];
        if (e.expires_at <= now) return null;
        if (dnssec.nsecProvesNameNonexistence(e.owner, .{
            .next_domain_name = e.next_domain,
            .type_bit_maps = e.type_bit_maps,
        }, qname)) return e;
        return null;
    }

    /// Find NSEC whose owner matches qname exactly.
    fn findExact(self: *const ZoneNsecList, qname: dns.Name, now: i64) ?*const NsecEntry {
        const pos = self.findInsertPos(qname);
        if (pos < self.len and self.entries[pos].owner.eql(qname) and self.entries[pos].expires_at > now) {
            return &self.entries[pos];
        }
        return null;
    }
};

fn cloneEntry(alloc: Allocator, rr: dns.ResourceRecord, expires_at: i64) !NsecEntry {
    const owner = try dns.cloneName(alloc, rr.name);
    errdefer dns.freeName(alloc, owner);
    const next = try dns.cloneName(alloc, rr.rdata.nsec.next_domain_name);
    errdefer dns.freeName(alloc, next);
    const bitmaps = try alloc.dupe(u8, rr.rdata.nsec.type_bit_maps);
    return .{ .owner = owner, .next_domain = next, .type_bit_maps = bitmaps, .expires_at = expires_at };
}

/// Detect minimal/black-lies NSEC ranges where next_domain is owner with
/// a prepended \x00 label (e.g. "example.com" → "\x00.example.com").
fn isMinimalNsec(owner: dns.Name, next: dns.Name) bool {
    if (next.labels.len != owner.labels.len + 1) return false;
    if (next.labels[0].len != 1 or next.labels[0][0] != 0) return false;
    const tail = dns.Name{ .labels = next.labels[1..] };
    return tail.eql(owner);
}

fn freeEntry(alloc: Allocator, e: *NsecEntry) void {
    dns.freeName(alloc, e.owner);
    dns.freeName(alloc, e.next_domain);
    alloc.free(e.type_bit_maps);
}

/// Determine closest encloser: walk up qname labels from left to right.
/// An ancestor provably exists if an NSEC with that owner is in the zone.
fn findClosestEncloser(list: *const ZoneNsecList, qname: dns.Name, now: i64) ?dns.Name {
    var label_count = qname.labels.len;
    while (label_count > 1) {
        label_count -= 1;
        const ancestor = dns.Name{ .labels = qname.labels[qname.labels.len - label_count ..] };
        if (list.findExact(ancestor, now) != null) return ancestor;
    }
    return null;
}

// ── NsecCache ─────────────────────────────────────────────────────────

/// Result of an aggressive NSEC lookup (RFC 8198).
pub const SynthResult = struct {
    rcode: RCode,
    /// SOA for authority section (RFC 2308 §3), cloned into caller's allocator.
    soa: dns.ResourceRecord,
    /// For wildcard_match: label count of the closest encloser. Caller reconstructs
    /// *.CE from the qname it already has (CE is the last ce_label_count labels).
    ce_label_count: u8 = 0,

    pub const RCode = enum { nxdomain, nodata, wildcard_match };
};

pub const NsecCache = struct {
    zones: std.StringHashMapUnmanaged(ZoneNsecList),
    rwlock: ?std.Thread.RwLock,
    counting: CountingAllocator,
    now_fn: *const fn () i64,
    hits: std.atomic.Value(u64),
    misses: std.atomic.Value(u64),

    pub const default_max_bytes: usize = 1024 * 1024; // 1MB
    const entries_per_zone: usize = 64;
    const max_zones: usize = 256;
    const max_store_batch: usize = 8;

    pub fn init(backing: Allocator, max_bytes: usize) NsecCache {
        return .{
            .zones = .empty,
            .rwlock = null,
            .counting = CountingAllocator.init(backing, max_bytes),
            .now_fn = &@import("monotonic.zig").nowSec,
            .hits = std.atomic.Value(u64).init(0),
            .misses = std.atomic.Value(u64).init(0),
        };
    }

    pub fn initThreadSafe(backing: Allocator, max_bytes: usize) NsecCache {
        var nc = init(backing, max_bytes);
        nc.rwlock = .{};
        return nc;
    }

    pub fn deinit(self: *NsecCache) void {
        const alloc = self.counting.allocator();
        var it = self.zones.iterator();
        while (it.next()) |kv| {
            var list = kv.value_ptr.*;
            list.deinit(alloc);
            alloc.free(kv.key_ptr.*);
        }
        self.zones.deinit(alloc);
    }

    // ── Store ─────────────────────────────────────────────────────────

    /// Extract NSEC records from authority section and store them.
    /// Only stores NSEC (not NSEC3 — marginal effectiveness per DNS-OARC research).
    /// TTL computed per RFC 9077: min(NSEC TTL, SOA.MINIMUM, SOA TTL, 10800).
    pub fn storeFromAuthority(
        self: *NsecCache,
        authorities: []const dns.ResourceRecord,
        zone: dns.Name,
    ) void {
        // Find SOA for TTL computation (RFC 9077)
        var soa_rr: ?dns.ResourceRecord = null;
        var soa_ttl: u32 = max_aggressive_ttl;
        var soa_minimum: u32 = max_aggressive_ttl;
        for (authorities) |rr| {
            if (rr.rtype == .soa) {
                soa_rr = rr;
                soa_ttl = rr.ttl;
                soa_minimum = rr.rdata.soa.minimum;
                break;
            }
        }

        // Format + lowercase zone key before lock (DNS is case-insensitive)
        const zone_formatted = zone.format();
        const zone_len = mem.indexOfScalar(u8, &zone_formatted, 0) orelse zone_formatted.len;
        var zone_lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const zone_lower = dns.lowerNameIntoBuf(zone_lower_buf[0..zone_len], zone_formatted[0..zone_len]);

        const now = self.now_fn();
        const alloc = self.counting.allocator();

        // Clone entries OUTSIDE the lock (CountingAllocator is atomic).
        var cloned: [max_store_batch]NsecEntry = undefined;
        var clone_count: usize = 0;
        for (authorities) |rr| {
            if (rr.rtype != .nsec) continue;
            if (rr.ttl == 0) continue;
            if (!rr.name.isSubdomainOf(zone)) continue;
            // Skip delegation NSECs (NS present, SOA absent) — these are parent-zone
            // proofs that a delegation exists, not proofs names don't exist (GL #3402).
            if (dns.typeBitmapContains(rr.rdata.nsec.type_bit_maps, .ns) and
                !dns.typeBitmapContains(rr.rdata.nsec.type_bit_maps, .soa)) continue;
            // Skip minimal/black-lies NSEC ranges (next = owner + \000) — these cover
            // only the queried name and waste cache space (Knot Resolver approach).
            if (isMinimalNsec(rr.name, rr.rdata.nsec.next_domain_name)) continue;
            if (clone_count >= max_store_batch) break;
            const effective_ttl = @min(rr.ttl, soa_minimum, soa_ttl, max_aggressive_ttl);
            cloned[clone_count] = cloneEntry(alloc, rr, now + @as(i64, effective_ttl)) catch continue;
            clone_count += 1;
        }
        if (clone_count == 0) return;

        // Clone SOA outside lock for synthesized responses (RFC 2308 §3)
        var cached_soa: ?dns.ResourceRecord = if (soa_rr) |sr| cloneSoaRecord(alloc, sr) catch null else null;

        // Take write lock only for zone lookup + sorted insert
        if (self.rwlock) |*rw| rw.lock();
        defer if (self.rwlock) |*rw| rw.unlock();

        const list = self.getOrCreateZone(alloc, zone_lower) orelse {
            for (cloned[0..clone_count]) |*e| freeEntry(alloc, e);
            if (cached_soa) |*s| freeSoaRecord(alloc, s);
            return;
        };
        if (cached_soa) |soa| {
            if (list.soa) |*old| freeSoaRecord(alloc, old);
            list.soa = soa;
            cached_soa = null; // ownership transferred
        }
        for (cloned[0..clone_count]) |entry| {
            list.insert(alloc, entry, now);
        }
    }

    fn getOrCreateZone(self: *NsecCache, alloc: Allocator, zone: []const u8) ?*ZoneNsecList {
        if (self.zones.getPtr(zone)) |list| return list;
        // Evict smallest zone if at capacity
        if (self.zones.count() >= max_zones) self.evictSmallestZone(alloc);
        const key = alloc.dupe(u8, zone) catch return null;
        const list = ZoneNsecList.init(alloc, entries_per_zone) catch {
            alloc.free(key);
            return null;
        };
        self.zones.put(alloc, key, list) catch {
            alloc.free(key);
            alloc.free(list.entries);
            return null;
        };
        return self.zones.getPtr(zone).?;
    }

    fn evictSmallestZone(self: *NsecCache, alloc: Allocator) void {
        var evict_key: ?[]const u8 = null;
        var min_len: usize = std.math.maxInt(usize);
        var it = self.zones.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.len < min_len) {
                min_len = kv.value_ptr.len;
                evict_key = kv.key_ptr.*;
            }
        }
        const key = evict_key orelse return;
        if (self.zones.fetchRemove(key)) |kv| {
            var list = kv.value;
            list.deinit(alloc);
            alloc.free(kv.key);
        }
    }

    // ── Lookup ────────────────────────────────────────────────────────

    /// Walk suffix zones of a dotted name and try NSEC synthesis under a
    /// single shared lock. SOA is cloned into `caller_alloc` before releasing.
    pub fn lookupSuffixes(self: *NsecCache, caller_alloc: Allocator, qname: dns.Name, qtype: dns.RType, dotted_name: []const u8) ?SynthResult {
        const now = self.now_fn();

        // Lowercase the full name once; suffix slices reuse this buffer.
        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const name_lower = dns.lowerNameIntoBuf(&lower_buf, dotted_name);

        if (self.rwlock) |*rw| rw.lockShared();
        defer if (self.rwlock) |*rw| rw.unlockShared();

        // Check the full name as a zone (handles apex NODATA, e.g. query
        // for example.com when zone "example.com" has a matching NSEC).
        if (self.tryZone(caller_alloc, name_lower, qname, qtype, now)) |r| return r;

        // Walk parent suffixes (most-specific first)
        var pos: usize = 0;
        while (mem.indexOfScalarPos(u8, name_lower, pos, '.')) |dot| {
            pos = dot + 1;
            const zone_lower = name_lower[pos..];
            if (zone_lower.len == 0) break;
            if (self.tryZone(caller_alloc, zone_lower, qname, qtype, now)) |r| return r;
        }

        _ = self.misses.fetchAdd(1, .monotonic);
        return null;
    }

    fn tryZone(
        self: *NsecCache,
        caller_alloc: Allocator,
        zone_lower: []const u8,
        qname: dns.Name,
        qtype: dns.RType,
        now: i64,
    ) ?SynthResult {
        const list = self.zones.getPtr(zone_lower) orelse return null;

        const cached_soa = &(list.soa orelse return null);

        // Parent-zone depth guard: if qname is >1 label deeper than the zone,
        // a non-delegation NSEC range from this zone could falsely cover names
        // in a child zone (e.g., a .com NSEC covering nnn.example.com).
        // Verify the direct-child ancestor is covered (proving it doesn't exist,
        // so no delegation is possible). DS queries are exempt (always answered
        // by the parent zone).
        const zone_label_count = zoneLabelsLen(zone_lower);
        if (qname.labels.len > zone_label_count + 1 and qtype != .ds) {
            const direct_child = dns.Name{ .labels = qname.labels[qname.labels.len - zone_label_count - 1 ..] };
            if (list.findCovering(direct_child, now) == null and list.findExact(direct_child, now) == null) {
                return null; // can't prove no delegation exists
            }
        }

        const rcode: SynthResult.RCode, const ce_len: u8 = switch (tryNameNonExistence(list, qname, qtype, now)) {
            .nxdomain => .{ .nxdomain, 0 },
            .wildcard_nodata => .{ .nodata, 0 },
            .wildcard_match => |ce| .{ .wildcard_match, ce },
            .unknown => nodata: {
                const nsec = list.findExact(qname, now) orelse return null;
                // Don't synthesize NODATA if CNAME exists — query must follow the
                // CNAME chain (RFC 1034 §3.6.2, RFC 4035 §2.5).
                if (qtype != .cname and dns.typeBitmapContains(nsec.type_bit_maps, .cname))
                    return null;
                if (!dns.typeBitmapContains(nsec.type_bit_maps, qtype))
                    break :nodata .{ .nodata, 0 };
                return null;
            },
        };
        const soa = cloneSoaRecord(caller_alloc, cached_soa.*) catch return null;
        _ = self.hits.fetchAdd(1, .monotonic);
        return .{ .rcode = rcode, .soa = soa, .ce_label_count = ce_len };
    }

    pub fn getStats(self: *NsecCache) struct { hits: u64, misses: u64, zones: usize, memory_bytes: usize } {
        if (self.rwlock) |*rw| rw.lockShared();
        defer if (self.rwlock) |*rw| rw.unlockShared();
        return .{
            .hits = self.hits.load(.monotonic),
            .misses = self.misses.load(.monotonic),
            .zones = self.zones.count(),
            .memory_bytes = self.counting.current_bytes.load(.monotonic),
        };
    }
};

/// Count labels in a dotted zone name (e.g., "example.com" → 2, "" → 0).
fn zoneLabelsLen(zone_lower: []const u8) usize {
    if (zone_lower.len == 0) return 0;
    var count: usize = 1;
    for (zone_lower) |c| {
        if (c == '.') count += 1;
    }
    return count;
}

/// Result of name non-existence proof (RFC 8198 §5.3).
const NameNonExistence = union(enum) {
    nxdomain, // name and wildcard both don't exist
    wildcard_nodata, // name doesn't exist, wildcard exists but lacks qtype
    wildcard_match: u8, // name doesn't exist, wildcard has qtype — CE label count
    unknown, // can't prove anything
};

fn tryNameNonExistence(list: *const ZoneNsecList, qname: dns.Name, qtype: dns.RType, now: i64) NameNonExistence {
    // (a) Find NSEC covering qname
    _ = list.findCovering(qname, now) orelse return .unknown;

    // (b) Determine closest encloser, then check wildcard
    const ce = findClosestEncloser(list, qname, now) orelse return .unknown;

    var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
    const wildcard_name = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unknown;

    // Check if wildcard exists
    if (list.findExact(wildcard_name, now)) |wc_nsec| {
        // Wildcard exists — check type bitmap for synthesis
        // CNAME at wildcard: must follow CNAME upstream, can't synthesize here
        if (qtype != .cname and dns.typeBitmapContains(wc_nsec.type_bit_maps, .cname))
            return .unknown;
        if (!dns.typeBitmapContains(wc_nsec.type_bit_maps, qtype)) {
            return .wildcard_nodata;
        }
        return .{ .wildcard_match = @intCast(ce.labels.len) };
    }

    // Prove wildcard name is covered by an NSEC (doesn't exist)
    _ = list.findCovering(wildcard_name, now) orelse return .unknown;
    return .nxdomain;
}

// ── Tests ─────────────────────────────────────────────────────────────

var test_time: i64 = 1000000;
fn testNowSeconds() i64 {
    return test_time;
}

const example_zone = dns.Name{ .labels = &.{ "example", "com" } };

fn testSoa(alloc: Allocator) !dns.ResourceRecord {
    return .{
        .name = try dns.parseDottedName(alloc, "example.com"),
        .rtype = .soa,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .soa = .{
            .mname = try dns.parseDottedName(alloc, "ns1.example.com"),
            .rname = try dns.parseDottedName(alloc, "admin.example.com"),
            .serial = 1,
            .refresh = 3600,
            .retry = 900,
            .expire = 604800,
            .minimum = 300,
        } },
    };
}

fn freeSoa(alloc: Allocator, soa: dns.ResourceRecord) void {
    dns.freeName(alloc, soa.name);
    dns.freeName(alloc, soa.rdata.soa.mname);
    dns.freeName(alloc, soa.rdata.soa.rname);
}

fn testCache(alloc: Allocator) NsecCache {
    var nc = NsecCache.init(alloc, 64 * 1024);
    nc.now_fn = &testNowSeconds;
    return nc;
}

fn expectSynth(alloc: Allocator, result: ?SynthResult, expected: SynthResult.RCode) !void {
    var r = result orelse return error.TestExpectedEqual;
    defer freeSoaRecord(alloc, &r.soa);
    try testing.expectEqual(expected, r.rcode);
}

test "NSEC cache: NODATA synthesis" {
    const alloc = testing.allocator;
    var nc = testCache(alloc);
    defer nc.deinit();

    // A(1), NS(2), SOA(6), MX(15), RRSIG(46), NSEC(47), DNSKEY(48)
    const bitmap = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const nsec_owner = try dns.parseDottedName(alloc, "example.com");
    const nsec_next = try dns.parseDottedName(alloc, "mail.example.com");
    defer dns.freeName(alloc, nsec_owner);
    defer dns.freeName(alloc, nsec_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = nsec_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = nsec_next, .type_bit_maps = bitmap } } },
    }, example_zone);

    // TXT not in bitmap → NODATA; A is in bitmap → null
    const qname = try dns.parseDottedName(alloc, "example.com");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .txt, "test.example.com"), .nodata);
    try testing.expect(nc.lookupSuffixes(alloc, qname, .a, "test.example.com") == null);
}

test "NSEC cache: NXDOMAIN synthesis" {
    const alloc = testing.allocator;
    var nc = testCache(alloc);
    defer nc.deinit();

    const bitmap_zone = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_host = &[_]u8{ 0, 2, 0x40, 0x01 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex_owner = try dns.parseDottedName(alloc, "example.com");
    const apex_next = try dns.parseDottedName(alloc, "alpha.example.com");
    const alpha_owner = try dns.parseDottedName(alloc, "alpha.example.com");
    const gamma_next = try dns.parseDottedName(alloc, "gamma.example.com");
    defer dns.freeName(alloc, apex_owner);
    defer dns.freeName(alloc, apex_next);
    defer dns.freeName(alloc, alpha_owner);
    defer dns.freeName(alloc, gamma_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = apex_next, .type_bit_maps = bitmap_zone } } },
        .{ .name = alpha_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = gamma_next, .type_bit_maps = bitmap_host } } },
    }, example_zone);

    // beta covered by alpha→gamma, wildcard covered by example.com→alpha
    const qname = try dns.parseDottedName(alloc, "beta.example.com");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .a, "beta.example.com"), .nxdomain);

    // alpha exists — not NXDOMAIN
    const exists = try dns.parseDottedName(alloc, "alpha.example.com");
    defer dns.freeName(alloc, exists);
    try testing.expect(nc.lookupSuffixes(alloc, exists, .a, "alpha.example.com") == null);
}

test "NSEC cache: empty cache returns null" {
    const alloc = testing.allocator;
    var nc = testCache(alloc);
    defer nc.deinit();

    const qname = try dns.parseDottedName(alloc, "nonexistent.example.com");
    defer dns.freeName(alloc, qname);
    try testing.expect(nc.lookupSuffixes(alloc, qname, .a, "nonexistent.example.com") == null);
}

test "NSEC cache: TTL expiration" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const bitmap = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const nsec_owner = try dns.parseDottedName(alloc, "example.com");
    const nsec_next = try dns.parseDottedName(alloc, "mail.example.com");
    defer dns.freeName(alloc, nsec_owner);
    defer dns.freeName(alloc, nsec_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = nsec_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = nsec_next, .type_bit_maps = bitmap } } },
    }, example_zone);

    const qname = try dns.parseDottedName(alloc, "example.com");
    defer dns.freeName(alloc, qname);

    // Before expiry: NODATA for TXT
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .txt, "test.example.com"), .nodata);

    // Advance past TTL (effective = min(3600, 300, 3600, 10800) = 300)
    test_time = 1000000 + 301;
    try testing.expect(nc.lookupSuffixes(alloc, qname, .txt, "test.example.com") == null);
}

test "NSEC cache: CNAME at owner suppresses NODATA synthesis" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    // Bitmap with CNAME(5), RRSIG(46), NSEC(47) — no A
    const bitmap = &[_]u8{ 0, 6, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const nsec_owner = try dns.parseDottedName(alloc, "alias.example.com");
    const nsec_next = try dns.parseDottedName(alloc, "beta.example.com");
    defer dns.freeName(alloc, nsec_owner);
    defer dns.freeName(alloc, nsec_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = nsec_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = nsec_next, .type_bit_maps = bitmap } } },
    }, example_zone);

    const qname = try dns.parseDottedName(alloc, "alias.example.com");
    defer dns.freeName(alloc, qname);

    // A not in bitmap, but CNAME IS → must NOT synthesize NODATA (follow CNAME)
    try testing.expect(nc.lookupSuffixes(alloc, qname, .a, "alias.example.com") == null);
    // Querying for CNAME itself is fine — type present → null
    try testing.expect(nc.lookupSuffixes(alloc, qname, .cname, "alias.example.com") == null);
}

test "NSEC cache: wildcard existence blocks NXDOMAIN" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    // Zone has: example.com NSEC *.example.com, *.example.com NSEC z.example.com
    // The wildcard exists, so NXDOMAIN must not be synthesized.
    const bitmap_zone = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_wc = &[_]u8{ 0, 2, 0x40, 0x01 }; // A, MX
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex_owner = try dns.parseDottedName(alloc, "example.com");
    const wc_name = try dns.parseDottedName(alloc, "*.example.com");
    const z_name = try dns.parseDottedName(alloc, "z.example.com");
    defer dns.freeName(alloc, apex_owner);
    defer dns.freeName(alloc, wc_name);
    defer dns.freeName(alloc, z_name);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = wc_name, .type_bit_maps = bitmap_zone } } },
        .{ .name = wc_name, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = z_name, .type_bit_maps = bitmap_wc } } },
    }, example_zone);

    // "foo.example.com" — name doesn't exist, wildcard exists with A
    // → wildcard_match (not NXDOMAIN). Caller synthesizes from RRset cache.
    const qname = try dns.parseDottedName(alloc, "foo.example.com");
    defer dns.freeName(alloc, qname);
    const result = nc.lookupSuffixes(alloc, qname, .a, "foo.example.com") orelse return error.TestExpectedEqual;
    defer freeSoaRecord(alloc, @constCast(&result.soa));
    try testing.expectEqual(SynthResult.RCode.wildcard_match, result.rcode);
    try testing.expect(result.ce_label_count > 0);
}

test "NSEC cache: apex NODATA via full-name zone check" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const bitmap = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 }; // A, NS, SOA, MX, RRSIG, NSEC, DNSKEY
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const nsec_owner = try dns.parseDottedName(alloc, "example.com");
    const nsec_next = try dns.parseDottedName(alloc, "mail.example.com");
    defer dns.freeName(alloc, nsec_owner);
    defer dns.freeName(alloc, nsec_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = nsec_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = nsec_next, .type_bit_maps = bitmap } } },
    }, example_zone);

    // Query for the zone apex itself — dotted_name == zone name
    const qname = try dns.parseDottedName(alloc, "example.com");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .txt, "example.com"), .nodata);
}

test "NSEC cache: bailiwick check rejects out-of-zone NSECs" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const bitmap = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    // NSEC owner is in a different zone than the zone parameter
    const nsec_owner = try dns.parseDottedName(alloc, "evil.attacker.com");
    const nsec_next = try dns.parseDottedName(alloc, "z.attacker.com");
    defer dns.freeName(alloc, nsec_owner);
    defer dns.freeName(alloc, nsec_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = nsec_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = nsec_next, .type_bit_maps = bitmap } } },
    }, example_zone);

    // Out-of-zone NSEC should have been rejected — no synthesis possible
    const qname = try dns.parseDottedName(alloc, "evil.attacker.com");
    defer dns.freeName(alloc, qname);
    try testing.expect(nc.lookupSuffixes(alloc, qname, .txt, "evil.attacker.com") == null);

    // Also shouldn't pollute the example.com zone
    const qname2 = try dns.parseDottedName(alloc, "evil.example.com");
    defer dns.freeName(alloc, qname2);
    try testing.expect(nc.lookupSuffixes(alloc, qname2, .txt, "evil.example.com") == null);
}

test "NSEC cache: wrap-around NSEC chain" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    // NSEC chain: example.com → beta.example.com → example.com (wraps)
    // The last NSEC wraps: beta.example.com → example.com covers everything after beta
    const bitmap = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_host = &[_]u8{ 0, 2, 0x40, 0x01 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex_owner = try dns.parseDottedName(alloc, "example.com");
    const beta_name = try dns.parseDottedName(alloc, "beta.example.com");
    const apex_owner2 = try dns.parseDottedName(alloc, "example.com");
    defer dns.freeName(alloc, apex_owner);
    defer dns.freeName(alloc, beta_name);
    defer dns.freeName(alloc, apex_owner2);

    nc.storeFromAuthority(&.{
        soa_rr,
        // apex → beta
        .{ .name = apex_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = beta_name, .type_bit_maps = bitmap } } },
        // beta → apex (wrap-around)
        .{ .name = beta_name, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = apex_owner2, .type_bit_maps = bitmap_host } } },
    }, example_zone);

    // "zebra.example.com" sorts after beta → covered by wrap-around NSEC
    // Closest encloser is example.com, wildcard *.example.com is covered by apex→beta
    const qname = try dns.parseDottedName(alloc, "zebra.example.com");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .a, "zebra.example.com"), .nxdomain);

    // "alpha.example.com" sorts before beta → covered by apex→beta
    const alpha = try dns.parseDottedName(alloc, "alpha.example.com");
    defer dns.freeName(alloc, alpha);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, alpha, .a, "alpha.example.com"), .nxdomain);
}

test "NSEC cache: parent-zone depth check prevents cross-zone coverage" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    // Store NSECs in the "com" zone where the range covers deep child names
    // but the direct child ancestor (example.com) is NOT covered by any NSEC.
    // This means we can't prove "example.com" doesn't exist → can't rule out delegation.
    const com_zone = dns.Name{ .labels = &.{"com"} };
    const bitmap = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_host = &[_]u8{ 0, 2, 0x40, 0x01 };

    const com_soa = dns.ResourceRecord{
        .name = com_zone,
        .rtype = .soa,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .soa = .{
            .mname = com_zone,
            .rname = com_zone,
            .serial = 1,
            .refresh = 3600,
            .retry = 900,
            .expire = 604800,
            .minimum = 300,
        } },
    };

    // NSECs: com → aaa.com, ggg.com → zzz.com
    // Gap: aaa.com to ggg.com is NOT covered — example.com falls in this gap.
    // But ggg.com → zzz.com covers "nnn.example.com" in canonical order.
    const com_owner = try dns.parseDottedName(alloc, "com");
    const aaa_next = try dns.parseDottedName(alloc, "aaa.com");
    const ggg_owner = try dns.parseDottedName(alloc, "ggg.com");
    const zzz_next = try dns.parseDottedName(alloc, "zzz.com");
    defer dns.freeName(alloc, com_owner);
    defer dns.freeName(alloc, aaa_next);
    defer dns.freeName(alloc, ggg_owner);
    defer dns.freeName(alloc, zzz_next);

    nc.storeFromAuthority(&.{
        com_soa,
        .{ .name = com_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = aaa_next, .type_bit_maps = bitmap } } },
        .{ .name = ggg_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = zzz_next, .type_bit_maps = bitmap_host } } },
    }, com_zone);

    // nnn.com (1 label deeper than zone) — should work, no depth issue
    const nnn_com = try dns.parseDottedName(alloc, "nnn.com");
    defer dns.freeName(alloc, nnn_com);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, nnn_com, .a, "nnn.com"), .nxdomain);

    // nnn.example.com (2 labels deeper than "com" zone) — depth check should reject
    // because "example.com" is NOT covered by any NSEC (falls in gap aaa.com→ggg.com)
    const deep_name = try dns.parseDottedName(alloc, "nnn.example.com");
    defer dns.freeName(alloc, deep_name);
    try testing.expect(nc.lookupSuffixes(alloc, deep_name, .a, "nnn.example.com") == null);

    // DS queries are exempt from the depth check (parent zone answers them)
    try testing.expect(nc.lookupSuffixes(alloc, deep_name, .ds, "nnn.example.com") == null);
}

test "NSEC cache: wildcard NODATA synthesis" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    // Zone has: example.com NSEC *.example.com, *.example.com NSEC z.example.com
    // Wildcard exists with A and MX but NOT TXT
    const bitmap_zone = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_wc = &[_]u8{ 0, 2, 0x40, 0x01 }; // A, NS
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex_owner = try dns.parseDottedName(alloc, "example.com");
    const wc_name = try dns.parseDottedName(alloc, "*.example.com");
    const z_name = try dns.parseDottedName(alloc, "z.example.com");
    defer dns.freeName(alloc, apex_owner);
    defer dns.freeName(alloc, wc_name);
    defer dns.freeName(alloc, z_name);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = wc_name, .type_bit_maps = bitmap_zone } } },
        .{ .name = wc_name, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = z_name, .type_bit_maps = bitmap_wc } } },
    }, example_zone);

    // "foo.example.com" doesn't exist, wildcard exists but lacks TXT → NODATA
    const qname = try dns.parseDottedName(alloc, "foo.example.com");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .txt, "foo.example.com"), .nodata);
}

test "NSEC cache: wildcard match returns wildcard_match" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    // Wildcard has A (bitmap includes type 1)
    const bitmap_zone = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_wc = &[_]u8{ 0, 2, 0x40, 0x01 }; // A=1, NS=2 present
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex_owner = try dns.parseDottedName(alloc, "example.com");
    const wc_name = try dns.parseDottedName(alloc, "*.example.com");
    const z_name = try dns.parseDottedName(alloc, "z.example.com");
    defer dns.freeName(alloc, apex_owner);
    defer dns.freeName(alloc, wc_name);
    defer dns.freeName(alloc, z_name);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = wc_name, .type_bit_maps = bitmap_zone } } },
        .{ .name = wc_name, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = z_name, .type_bit_maps = bitmap_wc } } },
    }, example_zone);

    // "foo.example.com" A — wildcard has A → wildcard_match
    const qname = try dns.parseDottedName(alloc, "foo.example.com");
    defer dns.freeName(alloc, qname);
    const result = nc.lookupSuffixes(alloc, qname, .a, "foo.example.com") orelse return error.TestExpectedEqual;
    defer freeSoaRecord(alloc, @constCast(&result.soa));
    try testing.expectEqual(SynthResult.RCode.wildcard_match, result.rcode);
    try testing.expect(result.ce_label_count > 0);
}

test "NSEC cache: wildcard CNAME suppression" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    // Wildcard bitmap has CNAME(5) — query for A should return unknown (follow CNAME upstream)
    const bitmap_zone = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_wc = &[_]u8{ 0, 6, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03 }; // CNAME(5), RRSIG(46), NSEC(47)
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex_owner = try dns.parseDottedName(alloc, "example.com");
    const wc_name = try dns.parseDottedName(alloc, "*.example.com");
    const z_name = try dns.parseDottedName(alloc, "z.example.com");
    defer dns.freeName(alloc, apex_owner);
    defer dns.freeName(alloc, wc_name);
    defer dns.freeName(alloc, z_name);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = wc_name, .type_bit_maps = bitmap_zone } } },
        .{ .name = wc_name, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = z_name, .type_bit_maps = bitmap_wc } } },
    }, example_zone);

    // A query when wildcard has CNAME → must NOT synthesize (follow CNAME upstream)
    const qname = try dns.parseDottedName(alloc, "foo.example.com");
    defer dns.freeName(alloc, qname);
    try testing.expect(nc.lookupSuffixes(alloc, qname, .a, "foo.example.com") == null);
}

test "zoneLabelsLen" {
    try testing.expectEqual(@as(usize, 0), zoneLabelsLen(""));
    try testing.expectEqual(@as(usize, 1), zoneLabelsLen("com"));
    try testing.expectEqual(@as(usize, 2), zoneLabelsLen("example.com"));
    try testing.expectEqual(@as(usize, 3), zoneLabelsLen("sub.example.com"));
}
