const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const CountingAllocator = @import("counting_allocator.zig").CountingAllocator;

/// Maximum effective TTL for synthesized responses (RFC 9077 §3).
const max_aggressive_ttl: u32 = 10800;

// ── NsecEntry ─────────────────────────────────────────────────────────

const NsecEntry = struct {
    owner: dns.Name,
    next_domain: dns.Name,
    type_bit_maps: []const u8,
    expires_at: i64,
    /// RRSIGs covering this NSEC (cloned, owned by zone allocator).
    /// Typically 1-2; multiple during key rollover (RFC 6781). Empty when
    /// upstream omitted the covering RRSIG — synthesis verdict still works
    /// for AD-trusting clients, DO=1 clients see the proof bundle as
    /// insecure rather than secure.
    sigs: []dns.ResourceRecord = &.{},
};

/// Deep-clone a non-NSEC record (e.g. RRSIG covering NSEC, SOA).
/// Assumes `wire` is not load-bearing — we re-emit from rdata on serve.
fn cloneRecord(alloc: Allocator, rr: dns.ResourceRecord) !dns.ResourceRecord {
    const name = try dns.cloneName(alloc, rr.name);
    errdefer dns.freeName(alloc, name);
    const rdata = try dns.cloneRData(alloc, rr.rdata);
    return .{ .name = name, .rtype = rr.rtype, .rclass = rr.rclass, .ttl = rr.ttl, .rdata = rdata };
}

fn freeRecord(alloc: Allocator, rr: *dns.ResourceRecord) void {
    dns.freeName(alloc, rr.name);
    dns.freeRData(alloc, rr.rdata);
}

// ── Zone NSEC list ────────────────────────────────────────────────────
// Sorted by canonical name order for binary search.

const ZoneNsecList = struct {
    entries: []NsecEntry,
    len: usize,
    soa: ?dns.ResourceRecord,

    fn init(alloc: Allocator, max_entries: usize) !ZoneNsecList {
        const entries = try alloc.alloc(NsecEntry, max_entries);
        return .{ .entries = entries, .len = 0, .soa = null };
    }

    fn deinit(self: *ZoneNsecList, alloc: Allocator) void {
        for (self.entries[0..self.len]) |*e| freeEntry(alloc, e);
        alloc.free(self.entries);
        if (self.soa) |*s| freeRecord(alloc, s);
    }

    /// Insert maintaining sorted order. Replaces existing entry with same owner.
    fn insert(self: *ZoneNsecList, alloc: Allocator, entry: NsecEntry, now: i64) void {
        var pos = self.findInsertPos(entry.owner);

        if (pos < self.len and self.entries[pos].owner.eql(entry.owner)) {
            freeEntry(alloc, &self.entries[pos]);
            self.entries[pos] = entry;
            return;
        }

        if (self.len >= self.entries.len) {
            // Try expiring stale entries first; fall back to evicting oldest
            self.evictExpired(alloc, now);
            if (self.len >= self.entries.len) {
                self.evictOldest(alloc);
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

    /// Evict the entry with the earliest expiration.
    fn evictOldest(self: *ZoneNsecList, alloc: Allocator) void {
        var oldest_idx: usize = 0;
        var oldest_expires: i64 = self.entries[0].expires_at;
        for (self.entries[1..self.len], 1..) |e, i| {
            if (e.expires_at < oldest_expires) {
                oldest_expires = e.expires_at;
                oldest_idx = i;
            }
        }
        self.removeAt(alloc, oldest_idx);
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

fn cloneEntry(
    alloc: Allocator,
    rr: dns.ResourceRecord,
    expires_at: i64,
    nsec_ttl: u32,
    authorities: []const dns.ResourceRecord,
) !NsecEntry {
    const owner = try dns.cloneName(alloc, rr.name);
    errdefer dns.freeName(alloc, owner);
    // `next` rides out to DO=1 clients verbatim via aggressive negative
    // synthesis; relies on `tryParseMessage`'s RData scrub to lowercase
    // upstream case first (else an attacker steers cached NSEC bytes).
    const next = try dns.cloneName(alloc, rr.rdata.nsec.next_domain_name);
    errdefer dns.freeName(alloc, next);
    const bitmaps = try alloc.dupe(u8, rr.rdata.nsec.type_bit_maps);
    errdefer alloc.free(bitmaps);

    // Collect RRSIGs covering this NSEC at the same owner. Bailiwick is
    // already enforced by storeFromAuthority's NSEC filter. Cap at 4 —
    // dual-algo + KSK-rollover transient is the realistic ceiling (RFC
    // 6781 §4.1.4 produces at most 4 RRSIGs per RRset during rollover).
    var sig_buf: [4]dns.ResourceRecord = undefined;
    var sig_count: usize = 0;
    for (authorities) |a| {
        if (a.rtype != .rrsig) continue;
        if (a.rdata.rrsig.type_covered != .nsec) continue;
        if (!a.name.eql(rr.name)) continue;
        if (sig_count >= sig_buf.len) break;
        var cloned = cloneRecord(alloc, a) catch continue;
        // Match the NSEC's RFC 9077 clamp so a defense-in-depth read of
        // entry.sigs[i].ttl would never over-cache.
        cloned.ttl = nsec_ttl;
        sig_buf[sig_count] = cloned;
        sig_count += 1;
    }
    const sigs: []dns.ResourceRecord = if (sig_count == 0) &.{} else blk: {
        const arr = alloc.alloc(dns.ResourceRecord, sig_count) catch {
            for (sig_buf[0..sig_count]) |*s| freeRecord(alloc, s);
            break :blk &.{};
        };
        @memcpy(arr, sig_buf[0..sig_count]);
        break :blk arr;
    };

    return .{ .owner = owner, .next_domain = next, .type_bit_maps = bitmaps, .expires_at = expires_at, .sigs = sigs };
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
    for (e.sigs) |*s| freeRecord(alloc, s);
    if (e.sigs.len > 0) alloc.free(e.sigs);
}

/// RFC 6840 §4.1: a parent-side NSEC at a delegation cut (NS+!SOA) is
/// authoritative for the cut, not the subtree below. Fires only when
/// `target` is at-or-below `nsec.owner` — the shape where misuse would
/// launder parent authority into a child zone. DS is the named exception
/// (RFC 4035 §5.2). Mirrors Knot's `kr_nsec_children_in_zone_check` and
/// Unbound's `val_nsec_proves_name_error` / `nsec_proves_nodata`.
fn isParentSideNsec(nsec: *const NsecEntry, target: dns.Name, qtype: dns.RType) bool {
    if (qtype == .ds) {
        // DS is the one type the parent owns, so a parent-side NSEC is
        // exactly what a DS proof wants — but only AT the cut. Two clauses,
        // neither subsuming the other (Unbound's val_nsec_proves_no_ds +
        // nsec_proves_nodata pair; RFC 6840 §4.4 states both at MUST level):
        //   · below the cut there is no parent authority at all, and the
        //     shape has no SOA, so only this clause catches it;
        //   · a child-side apex NSEC has target == owner, so only the SOA
        //     clause catches that one. DS never lives on the child side.
        if (!target.eql(nsec.owner)) return true;
        if (dns.typeBitmapContains(nsec.type_bit_maps, .soa) and target.labels.len > 0) return true;
        return false;
    }
    if (!dns.typeBitmapContains(nsec.type_bit_maps, .ns)) return false;
    if (dns.typeBitmapContains(nsec.type_bit_maps, .soa)) return false;
    return dnssec.commonSuffixLabels(target, nsec.owner) == nsec.owner.labels.len;
}

// ── NsecCache ─────────────────────────────────────────────────────────

/// Result of an aggressive NSEC lookup (RFC 8198).
pub const SynthResult = struct {
    kind: Kind,
    /// SOA for authority section (RFC 2308 §3), cloned into caller's allocator.
    soa: dns.ResourceRecord,
    /// For wildcard_match: label count of the closest encloser. Caller reconstructs
    /// *.CE from the qname it already has (CE is the last ce_label_count labels).
    ce_label_count: u8 = 0,
    /// NSEC records (and their covering RRSIGs) that justify `kind` for
    /// this specific qname (RFC 4035 §3.1.3.x). Cloned into caller_alloc;
    /// caller appends to authority for downstream revalidation. Empty when
    /// upstream omitted RRSIGs or only the SOA proves the negative.
    proofs: []dns.ResourceRecord = &.{},

    pub const Kind = enum { nxdomain, nodata, wildcard_match };
};

pub const NsecCache = struct {
    zones: std.StringHashMapUnmanaged(ZoneNsecList),
    rwlock: ?std.Io.RwLock,
    io: std.Io,
    counting: CountingAllocator,
    now_fn: *const fn () i64,
    hits: std.atomic.Value(u64),
    misses: std.atomic.Value(u64),

    pub const default_max_bytes: usize = 1024 * 1024; // 1MB
    const entries_per_zone: usize = 64;
    const max_zones: usize = 256;
    const max_store_batch: usize = 8;

    pub const Config = struct {
        backing: Allocator,
        max_bytes: usize,
        io: std.Io,
        thread_safe: bool = false,
    };

    pub fn init(cfg: Config) NsecCache {
        return .{
            .zones = .empty,
            .rwlock = if (cfg.thread_safe) std.Io.RwLock.init else null,
            .io = cfg.io,
            .counting = CountingAllocator.init(cfg.backing, cfg.max_bytes),
            .now_fn = &@import("monotonic.zig").nowSec,
            .hits = std.atomic.Value(u64).init(0),
            .misses = std.atomic.Value(u64).init(0),
        };
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
    /// TTL computed per RFC 9077: min(NSEC TTL, SOA.MINIMUM, SOA TTL, 10800),
    /// further bounded by `ttl_cap` — the verified RRSIG validity window, so
    /// aggressive synthesis never denies a name past the proof's own life.
    pub fn storeFromAuthority(
        self: *NsecCache,
        authorities: []const dns.ResourceRecord,
        zone: dns.Name,
        ttl_cap: u32,
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
        var zone_lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const zone_lower = zone.formatLower(&zone_lower_buf);

        const now = self.now_fn();
        const alloc = self.counting.allocator();

        // Clone entries OUTSIDE the lock (CountingAllocator is atomic).
        var cloned: [max_store_batch]NsecEntry = undefined;
        var clone_count: usize = 0;
        for (authorities) |rr| {
            if (rr.rtype != .nsec) continue;
            if (!rr.name.isSubdomainOf(zone)) continue;
            // Skip minimal/black-lies NSEC ranges (next = owner + \000) — these cover
            // only the queried name and waste cache space (Knot Resolver approach).
            if (isMinimalNsec(rr.name, rr.rdata.nsec.next_domain_name)) continue;
            if (clone_count >= max_store_batch) break;
            const effective_ttl = @min(rr.ttl, soa_minimum, soa_ttl, max_aggressive_ttl, ttl_cap);
            if (effective_ttl == 0) continue;
            cloned[clone_count] = cloneEntry(alloc, rr, now + @as(i64, effective_ttl), effective_ttl, authorities) catch continue;
            clone_count += 1;
        }
        if (clone_count == 0) return;

        // Clone SOA outside lock for synthesized responses (RFC 2308 §3)
        var cached_soa: ?dns.ResourceRecord = if (soa_rr) |sr| cloneRecord(alloc, sr) catch null else null;

        // Take write lock only for zone lookup + sorted insert
        if (self.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (self.rwlock) |*rw| rw.unlock(self.io);

        const list = self.getOrCreateZone(alloc, zone_lower) orelse {
            for (cloned[0..clone_count]) |*e| freeEntry(alloc, e);
            if (cached_soa) |*s| freeRecord(alloc, s);
            return;
        };
        if (cached_soa) |soa| {
            if (list.soa) |*old| freeRecord(alloc, old);
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

        if (self.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (self.rwlock) |*rw| rw.unlockShared(self.io);

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

        // Fall through to the root zone (keyed as "").
        if (name_lower.len > 0) {
            if (self.tryZone(caller_alloc, "", qname, qtype, now)) |r| return r;
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
        // so no delegation is possible). No DS exemption: the DS rule lives in
        // isParentSideNsec, not here.
        const zone_label_count = zoneLabelsLen(zone_lower);
        if (qname.labels.len > zone_label_count + 1) {
            const direct_child = dns.Name{ .labels = qname.labels[qname.labels.len - zone_label_count - 1 ..] };
            if (list.findCovering(direct_child, now) == null and list.findExact(direct_child, now) == null) {
                return null; // can't prove no delegation exists
            }
        }

        var proof_refs: [2]*const NsecEntry = undefined;
        var proof_ref_count: usize = 0;
        const kind: SynthResult.Kind, const ce_len: u8 = switch (tryNameNonExistence(list, qname, qtype, now)) {
            .nxdomain => |refs| blk: {
                proof_refs[0] = refs.qname_cover;
                proof_refs[1] = refs.wildcard_cover;
                proof_ref_count = 2;
                break :blk .{ .nxdomain, 0 };
            },
            .wildcard_nodata => |refs| blk: {
                proof_refs[0] = refs.qname_cover;
                proof_refs[1] = refs.wildcard_owner;
                proof_ref_count = 2;
                break :blk .{ .nodata, 0 };
            },
            .wildcard_match => |refs| blk: {
                proof_refs[0] = refs.qname_cover;
                proof_ref_count = 1;
                break :blk .{ .wildcard_match, refs.ce_label_count };
            },
            .unknown => nodata: {
                const nsec = list.findExact(qname, now) orelse return null;
                if (isParentSideNsec(nsec, qname, qtype)) return null;
                // No synthesis if the bitmap asserts qtype, or a CNAME the
                // query must follow (RFC 1034 §3.6.2, RFC 4035 §2.5).
                if (dnssec.bitmapContradictsNodata(nsec.type_bit_maps, qtype))
                    return null;
                break :nodata blk: {
                    proof_refs[0] = nsec;
                    proof_ref_count = 1;
                    break :blk .{ .nodata, 0 };
                };
            },
        };
        var soa = cloneRecord(caller_alloc, cached_soa.*) catch return null;
        // The synthesized verdict lives exactly as long as its weakest proof:
        // the zone-level SOA record does not decay on its own, so bound it here.
        for (proof_refs[0..proof_ref_count]) |r| {
            soa.ttl = @min(soa.ttl, remainingTtl(r, now));
        }
        const proofs = cloneProofs(caller_alloc, proof_refs[0..proof_ref_count], now);
        _ = self.hits.fetchAdd(1, .monotonic);
        return .{ .kind = kind, .soa = soa, .ce_label_count = ce_len, .proofs = proofs };
    }

    pub fn getStats(self: *NsecCache) struct { hits: u64, misses: u64, zones: usize, memory_bytes: usize } {
        if (self.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (self.rwlock) |*rw| rw.unlockShared(self.io);
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

/// Clone an NSEC entry as a fresh ResourceRecord. Owns its name, next, and
/// bitmap independently — freeRecord cleans up via dns.freeRData.
fn nsecEntryToRecord(alloc: Allocator, entry: *const NsecEntry, ttl: u32) !dns.ResourceRecord {
    const name = try dns.cloneName(alloc, entry.owner);
    errdefer dns.freeName(alloc, name);
    const next = try dns.cloneName(alloc, entry.next_domain);
    errdefer dns.freeName(alloc, next);
    const bitmap = try alloc.dupe(u8, entry.type_bit_maps);
    return .{
        .name = name,
        .rtype = .nsec,
        .rclass = .in,
        .ttl = ttl,
        .rdata = .{ .nsec = .{ .next_domain_name = next, .type_bit_maps = bitmap } },
    };
}

/// Seconds of proof life left in `r` at `now`, saturating at 0 and u32.
fn remainingTtl(r: *const NsecEntry, now: i64) u32 {
    return @intCast(std.math.clamp(r.expires_at - now, 0, std.math.maxInt(u32)));
}

/// Clone N NSEC proofs (each with covering RRSIGs) into a fresh slice.
/// Best-effort: on any allocation failure, unwinds anything written so far
/// and returns empty (DO=1 clients see the response as insecure rather
/// than secure; AD-trusting clients are unaffected because hark's verdict
/// already authenticated the synthesis).
fn cloneProofs(alloc: Allocator, refs: []const *const NsecEntry, now: i64) []dns.ResourceRecord {
    if (refs.len == 0) return &.{};
    var total: usize = 0;
    for (refs) |r| total += 1 + r.sigs.len;
    const out = alloc.alloc(dns.ResourceRecord, total) catch return &.{};
    var pos: usize = 0;
    for (refs) |r| {
        const remaining = remainingTtl(r, now);
        if (remaining == 0) {
            unwindProofs(alloc, out, pos);
            return &.{};
        }

        out[pos] = nsecEntryToRecord(alloc, r, remaining) catch {
            unwindProofs(alloc, out, pos);
            return &.{};
        };
        pos += 1;
        for (r.sigs) |sig| {
            out[pos] = cloneRecord(alloc, sig) catch {
                unwindProofs(alloc, out, pos);
                return &.{};
            };
            out[pos].ttl = remaining;
            pos += 1;
        }
    }
    return out[0..pos];
}

fn unwindProofs(alloc: Allocator, out: []dns.ResourceRecord, written: usize) void {
    for (out[0..written]) |*rr| freeRecord(alloc, rr);
    alloc.free(out);
}

/// Result of name non-existence proof (RFC 8198 §5.3). Variants carry
/// pointers to the cached NSECs the verdict relied on so tryZone can
/// clone them into the caller's allocator as proof material.
const NameNonExistence = union(enum) {
    nxdomain: struct { qname_cover: *const NsecEntry, wildcard_cover: *const NsecEntry },
    wildcard_nodata: struct { qname_cover: *const NsecEntry, wildcard_owner: *const NsecEntry },
    wildcard_match: struct { qname_cover: *const NsecEntry, ce_label_count: u8 },
    unknown,
};

fn tryNameNonExistence(list: *const ZoneNsecList, qname: dns.Name, qtype: dns.RType, now: i64) NameNonExistence {
    // (a) Find NSEC covering qname
    const qname_cover = list.findCovering(qname, now) orelse return .unknown;
    if (isParentSideNsec(qname_cover, qname, qtype)) return .unknown;

    // A cover whose next_domain descends below qname proves qname is an empty
    // non-terminal (RFC 4592 §2.2.2): it exists, so NXDOMAIN is a lie and RFC
    // 8020 consumers would deny the whole subtree for the negative TTL. The
    // open range excludes next == qname, so isSubdomainOf is strict — same
    // reasoning as the validator's arm (dnssec.zig, commit 39c5540). ip6.arpa's
    // nibble tree and _tcp/_domainkey under SRV/DANE are all this shape.
    // TODO: an ent_nodata variant would keep the aggressive-cache benefit on
    // exactly the traffic that motivated 39c5540, instead of forfeiting it.
    if (qname_cover.next_domain.isSubdomainOf(qname)) return .unknown;

    // (b) Derive closest encloser from cover, then check wildcard
    const ce = dnssec.closestEncloser(qname, qname_cover.owner, qname_cover.next_domain) orelse
        return .unknown;

    var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
    const wildcard_name = dns.makeWildcardName(&wc_labels_buf, ce) orelse return .unknown;

    // Check if wildcard exists
    if (list.findExact(wildcard_name, now)) |wc_nsec| {
        if (isParentSideNsec(wc_nsec, wildcard_name, qtype)) return .unknown;
        // Wildcard exists. NODATA synthesis is eligible only when nothing
        // in the bitmap would have answered the query.
        if (!dnssec.bitmapContradictsNodata(wc_nsec.type_bit_maps, qtype)) {
            return .{ .wildcard_nodata = .{ .qname_cover = qname_cover, .wildcard_owner = wc_nsec } };
        }
        // CNAME at the wildcard (for a non-CNAME query) must be followed
        // upstream — even beside qtype, where the zone is malformed.
        if (qtype != .cname and dns.typeBitmapContains(wc_nsec.type_bit_maps, .cname))
            return .unknown;
        return .{ .wildcard_match = .{ .qname_cover = qname_cover, .ce_label_count = @intCast(ce.labels.len) } };
    }

    // Prove wildcard name is covered by an NSEC (doesn't exist)
    const wildcard_cover = list.findCovering(wildcard_name, now) orelse return .unknown;
    if (isParentSideNsec(wildcard_cover, wildcard_name, qtype)) return .unknown;
    return .{ .nxdomain = .{ .qname_cover = qname_cover, .wildcard_cover = wildcard_cover } };
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
    var nc = NsecCache.init(.{ .backing = alloc, .max_bytes = 64 * 1024, .io = testing.io });
    nc.now_fn = &testNowSeconds;
    return nc;
}

fn freeSynth(alloc: Allocator, r: *SynthResult) void {
    freeRecord(alloc, &r.soa);
    for (r.proofs) |*p| freeRecord(alloc, p);
    if (r.proofs.len > 0) alloc.free(r.proofs);
}

fn expectSynth(alloc: Allocator, result: ?SynthResult, expected: SynthResult.Kind) !void {
    var r = result orelse return error.TestExpectedEqual;
    defer freeSynth(alloc, &r);
    try testing.expectEqual(expected, r.kind);
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
    }, example_zone, std.math.maxInt(u32));

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
    }, example_zone, std.math.maxInt(u32));

    // beta covered by alpha→gamma, wildcard covered by example.com→alpha
    const qname = try dns.parseDottedName(alloc, "beta.example.com");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .a, "beta.example.com"), .nxdomain);

    // alpha exists — not NXDOMAIN
    const exists = try dns.parseDottedName(alloc, "alpha.example.com");
    defer dns.freeName(alloc, exists);
    try testing.expect(nc.lookupSuffixes(alloc, exists, .a, "alpha.example.com") == null);
}

test "NSEC cache: NXDOMAIN synthesis without apex NSEC (nlnetlabs.nl shape)" {
    // .nl-style signers omit the apex NSEC; CE must come from the cover.
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const bitmap = &[_]u8{ 0, 2, 0x40, 0x01 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);

    // zuul-aws → example.com (apex-wrap qname cover);
    // !. → 6only (covers *.example.com: '!' < '*' < '6').
    const cover_owner = try dns.parseDottedName(alloc, "zuul-aws.example.com");
    const apex = try dns.parseDottedName(alloc, "example.com");
    const wc_cover_owner = try dns.parseDottedName(alloc, "!.example.com");
    const wc_cover_next = try dns.parseDottedName(alloc, "6only.example.com");
    defer dns.freeName(alloc, cover_owner);
    defer dns.freeName(alloc, apex);
    defer dns.freeName(alloc, wc_cover_owner);
    defer dns.freeName(alloc, wc_cover_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = cover_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = apex, .type_bit_maps = bitmap } } },
        .{ .name = wc_cover_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = wc_cover_next, .type_bit_maps = bitmap } } },
    }, example_zone, std.math.maxInt(u32));

    const qname = try dns.parseDottedName(alloc, "zzz-aggt.example.com");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .a, "zzz-aggt.example.com"), .nxdomain);

    // Depth guard: direct-child ancestor outside the cover range, no synth.
    const guarded = try dns.parseDottedName(alloc, "sub.aaa.example.com");
    defer dns.freeName(alloc, guarded);
    try testing.expect(nc.lookupSuffixes(alloc, guarded, .a, "sub.aaa.example.com") == null);

    // Apex query against apex-wrap cover: apex itself isn't covered (next
    // is exclusive), no findExact match — no synth.
    const apex_q = try dns.parseDottedName(alloc, "example.com");
    defer dns.freeName(alloc, apex_q);
    try testing.expect(nc.lookupSuffixes(alloc, apex_q, .a, "example.com") == null);
}

// Bitmap for a parent-side delegation NSEC: NS RRSIG NSEC, no SOA.
// NS=2 → byte 0 bit 5 (mask 0x20); RRSIG=46 → byte 5 bit 1 (mask 0x02);
// NSEC=47 → byte 5 bit 0 (mask 0x01).
const bitmap_delegation = &[_]u8{ 0, 6, 0x20, 0x00, 0x00, 0x00, 0x00, 0x03 };

test "NSEC cache: parent-side qname-cover usable when qname NOT at-or-below owner" {
    // TLD-style: every non-apex NSEC is parent-side (NS+!SOA). The predicate
    // only blocks at-or-below, so sibling NXDOMAINs synthesise from the same
    // proof material the on-wire validator already accepts.
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const bitmap_apex = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);

    // Apex NSEC (NS+SOA — covers *.example.com) + parent-side sibling cover.
    const apex_owner = try dns.parseDottedName(alloc, "example.com");
    const apex_next = try dns.parseDottedName(alloc, "sub.example.com");
    const cover_owner = try dns.parseDottedName(alloc, "nonex.example.com");
    const cover_next = try dns.parseDottedName(alloc, "nonexpired.example.com");
    defer dns.freeName(alloc, apex_owner);
    defer dns.freeName(alloc, apex_next);
    defer dns.freeName(alloc, cover_owner);
    defer dns.freeName(alloc, cover_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = apex_next, .type_bit_maps = bitmap_apex } } },
        .{ .name = cover_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = cover_next, .type_bit_maps = bitmap_delegation } } },
    }, example_zone, std.math.maxInt(u32));

    // commonSuffix(qname, cover_owner) == 2 < owner.labels.len == 3 → predicate
    // doesn't fire → parent-side cover IS the right proof material.
    const qname = try dns.parseDottedName(alloc, "nonexistent.example.com");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .a, "nonexistent.example.com"), .nxdomain);
}

test "NSEC cache: rejects parent-side cover when qname is at-or-below owner (RFC 6840 §4.1)" {
    // Scenario C: cover.owner == `bar.example.com` with NS+!SOA. A query for
    // `foo.bar.example.com` could be tricked into synthesising NXDOMAIN from
    // this parent-side NSEC if the predicate didn't fire — but
    // `bar.example.com`'s child zone is the real authority for that name.
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);

    // Delegation NSEC at the would-be CE, covering the target qname's range.
    const bar_owner = try dns.parseDottedName(alloc, "bar.example.com");
    const qux_next = try dns.parseDottedName(alloc, "qux.example.com");
    // Forged wildcard cover (also parent-side, owner is *.bar's ancestor).
    const wc_cover_owner = try dns.parseDottedName(alloc, "!.bar.example.com");
    const wc_cover_next = try dns.parseDottedName(alloc, "6only.bar.example.com");
    defer dns.freeName(alloc, bar_owner);
    defer dns.freeName(alloc, qux_next);
    defer dns.freeName(alloc, wc_cover_owner);
    defer dns.freeName(alloc, wc_cover_next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = bar_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = qux_next, .type_bit_maps = bitmap_delegation } } },
        .{ .name = wc_cover_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = wc_cover_next, .type_bit_maps = bitmap_delegation } } },
    }, example_zone, std.math.maxInt(u32));

    // foo.bar.example.com: commonSuffix(qname, bar.example.com) == 3 ==
    // owner.labels.len → predicate fires → cover rejected → no synthesis.
    const qname = try dns.parseDottedName(alloc, "foo.bar.example.com");
    defer dns.freeName(alloc, qname);
    try testing.expect(nc.lookupSuffixes(alloc, qname, .a, "foo.bar.example.com") == null);
}

test "NSEC cache: rejects parent-side NODATA at child apex; DS exemption synthesises" {
    // `.unknown` NODATA path: findExact at qname returns a parent-side NSEC.
    // For non-DS qtypes the bitmap reflects only what the parent knows (NS,
    // RRSIG, NSEC) — using it as NODATA proof leaks parent authority into
    // the child apex. For DS qtype the parent IS authoritative (RFC 4035 §5.2).
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);

    // Parent-side NSEC at `child.example.com` (a delegated SLD in example.com).
    const child_owner = try dns.parseDottedName(alloc, "child.example.com");
    const next_owner = try dns.parseDottedName(alloc, "sister.example.com");
    defer dns.freeName(alloc, child_owner);
    defer dns.freeName(alloc, next_owner);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = child_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = next_owner, .type_bit_maps = bitmap_delegation } } },
    }, example_zone, std.math.maxInt(u32));

    const qname = try dns.parseDottedName(alloc, "child.example.com");
    defer dns.freeName(alloc, qname);

    // A query: bitmap has no A; predicate fires for non-DS, NODATA refused.
    try testing.expect(nc.lookupSuffixes(alloc, qname, .a, "child.example.com") == null);

    // DS query: predicate exempts DS; bitmap has no DS; NODATA synthesises.
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .ds, "child.example.com"), .nodata);
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
    }, example_zone, std.math.maxInt(u32));

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
    }, example_zone, std.math.maxInt(u32));

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
    }, example_zone, std.math.maxInt(u32));

    // "foo.example.com" — name doesn't exist, wildcard exists with A
    // → wildcard_match (not NXDOMAIN). Caller synthesizes from RRset cache.
    const qname = try dns.parseDottedName(alloc, "foo.example.com");
    defer dns.freeName(alloc, qname);
    var result = nc.lookupSuffixes(alloc, qname, .a, "foo.example.com") orelse return error.TestExpectedEqual;
    defer freeSynth(alloc, &result);
    try testing.expectEqual(SynthResult.Kind.wildcard_match, result.kind);
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
    }, example_zone, std.math.maxInt(u32));

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
    }, example_zone, std.math.maxInt(u32));

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
    }, example_zone, std.math.maxInt(u32));

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
    }, com_zone, std.math.maxInt(u32));

    // nnn.com (1 label deeper than zone) — should work, no depth issue
    const nnn_com = try dns.parseDottedName(alloc, "nnn.com");
    defer dns.freeName(alloc, nnn_com);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, nnn_com, .a, "nnn.com"), .nxdomain);

    // nnn.example.com (2 labels deeper than "com" zone) — depth check should reject
    // because "example.com" is NOT covered by any NSEC (falls in gap aaa.com→ggg.com)
    const deep_name = try dns.parseDottedName(alloc, "nnn.example.com");
    defer dns.freeName(alloc, deep_name);
    try testing.expect(nc.lookupSuffixes(alloc, deep_name, .a, "nnn.example.com") == null);

    // DS gets no exemption — same depth rejection.
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
    }, example_zone, std.math.maxInt(u32));

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
    const bitmap_wc = &[_]u8{ 0, 2, 0x40, 0x01 }; // A=1, MX=15 present
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
    }, example_zone, std.math.maxInt(u32));

    // "foo.example.com" A — wildcard has A → wildcard_match
    const qname = try dns.parseDottedName(alloc, "foo.example.com");
    defer dns.freeName(alloc, qname);
    var result = nc.lookupSuffixes(alloc, qname, .a, "foo.example.com") orelse return error.TestExpectedEqual;
    defer freeSynth(alloc, &result);
    try testing.expectEqual(SynthResult.Kind.wildcard_match, result.kind);
    try testing.expect(result.ce_label_count > 0);
}

test "NSEC cache: wildcard_match proofs carry NSEC + covering RRSIG" {
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const bitmap_zone = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_wc = &[_]u8{ 0, 2, 0x40, 0x01 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex_owner = try dns.parseDottedName(alloc, "example.com");
    const wc_name = try dns.parseDottedName(alloc, "*.example.com");
    const z_name = try dns.parseDottedName(alloc, "z.example.com");
    defer dns.freeName(alloc, apex_owner);
    defer dns.freeName(alloc, wc_name);
    defer dns.freeName(alloc, z_name);
    const sig_signer = try dns.parseDottedName(alloc, "example.com");
    defer dns.freeName(alloc, sig_signer);

    // Authority section now includes RRSIGs covering the NSEC records —
    // these get bundled onto NsecEntry.sigs and emitted as proofs.
    // Canonical order: `*.example.com` < `foo.example.com` < `z.example.com`,
    // so the qname-covering NSEC for `foo` is the one at `*.example.com`.
    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex_owner, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = wc_name, .type_bit_maps = bitmap_zone } } },
        .{ .name = wc_name, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = z_name, .type_bit_maps = bitmap_wc } } },
        .{ .name = wc_name, .rtype = .rrsig, .rclass = .in, .ttl = 3600, .rdata = .{ .rrsig = .{
            .type_covered = .nsec,
            .algorithm = .ecdsap256sha256,
            .labels = 2,
            .original_ttl = 3600,
            .sig_expiration = 0,
            .sig_inception = 0,
            .key_tag = 0,
            .signer_name = sig_signer,
            .signature = "",
        } } },
    }, example_zone, std.math.maxInt(u32));

    const qname = try dns.parseDottedName(alloc, "foo.example.com");
    defer dns.freeName(alloc, qname);
    var result = nc.lookupSuffixes(alloc, qname, .a, "foo.example.com") orelse return error.TestExpectedEqual;
    defer freeSynth(alloc, &result);
    try testing.expectEqual(SynthResult.Kind.wildcard_match, result.kind);
    // 1 NSEC (qname cover) + 1 RRSIG covering it.
    try testing.expectEqual(@as(usize, 2), result.proofs.len);
    var saw_nsec = false;
    var saw_rrsig = false;
    for (result.proofs) |p| {
        if (p.rtype == .nsec) saw_nsec = true;
        if (p.rtype == .rrsig) saw_rrsig = true;
    }
    try testing.expect(saw_nsec);
    try testing.expect(saw_rrsig);
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
    }, example_zone, std.math.maxInt(u32));

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

test "NSEC cache: root-zone NXDOMAIN synthesis for single-label qname" {
    // Exercises the root-zone suffix-walk fall-through in lookupSuffixes plus
    // CE derivation from the cover NSEC's endpoints — see scenario 007 for
    // the end-to-end demonstration.
    const alloc = testing.allocator;
    var nc = testCache(alloc);
    defer nc.deinit();

    // Bitmap signalling NSEC + RRSIG + DNSKEY + SOA + NS — the load-bearing
    // bit for the wildcard-proof NSEC at root is just "isn't minimal and isn't
    // a delegation NSEC", which this satisfies.
    const bitmap_root = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const bitmap_a = &[_]u8{ 0, 2, 0x40, 0x01 };

    // Root SOA — owner is `.` (empty labels).
    const root_soa = dns.ResourceRecord{
        .name = dns.Name{ .labels = &.{} },
        .rtype = .soa,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .soa = .{
            .mname = try dns.parseDottedName(alloc, "root"),
            .rname = try dns.parseDottedName(alloc, "admin"),
            .serial = 1,
            .refresh = 3600,
            .retry = 900,
            .expire = 604800,
            .minimum = 300,
        } },
    };
    defer dns.freeName(alloc, root_soa.rdata.soa.mname);
    defer dns.freeName(alloc, root_soa.rdata.soa.rname);

    // NSEC chain: `. → a → c`. Covers `b` between `a` and `c` for NXDOMAIN,
    // and covers `*` between `.` and `a` for the wildcard-non-existence proof.
    const a_name = try dns.parseDottedName(alloc, "a");
    const c_name = try dns.parseDottedName(alloc, "c");
    defer dns.freeName(alloc, a_name);
    defer dns.freeName(alloc, c_name);

    nc.storeFromAuthority(&.{
        root_soa,
        .{ .name = dns.Name{ .labels = &.{} }, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = a_name, .type_bit_maps = bitmap_root } } },
        .{ .name = a_name, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = c_name, .type_bit_maps = bitmap_a } } },
    }, dns.Name{ .labels = &.{} }, std.math.maxInt(u32));

    const qname = try dns.parseDottedName(alloc, "b");
    defer dns.freeName(alloc, qname);
    try expectSynth(alloc, nc.lookupSuffixes(alloc, qname, .a, "b"), .nxdomain);
}

// ── DS queries and empty non-terminals ────────────────────────────────
//
// The cache re-derives negative-proof semantics from geometry while the
// on-wire validator carries the shape-specific exceptions — any rule
// added to one belongs in both.

test "NSEC cache: DS query below a delegation is not answered from the parent" {
    // `bar.example.com NSEC qux.example.com` with NS set and SOA clear is the
    // example.com side of a cut. Its range covers foo.bar.example.com, but the
    // parent's authority stops AT bar.example.com — below it only the child
    // can speak, DS included (RFC 6840 §4.1: "all RRs at that owner name other
    // than DS RRs, and all RRs below that owner name regardless of type").
    // Two independent guards now refuse this, and the test passes if either
    // survives: the shared `nsecProvesNameNonexistence` primitive (so
    // findCovering never returns the range) and `isParentSideNsec`'s
    // `!target.eql(nsec.owner)` DS clause. Deleting one alone will NOT fail
    // this test — the belt-and-braces is deliberate, but do not read a green
    // run here as coverage of either guard on its own.
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const bar = try dns.parseDottedName(alloc, "bar.example.com");
    const qux = try dns.parseDottedName(alloc, "qux.example.com");
    defer dns.freeName(alloc, bar);
    defer dns.freeName(alloc, qux);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = bar, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = qux, .type_bit_maps = bitmap_delegation } } },
    }, example_zone, std.math.maxInt(u32));

    const below = try dns.parseDottedName(alloc, "foo.bar.example.com");
    defer dns.freeName(alloc, below);
    try testing.expect(nc.lookupSuffixes(alloc, below, .ds, "foo.bar.example.com") == null);
    try testing.expect(nc.lookupSuffixes(alloc, below, .a, "foo.bar.example.com") == null);
}

test "NSEC cache: child-side apex NSEC cannot deny DS" {
    // DS lives only in the parent. A child apex NSEC (SOA present) never
    // carries the DS bit, so without the SOA clause its bitmap would read as
    // "no DS here" — an authenticated downgrade of a signed delegation.
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    // A NS SOA MX RRSIG NSEC DNSKEY, no DS.
    const child_apex = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex = try dns.parseDottedName(alloc, "example.com");
    const next = try dns.parseDottedName(alloc, "mail.example.com");
    defer dns.freeName(alloc, apex);
    defer dns.freeName(alloc, next);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = next, .type_bit_maps = child_apex } } },
    }, example_zone, std.math.maxInt(u32));

    try testing.expect(nc.lookupSuffixes(alloc, apex, .ds, "example.com") == null);
    // The same NSEC still answers what it legitimately can.
    try expectSynth(alloc, nc.lookupSuffixes(alloc, apex, .txt, "example.com"), .nodata);
}

test "NSEC cache: no NXDOMAIN synthesis at an empty non-terminal" {
    // The ip6.arpa shape. `example.com NSEC sub.ent.example.com` covers
    // ent.example.com, but its next descends *below* ent.example.com — which
    // proves ent.example.com exists as an empty non-terminal. Synthesizing
    // NXDOMAIN here would deny the whole subtree to every RFC 8020 consumer
    // downstream for up to the 3h clamp.
    const alloc = testing.allocator;
    test_time = 1000000;
    var nc = testCache(alloc);
    defer nc.deinit();

    const bitmap_apex = &[_]u8{ 0, 7, 0x62, 0x01, 0x00, 0x00, 0x00, 0x03, 0x80 };
    const soa_rr = try testSoa(alloc);
    defer freeSoa(alloc, soa_rr);
    const apex = try dns.parseDottedName(alloc, "example.com");
    const deep = try dns.parseDottedName(alloc, "sub.ent.example.com");
    defer dns.freeName(alloc, apex);
    defer dns.freeName(alloc, deep);

    nc.storeFromAuthority(&.{
        soa_rr,
        .{ .name = apex, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{ .next_domain_name = deep, .type_bit_maps = bitmap_apex } } },
    }, example_zone, std.math.maxInt(u32));

    const ent = try dns.parseDottedName(alloc, "ent.example.com");
    defer dns.freeName(alloc, ent);
    try testing.expect(nc.lookupSuffixes(alloc, ent, .a, "ent.example.com") == null);
}
