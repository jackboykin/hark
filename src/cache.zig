const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("dns.zig");
const rand = @import("rand.zig");

const CountingAllocator = @import("counting_allocator.zig").CountingAllocator;

/// Maximum TTL for cached entries (1 week). Prevents unreasonably long
/// cache lifetimes from malicious or misconfigured responses.
const max_cache_ttl: u32 = 604_800;

/// Max records per RRset in single-pass store (DNS wire format bounds the total).
const max_rrset_collect: usize = 64;

const defaultNowSeconds = @import("monotonic.zig").nowSec;

// ── Cache key ─────────────────────────────────────────────────────────

const CacheKey = struct {
    /// Lowercased dotted name, owned by the cache.
    name: []const u8,
    rtype: dns.RType,
    rclass: dns.RClass,
};

/// Hash seed randomized at startup to prevent hash collision attacks.
/// Remains 0 in tests (deterministic); call `randomizeHashSeed` in production.
var hash_seed: u64 = 0;

pub fn randomizeHashSeed(io: std.Io) void {
    hash_seed = rand.hashSeed(io);
}

const CacheKeyContext = struct {
    pub fn hash(_: @This(), key: CacheKey) u32 {
        var h = std.hash.Wyhash.init(hash_seed);
        h.update(key.name);
        h.update(mem.asBytes(&key.rtype));
        h.update(mem.asBytes(&key.rclass));
        return @truncate(h.final());
    }

    pub fn eql(_: @This(), a: CacheKey, b: CacheKey, _: usize) bool {
        return a.rtype == b.rtype and a.rclass == b.rclass and mem.eql(u8, a.name, b.name);
    }
};

/// Adapter context for `ArrayHashMap.getIndexAdapted`: returns a hash that
/// the caller has already computed (for shard selection), avoiding the
/// double-hash cost of `getIndex` on the lookup hot path.
const PrecomputedCtx = struct {
    precomputed: u32,
    pub fn hash(self: @This(), _: CacheKey) u32 {
        return self.precomputed;
    }
    pub fn eql(_: @This(), a: CacheKey, b: CacheKey, _: usize) bool {
        return a.rtype == b.rtype and a.rclass == b.rclass and mem.eql(u8, a.name, b.name);
    }
};

// ── Security status ───────────────────────────────────────────────────

/// DNSSEC validation status for cached RRsets.
/// Intentionally a subset of dnssec.SecurityStatus: the cache only stores
/// .secure (validated) or .insecure (provably unsigned); validation
/// failures (.bogus) are never cached — they produce immediate SERVFAIL.
pub const SecurityStatus = enum {
    unchecked,
    secure,
    insecure,
};

// ── Cache entry types ─────────────────────────────────────────────────

const CachedRecord = struct {
    name: dns.Name,
    rtype: dns.RType,
    rclass: dns.RClass,
    rdata: dns.RData,
    wire: []const u8,
    wire_ttl_offset: u16,
};

fn freeCachedRecord(alloc: Allocator, cr: CachedRecord) void {
    dns.freeName(alloc, cr.name);
    dns.freeRData(alloc, cr.rdata);
    alloc.free(cr.wire);
}

/// Stack staging buffer for serializing one RR at store time. Covers typical
/// DNSKEY/RRSIG (<2KB) with headroom; oversized RRs fail to cache.
const rr_wire_stage_len: usize = 4096;

fn buildCachedRecord(alloc: Allocator, rr: dns.ResourceRecord) !CachedRecord {
    var wire_stage: [rr_wire_stage_len]u8 = undefined;
    const built = try dns.buildResourceRecordWire(&wire_stage, rr);
    const wire_owned = try alloc.dupe(u8, built.bytes);
    errdefer alloc.free(wire_owned);
    const cloned_name = try cloneName(alloc, rr.name);
    errdefer dns.freeName(alloc, cloned_name);
    const cloned_rdata = try cloneRData(alloc, rr.rdata);
    return .{
        .name = cloned_name,
        .rtype = rr.rtype,
        .rclass = rr.rclass,
        .rdata = cloned_rdata,
        .wire = wire_owned,
        .wire_ttl_offset = built.ttl_offset,
    };
}

const CachedRRset = struct {
    records: []CachedRecord,
    expires_at: i64,
    original_ttl: u32,
    stored_at: i64,
    security_status: SecurityStatus = .unchecked,
};

const NegativeEntry = struct {
    rcode: dns.RCode,
    expires_at: i64,
    original_ttl: u32,
    stored_at: i64,
    soa: ?CachedRecord,
    security_status: SecurityStatus = .unchecked,
};

const CacheEntry = union(enum) {
    positive: CachedRRset,
    negative: NegativeEntry,

    fn expiresAt(self: CacheEntry) i64 {
        return switch (self) {
            .positive => |p| p.expires_at,
            .negative => |n| n.expires_at,
        };
    }
};

// ── Lookup result ─────────────────────────────────────────────────────

pub const CacheLookupResult = union(enum) {
    hit: struct {
        records: []dns.ResourceRecord,
        remaining_ttl: u32,
        needs_prefetch: bool = false,
        security_status: SecurityStatus = .unchecked,
    },
    negative: struct {
        rcode: dns.RCode,
        remaining_ttl: u32,
        soa: ?dns.ResourceRecord,
        needs_prefetch: bool = false,
        security_status: SecurityStatus = .unchecked,
    },
};

// ── Deep copy helpers ─────────────────────────────────────────────────

const cloneName = dns.cloneName;

pub fn cloneRData(alloc: Allocator, rdata: dns.RData) !dns.RData {
    return switch (rdata) {
        .a => |v| .{ .a = v },
        .aaaa => |v| .{ .aaaa = v },
        .ns => |name| .{ .ns = try cloneName(alloc, name) },
        .cname => |name| .{ .cname = try cloneName(alloc, name) },
        .ptr => |name| .{ .ptr = try cloneName(alloc, name) },
        .mx => |mx| .{ .mx = .{
            .preference = mx.preference,
            .exchange = try cloneName(alloc, mx.exchange),
        } },
        .soa => |soa| blk: {
            const mname = try cloneName(alloc, soa.mname);
            errdefer dns.freeName(alloc, mname);
            const rname = try cloneName(alloc, soa.rname);
            break :blk .{ .soa = .{
                .mname = mname,
                .rname = rname,
                .serial = soa.serial,
                .refresh = soa.refresh,
                .retry = soa.retry,
                .expire = soa.expire,
                .minimum = soa.minimum,
            } };
        },
        .txt => |txt| blk: {
            const strings = try alloc.alloc([]const u8, txt.strings.len);
            errdefer alloc.free(strings);
            var init_count: usize = 0;
            errdefer for (strings[0..init_count]) |s| alloc.free(s);
            for (txt.strings, 0..) |s, i| {
                strings[i] = try alloc.dupe(u8, s);
                init_count += 1;
            }
            break :blk .{ .txt = .{ .strings = strings } };
        },
        .rrsig => |rrsig| blk: {
            const signer = try cloneName(alloc, rrsig.signer_name);
            errdefer dns.freeName(alloc, signer);
            const sig = try alloc.dupe(u8, rrsig.signature);
            break :blk .{ .rrsig = .{
                .type_covered = rrsig.type_covered,
                .algorithm = rrsig.algorithm,
                .labels = rrsig.labels,
                .original_ttl = rrsig.original_ttl,
                .sig_expiration = rrsig.sig_expiration,
                .sig_inception = rrsig.sig_inception,
                .key_tag = rrsig.key_tag,
                .signer_name = signer,
                .signature = sig,
            } };
        },
        .dnskey => |dnskey| .{ .dnskey = .{
            .flags = dnskey.flags,
            .protocol = dnskey.protocol,
            .algorithm = dnskey.algorithm,
            .public_key = try alloc.dupe(u8, dnskey.public_key),
        } },
        .ds => |ds_data| .{ .ds = .{
            .key_tag = ds_data.key_tag,
            .algorithm = ds_data.algorithm,
            .digest_type = ds_data.digest_type,
            .digest = try alloc.dupe(u8, ds_data.digest),
        } },
        .nsec => |nsec_data| blk: {
            const next_name = try cloneName(alloc, nsec_data.next_domain_name);
            errdefer dns.freeName(alloc, next_name);
            break :blk .{ .nsec = .{
                .next_domain_name = next_name,
                .type_bit_maps = try dns.dupeOrEmpty(alloc, nsec_data.type_bit_maps),
            } };
        },
        .nsec3 => |nsec3| blk: {
            const salt = try dns.dupeOrEmpty(alloc, nsec3.salt);
            errdefer dns.freeIfOwned(alloc, salt);
            const next_hash = try dns.dupeOrEmpty(alloc, nsec3.next_hashed_owner);
            errdefer dns.freeIfOwned(alloc, next_hash);
            break :blk .{ .nsec3 = .{
                .hash_algorithm = nsec3.hash_algorithm,
                .flags = nsec3.flags,
                .iterations = nsec3.iterations,
                .salt = salt,
                .next_hashed_owner = next_hash,
                .type_bit_maps = try dns.dupeOrEmpty(alloc, nsec3.type_bit_maps),
            } };
        },
        .nsec3param => |nsec3p| .{ .nsec3param = .{
            .hash_algorithm = nsec3p.hash_algorithm,
            .flags = nsec3p.flags,
            .iterations = nsec3p.iterations,
            .salt = try dns.dupeOrEmpty(alloc, nsec3p.salt),
        } },
        .unknown => |data| .{ .unknown = try alloc.dupe(u8, data) },
    };
}

/// Apply min-TTL floor and max-TTL cap.
fn clampTtl(min_ttl: u32, ttl: u32) u32 {
    const effective = if (min_ttl > 0) @max(ttl, min_ttl) else ttl;
    return @min(effective, max_cache_ttl);
}

/// Clone cached records into caller-owned ResourceRecords with a given TTL.
/// The caller's allocator MUST be an arena (or otherwise free-resilient):
/// records share an inline wire-bytes region packed alongside the records
/// array, and an out-of-line shared owner name from `cloneNameFlat` —
/// neither can be freed individually. Today every caller uses a per-query
/// arena.
fn cloneRRset(alloc: Allocator, cached: []const CachedRecord, ttl: u32) ![]dns.ResourceRecord {
    if (cached.len == 0) return try alloc.alloc(dns.ResourceRecord, 0);

    const RR = dns.ResourceRecord;
    const records_bytes = @sizeOf(RR) * cached.len;
    var total_wire: usize = 0;
    for (cached) |cr| total_wire += cr.wire.len;

    const buf = try alloc.alignedAlloc(
        u8,
        comptime std.mem.Alignment.fromByteUnits(@alignOf(RR)),
        records_bytes + total_wire,
    );
    const records_ptr: [*]RR = @ptrCast(buf.ptr);
    const records: []RR = records_ptr[0..cached.len];
    const wire_area = buf[records_bytes..];

    const shared_name = try dns.cloneNameFlat(alloc, cached[0].name);

    var offset: usize = 0;
    for (cached, 0..) |cr, i| {
        @memcpy(wire_area[offset..][0..cr.wire.len], cr.wire);
        records[i] = .{
            .name = shared_name,
            .rtype = cr.rtype,
            .rclass = cr.rclass,
            .ttl = ttl,
            .rdata = try cloneRData(alloc, cr.rdata),
            .wire = wire_area[offset..][0..cr.wire.len],
            .wire_ttl_offset = cr.wire_ttl_offset,
        };
        offset += cr.wire.len;
    }
    return records;
}

/// Clone an optional CachedRecord into a ResourceRecord with a given TTL.
fn cloneCachedRecord(alloc: Allocator, cached: ?CachedRecord, ttl: u32) ?dns.ResourceRecord {
    const s = cached orelse return null;
    const cloned_name = cloneName(alloc, s.name) catch return null;
    const cloned_rdata = cloneRData(alloc, s.rdata) catch {
        dns.freeName(alloc, cloned_name);
        return null;
    };
    const cloned_wire = alloc.dupe(u8, s.wire) catch {
        dns.freeName(alloc, cloned_name);
        dns.freeRData(alloc, cloned_rdata);
        return null;
    };
    return dns.ResourceRecord{
        .name = cloned_name,
        .rtype = s.rtype,
        .rclass = s.rclass,
        .ttl = ttl,
        .rdata = cloned_rdata,
        .wire = cloned_wire,
        .wire_ttl_offset = s.wire_ttl_offset,
    };
}

/// Lowercase src into dest, returning the written slice.
const lowerInto = dns.lowerNameIntoBuf;

/// Lowercase a name into a stack buffer for lookup. Returns null if name too long.
fn lowerNameBuf(buf: *[dns.max_name_len + 1]u8, name: []const u8) ?[]const u8 {
    if (name.len > dns.max_name_len) return null;
    return lowerInto(buf, name);
}

/// Allocate a lowercased copy of a name string.
fn toLowerNameAlloc(alloc: Allocator, name: []const u8) ![]const u8 {
    const buf = try alloc.alloc(u8, name.len);
    return lowerInto(buf, name);
}

// ── RRsetCache ────────────────────────────────────────────────────────

/// Number of cache shards. Power-of-2 so shard selection is `& mask`.
/// 16 = 2^4 sits in the industry sweet spot (Unbound auto-sets *-slabs to
/// a power of 2 close to thread count; dnsdist defaults to 20 packet-cache
/// shards). Matches dev-host physical core count.
pub const shard_count: u32 = 16;
const shard_mask: u32 = shard_count - 1;

/// Per-shard state. Each shard owns its lock, map, allocator, eviction
/// state, and stat counters. Aligned to 64B so adjacent shards don't
/// share cache lines for their lock state words and counters.
const Shard = struct {
    counting: CountingAllocator,
    map: std.ArrayHashMapUnmanaged(CacheKey, CacheEntry, CacheKeyContext, true),
    rwlock: ?std.Io.RwLock = null,
    /// SIEVE eviction state: per-entry visited flag and circular scan pointer.
    visited: ?[]std.atomic.Value(u8) = null,
    hand: u32 = 0,
    max_entries: u32,
    hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    misses: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stores: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    negative_stores: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    evictions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Subset of `evictions` where the SIEVE scan cap was exhausted.
    cap_exhausted_evictions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    prefetch_eligible: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stale_hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const RRsetCache = struct {
    shards: [shard_count]Shard align(64),
    io: std.Io,
    now_fn: *const fn () i64,
    serve_stale_ttl: u32 = 0,
    min_ttl: u32 = 0,
    prefetch: bool = false,
    skip_key_types: bool = false,

    pub const Config = struct {
        backing: Allocator,
        max_bytes: usize,
        max_entries: u32,
        io: std.Io,
        thread_safe: bool = false,
        prefetch: bool = false,
        serve_stale_ttl: u32 = 0,
        min_ttl: u32 = 0,
        /// Skip .dnskey and .ds records in storeRRsetsImpl (routed to key cache).
        skip_key_types: bool = false,
    };

    pub fn init(cfg: Config) RRsetCache {
        var cache: RRsetCache = .{
            .shards = undefined,
            .io = cfg.io,
            .now_fn = &defaultNowSeconds,
            .serve_stale_ttl = cfg.serve_stale_ttl,
            .min_ttl = cfg.min_ttl,
            .prefetch = cfg.prefetch,
            .skip_key_types = cfg.skip_key_types,
        };

        const per_shard_bytes = @max(cfg.max_bytes / shard_count, 4096);
        const per_shard_entries: u32 = @max(cfg.max_entries / shard_count, 1);

        for (&cache.shards) |*shard| {
            // SIEVE visited flags allocated from backing allocator (not counted against cache budget).
            const visited: ?[]std.atomic.Value(u8) = if (cfg.backing.alloc(std.atomic.Value(u8), per_shard_entries)) |v| blk: {
                for (v) |*slot| slot.* = std.atomic.Value(u8).init(0);
                break :blk v;
            } else |_| null;
            shard.* = .{
                .counting = CountingAllocator.init(cfg.backing, per_shard_bytes),
                .map = .empty,
                .rwlock = if (cfg.thread_safe) std.Io.RwLock.init else null,
                .visited = visited,
                .max_entries = per_shard_entries,
            };
        }
        return cache;
    }

    fn shardOf(self: *RRsetCache, key: CacheKey) *Shard {
        // At N=1 the hash is redundant — map.getIndex computes it anyway.
        // Comptime-eliminate the shard-select hash when there's one shard.
        if (comptime shard_count == 1) return &self.shards[0];
        const h = CacheKeyContext.hash(.{}, key);
        return &self.shards[h & shard_mask];
    }

    /// Compute hash + shard pointer once. Caller passes the hash to
    /// `getIndexAdapted` (read paths) to avoid recomputing it inside the map.
    fn shardWithHash(self: *RRsetCache, key: CacheKey) struct { *Shard, u32 } {
        const h = CacheKeyContext.hash(.{}, key);
        const idx = if (comptime shard_count == 1) 0 else h & shard_mask;
        return .{ &self.shards[idx], h };
    }

    pub const Stats = struct {
        entries: u32,
        memory_bytes: usize,
        max_bytes: usize,
        hits: u64,
        misses: u64,
        stores: u64,
        negative_stores: u64,
        evictions: u64,
        /// Subset of `evictions` where the SIEVE scan cap was exhausted.
        cap_exhausted_evictions: u64,
        prefetch_eligible: u64,
        stale_hits: u64,
    };

    pub fn getStats(self: *RRsetCache) Stats {
        var stats: Stats = .{
            .entries = 0,
            .memory_bytes = 0,
            .max_bytes = 0,
            .hits = 0,
            .misses = 0,
            .stores = 0,
            .negative_stores = 0,
            .evictions = 0,
            .cap_exhausted_evictions = 0,
            .prefetch_eligible = 0,
            .stale_hits = 0,
        };
        for (&self.shards) |*shard| {
            if (shard.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
            stats.entries += @intCast(shard.map.count());
            if (shard.rwlock) |*rw| rw.unlockShared(self.io);
            stats.memory_bytes += shard.counting.current_bytes.load(.monotonic);
            stats.max_bytes += shard.counting.max_bytes;
            stats.hits += shard.hits.load(.monotonic);
            stats.misses += shard.misses.load(.monotonic);
            stats.stores += shard.stores.load(.monotonic);
            stats.negative_stores += shard.negative_stores.load(.monotonic);
            stats.evictions += shard.evictions.load(.monotonic);
            stats.cap_exhausted_evictions += shard.cap_exhausted_evictions.load(.monotonic);
            stats.prefetch_eligible += shard.prefetch_eligible.load(.monotonic);
            stats.stale_hits += shard.stale_hits.load(.monotonic);
        }
        return stats;
    }

    pub fn deinit(self: *RRsetCache) void {
        for (&self.shards) |*shard| {
            const alloc = shard.counting.allocator();
            const keys = shard.map.keys();
            const vals = shard.map.values();
            for (0..shard.map.count()) |i| {
                freeKey(alloc, keys[i]);
                freeEntry(alloc, vals[i]);
            }
            shard.map.deinit(alloc);
            if (shard.visited) |v| shard.counting.backing.free(v);
        }
    }

    // ── Lookup ────────────────────────────────────────────────────────

    /// Cheap existence probe: returns true iff a fresh (non-expired)
    /// positive or negative entry is present for (name, rtype, rclass).
    /// No clone, no prefetch accounting — just a short-lived shared lock
    /// + hash probe + timestamp check. Used as a fast path to skip the
    /// dedup table on cache hits. Marks the entry visited on hit so
    /// SIEVE eviction sees the fast-path access (otherwise hot entries
    /// that always take this path could be evicted as cold).
    pub fn lookupExists(
        self: *RRsetCache,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
    ) bool {
        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return false;
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const shard, const h = self.shardWithHash(probe);
        if (shard.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlockShared(self.io);
        const idx = shard.map.getIndexAdapted(probe, PrecomputedCtx{ .precomputed = h }) orelse return false;
        const now = self.now_fn();
        const fresh = now < shard.map.values()[idx].expiresAt();
        if (fresh) markVisited(shard, idx);
        return fresh;
    }

    /// Look up a cached RRset. Returns null if not found or expired.
    /// On hit, returns records allocated with caller_alloc (the per-query arena),
    /// with TTLs adjusted to reflect remaining time.
    pub fn lookup(
        self: *RRsetCache,
        caller_alloc: Allocator,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
    ) ?CacheLookupResult {
        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return null;
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const shard, const h = self.shardWithHash(probe);
        if (shard.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlockShared(self.io);
        const idx = shard.map.getIndexAdapted(probe, PrecomputedCtx{ .precomputed = h }) orelse {
            _ = shard.misses.fetchAdd(1, .monotonic);
            return null;
        };
        // SIEVE: mark as recently accessed (atomic store, safe under shared read lock)
        markVisited(shard, idx);
        const entry = shard.map.values()[idx];

        const now = self.now_fn();

        switch (entry) {
            .positive => |rrset| {
                const hit = self.evalFreshness(shard, rrset.expires_at, rrset.stored_at, rrset.original_ttl, now, false) orelse return null;
                const records = cloneRRset(caller_alloc, rrset.records, hit.remaining_ttl) catch return null;
                return .{ .hit = .{
                    .records = records,
                    .remaining_ttl = hit.remaining_ttl,
                    .needs_prefetch = hit.needs_prefetch,
                    .security_status = if (hit.force_unchecked) .unchecked else rrset.security_status,
                } };
            },
            .negative => |neg| {
                // SERVFAIL never serves stale: short TTL (e.g. 1s for DNSSEC bogus)
                // is intentional; extending it would prolong failure beyond design.
                const disable_stale = neg.rcode == .server_failure;
                const hit = self.evalFreshness(shard, neg.expires_at, neg.stored_at, neg.original_ttl, now, disable_stale) orelse return null;
                const soa = cloneCachedRecord(caller_alloc, neg.soa, hit.remaining_ttl);
                return .{ .negative = .{
                    .rcode = neg.rcode,
                    .remaining_ttl = hit.remaining_ttl,
                    .soa = soa,
                    .needs_prefetch = hit.needs_prefetch,
                    .security_status = if (hit.force_unchecked) .unchecked else neg.security_status,
                } };
            },
        }
    }

    /// Evaluate freshness for a cache entry, bumping hit/miss/stale counters.
    /// Returns null on full miss (expired beyond stale window, or stale disabled).
    /// On stale hit, returns force_unchecked=true: RRSIGs may have expired since
    /// caching, so the resolver cannot vouch for authenticity (RFC 4035 §3.2.3,
    /// RFC 8767). On fresh hit, force_unchecked=false.
    fn evalFreshness(
        self: *RRsetCache,
        shard: *Shard,
        expires_at: i64,
        stored_at: i64,
        original_ttl: u32,
        now: i64,
        disable_stale: bool,
    ) ?struct { remaining_ttl: u32, needs_prefetch: bool, force_unchecked: bool } {
        if (now < expires_at) {
            const elapsed: u32 = @intCast(@min(@max(now - stored_at, 0), original_ttl));
            const remaining = original_ttl - elapsed;
            const needs_prefetch = self.prefetch and (remaining * 10 <= original_ttl);
            _ = shard.hits.fetchAdd(1, .monotonic);
            if (needs_prefetch) _ = shard.prefetch_eligible.fetchAdd(1, .monotonic);
            return .{ .remaining_ttl = remaining, .needs_prefetch = needs_prefetch, .force_unchecked = false };
        }
        if (disable_stale or self.serve_stale_ttl == 0 or (now - expires_at) >= self.serve_stale_ttl) {
            // Deferred eviction: under shared read lock we cannot mutate the map;
            // expired entries linger until the next write path calls evictIfNeeded.
            _ = shard.misses.fetchAdd(1, .monotonic);
            return null;
        }
        _ = shard.hits.fetchAdd(1, .monotonic);
        _ = shard.stale_hits.fetchAdd(1, .monotonic);
        _ = shard.prefetch_eligible.fetchAdd(1, .monotonic);
        return .{ .remaining_ttl = 30, .needs_prefetch = true, .force_unchecked = true };
    }

    // ── Store ─────────────────────────────────────────────────────────

    /// Cache all RRsets from a DNS response. Applies bailiwick filtering
    /// to all sections to prevent cache poisoning.
    pub fn storeResponse(self: *RRsetCache, response: dns.Message, authority_zone: dns.Name) void {
        self.storeResponseWithStatus(response, authority_zone, .unchecked);
    }

    /// Cache answer RRsets with an explicit security status, and
    /// authorities/additionals with .unchecked (delegation data).
    /// Used by validate-then-store to cache with the correct status
    /// directly, avoiding the unchecked→secure race window.
    ///
    /// Locking is per-RRset (per shard), not per-response. A reader may
    /// observe a partial-response cache state mid-store; DNS clients
    /// tolerate this as they would tolerate a not-yet-arrived response.
    pub fn storeResponseWithStatus(self: *RRsetCache, response: dns.Message, authority_zone: dns.Name, status: SecurityStatus) void {
        if (response.header.rcode != .no_error) return;
        self.storeRRsetsImpl(response.answers, authority_zone, status);
        // Skip authority/additional from positive responses (CVE-2025-11411).
        if (response.answers.len == 0) {
            self.storeRRsetsImpl(response.authorities, authority_zone, .unchecked);
            self.storeRRsetsImpl(response.additionals, authority_zone, .unchecked);
        }
    }

    /// Cache a negative response (NXDOMAIN or NODATA) per RFC 2308.
    /// Only caches if a SOA record is present in the authority section.
    pub fn storeNegative(
        self: *RRsetCache,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
        rcode: dns.RCode,
        authorities: []const dns.ResourceRecord,
        authority_zone: dns.Name,
        security_status: SecurityStatus,
    ) void {
        // Find SOA in authority section — required per RFC 2308
        var soa_record: ?dns.ResourceRecord = null;
        for (authorities) |rr| {
            if (rr.rtype == .soa) {
                soa_record = rr;
                break;
            }
        }
        const soa = soa_record orelse return; // No SOA = don't cache

        // Validate SOA is from a parent zone of the queried name (RFC 2308 §3).
        // Reject cross-zone SOA injection (e.g., SOA for "other.net." in response
        // to "www.example.com" is not a valid parent).
        {
            // Use a stack buffer to avoid charging temporary validation work
            // against the counting allocator's cache memory budget.
            var fba_buf: [512]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
            const queried = dns.parseDottedName(fba.allocator(), name) catch return;
            if (!queried.isSubdomainOf(soa.name)) return;
            // AuthS3 (draft-qiu-dnsop-enhanced-bailiwick): SOA must also be
            // within the delegation chain, not above the zone cut.
            if (authority_zone.labels.len > 0 and !soa.name.isSubdomainOf(authority_zone)) return;
        }

        // TTL = min(SOA record TTL, SOA MINIMUM field) per RFC 2308 §5
        const neg_ttl = @min(soa.ttl, soa.rdata.soa.minimum);
        if (neg_ttl == 0) return;

        // Locate shard from the lowercased name view; key is owned later.
        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const lower_view = lowerNameBuf(&lower_buf, name) orelse return;
        const probe = CacheKey{ .name = lower_view, .rtype = rtype, .rclass = rclass };
        const shard = self.shardOf(probe);

        if (shard.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlock(self.io);

        const alloc = shard.counting.allocator();
        const key_name = toLowerNameAlloc(alloc, name) catch return;
        const key = CacheKey{ .name = key_name, .rtype = rtype, .rclass = rclass };

        if (self.shouldBlockOverwrite(shard, key, security_status)) {
            alloc.free(key_name);
            return;
        }
        removeAndFree(shard, key);

        const cached_soa = buildCachedRecord(alloc, soa) catch {
            alloc.free(key_name);
            return;
        };

        self.evictIfNeeded(shard);

        const now = self.now_fn();
        const capped_ttl = clampTtl(self.min_ttl, neg_ttl);
        shard.map.put(alloc, key, .{ .negative = .{
            .rcode = rcode,
            .expires_at = now + @as(i64, capped_ttl),
            .original_ttl = capped_ttl,
            .stored_at = now,
            .soa = cached_soa,
            .security_status = security_status,
        } }) catch {
            freeCachedRecord(alloc, cached_soa);
            alloc.free(key_name);
            return;
        };
        markLastVisited(shard);
        _ = shard.negative_stores.fetchAdd(1, .monotonic);
    }

    /// Store a bare negative entry (no SOA required).
    /// Used to cache insecure delegation status (negative DS) and
    /// DNSSEC validation failures (bogus SERVFAIL).
    pub fn storeNegativeBare(
        self: *RRsetCache,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
        rcode: dns.RCode,
        ttl: u32,
        security_status: SecurityStatus,
    ) void {
        if (ttl == 0) return;

        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const lower_view = lowerNameBuf(&lower_buf, name) orelse return;
        const probe = CacheKey{ .name = lower_view, .rtype = rtype, .rclass = rclass };
        const shard = self.shardOf(probe);

        if (shard.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlock(self.io);

        const alloc = shard.counting.allocator();
        const key_name = toLowerNameAlloc(alloc, name) catch return;
        const key = CacheKey{ .name = key_name, .rtype = rtype, .rclass = rclass };

        if (self.shouldBlockOverwrite(shard, key, security_status)) {
            alloc.free(key_name);
            return;
        }
        removeAndFree(shard, key);
        self.evictIfNeeded(shard);

        const now = self.now_fn();
        // Don't apply min_ttl — callers provide intentional TTLs (e.g. 1s for
        // DNSSEC SERVFAIL). Only cap at max_cache_ttl.
        const capped_ttl = @min(ttl, max_cache_ttl);
        shard.map.put(alloc, key, .{ .negative = .{
            .rcode = rcode,
            .expires_at = now + @as(i64, capped_ttl),
            .original_ttl = capped_ttl,
            .stored_at = now,
            .soa = null,
            .security_status = security_status,
        } }) catch {
            alloc.free(key_name);
            return;
        };
        markLastVisited(shard);
        _ = shard.negative_stores.fetchAdd(1, .monotonic);
    }

    /// True if a non-expired positive entry exists for (name, rtype, rclass)
    /// with a non-`.unchecked` security status (i.e., `.secure` or `.insecure`
    /// — the entries RFC 9520 §3.4 considers trustworthy).
    /// Takes the shared lock; safe to call without holding any other lock.
    pub fn hasValidatedPositive(
        self: *RRsetCache,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
    ) bool {
        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return false;
        const key = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const shard, const h = self.shardWithHash(key);
        if (shard.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlockShared(self.io);
        const idx = shard.map.getIndexAdapted(key, PrecomputedCtx{ .precomputed = h }) orelse return false;
        return switch (shard.map.values()[idx]) {
            .positive => |p| self.now_fn() < p.expires_at and p.security_status != .unchecked,
            .negative => false,
        };
    }

    // ── Internal ──────────────────────────────────────────────────────

    /// RFC 9520 §3.4 anti-downgrade. Block writes that would lower the
    /// trust rank of a non-expired entry. Same-rank overwrites land
    /// (refresh, zone-state flip), upgrades land (CD=1 revalidation),
    /// downgrades skip — so a forged `.insecure` cannot displace a real
    /// `.secure`, and a CD=1 `.unchecked` cannot displace either.
    fn shouldBlockOverwrite(self: *RRsetCache, shard: *Shard, key: CacheKey, new_status: SecurityStatus) bool {
        const existing = shard.map.get(key) orelse return false;
        if (self.now_fn() >= existing.expiresAt()) return false;
        const existing_status: SecurityStatus = switch (existing) {
            .positive => |p| p.security_status,
            .negative => |n| n.security_status,
        };
        return statusRank(new_status) < statusRank(existing_status);
    }

    fn statusRank(s: SecurityStatus) u8 {
        return switch (s) {
            .unchecked => 0,
            .insecure => 1,
            .secure => 2,
        };
    }

    fn storeRRsetsImpl(self: *RRsetCache, records: []const dns.ResourceRecord, authority_zone: dns.Name, status: SecurityStatus) void {
        if (records.len == 0) return;

        // Track which (name, type) groups we've already processed in this batch
        // to avoid O(n^2) re-scanning. Small fixed buffer — DNS sections are tiny.
        var processed: [64]struct { name_hash: u64, rtype: dns.RType } = undefined;
        var processed_count: usize = 0;

        for (records) |rr| {
            // Skip records we shouldn't cache
            if (rr.ttl == 0) continue;
            if (authority_zone.labels.len > 0 and !rr.name.isSubdomainOf(authority_zone)) continue;

            // Skip SOA in authority — these are for negative caching, handled separately
            if (rr.rtype == .soa) continue;
            // Skip OPT pseudo-records (belt-and-suspenders; parseMessage excludes them)
            if (rr.rtype == .opt) continue;
            // Skip standalone RRSIG — bundled with their signed RRset instead
            if (rr.rtype == .rrsig) continue;
            // Skip DNSKEY/DS when configured (routed to dedicated key cache)
            if (self.skip_key_types and (rr.rtype == .dnskey or rr.rtype == .ds)) continue;

            // Check if we already processed this (name, type) group
            var lower_buf: [dns.max_name_len + 1]u8 = undefined;
            const lower_name = rr.name.formatLower(&lower_buf);
            var nh = std.hash.Wyhash.init(0);
            nh.update(lower_name);
            const name_hash = nh.final();

            var already = false;
            for (processed[0..processed_count]) |p| {
                if (p.name_hash == name_hash and p.rtype == rr.rtype) {
                    already = true;
                    break;
                }
            }
            if (already) continue;
            if (processed_count < processed.len) {
                processed[processed_count] = .{ .name_hash = name_hash, .rtype = rr.rtype };
                processed_count += 1;
            }

            // Single-pass collect into stack buffer (avoids double scan).
            var match_buf: [max_rrset_collect]dns.ResourceRecord = undefined;
            var match_count: usize = 0;
            for (records) |other| {
                if (other.rtype == rr.rtype and other.rclass == rr.rclass and rr.name.eql(other.name)) {
                    if (match_count < match_buf.len) {
                        match_buf[match_count] = other;
                    }
                    match_count += 1;
                }
            }
            const collect_count = @min(match_count, match_buf.len);

            self.storeOneRRset(lower_name, rr, match_buf[0..collect_count], status);
        }
    }

    /// Store a single (name, rtype) RRset group. Acquires the shard's write
    /// lock for just this group; held only across the put + eviction work.
    fn storeOneRRset(
        self: *RRsetCache,
        lower_name: []const u8,
        rr: dns.ResourceRecord,
        matches: []const dns.ResourceRecord,
        status: SecurityStatus,
    ) void {
        const probe = CacheKey{ .name = lower_name, .rtype = rr.rtype, .rclass = rr.rclass };
        const shard = self.shardOf(probe);
        if (shard.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (shard.rwlock) |*rw| rw.unlock(self.io);

        const alloc = shard.counting.allocator();
        const key_name = alloc.dupe(u8, lower_name) catch return;
        const key = CacheKey{ .name = key_name, .rtype = rr.rtype, .rclass = rr.rclass };

        if (self.shouldBlockOverwrite(shard, key, status)) {
            alloc.free(key_name);
            return;
        }
        removeAndFree(shard, key);

        const cached_records = alloc.alloc(CachedRecord, matches.len) catch {
            alloc.free(key_name);
            return;
        };
        var idx: usize = 0;
        for (matches) |other| {
            cached_records[idx] = buildCachedRecord(alloc, other) catch break;
            idx += 1;
        }

        if (idx == 0 or idx < matches.len) {
            // Partial clone failure — don't cache an incomplete RRset.
            for (cached_records[0..idx]) |cr| freeCachedRecord(alloc, cr);
            alloc.free(cached_records);
            alloc.free(key_name);
            return;
        }

        self.evictIfNeeded(shard);

        const now = self.now_fn();
        const capped_ttl = clampTtl(self.min_ttl, rr.ttl);
        shard.map.put(alloc, key, .{ .positive = .{
            .records = cached_records,
            .expires_at = now + @as(i64, capped_ttl),
            .original_ttl = capped_ttl,
            .stored_at = now,
            .security_status = status,
        } }) catch {
            for (cached_records) |cr| freeCachedRecord(alloc, cr);
            alloc.free(cached_records);
            alloc.free(key_name);
            return;
        };
        markLastVisited(shard);
        _ = shard.stores.fetchAdd(1, .monotonic);
    }

    fn evictIfNeeded(self: *RRsetCache, shard: *Shard) void {
        const count: u32 = @intCast(shard.map.count());
        if (count < shard.max_entries) {
            if (count < shard.max_entries / 4 * 3) return;
            self.sweepExpired(shard, count);
            return;
        }
        sieveEvict(shard, count);
    }

    /// Probe a bounded number of entries from the SIEVE hand, evicting the first
    /// expired one. Clears visited flags as it goes for gradual SIEVE decay.
    fn sweepExpired(self: *RRsetCache, shard: *Shard, count: u32) void {
        if (count == 0) return;
        const now = self.now_fn();
        var probes: u32 = 0;
        while (probes < 8) : (probes += 1) {
            if (shard.hand >= count) shard.hand = 0;
            const i = shard.hand;
            shard.hand += 1;
            clearVisited(shard, i);
            const expired = now >= shard.map.values()[i].expiresAt();
            if (expired) {
                removeAtIndex(shard, i);
                _ = shard.evictions.fetchAdd(1, .monotonic);
                shard.hand = if (i < shard.map.count()) @intCast(i) else 0;
                return;
            }
        }
    }
};

// ── Shard helpers ─────────────────────────────────────────────────────
//
// Free functions taking *Shard rather than methods, since Shard is a
// private container type and these helpers need no access to RRsetCache
// global config (now_fn, prefetch, etc.).

fn removeAndFree(shard: *Shard, key: CacheKey) void {
    const idx = shard.map.getIndex(key) orelse return;
    removeAtIndex(shard, idx);
}

inline fn markVisited(shard: *Shard, i: usize) void {
    if (shard.visited) |v| if (i < v.len) v[i].store(1, .monotonic);
}

/// Mark the most recently inserted entry as visited. Callers MUST invoke
/// this only after a `map.put` that was a fresh insert (not an update),
/// so the new entry sits at the tail of the ordered map.
inline fn markLastVisited(shard: *Shard) void {
    markVisited(shard, shard.map.count() - 1);
}

inline fn clearVisited(shard: *Shard, i: usize) void {
    if (shard.visited) |v| if (i < v.len) v[i].store(0, .monotonic);
}

inline fn isVisited(shard: *Shard, i: usize) bool {
    const v = shard.visited orelse return false;
    return i < v.len and v[i].load(.monotonic) != 0;
}

/// Swap-remove entry at index: fixup visited flag, free key/value, clamp hand.
fn removeAtIndex(shard: *Shard, i: usize) void {
    const alloc = shard.counting.allocator();
    const key = shard.map.keys()[i];
    const val = shard.map.values()[i];
    const last = shard.map.count() - 1;
    if (i != last) {
        if (shard.visited) |v| if (i < v.len and last < v.len) {
            v[i].store(v[last].load(.monotonic), .monotonic);
        };
    }
    shard.map.swapRemoveAt(i);
    freeKey(alloc, key);
    freeEntry(alloc, val);
    if (shard.hand >= shard.map.count()) shard.hand = 0;
}

/// SIEVE eviction: scan from hand, give visited entries a second chance,
/// evict the first unvisited entry. Scan is capped to bound write-lock
/// hold time under a full, fully-popular cache — if no unvisited entry
/// is found within the budget, evict at hand. SIEVE is an approximation
/// policy; trading optimal eviction for bounded latency is sound.
const sieve_scan_cap: u32 = 64;

fn sieveEvict(shard: *Shard, count: u32) void {
    const limit = @min(count, sieve_scan_cap);
    var probes: u32 = 0;
    while (probes < limit) : (probes += 1) {
        if (shard.hand >= count) shard.hand = 0;
        const i = shard.hand;
        if (isVisited(shard, i)) {
            clearVisited(shard, i);
            shard.hand += 1;
        } else {
            removeAtIndex(shard, i);
            _ = shard.evictions.fetchAdd(1, .monotonic);
            return;
        }
    }
    // Budget exhausted (or all visited) — evict at hand.
    if (shard.hand >= count) shard.hand = 0;
    removeAtIndex(shard, shard.hand);
    _ = shard.evictions.fetchAdd(1, .monotonic);
    _ = shard.cap_exhausted_evictions.fetchAdd(1, .monotonic);
}

fn freeKey(alloc: Allocator, key: CacheKey) void {
    alloc.free(key.name);
}

fn freeEntry(alloc: Allocator, entry: CacheEntry) void {
    switch (entry) {
        .positive => |rrset| {
            for (rrset.records) |cr| freeCachedRecord(alloc, cr);
            alloc.free(rrset.records);
        },
        .negative => |neg| {
            if (neg.soa) |soa| freeCachedRecord(alloc, soa);
        },
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

var test_time: i64 = 1000;

fn testNowSeconds() i64 {
    return test_time;
}

fn makeTestCache(alloc: Allocator) RRsetCache {
    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    return cache;
}

fn makeTestName(alloc: Allocator, comptime labels: []const []const u8) !dns.Name {
    const name_labels = try alloc.alloc([]const u8, labels.len);
    inline for (labels, 0..) |label, i| name_labels[i] = try alloc.dupe(u8, label);
    return dns.Name{ .labels = name_labels };
}

fn makeTestResponse(answers: []const dns.ResourceRecord) dns.Message {
    return .{
        .header = .{
            .id = 0,
            .qr = true,
            .opcode = .query,
            .aa = true,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .ad = false,
            .cd = false,
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
    };
}

fn storeTestA(cache: *RRsetCache, alloc: Allocator, comptime labels: []const []const u8, ttl: u32, ip: [4]u8) !void {
    return storeTestAWithStatus(cache, alloc, labels, ttl, ip, .unchecked);
}

fn storeTestAWithStatus(cache: *RRsetCache, alloc: Allocator, comptime labels: []const []const u8, ttl: u32, ip: [4]u8, status: SecurityStatus) !void {
    const name = try makeTestName(alloc, labels);
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = ttl, .rdata = .{ .a = ip } };
    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);
    cache.storeResponseWithStatus(response, dns.Name{ .labels = &.{} }, status);
}

fn expectCachedHitStatus(alloc: Allocator, cache: *RRsetCache, name: []const u8, expected: SecurityStatus) !void {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const r = cache.lookup(arena.allocator(), name, .a, .in) orelse return error.TestExpectedHit;
    switch (r) {
        .hit => |h| try testing.expectEqual(expected, h.security_status),
        .negative => return error.TestExpectedHit,
    }
}

fn buildTestSoaAuthority(
    alloc: Allocator,
    comptime soa_labels: []const []const u8,
    comptime mname_labels: []const []const u8,
    comptime rname_labels: []const []const u8,
    ttl: u32,
    minimum: u32,
) ![]dns.ResourceRecord {
    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = try makeTestName(alloc, soa_labels),
        .rtype = .soa,
        .rclass = .in,
        .ttl = ttl,
        .rdata = .{ .soa = .{
            .mname = try makeTestName(alloc, mname_labels),
            .rname = try makeTestName(alloc, rname_labels),
            .serial = 2024010101,
            .refresh = 3600,
            .retry = 900,
            .expire = 604800,
            .minimum = minimum,
        } },
    };
    return authorities;
}

fn freeTestAuthorities(alloc: Allocator, authorities: []dns.ResourceRecord) void {
    for (authorities) |rr| {
        dns.freeName(alloc, rr.name);
        dns.freeRData(alloc, rr.rdata);
    }
    alloc.free(authorities);
}

test "cache store and lookup positive" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "example", "com" }, 300, .{ 93, 184, 216, 34 });

    // Lookup should hit
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "example.com", .a, .in);
    try testing.expect(result != null);
    switch (result.?) {
        .hit => |h| {
            try testing.expectEqual(@as(usize, 1), h.records.len);
            try testing.expectEqual(@as(u32, 300), h.remaining_ttl);
            try testing.expectEqual(dns.RType.a, h.records[0].rtype);
            try testing.expectEqual([4]u8{ 93, 184, 216, 34 }, h.records[0].rdata.a);
        },
        .negative => return error.TestUnexpectedResult,
    }
}

test "cache lookup expired entry returns null" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "example", "com" }, 60, .{ 1, 2, 3, 4 });

    // Advance time past TTL
    test_time = 1061;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "example.com", .a, .in);
    try testing.expect(result == null);
}

test "cache TTL adjustment" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "example", "com" }, 300, .{ 1, 2, 3, 4 });

    // Advance 100 seconds
    test_time = 1100;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "example.com", .a, .in);
    try testing.expect(result != null);
    switch (result.?) {
        .hit => |h| try testing.expectEqual(@as(u32, 200), h.remaining_ttl),
        .negative => return error.TestUnexpectedResult,
    }
}

test "cache case insensitive lookup" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "EXAMPLE", "COM" }, 300, .{ 1, 2, 3, 4 });

    // Lookup with lowercase
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "example.com", .a, .in);
    try testing.expect(result != null);
}

test "cache negative NXDOMAIN" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // min(900, 600) = 600
    const authorities = try buildTestSoaAuthority(alloc, &.{ "example", "com" }, &.{ "ns1", "example", "com" }, &.{ "admin", "example", "com" }, 900, 600);
    defer freeTestAuthorities(alloc, authorities);

    cache.storeNegative("nonexistent.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "nonexistent.example.com", .a, .in);
    try testing.expect(result != null);
    switch (result.?) {
        .negative => |n| {
            try testing.expectEqual(dns.RCode.name_error, n.rcode);
            try testing.expectEqual(@as(u32, 600), n.remaining_ttl); // min(900, 600)
            try testing.expect(n.soa != null);
        },
        .hit => return error.TestUnexpectedResult,
    }
}

test "storeNegative rejects cross-zone SOA" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // SOA for "other.net" — not a parent of "www.example.com"
    const authorities = try buildTestSoaAuthority(alloc, &.{ "other", "net" }, &.{ "ns1", "other", "net" }, &.{ "admin", "other", "net" }, 900, 600);
    defer freeTestAuthorities(alloc, authorities);

    cache.storeNegative("www.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "www.example.com", .a, .in);
    try testing.expect(result == null); // rejected — SOA not a parent
}

test "storeNegative accepts parent-zone SOA" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // SOA for "com" — valid parent of "www.example.com"
    const authorities = try buildTestSoaAuthority(alloc, &.{"com"}, &.{ "ns1", "com" }, &.{ "admin", "com" }, 900, 600);
    defer freeTestAuthorities(alloc, authorities);

    cache.storeNegative("www.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "www.example.com", .a, .in);
    try testing.expect(result != null); // accepted — "com" is a parent
    switch (result.?) {
        .negative => |n| {
            try testing.expectEqual(dns.RCode.name_error, n.rcode);
        },
        .hit => return error.TestUnexpectedResult,
    }
}

test "storeNegative rejects SOA above zone cut" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // SOA for "com" is a valid parent of "www.example.com", but the zone cut
    // is "example.com" — a rogue child server should not inject parent SOA.
    const zone_cut = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, zone_cut);

    const authorities = try buildTestSoaAuthority(alloc, &.{"com"}, &.{ "ns1", "com" }, &.{ "admin", "com" }, 900, 600);
    defer freeTestAuthorities(alloc, authorities);

    cache.storeNegative("www.example.com", .a, .in, .name_error, authorities, zone_cut, .unchecked);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "www.example.com", .a, .in);
    try testing.expect(result == null); // rejected — SOA "com" is above zone cut "example.com"
}

test "cache eviction when full" {
    const alloc = testing.allocator;
    test_time = 1000;

    // Configure cap so each shard floors at 1 entry; storing cap+1 names
    // forces eviction in at least one shard regardless of N.
    const cap = shard_count;
    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = cap, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    var i: u32 = 0;
    while (i < cap + 1) : (i += 1) {
        var name_buf: [32]u8 = undefined;
        const dotted = try std.fmt.bufPrint(&name_buf, "n{d}.com", .{i});
        const parsed = try dns.parseDottedName(alloc, dotted);
        const answers = try alloc.alloc(dns.ResourceRecord, 1);
        answers[0] = .{ .name = parsed, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
        const response = makeTestResponse(answers);
        cache.storeResponse(response, dns.Name{ .labels = &.{} });
        dns.freeMessage(alloc, response);
    }

    try testing.expect(cache.getStats().entries <= cap);
}

test "cache deep copy independence" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Store using an arena, then destroy the arena
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const a = arena.allocator();

        const name = try makeTestName(a, &.{ "deep", "test" });
        const answers = try a.alloc(dns.ResourceRecord, 1);
        answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 10, 20, 30, 40 } } };

        cache.storeResponse(makeTestResponse(answers), dns.Name{ .labels = &.{} });
        // arena destroyed here — cache must still work
    }

    // Lookup after source arena is freed
    var arena2 = std.heap.ArenaAllocator.init(alloc);
    defer arena2.deinit();
    const result = cache.lookup(arena2.allocator(), "deep.test", .a, .in);
    try testing.expect(result != null);
    switch (result.?) {
        .hit => |h| {
            try testing.expectEqual(@as(usize, 1), h.records.len);
            try testing.expectEqual([4]u8{ 10, 20, 30, 40 }, h.records[0].rdata.a);
        },
        .negative => return error.TestUnexpectedResult,
    }
}

test "cache skip zero TTL records" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "zero", "ttl" }, 0, .{ 1, 2, 3, 4 });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "zero.ttl", .a, .in);
    try testing.expect(result == null);
}

test "cache negative without SOA is not stored" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // No SOA in authority
    cache.storeNegative("no-soa.example.com", .a, .in, .name_error, &.{}, dns.Name{ .labels = &.{} }, .unchecked);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "no-soa.example.com", .a, .in);
    try testing.expect(result == null);
}

test "cache prefetch flag at 10 percent TTL" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .prefetch = true });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "example", "com" }, 300, .{ 1, 2, 3, 4 });

    // At 50% TTL — no prefetch
    test_time = 1150;
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const result = cache.lookup(arena.allocator(), "example.com", .a, .in);
        try testing.expect(result != null);
        switch (result.?) {
            .hit => |h| {
                try testing.expectEqual(@as(u32, 150), h.remaining_ttl);
                try testing.expectEqual(false, h.needs_prefetch);
            },
            .negative => return error.TestUnexpectedResult,
        }
    }

    // At 5% TTL (remaining=15 out of 300, 15*10=150 <= 300) — prefetch
    test_time = 1285;
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const result = cache.lookup(arena.allocator(), "example.com", .a, .in);
        try testing.expect(result != null);
        switch (result.?) {
            .hit => |h| {
                try testing.expectEqual(@as(u32, 15), h.remaining_ttl);
                try testing.expectEqual(true, h.needs_prefetch);
            },
            .negative => return error.TestUnexpectedResult,
        }
    }
}

test "cache prefetch disabled by default" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc); // default: prefetch=false
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "example", "com" }, 300, .{ 1, 2, 3, 4 });

    // At 5% TTL — still no prefetch (disabled)
    test_time = 1285;
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const result = cache.lookup(arena.allocator(), "example.com", .a, .in);
        try testing.expect(result != null);
        switch (result.?) {
            .hit => |h| try testing.expectEqual(false, h.needs_prefetch),
            .negative => return error.TestUnexpectedResult,
        }
    }
}

test "cache serve stale within window" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .serve_stale_ttl = 3600 });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "stale", "test" }, 60, .{ 1, 2, 3, 4 });

    // Expired but within stale window
    test_time = 1100; // 40s past expiry
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const result = cache.lookup(arena.allocator(), "stale.test", .a, .in);
        try testing.expect(result != null);
        switch (result.?) {
            .hit => |h| {
                try testing.expectEqual(@as(u32, 30), h.remaining_ttl); // synthetic TTL

                try testing.expectEqual(true, h.needs_prefetch);
            },
            .negative => return error.TestUnexpectedResult,
        }
    }

    try testing.expectEqual(@as(u64, 1), cache.getStats().stale_hits);
}

test "cache serve stale beyond window returns null" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .serve_stale_ttl = 3600 });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "stale2", "test" }, 60, .{ 1, 2, 3, 4 });

    // Beyond stale window (60s TTL + 3600s stale = 3660s)
    test_time = 1000 + 60 + 3601;
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const result = cache.lookup(arena.allocator(), "stale2.test", .a, .in);
        try testing.expect(result == null);
    }
}

test "SERVFAIL never serves stale" {
    // RFC 8767 + design intent: a SERVFAIL with intentionally-short TTL
    // (e.g. 1s for DNSSEC bogus per recursive.zig's bogusServfail) must
    // not be extended into the serve-stale window. Doing so would prolong
    // upstream failure long after the zone is fixed.
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .serve_stale_ttl = 3600 });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    cache.storeNegativeBare("bogus.test", .a, .in, .server_failure, 1, .unchecked);

    // 5s past expiry, well within the 3600s stale window — must still miss.
    test_time = 1000 + 1 + 5;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try testing.expect(cache.lookup(arena.allocator(), "bogus.test", .a, .in) == null);
}

test "cache min TTL floor" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .min_ttl = 300 });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "cdn", "test" }, 60, .{ 1, 2, 3, 4 });

    // Should be cached with TTL=300, not 60
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const result = cache.lookup(arena.allocator(), "cdn.test", .a, .in);
        try testing.expect(result != null);
        switch (result.?) {
            .hit => |h| try testing.expectEqual(@as(u32, 300), h.remaining_ttl),
            .negative => return error.TestUnexpectedResult,
        }
    }

    // Should still be available after original 60s TTL
    test_time = 1100;
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const result = cache.lookup(arena.allocator(), "cdn.test", .a, .in);
        try testing.expect(result != null);
        switch (result.?) {
            .hit => |h| try testing.expectEqual(@as(u32, 200), h.remaining_ttl),
            .negative => return error.TestUnexpectedResult,
        }
    }
}

test "cache stats tracking" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Initial stats should be zero
    const initial = cache.getStats();
    try testing.expectEqual(@as(u64, 0), initial.hits);
    try testing.expectEqual(@as(u64, 0), initial.misses);
    try testing.expectEqual(@as(u64, 0), initial.stores);
    try testing.expectEqual(@as(u32, 0), initial.entries);

    // Miss on empty cache
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    _ = cache.lookup(arena.allocator(), "nonexistent.com", .a, .in);
    try testing.expectEqual(@as(u64, 0), cache.getStats().hits);
    try testing.expectEqual(@as(u64, 1), cache.getStats().misses);

    // Store a record
    try storeTestA(&cache, alloc, &.{ "stats", "test" }, 300, .{ 1, 2, 3, 4 });
    try testing.expectEqual(@as(u64, 1), cache.getStats().stores);
    try testing.expectEqual(@as(u32, 1), cache.getStats().entries);

    // Hit on stored record
    _ = cache.lookup(arena.allocator(), "stats.test", .a, .in);
    try testing.expectEqual(@as(u64, 1), cache.getStats().hits);
    try testing.expectEqual(@as(u64, 1), cache.getStats().misses); // unchanged

    // Expired entry counts as miss
    test_time = 1301;
    _ = cache.lookup(arena.allocator(), "stats.test", .a, .in);
    try testing.expectEqual(@as(u64, 1), cache.getStats().hits); // unchanged
    try testing.expectEqual(@as(u64, 2), cache.getStats().misses);
}

test "BOGUS invalidates .unchecked positive to SERVFAIL" {
    // When background CD=1 revalidation discovers BOGUS, recursive.zig's
    // bogusServfail calls storeNegativeBare(SERVFAIL, ttl=1, .unchecked).
    // An .unchecked positive entry must be overwritten by that negative
    // entry so subsequent CD=0 queries hit SERVFAIL (RFC 4035 §5.5).
    // A .secure positive is protected (RFC 9520 §3.4) and must survive.
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    const name = try makeTestName(alloc, &.{ "example", "com" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    // Step 1: a CD=1 query populates the cache as .unchecked (the CD=1
    // resolver skips inline validation per server.zig's dnssec_enabled gate).
    cache.storeResponseWithStatus(response, dns.Name{ .labels = &.{} }, .unchecked);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    {
        const r = cache.lookup(a, "example.com", .a, .in).?;
        try testing.expectEqual(SecurityStatus.unchecked, r.hit.security_status);
    }

    // Step 2: bg validation finishes .bogus → bogusServfail path.
    cache.storeNegativeBare("example.com", .a, .in, .server_failure, 1, .unchecked);

    // Step 3: next CD=0 lookup must see the SERVFAIL negative, not the
    // stale .unchecked positive (which would have returned answer bytes
    // for bogus data).
    {
        const r = cache.lookup(a, "example.com", .a, .in).?;
        switch (r) {
            .hit => return error.TestExpectedNegative,
            .negative => |n| try testing.expectEqual(dns.RCode.server_failure, n.rcode),
        }
    }
}

test ".unchecked positive is upgraded to .secure on revalidation store" {
    // CD=1 then bg-revalidator: the .secure store must replace the
    // .unchecked entry, else scheduleCd1Revalidate is a silent no-op.
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestAWithStatus(&cache, alloc, &.{ "example", "com" }, 300, .{ 1, 2, 3, 4 }, .unchecked);
    try storeTestAWithStatus(&cache, alloc, &.{ "example", "com" }, 300, .{ 1, 2, 3, 4 }, .secure);
    try expectCachedHitStatus(alloc, &cache, "example.com", .secure);
}

test "fresh .secure positive replaces fresh .secure negative on same key" {
    // A cached negative for (name, rtype) must not block a subsequent
    // positive store at equal trust rank — otherwise a cached NXDOMAIN
    // locks out real data for the full SOA-derived TTL.
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();

    cache.storeNegativeBare("example.com", .a, .in, .name_error, 600, .secure);
    try storeTestAWithStatus(&cache, alloc, &.{ "example", "com" }, 300, .{ 1, 2, 3, 4 }, .secure);
    try expectCachedHitStatus(alloc, &cache, "example.com", .secure);
}

test ".unchecked store does not downgrade fresh .secure positive" {
    // Anti-downgrade: an .unchecked store from a CD=1 query must not
    // replace an already-validated .secure entry.
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestAWithStatus(&cache, alloc, &.{ "example", "com" }, 300, .{ 1, 2, 3, 4 }, .secure);
    try storeTestAWithStatus(&cache, alloc, &.{ "example", "com" }, 300, .{ 9, 9, 9, 9 }, .unchecked);
    try expectCachedHitStatus(alloc, &cache, "example.com", .secure);
}

test "BOGUS never overwrites .secure positive (RFC 9520 §3.4 protection)" {
    // A previously .secure entry must not be dropped by a subsequent
    // SERVFAIL store — hasProtectedPositive guards against downgrade by
    // a stale/injected negative. This is the counterpart invariant to
    // the preceding test: the bg-validation invalidation path only wins
    // against .unchecked, never against already-validated data.
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    const name = try makeTestName(alloc, &.{ "example", "com" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    cache.storeResponseWithStatus(response, dns.Name{ .labels = &.{} }, .secure);

    cache.storeNegativeBare("example.com", .a, .in, .server_failure, 1, .unchecked);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const r = cache.lookup(arena.allocator(), "example.com", .a, .in).?;
    switch (r) {
        .hit => |h| try testing.expectEqual(SecurityStatus.secure, h.security_status),
        .negative => return error.TestExpectedHitAfterProtection,
    }
}

test "shard distribution is reasonable for random names" {
    if (shard_count == 1) return; // degenerate; nothing to distribute
    const alloc = testing.allocator;
    test_time = 1000;

    const n_keys: u32 = 1024;
    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 16 * 1024 * 1024, .max_entries = n_keys * 2, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    var i: u32 = 0;
    while (i < n_keys) : (i += 1) {
        var name_buf: [32]u8 = undefined;
        const dotted = try std.fmt.bufPrint(&name_buf, "host{d}.example.com", .{i});
        const parsed = try dns.parseDottedName(alloc, dotted);
        const answers = try alloc.alloc(dns.ResourceRecord, 1);
        answers[0] = .{ .name = parsed, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
        const response = makeTestResponse(answers);
        cache.storeResponse(response, dns.Name{ .labels = &.{} });
        dns.freeMessage(alloc, response);
    }

    // Pigeonhole: expected mean = n_keys / shard_count. Allow up to 3× mean
    // before flagging as a hash regression. (3× is loose; Wyhash usually
    // stays within 1.5× even for adversarial inputs.)
    const mean_per_shard: usize = n_keys / shard_count;
    const max_allowed: usize = mean_per_shard * 3;
    for (&cache.shards) |*shard| {
        try testing.expect(shard.map.count() <= max_allowed);
    }
}

test "eviction stays within shard" {
    if (shard_count == 1) return;
    const alloc = testing.allocator;
    test_time = 1000;

    // 1 entry per shard. Find two names that hash to distinct shards;
    // fill shard X to capacity + 1 (force eviction in X), assert Y survives.
    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = shard_count, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Pick two names that land in distinct shards.
    var name_a_buf: [16]u8 = undefined;
    var name_b_buf: [16]u8 = undefined;
    const a_idx: u32 = 0;
    var b_idx: u32 = 1;
    while (true) {
        const a = try std.fmt.bufPrint(&name_a_buf, "a{d}.com", .{a_idx});
        const b = try std.fmt.bufPrint(&name_b_buf, "b{d}.com", .{b_idx});
        const ka = CacheKey{ .name = a, .rtype = .a, .rclass = .in };
        const kb = CacheKey{ .name = b, .rtype = .a, .rclass = .in };
        const sa = CacheKeyContext.hash(.{}, ka) & shard_mask;
        const sb = CacheKeyContext.hash(.{}, kb) & shard_mask;
        if (sa != sb) break;
        b_idx += 1;
    }
    const name_a = name_a_buf[0 .. std.mem.indexOfScalar(u8, &name_a_buf, 'm').? + 1];
    const name_b = name_b_buf[0 .. std.mem.indexOfScalar(u8, &name_b_buf, 'm').? + 1];

    // Store name_b first so it sits in its shard.
    {
        const parsed = try dns.parseDottedName(alloc, name_b);
        const answers = try alloc.alloc(dns.ResourceRecord, 1);
        answers[0] = .{ .name = parsed, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
        const response = makeTestResponse(answers);
        cache.storeResponse(response, dns.Name{ .labels = &.{} });
        dns.freeMessage(alloc, response);
    }

    // Hammer name_a's shard: store many names that all hash there.
    var stored: u32 = 0;
    var probe: u32 = 0;
    const a_shard = CacheKeyContext.hash(.{}, .{ .name = name_a, .rtype = .a, .rclass = .in }) & shard_mask;
    while (stored < 4) : (probe += 1) {
        var nb: [16]u8 = undefined;
        const dotted = try std.fmt.bufPrint(&nb, "x{d}.com", .{probe});
        const sh = CacheKeyContext.hash(.{}, .{ .name = dotted, .rtype = .a, .rclass = .in }) & shard_mask;
        if (sh != a_shard) continue;
        const parsed = try dns.parseDottedName(alloc, dotted);
        const answers = try alloc.alloc(dns.ResourceRecord, 1);
        answers[0] = .{ .name = parsed, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 5, 6, 7, 8 } } };
        const response = makeTestResponse(answers);
        cache.storeResponse(response, dns.Name{ .labels = &.{} });
        dns.freeMessage(alloc, response);
        stored += 1;
    }

    // name_b's shard was untouched; its entry must still be there.
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try testing.expect(cache.lookup(arena.allocator(), name_b, .a, .in) != null);
}
