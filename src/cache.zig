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
/// RFC 2308 §5: MAX_NCACHE_TTL SHOULD be a maximum default of 3 hours.
/// BIND/Unbound default to 24h, but pedantic compliance keeps the
/// receiver inside the spec recommendation. Stops a misconfigured or
/// malicious authority from pinning a stale negative for up to a week.
const negative_max_ttl: u32 = 10_800;
/// RFC 9520 §3: resolution-failure cache MUST NOT exceed 5 minutes.
const servfail_max_ttl: u32 = 300;

/// Max records per RRset in single-pass store (DNS wire format bounds the total).
const max_rrset_collect: usize = 64;

const monotonic = @import("monotonic.zig");

// ── Cache key ─────────────────────────────────────────────────────────

const CacheKey = struct {
    /// Lowercased dotted name, owned by the cache.
    name: []const u8,
    rtype: dns.RType,
    rclass: dns.RClass,
};

/// NXDOMAIN denies an entire node for every qtype (RFC 8020 §1 / RFC 1035
/// RCODE 3), so a `name_error` negative is keyed under one reserved rtype
/// rather than per-qtype: a single A-NXDOMAIN then answers a later AAAA
/// without re-walking. qtype 0 is IANA-reserved and can never appear in a
/// real query (RFC 6895 §3.1), so the sentinel slot shares nothing with a
/// genuine RRset. NODATA (`no_error`) stays per-qtype — it denies only the
/// queried type.
const nxdomain_key: dns.RType = @fromBackingInt(@intCast(0));

/// Hash seed randomized at startup to prevent hash collision attacks.
/// Remains 0 in tests (deterministic); call `randomizeHashSeed` in production.
var hash_seed: u64 = 0;

pub fn randomizeHashSeed(io: std.Io) void {
    hash_seed = rand.hashSeed(io);
}

const CacheKeyContext = struct {
    /// Tags fold into the seed rather than streaming: Wyhash's `update` only
    /// memcpys into a staging buffer, where one-shot `hash` reads in place.
    pub fn hash(_: @This(), key: CacheKey) u32 {
        const tag = (@as(u32, @backingInt(key.rtype)) << 16) | @backingInt(key.rclass);
        return @truncate(std.hash.Wyhash.hash(hash_seed ^ tag, key.name));
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
    pub fn eql(_: @This(), a: CacheKey, b: CacheKey, i: usize) bool {
        return CacheKeyContext.eql(.{}, a, b, i);
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

/// The wire at `wire_off` is the record; RDATA is reparsed on hit.
pub const CachedRecord = struct {
    name: dns.Name,
    rtype: dns.RType,
    rclass: dns.RClass,
    wire_off: u32,
    wire_len: u16,
    wire_ttl_offset: u16,
};

/// `[CachedRecord × n][flat names][wire]`; records, sigs, proofs.
pub const Pack = struct {
    blob: []align(pack_align) u8 = &.{},
    n_records: u16 = 0,
    n_sigs: u16 = 0,
    n_proofs: u16 = 0,

    const pack_align = @alignOf(CachedRecord);
    comptime {
        std.debug.assert(pack_align >= dns.name_flat_align.toByteUnits());
    }

    fn all(self: Pack) []const CachedRecord {
        const ptr: [*]const CachedRecord = @ptrCast(self.blob.ptr);
        return ptr[0 .. @as(usize, self.n_records) + self.n_sigs + self.n_proofs];
    }
    fn records(self: Pack) []const CachedRecord {
        return self.all()[0..self.n_records];
    }
    fn sigs(self: Pack) []const CachedRecord {
        return self.all()[self.n_records..][0..self.n_sigs];
    }
    fn proofs(self: Pack) []const CachedRecord {
        return self.all()[@as(usize, self.n_records) + self.n_sigs ..][0..self.n_proofs];
    }
    fn wire(self: Pack, cr: CachedRecord) []const u8 {
        return self.blob[cr.wire_off..][0..cr.wire_len];
    }
};

/// Covers typical DNSKEY/RRSIG (<2KB) with headroom; oversized RRs fail to cache.
const rr_wire_stage_len: usize = 4096;

fn placeName(blob: []align(Pack.pack_align) u8, at: *usize, name: dns.Name) dns.Name {
    const out = dns.writeNameFlat(@alignCast(blob[at.*..]), name, false);
    at.* += std.mem.alignForward(usize, dns.nameFlatSize(name), Pack.pack_align);
    return out;
}

/// All-or-nothing: sigs and proofs must travel with what they cover (RFC 4035 §3.2.3).
fn buildPack(alloc: Allocator, records: []const dns.ResourceRecord, sigs: []const dns.ResourceRecord, proofs: []const dns.ResourceRecord) !Pack {
    std.debug.assert(records.len > 0);
    const groups = [_][]const dns.ResourceRecord{ records, sigs, proofs };
    const n_all = records.len + sigs.len + proofs.len;
    if (n_all > std.math.maxInt(u16)) return error.TooManyRecords;

    const owner = records[0].name;
    var names_bytes = std.mem.alignForward(usize, dns.nameFlatSize(owner), Pack.pack_align);
    for (proofs) |rr| names_bytes += std.mem.alignForward(usize, dns.nameFlatSize(rr.name), Pack.pack_align);

    var wire_bytes: usize = 0;
    var stage: [rr_wire_stage_len]u8 = undefined;
    var parse_scratch: [rr_wire_stage_len * @sizeOf([]const u8)]u8 = undefined;
    for (groups) |g| for (g) |rr| {
        wire_bytes += (try dns.buildResourceRecordWire(&stage, rr)).bytes.len;
    };

    const rec_bytes = @sizeOf(CachedRecord) * n_all;
    const blob = try alloc.alignedAlloc(u8, .fromByteUnits(Pack.pack_align), rec_bytes + names_bytes + wire_bytes);
    errdefer alloc.free(blob);
    if (blob.len > std.math.maxInt(u32)) return error.RRsetTooLarge;

    var names_at = rec_bytes;
    const shared_name = placeName(blob, &names_at, owner);
    const group_owner = [_]?dns.Name{ shared_name, shared_name, null };

    const recs: [*]CachedRecord = @ptrCast(blob.ptr);
    var idx: usize = 0;
    var wire_at = rec_bytes + names_bytes;
    for (groups, group_owner) |g, owner_name| for (g) |rr| {
        const built = try dns.buildResourceRecordWire(blob[wire_at..], rr);
        // Refuse now, not a miss on every hit; scratch fits a TXT of one-byte strings.
        var fba = std.heap.FixedBufferAllocator.init(&parse_scratch);
        _ = try dns.parseRDataWire(fba.allocator(), built.bytes, rr.rtype, built.ttl_offset);
        recs[idx] = .{
            .name = owner_name orelse placeName(blob, &names_at, rr.name),
            .rtype = rr.rtype,
            .rclass = rr.rclass,
            .wire_off = @intCast(wire_at),
            .wire_len = @intCast(built.bytes.len),
            .wire_ttl_offset = built.ttl_offset,
        };
        idx += 1;
        wire_at += built.bytes.len;
    };
    std.debug.assert(wire_at == blob.len);

    return .{
        .blob = blob,
        .n_records = @intCast(records.len),
        .n_sigs = @intCast(sigs.len),
        .n_proofs = @intCast(proofs.len),
    };
}

const CachedRRset = struct {
    pack: Pack,
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
    /// SOA as records[0] when present.
    pack: Pack = .{},
    security_status: SecurityStatus = .unchecked,
};

pub const CacheEntry = union(enum) {
    positive: CachedRRset,
    negative: NegativeEntry,

    fn expiresAt(self: CacheEntry) i64 {
        return switch (self) {
            .positive => |p| p.expires_at,
            .negative => |n| n.expires_at,
        };
    }

    fn pack(self: CacheEntry) Pack {
        return switch (self) {
            .positive => |p| p.pack,
            .negative => |n| n.pack,
        };
    }
};

// ── Lookup result ─────────────────────────────────────────────────────

pub const CacheLookupResult = union(enum) {
    hit: struct {
        records: []dns.ResourceRecord,
        /// RRSIGs covering `records`. Wire shaper strips for DO=0 clients;
        /// kept for DO=1 / CD=1. Empty when zone is unsigned or hark
        /// caches `.unchecked` material.
        sigs: []dns.ResourceRecord = &.{},
        /// RFC 4035 §3.1.3.4 wildcard-expansion proof; recursive synthesis
        /// stitches into authority.
        nsec_proofs: []dns.ResourceRecord = &.{},
        remaining_ttl: u32,
        needs_prefetch: bool = false,
        security_status: SecurityStatus = .unchecked,
        /// RFC 8767 §6: true when the entry has expired but is still inside
        /// the serve-stale window. Resolvers SHOULD attempt fresh resolution
        /// before serving a stale answer.
        is_stale: bool = false,
    },
    negative: struct {
        rcode: dns.RCode,
        remaining_ttl: u32,
        soa: ?dns.ResourceRecord,
        /// RFC 4035 §3.1.3.2 / §3.1.3.3 negative-existence proof.
        nsec_proofs: []dns.ResourceRecord = &.{},
        needs_prefetch: bool = false,
        security_status: SecurityStatus = .unchecked,
        is_stale: bool = false,
    },
};

// ── Deep copy helpers ─────────────────────────────────────────────────

const cloneName = dns.cloneName;

fn clampTtl(min_ttl: u32, ttl: u32) u32 {
    return @min(@max(ttl, min_ttl), max_cache_ttl);
}

/// One arena allocation; `rdata` views into it. Arena callers only.
fn cloneRRset(alloc: Allocator, pack: Pack, cached: []const CachedRecord, ttl: u32) ![]dns.ResourceRecord {
    if (cached.len == 0) return &.{};

    const RR = dns.ResourceRecord;
    const records_bytes = @sizeOf(RR) * cached.len;
    const name_bytes = std.mem.alignForward(usize, dns.nameFlatSize(cached[0].name), @alignOf(RR));
    var total_wire: usize = 0;
    for (cached) |cr| total_wire += cr.wire_len;

    const buf = try alloc.alignedAlloc(
        u8,
        comptime std.mem.Alignment.fromByteUnits(@alignOf(RR)),
        records_bytes + name_bytes + total_wire,
    );
    const records_ptr: [*]RR = @ptrCast(buf.ptr);
    const records: []RR = records_ptr[0..cached.len];
    const shared_name = dns.writeNameFlat(@alignCast(buf[records_bytes..]), cached[0].name, false);
    const wire_area = buf[records_bytes + name_bytes ..];

    var offset: usize = 0;
    for (cached, 0..) |cr, i| {
        const wire = wire_area[offset..][0..cr.wire_len];
        @memcpy(wire, pack.wire(cr));
        records[i] = .{
            .name = shared_name,
            .rtype = cr.rtype,
            .rclass = cr.rclass,
            .ttl = ttl,
            .rdata = try dns.parseRDataWire(alloc, wire, cr.rtype, cr.wire_ttl_offset),
            .wire = wire,
            .wire_ttl_offset = cr.wire_ttl_offset,
        };
        offset += cr.wire_len;
    }
    return records;
}

/// Clone NSEC/NSEC3 proof records (and their covering RRSIGs) out of the
/// cache into the caller's allocator. Unlike `cloneRRset`, proofs carry
/// heterogenous owner names — an NSEC at `b.example` may sit alongside an
/// NSEC at `d.example` proving qname's nonexistence — so allocations
/// happen per-record. `rdata` views into `wire`; arena only.
fn cloneCachedRecords(alloc: Allocator, pack: Pack, cached: []const CachedRecord, ttl: u32) ![]dns.ResourceRecord {
    if (cached.len == 0) return &.{};
    const out = try alloc.alloc(dns.ResourceRecord, cached.len);
    for (cached, 0..) |cr, i| {
        const name = try cloneName(alloc, cr.name);
        const wire = try alloc.dupe(u8, pack.wire(cr));
        const rdata = try dns.parseRDataWire(alloc, wire, cr.rtype, cr.wire_ttl_offset);
        out[i] = .{
            .name = name,
            .rtype = cr.rtype,
            .rclass = cr.rclass,
            .ttl = ttl,
            .rdata = rdata,
            .wire = wire,
            .wire_ttl_offset = cr.wire_ttl_offset,
        };
    }
    return out;
}

/// Collect NSEC/NSEC3 + covering RRSIGs from `records`, bailiwick-filtered.
/// Fills `out` up to its capacity and returns the populated prefix length.
/// Used at store time to capture proof material for wildcard-expanded
/// positive answers (RFC 4035 §3.1.3.4) and NXDOMAIN/NODATA negatives
/// (§3.1.3.2 / §3.1.3.3).
fn collectNsecProofs(
    out: []dns.ResourceRecord,
    records: []const dns.ResourceRecord,
    authority_zone: dns.Name,
) usize {
    var count: usize = 0;
    for (records) |rr| {
        if (count >= out.len) break;
        if (!dns.isNsecProofMaterial(rr)) continue;
        if (!rr.name.isSubdomainOf(authority_zone)) continue;
        out[count] = rr;
        count += 1;
    }
    return count;
}

/// Detect wildcard-expanded answers. RFC 4035 §3.1.3.4: RRSIG.labels is
/// the wildcard owner's depth (root and wildcard label not counted), so
/// when the owner name's label count exceeds RRSIG.labels the rrset was
/// synthesized from a wildcard.
///
/// SECURITY: requires an actual rrset of the covered type at the same
/// owner to exist in answers. The DNSSEC validator only verifies RRSIGs
/// whose type_covered matches qtype; an attacker who can insert an
/// orphan forged RRSIG with `labels<owner` would otherwise trigger NSEC
/// capture and land attacker-supplied proofs on a `.secure` cache entry.
fn answersAreWildcardExpanded(answers: []const dns.ResourceRecord) bool {
    for (answers) |sig_rr| {
        if (sig_rr.rtype != .rrsig) continue;
        const rrsig = sig_rr.rdata.rrsig;
        if (rrsig.labels >= sig_rr.name.labels.len) continue;
        for (answers) |rr| {
            if (rr.rtype == rrsig.type_covered and rr.name.eql(sig_rr.name)) return true;
        }
    }
    return false;
}

/// Lowercase a name into a stack buffer for lookup. Returns null if name too long.
fn lowerNameBuf(buf: *[dns.max_dotted_len + 1]u8, name: []const u8) ?[]const u8 {
    if (name.len > dns.max_dotted_len) return null;
    return dns.lowerNameIntoBuf(buf, name);
}

// ── RRsetCache ────────────────────────────────────────────────────────

/// Cache shards: each is an independent rwlock + map, so lookups on different
/// names run concurrently. The active count is derived per cache from
/// reader_concurrency (Unbound/BIND model: slabs/buckets ~ thread count) and
/// capped by the per-shard entry budget — the read-contention knee tracks the
/// reader count, so a hardcoded value is wrong. Powers of two so selection is
/// `& mask`; `max_shards` is the inline array size (raise for >64-core hosts).
const max_shards: u32 = 64;
const min_shards: u32 = 16;
/// Keep per-shard entries above this so the SIEVE second-chance ring (scan cap
/// 64) and byte budget stay meaningful; this caps shard count on small caches.
const min_entries_per_shard: u32 = 128;

/// Shard from the top bits: the same hash goes to `getIndexAdapted`, which
/// probes from the low ones, so sharing them clusters every shard's index.
const shard_shift = 32 - @as(u6, std.math.log2_int(u32, max_shards));
inline fn shardIndex(h: u32, mask: u32) u32 {
    return (h >> shard_shift) & mask;
}

/// Active shard count: a power of two in [min_shards, max_shards], rounded up
/// toward `reader_concurrency` but capped by the per-shard entry budget.
fn deriveShardCount(reader_concurrency: u32, max_entries: u32) u32 {
    const by_concurrency = std.math.ceilPowerOfTwo(u32, @max(reader_concurrency, 1)) catch max_shards;
    const by_budget = std.math.floorPowerOfTwo(u32, @max(max_entries / min_entries_per_shard, 1));
    return std.math.clamp(@min(by_concurrency, by_budget), min_shards, max_shards);
}

/// Read-path stat counters (hits/misses/prefetch_eligible/stale_hits/expired_remiss) are
/// bumped on every cache hit/miss; as per-shard atomics they contended one
/// line across all readers of a hot shard. Stripe by thread into cache-line
/// slots so each reader bumps its own line; getStats sums. Advisory: a slot is
/// claimed once per thread and never reclaimed, so once more than
/// `counter_slots` distinct threads have *ever* touched the cache (e.g. bg-
/// prefetch churn) some share a slot — mild re-contention, never a torn or lost
/// count. Persistent hot readers (workers + pool) claim distinct slots at
/// startup, so steady-state striping holds.
const counter_slots: u32 = 128;
const counter_slot_mask: u32 = counter_slots - 1;
const no_counter_slot: u32 = std.math.maxInt(u32);

const ReadCounters = struct {
    // hits is cache-line aligned so @sizeOf(ReadCounters) rounds to a full
    // line and array elements never false-share. One thread owns a slot, so
    // the five counters sharing that line is intended, not contention.
    hits: std.atomic.Value(u64) align(std.atomic.cache_line) = std.atomic.Value(u64).init(0),
    misses: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    prefetch_eligible: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stale_hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Subset of `misses` where the entry existed but had expired — cached,
    /// demanded again, died in between. Gauges the prefetch blind spot
    /// (query interval > TTL). Absent-key misses do not count.
    expired_remiss: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

/// Thread's stripe index, assigned once on first cache touch and stable for
/// the thread's life. Shared across RRsetCache instances (each indexes its own
/// read_counters array) — the index is only a stripe selector.
var counter_slot_next: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
threadlocal var counter_slot_tl: u32 = no_counter_slot;

fn threadCounterSlot() u32 {
    if (counter_slot_tl == no_counter_slot)
        counter_slot_tl = counter_slot_next.fetchAdd(1, .monotonic) & counter_slot_mask;
    return counter_slot_tl;
}

/// Per-shard state: lock, map, allocator, eviction state, stat counters.
/// The shards array is cache-line aligned so shard 0 starts on a boundary.
/// Field-level alignment to make `@sizeOf(Shard)` a cache-line multiple was
/// tried — hurt single-thread cache_hit by ~40% with no contention-bench win.
const Shard = struct {
    counting: CountingAllocator,
    map: std.ArrayHashMapUnmanaged(CacheKey, CacheEntry, CacheKeyContext, true),
    rwlock: std.Io.RwLock = std.Io.RwLock.init,
    /// SIEVE eviction state: per-entry visited flag and circular scan pointer.
    visited: ?[]std.atomic.Value(u8) = null,
    hand: u32 = 0,
    max_entries: u32,
    // Read-path counters are striped per-thread in RRsetCache.read_counters
    // (they were contending one line per shard); write-path counters below run
    // under the exclusive lock and are rare.
    stores: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    evictions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Subset of `evictions` where the SIEVE scan cap was exhausted.
    cap_exhausted_evictions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Subset of `evictions` triggered by byte-budget pressure rather than entry-count pressure.
    byte_pressure_evictions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const RRsetCache = struct {
    shards: [max_shards]Shard align(std.atomic.cache_line),
    /// Active shard count (<= max_shards) and its mask, chosen at init.
    shard_count: u32 = max_shards,
    shard_mask: u32 = max_shards - 1,
    /// Per-thread striped read-path counters (see ReadCounters). Default-zeroed.
    read_counters: [counter_slots]ReadCounters align(std.atomic.cache_line) = @splat(.{}),
    io: std.Io,
    now_fn: *const fn () i64,
    serve_stale_ttl: u32 = 0,
    min_ttl: u32 = 0,
    prefetch: bool = false,
    skip_key_types: bool = false,
    /// Notified on each expired-remiss event — the demand signal for the
    /// server's hot-set tracker. Called with the lowercased name under the
    /// shard's SHARED lock: leaf locks only in the handler, and the name
    /// slice (stack buffer) must be copied, not retained. Set post-init.
    remiss_hook: ?RemissHook = null,

    pub const RemissHook = struct {
        ctx: *anyopaque,
        call: *const fn (ctx: *anyopaque, name: []const u8, rtype: dns.RType) void,
    };

    /// `max_bytes` and `max_entries` are split evenly across shards with
    /// floors of 4096 bytes and 1 entry per shard. Configurations smaller
    /// than `shard_count * floor` round up to the floor — production sizes
    /// (≥1 MB, ≥shard_count entries) divide cleanly.
    pub const Config = struct {
        backing: Allocator,
        max_bytes: usize,
        max_entries: u32,
        io: std.Io,
        prefetch: bool = false,
        serve_stale_ttl: u32 = 0,
        min_ttl: u32 = 0,
        /// Skip .dnskey and .ds records in storeRRsetsExcept (routed to key cache).
        skip_key_types: bool = false,
        /// Expected concurrent cache-reader threads (recv workers + their pool
        /// threads). Drives the shard count; see deriveShardCount.
        reader_concurrency: u32 = 1,
        /// Explicit shard-count override (power of 2, <= max_shards). The
        /// contention bench pins this for a fixed-config regression gate; null
        /// derives from reader_concurrency + the entry budget.
        shards: ?u32 = null,
    };

    pub fn init(cfg: Config) RRsetCache {
        const sc = cfg.shards orelse deriveShardCount(cfg.reader_concurrency, cfg.max_entries);
        std.debug.assert(sc >= 1 and sc <= max_shards and std.math.isPowerOfTwo(sc));
        var cache: RRsetCache = .{
            .shards = undefined,
            .shard_count = sc,
            .shard_mask = sc - 1,
            .io = cfg.io,
            .now_fn = &monotonic.nowSec,
            .serve_stale_ttl = cfg.serve_stale_ttl,
            .min_ttl = cfg.min_ttl,
            .prefetch = cfg.prefetch,
            .skip_key_types = cfg.skip_key_types,
        };

        const per_shard_bytes = @max(cfg.max_bytes / sc, 4096);
        const per_shard_entries: u32 = @max(cfg.max_entries / sc, 1);

        for (cache.shards[0..sc]) |*shard| {
            // SIEVE visited flags allocated from backing allocator (not counted against cache budget).
            const visited: ?[]std.atomic.Value(u8) = if (cfg.backing.alloc(std.atomic.Value(u8), per_shard_entries)) |v| blk: {
                for (v) |*slot| slot.* = std.atomic.Value(u8).init(0);
                break :blk v;
            } else |_| null;
            shard.* = .{
                .counting = CountingAllocator.init(cfg.backing, per_shard_bytes, .slot),
                .map = .empty,
                .visited = visited,
                .max_entries = per_shard_entries,
            };
        }
        return cache;
    }

    /// Compute hash + shard pointer once. Caller passes the hash to
    /// `getIndexAdapted` to avoid recomputing it inside the map.
    fn shardWithHash(self: *RRsetCache, key: CacheKey) struct { *Shard, u32 } {
        const h = CacheKeyContext.hash(.{}, key);
        return .{ &self.shards[shardIndex(h, self.shard_mask)], h };
    }

    /// Aggregated across shards. Not a consistent snapshot — a put racing
    /// `getStats` may be reflected in some counters but not others.
    /// Acceptable for monitoring; do not assert invariants like
    /// `stores == entries + evictions` on these values.
    pub const Stats = struct {
        entries: u32 = 0,
        memory_bytes: usize = 0,
        max_bytes: usize = 0,
        hits: u64 = 0,
        misses: u64 = 0,
        stores: u64 = 0,
        evictions: u64 = 0,
        /// Subset of `evictions` where the SIEVE scan cap was exhausted.
        cap_exhausted_evictions: u64 = 0,
        /// Subset of `evictions` triggered by byte-budget pressure.
        byte_pressure_evictions: u64 = 0,
        prefetch_eligible: u64 = 0,
        stale_hits: u64 = 0,
        /// Subset of `misses` where the entry existed but had expired. See
        /// ReadCounters.expired_remiss.
        expired_remiss: u64 = 0,
    };

    pub fn getStats(self: *RRsetCache) Stats {
        var stats: Stats = .{};
        for (self.shards[0..self.shard_count]) |*shard| {
            shard.rwlock.lockSharedUncancelable(self.io);
            stats.entries += @intCast(shard.map.count());
            shard.rwlock.unlockShared(self.io);
            stats.memory_bytes += shard.counting.current_bytes.load(.monotonic);
            stats.max_bytes += shard.counting.max_bytes;
            stats.stores += shard.stores.load(.monotonic);
            stats.evictions += shard.evictions.load(.monotonic);
            stats.cap_exhausted_evictions += shard.cap_exhausted_evictions.load(.monotonic);
            stats.byte_pressure_evictions += shard.byte_pressure_evictions.load(.monotonic);
        }
        // Read-path counters are striped per-thread (see ReadCounters); sum them.
        for (&self.read_counters) |*rc| {
            stats.hits += rc.hits.load(.monotonic);
            stats.misses += rc.misses.load(.monotonic);
            stats.prefetch_eligible += rc.prefetch_eligible.load(.monotonic);
            stats.stale_hits += rc.stale_hits.load(.monotonic);
            stats.expired_remiss += rc.expired_remiss.load(.monotonic);
        }
        return stats;
    }

    pub fn deinit(self: *RRsetCache) void {
        for (self.shards[0..self.shard_count]) |*shard| {
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
    pub fn containsFresh(
        self: *RRsetCache,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
    ) bool {
        var lower_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return false;
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const shard, const h = self.shardWithHash(probe);
        shard.rwlock.lockSharedUncancelable(self.io);
        defer shard.rwlock.unlockShared(self.io);
        const idx = shard.map.getIndexAdapted(probe, PrecomputedCtx{ .precomputed = h }) orelse return false;
        const now = self.now_fn();
        const fresh = now < shard.map.values()[idx].expiresAt();
        if (fresh) markVisited(shard, idx);
        return fresh;
    }

    /// Expiry probe for the hot-set sweeper: `expires_at` (fresh or
    /// expired-lingering) or null when absent. Pure observer — no stat
    /// counters, no SIEVE visited mark.
    pub fn entryExpiry(
        self: *RRsetCache,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
    ) ?i64 {
        var lower_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return null;
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const shard, const h = self.shardWithHash(probe);
        shard.rwlock.lockSharedUncancelable(self.io);
        defer shard.rwlock.unlockShared(self.io);
        const idx = shard.map.getIndexAdapted(probe, PrecomputedCtx{ .precomputed = h }) orelse return null;
        return shard.map.values()[idx].expiresAt();
    }

    fn notifyRemiss(self: *RRsetCache, lower_name: []const u8, rtype: dns.RType) void {
        const hook = self.remiss_hook orelse return;
        hook.call(hook.ctx, lower_name, rtype);
    }

    /// Look up an RRset by (name, rtype, rclass). On hit, records and sigs
    /// are cloned into `caller_alloc` with TTLs adjusted to remaining time.
    ///
    /// Trust-at-store: `hit.security_status` reflects the validator's
    /// verdict at store time; sigs are not re-verified on each read.
    pub fn lookup(
        self: *RRsetCache,
        caller_alloc: Allocator,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
    ) ?CacheLookupResult {
        var lower_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return null;
        if (self.lookupKey(caller_alloc, lower_name, rtype, rclass, false)) |result| return result;
        // A per-qtype miss retries the RFC 8020 sentinel: an NXDOMAIN cached
        // by an earlier qtype denies this one too. Only name_error lives
        // there, so any hit is the node-wide denial.
        if (rtype != nxdomain_key)
            return self.lookupKey(caller_alloc, lower_name, nxdomain_key, rclass, true);
        return null;
    }

    fn lookupKey(
        self: *RRsetCache,
        caller_alloc: Allocator,
        lower_name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
        name_error_only: bool,
    ) ?CacheLookupResult {
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const shard, const h = self.shardWithHash(probe);
        shard.rwlock.lockSharedUncancelable(self.io);
        defer shard.rwlock.unlockShared(self.io);
        const idx = shard.map.getIndexAdapted(probe, PrecomputedCtx{ .precomputed = h }) orelse {
            // The primary probe owns this query's miss; the sentinel retry
            // rides on the same lookup and must not double-charge it.
            if (!name_error_only) _ = self.read_counters[threadCounterSlot()].misses.fetchAdd(1, .monotonic);
            return null;
        };
        markVisited(shard, idx);
        const entry = shard.map.values()[idx];

        const now = self.now_fn();

        switch (entry) {
            .positive => |rrset| {
                if (name_error_only) return null;
                const hit = self.evalFreshness(rrset.expires_at, rrset.stored_at, rrset.original_ttl, now, false) orelse {
                    self.notifyRemiss(lower_name, rtype);
                    return null;
                };
                const records = cloneRRset(caller_alloc, rrset.pack, rrset.pack.records(), hit.remaining_ttl) catch return null;
                // Read path: degrade sigs/proofs to empty on OOM rather than
                // drop the answer. The records themselves are complete (the
                // store path skips any RRset that overflows its collect
                // buffer), so a transient clone failure here only costs a DO
                // client its proofs.
                const sigs: []dns.ResourceRecord = cloneRRset(caller_alloc, rrset.pack, rrset.pack.sigs(), hit.remaining_ttl) catch &.{};
                const nsec_proofs: []dns.ResourceRecord = cloneCachedRecords(caller_alloc, rrset.pack, rrset.pack.proofs(), hit.remaining_ttl) catch &.{};
                return .{ .hit = .{
                    .records = records,
                    .sigs = sigs,
                    .nsec_proofs = nsec_proofs,
                    .remaining_ttl = hit.remaining_ttl,
                    .needs_prefetch = hit.needs_prefetch,
                    .security_status = if (hit.force_unchecked) .unchecked else rrset.security_status,
                    .is_stale = hit.is_stale,
                } };
            },
            .negative => |neg| {
                if (name_error_only and neg.rcode != .name_error) return null;
                // SERVFAIL never serves stale: short TTL (e.g. 1s for DNSSEC bogus)
                // is intentional; extending it would prolong failure beyond design.
                const disable_stale = neg.rcode == .server_failure;
                const hit = self.evalFreshness(neg.expires_at, neg.stored_at, neg.original_ttl, now, disable_stale) orelse {
                    self.notifyRemiss(lower_name, rtype);
                    return null;
                };
                const soa_rrs = cloneRRset(caller_alloc, neg.pack, neg.pack.records(), hit.remaining_ttl) catch return null;
                const soa: ?dns.ResourceRecord = if (soa_rrs.len == 0) null else soa_rrs[0];
                const nsec_proofs: []dns.ResourceRecord = cloneCachedRecords(caller_alloc, neg.pack, neg.pack.proofs(), hit.remaining_ttl) catch &.{};
                return .{ .negative = .{
                    .rcode = neg.rcode,
                    .remaining_ttl = hit.remaining_ttl,
                    .soa = soa,
                    .nsec_proofs = nsec_proofs,
                    .needs_prefetch = hit.needs_prefetch,
                    .security_status = if (hit.force_unchecked) .unchecked else neg.security_status,
                    .is_stale = hit.is_stale,
                } };
            },
        }
    }

    /// RFC 8020: NXDOMAIN at an ancestor proves all names beneath are also
    /// non-existent. `lookup` folds in the sentinel key, so an ancestor
    /// NXDOMAIN cached under any qtype cuts here regardless of `rtype` —
    /// never false-cuts, no longer qtype-blind. Non-secure only; signed-zone
    /// cuts go through the RFC 8198 NSEC aggressive-use cache.
    pub fn lookupNxdomainAncestor(
        self: *RRsetCache,
        caller_alloc: Allocator,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
    ) ?CacheLookupResult {
        // Real query workloads almost never have NXDOMAIN cuts deeper than
        // 4–5 labels above the leaf, and the cuts that exist in practice are
        // at zone-cut depth, not at every intermediate label. 8 covers TLD +
        // apex + a couple of subdomain levels.
        var ancestors = dns.Ancestors.init(name, 8);
        while (ancestors.next()) |ancestor| {
            const result = self.lookup(caller_alloc, ancestor, rtype, rclass) orelse continue;
            switch (result) {
                .negative => |n| {
                    if (n.rcode == .name_error and n.security_status != .secure) return result;
                },
                .hit => {},
            }
        }
        return null;
    }

    /// Evaluate freshness for a cache entry, bumping hit/miss/stale counters.
    /// Returns null on full miss (expired beyond stale window, or stale disabled).
    /// On stale hit, returns force_unchecked=true: RRSIGs may have expired since
    /// caching, so the resolver cannot vouch for authenticity (RFC 4035 §3.2.3,
    /// RFC 8767). On fresh hit, force_unchecked=false.
    fn evalFreshness(
        self: *RRsetCache,
        expires_at: i64,
        stored_at: i64,
        original_ttl: u32,
        now: i64,
        disable_stale: bool,
    ) ?struct { remaining_ttl: u32, needs_prefetch: bool, force_unchecked: bool, is_stale: bool } {
        const cs = &self.read_counters[threadCounterSlot()];
        if (now < expires_at) {
            const elapsed: u32 = @intCast(@min(@max(now - stored_at, 0), original_ttl));
            const remaining = original_ttl - elapsed;
            const needs_prefetch = self.prefetch and (remaining <= original_ttl / 10);
            _ = cs.hits.fetchAdd(1, .monotonic);
            if (needs_prefetch) _ = cs.prefetch_eligible.fetchAdd(1, .monotonic);
            return .{ .remaining_ttl = remaining, .needs_prefetch = needs_prefetch, .force_unchecked = false, .is_stale = false };
        }
        if (disable_stale or self.serve_stale_ttl == 0 or (now - expires_at) >= self.serve_stale_ttl) {
            // Deferred eviction: under shared read lock we cannot mutate the map;
            // expired entries linger until the next write path calls evictIfNeeded.
            _ = cs.misses.fetchAdd(1, .monotonic);
            _ = cs.expired_remiss.fetchAdd(1, .monotonic);
            return null;
        }
        _ = cs.hits.fetchAdd(1, .monotonic);
        _ = cs.stale_hits.fetchAdd(1, .monotonic);
        _ = cs.prefetch_eligible.fetchAdd(1, .monotonic);
        // is_stale is computed from now/expires_at directly (not derived from
        // force_unchecked) so a future change that flips force_unchecked for
        // a non-stale reason can't silently lie to the resolver's RFC 8767
        // try-fresh-first branch.
        return .{ .remaining_ttl = 30, .needs_prefetch = true, .force_unchecked = true, .is_stale = true };
    }

    // ── Store ─────────────────────────────────────────────────────────

    const Lifetime = struct { ttl: u32, expires_at: i64, stored_at: i64 };

    /// `ttl` arrives floored and capped by config; `authenticated_ttl_max` is
    /// the validator's bound (`maxInt` if none) and goes on last, so `min_ttl`
    /// cannot lift an entry past its own proof.
    ///
    /// The cache does no RRSIG arithmetic: it cannot tell which signature
    /// verified, and reducing over the ones present let a single appended
    /// unverifiable RRSIG drive a `.secure` entry's TTL to zero.
    fn lifetime(self: *RRsetCache, ttl: u32, authenticated_ttl_max: u32) Lifetime {
        const capped = @min(ttl, authenticated_ttl_max);
        const now = self.now_fn();
        return .{ .ttl = capped, .expires_at = now + @as(i64, capped), .stored_at = now };
    }

    /// Cache all RRsets from a DNS response with bailiwick filtering.
    /// Answers get `status`; authorities/additionals always get `.unchecked`
    /// (delegation data). Validate-then-store passes the resolved status
    /// directly to avoid an unchecked→secure race window.
    ///
    /// Locking is per-RRset (per shard), not per-response. A reader may
    /// observe a partial-response cache state mid-store; DNS clients
    /// tolerate this as they would tolerate a not-yet-arrived response.
    pub fn storeResponse(self: *RRsetCache, response: dns.Message, authority_zone: dns.Name, status: SecurityStatus, authenticated_ttl_max: u32) void {
        if (response.header.flags.rcode != .no_error) return;

        // RFC 4035 §3.1.3.4: capture the wildcard NSEC denial onto the answer
        // entry so cache hits ship the same proof live did.
        var proof_buf: [32]dns.ResourceRecord = undefined;
        var proofs: []const dns.ResourceRecord = &.{};
        if (answersAreWildcardExpanded(response.answers)) {
            const n = collectNsecProofs(&proof_buf, response.authorities, authority_zone);
            proofs = proof_buf[0..n];
        }

        self.storeRRsetsExcept(response.answers, authority_zone, status, &.{}, proofs, authenticated_ttl_max);
        if (response.answers.len == 0) {
            // Referral / NODATA-without-SOA: cache everything (bailiwick filter
            // handles cross-zone poisoning).
            self.storeRRsetsExcept(response.authorities, authority_zone, .unchecked, &.{}, &.{}, std.math.maxInt(u32));
            self.storeRRsetsExcept(response.additionals, authority_zone, .unchecked, &.{}, &.{}, std.math.maxInt(u32));
        } else {
            // CVE-2025-11411: child auth listing parent NS in its own authority
            // would overwrite a valid delegation. Strip NS from authority and
            // A/AAAA glue from additional. NSEC/NSEC3 + RRSIGs survive — DO=1
            // clients still get proof material on cache-served wildcards.
            self.storeRRsetsExcept(response.authorities, authority_zone, .unchecked, &.{.ns}, &.{}, std.math.maxInt(u32));
            self.storeRRsetsExcept(response.additionals, authority_zone, .unchecked, &.{ .a, .aaaa }, &.{}, std.math.maxInt(u32));
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
        authenticated_ttl_max: u32,
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
            if (!soa.name.isSubdomainOf(authority_zone)) return;
        }

        // TTL = min(SOA record TTL, SOA MINIMUM field) per RFC 2308 §5
        const neg_ttl = @min(soa.ttl, soa.rdata.soa.minimum);
        if (neg_ttl == 0) return;

        // RFC 4035 §3.1.3.2 / §3.1.3.3 negative-existence proof. Collected
        // before slot lock acquisition to bound critical-section duration.
        var proof_buf: [32]dns.ResourceRecord = undefined;
        var proof_count = collectNsecProofs(&proof_buf, authorities, authority_zone);
        // The SOA's own RRSIG rides along: a cache hit must hand a DO client
        // the same validatable shape live did, and the SOA is the one record
        // here that collectNsecProofs does not cover.
        for (authorities) |rr| {
            if (proof_count >= proof_buf.len) break;
            if (dns.rrsigCovers(rr) != .soa or !rr.name.eql(soa.name)) continue;
            proof_buf[proof_count] = rr;
            proof_count += 1;
        }
        const proofs = proof_buf[0..proof_count];

        var lower_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const lower_view = lowerNameBuf(&lower_buf, name) orelse return;
        // RFC 8020: an NXDOMAIN holds for every qtype, so it lands under the
        // shared sentinel key; NODATA and any other rcode stay type-scoped.
        const key_rtype = if (rcode == .name_error) nxdomain_key else rtype;
        const slot = self.prepareSlot(lower_view, key_rtype, rclass, security_status, .always) orelse return;
        defer slot.shard.rwlock.unlock(self.io);

        // Refuse rather than cache a negative whose NSEC proofs were truncated
        // under OOM — a denial a DO client couldn't validate (RFC 4035 §3.1.3.2/.3).
        const pack = buildPack(slot.alloc, &.{soa}, &.{}, proofs) catch {
            slot.alloc.free(slot.key.name);
            return;
        };

        // RFC 2308 §5 SHOULD-3h cap on top of the min-TTL floor / max-TTL clamp.
        const life = self.lifetime(@min(clampTtl(self.min_ttl, neg_ttl), negative_max_ttl), authenticated_ttl_max);
        slot.shard.map.put(slot.alloc, slot.key, .{ .negative = .{
            .rcode = rcode,
            .expires_at = life.expires_at,
            .original_ttl = life.ttl,
            .stored_at = life.stored_at,
            .pack = pack,
            .security_status = security_status,
        } }) catch {
            slot.alloc.free(pack.blob);
            slot.alloc.free(slot.key.name);
            return;
        };
        markLastVisited(slot.shard);
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
        overwrite: Overwrite,
    ) void {
        if (ttl == 0) return;

        var lower_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const lower_view = lowerNameBuf(&lower_buf, name) orelse return;
        const slot = self.prepareSlot(lower_view, rtype, rclass, security_status, overwrite) orelse return;
        defer slot.shard.rwlock.unlock(self.io);

        // Don't apply min_ttl — callers provide intentional TTLs (e.g. 1s for
        // DNSSEC SERVFAIL). RFC 9520 §3 caps resolution-failure caching at
        // 5 minutes; NXDOMAIN/NODATA at RFC 2308 §5's 3h SHOULD ceiling.
        const ceiling: u32 = if (rcode == .server_failure) servfail_max_ttl else negative_max_ttl;
        // Caller-chosen TTL on a record-less entry: nothing to bound it by.
        const life = self.lifetime(@min(ttl, ceiling), std.math.maxInt(u32));
        slot.shard.map.put(slot.alloc, slot.key, .{ .negative = .{
            .rcode = rcode,
            .expires_at = life.expires_at,
            .original_ttl = life.ttl,
            .stored_at = life.stored_at,
            .security_status = security_status,
        } }) catch {
            slot.alloc.free(slot.key.name);
            return;
        };
        markLastVisited(slot.shard);
    }

    /// Cache a resolution failure per RFC 9520 §3. TTL chosen short (5 s)
    /// — long enough to absorb a misbehaving stub's retry storm, short
    /// enough that recovery from a transient upstream failure is fast.
    /// Never displaces a fresh entry: a failure marker is the lowest-value
    /// cache content, and any fresh entry here means a racing resolve
    /// succeeded after this one started.
    pub fn cacheServfail(self: *RRsetCache, name: []const u8, rtype: dns.RType) void {
        self.storeNegativeBare(name, rtype, .in, .server_failure, 5, .unchecked, .unless_fresh);
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
        var lower_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return false;
        const key = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const shard, const h = self.shardWithHash(key);
        shard.rwlock.lockSharedUncancelable(self.io);
        defer shard.rwlock.unlockShared(self.io);
        const idx = shard.map.getIndexAdapted(key, PrecomputedCtx{ .precomputed = h }) orelse return false;
        return switch (shard.map.values()[idx]) {
            .positive => |p| self.now_fn() < p.expires_at and p.security_status != .unchecked,
            .negative => false,
        };
    }

    // ── Internal ──────────────────────────────────────────────────────

    /// Displacement policy for a store finding a live entry in its slot.
    /// `.unless_fresh` is for failure markers, which never displace a fresh
    /// entry of any status; checked under the shard write lock so a
    /// concurrent successful store cannot be clobbered between a caller's
    /// freshness probe and the write (TOCTOU on the background-cousin path).
    pub const Overwrite = enum { always, unless_fresh };

    /// One home for "may this write displace the existing entry": the RFC
    /// 9520 §3.4 anti-downgrade rank check plus the failure-marker policy.
    /// Same-rank overwrites land (refresh, zone-state flip), upgrades land
    /// (CD=1 revalidation), downgrades skip — so a forged `.insecure` cannot
    /// displace a real `.secure`, and a CD=1 `.unchecked` cannot displace
    /// either.
    fn shouldBlockOverwrite(self: *RRsetCache, shard: *Shard, h: u32, key: CacheKey, new_status: SecurityStatus, overwrite: Overwrite) bool {
        const idx = shard.map.getIndexAdapted(key, PrecomputedCtx{ .precomputed = h }) orelse return false;
        const existing = shard.map.values()[idx];
        if (self.now_fn() >= existing.expiresAt()) return false;
        if (overwrite == .unless_fresh) return true;
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

    /// Cache every (name, rtype, rclass) rrset in `records`, skipping
    /// any whose rtype is in `skip_types`. RRSIGs are bundled with the
    /// rrset they cover (RFC 4035 §5.3.1) — pass `skip_types = &.{}` to
    /// admit everything (the default for unfiltered store paths).
    fn storeRRsetsExcept(
        self: *RRsetCache,
        records: []const dns.ResourceRecord,
        authority_zone: dns.Name,
        status: SecurityStatus,
        skip_types: []const dns.RType,
        nsec_proofs: []const dns.ResourceRecord,
        authenticated_ttl_max: u32,
    ) void {
        if (records.len == 0) return;

        // Track which (name, type) groups we've already processed in this batch
        // to avoid O(n^2) re-scanning. Small fixed buffer — DNS sections are tiny.
        var processed: [64]struct { name: dns.Name, rtype: dns.RType } = undefined;
        var processed_count: usize = 0;

        record_loop: for (records) |rr| {
            // Skip records we shouldn't cache
            if (rr.ttl == 0) continue;
            if (!rr.name.isSubdomainOf(authority_zone)) continue;

            // Skip SOA in authority — these are for negative caching, handled separately
            if (rr.rtype == .soa) continue;
            // Skip OPT pseudo-records (belt-and-suspenders; parseMessage excludes them)
            if (rr.rtype == .opt) continue;
            // RRSIG is bundled into its covered RRset's `sigs` slot below;
            // don't drive a standalone-RRSIG cache entry.
            if (rr.rtype == .rrsig) continue;
            // Skip DNSKEY/DS when configured (routed to dedicated key cache)
            if (self.skip_key_types and (rr.rtype == .dnskey or rr.rtype == .ds)) continue;
            // Caller-supplied type filter (e.g. surgical NS strip for
            // CVE-2025-11411 from positive-response authority).
            for (skip_types) |st| {
                if (rr.rtype == st) continue :record_loop;
            }

            // Check if we already processed this (name, type) group. `eql`
            // folds case, matching the collection loop below.
            var already = false;
            for (processed[0..processed_count]) |p| {
                if (p.rtype == rr.rtype and p.name.eql(rr.name)) {
                    already = true;
                    break;
                }
            }
            if (already) continue;
            if (processed_count < processed.len) {
                processed[processed_count] = .{ .name = rr.name, .rtype = rr.rtype };
                processed_count += 1;
            }

            var lower_buf: [dns.max_dotted_len + 1]u8 = undefined;
            const lower_name = rr.name.formatLower(&lower_buf);

            // Single-pass collect into stack buffer (avoids double scan).
            var match_buf: [max_rrset_collect]dns.ResourceRecord = undefined;
            var match_count: usize = 0;
            var sig_buf: [max_rrset_collect]dns.ResourceRecord = undefined;
            var sig_count: usize = 0;
            for (records) |other| {
                if (other.rclass != rr.rclass) continue;
                if (!rr.name.eql(other.name)) continue;
                if (other.rtype == rr.rtype) {
                    if (match_count < match_buf.len) {
                        match_buf[match_count] = other;
                    }
                    match_count += 1;
                } else if (dns.rrsigCovers(other) == rr.rtype) {
                    if (sig_count < sig_buf.len) {
                        sig_buf[sig_count] = other;
                    }
                    sig_count += 1;
                }
            }
            // Don't cache what we can't hold whole. Storing the first 64 would
            // serve a silently-short RRset without TC=1 for the whole TTL
            // (RFC 2181 §5.1) while the miss client got all N — correct-but-
            // uncached beats wrong-and-cached.
            if (match_count > match_buf.len or sig_count > sig_buf.len) continue;

            self.storeOneRRset(lower_name, rr, match_buf[0..match_count], sig_buf[0..sig_count], status, nsec_proofs, authenticated_ttl_max);
        }
    }

    /// Acquire the shard write lock and reserve a slot. Caller defers
    /// unlock on success and frees `key.name` on later failure paths.
    fn prepareSlot(
        self: *RRsetCache,
        lower_name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
        status: SecurityStatus,
        overwrite: Overwrite,
    ) ?struct { shard: *Shard, alloc: Allocator, key: CacheKey } {
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const shard, const h = self.shardWithHash(probe);
        shard.rwlock.lockUncancelable(self.io);
        // Displacement check must run before evictIfNeeded: SIEVE is
        // security-blind, so an eviction here could silently drop the
        // existing .secure entry we're about to refuse to overwrite (RFC
        // 9520 §3.4). Probe key is fine — shouldBlockOverwrite only reads
        // .name bytes for the hash-adapted lookup.
        if (self.shouldBlockOverwrite(shard, h, probe, status, overwrite)) {
            shard.rwlock.unlock(self.io);
            return null;
        }
        // Evict before allocating: the key-name dupe itself counts against
        // the byte budget, so byte-pressure eviction must run first or the
        // dupe latches the shard at max_bytes.
        self.evictIfNeeded(shard);
        const alloc = shard.counting.allocator();
        const key_name = alloc.dupe(u8, lower_name) catch {
            shard.rwlock.unlock(self.io);
            return null;
        };
        const key = CacheKey{ .name = key_name, .rtype = rtype, .rclass = rclass };
        removeAndFree(shard, h, key);
        return .{ .shard = shard, .alloc = alloc, .key = key };
    }

    /// Store a single (name, rtype) RRset group. Acquires the shard's write
    /// lock for just this group; held only across the put + eviction work.
    /// `sigs` are RRSIGs covering the rrset (same name, type_covered ==
    /// rr.rtype); stored alongside under RFC 4035 §5.3.1's invariant that
    /// signature and covered RRset travel together.
    fn storeOneRRset(
        self: *RRsetCache,
        lower_name: []const u8,
        rr: dns.ResourceRecord,
        matches: []const dns.ResourceRecord,
        sigs: []const dns.ResourceRecord,
        status: SecurityStatus,
        nsec_proofs: []const dns.ResourceRecord,
        authenticated_ttl_max: u32,
    ) void {
        // Empty matches would leave min_ttl = maxInt(u32) and store a
        // 1-week-pinned entry once clampTtl saturates. Belt-and-braces:
        // the existing partial-clone guard would catch this downstream,
        // but bailing early keeps the invariant ("matches has data")
        // explicit at the function boundary.
        if (matches.len == 0) return;

        // RFC 2181 §5.2: every RR in an RRset has the same TTL. Receivers
        // facing heterogeneous TTLs MUST treat the RRset as having a single
        // TTL — the minimum of the members. RRSIG and NSEC *TTL fields* fold
        // in so nothing outlives its own advertised lifetime. Not the §5.3.3
        // bound: §3.1 pins an RRSIG's TTL to its covered RRset's, so it says
        // nothing about expiry.
        var min_ttl: u32 = std.math.maxInt(u32);
        for (matches) |m| min_ttl = @min(min_ttl, m.ttl);
        for (sigs) |s| min_ttl = @min(min_ttl, s.ttl);
        for (nsec_proofs) |p| min_ttl = @min(min_ttl, p.ttl);
        // A folded minimum of 0 means some member said "never cache". The
        // caller's driver loop only skips 0-TTL *drivers* — a nonzero sibling
        // collects the 0-TTL member right back in — so the store dies here,
        // where neither the min-ttl floor nor serve-stale can resurrect it.
        if (min_ttl == 0) return;

        const slot = self.prepareSlot(lower_name, rr.rtype, rr.rclass, status, .always) orelse return;
        defer slot.shard.rwlock.unlock(self.io);

        const pack = buildPack(slot.alloc, matches, sigs, nsec_proofs) catch {
            slot.alloc.free(slot.key.name);
            return;
        };

        const life = self.lifetime(clampTtl(self.min_ttl, min_ttl), authenticated_ttl_max);
        slot.shard.map.put(slot.alloc, slot.key, .{ .positive = .{
            .pack = pack,
            .expires_at = life.expires_at,
            .original_ttl = life.ttl,
            .stored_at = life.stored_at,
            .security_status = status,
        } }) catch {
            slot.alloc.free(pack.blob);
            slot.alloc.free(slot.key.name);
            return;
        };
        markLastVisited(slot.shard);
        _ = slot.shard.stores.fetchAdd(1, .monotonic);
    }

    fn evictIfNeeded(self: *RRsetCache, shard: *Shard) void {
        const count: u32 = @intCast(shard.map.count());
        // Byte pressure: the counting allocator silently refuses writes once the
        // byte budget fills, latching the shard closed. Trigger SIEVE eviction
        // pre-emptively at 87.5% so the next allocation has slack to land.
        const bytes = shard.counting.current_bytes.load(.monotonic);
        const byte_pressure = bytes > shard.counting.max_bytes / 8 * 7;

        if (count >= shard.max_entries or byte_pressure) {
            if (count == 0) return;
            if (byte_pressure) _ = shard.byte_pressure_evictions.fetchAdd(1, .monotonic);
            sieveEvict(shard, count);
            return;
        }
        if (count < shard.max_entries / 4 * 3) return;
        self.sweepExpired(shard, count);
    }

    /// Probe a bounded number of entries from the SIEVE hand, evicting the first
    /// expired one. Clears visited flags as it goes for gradual SIEVE decay.
    /// Note: shares `shard.hand` with sieveEvict, so each call advances the SIEVE
    /// cursor (1-8 positions) — visited-bit decay is coupled to write rate, not
    /// access rate. Hand-wrap takes at least max_entries / (8 × calls_per_sec).
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
                shard.hand = if (i < shard.map.count()) i else 0;
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

fn removeAndFree(shard: *Shard, h: u32, key: CacheKey) void {
    const idx = shard.map.getIndexAdapted(key, PrecomputedCtx{ .precomputed = h }) orelse return;
    removeAtIndex(shard, idx);
}

inline fn markVisited(shard: *Shard, i: usize) void {
    // Load-first: an already-set hot bit skips the cache-line dirty write
    // that every concurrent reader would otherwise pay coherence for.
    // Monotonic u8 load/store compile to plain mov on x86_64/aarch64.
    if (shard.visited) |v| if (i < v.len and v[i].load(.monotonic) == 0) {
        v[i].store(1, .monotonic);
    };
}

/// Mark the most recently inserted entry as visited. Callers MUST invoke
/// this only after a `map.put` that was a fresh insert (not an update),
/// so the new entry sits at the tail of the ordered map.
inline fn markLastVisited(shard: *Shard) void {
    std.debug.assert(shard.map.count() > 0);
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
    alloc.free(entry.pack().blob);
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
            .flags = .{
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
            },
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
    };
}

// Test RRSIG with the fields the cache cares about (owner, covered type,
// labels, signer, ttl); the rest are fixed placeholders — signatures aren't
// verified here. original_ttl tracks ttl, matching real RRSIGs.
fn makeTestRrsig(owner: dns.Name, covered: dns.RType, labels: u8, signer: dns.Name, ttl: u32) dns.ResourceRecord {
    return .{ .name = owner, .rtype = .rrsig, .rclass = .in, .ttl = ttl, .rdata = .{ .rrsig = .{
        .type_covered = covered,
        .algorithm = .ecdsap256sha256,
        .labels = labels,
        .original_ttl = ttl,
        .sig_expiration = @intCast(test_time + max_cache_ttl),
        .sig_inception = 0,
        .key_tag = 0,
        .signer_name = signer,
        .signature = "",
    } } };
}

fn makeTestNsec(owner: dns.Name, next: dns.Name, ttl: u32) dns.ResourceRecord {
    return .{ .name = owner, .rtype = .nsec, .rclass = .in, .ttl = ttl, .rdata = .{ .nsec = .{
        .next_domain_name = next,
        .type_bit_maps = &.{},
    } } };
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
    cache.storeResponse(response, dns.Name{ .labels = &.{} }, status, std.math.maxInt(u32));
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

test "an RRset with a 0-TTL member is never cached, floor or no floor" {
    // RFC 2181 §5.2: heterogeneous TTLs fold to the minimum, and a 0-TTL
    // member means the zone said "do not cache this set". The driver loop
    // skips 0-TTL records, but a nonzero sibling drives the group and
    // collects the 0-TTL member back in — the folded minimum must then kill
    // the store outright. Neither the min-ttl floor nor serve-stale may
    // resurrect it, so both are armed here.
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = RRsetCache.init(.{
        .backing = alloc,
        .max_bytes = 1024 * 1024,
        .max_entries = 100,
        .io = testing.io,
        .min_ttl = 60,
        .serve_stale_ttl = 30,
    });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    const name = try makeTestName(alloc, &.{ "zero", "test" });
    const answers = try alloc.alloc(dns.ResourceRecord, 2);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
    answers[1] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 0, .rdata = .{ .a = .{ 5, 6, 7, 8 } } };
    const response = makeTestResponse(answers);
    cache.storeResponse(response, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
    dns.freeName(alloc, name);
    alloc.free(answers);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try testing.expect(cache.lookup(arena.allocator(), "zero.test", .a, .in) == null);
}

test "cache store and lookup positive" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "example", "com" }, 300, .{ 93, 184, 216, 34 });

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

    cache.storeNegative("nonexistent.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

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

test "NXDOMAIN answers every qtype via the sentinel key (RFC 8020)" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    const authorities = try buildTestSoaAuthority(alloc, &.{ "example", "com" }, &.{ "ns1", "example", "com" }, &.{ "admin", "example", "com" }, 900, 600);
    defer freeTestAuthorities(alloc, authorities);

    cache.storeNegative("nonexistent.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    // A single A-query NXDOMAIN must satisfy a later AAAA (and any other
    // type) with no re-walk.
    for ([_]dns.RType{ .a, .aaaa, .mx }) |qt| {
        switch (cache.lookup(arena.allocator(), "nonexistent.example.com", qt, .in) orelse return error.TestExpectedHit) {
            .negative => |n| try testing.expectEqual(dns.RCode.name_error, n.rcode),
            .hit => return error.TestUnexpectedResult,
        }
    }
}

test "NODATA stays type-scoped and never shares the NXDOMAIN sentinel" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    const authorities = try buildTestSoaAuthority(alloc, &.{ "example", "com" }, &.{ "ns1", "example", "com" }, &.{ "admin", "example", "com" }, 900, 600);
    defer freeTestAuthorities(alloc, authorities);

    // NODATA denies only the queried type — the name exists.
    cache.storeNegative("host.example.com", .a, .in, .no_error, authorities, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    switch (cache.lookup(arena.allocator(), "host.example.com", .a, .in) orelse return error.TestExpectedHit) {
        .negative => |n| try testing.expectEqual(dns.RCode.no_error, n.rcode),
        .hit => return error.TestUnexpectedResult,
    }
    // AAAA must miss: an A-NODATA proves nothing about AAAA.
    try testing.expect(cache.lookup(arena.allocator(), "host.example.com", .aaaa, .in) == null);
}

test "storeNegative rejects cross-zone SOA" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // SOA for "other.net" — not a parent of "www.example.com"
    const authorities = try buildTestSoaAuthority(alloc, &.{ "other", "net" }, &.{ "ns1", "other", "net" }, &.{ "admin", "other", "net" }, 900, 600);
    defer freeTestAuthorities(alloc, authorities);

    cache.storeNegative("www.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

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

    cache.storeNegative("www.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

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

test "lookupNxdomainAncestor finds parent NXDOMAIN (RFC 8020)" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Cache NXDOMAIN at "missing.example.com" for qtype A.
    const authorities = try buildTestSoaAuthority(alloc, &.{ "example", "com" }, &.{ "ns1", "example", "com" }, &.{ "admin", "example", "com" }, 900, 600);
    defer freeTestAuthorities(alloc, authorities);
    cache.storeNegative("missing.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    // Looking up the *parent* directly returns the NXDOMAIN.
    const direct = cache.lookup(arena.allocator(), "missing.example.com", .a, .in);
    try testing.expect(direct != null);

    // Querying a *child* of the cached NXDOMAIN should walk up via
    // lookupNxdomainAncestor and find the parent NXDOMAIN.
    const result = cache.lookupNxdomainAncestor(arena.allocator(), "child.missing.example.com", .a, .in);
    try testing.expect(result != null);
    switch (result.?) {
        .negative => |n| try testing.expectEqual(dns.RCode.name_error, n.rcode),
        .hit => return error.TestUnexpectedResult,
    }

    // A query for an unrelated parent miss returns null.
    const miss = cache.lookupNxdomainAncestor(arena.allocator(), "child.exists.example.com", .a, .in);
    try testing.expect(miss == null);
}

test "storeResponse captures wildcard NSEC proofs onto positive cache entry" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Synthesize a wildcard-expanded response: owner is `foo.example.com.`
    // (3 labels), covering RRSIG.labels=2 (proving the wildcard owner was
    // `*.example.com.` and labels<owner). The authority section carries the
    // RFC 4035 §3.1.3.4 NSEC proof of "no closer match exists".
    const owner = try makeTestName(alloc, &.{ "foo", "example", "com" });
    defer dns.freeName(alloc, owner);
    const signer = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, signer);
    const nsec_owner = try makeTestName(alloc, &.{ "bar", "example", "com" });
    defer dns.freeName(alloc, nsec_owner);
    const nsec_next = try makeTestName(alloc, &.{ "zzz", "example", "com" });
    defer dns.freeName(alloc, nsec_next);
    const rrsig_nsec_signer = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, rrsig_nsec_signer);
    const rrsig_a_signer = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, rrsig_a_signer);

    const answers = try alloc.alloc(dns.ResourceRecord, 2);
    defer alloc.free(answers);
    answers[0] = .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
    // labels 2 < owner's 3 → wildcard signal (covers *.example.com).
    answers[1] = makeTestRrsig(owner, .a, 2, rrsig_a_signer, 300);

    const authorities = try alloc.alloc(dns.ResourceRecord, 2);
    defer alloc.free(authorities);
    authorities[0] = makeTestNsec(nsec_owner, nsec_next, 300);
    authorities[1] = makeTestRrsig(nsec_owner, .nsec, 3, rrsig_nsec_signer, 300);

    const response: dns.Message = .{
        .header = .{
            .id = 0,
            .flags = .{
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
            },
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = @intCast(authorities.len),
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
        .authorities = authorities,
    };
    cache.storeResponse(response, signer, .secure, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const got = cache.lookup(arena.allocator(), "foo.example.com", .a, .in) orelse return error.TestExpectedHit;
    switch (got) {
        .hit => |h| {
            try testing.expectEqual(@as(usize, 1), h.records.len);
            try testing.expectEqual(@as(usize, 1), h.sigs.len);
            // Wildcard NSEC + its RRSIG were captured onto the entry.
            try testing.expectEqual(@as(usize, 2), h.nsec_proofs.len);
            // Verify the captured types — order isn't guaranteed but the set is.
            var saw_nsec = false;
            var saw_rrsig = false;
            for (h.nsec_proofs) |pr| {
                if (pr.rtype == .nsec) saw_nsec = true;
                if (pr.rtype == .rrsig) saw_rrsig = true;
            }
            try testing.expect(saw_nsec);
            try testing.expect(saw_rrsig);
        },
        .negative => return error.TestUnexpectedResult,
    }
}

test "storeResponse ignores orphan-RRSIG wildcard signal (forged-trigger defence)" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Upstream returns a legitimate non-wildcard A + RRSIG(A), plus a
    // forged RRSIG claiming type_covered=TXT with labels < owner.labels —
    // the wildcard signal. Validation only checks the qtype-matching
    // RRSIG (the genuine A one), but the forged RRSIG has no A/TXT to
    // cover, so an unguarded wildcard detector would still fire.
    // Plus an attacker-controlled NSEC in authority. After the fix,
    // capture must not fire — orphan RRSIG can't trigger.
    const owner = try makeTestName(alloc, &.{ "foo", "example", "com" });
    defer dns.freeName(alloc, owner);
    const signer = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, signer);
    const nsec_owner = try makeTestName(alloc, &.{ "bar", "example", "com" });
    defer dns.freeName(alloc, nsec_owner);
    const nsec_next = try makeTestName(alloc, &.{ "zzz", "example", "com" });
    defer dns.freeName(alloc, nsec_next);
    const rrsig_signer = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, rrsig_signer);
    const forged_signer = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, forged_signer);

    const answers = try alloc.alloc(dns.ResourceRecord, 3);
    defer alloc.free(answers);
    answers[0] = .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
    // Genuine RRSIG over A (non-wildcard: labels == owner.labels.len).
    answers[1] = makeTestRrsig(owner, .a, 3, rrsig_signer, 300);
    // Forged orphan RRSIG: claims to cover TXT (no TXT in answers), labels=1.
    answers[2] = makeTestRrsig(owner, .txt, 1, forged_signer, 300);

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    defer alloc.free(authorities);
    authorities[0] = makeTestNsec(nsec_owner, nsec_next, 300);

    const response: dns.Message = .{
        .header = .{
            .id = 0,
            .flags = .{
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
            },
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = @intCast(authorities.len),
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
        .authorities = authorities,
    };
    cache.storeResponse(response, signer, .secure, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const got = cache.lookup(arena.allocator(), "foo.example.com", .a, .in) orelse return error.TestExpectedHit;
    switch (got) {
        .hit => |h| {
            // Genuine A record cached; attacker's NSEC NOT bundled onto it.
            try testing.expectEqual(@as(usize, 1), h.records.len);
            try testing.expectEqual(@as(usize, 0), h.nsec_proofs.len);
        },
        .negative => return error.TestUnexpectedResult,
    }
}

test "storeNegative captures NSEC proofs onto negative cache entry" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Authority has SOA + NSEC + RRSIG(NSEC). NSEC proves b.example.com doesn't
    // exist; the cache should hold both onto the negative entry so cache-served
    // NXDOMAIN carries the proof material downstream validators need.
    const apex_labels: []const []const u8 = &.{ "example", "com" };
    const ns_labels: []const []const u8 = &.{ "ns1", "example", "com" };
    const admin_labels: []const []const u8 = &.{ "admin", "example", "com" };
    const apex = try makeTestName(alloc, apex_labels);
    defer dns.freeName(alloc, apex);
    const ns = try makeTestName(alloc, ns_labels);
    defer dns.freeName(alloc, ns);
    const admin = try makeTestName(alloc, admin_labels);
    defer dns.freeName(alloc, admin);
    const nsec_owner = try makeTestName(alloc, &.{ "a", "example", "com" });
    defer dns.freeName(alloc, nsec_owner);
    const nsec_next = try makeTestName(alloc, &.{ "c", "example", "com" });
    defer dns.freeName(alloc, nsec_next);
    const sig_signer = try makeTestName(alloc, apex_labels);
    defer dns.freeName(alloc, sig_signer);

    const authorities = try alloc.alloc(dns.ResourceRecord, 3);
    defer alloc.free(authorities);
    authorities[0] = .{ .name = apex, .rtype = .soa, .rclass = .in, .ttl = 900, .rdata = .{ .soa = .{
        .mname = ns,
        .rname = admin,
        .serial = 1,
        .refresh = 3600,
        .retry = 900,
        .expire = 604800,
        .minimum = 600,
    } } };
    authorities[1] = makeTestNsec(nsec_owner, nsec_next, 600);
    authorities[2] = makeTestRrsig(nsec_owner, .nsec, 3, sig_signer, 600);

    cache.storeNegative("b.example.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .secure, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const got = cache.lookup(arena.allocator(), "b.example.com", .a, .in) orelse return error.TestExpectedNegative;
    switch (got) {
        .negative => |n| {
            try testing.expectEqual(dns.RCode.name_error, n.rcode);
            try testing.expect(n.soa != null);
            try testing.expectEqual(@as(usize, 2), n.nsec_proofs.len);
            var saw_nsec = false;
            var saw_rrsig = false;
            for (n.nsec_proofs) |pr| {
                if (pr.rtype == .nsec) saw_nsec = true;
                if (pr.rtype == .rrsig) saw_rrsig = true;
            }
            try testing.expect(saw_nsec);
            try testing.expect(saw_rrsig);
        },
        .hit => return error.TestUnexpectedResult,
    }
}

test "storeNegative caps TTL at 3h (RFC 2308 §5)" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // SOA with TTL = MINIMUM = 1 week. RFC 2308 §5 caps the negative cache
    // lifetime at 3 hours (SHOULD) regardless of what the SOA advertises.
    const big_ttl: u32 = 604_800;
    const authorities = try buildTestSoaAuthority(alloc, &.{"com"}, &.{ "ns1", "com" }, &.{ "admin", "com" }, big_ttl, big_ttl);
    defer freeTestAuthorities(alloc, authorities);

    cache.storeNegative("missing.com", .a, .in, .name_error, authorities, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "missing.com", .a, .in);
    try testing.expect(result != null);
    switch (result.?) {
        .negative => |n| {
            try testing.expect(n.remaining_ttl <= negative_max_ttl);
            try testing.expect(n.remaining_ttl > 0);
        },
        .hit => return error.TestUnexpectedResult,
    }
}

test "storeResponse uses min TTL across RRset members (RFC 2181 §5.2)" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Two A records for the same name, deliberately heterogeneous TTLs.
    // The cache must adopt the minimum (60), not the first-seen value (300).
    const name = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, name);
    const records = [_]dns.ResourceRecord{
        .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 192, 0, 2, 1 } } },
        .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 192, 0, 2, 2 } } },
    };

    const question = dns.Question{ .name = name, .qtype = .a, .qclass = .in };
    const msg = dns.Message{
        .header = .{
            .id = 0,
            .flags = .{
                .qr = true,
                .opcode = .query,
                .aa = true,
                .tc = false,
                .rd = false,
                .ra = true,
                .z = 0,
                .ad = false,
                .cd = false,
                .rcode = .no_error,
            },
            .qd_count = 1,
            .an_count = records.len,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{question},
        .answers = &records,
    };
    cache.storeResponse(msg, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "example.com", .a, .in);
    try testing.expect(result != null);
    switch (result.?) {
        .hit => |h| {
            try testing.expectEqual(@as(u32, 60), h.remaining_ttl);
        },
        .negative => return error.TestUnexpectedResult,
    }
}

fn storeCappedA(cache: *RRsetCache, alloc: Allocator, ttl: u32, cap: u32) !dns.Message {
    const labels = &[_][]const u8{ "exp", "example", "com" };
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{
        .name = try makeTestName(alloc, labels),
        .rtype = .a,
        .rclass = .in,
        .ttl = ttl,
        .rdata = .{ .a = .{ 1, 2, 3, 4 } },
    };
    const response = makeTestResponse(answers);
    cache.storeResponse(response, dns.Name{ .labels = &.{} }, .secure, cap);
    return response;
}

fn lookupRemainingTtl(cache: *RRsetCache, alloc: Allocator) !?u32 {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const r = cache.lookup(arena.allocator(), "exp.example.com", .a, .in) orelse return null;
    return switch (r) {
        .hit => |h| h.remaining_ttl,
        .negative => error.TestUnexpectedResult,
    };
}

test "RFC 4035 §5.3.3: the validator's TTL cap bounds a .secure entry's life" {
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();

    const response = try storeCappedA(&cache, alloc, 86400, 600);
    defer dns.freeMessage(alloc, response);

    try testing.expectEqual(@as(?u32, 600), try lookupRemainingTtl(&cache, alloc));
    test_time = 1000 + 599;
    try testing.expectEqual(@as(?u32, 1), try lookupRemainingTtl(&cache, alloc));
    test_time = 1000 + 600;
    try testing.expectEqual(@as(?u32, null), try lookupRemainingTtl(&cache, alloc));
    test_time = 1000;
}

test "the min_ttl floor cannot re-inflate an entry past the validator's cap" {
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();
    cache.min_ttl = 3600;

    // The floor lifts 30 to 3600; the cap pulls it back to 600.
    const response = try storeCappedA(&cache, alloc, 30, 600);
    defer dns.freeMessage(alloc, response);

    try testing.expectEqual(@as(?u32, 600), try lookupRemainingTtl(&cache, alloc));
    test_time = 1000;
}

test "an uncapped store is not shortened by RRSIGs the cache cannot check" {
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Regression: reducing the TTL over every RRSIG travelling with the entry
    // let one appended already-expired signature zero it.
    const labels = &[_][]const u8{ "exp", "example", "com" };
    const answers = try alloc.alloc(dns.ResourceRecord, 2);
    answers[0] = .{
        .name = try makeTestName(alloc, labels),
        .rtype = .a,
        .rclass = .in,
        .ttl = 3600,
        .rdata = .{ .a = .{ 1, 2, 3, 4 } },
    };
    var dead = makeTestRrsig(try makeTestName(alloc, labels), .a, 3, try makeTestName(alloc, &.{ "example", "com" }), 3600);
    dead.rdata.rrsig.sig_expiration = @intCast(test_time - 1);
    answers[1] = dead;
    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);
    cache.storeResponse(response, dns.Name{ .labels = &.{} }, .secure, std.math.maxInt(u32));

    try testing.expectEqual(@as(?u32, 3600), try lookupRemainingTtl(&cache, alloc));
    test_time = 1000;
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

    cache.storeNegative("www.example.com", .a, .in, .name_error, authorities, zone_cut, .unchecked, std.math.maxInt(u32));

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
    const cap: u32 = min_shards;
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
        cache.storeResponse(response, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
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

        cache.storeResponse(makeTestResponse(answers), dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
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
    cache.storeNegative("no-soa.example.com", .a, .in, .name_error, &.{}, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

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

test "cache expired_remiss counts only present-but-expired misses" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc); // serve_stale_ttl = 0: expiry is a full miss
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "hot", "example" }, 60, .{ 1, 2, 3, 4 });

    // Past expiry: entry still in the map (deferred eviction) → miss + expired_remiss.
    test_time = 1100;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try testing.expect(cache.lookup(arena.allocator(), "hot.example", .a, .in) == null);
    try testing.expectEqual(@as(u64, 1), cache.getStats().expired_remiss);

    // Absent key: plain miss, expired_remiss unchanged.
    try testing.expect(cache.lookup(arena.allocator(), "never.stored", .a, .in) == null);
    const stats = cache.getStats();
    try testing.expectEqual(@as(u64, 2), stats.misses);
    try testing.expectEqual(@as(u64, 1), stats.expired_remiss);
}

test "remiss hook fires on expired entry only, with lowercased name" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    const Recorder = struct {
        var count: usize = 0;
        var last_name: [64]u8 = undefined;
        var last_len: usize = 0;
        var last_rtype: dns.RType = .a;
        fn hook(ctx: *anyopaque, name: []const u8, rtype: dns.RType) void {
            _ = ctx;
            count += 1;
            @memcpy(last_name[0..name.len], name);
            last_len = name.len;
            last_rtype = rtype;
        }
    };
    Recorder.count = 0;
    var dummy: u8 = 0;
    cache.remiss_hook = .{ .ctx = &dummy, .call = &Recorder.hook };

    try storeTestA(&cache, alloc, &.{ "hot", "example" }, 60, .{ 1, 2, 3, 4 });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    // Fresh hit: no hook.
    try testing.expect(cache.lookup(arena.allocator(), "hot.example", .a, .in) != null);
    try testing.expectEqual(@as(usize, 0), Recorder.count);

    // Absent key: no hook (never cached ≠ died between demands).
    try testing.expect(cache.lookup(arena.allocator(), "never.stored", .a, .in) == null);
    try testing.expectEqual(@as(usize, 0), Recorder.count);

    // Expired: hook fires with the lowercased name.
    test_time = 1100;
    try testing.expect(cache.lookup(arena.allocator(), "HOT.example", .a, .in) == null);
    try testing.expectEqual(@as(usize, 1), Recorder.count);
    try testing.expectEqualStrings("hot.example", Recorder.last_name[0..Recorder.last_len]);
    try testing.expectEqual(dns.RType.a, Recorder.last_rtype);
}

test "entryExpiry reports expires_at for fresh and lingering entries, null when absent" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "probe", "example" }, 300, .{ 1, 2, 3, 4 });

    try testing.expectEqual(@as(?i64, 1300), cache.entryExpiry("probe.example", .a, .in));
    // Past expiry the entry lingers (deferred eviction) and still reports.
    test_time = 1400;
    try testing.expectEqual(@as(?i64, 1300), cache.entryExpiry("probe.example", .a, .in));
    try testing.expectEqual(@as(?i64, null), cache.entryExpiry("absent.example", .a, .in));
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

test "cache lookup is_stale flag set on stale hit, clear on fresh (RFC 8767 §6)" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io, .serve_stale_ttl = 3600 });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "fresh", "test" }, 60, .{ 1, 2, 3, 4 });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    // Fresh hit must clear is_stale.
    const fresh = cache.lookup(arena.allocator(), "fresh.test", .a, .in);
    try testing.expect(fresh != null);
    switch (fresh.?) {
        .hit => |h| try testing.expectEqual(false, h.is_stale),
        .negative => return error.TestUnexpectedResult,
    }

    // Same entry, past expiry but inside the serve-stale window.
    test_time = 1100;
    const stale = cache.lookup(arena.allocator(), "fresh.test", .a, .in);
    try testing.expect(stale != null);
    switch (stale.?) {
        .hit => |h| try testing.expectEqual(true, h.is_stale),
        .negative => return error.TestUnexpectedResult,
    }
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

    cache.storeNegativeBare("bogus.test", .a, .in, .server_failure, 1, .unchecked, .always);

    // 5s past expiry, well within the 3600s stale window — must still miss.
    test_time = 1000 + 1 + 5;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try testing.expect(cache.lookup(arena.allocator(), "bogus.test", .a, .in) == null);
}

test "cacheServfail never displaces a fresh entry" {
    // A background cousin resolve can fail after a concurrent foreground
    // resolve succeeded; the freshness check lives under the shard write
    // lock so the marker loses that race deterministically. Once the entry
    // expires, the marker may land.
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();

    try storeTestA(&cache, alloc, &.{ "racy", "test" }, 300, .{ 1, 2, 3, 4 });
    cache.cacheServfail("racy.test", .a);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const fresh = cache.lookup(arena.allocator(), "racy.test", .a, .in) orelse return error.TestExpectedHit;
    try testing.expect(fresh == .hit);

    test_time = 1000 + 301;
    cache.cacheServfail("racy.test", .a);
    const after = cache.lookup(arena.allocator(), "racy.test", .a, .in) orelse return error.TestExpectedHit;
    try testing.expect(after == .negative);
    try testing.expectEqual(dns.RCode.server_failure, after.negative.rcode);
}

test "RFC 9520: SERVFAIL TTL clamped to 5 minutes" {
    // Per §3, the resolution-failure cache MUST NOT exceed 5 minutes,
    // even if a caller passes a larger TTL.
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    cache.storeNegativeBare("flooded.test", .a, .in, .server_failure, 86400, .unchecked, .always);

    // 301s after store: must miss. If the clamp regresses to max_cache_ttl
    // the entry would still be live for hours.
    test_time = 1000 + 301;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try testing.expect(cache.lookup(arena.allocator(), "flooded.test", .a, .in) == null);
}

test "cacheServfail caches with sub-5-minute TTL" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 100, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    cache.cacheServfail("broken.test", .a);

    // Cache hit during the failure window short-circuits upstream walk.
    test_time = 1003;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "broken.test", .a, .in);
    try testing.expect(result != null);
    switch (result.?) {
        .negative => |n| try testing.expectEqual(dns.RCode.server_failure, n.rcode),
        .hit => return error.TestUnexpectedResult,
    }
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

    const initial = cache.getStats();
    try testing.expectEqual(@as(u64, 0), initial.hits);
    try testing.expectEqual(@as(u64, 0), initial.misses);
    try testing.expectEqual(@as(u64, 0), initial.stores);
    try testing.expectEqual(@as(u32, 0), initial.entries);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    _ = cache.lookup(arena.allocator(), "nonexistent.com", .a, .in);
    try testing.expectEqual(@as(u64, 0), cache.getStats().hits);
    try testing.expectEqual(@as(u64, 1), cache.getStats().misses);

    try storeTestA(&cache, alloc, &.{ "stats", "test" }, 300, .{ 1, 2, 3, 4 });
    try testing.expectEqual(@as(u64, 1), cache.getStats().stores);
    try testing.expectEqual(@as(u32, 1), cache.getStats().entries);

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
    cache.storeResponse(response, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    {
        const r = cache.lookup(a, "example.com", .a, .in).?;
        try testing.expectEqual(SecurityStatus.unchecked, r.hit.security_status);
    }

    // Step 2: bg validation finishes .bogus → bogusServfail path.
    cache.storeNegativeBare("example.com", .a, .in, .server_failure, 1, .unchecked, .always);

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

    cache.storeNegativeBare("example.com", .a, .in, .name_error, 600, .secure, .always);
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
    // SERVFAIL store — shouldBlockOverwrite guards against downgrade by
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

    cache.storeResponse(response, dns.Name{ .labels = &.{} }, .secure, std.math.maxInt(u32));

    cache.storeNegativeBare("example.com", .a, .in, .server_failure, 1, .unchecked, .always);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const r = cache.lookup(arena.allocator(), "example.com", .a, .in).?;
    switch (r) {
        .hit => |h| try testing.expectEqual(SecurityStatus.secure, h.security_status),
        .negative => return error.TestExpectedHitAfterProtection,
    }
}

test "shard distribution is reasonable for random names" {
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
        cache.storeResponse(response, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
        dns.freeMessage(alloc, response);
    }

    // Pigeonhole: expected mean = n_keys / shard_count. Allow up to 3× mean
    // before flagging as a hash regression. (3× is loose; Wyhash usually
    // stays within 1.5× even for adversarial inputs.)
    const mean_per_shard: usize = n_keys / cache.shard_count;
    const max_allowed: usize = mean_per_shard * 3;
    for (cache.shards[0..cache.shard_count]) |*shard| {
        try testing.expect(shard.map.count() <= max_allowed);
    }
}

test "deriveShardCount tracks concurrency, floored and budget-capped" {
    // Floor: low concurrency / tiny cache still gets min_shards.
    try testing.expectEqual(min_shards, deriveShardCount(1, 100));
    // Default server concurrency: workers=2 * (1 + resolution_threads=4) = 10 -> 16.
    try testing.expectEqual(@as(u32, 16), deriveShardCount(10, 10_000));
    // High concurrency on a healthy cache scales up, capped at max_shards.
    try testing.expectEqual(max_shards, deriveShardCount(160, 10_000));
    try testing.expectEqual(max_shards, deriveShardCount(1000, 1_000_000));
    // Budget cap: a tight cache (2000/128=15 -> 8) is lifted back to the floor.
    try testing.expectEqual(min_shards, deriveShardCount(160, 2000));
}

test "eviction stays within shard" {
    const alloc = testing.allocator;
    test_time = 1000;

    // 1 entry per shard. Hammer one specific shard with many stores
    // (forces eviction there); a victim entry on a different shard must
    // survive — eviction must not cross shard boundaries.
    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = min_shards, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    const victim = "victim.test";
    const victim_shard = shardIndex(CacheKeyContext.hash(.{}, .{ .name = victim, .rtype = .a, .rclass = .in }), cache.shard_mask);
    const target_shard = (victim_shard +% 1) & cache.shard_mask;

    try storeTestA(&cache, alloc, &.{ "victim", "test" }, 300, .{ 1, 2, 3, 4 });

    var stored: u32 = 0;
    var probe: u32 = 0;
    while (stored < 4) : (probe += 1) {
        var nb: [16]u8 = undefined;
        const dotted = try std.fmt.bufPrint(&nb, "x{d}.com", .{probe});
        const sh = shardIndex(CacheKeyContext.hash(.{}, .{ .name = dotted, .rtype = .a, .rclass = .in }), cache.shard_mask);
        if (sh != target_shard) continue;
        const parsed = try dns.parseDottedName(alloc, dotted);
        const answers = try alloc.alloc(dns.ResourceRecord, 1);
        answers[0] = .{ .name = parsed, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 5, 6, 7, 8 } } };
        const response = makeTestResponse(answers);
        cache.storeResponse(response, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));
        dns.freeMessage(alloc, response);
        stored += 1;
    }

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try testing.expect(cache.lookup(arena.allocator(), victim, .a, .in) != null);
}

fn runStoreOneRRsetUnderFailing(failing_alloc: Allocator) !void {
    // Cache uses `failing_alloc` as its backing — every shard alloc routes
    // through it so injected failures hit prepareSlot's dupe, the
    // CachedRecord array, per-record wire/name/rdata clones, and the
    // shard's map.put resize.
    test_time = 1000;
    var cache = RRsetCache.init(.{
        .backing = failing_alloc,
        .max_bytes = 1024 * 1024,
        .max_entries = 64,
        .io = testing.io,
    });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Build an A RRset (2 records) on a side arena so the input lifetime
    // is independent of the failing allocator. Cache copies what it stores.
    var input_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer input_arena.deinit();
    const ia = input_arena.allocator();

    // Wildcard-expanded A + RRSIG(A) (rrsig.labels < owner.labels) so
    // storeResponse captures the authority NSEC + RRSIG(NSEC) as proofs. The
    // A rrset then reaches storeOneRRset with BOTH non-empty sigs and
    // nsec_proofs, so the fail-index sweep drives both clone-failure bails.
    const owner = try makeTestName(ia, &.{ "foo", "example", "com" });
    const signer = try makeTestName(ia, &.{ "example", "com" });
    const nsec_owner = try makeTestName(ia, &.{ "bar", "example", "com" });
    const nsec_next = try makeTestName(ia, &.{ "zzz", "example", "com" });

    const answers = try ia.alloc(dns.ResourceRecord, 2);
    answers[0] = .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
    answers[1] = makeTestRrsig(owner, .a, 2, signer, 300); // labels 2 < owner's 3 → wildcard signal

    const authorities = try ia.alloc(dns.ResourceRecord, 2);
    authorities[0] = makeTestNsec(nsec_owner, nsec_next, 300);
    authorities[1] = makeTestRrsig(nsec_owner, .nsec, 3, signer, 300);

    var response = makeTestResponse(answers);
    response.authorities = authorities;
    cache.storeResponse(response, signer, .secure, std.math.maxInt(u32));
}

test "evictIfNeeded triggers SIEVE on byte pressure" {
    // Regression: previously evictIfNeeded only checked entry count. When the
    // byte budget filled at fewer entries than max_entries, the key-name dupe
    // in prepareSlot started failing and the shard latched closed — silent
    // capacity loss with zero evictions recorded. The fix adds byte pressure
    // (≥87.5% full) as an eviction trigger.
    //
    // Driven directly against the eviction primitive: integration-style fills
    // are brittle because ArrayHashMap capacity-growth chunks can leap over
    // the 87.5% threshold without ever crossing it at small test sizes.
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 10_000, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Pre-populate shard 0 with a handful of entries so SIEVE has something
    // to evict. The exact names don't matter — the test exercises the byte-
    // pressure trigger directly below.
    var name_buf: [32]u8 = undefined;
    var stored: u32 = 0;
    var i: u32 = 0;
    while (stored < 4 and i < 100) : (i += 1) {
        const name = std.fmt.bufPrint(&name_buf, "n{d}.test", .{i}) catch unreachable;
        const probe = CacheKey{ .name = name, .rtype = .a, .rclass = .in };
        const shard, _ = cache.shardWithHash(probe);
        if (shard != &cache.shards[0]) continue;
        cache.storeNegativeBare(name, .a, .in, .name_error, 60, .unchecked, .always);
        stored += 1;
    }
    try testing.expect(stored == 4);
    try testing.expect(cache.shards[0].map.count() == 4);

    // Force byte pressure on shard 0: counter just above the 87.5% threshold.
    const shard0 = &cache.shards[0];
    const threshold = shard0.counting.max_bytes / 8 * 7;
    const real_bytes = shard0.counting.current_bytes.load(.monotonic);
    // Add synthetic bytes so total > threshold. We bump the counter directly
    // (instead of via real allocations) so this works regardless of how the
    // ArrayHashMap happens to be sized.
    const bump: usize = if (real_bytes >= threshold) 1 else threshold - real_bytes + 1;
    _ = shard0.counting.current_bytes.fetchAdd(bump, .monotonic);

    cache.evictIfNeeded(shard0);

    // Release synthetic bytes so deinit accounting checks out.
    _ = shard0.counting.current_bytes.fetchSub(bump, .monotonic);

    try testing.expect(shard0.byte_pressure_evictions.load(.monotonic) == 1);
    try testing.expect(shard0.evictions.load(.monotonic) == 1);
    try testing.expect(shard0.map.count() == 3);
}

test "byte-pressure check happens before key-name dupe" {
    // Regression for the ordering fix: previously, prepareSlot duped the key
    // name *before* calling evictIfNeeded. With the budget at max_bytes, the
    // dupe itself was the allocation that latched the shard closed, never
    // reaching the eviction code. The fix moves evictIfNeeded above the dupe.
    //
    // Verify by storing into a shard whose counter is at threshold: the
    // pre-dupe eviction must free a slot, and the new entry must land.
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 10_000, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Seed shard 0 with one entry.
    var name_buf: [32]u8 = undefined;
    var seeded: ?[]const u8 = null;
    var i: u32 = 0;
    while (seeded == null and i < 100) : (i += 1) {
        const name = std.fmt.bufPrint(&name_buf, "seed{d}.test", .{i}) catch unreachable;
        const probe = CacheKey{ .name = name, .rtype = .a, .rclass = .in };
        const shard, _ = cache.shardWithHash(probe);
        if (shard != &cache.shards[0]) continue;
        cache.storeNegativeBare(name, .a, .in, .name_error, 60, .unchecked, .always);
        seeded = name;
    }
    try testing.expect(seeded != null);

    // Push shard 0 over the byte-pressure threshold.
    const shard0 = &cache.shards[0];
    const threshold = shard0.counting.max_bytes / 8 * 7;
    const cur = shard0.counting.current_bytes.load(.monotonic);
    const bump: usize = if (cur >= threshold) 1 else threshold - cur + 1;
    _ = shard0.counting.current_bytes.fetchAdd(bump, .monotonic);

    // Find a different name that also hashes to shard 0.
    var newname_buf: [32]u8 = undefined;
    var newname: []const u8 = "";
    var j: u32 = 1000;
    while (j < 1200) : (j += 1) {
        const name = std.fmt.bufPrint(&newname_buf, "new{d}.test", .{j}) catch unreachable;
        const probe = CacheKey{ .name = name, .rtype = .a, .rclass = .in };
        const shard, _ = cache.shardWithHash(probe);
        if (shard != shard0) continue;
        newname = name;
        break;
    }
    try testing.expect(newname.len > 0);

    cache.storeNegativeBare(newname, .a, .in, .name_error, 60, .unchecked, .always);

    // Pop the synthetic bump so lookup runs against real state.
    _ = shard0.counting.current_bytes.fetchSub(bump, .monotonic);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try testing.expect(cache.lookup(arena.allocator(), newname, .a, .in) != null);
    try testing.expect(shard0.byte_pressure_evictions.load(.monotonic) >= 1);
}

fn runStoreNegativeUnderFailing(failing_alloc: Allocator) !void {
    // Drive both negative-store paths so injected failures cover the
    // alloc.create(NegativeEntry) failure + map.put rollback from boxing.
    test_time = 1000;
    var cache = RRsetCache.init(.{
        .backing = failing_alloc,
        .max_bytes = 1024 * 1024,
        .max_entries = 64,
        .io = testing.io,
    });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Bare negative (no SOA, no proofs): exercises the simpler path.
    cache.storeNegativeBare("missing.test", .a, .in, .name_error, 60, .unchecked, .always);

    // Negative with SOA + NSEC proofs: exercises the larger rollback path.
    var input_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer input_arena.deinit();
    const ia = input_arena.allocator();

    const zone_name = try makeTestName(ia, &.{"test"});
    const soa_name = try makeTestName(ia, &.{"test"});
    const mname = try makeTestName(ia, &.{ "ns1", "test" });
    const rname = try makeTestName(ia, &.{ "admin", "test" });
    const nsec_owner = try makeTestName(ia, &.{ "sub", "test" });
    const nsec_next = try makeTestName(ia, &.{ "zzz", "test" });
    const auths = try ia.alloc(dns.ResourceRecord, 3);
    auths[0] = .{
        .name = soa_name,
        .rtype = .soa,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .soa = .{
            .mname = mname,
            .rname = rname,
            .serial = 1,
            .refresh = 3600,
            .retry = 600,
            .expire = 86400,
            .minimum = 300,
        } },
    };
    // NSEC + RRSIG(NSEC) so collectNsecProofs yields non-empty proofs and the
    // negative proofs-clone bail path is leak-swept.
    auths[1] = makeTestNsec(nsec_owner, nsec_next, 300);
    auths[2] = makeTestRrsig(nsec_owner, .nsec, 2, zone_name, 300);
    cache.storeNegative("nodata.test", .a, .in, .no_error, auths, zone_name, .unchecked, std.math.maxInt(u32));
}

test "negative-store paths handle backing-allocator OOM without leaking" {
    // Catches the boxing rollbacks: alloc.create(NegativeEntry) failure
    // and the map.put rollback that must alloc.destroy() the boxed pointer.
    var counter = std.testing.FailingAllocator.init(testing.allocator, .{});
    try runStoreNegativeUnderFailing(counter.allocator());
    const total = counter.alloc_index;

    var idx: usize = 0;
    while (idx < total) : (idx += 1) {
        var f = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = idx });
        runStoreNegativeUnderFailing(f.allocator()) catch |err| {
            if (err != error.OutOfMemory) return err;
        };
        try testing.expectEqual(f.allocated_bytes, f.freed_bytes);
    }
}

test "anti-downgrade holds under byte pressure" {
    // Regression: when evictIfNeeded ran before shouldBlockOverwrite,
    // byte-pressure SIEVE (security-blind) could evict the existing .secure
    // entry before the anti-downgrade check saw it — RFC 9520 §3.4 bypass.
    // Fix runs shouldBlockOverwrite first against the stack probe key.
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(.{ .backing = alloc, .max_bytes = 1024 * 1024, .max_entries = 10_000, .io = testing.io });
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Store a .secure positive for a name. expectCachedHitStatus probes by
    // dotted string, so the labels must format back to that string.
    try storeTestAWithStatus(&cache, alloc, &.{ "protected", "example", "com" }, 300, .{ 1, 2, 3, 4 }, .secure);

    // Push the shard holding the entry over the 87.5% byte-pressure threshold.
    const probe = CacheKey{ .name = "protected.example.com", .rtype = .a, .rclass = .in };
    const shard, _ = cache.shardWithHash(probe);
    const threshold = shard.counting.max_bytes / 8 * 7;
    const cur = shard.counting.current_bytes.load(.monotonic);
    const bump: usize = if (cur >= threshold) 1 else threshold - cur + 1;
    _ = shard.counting.current_bytes.fetchAdd(bump, .monotonic);

    // Attempt .unchecked downgrade of the same key. Must be refused.
    try storeTestAWithStatus(&cache, alloc, &.{ "protected", "example", "com" }, 300, .{ 9, 9, 9, 9 }, .unchecked);

    // Release synthetic bytes so the deinit accounting checks out.
    _ = shard.counting.current_bytes.fetchSub(bump, .monotonic);

    // Original .secure must survive.
    try expectCachedHitStatus(alloc, &cache, "protected.example.com", .secure);
}

test "multi-record RRset round-trip preserves shared owner name" {
    // Catches wrong-offset bugs in the shared-name backing: every record's
    // owner name must compare equal to the original after store -> lookup.
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();

    const labels = &[_][]const u8{ "multi", "example", "com" };
    const n1 = try makeTestName(alloc, labels);
    const n2 = try makeTestName(alloc, labels);
    const n3 = try makeTestName(alloc, labels);
    const answers = try alloc.alloc(dns.ResourceRecord, 3);
    answers[0] = .{ .name = n1, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };
    answers[1] = .{ .name = n2, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 5, 6, 7, 8 } } };
    answers[2] = .{ .name = n3, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 9, 10, 11, 12 } } };
    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    cache.storeResponse(response, dns.Name{ .labels = &.{} }, .unchecked, std.math.maxInt(u32));

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const r = cache.lookup(arena.allocator(), "multi.example.com", .a, .in) orelse return error.TestExpectedHit;
    switch (r) {
        .hit => |h| {
            try testing.expectEqual(@as(usize, 3), h.records.len);
            // All three records' owner names must round-trip equal — a wrong
            // offset in the shared-name builder would corrupt one or more.
            const expected = try makeTestName(arena.allocator(), labels);
            for (h.records) |rec| try testing.expect(rec.name.eql(expected));
        },
        .negative => return error.TestExpectedHit,
    }
}

test "storeOneRRset handles backing-allocator OOM without leaking" {
    // `storeResponse` is best-effort and swallows OOM (degraded caching is
    // preferred over a failed query path), so `checkAllAllocationFailures`'
    // SwallowedOutOfMemoryError discipline doesn't fit. Drive the sweep
    // ourselves and assert allocated==freed at each fail_index — the leak
    // signal is what we actually care about.
    var counter = std.testing.FailingAllocator.init(testing.allocator, .{});
    try runStoreOneRRsetUnderFailing(counter.allocator());
    const total = counter.alloc_index;

    var idx: usize = 0;
    while (idx < total) : (idx += 1) {
        var f = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = idx });
        runStoreOneRRsetUnderFailing(f.allocator()) catch |err| {
            if (err != error.OutOfMemory) return err;
        };
        try testing.expectEqual(f.allocated_bytes, f.freed_bytes);
    }
}

test "storeResponse skips an RRset that overflows the collect buffer" {
    // A 64-record store of a 70-record RRset would serve a silently-short
    // answer with no TC=1 for the whole TTL (RFC 2181 §5.1) while the miss
    // client got all 70. Not caching is the correct degradation.
    const alloc = testing.allocator;
    test_time = 1000;
    var cache = makeTestCache(alloc);
    defer cache.deinit();

    // Oversized first, so the "no entry" assertion can't be satisfied by a
    // leftover from the in-bounds store.
    for ([_]usize{ max_rrset_collect + 1, max_rrset_collect }) |n| {
        const answers = try alloc.alloc(dns.ResourceRecord, n);
        for (answers, 0..) |*a, i| a.* = .{
            .name = try makeTestName(alloc, &.{ "big", "example", "com" }),
            .rtype = .a,
            .rclass = .in,
            .ttl = 300,
            .rdata = .{ .a = .{ 10, 0, @intCast(i / 256), @intCast(i % 256) } },
        };
        const response = makeTestResponse(answers);
        defer dns.freeMessage(alloc, response);
        cache.storeResponse(response, dns.Name{ .labels = &.{} }, .secure, std.math.maxInt(u32));

        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const r = cache.lookup(arena.allocator(), "big.example.com", .a, .in);
        if (n > max_rrset_collect) {
            try testing.expect(r == null);
        } else {
            try testing.expectEqual(n, r.?.hit.records.len);
        }
    }
}

test "cache key: read-side and write-side name lowering agree byte-for-byte" {
    // Reads key the cache via lowerNameBuf over a formatInto-dotted string;
    // writes key it via Name.formatLower over the label array
    // (storeRRsetsExcept). One byte of disagreement lands stores under a
    // key reads never hit — a silent cache miss, not a crash. Pin the
    // agreement across the shapes that could plausibly diverge.
    const names = [_]dns.Name{
        .{ .labels = &.{ "ExAmPlE", "CoM" } }, // mixed case (0x20 echo)
        .{ .labels = &.{ "WWW", "EXAMPLE", "COM" } },
        .{ .labels = &.{ "xn--nxasmq6b", "example" } }, // punycode
        .{ .labels = &.{ "_sip", "_tcp", "example", "com" } }, // SRV underscores
        .{ .labels = &.{ "\x01\x7fBIN", "TeSt" } }, // non-printables -> \DDD
        .{ .labels = &.{ "e.D", "CoM" } }, // literal dot -> \.
        .{ .labels = &.{ "a\\B", "c" } }, // literal backslash -> \\
        .{ .labels = &.{} }, // root
    };
    for (names) |n| {
        var fmt_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const dotted = n.formatInto(&fmt_buf);
        var read_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const read_key = lowerNameBuf(&read_buf, dotted).?;
        var write_buf: [dns.max_dotted_len + 1]u8 = undefined;
        const write_key = n.formatLower(&write_buf);
        try testing.expectEqualStrings(write_key, read_key);
    }
}
