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
};

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
            const bitmaps = if (nsec_data.type_bit_maps.len > 0)
                try alloc.dupe(u8, nsec_data.type_bit_maps)
            else
                @as([]const u8, &.{});
            break :blk .{ .nsec = .{
                .next_domain_name = next_name,
                .type_bit_maps = bitmaps,
            } };
        },
        .nsec3 => |nsec3| blk: {
            const salt = if (nsec3.salt.len > 0)
                try alloc.dupe(u8, nsec3.salt)
            else
                @as([]const u8, &.{});
            errdefer if (salt.len > 0) alloc.free(salt);
            const next_hash = try alloc.dupe(u8, nsec3.next_hashed_owner);
            errdefer alloc.free(next_hash);
            const bitmaps = if (nsec3.type_bit_maps.len > 0)
                try alloc.dupe(u8, nsec3.type_bit_maps)
            else
                @as([]const u8, &.{});
            break :blk .{ .nsec3 = .{
                .hash_algorithm = nsec3.hash_algorithm,
                .flags = nsec3.flags,
                .iterations = nsec3.iterations,
                .salt = salt,
                .next_hashed_owner = next_hash,
                .type_bit_maps = bitmaps,
            } };
        },
        .nsec3param => |nsec3p| .{ .nsec3param = .{
            .hash_algorithm = nsec3p.hash_algorithm,
            .flags = nsec3p.flags,
            .iterations = nsec3p.iterations,
            .salt = if (nsec3p.salt.len > 0)
                try alloc.dupe(u8, nsec3p.salt)
            else
                @as([]const u8, &.{}),
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
fn cloneRRset(alloc: Allocator, cached: []const CachedRecord, ttl: u32) ![]dns.ResourceRecord {
    const records = try alloc.alloc(dns.ResourceRecord, cached.len);
    errdefer alloc.free(records);
    var done: usize = 0;
    errdefer dns.freeResourceRecordContents(alloc, records[0..done]);
    for (cached, 0..) |cr, i| {
        const cloned_name = try cloneName(alloc, cr.name);
        errdefer dns.freeName(alloc, cloned_name);
        records[i] = .{
            .name = cloned_name,
            .rtype = cr.rtype,
            .rclass = cr.rclass,
            .ttl = ttl,
            .rdata = try cloneRData(alloc, cr.rdata),
        };
        done = i + 1;
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
    return dns.ResourceRecord{
        .name = cloned_name,
        .rtype = s.rtype,
        .rclass = s.rclass,
        .ttl = ttl,
        .rdata = cloned_rdata,
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

/// Convert a dns.Name to a lowercased dotted string, allocated.
fn nameToLowerDotted(alloc: Allocator, name: dns.Name) ![]const u8 {
    const fmt = name.format();
    const len = mem.indexOfScalar(u8, &fmt, 0) orelse fmt.len;
    const result = try alloc.alloc(u8, len);
    return lowerInto(result, fmt[0..len]);
}

// ── RRsetCache ────────────────────────────────────────────────────────

pub const RRsetCache = struct {
    counting: CountingAllocator,
    map: std.ArrayHashMapUnmanaged(CacheKey, CacheEntry, CacheKeyContext, true),
    max_entries: u32,
    now_fn: *const fn () i64,
    rwlock: ?std.Io.RwLock = null,
    io: std.Io,
    serve_stale_ttl: u32 = 0,
    min_ttl: u32 = 0,
    prefetch: bool = false,
    /// When true, storeRRsetsImpl skips .dnskey and .ds records (routed to key cache).
    skip_key_types: bool = false,
    /// SIEVE eviction state: per-entry visited flag and circular scan pointer.
    visited: ?[]std.atomic.Value(u8) = null,
    hand: u32 = 0,
    hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    misses: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stores: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    negative_stores: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    evictions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    prefetch_eligible: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stale_hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub const CacheOptions = struct {
        prefetch: bool = false,
        serve_stale_ttl: u32 = 0,
        min_ttl: u32 = 0,
        /// Skip .dnskey and .ds records in storeRRsetsImpl (routed to key cache).
        skip_key_types: bool = false,
    };

    pub fn init(backing: Allocator, max_bytes: usize, max_entries: u32, io: std.Io) RRsetCache {
        return initWithOptions(backing, max_bytes, max_entries, .{}, io);
    }

    pub fn initWithOptions(backing: Allocator, max_bytes: usize, max_entries: u32, opts: CacheOptions, io: std.Io) RRsetCache {
        // Allocate SIEVE visited flags from backing allocator (not counted against cache budget).
        const visited: ?[]std.atomic.Value(u8) = if (backing.alloc(std.atomic.Value(u8), max_entries)) |v| blk: {
            for (v) |*slot| slot.* = std.atomic.Value(u8).init(0);
            break :blk v;
        } else |_| null;
        return .{
            .counting = CountingAllocator.init(backing, max_bytes),
            .map = .empty,
            .max_entries = max_entries,
            .io = io,
            .now_fn = &defaultNowSeconds,
            .prefetch = opts.prefetch,
            .serve_stale_ttl = opts.serve_stale_ttl,
            .min_ttl = opts.min_ttl,
            .skip_key_types = opts.skip_key_types,
            .visited = visited,
        };
    }

    pub fn initThreadSafe(backing: Allocator, max_bytes: usize, max_entries: u32, io: std.Io) RRsetCache {
        return initThreadSafeWithOptions(backing, max_bytes, max_entries, .{}, io);
    }

    pub fn initThreadSafeWithOptions(backing: Allocator, max_bytes: usize, max_entries: u32, opts: CacheOptions, io: std.Io) RRsetCache {
        var c = initWithOptions(backing, max_bytes, max_entries, opts, io);
        c.rwlock = std.Io.RwLock.init;
        return c;
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
        prefetch_eligible: u64,
        stale_hits: u64,
    };

    pub fn getStats(self: *RRsetCache) Stats {
        if (self.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (self.rwlock) |*rw| rw.unlockShared(self.io);
        return .{
            .entries = @intCast(self.map.count()),
            .memory_bytes = self.counting.current_bytes.load(.monotonic),
            .max_bytes = self.counting.max_bytes,
            .hits = self.hits.load(.monotonic),
            .misses = self.misses.load(.monotonic),
            .stores = self.stores.load(.monotonic),
            .negative_stores = self.negative_stores.load(.monotonic),
            .evictions = self.evictions.load(.monotonic),
            .prefetch_eligible = self.prefetch_eligible.load(.monotonic),
            .stale_hits = self.stale_hits.load(.monotonic),
        };
    }

    pub fn deinit(self: *RRsetCache) void {
        const alloc = self.counting.allocator();
        const keys = self.map.keys();
        const vals = self.map.values();
        for (0..self.map.count()) |i| {
            freeKey(alloc, keys[i]);
            freeEntry(alloc, vals[i]);
        }
        self.map.deinit(alloc);
        if (self.visited) |v| self.counting.backing.free(v);
    }

    // ── Lookup ────────────────────────────────────────────────────────

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
        if (self.rwlock) |*rw| rw.lockSharedUncancelable(self.io);
        defer if (self.rwlock) |*rw| rw.unlockShared(self.io);
        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return null;
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const idx = self.map.getIndex(probe) orelse {
            _ = self.misses.fetchAdd(1, .monotonic);
            return null;
        };
        // SIEVE: mark as recently accessed (atomic store, safe under shared read lock)
        self.markVisited(idx);
        const entry = self.map.values()[idx];

        const now = self.now_fn();

        switch (entry) {
            .positive => |rrset| {
                const is_expired = now >= rrset.expires_at;
                if (is_expired) {
                    if (self.serve_stale_ttl == 0 or (now - rrset.expires_at) >= self.serve_stale_ttl) {
                        // Deferred eviction: under shared read lock we cannot mutate the map.
                        // Expired entries linger until the next write path calls evictIfNeeded().
                        // Compliant with RFC 8767.
                        _ = self.misses.fetchAdd(1, .monotonic);
                        return null;
                    }
                    // Stale but within window — serve with synthetic TTL (RFC 8767).
                    // Clear security status: RRSIGs may have expired since caching,
                    // so the resolver cannot vouch for authenticity (RFC 4035 §3.2.3).
                    const records = cloneRRset(caller_alloc, rrset.records, 30) catch return null;
                    _ = self.hits.fetchAdd(1, .monotonic);
                    _ = self.stale_hits.fetchAdd(1, .monotonic);
                    _ = self.prefetch_eligible.fetchAdd(1, .monotonic);
                    return .{ .hit = .{ .records = records, .remaining_ttl = 30, .needs_prefetch = true, .security_status = .unchecked } };
                }

                const elapsed: u32 = @intCast(@min(@max(now - rrset.stored_at, 0), rrset.original_ttl));
                const remaining = rrset.original_ttl - elapsed;
                const needs_prefetch = self.prefetch and (remaining * 10 <= rrset.original_ttl);
                const records = cloneRRset(caller_alloc, rrset.records, remaining) catch return null;

                _ = self.hits.fetchAdd(1, .monotonic);
                if (needs_prefetch) _ = self.prefetch_eligible.fetchAdd(1, .monotonic);
                return .{ .hit = .{ .records = records, .remaining_ttl = remaining, .needs_prefetch = needs_prefetch, .security_status = rrset.security_status } };
            },
            .negative => |neg| {
                const is_expired = now >= neg.expires_at;
                if (is_expired) {
                    // Never serve-stale for SERVFAIL entries — their short TTL
                    // (e.g. 1s for DNSSEC bogus) is intentional and serve-stale
                    // would extend failure duration beyond design intent.
                    if (self.serve_stale_ttl == 0 or neg.rcode == .server_failure or (now - neg.expires_at) >= self.serve_stale_ttl) {
                        // Deferred eviction: expired entry stays until next write.
                        _ = self.misses.fetchAdd(1, .monotonic);
                        return null;
                    }
                    const soa = cloneCachedRecord(caller_alloc, neg.soa, 30);
                    _ = self.hits.fetchAdd(1, .monotonic);
                    _ = self.stale_hits.fetchAdd(1, .monotonic);
                    _ = self.prefetch_eligible.fetchAdd(1, .monotonic);
                    return .{ .negative = .{
                        .rcode = neg.rcode,
                        .remaining_ttl = 30,
                        .soa = soa,
                        .needs_prefetch = true,
                        .security_status = .unchecked,
                    } };
                }

                const elapsed: u32 = @intCast(@min(@max(now - neg.stored_at, 0), neg.original_ttl));
                const remaining = neg.original_ttl - elapsed;
                const needs_prefetch = self.prefetch and (remaining * 10 <= neg.original_ttl);
                const soa = cloneCachedRecord(caller_alloc, neg.soa, remaining);

                _ = self.hits.fetchAdd(1, .monotonic);
                if (needs_prefetch) _ = self.prefetch_eligible.fetchAdd(1, .monotonic);
                return .{ .negative = .{
                    .rcode = neg.rcode,
                    .remaining_ttl = remaining,
                    .soa = soa,
                    .needs_prefetch = needs_prefetch,
                    .security_status = neg.security_status,
                } };
            },
        }
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
    pub fn storeResponseWithStatus(self: *RRsetCache, response: dns.Message, authority_zone: dns.Name, status: SecurityStatus) void {
        if (response.header.rcode != .no_error) return;
        if (self.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (self.rwlock) |*rw| rw.unlock(self.io);
        self.storeRRsetsImpl(response.answers, authority_zone, true, status);
        // Skip authority/additional from positive responses (CVE-2025-11411).
        if (response.answers.len == 0) {
            self.storeRRsetsImpl(response.authorities, authority_zone, true, .unchecked);
            self.storeRRsetsImpl(response.additionals, authority_zone, true, .unchecked);
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
        if (self.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (self.rwlock) |*rw| rw.unlock(self.io);
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

        const alloc = self.counting.allocator();
        const key_name = toLowerNameAlloc(alloc, name) catch return;
        const key = CacheKey{ .name = key_name, .rtype = rtype, .rclass = rclass };

        if (self.hasProtectedPositive(key)) {
            alloc.free(key_name);
            return;
        }
        self.removeAndFree(key);

        const cached_soa_name = cloneName(alloc, soa.name) catch {
            alloc.free(key_name);
            return;
        };
        const cached_soa_rdata = cloneRData(alloc, soa.rdata) catch {
            dns.freeName(alloc, cached_soa_name);
            alloc.free(key_name);
            return;
        };
        const cached_soa = CachedRecord{
            .name = cached_soa_name,
            .rtype = soa.rtype,
            .rclass = soa.rclass,
            .rdata = cached_soa_rdata,
        };

        self.evictIfNeeded();

        const now = self.now_fn();
        const capped_ttl = clampTtl(self.min_ttl, neg_ttl);
        self.map.put(alloc, key, .{ .negative = .{
            .rcode = rcode,
            .expires_at = now + @as(i64, capped_ttl),
            .original_ttl = capped_ttl,
            .stored_at = now,
            .soa = cached_soa,
            .security_status = security_status,
        } }) catch {
            dns.freeName(alloc, cached_soa.name);
            dns.freeRData(alloc, cached_soa.rdata);
            alloc.free(key_name);
            return;
        };
        self.markLastVisited();
        _ = self.negative_stores.fetchAdd(1, .monotonic);
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
        if (self.rwlock) |*rw| rw.lockUncancelable(self.io);
        defer if (self.rwlock) |*rw| rw.unlock(self.io);
        if (ttl == 0) return;

        const alloc = self.counting.allocator();
        const key_name = toLowerNameAlloc(alloc, name) catch return;
        const key = CacheKey{ .name = key_name, .rtype = rtype, .rclass = rclass };

        if (self.hasProtectedPositive(key)) {
            alloc.free(key_name);
            return;
        }
        self.removeAndFree(key);
        self.evictIfNeeded();

        const now = self.now_fn();
        // Don't apply min_ttl — callers provide intentional TTLs (e.g. 1s for
        // DNSSEC SERVFAIL). Only cap at max_cache_ttl.
        const capped_ttl = @min(ttl, max_cache_ttl);
        self.map.put(alloc, key, .{ .negative = .{
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
        self.markLastVisited();
        _ = self.negative_stores.fetchAdd(1, .monotonic);
    }

    // ── Internal ──────────────────────────────────────────────────────

    /// True if `key` has a non-expired validated positive entry (RFC 9520 §3.4).
    fn hasProtectedPositive(self: *RRsetCache, key: CacheKey) bool {
        const existing = self.map.get(key) orelse return false;
        return switch (existing) {
            .positive => |p| self.now_fn() < p.expires_at and p.security_status != .unchecked,
            .negative => false,
        };
    }

    fn storeRRsetsImpl(self: *RRsetCache, records: []const dns.ResourceRecord, authority_zone: dns.Name, check_bailiwick: bool, status: SecurityStatus) void {
        if (records.len == 0) return;
        const alloc = self.counting.allocator();

        // Track which (name, type) groups we've already processed in this batch
        // to avoid O(n^2) re-scanning. Small fixed buffer — DNS sections are tiny.
        var processed: [64]struct { name_hash: u64, rtype: dns.RType } = undefined;
        var processed_count: usize = 0;

        for (records) |rr| {
            // Skip records we shouldn't cache
            if (rr.ttl == 0) continue;
            if (check_bailiwick and authority_zone.labels.len > 0) {
                if (!rr.name.isSubdomainOf(authority_zone)) continue;
            }

            // Skip SOA in authority — these are for negative caching, handled separately
            if (rr.rtype == .soa) continue;
            // Skip OPT pseudo-records (belt-and-suspenders; parseMessage excludes them)
            if (rr.rtype == .opt) continue;
            // Skip standalone RRSIG — bundled with their signed RRset instead
            if (rr.rtype == .rrsig) continue;
            // Skip DNSKEY/DS when configured (routed to dedicated key cache)
            if (self.skip_key_types and (rr.rtype == .dnskey or rr.rtype == .ds)) continue;

            // Check if we already processed this (name, type) group
            const name_fmt = rr.name.format();
            const name_len = mem.indexOfScalar(u8, &name_fmt, 0) orelse name_fmt.len;
            var lower_buf: [dns.max_name_len + 1]u8 = undefined;
            const lower_name = lowerNameBuf(&lower_buf, name_fmt[0..name_len]) orelse continue;
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

            // Build the key (lower_name is already lowercased in stack buffer)
            const key_name = alloc.dupe(u8, lower_name) catch continue;
            const key = CacheKey{ .name = key_name, .rtype = rr.rtype, .rclass = rr.rclass };

            // Check if we already have a valid entry — don't overwrite
            if (self.map.get(key)) |existing| {
                const now = self.now_fn();
                const expired = switch (existing) {
                    .positive => |p| now >= p.expires_at,
                    .negative => |n| now >= n.expires_at,
                };
                if (!expired) {
                    alloc.free(key_name);
                    continue;
                }
                // Expired — remove and replace
                self.removeAndFree(key);
            }

            // Deep-copy from stack buffer
            const cached_records = alloc.alloc(CachedRecord, collect_count) catch {
                alloc.free(key_name);
                continue;
            };
            var idx: usize = 0;
            for (match_buf[0..collect_count]) |other| {
                const cloned_name = cloneName(alloc, other.name) catch break;
                const cloned_rdata = cloneRData(alloc, other.rdata) catch {
                    dns.freeName(alloc, cloned_name);
                    break;
                };
                cached_records[idx] = .{
                    .name = cloned_name,
                    .rtype = other.rtype,
                    .rclass = other.rclass,
                    .rdata = cloned_rdata,
                };
                idx += 1;
            }

            if (idx == 0 or idx < collect_count) {
                // Partial clone failure — don't cache an incomplete RRset.
                for (cached_records[0..idx]) |cr| {
                    dns.freeName(alloc, cr.name);
                    dns.freeRData(alloc, cr.rdata);
                }
                alloc.free(cached_records);
                alloc.free(key_name);
                continue;
            }

            self.evictIfNeeded();

            const now = self.now_fn();
            const capped_ttl = clampTtl(self.min_ttl, rr.ttl);
            self.map.put(alloc, key, .{ .positive = .{
                .records = cached_records,
                .expires_at = now + @as(i64, capped_ttl),
                .original_ttl = capped_ttl,
                .stored_at = now,
                .security_status = status,
            } }) catch {
                for (cached_records) |cr| {
                    dns.freeName(alloc, cr.name);
                    dns.freeRData(alloc, cr.rdata);
                }
                alloc.free(cached_records);
                alloc.free(key_name);
                continue;
            };
            self.markLastVisited();
            _ = self.stores.fetchAdd(1, .monotonic);
        }
    }

    fn removeAndFree(self: *RRsetCache, key: CacheKey) void {
        const idx = self.map.getIndex(key) orelse return;
        self.removeAtIndex(self.counting.allocator(), idx);
    }

    inline fn markVisited(self: *RRsetCache, i: usize) void {
        if (self.visited) |v| if (i < v.len) v[i].store(1, .monotonic);
    }

    /// Mark the most recently inserted entry as visited. Callers MUST invoke
    /// this only after a `map.put` that was a fresh insert (not an update),
    /// so the new entry sits at the tail of the ordered map.
    inline fn markLastVisited(self: *RRsetCache) void {
        self.markVisited(self.map.count() - 1);
    }

    inline fn clearVisited(self: *RRsetCache, i: usize) void {
        if (self.visited) |v| if (i < v.len) v[i].store(0, .monotonic);
    }

    inline fn isVisited(self: *RRsetCache, i: usize) bool {
        const v = self.visited orelse return false;
        return i < v.len and v[i].load(.monotonic) != 0;
    }

    /// Swap-remove entry at index: fixup visited flag, free key/value, clamp hand.
    fn removeAtIndex(self: *RRsetCache, alloc: Allocator, i: usize) void {
        const key = self.map.keys()[i];
        const val = self.map.values()[i];
        const last = self.map.count() - 1;
        if (i != last) {
            if (self.visited) |v| if (i < v.len and last < v.len) {
                v[i].store(v[last].load(.monotonic), .monotonic);
            };
        }
        self.map.swapRemoveAt(i);
        freeKey(alloc, key);
        freeEntry(alloc, val);
        if (self.hand >= self.map.count()) self.hand = 0;
    }

    fn evictIfNeeded(self: *RRsetCache) void {
        const count: u32 = @intCast(self.map.count());
        if (count < self.max_entries) {
            if (count < self.max_entries / 4 * 3) return;
            self.sweepExpired(count);
            return;
        }
        self.sieveEvict(count);
    }

    /// Probe a bounded number of entries from the SIEVE hand, evicting the first
    /// expired one. Clears visited flags as it goes for gradual SIEVE decay.
    fn sweepExpired(self: *RRsetCache, count: u32) void {
        if (count == 0) return;
        const now = self.now_fn();
        const alloc = self.counting.allocator();
        var probes: u32 = 0;
        while (probes < 8) : (probes += 1) {
            if (self.hand >= count) self.hand = 0;
            const i = self.hand;
            self.hand += 1;
            self.clearVisited(i);
            const expired = switch (self.map.values()[i]) {
                .positive => |p| now >= p.expires_at,
                .negative => |n| now >= n.expires_at,
            };
            if (expired) {
                self.removeAtIndex(alloc, i);
                _ = self.evictions.fetchAdd(1, .monotonic);
                self.hand = if (i < self.map.count()) @intCast(i) else 0;
                return;
            }
        }
    }

    /// SIEVE eviction: scan from hand, give visited entries a second chance,
    /// evict the first unvisited entry. Amortized O(1).
    fn sieveEvict(self: *RRsetCache, count: u32) void {
        const alloc = self.counting.allocator();
        var probes: u32 = 0;
        while (probes < count) : (probes += 1) {
            if (self.hand >= count) self.hand = 0;
            const i = self.hand;
            if (self.isVisited(i)) {
                self.clearVisited(i);
                self.hand += 1;
            } else {
                self.removeAtIndex(alloc, i);
                _ = self.evictions.fetchAdd(1, .monotonic);
                return;
            }
        }
        // All visited (flags now cleared) — evict at hand
        if (self.hand >= count) self.hand = 0;
        self.removeAtIndex(alloc, self.hand);
        _ = self.evictions.fetchAdd(1, .monotonic);
    }

    fn freeKey(alloc: Allocator, key: CacheKey) void {
        alloc.free(key.name);
    }

    fn freeEntry(alloc: Allocator, entry: CacheEntry) void {
        switch (entry) {
            .positive => |rrset| {
                for (rrset.records) |cr| {
                    dns.freeName(alloc, cr.name);
                    dns.freeRData(alloc, cr.rdata);
                }
                alloc.free(rrset.records);
            },
            .negative => |neg| {
                if (neg.soa) |soa| {
                    dns.freeName(alloc, soa.name);
                    dns.freeRData(alloc, soa.rdata);
                }
            },
        }
    }
};

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

var test_time: i64 = 1000;

fn testNowSeconds() i64 {
    return test_time;
}

fn makeTestCache(alloc: Allocator) RRsetCache {
    var cache = RRsetCache.init(alloc, 1024 * 1024, 100, testing.io);
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

test "cache store and lookup positive" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = makeTestCache(alloc);
    defer cache.deinit();

    const name = try makeTestName(alloc, &.{ "example", "com" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 93, 184, 216, 34 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    const root_zone = dns.Name{ .labels = &.{} };
    cache.storeResponse(response, root_zone);

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

    const name = try makeTestName(alloc, &.{ "example", "com" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    cache.storeResponse(response, dns.Name{ .labels = &.{} });

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

    const name = try makeTestName(alloc, &.{ "example", "com" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    cache.storeResponse(response, dns.Name{ .labels = &.{} });

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

    const name = try makeTestName(alloc, &.{ "EXAMPLE", "COM" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    cache.storeResponse(response, dns.Name{ .labels = &.{} });

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

    const soa_name = try makeTestName(alloc, &.{ "example", "com" });
    const mname = try makeTestName(alloc, &.{ "ns1", "example", "com" });
    const rname = try makeTestName(alloc, &.{ "admin", "example", "com" });

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = soa_name,
        .rtype = .soa,
        .rclass = .in,
        .ttl = 900,
        .rdata = .{
            .soa = .{
                .mname = mname,
                .rname = rname,
                .serial = 2024010101,
                .refresh = 3600,
                .retry = 900,
                .expire = 604800,
                .minimum = 600, // min(900, 600) = 600
            },
        },
    };
    defer {
        for (authorities) |rr| {
            dns.freeName(alloc, rr.name);
            dns.freeRData(alloc, rr.rdata);
        }
        alloc.free(authorities);
    }

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
    const soa_name = try makeTestName(alloc, &.{ "other", "net" });
    const mname = try makeTestName(alloc, &.{ "ns1", "other", "net" });
    const rname = try makeTestName(alloc, &.{ "admin", "other", "net" });

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = soa_name,
        .rtype = .soa,
        .rclass = .in,
        .ttl = 900,
        .rdata = .{ .soa = .{
            .mname = mname,
            .rname = rname,
            .serial = 2024010101,
            .refresh = 3600,
            .retry = 900,
            .expire = 604800,
            .minimum = 600,
        } },
    };
    defer {
        for (authorities) |rr| {
            dns.freeName(alloc, rr.name);
            dns.freeRData(alloc, rr.rdata);
        }
        alloc.free(authorities);
    }

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
    const soa_name = try makeTestName(alloc, &.{"com"});
    const mname = try makeTestName(alloc, &.{ "ns1", "com" });
    const rname = try makeTestName(alloc, &.{ "admin", "com" });

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = soa_name,
        .rtype = .soa,
        .rclass = .in,
        .ttl = 900,
        .rdata = .{ .soa = .{
            .mname = mname,
            .rname = rname,
            .serial = 2024010101,
            .refresh = 3600,
            .retry = 900,
            .expire = 604800,
            .minimum = 600,
        } },
    };
    defer {
        for (authorities) |rr| {
            dns.freeName(alloc, rr.name);
            dns.freeRData(alloc, rr.rdata);
        }
        alloc.free(authorities);
    }

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
    const soa_name = try makeTestName(alloc, &.{"com"});
    const mname = try makeTestName(alloc, &.{ "ns1", "com" });
    const rname = try makeTestName(alloc, &.{ "admin", "com" });
    const zone_cut = try makeTestName(alloc, &.{ "example", "com" });
    defer dns.freeName(alloc, zone_cut);

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = soa_name,
        .rtype = .soa,
        .rclass = .in,
        .ttl = 900,
        .rdata = .{ .soa = .{
            .mname = mname,
            .rname = rname,
            .serial = 2024010101,
            .refresh = 3600,
            .retry = 900,
            .expire = 604800,
            .minimum = 600,
        } },
    };
    defer {
        for (authorities) |rr| {
            dns.freeName(alloc, rr.name);
            dns.freeRData(alloc, rr.rdata);
        }
        alloc.free(authorities);
    }

    cache.storeNegative("www.example.com", .a, .in, .name_error, authorities, zone_cut, .unchecked);

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const result = cache.lookup(arena.allocator(), "www.example.com", .a, .in);
    try testing.expect(result == null); // rejected — SOA "com" is above zone cut "example.com"
}

test "cache eviction when full" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.init(alloc, 1024 * 1024, 2, testing.io); // max 2 entries
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    // Store 3 different entries
    const names = [_][]const u8{ "a.com", "b.com", "c.com" };
    for (names) |n| {
        const parsed = try dns.parseDottedName(alloc, n);
        const answers = try alloc.alloc(dns.ResourceRecord, 1);
        answers[0] = .{ .name = parsed, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

        const response = makeTestResponse(answers);
        cache.storeResponse(response, dns.Name{ .labels = &.{} });
        dns.freeMessage(alloc, response);
    }

    // Should not exceed max_entries
    try testing.expect(cache.map.count() <= 2);
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

    const name = try makeTestName(alloc, &.{ "zero", "ttl" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 0, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    cache.storeResponse(response, dns.Name{ .labels = &.{} });

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

    var cache = RRsetCache.initWithOptions(alloc, 1024 * 1024, 100, .{ .prefetch = true }, testing.io);
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    const name = try makeTestName(alloc, &.{ "example", "com" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);
    cache.storeResponse(response, dns.Name{ .labels = &.{} });

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

    const name = try makeTestName(alloc, &.{ "example", "com" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);
    cache.storeResponse(response, dns.Name{ .labels = &.{} });

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

    var cache = RRsetCache.initWithOptions(alloc, 1024 * 1024, 100, .{ .serve_stale_ttl = 3600 }, testing.io);
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    const name = try makeTestName(alloc, &.{ "stale", "test" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);
    cache.storeResponse(response, dns.Name{ .labels = &.{} });

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

    var cache = RRsetCache.initWithOptions(alloc, 1024 * 1024, 100, .{ .serve_stale_ttl = 3600 }, testing.io);
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    const name = try makeTestName(alloc, &.{ "stale2", "test" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);
    cache.storeResponse(response, dns.Name{ .labels = &.{} });

    // Beyond stale window (60s TTL + 3600s stale = 3660s)
    test_time = 1000 + 60 + 3601;
    {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const result = cache.lookup(arena.allocator(), "stale2.test", .a, .in);
        try testing.expect(result == null);
    }
}

test "cache min TTL floor" {
    const alloc = testing.allocator;
    test_time = 1000;

    var cache = RRsetCache.initWithOptions(alloc, 1024 * 1024, 100, .{ .min_ttl = 300 }, testing.io);
    cache.now_fn = &testNowSeconds;
    defer cache.deinit();

    const name = try makeTestName(alloc, &.{ "cdn", "test" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 60, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);
    cache.storeResponse(response, dns.Name{ .labels = &.{} });

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
    const name = try makeTestName(alloc, &.{ "stats", "test" });
    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 1, 2, 3, 4 } } };

    const response = makeTestResponse(answers);
    defer dns.freeMessage(alloc, response);

    cache.storeResponse(response, dns.Name{ .labels = &.{} });
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
