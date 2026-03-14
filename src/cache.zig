const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const dns = @import("dns.zig");

/// Maximum TTL for cached entries (1 week). Prevents unreasonably long
/// cache lifetimes from malicious or misconfigured responses.
const max_cache_ttl: u32 = 604_800;

// ── Counting allocator ────────────────────────────────────────────────
// Wraps a backing allocator and tracks total bytes allocated.
// Refuses allocations that would exceed a byte cap.

const CountingAllocator = struct {
    backing: Allocator,
    current_bytes: usize,
    max_bytes: usize,

    fn init(backing: Allocator, max_bytes: usize) CountingAllocator {
        return .{ .backing = backing, .current_bytes = 0, .max_bytes = max_bytes };
    }

    fn allocator(self: *CountingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .free = free,
        .remap = remap,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (self.current_bytes + len > self.max_bytes) return null;
        const ptr = self.backing.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.current_bytes += len;
        return ptr;
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len) {
            const delta = new_len - buf.len;
            if (self.current_bytes + delta > self.max_bytes) return false;
        }
        if (self.backing.rawResize(buf, alignment, new_len, ret_addr)) {
            if (new_len > buf.len) {
                self.current_bytes += new_len - buf.len;
            } else {
                self.current_bytes -= buf.len - new_len;
            }
            return true;
        }
        return false;
    }

    fn remap(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len) {
            const delta = new_len - buf.len;
            if (self.current_bytes + delta > self.max_bytes) return null;
        }
        const ptr = self.backing.rawRemap(buf, alignment, new_len, ret_addr) orelse return null;
        if (new_len > buf.len) {
            self.current_bytes += new_len - buf.len;
        } else {
            self.current_bytes -= buf.len - new_len;
        }
        return ptr;
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.current_bytes -= buf.len;
        self.backing.rawFree(buf, alignment, ret_addr);
    }
};

// ── Time ──────────────────────────────────────────────────────────────

/// Returns monotonic seconds (CLOCK_BOOTTIME on Linux).
fn defaultNowSeconds() i64 {
    const ts = std.posix.clock_gettime(.BOOTTIME) catch return 0;
    return ts.sec;
}

// ── Cache key ─────────────────────────────────────────────────────────

const CacheKey = struct {
    /// Lowercased dotted name, owned by the cache.
    name: []const u8,
    rtype: dns.RType,
    rclass: dns.RClass,
};

const CacheKeyContext = struct {
    pub fn hash(_: @This(), key: CacheKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(key.name);
        h.update(mem.asBytes(&key.rtype));
        h.update(mem.asBytes(&key.rclass));
        return h.final();
    }

    pub fn eql(_: @This(), a: CacheKey, b: CacheKey) bool {
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

fn cloneName(alloc: Allocator, name: dns.Name) !dns.Name {
    const labels = try alloc.alloc([]const u8, name.labels.len);
    errdefer alloc.free(labels);
    var initialized: usize = 0;
    errdefer for (labels[0..initialized]) |l| alloc.free(l);
    for (name.labels, 0..) |label, i| {
        labels[i] = try alloc.dupe(u8, label);
        initialized += 1;
    }
    return .{ .labels = labels };
}

fn cloneRData(alloc: Allocator, rdata: dns.RData) !dns.RData {
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
fn cloneRRset(alloc: Allocator, cached: []const CachedRecord, ttl: u32) ?[]dns.ResourceRecord {
    const records = alloc.alloc(dns.ResourceRecord, cached.len) catch return null;
    for (cached, 0..) |cr, i| {
        records[i] = .{
            .name = cloneName(alloc, cr.name) catch return null,
            .rtype = cr.rtype,
            .rclass = cr.rclass,
            .ttl = ttl,
            .rdata = cloneRData(alloc, cr.rdata) catch return null,
        };
    }
    return records;
}

/// Clone an optional CachedRecord into a ResourceRecord with a given TTL.
fn cloneCachedRecord(alloc: Allocator, cached: ?CachedRecord, ttl: u32) ?dns.ResourceRecord {
    const s = cached orelse return null;
    return dns.ResourceRecord{
        .name = cloneName(alloc, s.name) catch return null,
        .rtype = s.rtype,
        .rclass = s.rclass,
        .ttl = ttl,
        .rdata = cloneRData(alloc, s.rdata) catch return null,
    };
}

/// Lowercase src into dest, returning the written slice.
fn lowerInto(dest: []u8, src: []const u8) []const u8 {
    for (src, 0..) |c, i| dest[i] = std.ascii.toLower(c);
    return dest[0..src.len];
}

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
    map: std.HashMapUnmanaged(CacheKey, CacheEntry, CacheKeyContext, 80),
    max_entries: u32,
    now_fn: *const fn () i64,
    mutex: ?std.Thread.Mutex = null,
    serve_stale_ttl: u32 = 0,
    min_ttl: u32 = 0,
    prefetch: bool = false,
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
    };

    pub fn init(backing: Allocator, max_bytes: usize, max_entries: u32) RRsetCache {
        return initWithOptions(backing, max_bytes, max_entries, .{});
    }

    pub fn initWithOptions(backing: Allocator, max_bytes: usize, max_entries: u32, opts: CacheOptions) RRsetCache {
        return .{
            .counting = CountingAllocator.init(backing, max_bytes),
            .map = .empty,
            .max_entries = max_entries,
            .now_fn = &defaultNowSeconds,
            .prefetch = opts.prefetch,
            .serve_stale_ttl = opts.serve_stale_ttl,
            .min_ttl = opts.min_ttl,
        };
    }

    pub fn initThreadSafe(backing: Allocator, max_bytes: usize, max_entries: u32) RRsetCache {
        return initThreadSafeWithOptions(backing, max_bytes, max_entries, .{});
    }

    pub fn initThreadSafeWithOptions(backing: Allocator, max_bytes: usize, max_entries: u32, opts: CacheOptions) RRsetCache {
        var c = initWithOptions(backing, max_bytes, max_entries, opts);
        c.mutex = .{};
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
        if (self.mutex) |*m| m.lock();
        defer if (self.mutex) |*m| m.unlock();
        return .{
            .entries = @intCast(self.map.count()),
            .memory_bytes = self.counting.current_bytes,
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
        var it = self.map.iterator();
        const alloc = self.counting.allocator();
        while (it.next()) |entry| {
            freeKey(alloc, entry.key_ptr.*);
            freeEntry(alloc, entry.value_ptr.*);
        }
        self.map.deinit(alloc);
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
        if (self.mutex) |*m| m.lock();
        defer if (self.mutex) |*m| m.unlock();
        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return null;
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const entry = self.map.get(probe) orelse {
            _ = self.misses.fetchAdd(1, .monotonic);
            return null;
        };

        const now = self.now_fn();

        switch (entry) {
            .positive => |rrset| {
                const is_expired = now >= rrset.expires_at;
                if (is_expired) {
                    if (self.serve_stale_ttl == 0 or (now - rrset.expires_at) >= self.serve_stale_ttl) {
                        self.removeAndFree(probe);
                        _ = self.misses.fetchAdd(1, .monotonic);
                        return null;
                    }
                    // Stale but within window — serve with synthetic TTL (RFC 8767).
                    // Clear security status: RRSIGs may have expired since caching,
                    // so the resolver cannot vouch for authenticity (RFC 4035 §3.2.3).
                    const records = cloneRRset(caller_alloc, rrset.records, 30) orelse return null;
                    _ = self.hits.fetchAdd(1, .monotonic);
                    _ = self.stale_hits.fetchAdd(1, .monotonic);
                    _ = self.prefetch_eligible.fetchAdd(1, .monotonic);
                    return .{ .hit = .{ .records = records, .remaining_ttl = 30, .needs_prefetch = true, .security_status = .unchecked } };
                }

                const elapsed: u32 = @intCast(@min(@max(now - rrset.stored_at, 0), rrset.original_ttl));
                const remaining = rrset.original_ttl - elapsed;
                const needs_prefetch = self.prefetch and (remaining * 10 <= rrset.original_ttl);
                const records = cloneRRset(caller_alloc, rrset.records, remaining) orelse return null;

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
                        self.removeAndFree(probe);
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
        if (response.header.rcode != .no_error) return;
        if (self.mutex) |*m| m.lock();
        defer if (self.mutex) |*m| m.unlock();
        self.storeRRsets(response.answers, authority_zone, true);
        self.storeRRsets(response.authorities, authority_zone, true);
        self.storeRRsets(response.additionals, authority_zone, true);
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
        if (self.mutex) |*m| m.lock();
        defer if (self.mutex) |*m| m.unlock();
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

        // Remove existing entry if present
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
        _ = self.negative_stores.fetchAdd(1, .monotonic);
    }

    /// Store a bare negative entry (no SOA required).
    /// Used to cache insecure delegation status (negative DS) so that
    /// cached delegation lookups can determine DNSSEC security state.
    pub fn storeNegativeBare(
        self: *RRsetCache,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
        rcode: dns.RCode,
        ttl: u32,
    ) void {
        if (self.mutex) |*m| m.lock();
        defer if (self.mutex) |*m| m.unlock();
        if (ttl == 0) return;

        const alloc = self.counting.allocator();
        const key_name = toLowerNameAlloc(alloc, name) catch return;
        const key = CacheKey{ .name = key_name, .rtype = rtype, .rclass = rclass };

        // Don't overwrite non-expired validated positive entries — but DO overwrite
        // .unchecked entries so that DNSSEC validation failures (bogusServfail)
        // can replace pre-validation cached data (RFC 9520 §3.4).
        if (self.map.get(key)) |existing| {
            switch (existing) {
                .positive => |p| if (self.now_fn() < p.expires_at and p.security_status != .unchecked) {
                    alloc.free(key_name);
                    return;
                },
                .negative => {},
            }
            self.removeAndFree(key);
        }
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
        } }) catch {
            alloc.free(key_name);
            return;
        };
        _ = self.negative_stores.fetchAdd(1, .monotonic);
    }

    /// Update the DNSSEC security status of an existing cache entry.
    /// Called after DNSSEC validation succeeds to mark cached data as
    /// authenticated (RFC 4035 §3.2.3).
    pub fn updateSecurityStatus(
        self: *RRsetCache,
        name: []const u8,
        rtype: dns.RType,
        rclass: dns.RClass,
        status: SecurityStatus,
    ) void {
        if (self.mutex) |*m| m.lock();
        defer if (self.mutex) |*m| m.unlock();
        var lower_buf: [dns.max_name_len + 1]u8 = undefined;
        const lower_name = lowerNameBuf(&lower_buf, name) orelse return;
        const probe = CacheKey{ .name = lower_name, .rtype = rtype, .rclass = rclass };
        const entry = self.map.getPtr(probe) orelse return;
        switch (entry.*) {
            .positive => |*rrset| rrset.security_status = status,
            .negative => |*neg| neg.security_status = status,
        }
    }

    // ── Internal ──────────────────────────────────────────────────────

    fn storeRRsets(self: *RRsetCache, records: []const dns.ResourceRecord, authority_zone: dns.Name, check_bailiwick: bool) void {
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

            // Count matching records in this section
            var count: usize = 0;
            for (records) |other| {
                if (other.rtype == rr.rtype and other.rclass == rr.rclass and rr.name.eql(other.name)) {
                    count += 1;
                }
            }

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

            // Deep-copy the RRset
            const cached_records = alloc.alloc(CachedRecord, count) catch {
                alloc.free(key_name);
                continue;
            };
            var idx: usize = 0;
            for (records) |other| {
                if (other.rtype == rr.rtype and other.rclass == rr.rclass and rr.name.eql(other.name)) {
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
            }

            if (idx == 0 or idx < count) {
                // idx==0: no records cloned; idx<count: partial clone failure —
                // don't cache an incomplete RRset.
                for (cached_records[0..idx]) |cr| {
                    dns.freeName(alloc, cr.name);
                    dns.freeRData(alloc, cr.rdata);
                }
                alloc.free(cached_records);
                alloc.free(key_name);
                continue;
            }

            // Shrink allocation to actual count so freeEntry gets correct size
            const final_records = if (idx < count)
                alloc.realloc(cached_records, idx) catch {
                    // realloc shrink failed — free everything and skip
                    for (cached_records[0..idx]) |cr| {
                        dns.freeName(alloc, cr.name);
                        dns.freeRData(alloc, cr.rdata);
                    }
                    alloc.free(cached_records);
                    alloc.free(key_name);
                    continue;
                }
            else
                cached_records;

            self.evictIfNeeded();

            const now = self.now_fn();
            const capped_ttl = clampTtl(self.min_ttl, rr.ttl);
            self.map.put(alloc, key, .{ .positive = .{
                .records = final_records,
                .expires_at = now + @as(i64, capped_ttl),
                .original_ttl = capped_ttl,
                .stored_at = now,
            } }) catch {
                for (final_records) |cr| {
                    dns.freeName(alloc, cr.name);
                    dns.freeRData(alloc, cr.rdata);
                }
                alloc.free(final_records);
                alloc.free(key_name);
                continue;
            };
            _ = self.stores.fetchAdd(1, .monotonic);
        }
    }

    fn removeAndFree(self: *RRsetCache, key: CacheKey) void {
        const alloc = self.counting.allocator();
        if (self.map.fetchRemove(key)) |kv| {
            freeKey(alloc, kv.key);
            freeEntry(alloc, kv.value);
        }
    }

    fn evictIfNeeded(self: *RRsetCache) void {
        if (self.map.count() < self.max_entries) return;

        const alloc = self.counting.allocator();
        const now = self.now_fn();

        // First: try to evict an expired entry
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const expired = switch (entry.value_ptr.*) {
                .positive => |p| now >= p.expires_at,
                .negative => |n| now >= n.expires_at,
            };
            if (expired) {
                const key = entry.key_ptr.*;
                const val = entry.value_ptr.*;
                self.map.removeByPtr(entry.key_ptr);
                freeKey(alloc, key);
                freeEntry(alloc, val);
                _ = self.evictions.fetchAdd(1, .monotonic);
                return;
            }
        }

        // No expired entries: evict random
        var it2 = self.map.iterator();
        const count = self.map.count();
        if (count == 0) return;
        const target = std.crypto.random.uintLessThan(u32, @intCast(count));
        var idx: u32 = 0;
        while (it2.next()) |entry| {
            if (idx == target) {
                const key = entry.key_ptr.*;
                const val = entry.value_ptr.*;
                self.map.removeByPtr(entry.key_ptr);
                freeKey(alloc, key);
                freeEntry(alloc, val);
                _ = self.evictions.fetchAdd(1, .monotonic);
                return;
            }
            idx += 1;
        }
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
    var cache = RRsetCache.init(alloc, 1024 * 1024, 100);
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
            .id = 0, .qr = true, .opcode = .query, .aa = true, .tc = false,
            .rd = false, .ra = false, .z = 0, .ad = false, .cd = false, .rcode = .no_error,
            .qd_count = 0, .an_count = @intCast(answers.len), .ns_count = 0, .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
        .authorities = &.{},
        .additionals = &.{},
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
        .rdata = .{ .soa = .{
            .mname = mname,
            .rname = rname,
            .serial = 2024010101,
            .refresh = 3600,
            .retry = 900,
            .expire = 604800,
            .minimum = 600, // min(900, 600) = 600
        } },
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
    const soa_name = try makeTestName(alloc, &.{ "com" });
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

    var cache = RRsetCache.init(alloc, 1024 * 1024, 2); // max 2 entries
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

    var cache = RRsetCache.initWithOptions(alloc, 1024 * 1024, 100, .{ .prefetch = true });
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

    var cache = RRsetCache.initWithOptions(alloc, 1024 * 1024, 100, .{ .serve_stale_ttl = 3600 });
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

    var cache = RRsetCache.initWithOptions(alloc, 1024 * 1024, 100, .{ .serve_stale_ttl = 3600 });
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

    var cache = RRsetCache.initWithOptions(alloc, 1024 * 1024, 100, .{ .min_ttl = 300 });
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
