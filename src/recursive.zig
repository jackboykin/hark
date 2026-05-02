const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const BlockingUdpTransport = @import("blocking_transport.zig").BlockingUdpTransport;
const BlockingTcpTransport = @import("blocking_transport.zig").BlockingTcpTransport;
const TlsTransport = @import("tls_transport.zig").TlsTransport;
const transport_mod = @import("transport.zig");
const Transport = transport_mod.Transport;
const Transports = transport_mod.Transports;
const encrypted_ns = @import("encrypted_ns.zig");
const EncryptedNsCache = encrypted_ns.EncryptedNsCache;
const AddressKey = @import("connection_pool.zig").AddressKey;
const TcpConnectionPool = @import("connection_pool.zig").TcpConnectionPool;
const RttCache = @import("ns_rtt.zig").RttCache;
const rand = @import("rand.zig");
const monotonic = @import("monotonic.zig");
const na = @import("net_address.zig");
const CountingAllocator = @import("counting_allocator.zig").CountingAllocator;
const NsSelector = @import("ns_selector.zig").NsSelector;
const cache_mod = @import("cache.zig");
const RRsetCache = cache_mod.RRsetCache;
const InFlightTable = @import("dedup.zig").InFlightTable;
const NsecCache = @import("nsec_cache.zig").NsecCache;
const log = std.log.scoped(.resolver);

// ── Root Hints ─────────────────────────────────────────────────────────
// IPv4 + IPv6 addresses for a.root-servers.net through m.root-servers.net.
// Source: https://www.internic.net/domain/named.root

pub const root_hints: [26]na.Address = .{
    // IPv4
    na.initIp4(.{ 198, 41, 0, 4 }, 53), // a
    na.initIp4(.{ 170, 247, 170, 2 }, 53), // b
    na.initIp4(.{ 192, 33, 4, 12 }, 53), // c
    na.initIp4(.{ 199, 7, 91, 13 }, 53), // d
    na.initIp4(.{ 192, 203, 230, 10 }, 53), // e
    na.initIp4(.{ 192, 5, 5, 241 }, 53), // f
    na.initIp4(.{ 192, 112, 36, 4 }, 53), // g
    na.initIp4(.{ 198, 97, 190, 53 }, 53), // h
    na.initIp4(.{ 192, 36, 148, 17 }, 53), // i
    na.initIp4(.{ 192, 58, 128, 30 }, 53), // j
    na.initIp4(.{ 193, 0, 14, 129 }, 53), // k
    na.initIp4(.{ 199, 7, 83, 42 }, 53), // l
    na.initIp4(.{ 202, 12, 27, 33 }, 53), // m
    // IPv6
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x03, 0xba, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 }, 53, 0, 0), // a
    na.initIp6(.{ 0x28, 0x01, 0x01, 0xb8, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b }, 53, 0, 0), // b
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c }, 53, 0, 0), // c
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x2d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d }, 53, 0, 0), // d
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e }, 53, 0, 0), // e
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x2f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f }, 53, 0, 0), // f
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x0d }, 53, 0, 0), // g
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, 53, 0, 0), // h
    na.initIp6(.{ 0x20, 0x01, 0x07, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, 53, 0, 0), // i
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x03, 0x0c, 0x27, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 }, 53, 0, 0), // j
    na.initIp6(.{ 0x20, 0x01, 0x07, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 53, 0, 0), // k
    na.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x9f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 }, 53, 0, 0), // l
    na.initIp6(.{ 0x20, 0x01, 0x0d, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35 }, 53, 0, 0), // m
};

const max_referrals = 10;
const max_servers_per_level = 26;
const max_cname_chain = 8;
const max_minimise_count = 10;

/// Parse a DNS message, propagating OOM and converting other parse
/// errors to null so callers can skip malformed responses. Logs the
/// server address and error name at debug level — warn would be a DoS
/// amplifier for an attacker controlling an authoritative server.
fn tryParseMessage(allocator: mem.Allocator, data: []const u8, server: na.Address) error{OutOfMemory}!?dns.Message {
    return dns.parseMessage(allocator, data) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            var addr_buf: [64]u8 = undefined;
            log.debug("dropping malformed reply from {s}: {s}", .{ na.format(server, &addr_buf), @errorName(err) });
            return null;
        },
    };
}

// ── RecursiveResolver ──────────────────────────────────────────────────

pub const RecursiveResolver = struct {
    transports: Transports,
    io: std.Io,
    cache: ?*RRsetCache = null,
    qname_minimisation: bool = true,
    /// Whether to validate DNSSEC signatures (may be disabled per-query by CD bit)
    dnssec_enabled: bool = false,
    /// Whether to request DNSSEC data (DO bit) — always true if server is DNSSEC-capable.
    /// RFC 4035 §3.2.1: MUST set DO regardless of CD bit or per-query validation.
    dnssec_aware: bool = false,
    encrypted_ns_cache: ?*EncryptedNsCache = null,
    rtt_cache: ?*RttCache = null,
    ns_selector: ?*NsSelector = null,
    bypass_cache: bool = false,
    dedup: ?*InFlightTable = null,
    nsec_cache: ?*NsecCache = null,
    key_cache: ?*RRsetCache = null,
    tcp_pool: ?*TcpConnectionPool = null,
    /// Persistent allocator for helper thread arenas (parallel NS resolution).
    gpa: ?mem.Allocator = null,
    /// Per-query memory cap in bytes (for helper thread arenas).
    query_memory_limit: usize = 2 * 1024 * 1024,
    /// Staggered NS racing interval in ms (0 = disabled).
    stagger_ms: u32 = 0,

    /// Re-entrancy guard: prevents fetchDsFromParent → resolveNsAddresses →
    /// resolveImpl → validateAnswer → fetchDnskey → fetchDsFromParent loops.
    resolving_ds: bool = false,

    /// DNSKEY zone needing proactive refresh — stored in fixed buffer (not arena)
    /// to survive past the per-query arena lifetime. Set by fetchDnskey, propagated
    /// to ResolveResult for async refresh by the server layer.
    pending_dnskey_prefetch: ?[]const u8 = null,
    pending_dnskey_buf: [dns.max_name_len + 1]u8 = undefined,

    /// Per-resolution KeyTrap (CVE-2023-50387) budget. Reset at every `resolve()`
    /// entry so it bounds work for one user-facing query (incl. all CNAME hops,
    /// referrals, DNSKEY/DS validations, and authority NSEC checks).
    validation_budget: dnssec.ValidationBudget = .{},

    /// Create a thread-local resolver clone with fresh transports. Shared
    /// caches and config are inherited; transport and per-query mutable
    /// state are reset so the clone is safe for independent resolution.
    fn cloneForThread(self: *RecursiveResolver, transports: Transports) RecursiveResolver {
        var resolver = self.*;
        resolver.transports = transports;
        resolver.gpa = null;
        resolver.resolving_ds = false;
        resolver.pending_dnskey_prefetch = null;
        resolver.validation_budget = .{};
        return resolver;
    }

    fn udp(self: *const RecursiveResolver) *BlockingUdpTransport {
        return self.transports.do53.asBlocking().udp;
    }

    fn tcp(self: *const RecursiveResolver) ?*BlockingTcpTransport {
        return self.transports.do53.asBlocking().tcp;
    }

    /// Return the dedicated key cache for DNSKEY/DS, falling back to the main cache.
    fn keyCache(self: *RecursiveResolver) ?*RRsetCache {
        if (self.key_cache) |kc| return kc;
        std.debug.assert(!self.dnssec_enabled or self.cache != null);
        return self.cache;
    }

    /// Non-last server timeout cap (Knot KR_CONN_RTT_MAX, RFC 1035 §4.2.1 ≥2s).
    const failover_timeout_cap: u32 = 2000;

    fn serverTimeout(self: *RecursiveResolver, addr_key: AddressKey, is_last: bool) u32 {
        const base: u32 = if (self.rtt_cache) |rc| rc.getTimeout(addr_key) else self.udp().config.timeout_ms;
        return if (is_last) base else @min(base, failover_timeout_cap);
    }

    /// Snapshot timestamp for a server-skip loop. 0 when no rtt_cache —
    /// `RttCache.isDead` returns false for any key against now=0, which
    /// is the right "always live" fallback.
    fn rttNowMs(self: *const RecursiveResolver) i64 {
        return if (self.rtt_cache) |rc| rc.nowMs() else 0;
    }

    pub const ResolveResult = struct {
        message: dns.Message,
        prefetch_name: ?[]const u8 = null,
        prefetch_qtype: dns.RType = .a,
        /// DNSKEY zone needing async refresh (TTL < 10%). Server handles after responding.
        prefetch_dnskey_zone: ?[]const u8 = null,
        /// Happy-Eyeballs (RFC 8305) cousin qtype — A↔AAAA pairing.
        cousin_prefetch_qtype: ?dns.RType = null,
    };

    pub fn resolve(self: *RecursiveResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType) !ResolveResult {
        self.validation_budget = .{};
        var result = try self.resolveImpl(allocator, name, qtype, 0);
        result.prefetch_dnskey_zone = self.pending_dnskey_prefetch;
        result.cousin_prefetch_qtype = switch (qtype) {
            .a => .aaaa,
            .aaaa => .a,
            else => null,
        };
        return result;
    }

    const max_resolve_depth = 3;

    fn resolveImpl(self: *RecursiveResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType, depth: usize) anyerror!ResolveResult {
        var current_name: []const u8 = name;
        var cname_count: usize = 0;
        var total_probes: usize = 0;
        var cname_chain: std.ArrayListUnmanaged(dns.ResourceRecord) = .empty;
        defer cname_chain.deinit(allocator);
        var prefetch_name: ?[]const u8 = null;

        // DNSSEC chain of trust state — starts as secure at root
        var security_state: dnssec.SecurityStatus = if (self.dnssec_enabled) .secure else .unchecked;

        cname_loop: while (true) {
            // CACHE CHECK 1: Do we already have a cached answer?
            if (!self.bypass_cache) {
                if (self.cache) |c| {
                    if (c.lookup(allocator, current_name, qtype, .in)) |result| {
                        const needs_prefetch = switch (result) {
                            .hit => |h| h.needs_prefetch,
                            .negative => |n| n.needs_prefetch,
                        };
                        if (needs_prefetch and cname_count == 0) {
                            prefetch_name = name;
                        }
                        switch (result) {
                            .hit => |h| return .{
                                .message = try withCnameChain(allocator, cname_chain.items, makeCachedMessage(h.records, &.{}, .no_error, h.security_status == .secure)),
                                .prefetch_name = prefetch_name,
                                .prefetch_qtype = qtype,
                            },
                            .negative => |n| {
                                const authorities = if (n.soa) |soa| blk: {
                                    const auths = try allocator.alloc(dns.ResourceRecord, 1);
                                    auths[0] = soa;
                                    break :blk auths;
                                } else &[_]dns.ResourceRecord{};
                                return .{
                                    .message = try withCnameChain(allocator, cname_chain.items, makeCachedMessage(&.{}, authorities, n.rcode, n.security_status == .secure)),
                                    .prefetch_name = prefetch_name,
                                    .prefetch_qtype = qtype,
                                };
                            },
                        }
                    }
                }
            }

            var target_name = try dns.parseDottedName(allocator, current_name);

            // NSEC CACHE: synthesize negative responses from cached NSEC proofs (RFC 8198).
            // Skip if CD bit set (Appendix A) or cache bypassed.
            if (!self.bypass_cache and self.dnssec_enabled) {
                if (self.nsec_cache) |nc| {
                    if (nc.lookupSuffixes(allocator, target_name, qtype, current_name)) |synth| {
                        switch (synth.rcode) {
                            .nxdomain, .nodata => |rc| {
                                const rcode: dns.RCode = if (rc == .nxdomain) .name_error else .no_error;
                                return .{
                                    .message = try withCnameChain(allocator, cname_chain.items, makeCachedMessage(&.{}, &.{synth.soa}, rcode, true)),
                                    .prefetch_name = prefetch_name,
                                    .prefetch_qtype = qtype,
                                };
                            },
                            .wildcard_match => {
                                // RFC 8198 §5.3: synthesize answer from cached wildcard RRset.
                                if (try self.tryWildcardSynth(allocator, synth.ce_label_count, synth.soa, target_name, qtype, cname_chain.items)) |result| {
                                    return .{ .message = result, .prefetch_name = prefetch_name, .prefetch_qtype = qtype };
                                }
                                // Wildcard RRset not in cache — fall through to upstream (RFC 8198 §5.3 MUST)
                            },
                        }
                    }
                }
            }

            var servers: [max_servers_per_level]na.Address = undefined;
            var server_count: usize = root_hints.len;
            @memcpy(servers[0..root_hints.len], &root_hints);

            var seen_zones: [max_referrals]dns.Name = undefined;
            var seen_zone_count: usize = 0;

            // Parent zone tracks the zone the current servers are authoritative for.
            // Starts as root (empty labels = ".") since we begin at root hints.
            var parent_zone = dns.Name{ .labels = &.{} };

            // CACHE CHECK 2: Find closest cached delegation to skip root/TLD queries.
            if (try self.findClosestCachedDelegation(allocator, current_name)) |deleg| {
                server_count = deleg.count;
                @memcpy(servers[0..deleg.count], deleg.addrs[0..deleg.count]);
                parent_zone = deleg.zone;

                // DNSSEC: when skipping referrals via cache, we miss classifyDelegation
                // calls. Check for a cached negative DS to detect insecure delegations.
                if (security_state == .secure and self.dnssec_enabled) {
                    if (hasCachedInsecureDelegation(self.keyCache(), allocator, deleg.zone))
                        security_state = .insecure;
                }
            }

            // QNAME minimization (RFC 9156): start probing one label past the
            // current zone cut and advance toward the full target name.
            var minimise_label_count: usize = if (self.qname_minimisation)
                parent_zone.labels.len + 1
            else
                target_name.labels.len; // disabled: always send full name

            for (0..max_referrals) |_| {
                // Determine if this iteration sends the full (final) query or a probe.
                const is_final = minimise_label_count >= target_name.labels.len or
                    !self.qname_minimisation or total_probes >= max_minimise_count;

                // Build probe name from target's trailing labels, or use the full name.
                const query_name: []const u8 = if (is_final) current_name else blk: {
                    const child_view = dns.Name{ .labels = target_name.labels[target_name.labels.len - minimise_label_count ..] };
                    var child_buf: [dns.max_name_len + 1]u8 = undefined;
                    break :blk try allocator.dupe(u8, child_view.formatInto(&child_buf));
                };
                const query_type: dns.RType = if (is_final) qtype else .a;

                if (!is_final) total_probes += 1;

                // QMIN cache check: see if the probe answer is already cached.
                if (!is_final) {
                    if (self.cache) |c| {
                        if (c.lookup(allocator, query_name, query_type, .in)) |result| {
                            switch (result) {
                                .hit => {
                                    // Name exists — advance probe
                                    minimise_label_count += 1;
                                    continue;
                                },
                                .negative => |n| {
                                    if (n.rcode == .name_error) {
                                        // Cached NXDOMAIN — relaxed mode: stop minimising
                                        minimise_label_count = target_name.labels.len;
                                        continue;
                                    }
                                    // Cached NODATA — name exists, advance
                                    minimise_label_count += 1;
                                    continue;
                                },
                            }
                        }
                    }
                }

                const sqr = try self.queryAuthoritativeServers(allocator, query_name, query_type, &servers, server_count, parent_zone);
                var response = sqr.message;
                const responding_server = sqr.responding_server;

                // ── Probe response handling (non-final queries) ──
                if (!is_final) {
                    // Check for referral — only from successful responses (error responses
                    // may contain NS records in authority that are not valid delegations)
                    if (response.header.rcode == .no_error) {
                        if (extractReferral(response, target_name, parent_zone)) |referral| {
                            if (self.cache) |c| c.storeResponse(response, parent_zone);
                            try self.followReferral(allocator, referral, response.authorities, depth, &security_state, &parent_zone, &servers, &server_count, &seen_zones, &seen_zone_count);
                            minimise_label_count = parent_zone.labels.len + 1;
                            continue;
                        }
                    }

                    if (response.header.rcode == .name_error) {
                        // Probe NXDOMAIN — relaxed mode: cache negative and stop minimising
                        const probe_name = dns.Name{ .labels = target_name.labels[target_name.labels.len - minimise_label_count ..] };
                        switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, probe_name, query_type, true, servers[0..server_count])) {
                            .proceed => {
                                if (response.header.aa) {
                                    if (self.cache) |c| c.storeNegative(query_name, query_type, .in, .name_error, response.authorities, parent_zone, cacheSecurityStatus(security_state));
                                }
                            },
                            .skip_cache => {},
                            .bogus => {
                                minimise_label_count = target_name.labels.len;
                                continue;
                            },
                        }
                        minimise_label_count = target_name.labels.len;
                        continue;
                    }

                    if (response.header.rcode != .no_error and response.header.rcode != .name_error) {
                        // Probe error (SERVFAIL, REFUSED, FORMERR, etc.) — stop minimising, send full QNAME
                        minimise_label_count = target_name.labels.len;
                        continue;
                    }

                    if (response.answers.len > 0) {
                        // Probe got an answer — name exists, advance
                        minimise_label_count += 1;
                        continue;
                    }

                    // NODATA (no answers, no referral) — name exists, cache negative, advance
                    {
                        const probe_name = dns.Name{ .labels = target_name.labels[target_name.labels.len - minimise_label_count ..] };
                        switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, probe_name, query_type, false, servers[0..server_count])) {
                            .proceed => {
                                if (response.header.aa) {
                                    if (self.cache) |c| {
                                        c.storeResponse(response, parent_zone);
                                        c.storeNegative(query_name, query_type, .in, .no_error, response.authorities, parent_zone, cacheSecurityStatus(security_state));
                                    }
                                }
                            },
                            .skip_cache => {},
                            .bogus => {
                                minimise_label_count = target_name.labels.len;
                                continue;
                            },
                        }
                    }
                    minimise_label_count += 1;
                    continue;
                }

                // ── Scrub out-of-bailiwick answer records ──
                // Authoritative servers may include cross-zone records in answers
                // (e.g., CNAME target's A/AAAA from a different zone). Discard
                // them so validation only sees records from the queried zone.
                if (parent_zone.labels.len > 0 and response.answers.len > 0) {
                    const filtered = try allocator.alloc(dns.ResourceRecord, response.answers.len);
                    var filtered_count: usize = 0;
                    for (response.answers) |rr| {
                        if (rr.name.isSubdomainOf(parent_zone)) {
                            filtered[filtered_count] = rr;
                            filtered_count += 1;
                        }
                    }
                    response.answers = filtered[0..filtered_count];
                }

                // ── Final query response handling ──

                // DNSSEC: when the server is authoritative for both parent and
                // child zones, it answers directly without a referral, so
                // classifyDelegation never ran.  Establish delegation security
                // before validation/NXDOMAIN/NODATA (RFC 4035 §5.2).
                if (self.dnssec_enabled and security_state == .secure and
                    target_name.labels.len > parent_zone.labels.len and
                    response.header.aa and !hasSignedRecords(response))
                {
                    security_state = self.ensureDelegationSecurity(
                        allocator,
                        target_name,
                        &.{},
                        servers[0..server_count],
                    );
                }

                // Classify response
                if (response.header.rcode != .no_error) {
                    if (response.header.rcode == .name_error and response.header.aa) {
                        switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, target_name, qtype, true, servers[0..server_count])) {
                            .proceed => {
                                if (security_state == .secure) {
                                    response.header.ad = true;
                                    self.storeNsec(response.authorities, parent_zone);
                                }
                                if (self.cache) |c| c.storeNegative(current_name, qtype, .in, .name_error, response.authorities, parent_zone, cacheSecurityStatus(security_state));
                            },
                            .skip_cache => {},
                            .bogus => return self.bogusServfail(current_name, qtype),
                        }
                    }
                    return .{ .message = try withCnameChain(allocator, cname_chain.items, response) };
                }

                if (response.answers.len > 0) {
                    // Follow CNAME if the answer doesn't contain the queried type
                    if (qtype != .cname) {
                        var has_target_type = false;
                        for (response.answers) |rr| {
                            if (rr.rtype == qtype) {
                                has_target_type = true;
                                break;
                            }
                        }

                        if (!has_target_type) {
                            // Validate CNAME RRset before following in secure zones
                            var cname_status: cache_mod.SecurityStatus = .unchecked;
                            if (self.dnssec_enabled and security_state == .secure) {
                                if (dnssec.findRrsig(response.answers, .cname) != null) {
                                    switch (try self.validateAnswer(allocator, &response, .cname, security_state, servers[0..server_count])) {
                                        .bogus => {
                                            if (self.ns_selector) |ns| if (responding_server) |srv|
                                                ns.recordOutcome(parent_zone, srv, .validation_failure, 0);
                                            return self.bogusServfail(current_name, qtype);
                                        },
                                        .valid => {
                                            cname_status = .secure;
                                        },
                                        .skip => {},
                                    }
                                }
                            }
                            if (findCnameRecord(response, target_name)) |cname_rr| {
                                // Store before following CNAME — won't reach final answer validation
                                if (self.cache) |c| c.storeResponseWithStatus(response, parent_zone, cname_status);
                                if (cname_count >= max_cname_chain) return error.CnameChainTooLong;
                                cname_count += 1;
                                try cname_chain.append(allocator, cname_rr);

                                // Same-zone CNAME: keep current auth servers, delegation,
                                // and security_state. The DNSSEC chain of trust is
                                // unchanged within a zone, so re-walking from root would
                                // only redo cache lookups. Skip back to the inner
                                // referral loop with the new target.
                                if (parent_zone.labels.len > 0 and
                                    cname_rr.rdata.cname.isSubdomainOf(parent_zone))
                                {
                                    current_name = try nameToDotted(allocator, cname_rr.rdata.cname);
                                    target_name = try dns.parseDottedName(allocator, current_name);
                                    minimise_label_count = if (self.qname_minimisation)
                                        parent_zone.labels.len + 1
                                    else
                                        target_name.labels.len;
                                    continue;
                                }

                                current_name = try nameToDotted(allocator, cname_rr.rdata.cname);
                                // Re-resolve CNAME target from root with fresh security state.
                                // Preserve .insecure: an unauthenticated CNAME could redirect
                                // anywhere, so the answer must not carry AD (RFC 4035 §3.2.3).
                                if (security_state != .insecure) {
                                    security_state = if (self.dnssec_enabled) .secure else .unchecked;
                                }
                                continue :cname_loop;
                            }
                            // No CNAME found — fall through to final answer validation
                        }
                    }

                    // Validate answer RRsets if in secure zone
                    var answer_status: cache_mod.SecurityStatus = .unchecked;
                    if (self.dnssec_enabled) {
                        switch (try self.validateAnswer(allocator, &response, qtype, security_state, servers[0..server_count])) {
                            .bogus => {
                                if (self.ns_selector) |ns| if (responding_server) |srv|
                                    ns.recordOutcome(parent_zone, srv, .validation_failure, 0);
                                return self.bogusServfail(current_name, qtype);
                            },
                            .valid => {
                                answer_status = .secure;
                            },
                            .skip => {},
                        }
                    }
                    // Don't cache ANY responses: RFC 8482 makes them server-
                    // policy, so unauthenticated constituents would become a
                    // poisoning channel for later per-type lookups.
                    if (self.cache) |c| if (qtype != .any) {
                        c.storeResponseWithStatus(response, parent_zone, answer_status);
                        if (answer_status == .secure and self.nsec_cache != null) {
                            self.storeWildcardRRsets(response.answers, qtype);
                        }
                    };

                    return .{ .message = try withCnameChain(allocator, cname_chain.items, response) };
                }

                // Check for referral (NS records in authority section)
                const referral = extractReferral(response, target_name, parent_zone) orelse {
                    // NODATA: no answers, no referral. Cache only if authoritative.
                    if (response.header.aa) {
                        switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, target_name, qtype, false, servers[0..server_count])) {
                            .proceed => {
                                if (security_state == .secure) {
                                    response.header.ad = true;
                                    self.storeNsec(response.authorities, parent_zone);
                                }
                                if (self.cache) |c| {
                                    c.storeResponse(response, parent_zone);
                                    c.storeNegative(current_name, qtype, .in, .no_error, response.authorities, parent_zone, cacheSecurityStatus(security_state));
                                }
                            },
                            .skip_cache => {},
                            .bogus => return self.bogusServfail(current_name, qtype),
                        }
                    }
                    return .{ .message = try withCnameChain(allocator, cname_chain.items, response) };
                };

                if (self.cache) |c| c.storeResponse(response, parent_zone);
                try self.followReferral(allocator, referral, response.authorities, depth, &security_state, &parent_zone, &servers, &server_count, &seen_zones, &seen_zone_count);
                minimise_label_count = parent_zone.labels.len + 1;
            }

            return error.MaxReferralsExceeded;
        }
    }

    // ── Referral following ──────────────────────────────────────────────

    /// Process a referral: classify DNSSEC delegation, detect loops,
    /// resolve glueless NS if needed, and update iteration state.
    fn followReferral(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        referral: ReferralResult,
        authorities: []const dns.ResourceRecord,
        depth: usize,
        security_state: *dnssec.SecurityStatus,
        parent_zone: *dns.Name,
        servers: *[max_servers_per_level]na.Address,
        server_count: *usize,
        seen_zones: *[max_referrals]dns.Name,
        seen_zone_count: *usize,
    ) !void {
        const zone_cut = switch (referral) {
            .referral => |ref| ref.zone_cut,
            .no_glue => |ng| ng.zone_cut,
        };

        // DNSSEC: classify delegation security (RFC 4035 §5.2)
        if (security_state.* == .secure) {
            security_state.* = self.ensureDelegationSecurity(allocator, zone_cut, authorities, servers.*[0..server_count.*]);
        }

        // Resolve server addresses
        const addrs: NsAddrResult = switch (referral) {
            .referral => |ref| .{ .addrs = ref.addrs, .count = ref.count },
            .no_glue => |ng| blk: {
                if (try self.lookupCachedNsAddresses(allocator, ng.ns_names[0..ng.ns_count])) |res| break :blk res;
                const resolved = try self.resolveNsAddresses(allocator, ng.ns_names[0..ng.ns_count], depth);
                break :blk resolved orelse return error.NoGlueRecords;
            },
        };

        // Loop detection
        for (seen_zones.*[0..seen_zone_count.*]) |sz| {
            if (sz.eql(zone_cut)) return error.ReferralLoop;
        }
        seen_zones.*[seen_zone_count.*] = zone_cut;
        seen_zone_count.* += 1;

        parent_zone.* = zone_cut;
        server_count.* = addrs.count;
        @memcpy(servers.*[0..addrs.count], addrs.addrs[0..addrs.count]);
    }

    // ── Delegation security ────────────────────────────────────────────

    /// Determine delegation security for a zone cut (RFC 4035 §5.2).
    /// Tries verified NSEC/NSEC3 from referral authorities first, then
    /// falls back to cached/fetched DS status from parent servers.
    fn ensureDelegationSecurity(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_cut: dns.Name,
        authorities: []const dns.ResourceRecord,
        parent_servers: []const na.Address,
    ) dnssec.SecurityStatus {
        if (authorities.len > 0) {
            const auth_status = self.verifyAuthoritySigs(allocator, authorities, parent_servers);
            if (auth_status == .secure) {
                const status = dnssec.classifyDelegation(authorities, zone_cut);
                cacheInsecureDelegation(self.keyCache(), status, zone_cut, authorities);
                return status;
            }
            if (auth_status == .bogus) return .secure; // forged NSEC — don't downgrade
        }
        // No verified NSEC — check/fetch DS from parent (RFC 4035 §5.2).
        var zone_buf: [dns.max_name_len + 1]u8 = undefined;
        if (self.reproveDelegationSecurity(allocator, zone_cut.formatInto(&zone_buf), parent_servers) != null)
            return .secure;
        return if (hasCachedInsecureDelegation(self.keyCache(), allocator, zone_cut)) .insecure else .secure;
    }

    /// Try to synthesize a wildcard answer from the main RRset cache.
    /// Returns a synthesized message on success, or null to fall through to upstream.
    fn tryWildcardSynth(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ce_label_count: u8,
        soa: dns.ResourceRecord,
        target_name: dns.Name,
        qtype: dns.RType,
        cname_chain_items: []const dns.ResourceRecord,
    ) !?dns.Message {
        if (ce_label_count == 0 or target_name.labels.len < ce_label_count) return null;
        // Build *.CE from qname labels and format as dotted string for cache lookup
        const ce = dns.Name{ .labels = target_name.labels[target_name.labels.len - ce_label_count ..] };
        var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
        const wc_name = dns.makeWildcardName(&wc_labels_buf, ce) orelse return null;
        var wc_buf: [dns.max_name_len + 1]u8 = undefined;
        const wc_dotted = wc_name.formatInto(&wc_buf);

        const c = self.cache orelse return null;
        const wc_result = c.lookup(allocator, wc_dotted, qtype, .in) orelse return null;
        switch (wc_result) {
            .hit => |h| {
                // Rewrite owner names to the queried name (RFC 4592 §2.2).
                // target_name is arena-allocated and outlives the response — direct assignment.
                for (h.records) |*rr| rr.name = target_name;
                return try withCnameChain(allocator, cname_chain_items, makeCachedMessage(h.records, &.{soa}, .no_error, h.security_status == .secure));
            },
            .negative => return null,
        }
    }

    /// Store validated NSEC records in the aggressive NSEC cache.
    fn storeNsec(self: *RecursiveResolver, authorities: []const dns.ResourceRecord, zone: dns.Name) void {
        if (self.nsec_cache) |nc| {
            nc.storeFromAuthority(authorities, zone);
        }
    }

    /// Detect wildcard expansion in validated answers and store the wildcard RRset
    /// in the main cache under the wildcard name (e.g. *.example.com) for later
    /// synthesis by the NSEC cache (RFC 8198 §5.3).
    fn storeWildcardRRsets(
        self: *RecursiveResolver,
        answers: []const dns.ResourceRecord,
        qtype: dns.RType,
    ) void {
        // Pick the RRSIG covering qtype with the highest `labels` count
        // (narrowest wildcard). A smaller-labels forgery alongside the
        // real RRSIG would otherwise widen the cached wildcard owner —
        // e.g. forge labels=1 against real labels=2 to install *.com.
        // Larger-labels forgeries only narrow scope (DoS on aggressive
        // NSEC at this zone, no poisoning).
        var rrsig: ?dns.RrsigData = null;
        for (answers) |rr| {
            if (rr.rtype != .rrsig or rr.rdata.rrsig.type_covered != qtype) continue;
            if (rrsig == null or rr.rdata.rrsig.labels > rrsig.?.labels) {
                rrsig = rr.rdata.rrsig;
            }
        }
        const sig = rrsig orelse return;

        // Single pass: detect wildcard expansion from the first expanded answer record,
        // then collect all qtype records + covering RRSIGs with wildcard owner name.
        var wc_labels_buf: [dns.max_label_count + 1][]const u8 = undefined;
        var wildcard_owner: ?dns.Name = null;
        var wc_records: [16]dns.ResourceRecord = undefined; // typical wildcard RRsets are 1-3 records; silently caps at 16
        var wc_count: usize = 0;
        for (answers) |ans_rr| {
            if (wc_count >= wc_records.len) break;
            if (wildcard_owner == null and ans_rr.rtype == qtype and ans_rr.name.labels.len > sig.labels) {
                const ce = dns.Name{ .labels = ans_rr.name.labels[ans_rr.name.labels.len - sig.labels ..] };
                wildcard_owner = dns.makeWildcardName(&wc_labels_buf, ce);
            }
            const wco = wildcard_owner orelse continue;
            const dominated = ans_rr.rtype == qtype or
                (ans_rr.rtype == .rrsig and ans_rr.rdata.rrsig.type_covered == qtype);
            if (dominated) {
                wc_records[wc_count] = ans_rr;
                wc_records[wc_count].name = wco;
                wc_count += 1;
            }
        }
        if (wc_count == 0) return;

        const signer_zone = sig.signer_name;
        if (self.cache) |c| {
            c.storeResponseWithStatus(.{
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
                    .an_count = @intCast(wc_count),
                    .ns_count = 0,
                    .ar_count = 0,
                },
                .questions = &.{},
                .answers = wc_records[0..wc_count],
            }, signer_zone, .secure);
        }
    }

    // ── UDP+TCP query helper ──────────────────────────────────────────

    /// Send a UDP query to a single server with TC-bit TCP fallback and RTT tracking.
    /// Returns the parsed response, or null on failure (timeout, parse error, etc.).
    fn queryServerUdp(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        wire_query: []const u8,
        query_id: u16,
        server: na.Address,
        timeout: u32,
    ) error{OutOfMemory}!?dns.Message {
        const addr_key = AddressKey.fromAddress(server);
        const query_start = monotonic.nowUs();

        // Fresh per-hop response_buf in the caller arena: parsed Name/rdata
        // slices alias this buffer, and state such as parent_zone,
        // seen_zones, and cname_chain keeps referring to earlier-hop parse
        // output across loop iterations — each hop needs its own buffer so
        // those slices survive until the arena resets.
        const response_buf = try allocator.alloc(u8, dns.edns_udp_payload);
        const response_data = self.udp().queryWithTimeout(
            wire_query,
            query_id,
            server,
            timeout,
            response_buf,
        ) catch |err| {
            if (self.rtt_cache) |rc| rc.recordTimeout(addr_key);
            if (err != error.Timeout) {
                var addr_buf: [64]u8 = undefined;
                log.debug("UDP query to {s} failed: {s}", .{ na.format(server, &addr_buf), @errorName(err) });
            }
            return null;
        };
        const elapsed_us = monotonic.nowUs() - query_start;

        // Record liveness — truncated responses still prove server is alive
        if (self.rtt_cache) |rc| rc.recordSuccess(addr_key, elapsed_us);

        // RFC 2181 §9: TC-set UDP response must be retried over TCP.
        if (dns.hasTcBit(response_data)) {
            return self.tcpFallback(allocator, wire_query, server);
        }

        const response = try tryParseMessage(allocator, response_data, server) orelse return null;
        if (!response.header.qr) return null;
        return response;
    }

    /// Issue the query over TCP (pooled if available). Returns null if TCP
    /// isn't configured, the request fails, or the response is malformed.
    /// Caller is responsible for question-match validation when needed.
    fn tcpFallback(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        wire_query: []const u8,
        server: na.Address,
    ) error{OutOfMemory}!?dns.Message {
        const tcp_t = self.tcp() orelse return null;
        const tcp_buf = try allocator.alloc(u8, dns.max_message_len);
        const tcp_data = (if (self.tcp_pool) |p|
            tcp_t.queryPooled(wire_query, server, tcp_buf, p)
        else
            tcp_t.query(wire_query, server, tcp_buf)) catch |err| {
            var addr_buf: [64]u8 = undefined;
            log.debug("TCP fallback to {s} failed: {s}", .{ na.format(server, &addr_buf), @errorName(err) });
            return null;
        };
        const response = try tryParseMessage(allocator, tcp_data, server) orelse return null;
        if (!response.header.qr) return null;
        return response;
    }

    // ── Staggered NS Racing ─────────────────────────────────────────────

    const StaggeredResponse = struct {
        message: dns.Message,
        server: na.Address,
    };

    /// Cap on simultaneous staggered legs. Matches typical ns_fetch_limit at
    /// depth 0; must not exceed `BlockingUdpTransport.max_staggered_legs`.
    const max_staggered_legs: usize = 3;

    comptime {
        std.debug.assert(max_staggered_legs <= BlockingUdpTransport.max_staggered_legs);
    }

    fn tryStaggeredQuery(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        query_name: []const u8,
        query_type: dns.RType,
        servers: *[max_servers_per_level]na.Address,
        server_order: []const usize,
        parent_zone: dns.Name,
    ) error{OutOfMemory}!?StaggeredResponse {
        // Collect up to max_staggered_legs distinct-IP non-dead servers in
        // preferred order. Racing duplicate IPs wouldn't add birthday entropy
        // (RFC 5452) or latency diversity, so dedupe by IP.
        var leg_idxs: [max_staggered_legs]usize = undefined;
        var leg_count: usize = 0;
        const now_ms = self.rttNowMs();
        outer: for (server_order) |idx| {
            const addr_key = AddressKey.fromAddress(servers[idx]);
            if (self.rtt_cache) |rc| if (rc.isDead(addr_key, now_ms)) continue;
            for (leg_idxs[0..leg_count]) |prev| {
                if (na.ipEqual(servers[idx], servers[prev])) continue :outer;
            }
            leg_idxs[leg_count] = idx;
            leg_count += 1;
            if (leg_count >= max_staggered_legs) break;
        }
        if (leg_count < 2) return null;

        const stagger = if (self.rtt_cache) |rc|
            rc.getHedgeStagger(AddressKey.fromAddress(servers[leg_idxs[0]]))
        else
            self.stagger_ms;

        const overall_timeout = self.udp().config.timeout_ms;

        // Build leg 0 once, memcpy + patch ID for the rest. One stack buffer
        // per leg because each socket's send holds the wire bytes past the
        // individual call.
        var wires_storage: [max_staggered_legs][dns.edns_udp_payload]u8 = undefined;
        var wires: [max_staggered_legs][]const u8 = undefined;
        var qids: [max_staggered_legs]u16 = undefined;
        var leg_addrs: [max_staggered_legs]na.Address = undefined;

        qids[0] = rand.queryId(self.io);
        const msg0 = dns.buildQueryWithOptions(allocator, qids[0], query_name, query_type, .{
            .rd = false,
            .edns = .{ .do_bit = self.dnssec_aware },
        }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else null;
        const w0 = dns.serializeMessage(&wires_storage[0], msg0) catch |err|
            return if (err == error.OutOfMemory) error.OutOfMemory else null;
        wires[0] = w0;
        leg_addrs[0] = servers[leg_idxs[0]];

        for (1..leg_count) |i| {
            qids[i] = rand.queryId(self.io);
            @memcpy(wires_storage[i][0..w0.len], w0);
            dns.patchQueryId(wires_storage[i][0..w0.len], qids[i]);
            wires[i] = wires_storage[i][0..w0.len];
            leg_addrs[i] = servers[leg_idxs[i]];
        }

        const query_start = monotonic.nowUs();
        const response_buf = try allocator.alloc(u8, dns.edns_udp_payload);
        const stag_result = self.udp().queryStaggered(
            wires[0..leg_count],
            qids[0..leg_count],
            leg_addrs[0..leg_count],
            stagger,
            overall_timeout,
            response_buf,
        ) catch return null;

        const elapsed_us = monotonic.nowUs() - query_start;
        const winner = stag_result.responding_idx;
        const responding_addr = leg_addrs[winner];
        const addr_key = AddressKey.fromAddress(responding_addr);

        if (self.rtt_cache) |rc| rc.recordSuccess(addr_key, elapsed_us);
        if (self.ns_selector) |ns| {
            ns.recordOutcome(parent_zone, responding_addr, .success, elapsed_us);
        }

        // RFC 2181 §9: TC-set response cannot be used. Retry the winning
        // server over TCP immediately; falling through to the sequential loop
        // would re-query servers that already lost the race (wasted UDP RTTs).
        const resp = if (dns.hasTcBit(stag_result.response_data))
            try self.tcpFallback(allocator, wires[winner], responding_addr) orelse return null
        else
            try tryParseMessage(allocator, stag_result.response_data, responding_addr) orelse return null;

        // RFC 5452 §9.1 / RFC 9619: reject responses whose question doesn't echo
        // the query. (The sequential path enforces this via queryAuthoritativeServers.)
        dns.validateResponse(resp, msg0.questions[0].name, query_type) catch return null;

        return .{ .message = resp, .server = responding_addr };
    }

    // ── Authoritative Server Query ────────────────────────────────────

    const ServerQueryResult = struct {
        message: dns.Message,
        responding_server: ?na.Address,
    };

    /// Query authoritative nameservers in selection order, with staggered
    /// racing and opportunistic TLS. Returns the first useful response.
    fn queryAuthoritativeServers(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        query_name: []const u8,
        query_type: dns.RType,
        servers: *[max_servers_per_level]na.Address,
        server_count: usize,
        parent_zone: dns.Name,
    ) anyerror!ServerQueryResult {
        // Order servers: Thompson Sampling if available, Fisher-Yates otherwise
        var order_buf: [max_servers_per_level]usize = undefined;
        const server_order = if (self.ns_selector) |ns|
            ns.selectServers(parent_zone, servers[0..server_count], self.rtt_cache, &order_buf)
        else blk: {
            rand.shuffle(na.Address, self.io, servers[0..server_count]);
            for (0..server_count) |idx| order_buf[idx] = idx;
            break :blk order_buf[0..server_count];
        };

        var last_server_failure: ?dns.Message = null;

        // ── Staggered NS racing ──
        if (server_order.len >= 2 and self.stagger_ms > 0) {
            if (try self.tryStaggeredQuery(allocator, query_name, query_type, servers, server_order, parent_zone)) |stag| {
                self.fireOteProbe(stag.server);
                return .{ .message = stag.message, .responding_server = stag.server };
            }
        }

        const query_msg = try dns.buildQueryWithOptions(allocator, 0, query_name, query_type, .{
            .rd = false,
            .edns = .{ .do_bit = self.dnssec_aware },
        });
        var wire_buf: [dns.edns_udp_payload]u8 = undefined;
        const wire_query = try dns.serializeMessage(&wire_buf, query_msg);

        const now_ms = self.rttNowMs();
        for (server_order, 0..) |server_idx, server_i| {
            const server = servers[server_idx];
            const addr_key = AddressKey.fromAddress(server);

            const is_last_server = (server_i + 1 >= server_order.len);

            // Skip dead servers unless last (fallback when all are dead)
            if (self.rtt_cache) |rc| {
                if (rc.isDead(addr_key, now_ms) and !is_last_server) continue;
            }

            const per_server_timeout = self.serverTimeout(addr_key, is_last_server);

            // RFC 5452: fresh id per attempt.
            const query_id = rand.queryId(self.io);
            dns.patchQueryId(wire_buf[0..wire_query.len], query_id);

            // ── RFC 9539: Opportunistic encrypted query ──
            if (self.transports.tls) |tls_t| {
                if (self.encrypted_ns_cache) |oc| {
                    const tls_key = AddressKey.fromAddressWithPort(server, tls_t.config.port);
                    switch (oc.getStatus(tls_key)) {
                        .capable => {
                            // Known-good server → try encrypted (pool or new connection)
                            const padded_msg = try dns.buildQueryWithOptions(allocator, query_id, query_name, query_type, .{
                                .rd = false,
                                .edns = .{ .do_bit = self.dnssec_aware, .padding_target = dns.dot_padding_target },
                            });
                            var padded_buf: [dns.edns_udp_payload]u8 = undefined;
                            const padded_query = try dns.serializeMessage(&padded_buf, padded_msg);

                            const tls_response_buf = try allocator.alloc(u8, dns.max_message_len);
                            const ote_deadline_ns = monotonic.nowNs() + 4000 * std.time.ns_per_ms;
                            if (tls_t.queryOpportunistic(padded_query, server, tls_response_buf, ote_deadline_ns)) |tls_data| {
                                if (try tryParseMessage(allocator, tls_data, server)) |tls_response| {
                                    if (tls_response.header.qr and
                                        tls_response.header.rcode != .format_error and
                                        dns.validateQuestionMatch(tls_response, query_msg.questions[0].name, query_type))
                                    {
                                        if (tls_response.header.rcode.isServerError()) {
                                            last_server_failure = tls_response;
                                            continue; // Try next server, don't repeat over Do53
                                        }
                                        // Don't update RTT cache or NS selector from TLS —
                                        // different transport latency would poison Do53 estimates.
                                        return .{ .message = tls_response, .responding_server = null };
                                    }
                                }
                                // TLS error/unparseable — fall through to Do53
                            } else |_| {
                                oc.markFailed(tls_key);
                            }
                        },
                        .unknown => {}, // First contact → Do53 now, probe after
                        .probing, .failed => {}, // Skip, go straight to Do53
                    }
                }
            }

            // ── Do53: UDP with TCP fallback ──
            const do53_start = monotonic.nowUs();
            const response = try self.queryServerUdp(
                allocator,
                wire_query,
                query_id,
                server,
                per_server_timeout,
            ) orelse {
                if (self.ns_selector) |ns|
                    ns.recordOutcome(parent_zone, server, .timeout, 0);
                continue;
            };
            const do53_elapsed = monotonic.nowUs() - do53_start;

            // RFC 5452 §9.1 / RFC 9619: question must match; error rcodes exempt.
            dns.validateResponse(response, query_msg.questions[0].name, query_type) catch continue;

            // Lame detection (RFC 4697): SERVFAIL/REFUSED → try next server.
            // Per-query only; no persistent penalty (RFC 4697 requires per-zone+IP keying).
            if (response.header.rcode.isServerError()) {
                if (self.ns_selector) |ns|
                    ns.recordOutcome(parent_zone, server, .server_error, do53_elapsed);
                last_server_failure = response;
                continue;
            }

            if (self.ns_selector) |ns|
                ns.recordOutcome(parent_zone, server, .success, do53_elapsed);
            self.fireOteProbe(server);
            return .{ .message = response, .responding_server = server };
        }

        // Fall back to last SERVFAIL/REFUSED if all servers failed
        if (last_server_failure) |sf| {
            return .{ .message = sf, .responding_server = null };
        }
        return error.Timeout;
    }

    fn fireOteProbe(self: *RecursiveResolver, server: na.Address) void {
        const oc = self.encrypted_ns_cache orelse return;
        const tls_t = self.transports.tls orelse return;
        const tls_key = AddressKey.fromAddressWithPort(server, tls_t.config.port);
        if (oc.claimProbe(tls_key)) {
            tls_t.probeInBackground(server, oc);
        }
    }

    // ── DNSSEC Answer Validation ───────────────────────────────────────

    /// RFC 9520 §3.2: minimum negative-cache TTL for DNSSEC validation failures.
    const dnssec_bogus_ttl: u32 = 1;

    /// Dedup follower timeout for DNSKEY fetches. Cold-cache DNSSEC chains
    /// (root → TLD → SLD → DNSKEY) can take 3-5s; 6s provides headroom.
    const dnskey_dedup_timeout_ns: u64 = 6 * std.time.ns_per_s;

    /// Dedup follower timeout for DS fetches. DS queries go to already-known
    /// parent servers (no chain walk), so 3s is sufficient.
    const ds_dedup_timeout_ns: u64 = 3 * std.time.ns_per_s;

    const AnswerValidation = enum { valid, bogus, skip };

    /// RFC 9520 §3.4: MUST cache DNSSEC validation failures.
    /// Caches a SERVFAIL with dnssec_bogus_ttl and returns SERVFAIL to the client.
    fn bogusServfail(self: *RecursiveResolver, name: []const u8, qtype: dns.RType) ResolveResult {
        if (self.cache) |c| c.storeNegativeBare(name, qtype, .in, .server_failure, dnssec_bogus_ttl, .unchecked);
        return .{ .message = makeCachedMessage(&.{}, &.{}, .server_failure, false) };
    }

    /// Fetch DNSKEY records for a zone, checking cache first.
    /// Uses the dedup table to coalesce concurrent DNSKEY fetches for the
    /// same zone — prevents N parallel queries from each firing their own
    /// DNSKEY network request on cold cache.
    fn fetchDnskey(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        servers: []const na.Address,
    ) !?[]const dns.ResourceRecord {
        const kc = self.keyCache();

        // Fast path: cache hit — no dedup needed.
        if (kc) |c| {
            if (c.lookup(allocator, zone_name, .dnskey, .in)) |result| {
                switch (result) {
                    .hit => |h| {
                        // Signal near-expiry DNSKEY for async refresh after responding.
                        if (h.needs_prefetch and self.pending_dnskey_prefetch == null) {
                            @memcpy(self.pending_dnskey_buf[0..zone_name.len], zone_name);
                            self.pending_dnskey_prefetch = self.pending_dnskey_buf[0..zone_name.len];
                        }
                        return h.records;
                    },
                    .negative => return null,
                }
            }
        }

        // Dedup: coalesce concurrent DNSKEY fetches for the same zone.
        if (self.dedup) |dedup| {
            switch (dedup.acquireOrWaitWithTimeout(zone_name, .dnskey, 0, monotonic.nowNs() + dnskey_dedup_timeout_ns)) {
                .leader => {
                    // We're the leader — do the actual fetch, then release.
                    defer dedup.releaseLeader(zone_name, .dnskey, 0);
                    return self.fetchAndValidateDnskey(allocator, zone_name, servers);
                },
                .follower => {
                    // Leader finished (or timed out). Re-check cache — leader
                    // should have populated it on success.
                    if (kc) |c| {
                        if (c.lookup(allocator, zone_name, .dnskey, .in)) |result| {
                            switch (result) {
                                .hit => |h| return h.records,
                                .negative => return null,
                            }
                        }
                    }
                    // Cache still empty — leader failed. Re-acquire dedup so only
                    // one follower retries (prevents thundering herd). Shorter
                    // timeout: leader's partial work warmed intermediate caches.
                    switch (dedup.acquireOrWaitWithTimeout(zone_name, .dnskey, 0, monotonic.nowNs() + dnskey_dedup_timeout_ns / 2)) {
                        .leader => {
                            defer dedup.releaseLeader(zone_name, .dnskey, 0);
                            return self.fetchAndValidateDnskey(allocator, zone_name, servers);
                        },
                        .follower => {
                            // Another follower is already retrying — check cache once more.
                            if (kc) |c| {
                                if (c.lookup(allocator, zone_name, .dnskey, .in)) |result| {
                                    switch (result) {
                                        .hit => |h| return h.records,
                                        .negative => return null,
                                    }
                                }
                            }
                            return null;
                        },
                    }
                },
            }
        }

        // No dedup table (single-threaded mode) — fetch directly.
        return self.fetchAndValidateDnskey(allocator, zone_name, servers);
    }

    /// Fetch DNSKEY from network, validate against cached DS (RFC 4035 §5.3),
    /// and only cache after validation passes.
    fn fetchAndValidateDnskey(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        servers: []const na.Address,
    ) !?[]const dns.ResourceRecord {
        // Network fetch — don't cache yet (RFC 4035 §5.3: validate first)
        const resp = try self.fetchRRset(allocator, zone_name, .dnskey, servers, 3, true, false) orelse return null;
        if (resp.answers.len == 0) return null;

        const zone_parsed = try dns.parseDottedName(allocator, zone_name);

        // Validate DNSKEY against cached DS before caching (RFC 4035 §5.2)
        const kc = self.keyCache();
        if (kc) |c| {
            if (c.lookup(allocator, zone_name, .ds, .in)) |result| {
                switch (result) {
                    .hit => |h| {
                        validateDnskeyAgainstDs(resp.answers, h.records, zone_parsed, &self.validation_budget) catch return null;
                    },
                    .negative => {}, // Insecure delegation — no DS validation needed
                }
            } else if (zone_name.len > 0) {
                // DS not in cache. Re-fetch from parent and validate against the
                // freshly fetched records — RFC 1035 §3.2.1 permits using TTL=0
                // RRs "for the transaction in progress" even though they will
                // not be retained in the cache. The negative-DS cache (with
                // NSEC TTL, not the suppressed DS TTL) still distinguishes
                // insecure delegations from outright failures.
                if (self.fetchDsFromParent(allocator, zone_name)) |ds_records| {
                    validateDnskeyAgainstDs(resp.answers, ds_records, zone_parsed, &self.validation_budget) catch return null;
                } else if (c.lookup(allocator, zone_name, .ds, .in)) |result| {
                    switch (result) {
                        .negative => {}, // insecure delegation proven during fetch
                        .hit => |h| validateDnskeyAgainstDs(resp.answers, h.records, zone_parsed, &self.validation_budget) catch return null,
                    }
                } else return null;
            } else {
                // Root zone: validate against hardcoded trust anchor
                const now_u32 = epochNowU32();
                dnssec.validateDnskeyRrset(resp.answers, &dnssec.root_ds_records, zone_parsed, now_u32, &self.validation_budget) catch return null;
            }
        }

        // RFC 4035 §5.3: "the validator SHOULD cache the RRset" — after validation.
        // Store only answers to avoid polluting the key cache with NS/glue.
        if (kc) |c| c.storeResponseWithStatus(answersOnly(resp), zone_parsed, .unchecked);

        return resp.answers;
    }

    /// Query authoritative servers for a specific RRset, with RTT tracking
    /// and dead-server skipping.  Returns the full message so callers that
    /// need the authority section (e.g. DS probes) can use it.
    fn fetchRRset(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        qtype: dns.RType,
        servers: []const na.Address,
        max_servers: usize,
        do_bit: bool,
        store_response: bool,
    ) !?dns.Message {
        if (servers.len == 0) return null;

        const authority_zone = try dns.parseDottedName(allocator, zone_name);

        const try_count = @min(servers.len, max_servers);
        const now_ms = self.rttNowMs();
        for (servers[0..try_count], 0..) |server, i| {
            const addr_key = AddressKey.fromAddress(server);

            if (self.rtt_cache) |rc| {
                if (rc.isDead(addr_key, now_ms) and i + 1 < try_count) continue;
            }

            // Fresh TXID per server to prevent cross-server ID prediction.
            const query_id = rand.queryId(self.io);
            const query_msg = try dns.buildQueryWithOptions(allocator, query_id, zone_name, qtype, .{
                .rd = false,
                .edns = .{ .do_bit = do_bit },
            });

            var wire_buf: [dns.edns_udp_payload]u8 = undefined;
            const wire_query = dns.serializeMessage(&wire_buf, query_msg) catch return null;

            const timeout = self.serverTimeout(addr_key, i + 1 >= try_count);

            const response = try self.queryServerUdp(
                allocator,
                wire_query,
                query_id,
                server,
                timeout,
            ) orelse continue;
            // RFC 5452 §9.1: question section must match original query
            if (!dns.validateQuestionMatch(response, query_msg.questions[0].name, qtype)) continue;
            if (response.header.rcode != .no_error) continue;
            if (store_response) {
                if (self.cache) |c| c.storeResponse(response, authority_zone);
            }
            return response;
        }
        return null;
    }

    /// Re-fetch DS for a zone by finding the parent zone's NS in cache
    /// and querying them. Falls back to resolving NS addresses from the
    /// network when cached addresses have expired (simultaneous DS+DNSKEY
    /// TTL expiry). Returns the DS records on signed delegation, null on
    /// insecure (negative cached) or failure.
    fn fetchDsFromParent(self: *RecursiveResolver, allocator: mem.Allocator, zone_name: []const u8) ?[]const dns.ResourceRecord {
        if (self.resolving_ds) return null; // re-entrancy guard

        // Derive parent zone: strip first label (e.g. "example.com" → "com")
        // TLDs have no dot — parent is root, query root hints (RFC 4035 §3.1.4.1).
        const pos = mem.indexOfScalar(u8, zone_name, '.') orelse
            return self.reproveDelegationSecurity(allocator, zone_name, &root_hints);
        if (pos + 1 >= zone_name.len) // trailing dot (e.g. "com.")
            return self.reproveDelegationSecurity(allocator, zone_name, &root_hints);
        const parent_zone = zone_name[pos + 1 ..];

        const cache = self.cache orelse return null;
        const ns_hit = switch (cache.lookup(allocator, parent_zone, .ns, .in) orelse return null) {
            .hit => |h| h,
            .negative => return null,
        };
        var ns_names: [max_servers_per_level]dns.Name = undefined;
        var ns_count: usize = 0;
        for (ns_hit.records) |rr| {
            if (rr.rtype == .ns and ns_count < max_servers_per_level) {
                ns_names[ns_count] = rr.rdata.ns;
                ns_count += 1;
            }
        }
        // Try cached addresses first; fall back to network resolution when
        // addresses have expired alongside DS/DNSKEY (common with equal TTLs).
        const addrs = (self.lookupCachedNsAddresses(allocator, ns_names[0..ns_count]) catch null) orelse blk: {
            self.resolving_ds = true;
            defer self.resolving_ds = false;
            break :blk (self.resolveNsAddresses(allocator, ns_names[0..ns_count], 1) catch null) orelse return null;
        };
        return self.reproveDelegationSecurity(allocator, zone_name, addrs.addrs[0..addrs.count]);
    }

    /// Refresh expired DS status by querying parent servers directly. Uses
    /// dedup to coalesce concurrent fetches. Returns the fresh DS records
    /// (slice lives on `allocator`, the per-query arena) when the zone is
    /// signed; null when the delegation is proven insecure (negative DS
    /// cached) or when the fetch failed. The records themselves are not
    /// cached if their TTL is 0 (RFC 1035 §3.2.1) — callers therefore use
    /// the returned slice in-flight rather than relying on a cache lookup.
    fn reproveDelegationSecurity(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        parent_servers: []const na.Address,
    ) ?[]const dns.ResourceRecord {
        const kc = self.keyCache();

        // Fast path: DS already in cache (another thread may have fetched it).
        if (kc) |c| {
            if (c.lookup(allocator, zone_name, .ds, .in)) |result| return switch (result) {
                .hit => |h| h.records,
                .negative => null,
            };
        }

        // Dedup: coalesce concurrent DS fetches for the same zone.
        if (self.dedup) |dedup| {
            switch (dedup.acquireOrWaitWithTimeout(zone_name, .ds, 0, monotonic.nowNs() + ds_dedup_timeout_ns)) {
                .leader => {
                    defer dedup.releaseLeader(zone_name, .ds, 0);
                    return self.reproveDelegationSecurityImpl(allocator, zone_name, parent_servers);
                },
                .follower => {
                    // Leader finished — re-check cache.
                    if (kc) |c| {
                        if (c.lookup(allocator, zone_name, .ds, .in)) |result| return switch (result) {
                            .hit => |h| h.records,
                            .negative => null,
                        };
                    }
                    // Cache still empty — leader failed (or TTL=0 DS that the
                    // cache silently drops). One follower retries.
                    switch (dedup.acquireOrWaitWithTimeout(zone_name, .ds, 0, monotonic.nowNs() + ds_dedup_timeout_ns / 2)) {
                        .leader => {
                            defer dedup.releaseLeader(zone_name, .ds, 0);
                            return self.reproveDelegationSecurityImpl(allocator, zone_name, parent_servers);
                        },
                        .follower => {
                            if (kc) |c| {
                                if (c.lookup(allocator, zone_name, .ds, .in)) |result| return switch (result) {
                                    .hit => |h| h.records,
                                    .negative => null,
                                };
                            }
                            return null;
                        },
                    }
                },
            }
        }

        return self.reproveDelegationSecurityImpl(allocator, zone_name, parent_servers);
    }

    fn reproveDelegationSecurityImpl(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        parent_servers: []const na.Address,
    ) ?[]const dns.ResourceRecord {
        const response = (self.fetchRRset(allocator, zone_name, .ds, parent_servers, 2, self.dnssec_aware, false) catch return null) orelse return null;
        const zone = dns.parseDottedName(allocator, zone_name) catch return null;

        // Cache DS response: main cache for NS/glue (skip_key_types skips DS),
        // key cache for DS only (avoid polluting with NS/glue). Stores no-op
        // when the response carries TTL=0 — the returned slice keeps the
        // records alive for the in-flight transaction (RFC 1035 §3.2.1).
        if (self.cache) |c| c.storeResponse(response, zone);
        // DS stored as .unchecked — validated indirectly via DNSKEY RRSIG.
        if (self.key_cache) |kc| kc.storeResponseWithStatus(answersOnly(response), zone, .unchecked);

        // Positive DS — zone is signed. Return the section that holds the DS
        // records; validateDnskeyAgainstDs filters by rtype, so RRSIGs and
        // glue ride along harmlessly.
        for (response.answers) |rr| {
            if (rr.rtype == .ds) return response.answers;
        }
        for (response.authorities) |rr| {
            if (rr.rtype == .ds) return response.authorities;
        }

        // No DS — verify NSEC/NSEC3 proof and cache insecure delegation. The
        // negative-DS entry uses NSEC TTLs (not the DS's TTL=0), so callers
        // that fall back to the cache after a null return can still
        // distinguish insecure from outright failure.
        const auth_status = self.verifyAuthoritySigs(allocator, response.authorities, parent_servers);
        if (auth_status == .secure) {
            const status = dnssec.classifyDelegation(response.authorities, zone);
            if (status == .insecure) {
                cacheInsecureDelegation(self.keyCache(), status, zone, response.authorities);
            }
        }
        return null;
    }

    /// Validate answer RRsets for a response from a secure zone.
    /// Returns .valid (AD bit set), .bogus (should SERVFAIL), or .skip (insecure zone).
    fn validateAnswer(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        response: *dns.Message,
        qtype: dns.RType,
        security_state: dnssec.SecurityStatus,
        servers: []const na.Address,
    ) !AnswerValidation {
        if (security_state != .secure) return .skip;

        // RFC 8482: ANY responses are server-policy and have no single
        // type_covered RRSIG; treat as unauthenticated rather than bogus.
        if (qtype == .any) return .skip;

        const now_u32 = epochNowU32();

        // Find RRSIG in answers to get the signer zone
        const rrsig = dnssec.findRrsig(response.answers, qtype) orelse return .bogus;

        // RFC 4034 §3.1.3: signer must be at or above the RRset owner name
        for (response.answers) |rr| if (rr.rtype == qtype) {
            if (!rr.name.isSubdomainOf(rrsig.signer_name)) return .bogus;
            break;
        };

        // Extract signer zone name as dotted string
        const signer_dotted = try nameToDotted(allocator, rrsig.signer_name);

        // Fetch DNSKEY for the signer zone (validated against DS before caching — RFC 4035 §5.3)
        const dnskey_records = (try self.fetchDnskey(allocator, signer_dotted, servers)) orelse return .bogus;

        // Validate the answer RRsets
        return switch (dnssec.validateAnswerRrset(response.answers, qtype, dnskey_records, now_u32, &self.validation_budget)) {
            .secure => {
                response.header.ad = true;
                return .valid;
            },
            .bogus => .bogus,
            .unchecked, .insecure => .skip,
        };
    }

    /// Verify RRSIG signatures over NSEC/NSEC3 records in authorities.
    /// Fetches DNSKEY from cache or network (per RFC 4035 §5.2: signatures
    /// must be authenticated before accepting NSEC proofs).
    fn verifyAuthoritySigs(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        authorities: []const dns.ResourceRecord,
        parent_servers: []const na.Address,
    ) dnssec.SecurityStatus {
        // Find RRSIG signer_name in authorities
        var signer_name: ?dns.Name = null;
        for (authorities) |rr| {
            if (rr.rtype == .rrsig) {
                signer_name = rr.rdata.rrsig.signer_name;
                break;
            }
        }
        const signer = signer_name orelse return .unchecked;

        // RFC 4034 §3.1.3: verify authority record owners are under the signer zone
        for (authorities) |rr| if (rr.rtype == .nsec or rr.rtype == .nsec3) {
            if (!rr.name.isSubdomainOf(signer)) return .unchecked;
        };

        // Fetch DNSKEY from cache or parent servers
        const signer_dotted = nameToDotted(allocator, signer) catch return .unchecked;
        const dnskey_records = (self.fetchDnskey(allocator, signer_dotted, parent_servers) catch return .unchecked) orelse return .unchecked;

        const now_u32 = epochNowU32();
        return dnssec.verifyAuthorityNsecSigs(authorities, dnskey_records, now_u32, &self.validation_budget);
    }

    /// Verify authority NSEC/NSEC3 signatures, then validate the negative proof.
    fn verifiedNegativeResponse(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        security_state: dnssec.SecurityStatus,
        authorities: []const dns.ResourceRecord,
        qname: dns.Name,
        qtype: dns.RType,
        is_nxdomain: bool,
        zone_servers: []const na.Address,
    ) NegativeValidation {
        if (security_state != .secure) return .proceed;

        const auth_status = self.verifyAuthoritySigs(allocator, authorities, zone_servers);
        if (auth_status == .bogus) return .bogus;
        if (auth_status != .secure) return .skip_cache;

        return validateNegativeResponse(security_state, authorities, qname, qtype, is_nxdomain);
    }

    fn resolveNsAddresses(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
        depth: usize,
    ) !?NsAddrResult {
        if (depth >= max_resolve_depth) return null;

        // Fetch policy (Unbound-style): resolve more NS names at shallow depths
        // to warm cache for sibling queries. At least 1 at all depths.
        const ns_fetch_limit: usize = switch (depth) {
            0 => 3,
            1 => 2,
            else => 1,
        };

        // Parallel path: one helper thread per (ns_name × rtype) task beyond
        // the caller's. Bounded by ns_fetch_limit so the worst-case fanout is
        // `ns_fetch_limit * 2 - 1` helpers (5 at depth 0).
        if (self.gpa != null and ns_names.len >= 1) {
            return self.resolveNsAddressesFanout(allocator, ns_names, depth, ns_fetch_limit);
        }

        return self.resolveNsAddressesSerial(allocator, ns_names, depth, ns_fetch_limit);
    }

    const address_rtypes = [_]dns.RType{ .a, .aaaa };
    /// Largest ns_fetch_limit used by resolveNsAddresses (depth 0). Bounds the
    /// stack-allocated task-context array in resolveNsAddressesFanout.
    const max_ns_fetch_limit: usize = 3;
    const max_ns_parallel_tasks: usize = max_ns_fetch_limit * address_rtypes.len;

    /// Append A+AAAA addresses from `records` to `addrs`, skipping non-routable.
    /// Returns true if at least one address was appended.
    fn appendAddressesFromRecords(
        records: []const dns.ResourceRecord,
        addrs: *[max_servers_per_level]na.Address,
        count: *usize,
    ) bool {
        var added = false;
        for (records) |rr| {
            if (count.* >= max_servers_per_level) break;
            const addr: na.Address = switch (rr.rtype) {
                .a => na.initIp4(rr.rdata.a, 53),
                .aaaa => na.initIp6(rr.rdata.aaaa, 53, 0, 0),
                else => continue,
            };
            if (na.isNonRoutableNs(addr)) continue;
            addrs[count.*] = addr;
            count.* += 1;
            added = true;
        }
        return added;
    }

    const ns_addr_dedup_timeout_ns: u64 = 2 * std.time.ns_per_s;

    /// Resolve one (ns_name, rtype) pair and append any resulting addresses
    /// to `addrs[count..]`. Non-OOM resolution failures are swallowed.
    /// Wrapped in dedup so concurrent recursions hitting the same NS collapse;
    /// bounded timeout prevents follower-deadlock under cross-NS dependencies.
    fn resolveNsNameOne(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_dotted: []const u8,
        rtype: dns.RType,
        depth: usize,
        addrs: *[max_servers_per_level]na.Address,
        count: *usize,
    ) error{OutOfMemory}!void {
        const leader = if (self.dedup) |dedup|
            dedup.acquireOrWaitWithTimeout(ns_dotted, rtype, 0, monotonic.nowNs() + ns_addr_dedup_timeout_ns) == .leader
        else
            false;
        defer if (leader) self.dedup.?.releaseLeader(ns_dotted, rtype, 0);

        if (self.resolveImpl(allocator, ns_dotted, rtype, depth + 1)) |r| {
            _ = appendAddressesFromRecords(r.message.answers, addrs, count);
        } else |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
        }
    }

    /// Resolve A + AAAA for a single NS name serially.
    fn resolveNsName(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_name: dns.Name,
        depth: usize,
        addrs: *[max_servers_per_level]na.Address,
        count: *usize,
    ) error{OutOfMemory}!bool {
        const ns_dotted = try nameToDotted(allocator, ns_name);
        const before = count.*;
        for (address_rtypes) |qtype| {
            try self.resolveNsNameOne(allocator, ns_dotted, qtype, depth, addrs, count);
        }
        return count.* > before;
    }

    fn resolveNsAddressesSerial(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
        depth: usize,
        ns_fetch_limit: usize,
    ) !?NsAddrResult {
        var addrs: [max_servers_per_level]na.Address = undefined;
        var count: usize = 0;
        var resolved_ns_count: usize = 0;

        for (ns_names) |ns_name| {
            if (try self.resolveNsName(allocator, ns_name, depth, &addrs, &count)) {
                resolved_ns_count += 1;
                if (resolved_ns_count >= ns_fetch_limit) break;
            }
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    /// Fan out NS-address resolution across one thread per (ns_name × rtype)
    /// task. Task 0 (NS[0], A) runs on the caller thread; tasks 1..N run on
    /// helper threads so A and AAAA for each NS name execute in parallel. If
    /// a spawn fails, the task falls back to the caller thread after the
    /// helpers join — correctness is preserved, latency reverts to serial.
    fn resolveNsAddressesFanout(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
        depth: usize,
        ns_fetch_limit: usize,
    ) !?NsAddrResult {
        const rtypes_n = address_rtypes.len;
        const names_n = @min(ns_names.len, ns_fetch_limit);
        if (names_n == 0) return null;
        const task_n = names_n * rtypes_n;
        std.debug.assert(task_n <= max_ns_parallel_tasks);

        // Precompute dotted names once per NS name; the two rtype tasks for
        // each name share the string. Safe to share across helpers because
        // the caller-arena outlives the join.
        var dotted_names: [max_ns_fetch_limit][]const u8 = undefined;
        for (0..names_n) |ni| {
            dotted_names[ni] = try nameToDotted(allocator, ns_names[ni]);
        }

        // One shared CountingAllocator caps the helpers' combined memory at
        // query_memory_limit. Without sharing, each helper had its own cap and
        // a single user query could allocate task_n × limit.
        var helpers_cap = CountingAllocator.init(self.gpa.?, self.query_memory_limit);

        var task_ctxs: [max_ns_parallel_tasks]NsTaskCtx = undefined;
        var threads: [max_ns_parallel_tasks]?std.Thread = @splat(null);

        // Spawn helpers for tasks [1..task_n]. Task 0 runs on the caller.
        // `threads[i] == null` after this loop means spawn failed — the task
        // is handled synchronously in the fallback loop below.
        for (1..task_n) |i| {
            const ni = i / rtypes_n;
            const ri = i % rtypes_n;
            task_ctxs[i] = .{
                .parent = self,
                .ns_dotted = dotted_names[ni],
                .rtype = address_rtypes[ri],
                .depth = depth,
                .shared_cap = &helpers_cap,
            };
            threads[i] = std.Thread.spawn(.{ .stack_size = 1 << 20 }, NsTaskCtx.run, .{&task_ctxs[i]}) catch null;
        }
        // Guarantee helper join before task_ctxs go out of scope, including
        // error-return paths below.
        defer for (&threads) |*slot| {
            if (slot.*) |t| {
                t.join();
                slot.* = null;
            }
        };

        var addrs: [max_servers_per_level]na.Address = undefined;
        var count: usize = 0;

        // Task 0 = (NS[0], A) on caller thread.
        try self.resolveNsNameOne(allocator, dotted_names[0], address_rtypes[0], depth, &addrs, &count);

        // Thread-spawn fallbacks: run the task on the caller so we don't drop
        // it. Reserved for fork/resource-limit conditions.
        for (1..task_n) |i| {
            if (threads[i] != null) continue;
            const ni = i / rtypes_n;
            const ri = i % rtypes_n;
            try self.resolveNsNameOne(allocator, dotted_names[ni], address_rtypes[ri], depth, &addrs, &count);
        }

        // Join helpers and merge their addresses. Null each slot after the
        // join so the deferred cleanup loop at the top doesn't double-join.
        for (1..task_n) |i| {
            const t = threads[i] orelse continue;
            t.join();
            threads[i] = null;
            if (task_ctxs[i].oom) return error.OutOfMemory;
            const hc = task_ctxs[i].count;
            if (hc == 0) continue;
            const space = max_servers_per_level - count;
            const to_copy = @min(hc, space);
            @memcpy(addrs[count..][0..to_copy], task_ctxs[i].addrs[0..to_copy]);
            count += to_copy;
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    /// Context for a helper thread resolving one (ns_dotted, rtype) pair.
    /// `ns_dotted` references the caller arena; safe because
    /// `resolveNsAddressesFanout` joins all helpers before returning. The
    /// parent pointer is read once at start to clone shared state (caches,
    /// selectors) into a thread-local resolver; config is stable after init.
    const NsTaskCtx = struct {
        parent: *RecursiveResolver,
        ns_dotted: []const u8,
        rtype: dns.RType,
        depth: usize,
        shared_cap: *CountingAllocator,
        addrs: [max_servers_per_level]na.Address = undefined,
        count: usize = 0,
        oom: bool = false,

        fn run(ctx: *NsTaskCtx) void {
            var udp_t = BlockingUdpTransport.init(.{}, ctx.parent.io);
            defer udp_t.deinit();
            var tcp_t = BlockingTcpTransport.init(.{});
            var resolver = ctx.parent.cloneForThread(.{
                .do53 = .{ .blocking = .{ .udp = &udp_t, .tcp = &tcp_t } },
                .tls = ctx.parent.transports.tls,
            });

            var arena = std.heap.ArenaAllocator.init(ctx.shared_cap.allocator());
            defer arena.deinit();

            resolver.resolveNsNameOne(
                arena.allocator(),
                ctx.ns_dotted,
                ctx.rtype,
                ctx.depth,
                &ctx.addrs,
                &ctx.count,
            ) catch {
                ctx.oom = true;
            };
        }
    };

    const NsAddrResult = struct { addrs: [max_servers_per_level]na.Address, count: usize };
    const DelegationResult = struct { addrs: [max_servers_per_level]na.Address, count: usize, zone: dns.Name };

    /// Check cache for A/AAAA records of NS names, avoiding network queries.
    /// Collects addresses from all cached NS names (cache lookups are free)
    /// for better server diversity.
    fn lookupCachedNsAddresses(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
    ) !?NsAddrResult {
        const cache = self.cache orelse return null;

        var addrs: [max_servers_per_level]na.Address = undefined;
        var count: usize = 0;

        for (ns_names) |ns_name| {
            const ns_dotted = try nameToDotted(allocator, ns_name);
            for (address_rtypes) |qtype| {
                if (cache.lookup(allocator, ns_dotted, qtype, .in)) |result| {
                    switch (result) {
                        .hit => |h| _ = appendAddressesFromRecords(h.records, &addrs, &count),
                        .negative => {},
                    }
                }
            }
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    /// Walk the domain name from TLD to find the closest cached delegation.
    /// E.g., for "www.example.com", check NS records for "com" then "example.com".
    pub fn findClosestCachedDelegation(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        target_name: []const u8,
    ) !?DelegationResult {
        const cache = self.cache orelse return null;

        // Split into labels
        var parts: [128][]const u8 = undefined;
        var part_count: usize = 0;
        var iter = mem.splitScalar(u8, target_name, '.');
        while (iter.next()) |part| {
            if (part.len == 0) continue;
            if (part_count >= 128) break;
            parts[part_count] = part;
            part_count += 1;
        }
        if (part_count == 0) return null;

        // Walk from TLD toward full name, looking for cached NS + addresses.
        // Intermediate NS/glue clones live in a scratch arena that is reset
        // each iteration, so losing levels do not accumulate in the caller's
        // arena. A miss after a prior hit terminates the walk: referral
        // caching is populated top-down, so no deeper level can exist.
        var scratch_arena = std.heap.ArenaAllocator.init(allocator);
        defer scratch_arena.deinit();

        var best: ?DelegationResult = null;
        var had_ns_hit = false;

        var i: usize = part_count;
        while (i > 0) {
            i -= 1;
            // Build zone name string from parts[i..part_count]
            var zone_buf: [dns.max_name_len + 1]u8 = undefined;
            var pos: usize = 0;
            for (parts[i..part_count]) |p| {
                if (pos > 0) {
                    zone_buf[pos] = '.';
                    pos += 1;
                }
                if (pos + p.len > dns.max_name_len) break;
                @memcpy(zone_buf[pos..][0..p.len], p);
                pos += p.len;
            }
            const zone_str = zone_buf[0..pos];

            _ = scratch_arena.reset(.retain_capacity);
            const scratch = scratch_arena.allocator();

            const ns_lookup = cache.lookup(scratch, zone_str, .ns, .in) orelse {
                if (had_ns_hit) break;
                continue;
            };
            const hit = switch (ns_lookup) {
                .hit => |h| h,
                .negative => continue,
            };
            had_ns_hit = true;

            var ns_names: [max_servers_per_level]dns.Name = undefined;
            var ns_count: usize = 0;
            for (hit.records) |ns_rr| {
                if (ns_rr.rtype == .ns and ns_count < max_servers_per_level) {
                    ns_names[ns_count] = ns_rr.rdata.ns;
                    ns_count += 1;
                }
            }

            const res = (try self.lookupCachedNsAddresses(scratch, ns_names[0..ns_count])) orelse continue;

            // DNSSEC: only use this delegation if DS status is known.
            // If DS is a cache miss, another thread may not have cached
            // the insecure delegation yet. Try a targeted DS re-probe
            // using the parent delegation's servers (like Unbound's key
            // cache refresh) before falling back to referral re-walk.
            if (self.dnssec_enabled) {
                const ds_cache = self.keyCache() orelse break;
                if (!ds_cache.lookupExists(zone_str, .ds, .in)) {
                    const records = if (best) |parent_deleg|
                        self.reproveDelegationSecurity(
                            allocator,
                            zone_str,
                            parent_deleg.addrs[0..parent_deleg.count],
                        )
                    else
                        null;
                    // Records non-null = signed (may not be cached if TTL=0,
                    // but DS status is known). Null + cache hit (negative)
                    // = insecure. Null + cache miss = unknown, give up.
                    if (records == null and !ds_cache.lookupExists(zone_str, .ds, .in)) break;
                }
            }

            // Zone name must live on the caller's arena: `best` outlives
            // the scratch reset. Addresses are plain `na.Address` values.
            const zone_name = try dns.parseDottedName(allocator, zone_str);
            best = .{
                .addrs = res.addrs,
                .count = res.count,
                .zone = zone_name,
            };
        }

        return best;
    }
};

// ── Insecure delegation caching ───────────────────────────────────────

fn hasCachedInsecureDelegation(cache: ?*RRsetCache, allocator: mem.Allocator, zone: dns.Name) bool {
    const c = cache orelse return false;
    var zone_buf: [dns.max_name_len + 1]u8 = undefined;
    const ds_result = c.lookup(allocator, zone.formatInto(&zone_buf), .ds, .in) orelse return false;
    return switch (ds_result) {
        .negative => true,
        .hit => false,
    };
}

/// When classifyDelegation returns .insecure, cache a negative DS entry
/// so that findClosestCachedDelegation can determine DNSSEC security state
/// without re-walking the referral chain.
fn cacheInsecureDelegation(
    cache: ?*@import("cache.zig").RRsetCache,
    security_state: dnssec.SecurityStatus,
    zone_cut: dns.Name,
    authorities: []const dns.ResourceRecord,
) void {
    if (security_state != .insecure) return;
    const c = cache orelse return;

    // Use minimum authority section TTL (from NSEC/NSEC3 proving no DS)
    var neg_ttl: u32 = 3600;
    for (authorities) |rr| {
        if (rr.ttl > 0 and rr.ttl < neg_ttl) neg_ttl = rr.ttl;
    }

    var zone_buf: [dns.max_name_len + 1]u8 = undefined;
    c.storeNegativeBare(zone_cut.formatInto(&zone_buf), .ds, .in, .no_error, neg_ttl, .insecure);
}

/// Validate DNSKEY answers against cached DS records (RFC 4035 §5.2).
/// Extracts DS data from cache hit records and calls dnssec.validateDnskeyRrset.
fn validateDnskeyAgainstDs(
    dnskey_answers: []const dns.ResourceRecord,
    ds_records_rr: []const dns.ResourceRecord,
    zone_parsed: dns.Name,
    budget: ?*dnssec.ValidationBudget,
) !void {
    var ds_records: [16]dns.DsData = undefined;
    var ds_count: usize = 0;
    for (ds_records_rr) |rr| {
        if (rr.rtype == .ds and ds_count < ds_records.len) {
            ds_records[ds_count] = rr.rdata.ds;
            ds_count += 1;
        }
    }
    if (ds_count > 0) {
        // RFC 4035 §5.2: DNSKEY RRset MUST be self-signed.
        const now_u32 = epochNowU32();
        try dnssec.validateDnskeyRrset(
            dnskey_answers,
            ds_records[0..ds_count],
            zone_parsed,
            now_u32,
            budget,
        );
    }
}

/// Map dnssec validation status to the cache-tier subset (no .bogus).
fn cacheSecurityStatus(state: dnssec.SecurityStatus) cache_mod.SecurityStatus {
    return switch (state) {
        .secure => .secure,
        .insecure => .insecure,
        .unchecked, .bogus => .unchecked,
    };
}

// ── Response synthesis (for cache hits) ────────────────────────────────

fn makeCachedMessage(answers: []const dns.ResourceRecord, authorities: []const dns.ResourceRecord, rcode: dns.RCode, authenticated: bool) dns.Message {
    return .{
        .header = .{
            .id = 0,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = true,
            .z = 0,
            .ad = authenticated,
            .cd = false,
            .rcode = rcode,
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = @intCast(authorities.len),
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
        .authorities = authorities,
    };
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Strip authority/additional sections from a message for targeted cache stores.
fn answersOnly(msg: dns.Message) dns.Message {
    var m = msg;
    m.authorities = &.{};
    m.additionals = &.{};
    m.header.ns_count = 0;
    m.header.ar_count = 0;
    return m;
}

/// Returns current epoch time as u32 for DNSSEC signature validation.
/// Uses wall clock (not monotonic) because RRSIG inception/expiration
/// are defined as epoch seconds (RFC 4034 §3.1.5). Truncation gives
/// correct serial number arithmetic wrapping behavior.
fn epochNowU32() u32 {
    return @truncate(@as(u64, @intCast(monotonic.wallclockSec())));
}

fn nameToDotted(allocator: mem.Allocator, name: dns.Name) ![]const u8 {
    var buf: [dns.max_name_len + 1]u8 = undefined;
    return allocator.dupe(u8, name.formatInto(&buf));
}

fn findCnameRecord(response: dns.Message, target: dns.Name) ?dns.ResourceRecord {
    for (response.answers) |rr| {
        if (rr.rtype == .cname and target.eql(rr.name)) {
            return rr;
        }
    }
    return null;
}

fn withCnameChain(allocator: mem.Allocator, chain: []const dns.ResourceRecord, response: dns.Message) !dns.Message {
    if (chain.len == 0) return response;
    const new_answers = try allocator.alloc(dns.ResourceRecord, chain.len + response.answers.len);
    @memcpy(new_answers[0..chain.len], chain);
    @memcpy(new_answers[chain.len..], response.answers);
    var msg = response;
    msg.answers = new_answers;
    msg.header.an_count = @intCast(new_answers.len);
    return msg;
}

// ── Referral extraction ────────────────────────────────────────────────

const ReferralResult = union(enum) {
    referral: struct {
        addrs: [max_servers_per_level]na.Address,
        count: usize,
        zone_cut: dns.Name, // borrows from response (valid for caller's scope)
    },
    no_glue: struct {
        ns_names: [max_servers_per_level]dns.Name,
        ns_count: usize,
        zone_cut: dns.Name,
    },
};

/// Returns true if the response contains any RRSIG records (signed zone).
fn hasSignedRecords(response: dns.Message) bool {
    for (response.answers) |rr| if (rr.rtype == .rrsig) return true;
    for (response.authorities) |rr| if (rr.rtype == .rrsig) return true;
    return false;
}

fn extractReferral(response: dns.Message, target: dns.Name, parent_zone: dns.Name) ?ReferralResult {
    // Find the most specific zone cut: NS owner where target is a subdomain
    var zone_cut: ?dns.Name = null;
    var zone_cut_depth: usize = 0;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and target.isSubdomainOf(rr.name)) {
            if (zone_cut == null or rr.name.labels.len > zone_cut_depth) {
                zone_cut = rr.name;
                zone_cut_depth = rr.name.labels.len;
            }
        }
    }
    const zc = zone_cut orelse return null;

    // A valid referral always delegates to a child zone — the zone cut must
    // be strictly deeper than the current parent zone.  If the authority
    // section contains NS records for the same zone (or a parent), it is
    // not a referral (e.g. a server returning its own NS records alongside
    // a CNAME answer).  RFC 1034 §4.2.1, RFC 8499 §7.
    if (zc.labels.len <= parent_zone.labels.len) return null;

    // Collect NS names at the zone cut
    var ns_count: usize = 0;
    var ns_names: [max_servers_per_level]dns.Name = undefined;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns and rr.name.eql(zc)) {
            if (ns_count < max_servers_per_level) {
                ns_names[ns_count] = rr.rdata.ns;
                ns_count += 1;
            }
        }
    }

    // Match glue A/AAAA records with bailiwick check
    var glue_addrs: [max_servers_per_level]na.Address = undefined;
    var glue_count: usize = 0;
    for (response.additionals) |rr| {
        const is_a = rr.rtype == .a;
        const is_aaaa = rr.rtype == .aaaa;
        if (!is_a and !is_aaaa) continue;
        // Bailiwick: glue name must be within the parent zone (the zone
        // the referring server is authoritative for). For root referrals
        // parent_zone is "." so all glue is accepted; for .com referrals,
        // glue under .com is accepted, etc.
        if (parent_zone.labels.len > 0 and !rr.name.isSubdomainOf(parent_zone)) continue;

        for (ns_names[0..ns_count]) |ns_name| {
            if (ns_name.eql(rr.name)) {
                if (glue_count < max_servers_per_level) {
                    const addr = if (is_a)
                        na.initIp4(rr.rdata.a, 53)
                    else
                        na.initIp6(rr.rdata.aaaa, 53, 0, 0);
                    if (na.isNonRoutableNs(addr)) break;
                    glue_addrs[glue_count] = addr;
                    glue_count += 1;
                }
                break;
            }
        }
    }
    if (glue_count == 0) return .{ .no_glue = .{
        .ns_names = ns_names,
        .ns_count = ns_count,
        .zone_cut = zc,
    } };

    return .{ .referral = .{
        .addrs = glue_addrs,
        .count = glue_count,
        .zone_cut = zc,
    } };
}

// ── Negative proof validation ──────────────────────────────────────────

const NegativeValidation = enum { proceed, skip_cache, bogus };

fn validateNegativeResponse(
    security_state: dnssec.SecurityStatus,
    authorities: []const dns.ResourceRecord,
    qname: dns.Name,
    qtype: dns.RType,
    is_nxdomain: bool,
) NegativeValidation {
    if (security_state != .secure) return .proceed;
    // RFC 4035 §5.4 + §5.5: inside a known-secure zone every negative
    // response must carry a complete proof; an incomplete one (.unchecked)
    // fails closed. .insecure (RFC 6840 §5.11) still proceeds without AD.
    return switch (dnssec.validateNegativeProof(authorities, qname, qtype, is_nxdomain)) {
        .secure => .proceed,
        .insecure => .skip_cache,
        .bogus => .bogus,
        .unchecked => {
            // Diagnostic for the fail-closed path: a real-world broken auth
            // (or a middlebox stripping NSEC) shows up here as SERVFAIL
            // where other resolvers may serve unauthenticated.
            var name_buf: [dns.max_name_len + 1]u8 = undefined;
            var qtype_buf: [24]u8 = undefined;
            log.warn(
                "incomplete NSEC/NSEC3 proof for {s} {s} (nx={}); SERVFAIL per RFC 4035 §5.4",
                .{ qname.formatInto(&name_buf), dns.safeTagName(dns.RType, qtype, &qtype_buf), is_nxdomain },
            );
            return .bogus;
        },
    };
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

// ── Test helpers ──────────────────────────────────────────────────────

fn makeHeader(ns_count: u16, ar_count: u16, an_count: u16) dns.Header {
    return .{
        .id = 0x1234,
        .qr = true,
        .opcode = .query,
        .aa = false,
        .tc = false,
        .rd = false,
        .ra = false,
        .z = 0,
        .ad = false,
        .cd = false,
        .rcode = .no_error,
        .qd_count = 0,
        .an_count = an_count,
        .ns_count = ns_count,
        .ar_count = ar_count,
    };
}

fn makeName(alloc: mem.Allocator, comptime labels: []const []const u8) !dns.Name {
    const l = try alloc.alloc([]const u8, labels.len);
    for (labels, 0..) |label, i| l[i] = try alloc.dupe(u8, label);
    return dns.Name{ .labels = l };
}

fn makeNsRr(zone: dns.Name, ns_name: dns.Name) dns.ResourceRecord {
    return .{ .name = zone, .rtype = .ns, .rclass = .in, .ttl = 172800, .rdata = .{ .ns = ns_name } };
}

fn makeGlueA(name: dns.Name, addr: [4]u8) dns.ResourceRecord {
    return .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 172800, .rdata = .{ .a = addr } };
}

fn makeGlueAaaa(name: dns.Name, addr: [16]u8) dns.ResourceRecord {
    return .{ .name = name, .rtype = .aaaa, .rclass = .in, .ttl = 172800, .rdata = .{ .aaaa = addr } };
}

fn makeResponse(alloc: mem.Allocator, authorities: []const dns.ResourceRecord, additionals: []const dns.ResourceRecord) !dns.Message {
    const auths = try alloc.alloc(dns.ResourceRecord, authorities.len);
    @memcpy(auths, authorities);
    const adds = try alloc.alloc(dns.ResourceRecord, additionals.len);
    @memcpy(adds, additionals);
    return .{
        .header = makeHeader(@intCast(authorities.len), @intCast(additionals.len), 0),
        .questions = &.{},
        .authorities = auths,
        .additionals = adds,
    };
}

// ── extractReferral tests ─────────────────────────────────────────────

test "extractReferral with NS and glue A records" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 192, 0, 2, 1 })});
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const result = extractReferral(response, target, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
            const expected = na.initIp4(.{ 192, 0, 2, 1 }, 53);
            try testing.expectEqual(expected.ip4.bytes, ref.addrs[0].ip4.bytes);
            try testing.expectEqual(@as(u16, 53), ref.addrs[0].getPort());
            try testing.expect(ref.zone_cut.eql(zone_name));
        },
        .no_glue => return error.TestUnexpectedResult,
    }
}

test "extractReferral with no NS records returns null" {
    const response = dns.Message{
        .header = makeHeader(0, 0, 0),
        .questions = &.{},
    };
    try testing.expect(extractReferral(response, dns.Name{ .labels = &.{ "example", "com" } }, dns.Name{ .labels = &.{} }) == null);
}

test "extractReferral with NS but no glue returns no_glue" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    switch (result) {
        .no_glue => |ng| {
            try testing.expectEqual(@as(usize, 1), ng.ns_count);
            try testing.expect(ng.zone_cut.eql(zone_name));
            const ns_dotted = try nameToDotted(alloc, ng.ns_names[0]);
            defer alloc.free(ns_dotted);
            try testing.expectEqualStrings("ns1.example.com", ns_dotted);
        },
        .referral => return error.TestUnexpectedResult,
    }
}

test "extractReferral case-insensitive glue matching" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "NS1", "EXAMPLE", "COM" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 198, 51, 100, 1 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    try testing.expect(result == .referral);
    try testing.expectEqual(@as(usize, 1), result.referral.count);
}

test "extractReferral rejects private IP glue (DNS rebinding defense)" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    // Glue pointing to loopback — must be rejected
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 127, 0, 0, 1 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    // Private glue is dropped, so we should get no_glue (triggers glueless resolution)
    try testing.expect(result == .no_glue);
}

test "extractReferral rejects out-of-zone glue" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "evil", "org" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "evil", "org" });
    // Glue for ns1.evil.org — out of bailiwick for parent zone "com"
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 6, 6, 6, 6 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{"com"} }) orelse return error.TestUnexpectedResult;
    try testing.expect(result == .no_glue);
}

test "extractReferral no_glue carries multiple NS names" {
    const alloc = testing.allocator;
    const ns1 = try makeName(alloc, &.{ "ns1", "other", "net" });
    const ns2 = try makeName(alloc, &.{ "ns2", "other", "net" });
    const zone1 = try makeName(alloc, &.{ "example", "com" });
    const zone2 = try makeName(alloc, &.{ "example", "com" });
    const response = try makeResponse(alloc, &.{ makeNsRr(zone1, ns1), makeNsRr(zone2, ns2) }, &.{});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    switch (result) {
        .no_glue => |ng| {
            try testing.expectEqual(@as(usize, 2), ng.ns_count);
            try testing.expect(ng.zone_cut.eql(zone1));
        },
        .referral => return error.TestUnexpectedResult,
    }
}

test "extractReferral accepts in-zone glue" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{"com"});
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 192, 0, 2, 53 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    try testing.expect(result == .referral);
    try testing.expectEqual(@as(usize, 1), result.referral.count);
}

test "extractReferral with AAAA glue returns IPv6 address" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const ipv6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueAaaa(glue_name, ipv6)});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
            try testing.expectEqual(@as(u16, 53), ref.addrs[0].getPort());
            const expected = na.initIp6(ipv6, 53, 0, 0);
            try testing.expectEqual(expected.ip6.bytes, ref.addrs[0].ip6.bytes);
        },
        .no_glue => return error.TestUnexpectedResult,
    }
}

test "extractReferral rejects same-zone NS as non-referral" {
    // A server returning NS records for its own zone (e.g. alongside a CNAME
    // answer) is not a referral — the zone cut must be strictly deeper than
    // the parent zone.  RFC 1034 §4.2.1, RFC 8499 §7.
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const response = try makeResponse(alloc, &.{makeNsRr(zone_name, ns_name)}, &.{makeGlueA(glue_name, .{ 192, 0, 2, 1 })});
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "api", "example", "com" } };
    // parent_zone == zone_cut → same zone, must return null
    const parent_zone = dns.Name{ .labels = &.{ "example", "com" } };
    try testing.expect(extractReferral(response, target, parent_zone) == null);
}

// ── findCnameRecord / nameToDotted tests ──────────────────────────────

test "nameToDotted round-trips correctly" {
    const alloc = testing.allocator;
    const name = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const dotted = try nameToDotted(alloc, name);
    defer alloc.free(dotted);
    try testing.expectEqualStrings("www.example.com", dotted);
}

test "findCnameRecord finds CNAME matching target" {
    const alloc = testing.allocator;
    const owner = try makeName(alloc, &.{ "www", "example", "com" });
    const cname_target = try makeName(alloc, &.{ "example", "com" });

    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = owner, .rtype = .cname, .rclass = .in, .ttl = 300, .rdata = .{ .cname = cname_target } };
    const response = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = answers };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const result = findCnameRecord(response, target);
    try testing.expect(result != null);
    try testing.expectEqual(dns.RType.cname, result.?.rtype);
    try testing.expect(target.eql(result.?.name));
}

test "findCnameRecord returns null when no CNAME present" {
    const alloc = testing.allocator;
    const owner = try makeName(alloc, &.{ "example", "com" });

    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{ .name = owner, .rtype = .a, .rclass = .in, .ttl = 300, .rdata = .{ .a = .{ 93, 184, 216, 34 } } };
    const response = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = answers };
    defer dns.freeMessage(alloc, response);

    try testing.expect(findCnameRecord(response, dns.Name{ .labels = &.{ "example", "com" } }) == null);
}

// ── QNAME minimization tests ──────────────────────────────────────────

test "probe name construction from label sub-slice" {
    // Verify that Name{ .labels = sub_slice }.format() produces correct dotted names
    const full_labels: []const []const u8 = &.{ "www", "sub", "example", "com" };

    // 1 label: "com"
    const view1 = dns.Name{ .labels = full_labels[3..] };
    const buf1 = view1.format();
    const len1 = mem.indexOfScalar(u8, &buf1, 0) orelse buf1.len;
    try testing.expectEqualStrings("com", buf1[0..len1]);

    // 2 labels: "example.com"
    const view2 = dns.Name{ .labels = full_labels[2..] };
    const buf2 = view2.format();
    const len2 = mem.indexOfScalar(u8, &buf2, 0) orelse buf2.len;
    try testing.expectEqualStrings("example.com", buf2[0..len2]);

    // 3 labels: "sub.example.com"
    const view3 = dns.Name{ .labels = full_labels[1..] };
    const buf3 = view3.format();
    const len3 = mem.indexOfScalar(u8, &buf3, 0) orelse buf3.len;
    try testing.expectEqualStrings("sub.example.com", buf3[0..len3]);

    // All 4 labels: "www.sub.example.com"
    const view4 = dns.Name{ .labels = full_labels[0..] };
    const buf4 = view4.format();
    const len4 = mem.indexOfScalar(u8, &buf4, 0) orelse buf4.len;
    try testing.expectEqualStrings("www.sub.example.com", buf4[0..len4]);
}

test "minimisation stepping — probes advance one label at a time" {
    // Simulate: target = "www.sub.example.com", parent_zone = "com" (1 label)
    // Expected probes: label_count 2 → "example.com", 3 → "sub.example.com", 4 → final "www.sub.example.com"
    const target_labels: []const []const u8 = &.{ "www", "sub", "example", "com" };
    const parent_zone_labels: usize = 1; // "com"

    var label_count: usize = parent_zone_labels + 1; // start at 2

    // First probe: "example.com"
    try testing.expectEqual(@as(usize, 2), label_count);
    const v1 = dns.Name{ .labels = target_labels[target_labels.len - label_count ..] };
    const b1 = v1.format();
    const l1 = mem.indexOfScalar(u8, &b1, 0) orelse b1.len;
    try testing.expectEqualStrings("example.com", b1[0..l1]);

    label_count += 1; // advance

    // Second probe: "sub.example.com"
    try testing.expectEqual(@as(usize, 3), label_count);
    const v2 = dns.Name{ .labels = target_labels[target_labels.len - label_count ..] };
    const b2 = v2.format();
    const l2 = mem.indexOfScalar(u8, &b2, 0) orelse b2.len;
    try testing.expectEqualStrings("sub.example.com", b2[0..l2]);

    label_count += 1; // advance

    // Now label_count == target_labels.len → is_final
    try testing.expectEqual(@as(usize, 4), label_count);
    try testing.expect(label_count >= target_labels.len);
}

test "referral resets minimise_label_count" {
    // parent_zone = "." (0 labels) → label_count = 1
    // After referral to "com" (1 label) → label_count should reset to 2
    // After referral to "example.com" (2 labels) → label_count should reset to 3
    var parent_zone_len: usize = 0;
    var label_count: usize = parent_zone_len + 1;
    try testing.expectEqual(@as(usize, 1), label_count);

    // Referral to "com"
    parent_zone_len = 1;
    label_count = parent_zone_len + 1;
    try testing.expectEqual(@as(usize, 2), label_count);

    // Referral to "example.com"
    parent_zone_len = 2;
    label_count = parent_zone_len + 1;
    try testing.expectEqual(@as(usize, 3), label_count);
}

test "max_minimise_count cap forces full QNAME" {
    // After max_minimise_count probes, is_final should be true
    const target_label_count: usize = 20; // very deep name
    var total_probes: usize = 0;
    var minimise_label_count: usize = 1; // start from root

    // Simulate probes
    while (total_probes < max_minimise_count) : (total_probes += 1) {
        const is_final = minimise_label_count >= target_label_count or
            total_probes >= max_minimise_count;
        try testing.expect(!is_final); // should still be probing
        minimise_label_count += 1;
    }

    // Now total_probes == max_minimise_count, should be final
    const is_final = minimise_label_count >= target_label_count or
        total_probes >= max_minimise_count;
    try testing.expect(is_final);
}

test "NXDOMAIN during probe — relaxed mode stops minimising" {
    // Simulate: probe returns NXDOMAIN → set label_count to target length
    const target_label_count: usize = 4;
    var minimise_label_count: usize = 2;

    // Probe NXDOMAIN → relaxed mode
    const probe_nxdomain = true;
    if (probe_nxdomain) {
        minimise_label_count = target_label_count;
    }

    // Next iteration should be final
    try testing.expect(minimise_label_count >= target_label_count);
}

test "qname_minimisation=false sends full name immediately" {
    // When disabled, minimise_label_count starts at target_name.labels.len
    const target_label_count: usize = 4;
    const qname_minimisation = false;
    const parent_zone_labels: usize = 0;

    const minimise_label_count: usize = if (qname_minimisation)
        parent_zone_labels + 1
    else
        target_label_count;

    // Should always be final
    const is_final = minimise_label_count >= target_label_count or !qname_minimisation;
    try testing.expect(is_final);
    try testing.expectEqual(target_label_count, minimise_label_count);
}

// ── Integration tests (require Linux + network) ────────────────────────

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "recursive resolve example.com A from root hints" {
    try skipIfNotLinux();
    const io = testing.io;

    var transport = BlockingUdpTransport.init(.{}, io);

    var resolver = RecursiveResolver{
        .transports = .{ .do53 = .{ .blocking = .{ .udp = &transport, .tcp = null } } },
        .io = io,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const result = resolver.resolve(arena.allocator(), "example.com", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        error.ReferralLoop => return error.SkipZigTest,
        error.CnameChainTooLong => return error.SkipZigTest,
        error.MaxReferralsExceeded => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(result.message.header.qr);
    try testing.expectEqual(dns.RCode.no_error, result.message.header.rcode);
    try testing.expect(result.message.answers.len > 0);

    // Verify we got an A record
    var found_a = false;
    for (result.message.answers) |rr| {
        if (rr.rtype == .a) {
            found_a = true;
            break;
        }
    }
    try testing.expect(found_a);
}

test "recursive resolve nonexistent domain returns name_error" {
    try skipIfNotLinux();
    const io = testing.io;

    var transport = BlockingUdpTransport.init(.{}, io);

    var resolver = RecursiveResolver{
        .transports = .{ .do53 = .{ .blocking = .{ .udp = &transport, .tcp = null } } },
        .io = io,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const result = resolver.resolve(arena.allocator(), "this-domain-does-not-exist-xyzzy.example.com", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        error.ReferralLoop => return error.SkipZigTest,
        error.CnameChainTooLong => return error.SkipZigTest,
        error.MaxReferralsExceeded => return error.SkipZigTest,
        else => return err,
    };

    try testing.expectEqual(dns.RCode.name_error, result.message.header.rcode);
}

test "recursive resolve domain with glueless NS" {
    try skipIfNotLinux();
    const io = testing.io;

    // Shorter timeouts: glueless path issues many sub-queries
    var transport = BlockingUdpTransport.init(.{ .timeout_ms = 2000 }, io);

    var resolver = RecursiveResolver{
        .transports = .{ .do53 = .{ .blocking = .{ .udp = &transport, .tcp = null } } },
        .io = io,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // ietf.org uses ns0.amsl.com etc. — glueless from .org zone
    const result = resolver.resolve(arena.allocator(), "ietf.org", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        error.ReferralLoop => return error.SkipZigTest,
        error.CnameChainTooLong => return error.SkipZigTest,
        error.MaxReferralsExceeded => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(result.message.header.qr);
    try testing.expectEqual(dns.RCode.no_error, result.message.header.rcode);
    try testing.expect(result.message.answers.len > 0);

    var found_a = false;
    for (result.message.answers) |rr| {
        if (rr.rtype == .a) {
            found_a = true;
            break;
        }
    }
    try testing.expect(found_a);
}

test "recursive resolve with CNAME chain" {
    try skipIfNotLinux();
    const io = testing.io;

    var transport = BlockingUdpTransport.init(.{ .timeout_ms = 2000 }, io);

    var resolver = RecursiveResolver{
        .transports = .{ .do53 = .{ .blocking = .{ .udp = &transport, .tcp = null } } },
        .io = io,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // www.github.com is a CNAME to github.github.io
    const result = resolver.resolve(arena.allocator(), "www.github.com", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        error.ReferralLoop => return error.SkipZigTest,
        error.CnameChainTooLong => return error.SkipZigTest,
        error.MaxReferralsExceeded => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(result.message.header.qr);
    try testing.expectEqual(dns.RCode.no_error, result.message.header.rcode);
    try testing.expect(result.message.answers.len > 0);

    var found_a = false;
    var found_cname = false;
    for (result.message.answers) |rr| {
        if (rr.rtype == .a) found_a = true;
        if (rr.rtype == .cname) found_cname = true;
    }
    try testing.expect(found_a);
    try testing.expect(found_cname);
}

// ── validateNegativeResponse tests ─────────────────────────────────────

test "validateNegativeResponse returns proceed when security_state is not secure" {
    const name = dns.Name{ .labels = &.{ "example", "com" } };
    // unchecked/insecure → proceed regardless of authorities
    try testing.expectEqual(NegativeValidation.proceed, validateNegativeResponse(.unchecked, &.{}, name, .a, true));
    try testing.expectEqual(NegativeValidation.proceed, validateNegativeResponse(.insecure, &.{}, name, .a, false));
}

test "validateNegativeResponse returns bogus for mixed NSEC/NSEC3 authorities" {
    const name = dns.Name{ .labels = &.{ "example", "com" } };
    // Build authorities with both NSEC and NSEC3 records
    const authorities = [_]dns.ResourceRecord{
        .{
            .name = dns.Name{ .labels = &.{ "example", "com" } },
            .rtype = .nsec,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{
                .nsec = .{
                    .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
                    .type_bit_maps = &.{ 0, 1, 0x40 }, // window 0, len 1, A bit
                },
            },
        },
        .{
            .name = dns.Name{ .labels = &.{ "example", "com" } },
            .rtype = .nsec3,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .nsec3 = .{
                .hash_algorithm = .sha1,
                .flags = 0,
                .iterations = 0,
                .salt = &.{},
                .next_hashed_owner = &(.{@as(u8, 0)} ** 20),
                .type_bit_maps = &.{},
            } },
        },
    };
    try testing.expectEqual(NegativeValidation.bogus, validateNegativeResponse(.secure, &authorities, name, .a, true));
}

test "validateNegativeResponse returns proceed for valid NSEC NODATA proof" {
    const name = dns.Name{ .labels = &.{ "example", "com" } };
    // NSEC owner matches qname, type bitmap does NOT include A.
    // Bitmap with only SOA (type 6): window 0, len 1, byte 0 = 0x02 (bit 6)
    const authorities = [_]dns.ResourceRecord{
        .{
            .name = dns.Name{ .labels = &.{ "example", "com" } },
            .rtype = .nsec,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{
                .nsec = .{
                    .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
                    .type_bit_maps = &.{ 0, 1, 0x02 }, // window 0, len 1, only SOA
                },
            },
        },
    };
    try testing.expectEqual(NegativeValidation.proceed, validateNegativeResponse(.secure, &authorities, name, .a, false));
}

test "validateNegativeResponse returns bogus when no proof found in secure zone" {
    const name = dns.Name{ .labels = &.{ "nonexistent", "example", "com" } };
    // Empty authorities in a known-secure zone is a downgrade attempt:
    // RFC 4035 §3.2.1 requires NSEC/NSEC3 with every negative response for
    // signed zones. Fail closed rather than serving the unauthenticated
    // NXDOMAIN/NODATA.
    try testing.expectEqual(NegativeValidation.bogus, validateNegativeResponse(.secure, &.{}, name, .a, true));
    try testing.expectEqual(NegativeValidation.bogus, validateNegativeResponse(.secure, &.{}, name, .a, false));
}

test "validateNegativeResponse returns bogus on incomplete NSEC NXDOMAIN proof" {
    // NSEC covers qname but the wildcard-denial NSEC is missing — RFC 4035
    // §5.4 requires both. validateNegativeProof returns .unchecked; the
    // recursive wrapper must escalate that to .bogus inside a secure zone,
    // not serve the response unauthenticated.
    const aaa = dns.Name{ .labels = &.{ "aaa", "example", "com" } };
    const ccc = dns.Name{ .labels = &.{ "ccc", "example", "com" } };
    const beta = dns.Name{ .labels = &.{ "beta", "example", "com" } };
    const authorities = [_]dns.ResourceRecord{
        .{ .name = aaa, .rtype = .nsec, .rclass = .in, .ttl = 3600, .rdata = .{ .nsec = .{
            .next_domain_name = ccc,
            .type_bit_maps = &.{},
        } } },
        // No NSEC for *.example.com — proof is incomplete.
    };
    try testing.expectEqual(
        NegativeValidation.bogus,
        validateNegativeResponse(.secure, &authorities, beta, .a, true),
    );
}
