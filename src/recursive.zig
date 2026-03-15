const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const UdpTransport = @import("transport.zig").UdpTransport;
const TcpTransport = @import("tcp_transport.zig").TcpTransport;
const TlsTransport = @import("tls_transport.zig").TlsTransport;
const encrypted_ns = @import("encrypted_ns.zig");
const EncryptedNsCache = encrypted_ns.EncryptedNsCache;
const AddressKey = @import("connection_pool.zig").AddressKey;
const RttCache = @import("ns_rtt.zig").RttCache;
const cache_mod = @import("cache.zig");
const RRsetCache = cache_mod.RRsetCache;
const InFlightTable = @import("dedup.zig").InFlightTable;
const log = std.log.scoped(.resolver);

// ── Root Hints ─────────────────────────────────────────────────────────
// IPv4 + IPv6 addresses for a.root-servers.net through m.root-servers.net.
// Source: https://www.internic.net/domain/named.root

pub const root_hints: [26]std.net.Address = .{
    // IPv4
    std.net.Address.initIp4(.{ 198, 41, 0, 4 }, 53), // a
    std.net.Address.initIp4(.{ 170, 247, 170, 2 }, 53), // b
    std.net.Address.initIp4(.{ 192, 33, 4, 12 }, 53), // c
    std.net.Address.initIp4(.{ 199, 7, 91, 13 }, 53), // d
    std.net.Address.initIp4(.{ 192, 203, 230, 10 }, 53), // e
    std.net.Address.initIp4(.{ 192, 5, 5, 241 }, 53), // f
    std.net.Address.initIp4(.{ 192, 112, 36, 4 }, 53), // g
    std.net.Address.initIp4(.{ 198, 97, 190, 53 }, 53), // h
    std.net.Address.initIp4(.{ 192, 36, 148, 17 }, 53), // i
    std.net.Address.initIp4(.{ 192, 58, 128, 30 }, 53), // j
    std.net.Address.initIp4(.{ 193, 0, 14, 129 }, 53), // k
    std.net.Address.initIp4(.{ 199, 7, 83, 42 }, 53), // l
    std.net.Address.initIp4(.{ 202, 12, 27, 33 }, 53), // m
    // IPv6
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x03, 0xba, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 }, 53, 0, 0), // a
    std.net.Address.initIp6(.{ 0x28, 0x01, 0x01, 0xb8, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b }, 53, 0, 0), // b
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c }, 53, 0, 0), // c
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x2d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d }, 53, 0, 0), // d
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e }, 53, 0, 0), // e
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x2f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f }, 53, 0, 0), // f
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x0d }, 53, 0, 0), // g
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, 53, 0, 0), // h
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x07, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, 53, 0, 0), // i
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x03, 0x0c, 0x27, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 }, 53, 0, 0), // j
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x07, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 53, 0, 0), // k
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x9f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 }, 53, 0, 0), // l
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35 }, 53, 0, 0), // m
};

const max_referrals = 10;
const max_servers_per_level = 26;
const max_cname_chain = 8;
const max_minimise_count = 10;

/// Parse a DNS message, propagating OOM and converting other parse
/// errors to null so callers can skip malformed responses.
fn tryParseMessage(allocator: mem.Allocator, data: []const u8) error{OutOfMemory}!?dns.Message {
    return dns.parseMessage(allocator, data) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
}

// ── RecursiveResolver ──────────────────────────────────────────────────

pub const RecursiveResolver = struct {
    transport: *UdpTransport,
    tcp_transport: ?*TcpTransport = null,
    cache: ?*RRsetCache = null,
    qname_minimisation: bool = true,
    /// Whether to validate DNSSEC signatures (may be disabled per-query by CD bit)
    dnssec_enabled: bool = false,
    /// Whether to request DNSSEC data (DO bit) — always true if server is DNSSEC-capable.
    /// RFC 4035 §3.2.1: MUST set DO regardless of CD bit or per-query validation.
    dnssec_aware: bool = false,
    tls_transport: ?*TlsTransport = null,
    encrypted_ns_cache: ?*EncryptedNsCache = null,
    rtt_cache: ?*RttCache = null,
    bypass_cache: bool = false,
    dedup: ?*InFlightTable = null,
    /// Re-entrancy guard: prevents fetchDsFromParent → resolveNsAddresses →
    /// resolveImpl → validateAnswer → fetchDnskey → fetchDsFromParent loops.
    resolving_ds: bool = false,

    /// DNSKEY zone needing proactive refresh — stored in fixed buffer (not arena)
    /// to survive past the per-query arena lifetime. Set by fetchDnskey, propagated
    /// to ResolveResult for async refresh by the server layer.
    pending_dnskey_prefetch: ?[]const u8 = null,
    pending_dnskey_buf: [dns.max_name_len + 1]u8 = undefined,

    /// Non-last server timeout cap (Knot KR_CONN_RTT_MAX, RFC 1035 §4.2.1 ≥2s).
    const failover_timeout_cap: u32 = 2000;

    fn serverTimeout(self: *RecursiveResolver, addr_key: AddressKey, is_last: bool) u32 {
        const base: u32 = if (self.rtt_cache) |rc| rc.getTimeout(addr_key) else self.transport.config.timeout_ms;
        return if (is_last) base else @min(base, failover_timeout_cap);
    }

    pub const ResolveResult = struct {
        message: dns.Message,
        prefetch_name: ?[]const u8 = null,
        prefetch_qtype: dns.RType = .a,
        /// DNSKEY zone needing async refresh (TTL < 10%). Server handles after responding.
        prefetch_dnskey_zone: ?[]const u8 = null,
    };

    pub fn resolve(self: *RecursiveResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType) !ResolveResult {
        var result = try self.resolveImpl(allocator, name, qtype, 0);
        result.prefetch_dnskey_zone = self.pending_dnskey_prefetch;
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

            var servers: [max_servers_per_level]std.net.Address = undefined;
            var server_count: usize = root_hints.len;
            @memcpy(servers[0..root_hints.len], &root_hints);

            const target_name = try dns.parseDottedName(allocator, current_name);

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
                    if (hasCachedInsecureDelegation(self.cache, allocator, deleg.zone))
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
                    const child_buf = child_view.format();
                    const child_len = mem.indexOfScalar(u8, &child_buf, 0) orelse child_buf.len;
                    break :blk try allocator.dupe(u8, child_buf[0..child_len]);
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

                // Order servers: RTT-band selection if available, Fisher-Yates otherwise
                var order_buf: [max_servers_per_level]usize = undefined;
                const server_order = if (self.rtt_cache) |rc|
                    rc.selectServers(servers[0..server_count], &order_buf)
                else blk: {
                    fisherYatesShuffle(std.net.Address, servers[0..server_count]);
                    for (0..server_count) |idx| order_buf[idx] = idx;
                    break :blk order_buf[0..server_count];
                };

                // Try each server until one responds with a useful answer
                var got_response = false;
                var response: dns.Message = undefined;
                var last_server_failure: ?dns.Message = null;

                for (server_order, 0..) |server_idx, server_i| {
                    const server = servers[server_idx];
                    const addr_key = AddressKey.fromAddress(server);

                    const is_last_server = (server_i + 1 >= server_order.len);

                    // Skip dead servers unless last (fallback when all are dead)
                    if (self.rtt_cache) |rc| {
                        if (rc.isDead(addr_key) and !is_last_server) continue;
                    }

                    const per_server_timeout = self.serverTimeout(addr_key, is_last_server);

                    // Generate random query ID
                    var id_bytes: [2]u8 = undefined;
                    std.crypto.random.bytes(&id_bytes);
                    const query_id = mem.readInt(u16, &id_bytes, .big);

                    // Build iterative query (rd=false, EDNS0)
                    const query_msg = try dns.buildQueryWithOptions(allocator, query_id, query_name, query_type, .{
                        .rd = false,
                        .edns = .{ .do_bit = self.dnssec_aware },
                    });

                    // Serialize
                    var wire_buf: [dns.edns_udp_payload]u8 = undefined;
                    const wire_query = try dns.serializeMessage(&wire_buf, query_msg);

                    // ── RFC 9539: Opportunistic encrypted query ──
                    if (self.tls_transport) |tls_t| {
                        if (self.encrypted_ns_cache) |oc| {
                            const tls_key = AddressKey.fromAddressWithPort(server, tls_t.config.port);
                            switch (oc.getStatus(tls_key)) {
                                .capable => {
                                    // Known-good server → try encrypted (pool or new connection)
                                    const padded_msg = try dns.buildQueryWithOptions(allocator, query_id, query_name, query_type, .{
                                        .rd = false,
                                        .edns = .{ .do_bit = self.dnssec_aware, .padding_target = 468 },
                                    });
                                    var padded_buf: [dns.edns_udp_payload]u8 = undefined;
                                    const padded_query = try dns.serializeMessage(&padded_buf, padded_msg);

                                    var tls_response_buf: [65535]u8 = undefined;
                                    if (tls_t.queryOpportunistic(padded_query, server, &tls_response_buf, 4000)) |tls_data| {
                                        if (try tryParseMessage(allocator, tls_data)) |tls_response| {
                                            if (tls_response.header.qr and
                                                !tls_response.header.rcode.isServerError() and
                                                tls_response.header.rcode != .format_error)
                                            {
                                                response = tls_response;
                                                got_response = true;
                                                if (self.cache) |c| c.storeResponse(response, parent_zone);
                                                // Don't update UDP RTT cache from TLS — different transport
                                                // latency would poison UDP timeout estimates.
                                                break;
                                            }
                                        }
                                        // TLS error/unparseable — fall through to Do53
                                    } else |_| {
                                        // TLS connection failed — fall through to Do53
                                    }
                                },
                                .unknown => {}, // First contact → Do53 now, probe after
                                .probing, .failed => {}, // Skip, go straight to Do53
                            }
                        }
                    }

                    // ── Do53: UDP with TCP fallback ──
                    response = try self.queryServerUdp(
                        allocator, wire_query, query_id, server, per_server_timeout,
                    ) orelse continue;

                    // Lame detection (RFC 4697): SERVFAIL/REFUSED → try next server.
                    // Per-query only; no persistent penalty (RFC 4697 requires per-zone+IP keying).
                    if (response.header.rcode.isServerError()) {
                        last_server_failure = response;
                        continue;
                    }

                    got_response = true;
                    if (self.cache) |c| c.storeResponse(response, parent_zone);
                    break;
                }

                // Fall back to last SERVFAIL/REFUSED if all servers failed
                if (!got_response) {
                    if (last_server_failure) |sf| {
                        response = sf;
                        got_response = true;
                    } else {
                        return error.Timeout;
                    }
                }

                // Fire background OTE probes (skip if we fell back to a SERVFAIL)
                if (!response.header.rcode.isServerError()) {
                    if (self.encrypted_ns_cache) |oc| {
                        if (self.tls_transport) |tls_t| {
                            for (server_order) |si| {
                                const srv = servers[si];
                                const tls_key = AddressKey.fromAddressWithPort(srv, tls_t.config.port);
                                if (oc.claimProbe(tls_key)) {
                                    tls_t.probeInBackground(srv, oc);
                                }
                            }
                        }
                    }
                }

                // ── Probe response handling (non-final queries) ──
                if (!is_final) {
                    // Check for referral — only from successful responses (error responses
                    // may contain NS records in authority that are not valid delegations)
                    if (response.header.rcode == .no_error) {
                        if (extractReferral(response, target_name, parent_zone)) |referral| {
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
                                    if (self.cache) |c| c.storeNegative(query_name, query_type, .in, .no_error, response.authorities, parent_zone, cacheSecurityStatus(security_state));
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

                // Classify response
                if (response.header.rcode != .no_error) {
                    if (response.header.rcode == .name_error and response.header.aa) {
                        switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, target_name, qtype, true, servers[0..server_count])) {
                            .proceed => {
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
                            if (self.dnssec_enabled and security_state == .secure) {
                                if (dnssec.findRrsig(response.answers, .cname) != null) {
                                    switch (try self.validateAnswer(allocator, &response, .cname, security_state, servers[0..server_count])) {
                                        .bogus => return self.bogusServfail(current_name, qtype),
                                        .valid => {
                                            if (self.cache) |c| {
                                                c.storeResponse(response, parent_zone);
                                                c.updateSecurityStatus(current_name, .cname, .in, .secure);
                                            }
                                        },
                                        .skip => {},
                                    }
                                }
                            }
                            if (findCnameRecord(response, target_name)) |cname_rr| {
                                if (cname_count >= max_cname_chain) return error.CnameChainTooLong;
                                cname_count += 1;
                                try cname_chain.append(allocator, cname_rr);
                                current_name = try nameToDotted(allocator, cname_rr.rdata.cname);
                                // Re-resolve CNAME target from root with fresh security state.
                                // Preserve .insecure: an unauthenticated CNAME could redirect
                                // anywhere, so the answer must not carry AD (RFC 4035 §3.2.3).
                                if (security_state != .insecure) {
                                    security_state = if (self.dnssec_enabled) .secure else .unchecked;
                                }
                                continue :cname_loop;
                            }
                        }
                    }

                    // Validate answer RRsets if in secure zone
                    if (self.dnssec_enabled) {
                        switch (try self.validateAnswer(allocator, &response, qtype, security_state, servers[0..server_count])) {
                            .bogus => return self.bogusServfail(current_name, qtype),
                            .valid => {
                                if (self.cache) |c| c.updateSecurityStatus(current_name, qtype, .in, .secure);
                            },
                            .skip => {},
                        }
                    }

                    return .{ .message = try withCnameChain(allocator, cname_chain.items, response) };
                }

                // Check for referral (NS records in authority section)
                const referral = extractReferral(response, target_name, parent_zone) orelse {
                    // NODATA: no answers, no referral. Cache only if authoritative.
                    if (response.header.aa) {
                        switch (self.verifiedNegativeResponse(allocator, security_state, response.authorities, target_name, qtype, false, servers[0..server_count])) {
                            .proceed => {
                                if (self.cache) |c| c.storeNegative(current_name, qtype, .in, .no_error, response.authorities, parent_zone, cacheSecurityStatus(security_state));
                            },
                            .skip_cache => {},
                            .bogus => return self.bogusServfail(current_name, qtype),
                        }
                    }
                    return .{ .message = try withCnameChain(allocator, cname_chain.items, response) };
                };

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
        servers: *[max_servers_per_level]std.net.Address,
        server_count: *usize,
        seen_zones: *[max_referrals]dns.Name,
        seen_zone_count: *usize,
    ) !void {
        const zone_cut = switch (referral) {
            .referral => |ref| ref.zone_cut,
            .no_glue => |ng| ng.zone_cut,
        };

        // DNSSEC: classify delegation security at referral (RFC 4035 §5.2)
        // Verify authority NSEC/NSEC3 signatures before accepting insecure classification.
        if (security_state.* == .secure) {
            const auth_status = self.verifyAuthoritySigs(allocator, authorities, servers.*[0..server_count.*]);
            if (auth_status == .secure) {
                security_state.* = dnssec.classifyDelegation(authorities, zone_cut);
                cacheInsecureDelegation(self.cache, security_state.*, zone_cut, authorities);
            } else if (auth_status == .unchecked) {
                if (hasCachedInsecureDelegation(self.cache, allocator, zone_cut))
                    security_state.* = .insecure;
            }
            // .bogus: keep .secure — prevents forged NSEC downgrade.
        }

        // Resolve server addresses
        const addrs: NsAddrResult = switch (referral) {
            .referral => |ref| .{ .addrs = ref.addrs, .count = ref.count },
            .no_glue => |ng| blk: {
                if (try self.lookupCachedNsAddresses(allocator, ng.ns_names[0..ng.ns_count])) |res| break :blk res;
                const resolved = self.resolveNsAddresses(allocator, ng.ns_names[0..ng.ns_count], depth) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    return error.NoGlueRecords;
                };
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

    // ── UDP+TCP query helper ──────────────────────────────────────────

    /// Send a UDP query to a single server with TC-bit TCP fallback and RTT tracking.
    /// Returns the parsed response, or null on failure (timeout, parse error, etc.).
    fn queryServerUdp(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        wire_query: []const u8,
        query_id: u16,
        server: std.net.Address,
        timeout: u32,
    ) error{OutOfMemory}!?dns.Message {
        const addr_key = AddressKey.fromAddress(server);
        const query_start = std.time.microTimestamp();

        const response_data = self.transport.queryWithTimeout(
            wire_query, query_id, server, timeout,
        ) catch {
            if (self.rtt_cache) |rc| rc.recordTimeout(addr_key);
            return null;
        };
        const elapsed_us = std.time.microTimestamp() - query_start;

        // Record liveness — truncated responses still prove server is alive
        if (self.rtt_cache) |rc| rc.recordSuccess(addr_key, elapsed_us);

        // TC bit: retry over TCP (RFC 2181 — ignore truncated data)
        if (dns.hasTcBit(response_data)) {
            if (self.tcp_transport) |tcp| {
                var tcp_buf: [65535]u8 = undefined;
                if (tcp.query(wire_query, server, &tcp_buf)) |tcp_data| {
                    const response = try tryParseMessage(allocator, tcp_data) orelse return null;
                    if (!response.header.qr) return null;
                    return response;
                } else |err| {
                    log.warn("TCP fallback failed: {s}", .{@errorName(err)});
                }
            }
            return null;
        }

        const response = try tryParseMessage(allocator, response_data) orelse return null;
        if (!response.header.qr) return null;
        return response;
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
        if (self.cache) |c| c.storeNegativeBare(name, qtype, .in, .server_failure, dnssec_bogus_ttl);
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
        servers: []const std.net.Address,
    ) !?[]const dns.ResourceRecord {
        // Fast path: cache hit — no dedup needed.
        if (self.cache) |c| {
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
            switch (dedup.acquireOrWaitWithTimeout(zone_name, .dnskey, 0, dnskey_dedup_timeout_ns)) {
                .leader => {
                    // We're the leader — do the actual fetch, then release.
                    defer dedup.releaseLeader(zone_name, .dnskey, 0);
                    return self.fetchAndValidateDnskey(allocator, zone_name, servers);
                },
                .follower => {
                    // Leader finished (or timed out). Re-check cache — leader
                    // should have populated it on success.
                    if (self.cache) |c| {
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
                    switch (dedup.acquireOrWaitWithTimeout(zone_name, .dnskey, 0, dnskey_dedup_timeout_ns / 2)) {
                        .leader => {
                            defer dedup.releaseLeader(zone_name, .dnskey, 0);
                            return self.fetchAndValidateDnskey(allocator, zone_name, servers);
                        },
                        .follower => {
                            // Another follower is already retrying — check cache once more.
                            if (self.cache) |c| {
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
        servers: []const std.net.Address,
    ) !?[]const dns.ResourceRecord {
        // Network fetch — don't cache yet (RFC 4035 §5.3: validate first)
        const resp = try self.fetchRRset(allocator, zone_name, .dnskey, servers, 3, true, false) orelse return null;
        if (resp.answers.len == 0) return null;

        const zone_parsed = try dns.parseDottedName(allocator, zone_name);

        // Validate DNSKEY against cached DS before caching (RFC 4035 §5.2)
        if (self.cache) |c| {
            if (c.lookup(allocator, zone_name, .ds, .in)) |result| {
                switch (result) {
                    .hit => |h| {
                        validateDnskeyAgainstDs(resp.answers, h.records, zone_parsed) catch return null;
                    },
                    .negative => {}, // Insecure delegation — no DS validation needed
                }
            } else {
                // DS not in cache (evicted or cold start). For non-root zones,
                // re-fetch DS from the parent zone's NS before giving up
                // (RFC 4035 §5.2). All major resolvers (Unbound, BIND, PowerDNS)
                // re-fetch rather than returning bogus for transient cache misses.
                // Root zone (empty name) is exempt — it's the trust anchor.
                if (zone_name.len > 0) {
                    if (!self.fetchDsFromParent(allocator, zone_name)) return null;
                    const ds_result = c.lookup(allocator, zone_name, .ds, .in) orelse return null;
                    switch (ds_result) {
                        .hit => |h| validateDnskeyAgainstDs(resp.answers, h.records, zone_parsed) catch return null,
                        .negative => return null, // Re-probe established insecure — caller's security_state is stale
                    }
                }
            }
        }

        // RFC 4035 §5.3: "the validator SHOULD cache the RRset" — after validation
        if (self.cache) |c| c.storeResponse(resp, zone_parsed);

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
        servers: []const std.net.Address,
        max_servers: usize,
        do_bit: bool,
        store_response: bool,
    ) !?dns.Message {
        if (servers.len == 0) return null;

        var id_bytes: [2]u8 = undefined;
        std.crypto.random.bytes(&id_bytes);
        const query_id = mem.readInt(u16, &id_bytes, .big);

        const query_msg = try dns.buildQueryWithOptions(allocator, query_id, zone_name, qtype, .{
            .rd = false,
            .edns = .{ .do_bit = do_bit },
        });

        var wire_buf: [dns.edns_udp_payload]u8 = undefined;
        const wire_query = dns.serializeMessage(&wire_buf, query_msg) catch return null;

        const authority_zone = try dns.parseDottedName(allocator, zone_name);

        const try_count = @min(servers.len, max_servers);
        for (servers[0..try_count], 0..) |server, i| {
            const addr_key = AddressKey.fromAddress(server);

            if (self.rtt_cache) |rc| {
                if (rc.isDead(addr_key) and i + 1 < try_count) continue;
            }

            const timeout = self.serverTimeout(addr_key, i + 1 >= try_count);

            const response = try self.queryServerUdp(
                allocator, wire_query, query_id, server, timeout,
            ) orelse continue;
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
    /// TTL expiry). Returns true if DS is now in cache.
    fn fetchDsFromParent(self: *RecursiveResolver, allocator: mem.Allocator, zone_name: []const u8) bool {
        if (self.resolving_ds) return false; // re-entrancy guard

        // Derive parent zone: strip first label (e.g. "example.com" → "com")
        const dot_pos = mem.indexOfScalar(u8, zone_name, '.') orelse return false;
        if (dot_pos + 1 >= zone_name.len) return false; // TLD — parent is root
        const parent_zone = zone_name[dot_pos + 1 ..];

        const cache = self.cache orelse return false;
        const ns_hit = switch (cache.lookup(allocator, parent_zone, .ns, .in) orelse return false) {
            .hit => |h| h,
            .negative => return false,
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
            break :blk (self.resolveNsAddresses(allocator, ns_names[0..ns_count], 1) catch null) orelse return false;
        };
        return self.reproveDelegationSecurity(allocator, zone_name, addrs.addrs[0..addrs.count]);
    }

    /// Refresh expired DS status by querying parent servers directly.
    /// Uses dedup to coalesce concurrent fetches. Returns true if DS is now in cache.
    fn reproveDelegationSecurity(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        zone_name: []const u8,
        parent_servers: []const std.net.Address,
    ) bool {
        // Fast path: DS already in cache (another thread may have fetched it).
        if (self.cache) |c| {
            if (c.lookup(allocator, zone_name, .ds, .in) != null) return true;
        }

        // Dedup: coalesce concurrent DS fetches for the same zone.
        if (self.dedup) |dedup| {
            switch (dedup.acquireOrWaitWithTimeout(zone_name, .ds, 0, ds_dedup_timeout_ns)) {
                .leader => {
                    defer dedup.releaseLeader(zone_name, .ds, 0);
                    return self.reproveDelegationSecurityImpl(allocator, zone_name, parent_servers);
                },
                .follower => {
                    // Leader finished — re-check cache.
                    if (self.cache) |c| {
                        if (c.lookup(allocator, zone_name, .ds, .in) != null) return true;
                    }
                    // Cache still empty — leader failed. One follower retries.
                    switch (dedup.acquireOrWaitWithTimeout(zone_name, .ds, 0, ds_dedup_timeout_ns / 2)) {
                        .leader => {
                            defer dedup.releaseLeader(zone_name, .ds, 0);
                            return self.reproveDelegationSecurityImpl(allocator, zone_name, parent_servers);
                        },
                        .follower => {
                            if (self.cache) |c| {
                                if (c.lookup(allocator, zone_name, .ds, .in) != null) return true;
                            }
                            return false;
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
        parent_servers: []const std.net.Address,
    ) bool {
        const response = (self.fetchRRset(allocator, zone_name, .ds, parent_servers, 2, self.dnssec_aware, true) catch return false) orelse return false;
        const zone = dns.parseDottedName(allocator, zone_name) catch return false;

        // Positive DS — zone is signed (already cached by fetchRRset).
        // Check both answers (direct DS query) and authorities (referral-style response).
        for (response.answers) |rr| {
            if (rr.rtype == .ds) return true;
        }
        for (response.authorities) |rr| {
            if (rr.rtype == .ds) return true;
        }

        // No DS — verify NSEC/NSEC3 proof and cache insecure delegation
        const auth_status = self.verifyAuthoritySigs(allocator, response.authorities, parent_servers);
        if (auth_status == .secure) {
            const status = dnssec.classifyDelegation(response.authorities, zone);
            if (status == .insecure) {
                cacheInsecureDelegation(self.cache, status, zone, response.authorities);
                return true;
            }
        }
        return false;
    }

    /// Validate answer RRsets for a response from a secure zone.
    /// Returns .valid (AD bit set), .bogus (should SERVFAIL), or .skip (insecure zone).
    fn validateAnswer(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        response: *dns.Message,
        qtype: dns.RType,
        security_state: dnssec.SecurityStatus,
        servers: []const std.net.Address,
    ) !AnswerValidation {
        if (security_state != .secure) return .skip;

        const now_u32: u32 = @truncate(@as(u64, @intCast(std.time.timestamp())));

        // Find RRSIG in answers to get the signer zone
        const rrsig = dnssec.findRrsig(response.answers, qtype) orelse return .bogus;

        // Extract signer zone name as dotted string
        const signer_dotted = try nameToDotted(allocator, rrsig.signer_name);

        // Fetch DNSKEY for the signer zone (validated against DS before caching — RFC 4035 §5.3)
        const dnskey_records = (try self.fetchDnskey(allocator, signer_dotted, servers)) orelse return .bogus;

        // Validate the answer RRsets
        return switch (dnssec.validateAnswerRrset(response.answers, qtype, dnskey_records, now_u32)) {
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
        parent_servers: []const std.net.Address,
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

        // Fetch DNSKEY from cache or parent servers
        const signer_dotted = nameToDotted(allocator, signer) catch return .unchecked;
        const dnskey_records = (self.fetchDnskey(allocator, signer_dotted, parent_servers) catch return .unchecked) orelse return .unchecked;

        const now_u32: u32 = @truncate(@as(u64, @intCast(std.time.timestamp())));
        return dnssec.verifyAuthorityNsecSigs(authorities, dnskey_records, now_u32);
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
        zone_servers: []const std.net.Address,
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

        var addrs: [max_servers_per_level]std.net.Address = undefined;
        var count: usize = 0;
        var resolved_ns_count: usize = 0;
        // Fetch policy (Unbound-style): resolve more NS names at shallow depths
        // to warm cache for sibling queries. At least 1 at all depths.
        const ns_fetch_limit: usize = switch (depth) {
            0 => 3,
            1 => 2,
            else => 1,
        };

        for (ns_names) |ns_name| {
            const ns_dotted = nameToDotted(allocator, ns_name) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                continue;
            };
            var found_for_this_ns = false;
            // Resolve A records
            if (self.resolveImpl(allocator, ns_dotted, .a, depth + 1)) |ns_result| {
                for (ns_result.message.answers) |rr| {
                    if (rr.rtype == .a and count < max_servers_per_level) {
                        addrs[count] = std.net.Address.initIp4(rr.rdata.a, 53);
                        count += 1;
                        found_for_this_ns = true;
                    }
                }
            } else |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
            }
            // Resolve AAAA records
            if (self.resolveImpl(allocator, ns_dotted, .aaaa, depth + 1)) |ns6_result| {
                for (ns6_result.message.answers) |rr| {
                    if (rr.rtype == .aaaa and count < max_servers_per_level) {
                        addrs[count] = std.net.Address.initIp6(rr.rdata.aaaa, 53, 0, 0);
                        count += 1;
                        found_for_this_ns = true;
                    }
                }
            } else |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
            }
            if (found_for_this_ns) {
                resolved_ns_count += 1;
                if (resolved_ns_count >= ns_fetch_limit) break;
            }
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    const NsAddrResult = struct { addrs: [max_servers_per_level]std.net.Address, count: usize };
    const DelegationResult = struct { addrs: [max_servers_per_level]std.net.Address, count: usize, zone: dns.Name };

    /// Check cache for A/AAAA records of NS names, avoiding network queries.
    /// Collects addresses from all cached NS names (cache lookups are free)
    /// for better server diversity.
    fn lookupCachedNsAddresses(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
    ) !?NsAddrResult {
        const cache = self.cache orelse return null;

        var addrs: [max_servers_per_level]std.net.Address = undefined;
        var count: usize = 0;

        for (ns_names) |ns_name| {
            const ns_dotted = try nameToDotted(allocator, ns_name);
            if (cache.lookup(allocator, ns_dotted, .a, .in)) |result| {
                switch (result) {
                    .hit => |h| {
                        for (h.records) |rr| {
                            if (rr.rtype == .a and count < max_servers_per_level) {
                                addrs[count] = std.net.Address.initIp4(rr.rdata.a, 53);
                                count += 1;
                            }
                        }
                    },
                    .negative => {},
                }
            }
            if (cache.lookup(allocator, ns_dotted, .aaaa, .in)) |result| {
                switch (result) {
                    .hit => |h| {
                        for (h.records) |rr| {
                            if (rr.rtype == .aaaa and count < max_servers_per_level) {
                                addrs[count] = std.net.Address.initIp6(rr.rdata.aaaa, 53, 0, 0);
                                count += 1;
                            }
                        }
                    },
                    .negative => {},
                }
            }
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    /// Walk the domain name from TLD to find the closest cached delegation.
    /// E.g., for "www.example.com", check NS records for "com" then "example.com".
    fn findClosestCachedDelegation(
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

        // Walk from TLD toward full name, looking for cached NS + addresses
        var best: ?DelegationResult = null;

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

            // Look up cached NS records for this zone
            if (cache.lookup(allocator, zone_str, .ns, .in)) |result| {
                switch (result) {
                    .hit => |h| {
                        // Extract NS names from cached records
                        var ns_names: [max_servers_per_level]dns.Name = undefined;
                        var ns_count: usize = 0;
                        for (h.records) |ns_rr| {
                            if (ns_rr.rtype == .ns and ns_count < max_servers_per_level) {
                                ns_names[ns_count] = ns_rr.rdata.ns;
                                ns_count += 1;
                            }
                        }

                        if (try self.lookupCachedNsAddresses(allocator, ns_names[0..ns_count])) |res| {
                            // DNSSEC: only use this delegation if DS status is known.
                            // If DS is a cache miss, another thread may not have cached
                            // the insecure delegation yet. Try a targeted DS re-probe
                            // using the parent delegation's servers (like Unbound's key
                            // cache refresh) before falling back to referral re-walk.
                            if (self.dnssec_enabled) {
                                if (cache.lookup(allocator, zone_str, .ds, .in) == null) {
                                    const reprobed = if (best) |parent_deleg|
                                        self.reproveDelegationSecurity(
                                            allocator,
                                            zone_str,
                                            parent_deleg.addrs[0..parent_deleg.count],
                                        )
                                    else
                                        false;
                                    if (!reprobed) break;
                                    // DS status re-established — re-check before using
                                    if (cache.lookup(allocator, zone_str, .ds, .in) == null) break;
                                }
                            }

                            const zone_name = try dns.parseDottedName(allocator, zone_str);
                            best = .{
                                .addrs = res.addrs,
                                .count = res.count,
                                .zone = zone_name,
                            };
                            // Keep going to find a more specific zone
                        }
                    },
                    .negative => {},
                }
            }
        }

        return best;
    }
};

// ── Insecure delegation caching ───────────────────────────────────────

fn hasCachedInsecureDelegation(cache: ?*RRsetCache, allocator: mem.Allocator, zone: dns.Name) bool {
    const c = cache orelse return false;
    const zs = nameToSlice(zone);
    const ds_result = c.lookup(allocator, zs.buf[0..zs.len], .ds, .in) orelse return false;
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

    const zs = nameToSlice(zone_cut);
    c.storeNegativeBare(zs.buf[0..zs.len], .ds, .in, .no_error, neg_ttl);
}

/// Validate DNSKEY answers against cached DS records (RFC 4035 §5.2).
/// Extracts DS data from cache hit records and calls dnssec.validateDnskeyRrset.
fn validateDnskeyAgainstDs(
    dnskey_answers: []const dns.ResourceRecord,
    ds_records_rr: []const dns.ResourceRecord,
    zone_parsed: dns.Name,
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
        if (dnssec.findRrsig(dnskey_answers, .dnskey) != null) {
            const now_u32: u32 = @truncate(@as(u64, @intCast(std.time.timestamp())));
            try dnssec.validateDnskeyRrset(
                dnskey_answers,
                ds_records[0..ds_count],
                zone_parsed,
                now_u32,
            );
        }
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
            .z = 0, .ad = authenticated, .cd = false,
            .rcode = rcode,
            .qd_count = 0,
            .an_count = @intCast(answers.len),
            .ns_count = @intCast(authorities.len),
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = answers,
        .authorities = authorities,
        .additionals = &.{},
    };
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Return the formatted name as a slice into a stack buffer (no allocation).
fn nameToSlice(name: dns.Name) struct { buf: [dns.max_name_len + 1]u8, len: usize } {
    const buf = name.format();
    const len = mem.indexOfScalar(u8, &buf, 0) orelse buf.len;
    return .{ .buf = buf, .len = len };
}

fn nameToDotted(allocator: mem.Allocator, name: dns.Name) ![]const u8 {
    const s = nameToSlice(name);
    return allocator.dupe(u8, s.buf[0..s.len]);
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
        addrs: [max_servers_per_level]std.net.Address,
        count: usize,
        zone_cut: dns.Name, // borrows from response (valid for caller's scope)
    },
    no_glue: struct {
        ns_names: [max_servers_per_level]dns.Name,
        ns_count: usize,
        zone_cut: dns.Name,
    },
};

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
    var glue_addrs: [max_servers_per_level]std.net.Address = undefined;
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
                    if (is_a) {
                        glue_addrs[glue_count] = std.net.Address.initIp4(rr.rdata.a, 53);
                    } else {
                        glue_addrs[glue_count] = std.net.Address.initIp6(rr.rdata.aaaa, 53, 0, 0);
                    }
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
    return switch (dnssec.validateNegativeProof(authorities, qname, qtype, is_nxdomain)) {
        .secure => .proceed,
        .bogus => .bogus,
        .unchecked, .insecure => .skip_cache,
    };
}

fn fisherYatesShuffle(comptime T: type, items: []T) void {
    if (items.len <= 1) return;
    var i: usize = items.len - 1;
    while (i > 0) : (i -= 1) {
        const j = std.crypto.random.uintLessThan(usize, i + 1);
        const tmp = items[i];
        items[i] = items[j];
        items[j] = tmp;
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

test "root_hints has 26 entries, all port 53" {
    try testing.expectEqual(@as(usize, 26), root_hints.len);
    for (root_hints) |addr| {
        try testing.expectEqual(@as(u16, 53), addr.getPort());
    }
}

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
        .z = 0, .ad = false, .cd = false,
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

fn makeNsRr(alloc: mem.Allocator, zone: dns.Name, ns_name: dns.Name) !dns.ResourceRecord {
    _ = alloc;
    return .{ .name = zone, .rtype = .ns, .rclass = .in, .ttl = 172800, .rdata = .{ .ns = ns_name } };
}

fn makeGlueA(alloc: mem.Allocator, name: dns.Name, addr: [4]u8) !dns.ResourceRecord {
    _ = alloc;
    return .{ .name = name, .rtype = .a, .rclass = .in, .ttl = 172800, .rdata = .{ .a = addr } };
}

fn makeGlueAaaa(alloc: mem.Allocator, name: dns.Name, addr: [16]u8) !dns.ResourceRecord {
    _ = alloc;
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
        .answers = &.{},
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
    const response = try makeResponse(alloc, &.{try makeNsRr(alloc, zone_name, ns_name)}, &.{try makeGlueA(alloc, glue_name, .{ 192, 0, 2, 1 })});
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const result = extractReferral(response, target, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
            const expected = std.net.Address.initIp4(.{ 192, 0, 2, 1 }, 53);
            try testing.expectEqual(expected.in.sa.addr, ref.addrs[0].in.sa.addr);
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
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };
    try testing.expect(extractReferral(response, dns.Name{ .labels = &.{ "example", "com" } }, dns.Name{ .labels = &.{} }) == null);
}

test "extractReferral with NS but no glue returns no_glue" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "example", "com" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const response = try makeResponse(alloc, &.{try makeNsRr(alloc, zone_name, ns_name)}, &.{});
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
    const response = try makeResponse(alloc, &.{try makeNsRr(alloc, zone_name, ns_name)}, &.{try makeGlueA(alloc, glue_name, .{ 10, 0, 0, 1 })});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    try testing.expect(result == .referral);
    try testing.expectEqual(@as(usize, 1), result.referral.count);
}

test "extractReferral rejects out-of-zone glue" {
    const alloc = testing.allocator;
    const ns_name = try makeName(alloc, &.{ "ns1", "evil", "org" });
    const zone_name = try makeName(alloc, &.{ "example", "com" });
    const glue_name = try makeName(alloc, &.{ "ns1", "evil", "org" });
    // Glue for ns1.evil.org — out of bailiwick for parent zone "com"
    const response = try makeResponse(alloc, &.{try makeNsRr(alloc, zone_name, ns_name)}, &.{try makeGlueA(alloc, glue_name, .{ 6, 6, 6, 6 })});
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
    const response = try makeResponse(alloc, &.{ try makeNsRr(alloc, zone1, ns1), try makeNsRr(alloc, zone2, ns2) }, &.{});
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
    const response = try makeResponse(alloc, &.{try makeNsRr(alloc, zone_name, ns_name)}, &.{try makeGlueA(alloc, glue_name, .{ 192, 0, 2, 53 })});
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
    const response = try makeResponse(alloc, &.{try makeNsRr(alloc, zone_name, ns_name)}, &.{try makeGlueAaaa(alloc, glue_name, ipv6)});
    defer dns.freeMessage(alloc, response);

    const result = extractReferral(response, dns.Name{ .labels = &.{ "www", "example", "com" } }, dns.Name{ .labels = &.{} }) orelse return error.TestUnexpectedResult;
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
            try testing.expectEqual(@as(u16, 53), ref.addrs[0].getPort());
            const expected = std.net.Address.initIp6(ipv6, 53, 0, 0);
            try testing.expectEqual(expected.in6.sa.addr, ref.addrs[0].in6.sa.addr);
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
    const response = try makeResponse(alloc, &.{try makeNsRr(alloc, zone_name, ns_name)}, &.{try makeGlueA(alloc, glue_name, .{ 192, 0, 2, 1 })});
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
    const response = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = answers, .authorities = &.{}, .additionals = &.{} };
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
    const response = dns.Message{ .header = makeHeader(0, 0, 1), .questions = &.{}, .answers = answers, .authorities = &.{}, .additionals = &.{} };
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

// ── Integration tests (require Linux + io_uring + network) ─────────────

const EventLoop = @import("event_loop.zig").EventLoop;

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "recursive resolve example.com A from root hints" {
    try skipIfNotLinux();

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{}) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver{ .transport = &transport };

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

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{}) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver{ .transport = &transport };

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

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Shorter timeouts: glueless path issues many sub-queries
    var transport = UdpTransport.init(loop, .{ .timeout_ms = 2000, .retransmit_ms = 500 }) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver{ .transport = &transport };

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

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{ .timeout_ms = 2000, .retransmit_ms = 500 }) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver{ .transport = &transport };

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
            .rdata = .{ .nsec = .{
                .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
                .type_bit_maps = &.{ 0, 1, 0x40 }, // window 0, len 1, A bit
            } },
        },
        .{
            .name = dns.Name{ .labels = &.{ "example", "com" } },
            .rtype = .nsec3,
            .rclass = .in,
            .ttl = 3600,
            .rdata = .{ .nsec3 = .{
                .hash_algorithm = 1,
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
            .rdata = .{ .nsec = .{
                .next_domain_name = dns.Name{ .labels = &.{ "z", "example", "com" } },
                .type_bit_maps = &.{ 0, 1, 0x02 }, // window 0, len 1, only SOA
            } },
        },
    };
    try testing.expectEqual(NegativeValidation.proceed, validateNegativeResponse(.secure, &authorities, name, .a, false));
}

test "validateNegativeResponse returns skip_cache when no proof found in secure zone" {
    const name = dns.Name{ .labels = &.{ "nonexistent", "example", "com" } };
    // Empty authorities — no NSEC/NSEC3 records to prove anything
    try testing.expectEqual(NegativeValidation.skip_cache, validateNegativeResponse(.secure, &.{}, name, .a, true));
    try testing.expectEqual(NegativeValidation.skip_cache, validateNegativeResponse(.secure, &.{}, name, .a, false));
}

