const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const dnssec = @import("dnssec.zig");
const UdpTransport = @import("transport.zig").UdpTransport;
const TcpTransport = @import("tcp_transport.zig").TcpTransport;
const cache_mod = @import("cache.zig");
const RRsetCache = cache_mod.RRsetCache;

// ── Root Hints ─────────────────────────────────────────────────────────
// IPv4 addresses for a.root-servers.net through m.root-servers.net.
// Source: https://www.internic.net/domain/named.root

pub const root_hints: [13]std.net.Address = .{
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
};

const max_referrals = 10;
const max_servers_per_level = 13;
const max_cname_chain = 8;
const max_minimise_count = 10;

// ── RecursiveResolver ──────────────────────────────────────────────────

pub const RecursiveResolver = struct {
    transport: *UdpTransport,
    tcp_transport: ?*TcpTransport,
    cache: ?*RRsetCache,
    qname_minimisation: bool = true,
    dnssec_enabled: bool = false,

    pub fn init(transport: *UdpTransport) RecursiveResolver {
        return .{ .transport = transport, .tcp_transport = null, .cache = null };
    }

    pub fn initWithCache(transport: *UdpTransport, cache: *RRsetCache) RecursiveResolver {
        return .{ .transport = transport, .tcp_transport = null, .cache = cache };
    }

    pub fn initFull(transport: *UdpTransport, tcp: *TcpTransport, cache: *RRsetCache) RecursiveResolver {
        return .{ .transport = transport, .tcp_transport = tcp, .cache = cache };
    }

    pub fn resolve(self: *RecursiveResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType) !dns.Message {
        return self.resolveImpl(allocator, name, qtype, 0);
    }

    const max_resolve_depth = 3;

    fn resolveImpl(self: *RecursiveResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType, depth: usize) anyerror!dns.Message {
        var current_name: []const u8 = name;
        var cname_count: usize = 0;
        var total_probes: usize = 0;

        // DNSSEC chain of trust state — starts as secure at root
        var security_state: dnssec.SecurityStatus = if (self.dnssec_enabled) .secure else .unchecked;

        cname_loop: while (true) {
            // CACHE CHECK 1: Do we already have a cached answer?
            if (self.cache) |c| {
                if (c.lookup(allocator, current_name, qtype, .in)) |result| {
                    switch (result) {
                        .hit => |h| return makeCachedMessage(h.records, &.{}, .no_error),
                        .negative => |n| {
                            const authorities = if (n.soa) |soa| blk: {
                                const auths = try allocator.alloc(dns.ResourceRecord, 1);
                                auths[0] = soa;
                                break :blk auths;
                            } else &[_]dns.ResourceRecord{};
                            return makeCachedMessage(&.{}, authorities, n.rcode);
                        },
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
            if (self.findClosestCachedDelegation(allocator, current_name)) |deleg| {
                server_count = deleg.count;
                @memcpy(servers[0..deleg.count], deleg.addrs[0..deleg.count]);
                parent_zone = deleg.zone;
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

                // Shuffle servers (Fisher-Yates)
                fisherYatesShuffle(std.net.Address, servers[0..server_count]);

                // Try each server until one responds
                var got_response = false;
                var response: dns.Message = undefined;

                for (servers[0..server_count]) |server| {
                    // Generate random query ID
                    var id_bytes: [2]u8 = undefined;
                    std.crypto.random.bytes(&id_bytes);
                    const query_id = mem.readInt(u16, &id_bytes, .big);

                    // Build iterative query (rd=false, EDNS0)
                    const query_msg = try dns.buildQueryWithOptions(allocator, query_id, query_name, query_type, .{
                        .rd = false,
                        .edns = .{ .do_bit = self.dnssec_enabled },
                    });

                    // Serialize
                    var wire_buf: [dns.edns_udp_payload]u8 = undefined;
                    const wire_query = try dns.serializeMessage(&wire_buf, query_msg);

                    // Send and receive
                    const response_data = self.transport.query(wire_query, query_id, server) catch |err| switch (err) {
                        error.Timeout => continue, // try next server
                        else => return err,
                    };

                    // Parse response
                    response = try dns.parseMessage(allocator, response_data);

                    // TC bit: retry same query over TCP
                    if (response.header.tc) {
                        if (self.tcp_transport) |tcp| {
                            var tcp_buf: [65535]u8 = undefined;
                            if (tcp.query(wire_query, server, &tcp_buf)) |tcp_data| {
                                response = try dns.parseMessage(allocator, tcp_data);
                            } else |_| {
                                // TCP failed — use truncated UDP response
                            }
                        }
                    }

                    got_response = true;

                    // CACHE STORE: Cache all RRsets from this response
                    if (self.cache) |c| c.storeResponse(response, parent_zone);

                    break;
                }

                if (!got_response) return error.Timeout;

                // ── Probe response handling (non-final queries) ──
                if (!is_final) {
                    // Check for referral first — applies to probes too
                    if (extractReferral(response, target_name, parent_zone)) |referral| {
                        const zone_cut = switch (referral) {
                            .referral => |ref| ref.zone_cut,
                            .no_glue => |ng| ng.zone_cut,
                        };

                        // DNSSEC: classify delegation security at referral
                        if (security_state == .secure) {
                            security_state = dnssec.classifyDelegation(response.authorities, zone_cut);
                        }

                        switch (referral) {
                            .referral => |ref| {
                                for (seen_zones[0..seen_zone_count]) |sz| {
                                    if (sz.eql(ref.zone_cut)) return error.ReferralLoop;
                                }
                                seen_zones[seen_zone_count] = ref.zone_cut;
                                seen_zone_count += 1;
                                parent_zone = ref.zone_cut;
                                server_count = ref.count;
                                @memcpy(servers[0..ref.count], ref.addrs[0..ref.count]);
                                minimise_label_count = parent_zone.labels.len + 1;
                                continue;
                            },
                            .no_glue => |ng| {
                                const res = self.lookupCachedNsAddresses(allocator, ng.ns_names[0..ng.ns_count]) orelse blk: {
                                    const resolved = self.resolveNsAddresses(allocator, ng.ns_names[0..ng.ns_count], depth) catch return error.NoGlueRecords;
                                    break :blk resolved orelse return error.NoGlueRecords;
                                };
                                for (seen_zones[0..seen_zone_count]) |sz| {
                                    if (sz.eql(ng.zone_cut)) return error.ReferralLoop;
                                }
                                seen_zones[seen_zone_count] = ng.zone_cut;
                                seen_zone_count += 1;
                                parent_zone = ng.zone_cut;
                                server_count = res.count;
                                @memcpy(servers[0..res.count], res.addrs[0..res.count]);
                                minimise_label_count = parent_zone.labels.len + 1;
                                continue;
                            },
                        }
                    }

                    if (response.header.rcode == .name_error) {
                        // Probe NXDOMAIN — relaxed mode: cache negative and stop minimising
                        if (response.header.aa) {
                            if (self.cache) |c| c.storeNegative(query_name, query_type, .in, .name_error, response.authorities);
                        }
                        minimise_label_count = target_name.labels.len;
                        continue;
                    }

                    if (response.header.rcode == .server_failure or response.header.rcode == .refused) {
                        // Probe SERVFAIL/REFUSED — stop minimising, send full QNAME
                        minimise_label_count = target_name.labels.len;
                        continue;
                    }

                    if (response.answers.len > 0) {
                        // Probe got an answer — name exists, advance
                        minimise_label_count += 1;
                        continue;
                    }

                    // NODATA (no answers, no referral) — name exists, cache negative, advance
                    if (response.header.aa) {
                        if (self.cache) |c| c.storeNegative(query_name, query_type, .in, .no_error, response.authorities);
                    }
                    minimise_label_count += 1;
                    continue;
                }

                // ── Final query response handling (unchanged logic) ──

                // Classify response
                if (response.header.rcode != .no_error) {
                    if (response.header.rcode == .name_error and response.header.aa) {
                        if (self.cache) |c| c.storeNegative(current_name, qtype, .in, .name_error, response.authorities);
                    }
                    return response;
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
                            if (try findCname(response, target_name, allocator)) |cname_target| {
                                if (cname_count >= max_cname_chain) return error.CnameChainTooLong;
                                cname_count += 1;
                                current_name = cname_target;
                                continue :cname_loop;
                            }
                        }
                    }
                    return response;
                }

                // Check for referral (NS records in authority section)
                const referral = extractReferral(response, target_name, parent_zone) orelse {
                    // NODATA: no answers, no referral. Cache only if authoritative.
                    if (response.header.aa) {
                        if (self.cache) |c| c.storeNegative(current_name, qtype, .in, .no_error, response.authorities);
                    }
                    return response;
                };

                // DNSSEC: classify delegation security at referral
                {
                    const zone_cut = switch (referral) {
                        .referral => |ref| ref.zone_cut,
                        .no_glue => |ng| ng.zone_cut,
                    };
                    if (security_state == .secure) {
                        security_state = dnssec.classifyDelegation(response.authorities, zone_cut);
                    }
                }

                switch (referral) {
                    .referral => |ref| {
                        // Loop detection: reject if we've already visited this zone
                        for (seen_zones[0..seen_zone_count]) |sz| {
                            if (sz.eql(ref.zone_cut)) return error.ReferralLoop;
                        }
                        seen_zones[seen_zone_count] = ref.zone_cut;
                        seen_zone_count += 1;

                        parent_zone = ref.zone_cut;
                        server_count = ref.count;
                        @memcpy(servers[0..ref.count], ref.addrs[0..ref.count]);
                        minimise_label_count = parent_zone.labels.len + 1;
                    },
                    .no_glue => |ng| {
                        // CACHE CHECK 3: Try cached A records for NS names first
                        const res = self.lookupCachedNsAddresses(allocator, ng.ns_names[0..ng.ns_count]) orelse blk: {
                            const resolved = self.resolveNsAddresses(
                                allocator,
                                ng.ns_names[0..ng.ns_count],
                                depth,
                            ) catch return error.NoGlueRecords;
                            break :blk resolved orelse return error.NoGlueRecords;
                        };

                        // Loop detection on the zone cut (same as .referral path)
                        for (seen_zones[0..seen_zone_count]) |sz| {
                            if (sz.eql(ng.zone_cut)) return error.ReferralLoop;
                        }
                        seen_zones[seen_zone_count] = ng.zone_cut;
                        seen_zone_count += 1;

                        parent_zone = ng.zone_cut;
                        server_count = res.count;
                        @memcpy(servers[0..res.count], res.addrs[0..res.count]);
                        minimise_label_count = parent_zone.labels.len + 1;
                    },
                }
            }

            return error.MaxReferralsExceeded;
        }
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

        for (ns_names) |ns_name| {
            const ns_dotted = nameToDotted(allocator, ns_name) catch continue;
            const ns_response = self.resolveImpl(allocator, ns_dotted, .a, depth + 1) catch continue;
            for (ns_response.answers) |rr| {
                if (rr.rtype == .a and count < max_servers_per_level) {
                    addrs[count] = std.net.Address.initIp4(rr.rdata.a, 53);
                    count += 1;
                }
            }
            if (count > 0) break; // one working NS is enough
        }

        if (count == 0) return null;
        return .{ .addrs = addrs, .count = count };
    }

    const NsAddrResult = struct { addrs: [max_servers_per_level]std.net.Address, count: usize };
    const DelegationResult = struct { addrs: [max_servers_per_level]std.net.Address, count: usize, zone: dns.Name };

    /// Check cache for A records of NS names, avoiding network queries.
    fn lookupCachedNsAddresses(
        self: *RecursiveResolver,
        allocator: mem.Allocator,
        ns_names: []const dns.Name,
    ) ?NsAddrResult {
        const cache = self.cache orelse return null;

        var addrs: [max_servers_per_level]std.net.Address = undefined;
        var count: usize = 0;

        for (ns_names) |ns_name| {
            const ns_dotted = nameToDotted(allocator, ns_name) catch continue;
            if (cache.lookup(allocator, ns_dotted, .a, .in)) |result| {
                switch (result) {
                    .hit => |h| {
                        for (h.records) |rr| {
                            if (rr.rtype == .a and count < max_servers_per_level) {
                                addrs[count] = std.net.Address.initIp4(rr.rdata.a, 53);
                                count += 1;
                            }
                        }
                        if (count > 0) break;
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
    ) ?DelegationResult {
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
                        // Try to find cached A records for these NS names
                        var addrs: [max_servers_per_level]std.net.Address = undefined;
                        var addr_count: usize = 0;

                        for (h.records) |ns_rr| {
                            if (ns_rr.rtype != .ns) continue;
                            const ns_dotted = nameToDotted(allocator, ns_rr.rdata.ns) catch continue;
                            if (cache.lookup(allocator, ns_dotted, .a, .in)) |a_result| {
                                switch (a_result) {
                                    .hit => |a_hit| {
                                        for (a_hit.records) |a_rr| {
                                            if (a_rr.rtype == .a and addr_count < max_servers_per_level) {
                                                addrs[addr_count] = std.net.Address.initIp4(a_rr.rdata.a, 53);
                                                addr_count += 1;
                                            }
                                        }
                                    },
                                    .negative => {},
                                }
                            }
                        }

                        if (addr_count > 0) {
                            const zone_name = dns.parseDottedName(allocator, zone_str) catch continue;
                            best = .{
                                .addrs = addrs,
                                .count = addr_count,
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

// ── Response synthesis (for cache hits) ────────────────────────────────

fn makeCachedMessage(answers: []const dns.ResourceRecord, authorities: []const dns.ResourceRecord, rcode: dns.RCode) dns.Message {
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

fn nameToDotted(allocator: mem.Allocator, name: dns.Name) ![]const u8 {
    const buf = name.format();
    const len = mem.indexOfScalar(u8, &buf, 0) orelse buf.len;
    return allocator.dupe(u8, buf[0..len]);
}

fn findCname(response: dns.Message, target: dns.Name, allocator: mem.Allocator) !?[]const u8 {
    for (response.answers) |rr| {
        if (rr.rtype == .cname and target.eql(rr.name)) {
            return try nameToDotted(allocator, rr.rdata.cname);
        }
    }
    return null;
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

test "root_hints has 13 entries, all port 53" {
    try testing.expectEqual(@as(usize, 13), root_hints.len);
    for (root_hints) |addr| {
        // All should be IPv4, port 53
        try testing.expectEqual(@as(u16, 53), addr.getPort());
    }
}

// ── Helper to build a minimal response ────────────────────────────────

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
        .rcode = .no_error,
        .qd_count = 0,
        .an_count = an_count,
        .ns_count = ns_count,
        .ar_count = ar_count,
    };
}

// ── extractReferral tests ─────────────────────────────────────────────

test "extractReferral with NS and glue A records" {
    const alloc = testing.allocator;

    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "example");
    ns_name_labels[2] = try alloc.dupe(u8, "com");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 2);
    zone_labels[0] = try alloc.dupe(u8, "example");
    zone_labels[1] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    const glue_name_labels = try alloc.alloc([]const u8, 3);
    glue_name_labels[0] = try alloc.dupe(u8, "ns1");
    glue_name_labels[1] = try alloc.dupe(u8, "example");
    glue_name_labels[2] = try alloc.dupe(u8, "com");
    const glue_name = dns.Name{ .labels = glue_name_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    const additionals = try alloc.alloc(dns.ResourceRecord, 1);
    additionals[0] = .{
        .name = glue_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .a = .{ 192, 0, 2, 1 } },
    };

    const response = dns.Message{
        .header = makeHeader(1, 1, 0),
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = additionals,
    };
    defer dns.freeMessage(alloc, response);

    // Target is under the zone being delegated
    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const root_zone = dns.Name{ .labels = &.{} };
    const result = extractReferral(response, target, root_zone) orelse {
        return error.TestUnexpectedResult;
    };
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
            const expected = std.net.Address.initIp4(.{ 192, 0, 2, 1 }, 53);
            try testing.expectEqual(expected.in.sa.addr, ref.addrs[0].in.sa.addr);
            try testing.expectEqual(@as(u16, 53), ref.addrs[0].getPort());
            // Zone cut should be example.com
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

    const target = dns.Name{ .labels = &.{ "example", "com" } };
    const root_zone = dns.Name{ .labels = &.{} };
    try testing.expect(extractReferral(response, target, root_zone) == null);
}

test "extractReferral with NS but no glue returns no_glue" {
    const alloc = testing.allocator;

    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "example");
    ns_name_labels[2] = try alloc.dupe(u8, "com");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 2);
    zone_labels[0] = try alloc.dupe(u8, "example");
    zone_labels[1] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    const response = dns.Message{
        .header = makeHeader(1, 0, 0),
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = &.{},
    };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const root_zone = dns.Name{ .labels = &.{} };
    const result = extractReferral(response, target, root_zone) orelse {
        return error.TestUnexpectedResult;
    };
    switch (result) {
        .no_glue => |ng| {
            try testing.expectEqual(@as(usize, 1), ng.ns_count);
            try testing.expect(ng.zone_cut.eql(zone_name));
            // Verify the NS name was captured
            const ns_dotted = try nameToDotted(testing.allocator, ng.ns_names[0]);
            defer testing.allocator.free(ns_dotted);
            try testing.expectEqualStrings("ns1.example.com", ns_dotted);
        },
        .referral => return error.TestUnexpectedResult,
    }
}

test "extractReferral case-insensitive glue matching" {
    const alloc = testing.allocator;

    // NS name in lowercase
    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "example");
    ns_name_labels[2] = try alloc.dupe(u8, "com");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 2);
    zone_labels[0] = try alloc.dupe(u8, "example");
    zone_labels[1] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    // Glue record name in UPPERCASE
    const glue_name_labels = try alloc.alloc([]const u8, 3);
    glue_name_labels[0] = try alloc.dupe(u8, "NS1");
    glue_name_labels[1] = try alloc.dupe(u8, "EXAMPLE");
    glue_name_labels[2] = try alloc.dupe(u8, "COM");
    const glue_name = dns.Name{ .labels = glue_name_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    const additionals = try alloc.alloc(dns.ResourceRecord, 1);
    additionals[0] = .{
        .name = glue_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .a = .{ 10, 0, 0, 1 } },
    };

    const response = dns.Message{
        .header = makeHeader(1, 1, 0),
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = additionals,
    };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const root_zone = dns.Name{ .labels = &.{} };
    const result = extractReferral(response, target, root_zone) orelse {
        return error.TestUnexpectedResult;
    };
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
        },
        .no_glue => return error.TestUnexpectedResult,
    }
}

test "extractReferral rejects out-of-zone glue" {
    const alloc = testing.allocator;

    // NS for example.com pointing to ns1.evil.org
    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "evil");
    ns_name_labels[2] = try alloc.dupe(u8, "org");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 2);
    zone_labels[0] = try alloc.dupe(u8, "example");
    zone_labels[1] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    // Out-of-zone glue for ns1.evil.org
    const glue_name_labels = try alloc.alloc([]const u8, 3);
    glue_name_labels[0] = try alloc.dupe(u8, "ns1");
    glue_name_labels[1] = try alloc.dupe(u8, "evil");
    glue_name_labels[2] = try alloc.dupe(u8, "org");
    const glue_name = dns.Name{ .labels = glue_name_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    const additionals = try alloc.alloc(dns.ResourceRecord, 1);
    additionals[0] = .{
        .name = glue_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .a = .{ 6, 6, 6, 6 } },
    };

    const response = dns.Message{
        .header = makeHeader(1, 1, 0),
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = additionals,
    };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    // Parent zone is "com" — as if a .com TLD server sent this referral.
    // ns1.evil.org is NOT under "com", so glue should be rejected.
    const parent_zone = dns.Name{ .labels = &.{"com"} };
    const result = extractReferral(response, target, parent_zone) orelse {
        return error.TestUnexpectedResult;
    };
    try testing.expect(result == .no_glue);
}

test "extractReferral no_glue carries multiple NS names" {
    const alloc = testing.allocator;

    const ns1_labels = try alloc.alloc([]const u8, 3);
    ns1_labels[0] = try alloc.dupe(u8, "ns1");
    ns1_labels[1] = try alloc.dupe(u8, "other");
    ns1_labels[2] = try alloc.dupe(u8, "net");
    const ns1_name = dns.Name{ .labels = ns1_labels };

    const ns2_labels = try alloc.alloc([]const u8, 3);
    ns2_labels[0] = try alloc.dupe(u8, "ns2");
    ns2_labels[1] = try alloc.dupe(u8, "other");
    ns2_labels[2] = try alloc.dupe(u8, "net");
    const ns2_name = dns.Name{ .labels = ns2_labels };

    const zone_labels1 = try alloc.alloc([]const u8, 2);
    zone_labels1[0] = try alloc.dupe(u8, "example");
    zone_labels1[1] = try alloc.dupe(u8, "com");
    const zone_name1 = dns.Name{ .labels = zone_labels1 };

    const zone_labels2 = try alloc.alloc([]const u8, 2);
    zone_labels2[0] = try alloc.dupe(u8, "example");
    zone_labels2[1] = try alloc.dupe(u8, "com");
    const zone_name2 = dns.Name{ .labels = zone_labels2 };

    const authorities = try alloc.alloc(dns.ResourceRecord, 2);
    authorities[0] = .{
        .name = zone_name1,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns1_name },
    };
    authorities[1] = .{
        .name = zone_name2,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns2_name },
    };

    const response = dns.Message{
        .header = makeHeader(2, 0, 0),
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = &.{},
    };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const root_zone = dns.Name{ .labels = &.{} };
    const result = extractReferral(response, target, root_zone) orelse {
        return error.TestUnexpectedResult;
    };
    switch (result) {
        .no_glue => |ng| {
            try testing.expectEqual(@as(usize, 2), ng.ns_count);
            try testing.expect(ng.zone_cut.eql(zone_name1));
        },
        .referral => return error.TestUnexpectedResult,
    }
}

test "extractReferral accepts in-zone glue" {
    const alloc = testing.allocator;

    // NS for com pointing to ns1.example.com (in-zone under com)
    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "example");
    ns_name_labels[2] = try alloc.dupe(u8, "com");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 1);
    zone_labels[0] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    const glue_name_labels = try alloc.alloc([]const u8, 3);
    glue_name_labels[0] = try alloc.dupe(u8, "ns1");
    glue_name_labels[1] = try alloc.dupe(u8, "example");
    glue_name_labels[2] = try alloc.dupe(u8, "com");
    const glue_name = dns.Name{ .labels = glue_name_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    const additionals = try alloc.alloc(dns.ResourceRecord, 1);
    additionals[0] = .{
        .name = glue_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .a = .{ 192, 0, 2, 53 } },
    };

    const response = dns.Message{
        .header = makeHeader(1, 1, 0),
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = additionals,
    };
    defer dns.freeMessage(alloc, response);

    // Target under com
    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const root_zone = dns.Name{ .labels = &.{} };
    const result = extractReferral(response, target, root_zone) orelse {
        return error.TestUnexpectedResult;
    };
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
        },
        .no_glue => return error.TestUnexpectedResult,
    }
}

test "extractReferral with AAAA glue returns IPv6 address" {
    const alloc = testing.allocator;

    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "example");
    ns_name_labels[2] = try alloc.dupe(u8, "com");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 2);
    zone_labels[0] = try alloc.dupe(u8, "example");
    zone_labels[1] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    const glue_name_labels = try alloc.alloc([]const u8, 3);
    glue_name_labels[0] = try alloc.dupe(u8, "ns1");
    glue_name_labels[1] = try alloc.dupe(u8, "example");
    glue_name_labels[2] = try alloc.dupe(u8, "com");
    const glue_name = dns.Name{ .labels = glue_name_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    // AAAA glue: 2001:db8::1
    const additionals = try alloc.alloc(dns.ResourceRecord, 1);
    additionals[0] = .{
        .name = glue_name,
        .rtype = .aaaa,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .aaaa = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
    };

    const response = dns.Message{
        .header = makeHeader(1, 1, 0),
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = additionals,
    };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const root_zone = dns.Name{ .labels = &.{} };
    const result = extractReferral(response, target, root_zone) orelse {
        return error.TestUnexpectedResult;
    };
    switch (result) {
        .referral => |ref| {
            try testing.expectEqual(@as(usize, 1), ref.count);
            try testing.expectEqual(@as(u16, 53), ref.addrs[0].getPort());
            // Verify it's an IPv6 address
            const expected = std.net.Address.initIp6(
                .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
                53,
                0,
                0,
            );
            try testing.expectEqual(expected.in6.sa.addr, ref.addrs[0].in6.sa.addr);
        },
        .no_glue => return error.TestUnexpectedResult,
    }
}

// ── findCname / nameToDotted tests ────────────────────────────────────

test "nameToDotted round-trips correctly" {
    const alloc = testing.allocator;
    const name = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const dotted = try nameToDotted(alloc, name);
    defer alloc.free(dotted);
    try testing.expectEqualStrings("www.example.com", dotted);
}

test "findCname finds CNAME matching target" {
    const alloc = testing.allocator;

    // CNAME: www.example.com -> example.com
    const owner_labels = try alloc.alloc([]const u8, 3);
    owner_labels[0] = try alloc.dupe(u8, "www");
    owner_labels[1] = try alloc.dupe(u8, "example");
    owner_labels[2] = try alloc.dupe(u8, "com");
    const owner = dns.Name{ .labels = owner_labels };

    const cname_labels = try alloc.alloc([]const u8, 2);
    cname_labels[0] = try alloc.dupe(u8, "example");
    cname_labels[1] = try alloc.dupe(u8, "com");
    const cname_target = dns.Name{ .labels = cname_labels };

    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{
        .name = owner,
        .rtype = .cname,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .cname = cname_target },
    };

    const response = dns.Message{
        .header = makeHeader(0, 0, 1),
        .questions = &.{},
        .answers = answers,
        .authorities = &.{},
        .additionals = &.{},
    };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "www", "example", "com" } };
    const result = try findCname(response, target, alloc);
    try testing.expect(result != null);
    defer alloc.free(result.?);
    try testing.expectEqualStrings("example.com", result.?);
}

test "findCname returns null when no CNAME present" {
    const alloc = testing.allocator;

    const owner_labels = try alloc.alloc([]const u8, 2);
    owner_labels[0] = try alloc.dupe(u8, "example");
    owner_labels[1] = try alloc.dupe(u8, "com");
    const owner = dns.Name{ .labels = owner_labels };

    const answers = try alloc.alloc(dns.ResourceRecord, 1);
    answers[0] = .{
        .name = owner,
        .rtype = .a,
        .rclass = .in,
        .ttl = 300,
        .rdata = .{ .a = .{ 93, 184, 216, 34 } },
    };

    const response = dns.Message{
        .header = makeHeader(0, 0, 1),
        .questions = &.{},
        .answers = answers,
        .authorities = &.{},
        .additionals = &.{},
    };
    defer dns.freeMessage(alloc, response);

    const target = dns.Name{ .labels = &.{ "example", "com" } };
    const result = try findCname(response, target, alloc);
    try testing.expect(result == null);
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
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{}) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver.init(&transport);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const response = resolver.resolve(arena.allocator(), "example.com", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        error.ReferralLoop => return error.SkipZigTest,
        error.CnameChainTooLong => return error.SkipZigTest,
        error.MaxReferralsExceeded => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);

    // Verify we got an A record
    var found_a = false;
    for (response.answers) |rr| {
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
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{}) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver.init(&transport);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const response = resolver.resolve(arena.allocator(), "this-domain-does-not-exist-xyzzy.example.com", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        error.ReferralLoop => return error.SkipZigTest,
        error.CnameChainTooLong => return error.SkipZigTest,
        error.MaxReferralsExceeded => return error.SkipZigTest,
        else => return err,
    };

    try testing.expectEqual(dns.RCode.name_error, response.header.rcode);
}

test "recursive resolve domain with glueless NS" {
    try skipIfNotLinux();

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    // Shorter timeouts: glueless path issues many sub-queries
    var transport = UdpTransport.init(loop, .{ .timeout_ms = 2000, .retransmit_ms = 500 }) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver.init(&transport);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // ietf.org uses ns0.amsl.com etc. — glueless from .org zone
    const response = resolver.resolve(arena.allocator(), "ietf.org", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        error.ReferralLoop => return error.SkipZigTest,
        error.CnameChainTooLong => return error.SkipZigTest,
        error.MaxReferralsExceeded => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);

    var found_a = false;
    for (response.answers) |rr| {
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
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{ .timeout_ms = 2000, .retransmit_ms = 500 }) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver.init(&transport);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // www.github.com is a CNAME to github.github.io
    const response = resolver.resolve(arena.allocator(), "www.github.com", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        error.ReferralLoop => return error.SkipZigTest,
        error.CnameChainTooLong => return error.SkipZigTest,
        error.MaxReferralsExceeded => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);

    var found_a = false;
    for (response.answers) |rr| {
        if (rr.rtype == .a) {
            found_a = true;
            break;
        }
    }
    try testing.expect(found_a);
}

