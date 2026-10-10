const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const maxInt = std.math.maxInt;
const Allocator = mem.Allocator;
const toml = @import("toml.zig");
const net_addr = @import("net_address.zig");
const Address = net_addr.Address;
const acl = @import("acl.zig");
const dns = @import("dns.zig");
const rebinding = @import("rebinding.zig");
const dns64 = @import("dns64.zig");
const dnssec = @import("dnssec.zig");
const delegation = @import("delegation.zig");
const special_use = @import("special_use.zig");
const stub = @import("stub.zig");
const build_options = @import("build_options");

/// Error variants can't carry the offending key name, so log it at rejection
/// time. Silent under test: the schema tests trigger these intentionally and
/// the test runner fails on error-level logs.
fn errLog(comptime fmt: []const u8, args: anytype) void {
    if (@import("builtin").is_test) return;
    std.log.err(fmt, args);
}

// IPv4 + IPv6 addresses for a.root-servers.net through m.root-servers.net.
// Source: https://www.internic.net/domain/named.root

const root_hints_default: [26]Address = .{
    net_addr.initIp4(.{ 198, 41, 0, 4 }, 53), // a
    net_addr.initIp4(.{ 170, 247, 170, 2 }, 53), // b
    net_addr.initIp4(.{ 192, 33, 4, 12 }, 53), // c
    net_addr.initIp4(.{ 199, 7, 91, 13 }, 53), // d
    net_addr.initIp4(.{ 192, 203, 230, 10 }, 53), // e
    net_addr.initIp4(.{ 192, 5, 5, 241 }, 53), // f
    net_addr.initIp4(.{ 192, 112, 36, 4 }, 53), // g
    net_addr.initIp4(.{ 198, 97, 190, 53 }, 53), // h
    net_addr.initIp4(.{ 192, 36, 148, 17 }, 53), // i
    net_addr.initIp4(.{ 192, 58, 128, 30 }, 53), // j
    net_addr.initIp4(.{ 193, 0, 14, 129 }, 53), // k
    net_addr.initIp4(.{ 199, 7, 83, 42 }, 53), // l
    net_addr.initIp4(.{ 202, 12, 27, 33 }, 53), // m
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x03, 0xba, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 }, 53, 0, 0), // a
    net_addr.initIp6(.{ 0x28, 0x01, 0x01, 0xb8, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b }, 53, 0, 0), // b
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c }, 53, 0, 0), // c
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x2d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d }, 53, 0, 0), // d
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e }, 53, 0, 0), // e
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x2f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f }, 53, 0, 0), // f
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x0d }, 53, 0, 0), // g
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, 53, 0, 0), // h
    net_addr.initIp6(.{ 0x20, 0x01, 0x07, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, 53, 0, 0), // i
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x03, 0x0c, 0x27, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 }, 53, 0, 0), // j
    net_addr.initIp6(.{ 0x20, 0x01, 0x07, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 53, 0, 0), // k
    net_addr.initIp6(.{ 0x20, 0x01, 0x05, 0x00, 0, 0x9f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 }, 53, 0, 0), // l
    net_addr.initIp6(.{ 0x20, 0x01, 0x0d, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35 }, 53, 0, 0), // m
};

/// Each default is the value `hark.toml.example` shows.
pub const ServerConfig = struct {
    listen: []const Address = &.{ net_addr.initIp4(.{ 127, 0, 0, 1 }, 53), net_addr.initIp6(@as([15]u8, @splat(0)) ++ [_]u8{1}, 53, 0, 0) },
    /// Empty: the IANA roots.
    root_hints: []const Address = &.{},
    /// Where glue points. Test-only: production always asks port 53.
    upstream_port: u16 = 53,
    /// Lets upstreams sit on 127/8. Test-only.
    allow_loopback_upstreams: bool = false,
    stub_zones: []const stub.Zone = &.{},
    cache_size: usize = 12 * 1024 * 1024,
    prefetch: bool = false,
    serve_stale_ttl: u32 = 0,
    min_ttl: u32 = 0,
    /// The first window a failed question is answered from memory (RFC 9520 §3.2).
    servfail_ttl: u32 = 5,
    dnssec: bool = true,
    qname_minimization: bool = true,
    dns64: ?dns64.Prefix = null,
    stagger_ms: u32 = 150,
    /// Upstream exchanges one resolution may spend.
    max_queries: u32 = 100,
    log_queries: bool = false,
    max_udp_payload: u16 = dns.edns_udp_payload,
    /// Numeric: names would need NSS.
    drop_uid: ?u32 = null,
    drop_gid: ?u32 = null,
    /// BCP 140: empty allows every client, which off loopback is an open resolver.
    allow_from: []const acl.Cidr = &.{},
    /// Only what answers the question: the answer, SOA on negatives, and
    /// DNSSEC proofs under DO (`answer.zig:Keep`).
    minimal_responses: bool = true,
    /// RFC 7766 §6.2.3.
    tcp_idle_timeout_ms: u32 = 5_000,
    tcp_queries_per_conn: u32 = 128,
    /// Empty: the IANA root anchors. Test-only.
    trust_anchors: []const dns.DsData = &.{},
    rebinding: rebinding.Config = .{ .enabled = true, .allow_zones = &.{}, .extra_block = &.{}, .extra_allow = &.{} },
    /// Owns every slice above.
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *ServerConfig) void {
        self.arena.deinit();
    }

    pub fn rootHints(self: ServerConfig) []const Address {
        return if (self.root_hints.len > 0) self.root_hints else &root_hints_default;
    }

    pub fn addrPolicy(self: ServerConfig) delegation.AddrPolicy {
        return .{ .upstream_port = self.upstream_port, .allow_loopback = self.allow_loopback_upstreams };
    }

    /// A production build has only the IANA anchors.
    pub fn trustAnchors(self: ServerConfig) []const dns.DsData {
        if (comptime !build_options.testing_enabled) return &dnssec.root_ds_records;
        return if (self.trust_anchors.len > 0) self.trust_anchors else &dnssec.root_ds_records;
    }
};

const ConfigError = error{
    InvalidListenAddress,
    InvalidRootHintAddress,
    TooManyRootHints,
    InvalidValue,
    InvalidAclEntry,
    /// Operator set a key gated behind `-Dtesting=true` in a production build.
    TestOnlyConfigKey,
    /// Key or section not in the schema — almost always a typo. Fail loud
    /// rather than silently serve with the default.
    UnknownConfigKey,
    ConfigFileTooLarge,
    OutOfMemory,
};

// ── Schema ─────────────────────────────────────────────────────────────
// Every key the parser reads, with its expected TOML type — validated before
// parsing so a typo'd key or wrong-typed value (`dnssec = "true"`) errors
// instead of silently keeping the default. Test-only keys are listed too;
// their `-Dtesting` gate stays in the parser for the distinct error.

const KeySpec = struct { name: []const u8, kind: std.meta.Tag(toml.Value) };
const SectionSpec = struct { name: []const u8, keys: []const KeySpec };

const config_schema = [_]SectionSpec{
    .{ .name = "server", .keys = &.{
        .{ .name = "listen", .kind = .string_array },
        .{ .name = "max-udp-payload", .kind = .integer },
        .{ .name = "user", .kind = .integer },
        .{ .name = "group", .kind = .integer },
        .{ .name = "allow-from", .kind = .string_array },
        .{ .name = "tcp-idle-timeout-ms", .kind = .integer },
        .{ .name = "tcp-queries-per-conn", .kind = .integer },
        .{ .name = "minimal-responses", .kind = .boolean },
    } },
    .{ .name = "resolver", .keys = &.{
        .{ .name = "root-hints", .kind = .string_array },
        .{ .name = "stub-zones", .kind = .string_array },
        .{ .name = "upstream-port", .kind = .integer },
        .{ .name = "allow-loopback-upstreams", .kind = .boolean },
        .{ .name = "trust-anchors", .kind = .string_array },
        .{ .name = "dnssec", .kind = .boolean },
        .{ .name = "qname-minimization", .kind = .boolean },
        .{ .name = "dns64-prefix", .kind = .string },
        .{ .name = "stagger-ms", .kind = .integer },
        .{ .name = "max-queries", .kind = .integer },
    } },
    .{ .name = "cache", .keys = &.{
        .{ .name = "size", .kind = .integer },
        .{ .name = "prefetch", .kind = .boolean },
        .{ .name = "serve-stale-ttl", .kind = .integer },
        .{ .name = "min-ttl", .kind = .integer },
        .{ .name = "servfail-ttl", .kind = .integer },
    } },
    .{ .name = "logging", .keys = &.{
        .{ .name = "queries", .kind = .boolean },
    } },
    .{ .name = "rebinding", .keys = &.{
        .{ .name = "enabled", .kind = .boolean },
        .{ .name = "allow-zones", .kind = .string_array },
        .{ .name = "extra-block", .kind = .string_array },
        .{ .name = "extra-allow", .kind = .string_array },
    } },
};

fn validateSchema(root: toml.Table) ConfigError!void {
    var sections = root.map.iterator();
    while (sections.next()) |entry| {
        const section_name = entry.key_ptr.*;
        const spec = for (config_schema) |s| {
            if (mem.eql(u8, s.name, section_name)) break s;
        } else {
            errLog("config: unknown section [{s}]", .{section_name});
            return error.UnknownConfigKey;
        };
        const table = switch (entry.value_ptr.*) {
            .table => |t| t,
            else => {
                errLog("config: top-level key '{s}' — every setting lives under a [section]", .{section_name});
                return error.UnknownConfigKey;
            },
        };
        var keys = table.map.iterator();
        while (keys.next()) |kv| {
            const key = kv.key_ptr.*;
            const kspec = for (spec.keys) |k| {
                if (mem.eql(u8, k.name, key)) break k;
            } else {
                errLog("config: unknown key '{s}' in [{s}]", .{ key, section_name });
                return error.UnknownConfigKey;
            };
            if (kv.value_ptr.* != kspec.kind) {
                errLog("config: [{s}] {s} expects {s}, got {s}", .{
                    section_name, key, @tagName(kspec.kind), @tagName(kv.value_ptr.*),
                });
                return error.InvalidValue;
            }
        }
    }
}

/// Refused outside `min` to `max`, never clamped: `stagger-ms = 5000` meant
/// five seconds to whoever wrote it.
fn integer(comptime T: type, table: toml.Table, key: []const u8, min: T, max: T) ConfigError!?T {
    const v = table.get(key, .integer) orelse return null;
    if (v < min or v > max) {
        errLog("config: {s} must be {d} to {d}, got {d}", .{ key, min, max, v });
        return error.InvalidValue;
    }
    return @intCast(v);
}

/// Neither `(uid_t)-1` (setresuid's "leave unchanged" sentinel) nor 0 is an id
/// worth dropping to; both make the drop a no-op that reports success.
fn credential(table: toml.Table, key: []const u8) ConfigError!?u32 {
    const v = try integer(u32, table, key, 0, maxInt(u32)) orelse return null;
    if (v == maxInt(u32)) {
        errLog("config: {s} must be a real id, got the 'unchanged' sentinel {d}", .{ key, v });
        return error.InvalidValue;
    }
    // 0 reaches the same no-op by a likelier route than the sentinel: a
    // template substituting an unset variable. Dropping *to* root is not
    // something these keys can express; omitting them is how you stay put.
    if (v == 0) {
        errLog("config: {s} must not be 0 — omit the key to run as the current user", .{key});
        return error.InvalidValue;
    }
    return v;
}

pub fn parseConfig(gpa: Allocator, contents: []const u8) (toml.ParseError || ConfigError)!ServerConfig {
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    const root = try toml.parse(scratch.allocator(), contents);

    try validateSchema(root);

    var cfg: ServerConfig = .{ .arena = .init(gpa) };
    errdefer cfg.deinit();
    const arena = cfg.arena.allocator();

    if (root.get("server", .table)) |server| {
        if (server.get("listen", .string_array)) |addrs| cfg.listen = try parseAddressList(arena, addrs, error.InvalidListenAddress);
        if (try integer(u16, server, "max-udp-payload", dns.max_udp_payload, dns.max_message_len)) |v| cfg.max_udp_payload = v;
        if (try credential(server, "user")) |u| cfg.drop_uid = u;
        if (try credential(server, "group")) |g| cfg.drop_gid = g;
        if (server.get("allow-from", .string_array)) |entries| cfg.allow_from = try parseCidrList(arena, entries);
        // RFC 7828 §3.1: the keepalive TIMEOUT is a u16 of 100 ms units.
        if (try integer(u32, server, "tcp-idle-timeout-ms", 0, maxInt(u16) * 100)) |v| cfg.tcp_idle_timeout_ms = v;
        if (try integer(u32, server, "tcp-queries-per-conn", 1, maxInt(u32))) |v| cfg.tcp_queries_per_conn = v;
        if (server.get("minimal-responses", .boolean)) |m| cfg.minimal_responses = m;
    }

    if (root.get("resolver", .table)) |resolver| {
        if (resolver.get("root-hints", .string_array)) |addrs| {
            cfg.root_hints = try parseAddressList(arena, addrs, error.InvalidRootHintAddress);
            const max_hints = delegation.max_servers_per_level;
            if (addrs.len > max_hints) {
                errLog("config: root-hints holds at most {d} addresses, got {d}", .{ max_hints, addrs.len });
                return error.TooManyRootHints;
            }
        }
        if (resolver.get("stub-zones", .string_array)) |entries| cfg.stub_zones = try parseStubZones(arena, entries);
        // Test-only knobs: a production binary refuses the key.
        if (resolver.get("upstream-port", .integer)) |p| {
            if (!build_options.testing_enabled) return error.TestOnlyConfigKey;
            if (p < 1 or p > 65535) return error.InvalidValue;
            cfg.upstream_port = @intCast(p);
        }
        if (resolver.get("allow-loopback-upstreams", .boolean)) |b| {
            if (!build_options.testing_enabled) return error.TestOnlyConfigKey;
            cfg.allow_loopback_upstreams = b;
        }
        if (resolver.get("trust-anchors", .string_array)) |entries| {
            if (!build_options.testing_enabled) return error.TestOnlyConfigKey;
            cfg.trust_anchors = try parseTrustAnchors(arena, entries);
        }
        if (resolver.get("dnssec", .boolean)) |d| cfg.dnssec = d;
        if (resolver.get("qname-minimization", .boolean)) |q| cfg.qname_minimization = q;
        if (resolver.get("dns64-prefix", .string)) |s| if (s.len > 0) {
            cfg.dns64 = dns64.Prefix.parse(s) orelse {
                errLog("config: dns64-prefix '{s}' is not an IPv6 /32, /40, /48, /56, /64 or /96 (RFC 6052 §2.2)", .{s});
                return error.InvalidValue;
            };
        };
        // Past a second, most stubs have given up.
        if (try integer(u32, resolver, "stagger-ms", 0, 1000)) |v| cfg.stagger_ms = v;
        if (try integer(u32, resolver, "max-queries", 1, maxInt(u32))) |v| cfg.max_queries = v;
    }

    if (root.get("cache", .table)) |cache| {
        if (try integer(usize, cache, "size", 1, maxInt(usize))) |v| cfg.cache_size = v;
        if (cache.get("prefetch", .boolean)) |p| cfg.prefetch = p;
        if (try integer(u32, cache, "serve-stale-ttl", 0, maxInt(u32))) |v| cfg.serve_stale_ttl = v;
        if (try integer(u32, cache, "min-ttl", 0, maxInt(u32))) |v| cfg.min_ttl = v;
        // RFC 9520 §3.2: a failure is remembered no longer than 5 minutes.
        if (try integer(u32, cache, "servfail-ttl", 0, 300)) |v| cfg.servfail_ttl = v;
    }

    if (root.get("logging", .table)) |logging| {
        if (logging.get("queries", .boolean)) |q| cfg.log_queries = q;
    }

    if (root.get("rebinding", .table)) |reb| {
        if (reb.get("enabled", .boolean)) |b| cfg.rebinding.enabled = b;
        if (reb.get("allow-zones", .string_array)) |entries| cfg.rebinding.allow_zones = try parseZoneList(arena, entries);
        if (reb.get("extra-block", .string_array)) |entries| cfg.rebinding.extra_block = try parseCidrList(arena, entries);
        if (reb.get("extra-allow", .string_array)) |entries| cfg.rebinding.extra_allow = try parseCidrList(arena, entries);
    }

    cfg.rebinding.nat64 = cfg.dns64;

    // Told servers skip the ask's policy, so the root's are held to it
    // here: a private root hint is a footgun, not a steer. Loopback ones
    // only if the operator opted in (tests do).
    for (cfg.root_hints) |addr| if (!cfg.addrPolicy().allows(addr)) return error.InvalidRootHintAddress;

    // hark recurses for any question: a stub server that is hark itself
    // asks hark, which asks hark.
    for (cfg.stub_zones) |z| for (z.servers) |server| for (cfg.listen) |l| if (reaches(l, server)) {
        errLog("config: stub-zones names an address hark itself listens on", .{});
        return error.InvalidValue;
    };

    return cfg;
}

/// A socket bound to `l` would take a query sent to `to`: the same address,
/// or, bound to the family's wildcard, one certain to be this host's. Each
/// family listens apart (IPV6_V6ONLY).
fn reaches(l: Address, to: Address) bool {
    if (l.getPort() != to.getPort()) return false;
    if (net_addr.ipEqual(l, to)) return true;
    return switch (l) {
        .ip4 => |b| to == .ip4 and mem.allEqual(u8, &b.bytes, 0) and (to.ip4.bytes[0] == 127 or mem.allEqual(u8, &to.ip4.bytes, 0)),
        .ip6 => |b| to == .ip6 and mem.allEqual(u8, &b.bytes, 0) and mem.allEqual(u8, to.ip6.bytes[0..15], 0) and to.ip6.bytes[15] <= 1,
    };
}

pub fn parseConfigFile(allocator: Allocator, io: std.Io, path: []const u8) !ServerConfig {
    const contents = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.StreamTooLong => return error.ConfigFileTooLarge,
        else => |e| return e,
    };
    defer allocator.free(contents);
    return parseConfig(allocator, contents);
}

/// Each `"<key-tag> <algorithm> <digest-type> <hex-digest>"`, in decimal
/// IANA numbers, for the root.
fn parseTrustAnchors(arena: Allocator, strs: []const []const u8) ConfigError![]dns.DsData {
    const list = try arena.alloc(dns.DsData, strs.len);
    for (list, strs) |*ta, s| ta.* = try parseTrustAnchor(arena, s);
    return list;
}

fn parseTrustAnchor(arena: Allocator, s: []const u8) ConfigError!dns.DsData {
    var it = mem.tokenizeAny(u8, s, " \t");
    const tag_str = it.next() orelse return error.InvalidValue;
    const alg_str = it.next() orelse return error.InvalidValue;
    const dtype_str = it.next() orelse return error.InvalidValue;
    const digest_str = it.next() orelse return error.InvalidValue;
    if (it.next() != null) return error.InvalidValue;

    const key_tag = std.fmt.parseInt(u16, tag_str, 10) catch return error.InvalidValue;
    const alg_int = std.fmt.parseInt(u8, alg_str, 10) catch return error.InvalidValue;
    const dtype_int = std.fmt.parseInt(u8, dtype_str, 10) catch return error.InvalidValue;
    // Both enums are open: an unnamed value is a typo, refused here rather
    // than met later as a SERVFAIL.
    const algorithm: dns.DnssecAlgorithm = @fromBackingInt(@intCast(alg_int));
    if (std.enums.tagName(dns.DnssecAlgorithm, algorithm) == null) return error.InvalidValue;
    const digest_type: dns.DigestType = @fromBackingInt(@intCast(dtype_int));
    // RFC 4034 §5.1.4 + RFC 6605 §3: digest length is fixed per digest type.
    const digest_len: usize = switch (digest_type) {
        .sha1 => 20,
        .sha256 => 32,
        .sha384 => 48,
        _ => return error.InvalidValue,
    };
    if (digest_str.len != 2 * digest_len) return error.InvalidValue;

    const digest = try arena.alloc(u8, digest_len);
    _ = std.fmt.hexToBytes(digest, digest_str) catch return error.InvalidValue;

    return .{
        .key_tag = key_tag,
        .algorithm = algorithm,
        .digest_type = digest_type,
        .digest = digest,
    };
}

pub fn parseZoneList(arena: Allocator, strs: []const []const u8) ConfigError![]dns.Name {
    const list = try arena.alloc(dns.Name, strs.len);
    for (list, strs) |*zone, s| {
        // The root holds every name: `allow-zones = [""]` would turn the
        // scrub off entirely.
        if (s.len == 0 or mem.eql(u8, s, ".")) {
            errLog("config: allow-zones entry must name a zone, got '{s}'", .{s});
            return error.InvalidValue;
        }
        zone.* = try parseZone(arena, s);
    }
    return list;
}

fn parseZone(arena: Allocator, s: []const u8) ConfigError!dns.Name {
    return dns.parseDottedName(arena, s) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            errLog("config: invalid zone name '{s}'", .{s});
            return error.InvalidValue;
        },
    };
}

fn parseStubZones(arena: Allocator, strs: []const []const u8) ConfigError![]stub.Zone {
    const zones = try arena.alloc(stub.Zone, strs.len);
    var fields: [1 + delegation.max_servers_per_level + 1][]const u8 = undefined;
    for (zones, strs, 0..) |*zone, s, i| {
        var n: usize = 0;
        var it = mem.tokenizeAny(u8, s, " \t");
        while (it.next()) |f| : (n += 1) {
            if (n == fields.len) break;
            fields[n] = f;
        }
        if (n < 2 or n == fields.len) {
            errLog("config: stub-zones entry '{s}' must be a zone and 1 to {d} addresses", .{ s, fields.len - 2 });
            return error.InvalidValue;
        }
        const apex = try parseZone(arena, fields[0]);
        if (apex.labels.len == 0 or special_use.fixed(apex)) {
            errLog("config: stub-zones cannot name '{s}'", .{fields[0]});
            return error.InvalidValue;
        }
        for (zones[0..i]) |z| if (z.apex.eql(apex)) {
            errLog("config: stub-zones names '{s}' twice", .{fields[0]});
            return error.InvalidValue;
        };
        zone.* = .{ .apex = apex, .servers = try parseAddressList(arena, fields[1..n], error.InvalidValue) };
    }
    return zones;
}

pub fn parseCidrList(arena: Allocator, strs: []const []const u8) ConfigError![]acl.Cidr {
    const list = try arena.alloc(acl.Cidr, strs.len);
    for (list, strs) |*c, s| c.* = acl.parse(s) orelse {
        errLog("config: invalid CIDR entry '{s}'", .{s});
        return error.InvalidAclEntry;
    };
    return list;
}

fn parseAddressList(arena: Allocator, strs: []const []const u8, comptime err: ConfigError) ConfigError![]Address {
    const addrs = try arena.alloc(Address, strs.len);
    for (addrs, strs) |*a, s| a.* = parseAddress(s, 53) orelse {
        errLog("config: invalid address '{s}'", .{s});
        return err;
    };
    return addrs;
}

fn parseAddress(s: []const u8, default_port: u16) ?Address {
    if (s.len > 0 and s[0] == '[') {
        const close = mem.indexOfScalar(u8, s, ']') orelse return null;
        const ip6_str = s[1..close];
        if (close + 1 < s.len and s[close + 1] != ':') return null;
        const port = if (close + 1 < s.len)
            std.fmt.parseInt(u16, s[close + 2 ..], 10) catch return null
        else
            default_port;
        const ip6 = net_addr.Ip6.parse(ip6_str, port) catch return null;
        return net_addr.initIp6(ip6.bytes, port, 0, 0);
    }

    // First vs last colon distinguish the three remaining shapes:
    //   no colons     → bare IPv4
    //   one colon     → IPv4:port (first == last)
    //   many colons   → bare IPv6 (first != last)
    const first = mem.indexOfScalar(u8, s, ':');
    const last = mem.lastIndexOfScalar(u8, s, ':');

    if (first) |f| {
        if (f == last.?) {
            const port = std.fmt.parseInt(u16, s[f + 1 ..], 10) catch return null;
            const ip4 = std.Io.net.Ip4Address.parse(s[0..f], port) catch return null;
            return .{ .ip4 = ip4 };
        }
        const ip6 = net_addr.Ip6.parse(s, default_port) catch return null;
        return net_addr.initIp6(ip6.bytes, default_port, 0, 0);
    }

    // Same strict dotted-quad grammar as acl.zig's allow-from parsing —
    // one config file, one IPv4 grammar.
    const ip4 = std.Io.net.Ip4Address.parse(s, default_port) catch return null;
    return .{ .ip4 = ip4 };
}

test "parse full config" {
    var cfg = try parseConfig(testing.allocator,
        \\[server]
        \\listen = ["127.0.0.1:8053"]
        \\
        \\[resolver]
        \\dnssec = true
        \\qname-minimization = false
        \\
        \\[cache]
        \\size = 8388608
    );
    defer cfg.deinit();

    try testing.expectEqual(@as(usize, 1), cfg.listen.len);
    try testing.expectEqual(@as(u16, 8053), cfg.listen[0].getPort());
    try testing.expectEqual(true, cfg.dnssec);
    try testing.expectEqual(false, cfg.qname_minimization);
    try testing.expectEqual(@as(usize, 8388608), cfg.cache_size);
}

test "a bad dns64-prefix refuses startup" {
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator, "[resolver]\ndns64-prefix = \"64:ff9b::/100\"\n"));
}

test "parse IPv6 listen address" {
    var cfg = try parseConfig(testing.allocator,
        \\[server]
        \\listen = ["[::1]:5353"]
    );
    defer cfg.deinit();

    try testing.expectEqual(@as(usize, 1), cfg.listen.len);
    try testing.expectEqual(@as(u16, 5353), cfg.listen[0].getPort());
}

test "parse address with default port" {
    const addr = parseAddress("192.168.1.1", 53).?;
    try testing.expectEqual(@as(u16, 53), addr.getPort());
}

test "parse address with explicit port" {
    const addr = parseAddress("192.168.1.1:8053", 53).?;
    try testing.expectEqual(@as(u16, 8053), addr.getPort());
}

test "bracketed address needs a colon before its port" {
    try testing.expectEqual(@as(?Address, null), parseAddress("[::1]5353", 53));
}

test "cache prefetch and stale config" {
    var cfg = try parseConfig(testing.allocator,
        \\[cache]
        \\prefetch = true
        \\serve-stale-ttl = 3600
        \\min-ttl = 300
        \\servfail-ttl = 7
    );
    defer cfg.deinit();

    try testing.expectEqual(true, cfg.prefetch);
    try testing.expectEqual(@as(u32, 3600), cfg.serve_stale_ttl);
    try testing.expectEqual(@as(u32, 300), cfg.min_ttl);
    try testing.expectEqual(@as(u32, 7), cfg.servfail_ttl);
}

test "tcp idle and queries knobs parse and validate" {
    var cfg = try parseConfig(testing.allocator,
        \\[server]
        \\tcp-idle-timeout-ms = 8000
        \\tcp-queries-per-conn = 64
    );
    defer cfg.deinit();
    try testing.expectEqual(@as(u32, 8000), cfg.tcp_idle_timeout_ms);
    try testing.expectEqual(@as(u32, 64), cfg.tcp_queries_per_conn);

    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\tcp-queries-per-conn = 0
    ));

    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\tcp-idle-timeout-ms = 7000000
    ));
}

test "rebinding defaults are safe (enabled, empty extras)" {
    var cfg = try parseConfig(testing.allocator, "");
    defer cfg.deinit();
    try testing.expectEqual(true, cfg.rebinding.enabled);
    try testing.expectEqual(@as(usize, 0), cfg.rebinding.allow_zones.len);
    try testing.expectEqual(@as(usize, 0), cfg.rebinding.extra_block.len);
    try testing.expectEqual(@as(usize, 0), cfg.rebinding.extra_allow.len);
}

test "rebinding rejects empty / root zone in allow_zones (would silently disable scrub)" {
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[rebinding]
        \\allow-zones = [""]
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[rebinding]
        \\allow-zones = ["."]
    ));
    try testing.expectError(error.InvalidAclEntry, parseConfig(testing.allocator,
        \\[rebinding]
        \\extra-block = ["not-a-cidr"]
    ));
}

test "unknown key rejected, not silently ignored" {
    try testing.expectError(error.UnknownConfigKey, parseConfig(testing.allocator,
        \\[server]
        \\worker = 4
    ));
    try testing.expectError(error.UnknownConfigKey, parseConfig(testing.allocator,
        \\[resolvers]
        \\dnssec = true
    ));
    // Underscore instead of dash — the most likely real-world typo.
    try testing.expectError(error.UnknownConfigKey, parseConfig(testing.allocator,
        \\[resolver]
        \\qname_minimization = false
    ));
    try testing.expectError(error.UnknownConfigKey, parseConfig(testing.allocator,
        \\dnssec = true
    ));
}

test "wrong-typed key rejected, default must not silently win" {
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\dnssec = "true"
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[rebinding]
        \\allow-zones = "homelab.lan"
    ));
}

test "trust-anchors rejects malformed entries" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{
        "20326 8 2 ABC",
        "20326 8 2",
        "20326 8 2 AB EXTRA",
        "20326 8 2 ZZZZ",
        // Unknown algorithm (255 is reserved/unassigned per IANA DNSSEC alg registry)
        "20326 255 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        "20326 8 99 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        // 16-byte digest is too short for any standard digest type
        "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D084",
        // Digest length doesn't match digest type (SHA-256 declared, 20-byte SHA-1 supplied)
        "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E88040",
    }) |s| try testing.expectError(error.InvalidValue, parseTrustAnchor(arena.allocator(), s));
}

test "test-only knobs gated on -Dtesting" {
    const cfg_text =
        \\[resolver]
        \\upstream-port = 5353
        \\trust-anchors = ["20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
    ;
    if (build_options.testing_enabled) {
        var cfg = try parseConfig(testing.allocator, cfg_text);
        defer cfg.deinit();
        try testing.expectEqual(@as(u16, 5353), cfg.upstream_port);
        try testing.expectEqual(@as(usize, 1), cfg.trust_anchors.len);
    } else {
        try testing.expectError(error.TestOnlyConfigKey, parseConfig(testing.allocator, cfg_text));
    }
}

test "an out-of-range integer is rejected, never clamped" {
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\user = 99999999999
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\user = 4294967295
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\group = 4294967295
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\user = 0
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[server]
        \\group = 0
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\stagger-ms = 5000
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[cache]
        \\serve-stale-ttl = 99999999999
    ));
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[cache]
        \\min-ttl = 4294967296
    ));

    var cfg = try parseConfig(testing.allocator,
        \\[server]
        \\user = 4294967294
        \\group = 65534
    );
    defer cfg.deinit();
    try testing.expectEqual(@as(?u32, 4294967294), cfg.drop_uid);
    try testing.expectEqual(@as(?u32, 65534), cfg.drop_gid);
}

fn parseConfigOomProbe(allocator: Allocator, contents: []const u8) !void {
    var cfg = try parseConfig(allocator, contents);
    cfg.deinit();
}

test "stub-zones names a zone's servers, and refuses what no operator may name" {
    var cfg = try parseConfig(testing.allocator,
        \\[resolver]
        \\stub-zones = ["Internal 192.168.1.1:5353  [fd00::53]", "lab.test 10.0.0.1"]
    );
    defer cfg.deinit();
    try testing.expectEqual(@as(usize, 2), cfg.stub_zones.len);
    try testing.expectEqual(@as(u16, 5353), cfg.stub_zones[0].servers[0].getPort());
    try testing.expectEqual(@as(u16, 53), cfg.stub_zones[0].servers[1].getPort());
    for ([_][]const u8{
        "internal",
        ". 192.0.2.1",
        "invalid 192.0.2.1",
        "a.onion 192.0.2.1",
        "IPv4only.arpa 192.0.2.1",
        "internal not-an-address",
    }) |entry| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "[resolver]\nstub-zones = [\"{s}\"]\n", .{entry});
        try testing.expectError(error.InvalidValue, parseConfig(testing.allocator, text));
    }
    try testing.expectError(error.InvalidValue, parseConfig(testing.allocator,
        \\[resolver]
        \\stub-zones = ["internal 192.0.2.1", "INTERNAL 192.0.2.2"]
    ));
    for ([_][]const u8{ "127.0.0.1:53", "127.0.0.1:5335", "[::1]:5335", "[::]:5335" }) |server| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "[server]\nlisten = [\"127.0.0.1:53\", \"0.0.0.0:5335\", \"[::]:5335\"]\n[resolver]\nstub-zones = [\"internal {s}\"]\n", .{server});
        try testing.expectError(error.InvalidValue, parseConfig(testing.allocator, text));
    }
    var other = try parseConfig(testing.allocator,
        \\[server]
        \\listen = ["0.0.0.0:5335", "[::]:5335"]
        \\[resolver]
        \\stub-zones = ["internal 192.168.1.1:5335 127.0.0.1:53 [::1]:53"]
    );
    other.deinit();
}

test "root-hints refuses more addresses than a walk level holds" {
    try testing.expectError(error.TooManyRootHints, parseConfig(testing.allocator,
        \\[resolver]
        \\root-hints = ["192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53", "192.0.2.4:53", "192.0.2.5:53", "192.0.2.6:53", "192.0.2.7:53", "192.0.2.8:53", "192.0.2.9:53", "192.0.2.10:53", "192.0.2.11:53", "192.0.2.12:53", "192.0.2.13:53", "192.0.2.14:53", "192.0.2.15:53", "192.0.2.16:53", "192.0.2.17:53", "192.0.2.18:53", "192.0.2.19:53", "192.0.2.20:53", "192.0.2.21:53", "192.0.2.22:53", "192.0.2.23:53", "192.0.2.24:53", "192.0.2.25:53", "192.0.2.26:53", "192.0.2.27:53"]
    ));
}

test "parseConfig handles OOM without leaking" {
    const contents =
        \\[server]
        \\listen = ["127.0.0.1:8053", "[::1]:8053"]
        \\allow-from = ["127.0.0.0/8", "10.0.0.0/8"]
        \\
        \\[resolver]
        \\root-hints = ["198.41.0.4:53", "199.9.14.201:53"]
        \\
        \\[rebinding]
        \\enabled = true
        \\allow-zones = ["home.arpa", "lan"]
        \\extra-block = ["192.0.2.0/24"]
        \\extra-allow = ["203.0.113.0/24"]
    ;
    // Refusing resize makes every growth an injectable alloc and the count deterministic.
    var backing = testing.FailingAllocator.init(testing.allocator, .{ .resize_fail_index = 0 });
    try testing.checkAllAllocationFailures(backing.allocator(), parseConfigOomProbe, .{contents});
}
