/// Address type and helpers, replacing std.net.Address with std.Io.net.IpAddress.
/// Wraps std.Io.net.IpAddress with convenience constructors and sockaddr
/// conversion for raw linux syscall usage (sys.zig).
const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const sys = @import("sys.zig");
const rand = @import("rand.zig");

/// Hash seed randomized at startup so an authoritative server serving crafted
/// glue addresses can't engineer bucket collisions against `RttCache` /
/// `NsSelector`. Stays 0 in tests (deterministic); production calls
/// `randomizeHashSeed`.
var hash_seed: u64 = 0;

pub fn randomizeHashSeed(io: std.Io) void {
    hash_seed = rand.hashSeed(io);
}

pub const Address = std.Io.net.IpAddress;
pub const Ip6 = std.Io.net.Ip6Address;

pub fn initIp4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn initIp6(bytes: [16]u8, port: u16, flow: u32, scope: u32) Address {
    return .{ .ip6 = .{ .bytes = bytes, .port = port, .flow = flow, .interface = .{ .index = scope } } };
}

/// Wildcard `0.0.0.0:0` / `[::]:0` of the same family as `peer`. The kernel
/// fills in a random ephemeral source port (RFC 5452 §9.1) when this binds.
pub fn wildcardFor(peer: Address) Address {
    return switch (peer) {
        .ip4 => initIp4(.{ 0, 0, 0, 0 }, 0),
        .ip6 => initIp6(@splat(0), 0, 0, 0),
    };
}

/// Canonical Murmur3 fmix64. FNV-1a's multiply only propagates leftward, so
/// without it the bottom bits stay invariant when inputs share theirs (IPv4
/// keys with addr[0]=0). Shard selectors subset both halves. Not cryptographic.
pub fn fmix64(h0: u64) u64 {
    var h = h0;
    h ^= h >> 33;
    h *%= 0xff51afd7ed558ccd;
    h ^= h >> 33;
    h *%= 0xc4ceb9fe1a85ec53;
    h ^= h >> 33;
    return h;
}

/// Hashable, equality-comparable address-with-port. Used as a key in caches
/// (RTT, NS-selector, encrypted_ns, connection pools).
pub const AddressKey = struct {
    family: u8,
    addr: [16]u8,
    port: u16,

    pub fn fromAddressWithPort(address: Address, port: u16) AddressKey {
        var key = fromAddress(address);
        key.port = port;
        return key;
    }

    pub fn eql(a: AddressKey, b: AddressKey) bool {
        return a.family == b.family and a.port == b.port and mem.eql(u8, &a.addr, &b.addr);
    }

    pub fn fromAddress(address: Address) AddressKey {
        var key = AddressKey{ .family = 0, .addr = @splat(0), .port = 0 };
        switch (address) {
            .ip4 => |v4| {
                key.family = @intCast(posix.AF.INET);
                @memcpy(key.addr[0..4], &v4.bytes);
                key.port = v4.port;
            },
            .ip6 => |v6| {
                key.family = @intCast(posix.AF.INET6);
                @memcpy(&key.addr, &v6.bytes);
                key.port = v6.port;
            },
        }
        return key;
    }

    /// Hash context tuned for AddressKey: reads the 16-byte addr as two u64s
    /// and mixes via FNV-1a-style multiply, avoiding Wyhash's variable-length
    /// dispatch + final mixing chain. Wyhash showed at ~20% of CPU on miss
    /// workloads where this key is hashed per upstream selection.
    pub const HashCtx = struct {
        pub fn hash(_: @This(), key: AddressKey) u64 {
            const lo = mem.readInt(u64, key.addr[0..8], .little);
            const hi = mem.readInt(u64, key.addr[8..16], .little);
            const tag = (@as(u64, key.family) << 16) | key.port;
            var h: u64 = hash_seed ^ 0xcbf29ce484222325;
            h ^= lo;
            h *%= 0x100000001b3;
            h ^= hi;
            h *%= 0x100000001b3;
            h ^= tag;
            h *%= 0x100000001b3;
            return fmix64(h);
        }

        pub fn eql(_: @This(), a: AddressKey, b: AddressKey) bool {
            return a.eql(b);
        }
    };
};

/// PosixAddress union for sockaddr conversion (matches Io.Threaded.PosixAddress).
pub const PosixAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

pub fn toSockaddr(addr: *const Address, storage: *PosixAddress) posix.socklen_t {
    return switch (addr.*) {
        .ip4 => |ip4| {
            storage.in = .{
                .port = mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |ip6| {
            storage.in6 = .{
                .port = mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            return @sizeOf(posix.sockaddr.in6);
        },
    };
}

pub fn fromSockaddr(sa: *const PosixAddress) Address {
    return switch (sa.any.family) {
        posix.AF.INET => .{ .ip4 = .{
            .port = mem.bigToNative(u16, sa.in.port),
            .bytes = @bitCast(sa.in.addr),
        } },
        posix.AF.INET6 => .{ .ip6 = .{
            .port = mem.bigToNative(u16, sa.in6.port),
            .bytes = sa.in6.addr,
            .flow = sa.in6.flowinfo,
            .interface = .{ .index = sa.in6.scope_id },
        } },
        else => unreachable,
    };
}

/// Address family as u32 for socket() calls.
pub fn afU32(addr: Address) u32 {
    return switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

pub fn getSockName(fd: posix.fd_t) !Address {
    var pa: PosixAddress = undefined;
    var len: posix.socklen_t = @sizeOf(PosixAddress);
    try sys.getsockname(fd, @ptrCast(&pa), &len);
    return fromSockaddr(&pa);
}

pub fn getPeerName(fd: posix.fd_t) !Address {
    var pa: PosixAddress = undefined;
    var len: posix.socklen_t = @sizeOf(PosixAddress);
    try sys.getpeername(fd, @ptrCast(&pa), &len);
    return fromSockaddr(&pa);
}

/// Format an address as "ip:port" into a caller-provided buffer.
/// Delegates to std.Io.net.IpAddress.format, which emits IPv6 in
/// RFC 5952 canonical form ("[::1]:53" rather than "[0000:...:0001]:53").
pub fn format(addr: Address, buf: []u8) []const u8 {
    var w = std.Io.Writer.fixed(buf);
    addr.format(&w) catch return "?";
    return w.buffered();
}

pub fn connectTo(fd: posix.fd_t, addr: *const Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try sys.connect(fd, &storage.any, sa_len);
}

pub fn bindTo(fd: posix.fd_t, addr: *const Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try sys.bind(fd, &storage.any, sa_len);
}

/// Returns true if the address is in a private, reserved, or loopback range
/// that should not be contacted during recursive resolution (DNS rebinding defense).
/// Superset of the shared special-use table: NS contact also refuses multicast,
/// which the answer scrub (rebinding.zig) deliberately serves.
pub fn isNonRoutableNs(addr: Address) bool {
    return switch (addr) {
        .ip4 => |v4| isNonRoutableIp4(v4.bytes),
        .ip6 => |v6| isNonRoutableIp6(v6.bytes),
    };
}

fn isNonRoutableIp4(b: [4]u8) bool {
    return isSpecialUseIp4(b) or b[0] >= 224; // + 224.0.0.0/4 multicast
}

fn isNonRoutableIp6(b: [16]u8) bool {
    if (isIp4Mapped(&b)) return isNonRoutableIp4(b[12..16].*);
    return isSpecialUseIp6(b) or b[0] == 0xff; // + ff00::/8 multicast
}

/// Shared special-use IPv4 set: Knot's set + the IANA special-use registries
/// (RFC 6890): CGNAT (RFC 6598), IETF protocol assignments, TEST-NET 1/2/3
/// (RFC 5737), benchmarking (RFC 2544), reserved (RFC 1112), broadcast.
/// Multicast 224.0.0.0/4 is deliberately *not* here — a recursive resolver
/// returning multicast to a stub is not a rebinding-attack primitive, so the
/// answer scrub serves it; NS egress re-adds it above.
pub fn isSpecialUseIp4(b: [4]u8) bool {
    if (b[0] == 0) return true; // 0.0.0.0/8         (this network, RFC 1122)
    if (b[0] == 10) return true; // 10.0.0.0/8       (RFC 1918)
    if (b[0] == 100 and (b[1] & 0xc0) == 64) return true; // 100.64.0.0/10 (CGNAT, RFC 6598)
    if (b[0] == 127) return true; // 127.0.0.0/8     (loopback, RFC 1122)
    if (b[0] == 169 and b[1] == 254) return true; // 169.254.0.0/16 (link-local, RFC 3927)
    if (b[0] == 172 and (b[1] & 0xf0) == 16) return true; // 172.16.0.0/12 (RFC 1918)
    if (b[0] == 192 and b[1] == 0 and b[2] == 0) return true; // 192.0.0.0/24 (IETF, RFC 6890)
    if (b[0] == 192 and b[1] == 0 and b[2] == 2) return true; // 192.0.2.0/24 (TEST-NET-1)
    if (b[0] == 192 and b[1] == 168) return true; // 192.168.0.0/16 (RFC 1918)
    if (b[0] == 198 and (b[1] & 0xfe) == 18) return true; // 198.18.0.0/15 (benchmarking)
    if (b[0] == 198 and b[1] == 51 and b[2] == 100) return true; // 198.51.100.0/24 (TEST-NET-2)
    if (b[0] == 203 and b[1] == 0 and b[2] == 113) return true; // 203.0.113.0/24 (TEST-NET-3)
    if (b[0] >= 240) return true; // 240.0.0.0/4     (reserved, includes 255.255.255.255)
    return false;
}

/// Shared special-use IPv6 set: loopback, unspecified, ULA, link-local, the
/// documentation prefix (RFC 3849), and IPv4-mapped addresses re-evaluated
/// against the v4 set. Multicast ff00::/8 excluded for symmetry with IPv4.
pub fn isSpecialUseIp6(b: [16]u8) bool {
    // ::/128 and ::1/128
    if (mem.eql(u8, b[0..15], &@as([15]u8, @splat(0)))) return b[15] <= 1;
    // ::ffff:0:0/96 — IPv4-mapped, defer to v4 rules so a mapped 127.0.0.1
    // doesn't slip through as a "v6 address" the v6 set has no opinion on.
    if (isIp4Mapped(&b)) return isSpecialUseIp4(b[12..16].*);
    if (b[0] == 0x20 and b[1] == 0x01 and b[2] == 0x0d and b[3] == 0xb8) return true; // 2001:db8::/32 (RFC 3849)
    if ((b[0] & 0xfe) == 0xfc) return true; // fc00::/7  (ULA, RFC 4193)
    if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true; // fe80::/10 (link-local)
    return false;
}

/// ::ffff:0:0/96 — IPv4-mapped IPv6.
pub fn isIp4Mapped(bytes: []const u8) bool {
    return bytes.len == 16 and mem.eql(u8, bytes[0..10], &@as([10]u8, @splat(0))) and bytes[10] == 0xff and bytes[11] == 0xff;
}

// ── Tests ────────────────────────────────────────────────────────────

const testing = std.testing;

test "AddressKey.HashCtx: eql peers hash equal, distinct peers diverge" {
    const ctx: AddressKey.HashCtx = .{};
    const a = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 53));
    const b = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 53));
    const c = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 5353));
    const d = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 5 }, 53));
    const e = AddressKey.fromAddress(initIp6([_]u8{ 1, 2, 3, 4 } ++ @as([12]u8, @splat(0)), 53, 0, 0));

    try testing.expect(ctx.eql(a, b));
    try testing.expectEqual(ctx.hash(a), ctx.hash(b));
    try testing.expect(!ctx.eql(a, c));
    try testing.expect(ctx.hash(a) != ctx.hash(c));
    try testing.expect(!ctx.eql(a, d));
    try testing.expect(ctx.hash(a) != ctx.hash(d));
    // v4 1.2.3.4 vs v6 ::102:304 share addr bytes — family must disambiguate.
    try testing.expect(!ctx.eql(a, e));
    try testing.expect(ctx.hash(a) != ctx.hash(e));
}

test "AddressKey.HashCtx: 16-shard distribution on sequential IPv4 keys" {
    // Pre-finalizer, every IPv4 key with addr[0]=0 collapsed to a single
    // shard because the FNV chain didn't propagate input bits to bit 32+.
    // Pin the floor so any future tweak that re-introduces that pathology
    // fails loudly.
    const ctx: AddressKey.HashCtx = .{};
    var counts: [16]u32 = @splat(0);
    var i: u32 = 0;
    while (i < 4096) : (i += 1) {
        const k = AddressKey.fromAddress(initIp4(.{
            @intCast((i >> 16) & 0xff),
            @intCast((i >> 8) & 0xff),
            @intCast(i & 0xff),
            1,
        }, 53));
        const h32: u32 = @truncate(ctx.hash(k) >> 32);
        counts[h32 & 15] += 1;
    }
    // Uniform expectation: 4096 / 16 = 256 per bucket. Allow ±60% (worst
    // observed ~190 with the post-finalizer hash); a bucket at 0 or > 700
    // would mean the finalizer regressed.
    for (counts) |c| {
        try testing.expect(c >= 100);
        try testing.expect(c <= 700);
    }
}

test "AddressKey.HashCtx: randomizeHashSeed shifts the hash space" {
    const ctx: AddressKey.HashCtx = .{};
    const k = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 53));
    const h0 = ctx.hash(k);
    const saved = hash_seed;
    defer hash_seed = saved;
    hash_seed = 0xdeadbeefcafef00d;
    const h1 = ctx.hash(k);
    try testing.expect(h0 != h1);
}

test "format produces ip:port and RFC 5952 IPv6" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("127.0.0.1:53", format(initIp4(.{ 127, 0, 0, 1 }, 53), &buf));
    try testing.expectEqualStrings("[::1]:53884", format(initIp6(@as([15]u8, @splat(0)) ++ [_]u8{1}, 53884, 0, 0), &buf));
    try testing.expectEqualStrings(
        "[2001:db8::1]:53",
        format(initIp6([_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([11]u8, @splat(0)) ++ [_]u8{1}, 53, 0, 0), &buf),
    );
}

test "special-use IPv4 set covers RFC 1918 + loopback + link-local + TEST-NET + CGNAT" {
    inline for ([_][4]u8{
        .{ 0, 0, 0, 0 },
        .{ 10, 1, 2, 3 },
        .{ 100, 64, 0, 1 }, // CGNAT
        .{ 100, 127, 255, 255 }, // CGNAT upper edge
        .{ 127, 0, 0, 1 },
        .{ 169, 254, 1, 1 },
        .{ 172, 16, 0, 1 },
        .{ 172, 31, 255, 255 },
        .{ 192, 0, 0, 1 }, // IETF
        .{ 192, 0, 2, 1 }, // TEST-NET-1
        .{ 192, 168, 1, 1 },
        .{ 198, 18, 0, 1 }, // benchmarking
        .{ 198, 19, 255, 255 },
        .{ 198, 51, 100, 1 }, // TEST-NET-2
        .{ 203, 0, 113, 1 }, // TEST-NET-3
        .{ 240, 0, 0, 1 },
        .{ 255, 255, 255, 255 },
    }) |bytes| try testing.expect(isSpecialUseIp4(bytes));
}

test "special-use IPv4 set leaves routable space alone (incl. boundaries + multicast)" {
    inline for ([_][4]u8{
        .{ 1, 1, 1, 1 },
        .{ 8, 8, 8, 8 },
        .{ 100, 63, 255, 255 }, // just below CGNAT
        .{ 100, 128, 0, 0 }, // just above CGNAT
        .{ 172, 15, 255, 255 }, // just below RFC 1918
        .{ 172, 32, 0, 0 }, // just above RFC 1918
        .{ 192, 0, 1, 1 }, // 192.0.1/24 allocated, not reserved
        .{ 198, 17, 255, 255 }, // just below benchmarking
        .{ 198, 20, 0, 0 }, // just above benchmarking
        .{ 224, 0, 0, 1 }, // multicast — deliberately not blocked
        .{ 239, 255, 255, 255 },
    }) |bytes| try testing.expect(!isSpecialUseIp4(bytes));
}

test "special-use IPv6 set covers ::/::1, ULA, link-local, docs, mapped-v4" {
    try testing.expect(isSpecialUseIp6(@as([16]u8, @splat(0)))); // ::
    try testing.expect(isSpecialUseIp6(@as([15]u8, @splat(0)) ++ [_]u8{1})); // ::1
    try testing.expect(isSpecialUseIp6([_]u8{0xfc} ++ @as([15]u8, @splat(0)))); // fc00::/7
    try testing.expect(isSpecialUseIp6([_]u8{0xfd} ++ @as([15]u8, @splat(0))));
    try testing.expect(isSpecialUseIp6([_]u8{ 0xfe, 0x80 } ++ @as([14]u8, @splat(0)))); // fe80::/10
    try testing.expect(isSpecialUseIp6([_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([12]u8, @splat(0)))); // 2001:db8::/32
    try testing.expect(isSpecialUseIp6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 })); // mapped 127
    try testing.expect(!isSpecialUseIp6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 1, 1, 1, 1 })); // mapped public
    try testing.expect(!isSpecialUseIp6([_]u8{ 0xff, 0x02 } ++ @as([14]u8, @splat(0)))); // multicast — not blocked
    try testing.expect(!isSpecialUseIp6([_]u8{ 0x26, 0x06 } ++ @as([14]u8, @splat(0)))); // public
}

test "isNonRoutableNs blocks special-use + multicast IPv4" {
    // Special-use (shared table)
    try testing.expect(isNonRoutableNs(initIp4(.{ 127, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 10, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 192, 168, 1, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 169, 254, 1, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 0, 0, 0, 0 }, 53)));
    // Widened vs the old NS-only set: CGNAT, TEST-NET, benchmarking
    try testing.expect(isNonRoutableNs(initIp4(.{ 100, 64, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 192, 0, 2, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 198, 51, 100, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 203, 0, 113, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 198, 18, 0, 1 }, 53)));
    // Multicast — NS-only addition over the shared table
    try testing.expect(isNonRoutableNs(initIp4(.{ 224, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 239, 255, 255, 255 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 255, 255, 255, 255 }, 53)));
}

test "isNonRoutableNs allows routable IPv4" {
    try testing.expect(!isNonRoutableNs(initIp4(.{ 1, 1, 1, 1 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 8, 8, 8, 8 }, 53)));
    // 172.15.x and 172.32.x are routable
    try testing.expect(!isNonRoutableNs(initIp4(.{ 172, 15, 255, 255 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 172, 32, 0, 1 }, 53)));
}

test "isNonRoutableNs blocks special-use + multicast IPv6" {
    // Loopback ::1
    try testing.expect(isNonRoutableNs(initIp6(@as([15]u8, @splat(0)) ++ [_]u8{1}, 53, 0, 0)));
    // Unspecified ::
    try testing.expect(isNonRoutableNs(initIp6(@splat(0), 53, 0, 0)));
    // Unique local fc00::/7
    try testing.expect(isNonRoutableNs(initIp6([_]u8{ 0xfc, 0 } ++ @as([14]u8, @splat(0)), 53, 0, 0)));
    try testing.expect(isNonRoutableNs(initIp6([_]u8{ 0xfd, 0x12 } ++ @as([14]u8, @splat(0)), 53, 0, 0)));
    // Link-local fe80::/10
    try testing.expect(isNonRoutableNs(initIp6([_]u8{ 0xfe, 0x80 } ++ @as([14]u8, @splat(0)), 53, 0, 0)));
    // Multicast ff00::/8 — NS-only addition over the shared table
    try testing.expect(isNonRoutableNs(initIp6([_]u8{ 0xff, 0x02 } ++ @as([14]u8, @splat(0)), 53, 0, 0)));
    // Documentation 2001:db8::/32 — widened vs the old NS-only set
    try testing.expect(isNonRoutableNs(initIp6([_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([11]u8, @splat(0)) ++ [_]u8{1}, 53, 0, 0)));
    // IPv4-mapped ::ffff:127.0.0.1
    try testing.expect(isNonRoutableNs(initIp6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 }, 53, 0, 0)));
    // IPv4-mapped ::ffff:10.0.0.1
    try testing.expect(isNonRoutableNs(initIp6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 10, 0, 0, 1 }, 53, 0, 0)));
    // IPv4-mapped multicast ::ffff:224.0.0.1 — must stay blocked at NS-time
    try testing.expect(isNonRoutableNs(initIp6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 224, 0, 0, 1 }, 53, 0, 0)));
}

test "isNonRoutableNs allows routable IPv6" {
    try testing.expect(!isNonRoutableNs(initIp6([_]u8{ 0x26, 0x06 } ++ @as([14]u8, @splat(0)), 53, 0, 0)));
    // IPv4-mapped ::ffff:1.1.1.1 (routable mapped address)
    try testing.expect(!isNonRoutableNs(initIp6(@as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff, 1, 1, 1, 1 }, 53, 0, 0)));
}

pub fn ipEqual(a: Address, b: Address) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip6 => |b6| mem.eql(u8, &a6.bytes, &b6.bytes),
            .ip4 => false,
        },
    };
}
