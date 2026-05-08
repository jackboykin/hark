/// Address type and helpers, replacing std.net.Address with std.Io.net.IpAddress.
/// Wraps std.Io.net.IpAddress with convenience constructors and sockaddr
/// conversion for raw linux syscall usage (sys.zig).
const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const sys = @import("sys.zig");
const rand = @import("rand.zig");

/// Hash seed randomized at startup so an authoritative serving crafted glue
/// addresses can't engineer bucket collisions against `RttCache` /
/// `NsSelector`. Stays 0 in tests (deterministic); production calls
/// `randomizeHashSeed`.
var hash_seed: u64 = 0;

pub fn randomizeHashSeed(io: std.Io) void {
    hash_seed = rand.hashSeed(io);
}

pub const Address = std.Io.net.IpAddress;
pub const Ip4 = std.Io.net.Ip4Address;
pub const Ip6 = std.Io.net.Ip6Address;

pub fn initIp4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn initIp6(bytes: [16]u8, port: u16, flow: u32, scope: u32) Address {
    return .{ .ip6 = .{ .bytes = bytes, .port = port, .flow = flow, .interface = .{ .index = scope } } };
}

/// Hashable, equality-comparable address-with-port. Used as a key in caches
/// (RTT, NS-selector, encrypted_ns, connection pools).
pub const AddressKey = struct {
    family: u8,
    addr: [16]u8,
    port: u16,

    /// Create a key from an address, overriding the port.
    pub fn fromAddressWithPort(address: Address, port: u16) AddressKey {
        var key = fromAddress(address);
        key.port = port;
        return key;
    }

    pub fn fromAddress(address: Address) AddressKey {
        var key = AddressKey{ .family = 0, .addr = .{0} ** 16, .port = 0 };
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
            // FNV-1a's multiply only propagates input bits leftward — without
            // a finalizer, the bottom bits stay invariant whenever inputs
            // share their low bits (e.g. IPv4 keys with addr[0]=0).
            // Consumers (RttCache shard selector) subset these bits, so we
            // run the canonical Murmur3 fmix64 to break that structure.
            // This is collision-mitigation, not cryptographic — the input
            // is small and `hash_seed` is the only randomness.
            h ^= h >> 33;
            h *%= 0xff51afd7ed558ccd;
            h ^= h >> 33;
            h *%= 0xc4ceb9fe1a85ec53;
            h ^= h >> 33;
            return h;
        }

        pub fn eql(_: @This(), a: AddressKey, b: AddressKey) bool {
            return a.family == b.family and a.port == b.port and mem.eql(u8, &a.addr, &b.addr);
        }
    };
};

/// PosixAddress union for sockaddr conversion (matches Io.Threaded.PosixAddress).
pub const PosixAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

/// Convert an Address to a posix sockaddr. Returns the sockaddr length.
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

/// Convert a posix sockaddr to an Address.
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

/// Get the local address bound to a socket.
pub fn getSockName(fd: posix.fd_t) !Address {
    var pa: PosixAddress = undefined;
    var len: posix.socklen_t = @sizeOf(PosixAddress);
    try sys.getsockname(fd, @ptrCast(&pa), &len);
    return fromSockaddr(&pa);
}

/// Get the remote peer address of a connected socket.
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

/// Connect a socket to an Address (converts to sockaddr internally).
pub fn connectTo(fd: posix.fd_t, addr: *const Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try sys.connect(fd, &storage.any, sa_len);
}

/// Bind a socket to an Address (converts to sockaddr internally).
pub fn bindTo(fd: posix.fd_t, addr: *const Address) !void {
    var storage: PosixAddress = undefined;
    const sa_len = toSockaddr(addr, &storage);
    try sys.bind(fd, &storage.any, sa_len);
}

/// Returns true if the address is in a private, reserved, or loopback range
/// that should not be contacted during recursive resolution (DNS rebinding defense).
pub fn isNonRoutableNs(addr: Address) bool {
    return switch (addr) {
        .ip4 => |v4| isNonRoutableIp4(v4.bytes),
        .ip6 => |v6| isNonRoutableIp6(v6.bytes),
    };
}

fn isNonRoutableIp4(b: [4]u8) bool {
    if (b[0] == 0) return true; // 0.0.0.0/8  (this network)
    if (b[0] == 10) return true; // 10.0.0.0/8  (RFC 1918)
    if (b[0] == 127) return true; // 127.0.0.0/8 (loopback)
    if (b[0] == 169 and b[1] == 254) return true; // 169.254.0.0/16 (link-local)
    if (b[0] == 172 and (b[1] & 0xf0) == 16) return true; // 172.16.0.0/12 (RFC 1918)
    if (b[0] == 192 and b[1] == 168) return true; // 192.168.0.0/16 (RFC 1918)
    if (b[0] >= 224) return true; // 224.0.0.0/4+ (multicast + reserved)
    return false;
}

fn isNonRoutableIp6(b: [16]u8) bool {
    return switch (b[0]) {
        0x00 => isNonRoutableIp6Zero(b),
        0xfc, 0xfd => true, // fc00::/7  (unique local)
        0xfe => (b[1] & 0xc0) == 0x80, // fe80::/10 (link-local)
        0xff => true, // ff00::/8  (multicast)
        else => false,
    };
}

fn isNonRoutableIp6Zero(b: [16]u8) bool {
    // All addresses starting with 0x00: check for ::, ::1, and ::ffff:mapped
    if (!mem.eql(u8, b[1..10], &([_]u8{0} ** 9))) return false;
    if (b[10] == 0 and b[11] == 0) {
        // :: (unspecified) or ::1 (loopback)
        return mem.eql(u8, b[12..15], &([_]u8{0} ** 3)) and b[15] <= 1;
    }
    if (b[10] == 0xff and b[11] == 0xff) {
        // ::ffff:0:0/96 (IPv4-mapped) — check the mapped IPv4 address
        return isNonRoutableIp4(b[12..16].*);
    }
    return false;
}

// ── Tests ────────────────────────────────────────────────────────────

const testing = std.testing;

test "AddressKey.HashCtx: eql peers hash equal, distinct peers diverge" {
    const ctx: AddressKey.HashCtx = .{};
    const a = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 53));
    const b = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 53));
    const c = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 4 }, 5353));
    const d = AddressKey.fromAddress(initIp4(.{ 1, 2, 3, 5 }, 53));
    const e = AddressKey.fromAddress(initIp6(.{ 1, 2, 3, 4 } ++ .{0} ** 12, 53, 0, 0));

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
    var counts: [16]u32 = .{0} ** 16;
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
    try testing.expectEqualStrings("[::1]:53884", format(initIp6(.{0} ** 15 ++ .{1}, 53884, 0, 0), &buf));
    try testing.expectEqualStrings(
        "[2001:db8::1]:53",
        format(initIp6(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1}, 53, 0, 0), &buf),
    );
}

test "isNonRoutableNs blocks private/reserved IPv4" {
    // Loopback
    try testing.expect(isNonRoutableNs(initIp4(.{ 127, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 127, 255, 255, 255 }, 53)));
    // RFC 1918
    try testing.expect(isNonRoutableNs(initIp4(.{ 10, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 172, 16, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 172, 31, 255, 255 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 192, 168, 1, 1 }, 53)));
    // Link-local
    try testing.expect(isNonRoutableNs(initIp4(.{ 169, 254, 1, 1 }, 53)));
    // This network
    try testing.expect(isNonRoutableNs(initIp4(.{ 0, 0, 0, 0 }, 53)));
    // Multicast
    try testing.expect(isNonRoutableNs(initIp4(.{ 224, 0, 0, 1 }, 53)));
    try testing.expect(isNonRoutableNs(initIp4(.{ 255, 255, 255, 255 }, 53)));
}

test "isNonRoutableNs allows routable IPv4" {
    try testing.expect(!isNonRoutableNs(initIp4(.{ 1, 1, 1, 1 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 8, 8, 8, 8 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 192, 0, 2, 1 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 198, 51, 100, 1 }, 53)));
    // 172.15.x and 172.32.x are routable
    try testing.expect(!isNonRoutableNs(initIp4(.{ 172, 15, 255, 255 }, 53)));
    try testing.expect(!isNonRoutableNs(initIp4(.{ 172, 32, 0, 1 }, 53)));
}

test "isNonRoutableNs blocks private/reserved IPv6" {
    // Loopback ::1
    try testing.expect(isNonRoutableNs(initIp6(.{0} ** 15 ++ .{1}, 53, 0, 0)));
    // Unspecified ::
    try testing.expect(isNonRoutableNs(initIp6(.{0} ** 16, 53, 0, 0)));
    // Unique local fc00::/7
    try testing.expect(isNonRoutableNs(initIp6(.{ 0xfc, 0 } ++ .{0} ** 14, 53, 0, 0)));
    try testing.expect(isNonRoutableNs(initIp6(.{ 0xfd, 0x12 } ++ .{0} ** 14, 53, 0, 0)));
    // Link-local fe80::/10
    try testing.expect(isNonRoutableNs(initIp6(.{ 0xfe, 0x80 } ++ .{0} ** 14, 53, 0, 0)));
    // Multicast ff00::/8
    try testing.expect(isNonRoutableNs(initIp6(.{ 0xff, 0x02 } ++ .{0} ** 14, 53, 0, 0)));
    // IPv4-mapped ::ffff:127.0.0.1
    try testing.expect(isNonRoutableNs(initIp6(.{0} ** 10 ++ .{ 0xff, 0xff, 127, 0, 0, 1 }, 53, 0, 0)));
    // IPv4-mapped ::ffff:10.0.0.1
    try testing.expect(isNonRoutableNs(initIp6(.{0} ** 10 ++ .{ 0xff, 0xff, 10, 0, 0, 1 }, 53, 0, 0)));
}

test "isNonRoutableNs allows routable IPv6" {
    // 2001:db8::1 (documentation, but routable from resolver perspective)
    try testing.expect(!isNonRoutableNs(initIp6(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1}, 53, 0, 0)));
    // IPv4-mapped ::ffff:1.1.1.1 (routable mapped address)
    try testing.expect(!isNonRoutableNs(initIp6(.{0} ** 10 ++ .{ 0xff, 0xff, 1, 1, 1, 1 }, 53, 0, 0)));
}

/// Compare two addresses by IP only, ignoring port.
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
