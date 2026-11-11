//! What a cell is asked and what it settles to: the words the graph, its
//! rules and the store share. Nothing here acts.
const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const dns = @import("dns.zig");
const na = @import("net_address.zig");
const rand = @import("rand.zig");

/// A DNAME and its synthesised CNAME count once. Chains in the wild run to
/// 12; resolvers stop at 10 to 19.
pub const max_links = 14;

pub const CellId = u32;

pub const OptionalCellId = enum(CellId) {
    none = std.math.maxInt(CellId),
    _,

    pub fn wrap(id: ?CellId) OptionalCellId {
        const i = id orelse return .none;
        std.debug.assert(i != @backingInt(OptionalCellId.none));
        return @fromBackingInt(i);
    }

    pub fn unwrap(o: OptionalCellId) ?CellId {
        return if (o == .none) null else @backingInt(o);
    }
};

/// `parental` is held for the denial index alone and is never a cell.
pub const Kind = enum(u8) { cut, addr, rrset, stub, answer, ds, dnskey, secure, exchange, refresh, ahead, parental };

pub const Key = struct {
    kind: Kind,
    rtype: dns.RType,
    name: []const u8,
    name_hash: u32,

    /// Borrows `name`: whatever keeps a key dupes it.
    pub fn of(kind: Kind, name: dns.Name, rtype: dns.RType) Key {
        return .init(kind, name.wire, rtype);
    }

    pub fn shown(k: Key, buf: *[dns.max_dotted_len + 1]u8) []const u8 {
        return if (k.name.len == 0) "" else dns.Name.of(k.name).formatInto(buf);
    }

    pub fn init(kind: Kind, name: []const u8, rtype: dns.RType) Key {
        return .{ .kind = kind, .rtype = rtype, .name = name, .name_hash = hashName(name) };
    }

    pub fn at(k: Key, kind: Kind, rtype: dns.RType) Key {
        return .{ .kind = kind, .rtype = rtype, .name = k.name, .name_hash = k.name_hash };
    }

    fn hashName(name: []const u8) u32 {
        return @truncate(std.hash.Wyhash.hash(rand.hash_seed, name));
    }

    pub fn hash(k: Key) u64 {
        if (builtin.mode == .debug) std.debug.assert(k.name_hash == hashName(k.name));
        const x = (@as(u64, k.name_hash) << 32) | (@as(u64, @backingInt(k.kind)) << 16) | @backingInt(k.rtype);
        const p = @as(u128, x) * 0x9e3779b97f4a7c15;
        return @truncate(p ^ (p >> 64));
    }

    pub fn eql(a: Key, b: Key) bool {
        return a.kind == b.kind and a.rtype == b.rtype and mem.eql(u8, a.name, b.name);
    }

    pub const Context = struct {
        pub fn hash(_: Context, k: Key) u32 {
            return @truncate(k.hash());
        }
        pub fn eql(_: Context, a: Key, b: Key, _: usize) bool {
            return a.eql(b);
        }
    };
};

pub const Cut = struct {
    zone: dns.Name,
    servers: []const Server = &.{},
    placed_until_ns: i64 = std.math.maxInt(i64),
};

pub const Server = struct {
    key: Key,
    glue: []const na.AddressKey = &.{},
};

pub const Reply = struct {
    kind: Of,
    aa: bool,
    answers: []const dns.ResourceRecord = &.{},
    authorities: []const dns.ResourceRecord = &.{},
    additionals: []const dns.ResourceRecord = &.{},
    target: dns.Name = .root,
    zone: dns.Name = .root,
    ede: ?dns.Ede.Code = null,
    stored_ns: i64 = 0,
    ttl: u32 = 0,

    pub const Of = enum {
        answer,
        alias,
        nodata,
        nxdomain,
        yxdomain,

        pub fn rcode(k: Of) dns.RCode {
            return switch (k) {
                .answer, .alias, .nodata => .no_error,
                .nxdomain => .name_error,
                .yxdomain => .yx_domain,
            };
        }
    };
};

pub const Answer = struct {
    hops: []const Hop,

    pub const Hop = struct {
        set: CellId,
        judge: OptionalCellId = .none,
    };
};

pub const Outcome = union(enum) {
    reply: struct { msg: dns.Message, rtt_ns: i64, stream: bool },
    timeout,
    unsent,
    moved,
    mismatch,
    malformed,
    oversized,
};

pub const Failure = struct {
    code: dns.Ede.Code,
    text: []const u8 = "",
    cause: enum { zone, host, asker } = .zone,
    remembered: bool = false,
    unplaced: bool = false,

    pub const unreachable_authority: Failure = .{ .code = .no_reachable_authority };
};

pub const Value = union(Kind) {
    cut: Cut,
    addr: []const na.AddressKey,
    rrset: Reply,
    stub: Reply,
    answer: Answer,
    ds: Chain,
    dnskey: Chain,
    secure: Chain,
    exchange: Outcome,
    refresh: void,
    ahead: void,
    parental: void,

    pub fn reply(v: Value) Reply {
        return switch (v) {
            .rrset, .stub => |r| r,
            .cut, .addr, .answer, .ds, .dnskey, .secure, .exchange, .refresh, .ahead, .parental => unreachable,
        };
    }
};

/// `absent`, for `ds` and `dnskey` only: the parent's signed denial shows no
/// delegation, so the name is no zone. Bogus is not a value: it fails.
pub const Proof = enum(u8) { secure, insecure, absent };

pub const Chain = struct {
    status: Proof,
    records: []const dns.ResourceRecord = &.{},
    proven_until_ns: i64 = std.math.maxInt(i64),
};

test "a key's name hash follows the process seed" {
    const saved = rand.hash_seed;
    defer rand.hash_seed = saved;
    const a: Key = .of(.rrset, .lit("www.example"), .a);
    rand.hash_seed = 0xdeadbeefcafef00d;
    const b: Key = .of(.rrset, .lit("www.example"), .a);
    try std.testing.expect(a.name_hash != b.name_hash);
}
