//! Tables keyed by what a stranger picks: SipHash-1-3 under a key drawn once
//! a process, the context that hashes strings with it, and a bounded memory
//! that forgets by it.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const keyed = @This();

/// Set once, before anything is hashed; zero in tests so replays repeat.
pub var hash_key: [16]u8 = @splat(0);

/// SipHash-1-3: Wyhash's secrets are constant, so some inputs collide under
/// every seed.
pub const Hasher = std.crypto.auth.siphash.SipHash64(1, 3);

/// `Hasher` in one pass: std's buffers, costing a quarter more on a name.
pub fn hash(m: []const u8) u64 {
    const k0 = mem.readInt(u64, hash_key[0..8], .little);
    const k1 = mem.readInt(u64, hash_key[8..16], .little);
    var v: [4]u64 = .{ k0 ^ 0x736f6d6570736575, k1 ^ 0x646f72616e646f6d, k0 ^ 0x6c7967656e657261, k1 ^ 0x7465646279746573 };
    var i: usize = 0;
    while (i + 8 <= m.len) : (i += 8) compress(&v, mem.readInt(u64, m[i..][0..8], .little));
    compress(&v, (@as(u64, m.len) << 56) | tail(m, i));
    v[2] ^= 0xff;
    inline for (0..3) |_| round(&v);
    return v[0] ^ v[1] ^ v[2] ^ v[3];
}

fn compress(v: *[4]u64, w: u64) void {
    v[3] ^= w;
    round(v);
    v[0] ^= w;
}

fn tail(m: []const u8, i: usize) u64 {
    const rem = m.len - i;
    if (rem == 0) return 0;
    if (m.len >= 8) return mem.readInt(u64, m[m.len - 8 ..][0..8], .little) >> @intCast(8 * (8 - rem));
    var t: [8]u8 = @splat(0);
    @memcpy(t[0..rem], m[i..]);
    return mem.readInt(u64, &t, .little);
}

fn round(v: *[4]u64) void {
    v[0] +%= v[1];
    v[1] = std.math.rotl(u64, v[1], 13) ^ v[0];
    v[0] = std.math.rotl(u64, v[0], 32);
    v[2] +%= v[3];
    v[3] = std.math.rotl(u64, v[3], 16) ^ v[2];
    v[0] +%= v[3];
    v[3] = std.math.rotl(u64, v[3], 21) ^ v[0];
    v[2] +%= v[1];
    v[1] = std.math.rotl(u64, v[1], 17) ^ v[2];
    v[2] = std.math.rotl(u64, v[2], 32);
}

pub const Strings = struct {
    pub fn hash(_: Strings, k: []const u8) u32 {
        return @truncate(keyed.hash(k));
    }
    pub fn eql(_: Strings, a: []const u8, b: []const u8, _: usize) bool {
        return mem.eql(u8, a, b);
    }
    pub fn own(gpa: Allocator, k: []const u8) ![]const u8 {
        return gpa.dupe(u8, k);
    }
    pub fn free(gpa: Allocator, k: []const u8) void {
        gpa.free(k);
    }
};

/// A bounded memory of what failed lately: each entry stands until its own
/// time, and what it means is its owner's. `Context` hashes and compares keys,
/// and owns and frees what a key borrows.
pub fn Memory(comptime K: type, comptime V: type, comptime Context: type) type {
    return struct {
        map: std.array_hash_map.Custom(K, Entry, Context, true) = .empty,

        const Entry = struct { until_ns: i64, is: V };
        pub const max_entries = 4096;

        pub fn deinit(m: *@This(), gpa: Allocator) void {
            for (m.map.keys()) |k| Context.free(gpa, k);
            m.map.deinit(gpa);
        }

        pub fn get(m: *const @This(), k: K, now_ns: i64) ?V {
            if (m.map.count() == 0) return null;
            const e = m.map.get(k) orelse return null;
            return if (e.until_ns > now_ns) e.is else null;
        }

        /// At `max_entries` another entry is evicted, picked by the keyed hash
        /// of this key so no asker can choose it.
        pub fn put(m: *@This(), gpa: Allocator, k: K, e: Entry) !void {
            if (m.map.getPtr(k)) |old| {
                old.* = e;
                return;
            }
            if (m.map.count() >= max_entries) {
                const at = Context.hash(.{}, k) % m.map.count();
                const old = m.map.keys()[at];
                m.map.swapRemoveAt(at);
                Context.free(gpa, old);
            }
            const own = try Context.own(gpa, k);
            errdefer Context.free(gpa, own);
            try m.map.put(gpa, own, e);
        }

        pub fn forget(m: *@This(), gpa: Allocator, k: K) void {
            if (m.map.fetchSwapRemove(k)) |kv| Context.free(gpa, kv.key);
        }
    };
}

test "hash is SipHash-1-3 under the key, at every length" {
    const saved = hash_key;
    defer hash_key = saved;
    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    prng.random().bytes(&hash_key);
    var buf: [256]u8 = undefined;
    prng.random().bytes(&buf);
    for (0..buf.len + 1) |n| try std.testing.expectEqual(Hasher.toInt(buf[0..n], &hash_key), hash(buf[0..n]));
}
