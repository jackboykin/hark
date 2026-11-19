//! Each thread's ChaCha CSPRNG, as `thread`, and the keyed hash over what a
//! stranger picks.

const std = @import("std");
const mem = std.mem;
const linux = std.os.linux;
const rand = @This();

threadlocal var csprng: ?std.Random.DefaultCsprng = null;

/// Set once, before anything is hashed; zero in tests so replays repeat.
pub var hash_key: [16]u8 = @splat(0);

pub fn randomizeHashKey() void {
    thread.bytes(&hash_key);
}

/// Per-thread, not `io.random`: its global mutex costs ~6% CPU on misses.
pub const thread: std.Random = .{ .ptr = undefined, .fillFn = fill };

fn fill(_: *anyopaque, buf: []u8) void {
    if (csprng == null) {
        @branchHint(.unlikely);
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        // No fallback seed: guessable TXIDs are worse than no resolver.
        if (linux.getrandom(&seed, seed.len, 0) != seed.len) @panic("getrandom failed");
        csprng = .init(seed);
    }
    csprng.?.fill(buf);
}

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

pub const Keyed = struct {
    pub fn hash(_: Keyed, k: []const u8) u32 {
        return @truncate(rand.hash(k));
    }
    pub fn eql(_: Keyed, a: []const u8, b: []const u8, _: usize) bool {
        return mem.eql(u8, a, b);
    }
    pub fn own(gpa: mem.Allocator, k: []const u8) ![]const u8 {
        return gpa.dupe(u8, k);
    }
    pub fn free(gpa: mem.Allocator, k: []const u8) void {
        gpa.free(k);
    }
};

test "thread draws differ across threads" {
    const T = struct {
        fn draw(out: *u64) void {
            out.* = thread.int(u64);
        }
    };
    var a: u64 = 0;
    var b: u64 = 0;
    const t = try std.Thread.spawn(.{}, T.draw, .{&a});
    T.draw(&b);
    t.join();
    try std.testing.expect(a != b);
}

test "hash is SipHash-1-3 under the key, at every length" {
    const saved = hash_key;
    defer hash_key = saved;
    thread.bytes(&hash_key);
    var buf: [256]u8 = undefined;
    thread.bytes(&buf);
    for (0..buf.len + 1) |n| try std.testing.expectEqual(Hasher.toInt(buf[0..n], &hash_key), hash(buf[0..n]));
}
