/// Centralized random helpers. Two tiers:
///   - Crypto (`io.random`): query IDs, source ports, 0x20 case bits, hash
///     seeds — RFC 5452 §9 spoofing mitigations need cryptographic quality.
///   - Fast (`fast*` family): NS shuffle, Thompson / Beta / Box-Muller
///     sampling — tactical bandit decisions where statistical quality is
///     fine and speed dominates. Crypto is seeded once per thread; the
///     fast PRNG is a thread-local Xoshiro256++ derived from that seed.
const std = @import("std");
const mem = std.mem;
const Io = std.Io;

/// Generate a random DNS query ID.
pub fn queryId(io: Io) u16 {
    var buf: [2]u8 = undefined;
    io.random(&buf);
    return mem.readInt(u16, &buf, .big);
}

/// Generate a random u64 hash seed.
pub fn hashSeed(io: Io) u64 {
    var buf: [8]u8 = undefined;
    io.random(&buf);
    return mem.readInt(u64, &buf, .little);
}

// ── Fast tactical RNG ────────────────────────────────────────────────
//
// std.Io.random funnels every call to a global mutex when the calling
// thread is not registered with std.Io.Threaded. Hark's resolution pool
// threads aren't registered, so on the miss workload Thompson sampling
// alone (~13 floats × 350k QPS = ~5M calls/s) put `randomMainThread` at
// ~6% of CPU. The fix is a thread-local Xoshiro256++ seeded once from
// io.random — sub-ns per draw, no contention.

threadlocal var fast_prng: ?std.Random.Xoshiro256 = null;

fn fastPrng(io: Io) *std.Random.Xoshiro256 {
    if (fast_prng == null) {
        @branchHint(.unlikely);
        var seed_buf: [8]u8 = undefined;
        io.random(&seed_buf);
        fast_prng = std.Random.Xoshiro256.init(mem.readInt(u64, &seed_buf, .little));
    }
    return &fast_prng.?;
}

/// Tactical-quality uniform [0,1) — NOT crypto. For Thompson / Beta sampling.
pub fn fastUniformFloat(io: Io) f32 {
    return fastPrng(io).random().float(f32);
}

/// Tactical-quality Fisher-Yates shuffle — NOT crypto.
pub fn fastShuffle(comptime T: type, io: Io, items: []T) void {
    fastPrng(io).random().shuffle(T, items);
}
