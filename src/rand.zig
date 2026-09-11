/// One thread-local ChaCha CSPRNG behind every draw, seeded once from
/// `io.random` — which takes a global mutex on threads Io.Threaded didn't
/// spawn (all of hark's resolution pool): ~6% CPU on the miss workload.
const std = @import("std");
const Io = std.Io;

threadlocal var csprng: ?std.Random.DefaultCsprng = null;

fn rng(io: Io) std.Random {
    if (csprng == null) {
        @branchHint(.unlikely);
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        io.random(&seed);
        csprng = .init(seed);
    }
    return csprng.?.random();
}

pub fn queryId(io: Io) u16 {
    return rng(io).int(u16);
}

pub fn hashSeed(io: Io) u64 {
    return rng(io).int(u64);
}

pub fn uniformFloat(io: Io) f32 {
    return rng(io).float(f32);
}

pub fn shuffle(comptime T: type, io: Io, items: []T) void {
    rng(io).shuffle(T, items);
}
