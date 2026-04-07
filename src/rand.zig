/// Centralized random helpers. Uses std.Io.random() for CSPRNG.
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

/// Generate a random ephemeral port in [1024, 65535]. Uses the full
/// unprivileged range rather than the narrower IANA dynamic range
/// [49152, 65535] to maximise source port entropy (~16 bits vs ~14)
/// for Kaminsky-attack resistance (RFC 5452 §9.1).
pub fn ephemeralPort(io: Io) u16 {
    return intRangeAtMost(u16, io, 1024, 65535);
}

/// Uniform(0,1) float from crypto random, excluding exact 0.
pub fn uniformFloat(io: Io) f32 {
    var buf: [4]u8 = undefined;
    io.random(&buf);
    const bits: u32 = mem.readInt(u32, &buf, .little);
    return (@as(f32, @floatFromInt(bits)) + 0.5) / 4294967296.0;
}

/// Fisher-Yates shuffle using crypto random.
pub fn shuffle(comptime T: type, io: Io, items: []T) void {
    if (items.len <= 1) return;
    var i: usize = items.len - 1;
    while (i > 0) : (i -= 1) {
        const j = uintLessThan(usize, io, i + 1);
        const tmp = items[i];
        items[i] = items[j];
        items[j] = tmp;
    }
}

/// Random integer in [at_least, at_most] inclusive. Debiased modulo
/// rejection sampling.
fn intRangeAtMost(comptime T: type, io: Io, at_least: T, at_most: T) T {
    const range: @TypeOf(@as(T, 0) +% 1) = at_most - at_least;
    return at_least +| @as(T, @intCast(uintLessThan(@TypeOf(@as(T, 0) +% 1), io, range + 1)));
}

/// Random integer in [0, less_than). Rejection sampling.
fn uintLessThan(comptime T: type, io: Io, less_than: T) T {
    std.debug.assert(less_than > 0);
    const bits = @bitSizeOf(T);
    var buf: [bits / 8]u8 = undefined;
    while (true) {
        io.random(&buf);
        const val = mem.readInt(T, &buf, .little);
        // Debiased modulo reduction: reject values in the biased tail
        const rem = val % less_than;
        if (val -% rem <= (0 -% less_than)) return rem;
    }
}
