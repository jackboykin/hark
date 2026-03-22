/// Centralized random helpers. In Zig 0.16, std.crypto.random is removed
/// and replaced by std.Io.randomSecure(io, buf) — update only this file.
const std = @import("std");
const mem = std.mem;

/// Generate a random DNS query ID.
pub fn queryId() u16 {
    var buf: [2]u8 = undefined;
    std.crypto.random.bytes(&buf);
    return mem.readInt(u16, &buf, .big);
}

/// Generate a random ephemeral port in [1024, 65535]. Uses the full
/// unprivileged range rather than the narrower IANA dynamic range
/// [49152, 65535] to maximise source port entropy (~16 bits vs ~14)
/// for Kaminsky-attack resistance (RFC 5452 §9.1).
pub fn ephemeralPort() u16 {
    return std.crypto.random.intRangeAtMost(u16, 1024, 65535);
}

/// Uniform(0,1) float from crypto random, excluding exact 0.
pub fn uniformFloat() f32 {
    var buf: [4]u8 = undefined;
    std.crypto.random.bytes(&buf);
    const bits: u32 = mem.readInt(u32, &buf, .little);
    return (@as(f32, @floatFromInt(bits)) + 0.5) / 4294967296.0;
}

/// Fisher-Yates shuffle using crypto random.
pub fn shuffle(comptime T: type, items: []T) void {
    if (items.len <= 1) return;
    var i: usize = items.len - 1;
    while (i > 0) : (i -= 1) {
        const j = std.crypto.random.uintLessThan(usize, i + 1);
        const tmp = items[i];
        items[i] = items[j];
        items[j] = tmp;
    }
}
