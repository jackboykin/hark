//! Each thread's ChaCha CSPRNG, as `thread`, and the seeded hash over what a
//! stranger picks.

const std = @import("std");
const linux = std.os.linux;

threadlocal var csprng: ?std.Random.DefaultCsprng = null;

/// Seeds every hash over keys a stranger picks, so collisions can't be ground
/// offline. Set once, before anything is hashed; 0 in tests so replays repeat.
pub var hash_seed: u64 = 0;

pub fn randomizeHashSeed() void {
    hash_seed = thread.int(u64);
}

pub const Seeded = struct {
    pub fn hash(_: Seeded, k: []const u8) u32 {
        return @truncate(std.hash.Wyhash.hash(hash_seed, k));
    }
    pub fn eql(_: Seeded, a: []const u8, b: []const u8, _: usize) bool {
        return std.mem.eql(u8, a, b);
    }
};

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
