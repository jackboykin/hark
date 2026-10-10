//! A bump arena for one thread. std.heap.ArenaAllocator is lock-free and
//! pays atomics on every allocation; each of hark's arenas belongs to one
//! thread.
//!
//! A chunk ends in its foot and the arena points at the newest, so an
//! allocation that fits touches the arena alone.
const Arena = @This();
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Alignment = mem.Alignment;
const testing = std.testing;

child: Allocator,
at: usize = 0,
foot: ?*Foot = null,

const Foot = struct {
    older: ?*Foot,
    base: [*]u8,

    fn chunk(f: *Foot) []u8 {
        return f.base[0 .. @intFromPtr(f) + @sizeOf(Foot) - @intFromPtr(f.base)];
    }
};

/// std.heap.ArenaAllocator's node header: chunks are sized as std sized
/// its nodes, so a cell lands in the slab it was measured in.
const unheld = 24;

pub fn init(child: Allocator) Arena {
    return .{ .child = child };
}

pub fn deinit(a: Arena) void {
    var it = a.foot;
    while (it) |f| {
        it = f.older;
        a.child.rawFree(f.chunk(), .of(Foot), @returnAddress());
    }
}

pub fn allocator(a: *Arena) Allocator {
    return .{ .ptr = a, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
}

pub fn reset(a: *Arena, mode: enum { free_all, retain_capacity }) void {
    const newest = a.foot orelse return;
    if (mode == .retain_capacity and newest.older == null) {
        a.at = @intFromPtr(newest.base);
        return;
    }
    var room: usize = @sizeOf(Foot);
    var it = a.foot;
    while (it) |f| : (it = f.older) room += f.chunk().len - @sizeOf(Foot);
    a.deinit();
    a.* = .{ .child = a.child };
    if (mode == .retain_capacity) _ = a.open(room, @returnAddress());
}

fn open(a: *Arena, size: usize, ra: usize) ?usize {
    std.debug.assert(size % @alignOf(Foot) == 0);
    const base = a.child.rawAlloc(size, .of(Foot), ra) orelse return null;
    const f: *Foot = @ptrCast(@alignCast(base + size - @sizeOf(Foot)));
    f.* = .{ .older = a.foot, .base = base };
    a.foot = f;
    a.at = @intFromPtr(base);
    return a.at;
}

fn alloc(ctx: *anyopaque, n: usize, alignment: Alignment, ra: usize) ?[*]u8 {
    const a: *Arena = @ptrCast(@alignCast(ctx));
    const p = alignment.forward(a.at);
    if (n <= @intFromPtr(a.foot) -| p) {
        a.at = p + n;
        return @ptrFromInt(p);
    }
    return a.more(n, alignment, ra);
}

fn more(a: *Arena, n: usize, alignment: Alignment, ra: usize) ?[*]u8 {
    @branchHint(.unlikely);
    var held: usize = unheld;
    if (a.foot) |f| {
        const chunk = f.chunk();
        const p = alignment.forward(a.at);
        const size = mem.alignForward(usize, p + n + @sizeOf(Foot) - @intFromPtr(chunk.ptr), @alignOf(Foot));
        if (a.child.rawResize(chunk, .of(Foot), size, ra)) {
            // The new room may lie over the old foot.
            const foot = f.*;
            const moved: *Foot = @ptrCast(@alignCast(chunk.ptr + size - @sizeOf(Foot)));
            moved.* = foot;
            a.foot = moved;
            a.at = p + n;
            return @ptrFromInt(p);
        }
        held = chunk.len;
    }
    const want = held + alignment.toByteUnits() + n + 16;
    const base = a.open(mem.alignForward(usize, want + want / 2, @alignOf(Foot)), ra) orelse return null;
    const p = alignment.forward(base);
    a.at = p + n;
    return @ptrFromInt(p);
}

fn resize(ctx: *anyopaque, memory: []u8, _: Alignment, new_len: usize, _: usize) bool {
    const a: *Arena = @ptrCast(@alignCast(ctx));
    const start = @intFromPtr(memory.ptr);
    if (start + memory.len != a.at) return new_len <= memory.len;
    if (new_len > @intFromPtr(a.foot) - start) return false;
    a.at = start + new_len;
    return true;
}

fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ra: usize) ?[*]u8 {
    return if (resize(ctx, memory, alignment, new_len, ra)) memory.ptr else null;
}

fn free(ctx: *anyopaque, memory: []u8, _: Alignment, _: usize) void {
    const a: *Arena = @ptrCast(@alignCast(ctx));
    if (@intFromPtr(memory.ptr) + memory.len == a.at) a.at = @intFromPtr(memory.ptr);
}

test "an arena is an allocator" {
    var arena: Arena = .init(testing.allocator);
    defer arena.deinit();
    try std.heap.testAllocator(arena.allocator());
    try std.heap.testAllocatorAligned(arena.allocator());
    try std.heap.testAllocatorLargeAlignment(arena.allocator());
    try std.heap.testAllocatorAlignedShrink(arena.allocator());
}

test "allocations are aligned, apart, and keep their bytes across chunks" {
    var arena: Arena = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng: std.Random.DefaultPrng = .init(testing.random_seed);
    const random = prng.random();
    var held: std.ArrayList(struct { bytes: []u8, fill: u8 }) = .empty;
    defer held.deinit(testing.allocator);
    for (0..400) |i| {
        const alignment: Alignment = @fromBackingInt(@intCast(random.uintAtMost(u3, 6)));
        const n = random.intRangeAtMost(usize, 1, 300);
        const bytes = (a.rawAlloc(n, alignment, @returnAddress()) orelse return error.OutOfMemory)[0..n];
        try testing.expect(alignment.check(@intFromPtr(bytes.ptr)));
        @memset(bytes, @truncate(i));
        try held.append(testing.allocator, .{ .bytes = bytes, .fill = @truncate(i) });
    }
    for (held.items) |h| for (h.bytes) |b| try testing.expectEqual(h.fill, b);
}

test "only the newest allocation grows in place" {
    var arena: Arena = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first = try a.alloc(u8, 8);
    const last = try a.alloc(u8, 8);
    try testing.expect(!a.resize(first, 9));
    try testing.expect(a.resize(first, 4));
    try testing.expect(a.resize(last, 16));
    try testing.expect(a.resize(last.ptr[0..16], 2));
    try testing.expect(!a.resize(last.ptr[0..2], 1 << 20));
}

test "a reset arena gives the same memory again" {
    var arena: Arena = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first = try a.alloc(u8, 100);
    arena.reset(.retain_capacity);
    try testing.expectEqual(first.ptr, (try a.alloc(u8, 100)).ptr);
}

test "an allocation the child refuses leaves the arena as it was" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(gpa: Allocator) !void {
            var arena: Arena = .init(gpa);
            defer arena.deinit();
            const a = arena.allocator();
            for ([_]usize{ 100, 200, 400, 800, 1600, 3200 }) |n| {
                const at, const foot = .{ arena.at, arena.foot };
                const bytes = a.alloc(u8, n) catch |err| {
                    try testing.expectEqual(at, arena.at);
                    try testing.expectEqual(foot, arena.foot);
                    return err;
                };
                @memset(bytes, 0xa5);
            }
            arena.reset(.retain_capacity);
            @memset(try a.alloc(u8, 10), 0x5a);
        }
    }.run, .{});
}
