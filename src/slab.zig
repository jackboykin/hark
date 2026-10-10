//! hark's allocator. Each `Tenant` serves one lifetime and never shares a
//! slab with another, so long-lived facts and bursty work can't pin each
//! other's memory. A slab that empties goes back to the `Reserve`, where
//! any size class or tenant can take it, or the OS gets it back.
const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const Allocator = mem.Allocator;
const Alignment = mem.Alignment;
const testing = std.testing;
const assert = std.debug.assert;

const slab_len = 64 << 10;
const region_len = 4 << 20;
const slabs_per_region = region_len / slab_len;

const steps = 8;
const fine_max = 128;
const max_slot = 32 << 10;
const class_count = fine_max / 16 + (std.math.log2(max_slot) - std.math.log2(fine_max)) * steps;

const slot_sizes: [class_count]u32 = blk: {
    var sizes: [class_count]u32 = undefined;
    for (&sizes, 0..) |*s, c| {
        if (c < fine_max / 16) {
            s.* = (c + 1) * 16;
        } else {
            const base = fine_max << ((c - fine_max / 16) / steps);
            s.* = base + base / steps * ((c - fine_max / 16) % steps + 1);
        }
    }
    break :blk sizes;
};

/// The 16-byte steps below `fine_max` are its first doubling's eighths,
/// so one formula covers both ranges.
fn classOf(len: usize) u8 {
    const n = len -| 1;
    const k: usize = std.math.log2_int(usize, n | fine_max);
    return @intCast((k - std.math.log2(fine_max) << std.math.log2(steps)) + (n >> @intCast(k - std.math.log2(steps))));
}

/// Slots sit at multiples of their size from a slab's start, and a class
/// `steps` times the alignment or larger is a multiple of it.
fn classFor(len: usize, alignment: Alignment) ?u8 {
    const a = alignment.toByteUnits();
    const n = if (a <= 16) len else @max(len, a * steps);
    if (n > max_slot) return null;
    return classOf(n);
}

const Slot = struct { next: ?*Slot };

const Slab = struct {
    node: std.DoublyLinkedList.Node = .{},
    free: ?*Slot = null,
    fresh: usize = 0,
    end: usize = 0,
    used: u32 = 0,
    class: u8 = 0,
    where: enum(u8) { reserve, current, partial, full } = .reserve,
    dirty: bool = false,
    owner: ?*Tenant = null,

    fn base(slab: *Slab) usize {
        const r: *Region = @ptrFromInt(@intFromPtr(slab) & ~@as(usize, region_len - 1));
        const i = (@intFromPtr(slab) - @intFromPtr(&r.slabs)) / @sizeOf(Slab);
        return @intFromPtr(r) + i * slab_len;
    }

    fn of(ptr: [*]u8) *Slab {
        const r: *Region = @ptrFromInt(@intFromPtr(ptr) & ~@as(usize, region_len - 1));
        return &r.slabs[(@intFromPtr(ptr) & (region_len - 1)) / slab_len];
    }

    fn from(node: *std.DoublyLinkedList.Node) *Slab {
        return @fieldParentPtr("node", node);
    }
};

/// Sits in the region's first 64 KiB, which is never a slab.
const Region = struct {
    slabs: [slabs_per_region]Slab,
    older: ?*Region,

    comptime {
        assert(@sizeOf(Region) <= slab_len);
    }
};

pub const Reserve = struct {
    dirty: std.DoublyLinkedList = .{},
    dirty_count: usize = 0,
    /// The oldest of `dirty`: empty since the last tick at least.
    aged: usize = 0,
    clean: std.DoublyLinkedList = .{},
    held: usize = 0,
    newest: ?*Region = null,

    /// Call every second or so: a slab empty for a whole tick goes back to
    /// the OS, while a load swinging back within one reuses it warm.
    pub fn tick(r: *Reserve) void {
        for (0..r.aged) |_| {
            const cold = Slab.from(r.dirty.popLast().?);
            // Refused, it stays resident; it is empty either way.
            posix.madvise(@ptrFromInt(cold.base()), slab_len, std.os.linux.MADV.DONTNEED) catch {};
            cold.dirty = false;
            r.clean.append(&cold.node);
        }
        r.dirty_count -= r.aged;
        r.aged = r.dirty_count;
    }

    pub fn deinit(r: *Reserve) void {
        var it = r.newest;
        while (it) |region| {
            it = region.older;
            posix.munmap(@as([*]align(region_len) u8, @ptrCast(@alignCast(region)))[0..region_len]);
        }
        r.* = .{};
    }

    fn take(r: *Reserve) ?*Slab {
        const node = r.dirty.popFirst() orelse r.clean.popFirst() orelse blk: {
            r.grow() orelse return null;
            break :blk r.clean.popFirst().?;
        };
        const slab = Slab.from(node);
        if (slab.dirty) {
            r.dirty_count -= 1;
            r.aged = @min(r.aged, r.dirty_count);
        }
        r.held += 1;
        return slab;
    }

    fn give(r: *Reserve, slab: *Slab) void {
        slab.where = .reserve;
        slab.owner = null;
        r.held -= 1;
        r.dirty.prepend(&slab.node);
        r.dirty_count += 1;
    }

    fn grow(r: *Reserve) ?void {
        const raw = posix.mmap(null, 2 * region_len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch return null;
        const start = mem.alignForward(usize, @intFromPtr(raw.ptr), region_len);
        const head = start - @intFromPtr(raw.ptr);
        if (head > 0) posix.munmap(raw[0..head]);
        if (region_len - head > 0) posix.munmap(@alignCast(raw[head + region_len ..]));
        const region: *Region = @ptrFromInt(start);
        region.* = .{ .slabs = @splat(.{}), .older = r.newest };
        r.newest = region;
        for (region.slabs[1..]) |*slab| r.clean.append(&slab.node);
    }
};

pub const Tenant = struct {
    reserve: *Reserve,
    current: [class_count]?*Slab = @splat(null),
    partial: [class_count]std.DoublyLinkedList = @splat(.{}),

    pub fn init(reserve: *Reserve) Tenant {
        return .{ .reserve = reserve };
    }

    pub fn allocator(t: *Tenant) Allocator {
        return .{ .ptr = t, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, _: usize) ?[*]u8 {
        const t: *Tenant = @ptrCast(@alignCast(ctx));
        const c = classFor(len, alignment) orelse {
            @branchHint(.unlikely);
            return std.heap.PageAllocator.map(len, alignment);
        };
        if (t.current[c]) |slab| if (take(slab)) |slot| return slot;
        return t.refill(c);
    }

    fn take(slab: *Slab) ?[*]u8 {
        if (slab.free) |s| {
            slab.free = s.next;
            slab.used += 1;
            return @ptrCast(s);
        }
        if (slab.fresh < slab.end) {
            const at = slab.fresh;
            slab.fresh += slot_sizes[slab.class];
            slab.used += 1;
            return @ptrFromInt(at);
        }
        return null;
    }

    fn refill(t: *Tenant, c: u8) ?[*]u8 {
        @branchHint(.unlikely);
        const slab = if (t.partial[c].popFirst()) |n| Slab.from(n) else blk: {
            const empty = t.reserve.take() orelse return null;
            const size = slot_sizes[c];
            const at = empty.base();
            empty.* = .{ .node = empty.node, .dirty = true, .class = c, .owner = t, .fresh = at, .end = at + slab_len / size * size };
            break :blk empty;
        };
        if (t.current[c]) |full| full.where = .full;
        slab.where = .current;
        t.current[c] = slab;
        return take(slab).?;
    }

    fn resize(_: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, _: usize) bool {
        if (classFor(memory.len, alignment) == null) {
            if (classFor(new_len, alignment) != null) return false;
            return std.heap.PageAllocator.realloc(memory, alignment, new_len, false) != null;
        }
        return new_len <= slot_sizes[Slab.of(memory.ptr).class];
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ra: usize) ?[*]u8 {
        if (classFor(memory.len, alignment) == null and classFor(new_len, alignment) == null)
            return std.heap.PageAllocator.realloc(memory, alignment, new_len, true);
        return if (resize(ctx, memory, alignment, new_len, ra)) memory.ptr else null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, _: usize) void {
        const t: *Tenant = @ptrCast(@alignCast(ctx));
        if (classFor(memory.len, alignment) == null) {
            @branchHint(.unlikely);
            return std.heap.PageAllocator.unmap(@alignCast(memory));
        }
        const slab = Slab.of(memory.ptr);
        assert(slab.owner == t and slab.used > 0);
        const s: *Slot = @ptrCast(@alignCast(memory.ptr));
        s.next = slab.free;
        slab.free = s;
        slab.used -= 1;
        // An empty slab is always the reserve's.
        switch (slab.where) {
            .full => {
                slab.where = .partial;
                if (slab.used > 0) return t.partial[slab.class].prepend(&slab.node);
            },
            .partial => if (slab.used > 0) return else t.partial[slab.class].remove(&slab.node),
            .current => if (slab.used > 0) return else {
                t.current[slab.class] = null;
            },
            .reserve => unreachable,
        }
        t.reserve.give(slab);
    }
};

test "a tenant is an allocator" {
    var reserve: Reserve = .{};
    defer reserve.deinit();
    var t: Tenant = .init(&reserve);
    const a = t.allocator();
    try std.heap.testAllocator(a);
    try std.heap.testAllocatorAligned(a);
    try std.heap.testAllocatorLargeAlignment(a);
    try std.heap.testAllocatorAlignedShrink(a);
}

test "every length lands in the least slot that holds it, an eighth over at most" {
    for (1..max_slot + 1) |len| {
        const c = classOf(len);
        try testing.expect(slot_sizes[c] >= len);
        if (c > 0) try testing.expect(slot_sizes[c - 1] < len);
        if (len > fine_max) try testing.expect((slot_sizes[c] - len) * steps < len);
    }
}

test "slots keep their bytes, and every slab goes home when all is freed" {
    var reserve: Reserve = .{};
    defer reserve.deinit();
    var t: Tenant = .init(&reserve);
    const a = t.allocator();
    var prng: std.Random.DefaultPrng = .init(testing.random_seed);
    const random = prng.random();
    const Held = struct { bytes: []u8, fill: u8 };
    var held: std.ArrayList(Held) = .empty;
    defer held.deinit(testing.allocator);
    for (0..20000) |i| {
        if (held.items.len > 0 and random.uintLessThan(u8, 5) < 2) {
            const k = random.uintLessThan(usize, held.items.len);
            const x = held.swapRemove(k);
            for (x.bytes) |b| try testing.expectEqual(x.fill, b);
            a.free(x.bytes);
            continue;
        }
        const len = if (random.uintLessThan(u8, 50) == 0) random.intRangeAtMost(usize, max_slot, 3 * max_slot) else random.intRangeAtMost(usize, 1, 2048);
        const bytes = try a.alloc(u8, len);
        @memset(bytes, @truncate(i));
        try held.append(testing.allocator, .{ .bytes = bytes, .fill = @truncate(i) });
    }
    for (held.items) |x| {
        for (x.bytes) |b| try testing.expectEqual(x.fill, b);
        a.free(x.bytes);
    }
    try testing.expectEqual(0, reserve.held);
}

test "slabs one class emptied serve another, and the rest go back to the OS" {
    var reserve: Reserve = .{};
    defer reserve.deinit();
    var work: Tenant = .init(&reserve);
    var facts: Tenant = .init(&reserve);
    var burst: [4096][]u8 = undefined;
    for (&burst) |*b| b.* = try work.allocator().alloc(u8, 1000);
    const regions = reserve.newest;
    const peak = reserve.held;
    for (burst) |b| work.allocator().free(b);
    try testing.expectEqual(0, reserve.held);
    const at: [*]u8 = @ptrFromInt(mem.alignBackward(usize, @intFromPtr(burst[0].ptr), slab_len));
    reserve.tick();
    try testing.expect(resident(at));
    reserve.tick();
    try testing.expect(!resident(at));
    for (&burst) |*b| b.* = try facts.allocator().alloc(u8, 300);
    try testing.expectEqual(regions, reserve.newest);
    try testing.expect(reserve.held < peak);
    for (burst) |b| facts.allocator().free(b);
}

fn resident(slab: [*]u8) bool {
    var pages: [slab_len / std.heap.page_size_min]u8 = undefined;
    assert(std.os.linux.mincore(slab, slab_len, &pages) == 0);
    for (pages) |p| if (p & 1 != 0) return true;
    return false;
}
