//! hark's allocator: size classes on 64 KiB slabs, each slab one `Tenant`'s,
//! a tenant per lifetime, and the `Reserve` a slab goes back to when it
//! empties, where any size class or tenant can take it, or the OS gets it
//! back.
const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const Allocator = mem.Allocator;
const Alignment = mem.Alignment;
const testing = std.testing;
const assert = std.debug.assert;
const Share = @import("share.zig");

const slab_len = 64 << 10;
const region_len = 4 << 20;
const slabs_per_region = region_len / slab_len;

const steps = 8;
const fine_max = 128;
const max_slot = 32 << 10;
const class_count = fine_max / 16 + (std.math.log2(max_slot) - std.math.log2(fine_max)) * steps;

const safe = @import("builtin").mode.runtimeSafety();
const quarantined = @import("builtin").mode == .debug;
const quarantine_bytes = 4 << 20;

const slot_sizes: [class_count]u32 = blk: {
    var sizes: [class_count]u32 = undefined;
    for (&sizes, 0..) |*s, c| {
        if (c < fine_max / 16) {
            s.* = (c + 1) * 16;
        } else {
            const base = fine_max << ((c - fine_max / 16) / steps);
            s.* = base + base / steps * ((c - fine_max / 16) % steps + 1);
        }
        assert(s.* % 16 == 0);
    }
    break :blk sizes;
};

fn classOf(len: usize) u8 {
    const n = len -| 1;
    const k: usize = std.math.log2_int(usize, n | fine_max);
    return @intCast(((k - std.math.log2(fine_max)) << std.math.log2(steps)) + (n >> @intCast(k - std.math.log2(steps))));
}

/// Slots sit at multiples of their size from the slab's start, and every
/// class of at least `steps` times the alignment is a multiple of it.
fn classFor(len: usize, alignment: Alignment) ?u8 {
    const a = alignment.toByteUnits();
    const n = if (a <= 16) len else @max(len, a * steps);
    if (n > max_slot) return null;
    return classOf(n);
}

fn paged(len: usize) usize {
    return mem.alignForward(usize, len, std.heap.pageSize());
}

const Slot = struct { next: ?*Slot };

const most_slots = slab_len / 16;

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
    out: if (safe) std.bit_set.Static(most_slots) else void = if (safe) .empty else {},

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

    fn slot(slab: *Slab, ptr: [*]u8) ?usize {
        const at = @intFromPtr(ptr);
        if (at >= slab.fresh or at & 15 != 0) return null;
        return (at & (slab_len - 1)) >> 4;
    }

    fn handOut(slab: *Slab, ptr: [*]u8) void {
        const i = slab.slot(ptr).?;
        if (slab.out.isSet(i)) @panic("slab: handed out a slot twice");
        slab.out.set(i);
    }

    fn takeBack(slab: *Slab, memory: []u8) ?[]const u8 {
        const i = slab.slot(memory.ptr) orelse return "slab: freed a pointer that is no slot";
        if (!slab.out.isSet(i)) return "slab: double free, or a slot never handed out";
        if (memory.len > slot_sizes[slab.class]) return "slab: freed more than its slot";
        slab.out.unset(i);
        return null;
    }
};

const Quarantine = struct {
    ring: [][*]u8 = &.{},
    head: usize = 0,
    len: usize = 0,
    bytes: usize = 0,

    const ring_len = quarantine_bytes / 16;

    fn hold(q: *Quarantine, ptr: [*]u8, size: usize) void {
        if (q.ring.len == 0) {
            const raw = std.heap.PageAllocator.map(ring_len * @sizeOf([*]u8), .of([*]u8)) orelse return Tenant.release(Slab.of(ptr), ptr);
            q.ring = @as([*][*]u8, @ptrCast(@alignCast(raw)))[0..ring_len];
        }
        while (q.len == ring_len or q.bytes + size > quarantine_bytes) q.evict();
        q.ring[(q.head + q.len) % ring_len] = ptr;
        q.len += 1;
        q.bytes += size;
    }

    fn evict(q: *Quarantine) void {
        const ptr = q.ring[q.head];
        q.head = (q.head + 1) % ring_len;
        q.len -= 1;
        const slab = Slab.of(ptr);
        const size = slot_sizes[slab.class];
        q.bytes -= size;
        if (!mem.allEqual(u8, ptr[0..size], 0xaa)) @panic("slab: a slot was written after it was freed");
        Tenant.release(slab, ptr);
    }

    fn drain(q: *Quarantine) void {
        while (q.len > 0) q.evict();
    }

    fn deinit(q: *Quarantine) void {
        if (q.ring.len != 0) std.heap.PageAllocator.unmap(@alignCast(mem.sliceAsBytes(q.ring)));
        q.* = .{};
    }
};

/// Lives in the region's first 64 KiB, so `slabs[0]` is never handed out.
const Region = struct {
    slabs: [slabs_per_region]Slab,
    older: ?*Region,

    comptime {
        assert(@sizeOf(Region) <= slab_len);
    }
};

pub const Reserve = struct {
    limit: usize = std.math.maxInt(usize),
    whole: Share = .{},
    regions: usize = 0,
    mapped: usize = 0,
    dirty: std.DoublyLinkedList = .{},
    dirty_count: usize = 0,
    aged: usize = 0,
    clean: std.DoublyLinkedList = .{},
    held: usize = 0,
    newest: ?*Region = null,
    quarantine: if (quarantined) Quarantine else void = if (quarantined) .{} else {},

    /// Call about once a second: a slab empty for a whole tick goes back to the OS.
    pub fn tick(r: *Reserve) void {
        for (0..r.aged) |_| {
            const cold = Slab.from(r.dirty.popLast().?);
            posix.madvise(@ptrFromInt(cold.base()), slab_len, std.os.linux.MADV.DONTNEED) catch {};
            cold.dirty = false;
            r.clean.append(&cold.node);
        }
        r.dirty_count -= r.aged;
        r.aged = r.dirty_count;
    }

    pub fn drain(r: *Reserve) void {
        if (quarantined) r.quarantine.drain();
    }

    pub fn deinit(r: *Reserve) void {
        r.drain();
        if (quarantined) r.quarantine.deinit();
        var it = r.newest;
        while (it) |region| {
            it = region.older;
            posix.munmap(@as([*]align(region_len) u8, @ptrCast(@alignCast(region)))[0..region_len]);
        }
        r.* = .{};
    }

    pub fn resident(r: *const Reserve) usize {
        return (r.held + r.dirty_count + r.regions) * slab_len + r.mapped;
    }

    fn fits(r: *const Reserve, n: usize) bool {
        return r.resident() + n <= r.limit;
    }

    /// A dirty slab is already resident, so it is free to take. A clean one, or a
    /// new region with its header slab, must fit under the limit.
    fn take(r: *Reserve) ?*Slab {
        const node = r.dirty.popFirst() orelse blk: {
            if (!r.fits(slab_len)) return null;
            break :blk r.clean.popFirst() orelse grown: {
                if (!r.fits(2 * slab_len)) return null;
                r.grow() orelse return null;
                break :grown r.clean.popFirst().?;
            };
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
        posix.madvise(@ptrFromInt(start), region_len, std.os.linux.MADV.NOHUGEPAGE) catch {};
        const region: *Region = @ptrFromInt(start);
        region.* = .{ .slabs = @splat(.{}), .older = r.newest };
        r.newest = region;
        r.regions += 1;
        for (region.slabs[1..]) |*slab| r.clean.append(&slab.node);
    }
};

pub const Tenant = struct {
    reserve: *Reserve,
    share: *Share,
    current: [class_count]?*Slab = @splat(null),
    partial: [class_count]std.DoublyLinkedList = @splat(.{}),

    pub fn init(reserve: *Reserve) Tenant {
        return .in(reserve, &reserve.whole);
    }

    pub fn in(reserve: *Reserve, share: *Share) Tenant {
        return .{ .reserve = reserve, .share = share };
    }

    pub fn allocator(t: *Tenant) Allocator {
        return .{ .ptr = t, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, _: usize) ?[*]u8 {
        const t: *Tenant = @ptrCast(@alignCast(ctx));
        const c = classFor(len, alignment) orelse {
            @branchHint(.unlikely);
            if (!t.mappable(paged(len))) return null;
            const p = std.heap.PageAllocator.map(len, alignment) orelse return null;
            t.mapped(paged(len), 0);
            return p;
        };
        if (!t.share.room(slot_sizes[c])) return null;
        const slot = (if (t.current[c]) |slab| take(slab) else null) orelse t.refill(c) orelse return null;
        t.share.held += slot_sizes[c];
        return slot;
    }

    fn take(slab: *Slab) ?[*]u8 {
        const ptr: [*]u8 = if (slab.free) |s| blk: {
            slab.free = s.next;
            break :blk @ptrCast(s);
        } else if (slab.fresh < slab.end) blk: {
            const at = slab.fresh;
            slab.fresh += slot_sizes[slab.class];
            break :blk @ptrFromInt(at);
        } else return null;
        slab.used += 1;
        if (safe) slab.handOut(ptr);
        return ptr;
    }

    fn refill(t: *Tenant, c: u8) ?[*]u8 {
        @branchHint(.unlikely);
        const slab = if (t.partial[c].popFirst()) |n| Slab.from(n) else blk: {
            const empty = t.reserve.take() orelse return null;
            const size = slot_sizes[c];
            const at = empty.base();
            assert(empty.used == 0);
            empty.free = null;
            empty.fresh = at;
            empty.end = at + slab_len / size * size;
            empty.class = c;
            empty.dirty = true;
            empty.owner = t;
            break :blk empty;
        };
        if (t.current[c]) |full| full.where = .full;
        slab.where = .current;
        t.current[c] = slab;
        return take(slab).?;
    }

    /// `free` tells a mapping from a slot by length alone, so no resize may
    /// carry an allocation across `max_slot`.
    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, _: usize) bool {
        if (classFor(memory.len, alignment) == null) {
            if (classFor(new_len, alignment) != null) return false;
            return @as(*Tenant, @ptrCast(@alignCast(ctx))).remapped(memory, alignment, new_len, false) != null;
        }
        return new_len <= slot_sizes[Slab.of(memory.ptr).class];
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ra: usize) ?[*]u8 {
        if (classFor(memory.len, alignment) == null and classFor(new_len, alignment) == null)
            return @as(*Tenant, @ptrCast(@alignCast(ctx))).remapped(memory, alignment, new_len, true);
        return if (resize(ctx, memory, alignment, new_len, ra)) memory.ptr else null;
    }

    fn remapped(t: *Tenant, memory: []u8, alignment: Alignment, new_len: usize, may_move: bool) ?[*]u8 {
        const old = paged(memory.len);
        const new = paged(new_len);
        if (new > old and !t.mappable(new - old)) return null;
        const p = std.heap.PageAllocator.realloc(memory, alignment, new_len, may_move) orelse return null;
        t.mapped(new, old);
        return p;
    }

    fn mappable(t: *const Tenant, n: usize) bool {
        return t.share.room(n) and t.reserve.fits(n);
    }

    fn mapped(t: *Tenant, new: usize, old: usize) void {
        t.share.held = t.share.held - old + new;
        t.reserve.mapped = t.reserve.mapped - old + new;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, _: usize) void {
        const t: *Tenant = @ptrCast(@alignCast(ctx));
        if (classFor(memory.len, alignment) == null) {
            @branchHint(.unlikely);
            t.mapped(0, paged(memory.len));
            return std.heap.PageAllocator.unmap(@alignCast(memory));
        }
        const slab = Slab.of(memory.ptr);
        assert(slab.owner == t and slab.used > 0);
        t.share.held -= slot_sizes[slab.class];
        if (!safe) return release(slab, memory.ptr);
        if (slab.takeBack(memory)) |why| @panic(why);
        if (!quarantined) return release(slab, memory.ptr);
        const size = slot_sizes[slab.class];
        @memset(memory.ptr[0..size], 0xaa);
        t.reserve.quarantine.hold(memory.ptr, size);
    }

    fn release(slab: *Slab, ptr: [*]u8) void {
        const t = slab.owner.?;
        const s: *Slot = @ptrCast(@alignCast(ptr));
        s.next = slab.free;
        slab.free = s;
        slab.used -= 1;
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
    try testing.expectEqual(0, reserve.whole.held);
    reserve.drain();
    try testing.expectEqual(0, reserve.held);
}

test "a tenant holds its slots at their size and its mappings in pages" {
    var reserve: Reserve = .{};
    defer reserve.deinit();
    var t: Tenant = .init(&reserve);
    const a = t.allocator();
    const small = try a.alloc(u8, 17);
    const mid = try a.alloc(u8, 200);
    var big = try a.alloc(u8, max_slot + 1);
    try testing.expectEqual(slot_sizes[classOf(17)] + slot_sizes[classOf(200)] + paged(max_slot + 1), reserve.whole.held);
    big = try a.realloc(big, 4 * max_slot);
    try testing.expectEqual(slot_sizes[classOf(17)] + slot_sizes[classOf(200)] + paged(4 * max_slot), reserve.whole.held);
    a.free(big);
    a.free(mid);
    a.free(small);
    try testing.expectEqual(0, reserve.whole.held);
}

test "a reserve grants nothing past its limit, nor a share past its own" {
    var reserve: Reserve = .{ .limit = 3 * slab_len };
    defer reserve.deinit();
    var small: Share = .{ .limit = 64 };
    var t: Tenant = .in(&reserve, &small);
    var u: Tenant = .init(&reserve);
    const one = try t.allocator().alloc(u8, 40);
    try testing.expectError(error.OutOfMemory, t.allocator().alloc(u8, 40));
    const two = try u.allocator().alloc(u8, 400);
    try testing.expectError(error.OutOfMemory, u.allocator().alloc(u8, 4000));
    try testing.expectError(error.OutOfMemory, u.allocator().alloc(u8, max_slot + 1));
    t.allocator().free(one);
    u.allocator().free(two);
    try testing.expectEqual(0, small.held + reserve.whole.held);
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
    reserve.drain();
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

test "a free of anything but a slot handed out is a fault" {
    if (!safe) return error.SkipZigTest;
    var reserve: Reserve = .{};
    defer reserve.deinit();
    var t: Tenant = .init(&reserve);
    const a = t.allocator();
    const x = try a.alloc(u8, 40);
    const slab = Slab.of(x.ptr);
    const size = slot_sizes[slab.class];
    try testing.expectEqualStrings("slab: freed more than its slot", slab.takeBack(x.ptr[0 .. size + 1]).?);
    try testing.expectEqualStrings("slab: freed a pointer that is no slot", slab.takeBack(x.ptr[1..41]).?);
    try testing.expectEqualStrings("slab: freed a pointer that is no slot", slab.takeBack((x.ptr + size)[0..40]).?);
    try testing.expectEqualStrings("slab: double free, or a slot never handed out", slab.takeBack(x.ptr[16..40]).?);
    a.free(x);
    try testing.expectEqualStrings("slab: double free, or a slot never handed out", slab.takeBack(x).?);
}

test "a freed slot comes back only after the quarantine has moved past it" {
    if (!quarantined) return error.SkipZigTest;
    var reserve: Reserve = .{};
    defer reserve.deinit();
    var t: Tenant = .init(&reserve);
    const a = t.allocator();
    const x = try a.alloc(u8, 40);
    a.free(x);
    try testing.expect(mem.allEqual(u8, x.ptr[0..slot_sizes[Slab.of(x.ptr).class]], 0xaa));
    const y = try a.alloc(u8, 40);
    try testing.expect(y.ptr != x.ptr);
    a.free(y);
    reserve.drain();
    const z = try a.alloc(u8, 40);
    try testing.expect(z.ptr == x.ptr or z.ptr == y.ptr);
    a.free(z);
}

fn resident(slab: [*]u8) bool {
    var pages: [slab_len / std.heap.page_size_min]u8 = undefined;
    assert(std.os.linux.mincore(slab, slab_len, &pages) == 0);
    for (pages) |p| if (p & 1 != 0) return true;
    return false;
}
