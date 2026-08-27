const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Wraps a backing allocator and tracks total bytes allocated.
/// Refuses allocations that would exceed a byte cap.
pub const CountingAllocator = struct {
    backing: Allocator,
    current_bytes: std.atomic.Value(usize),
    max_bytes: usize,
    charge_as: Charge,

    pub const Charge = enum { payload, slot };

    pub fn init(backing: Allocator, max_bytes: usize, charge_as: Charge) CountingAllocator {
        return .{ .backing = backing, .current_bytes = .init(0), .max_bytes = max_bytes, .charge_as = charge_as };
    }

    pub fn allocator(self: *CountingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{
        .alloc = countingAlloc,
        .resize = countingResize,
        .free = countingFree,
        .remap = countingRemap,
    };

    pub fn slotSize(len: usize) usize {
        if (len >= 64 * 1024) return mem.alignForward(usize, len, std.heap.pageSize());
        return std.math.ceilPowerOfTwoAssert(usize, @max(len, @sizeOf(usize)));
    }

    fn charge(self: *const CountingAllocator, len: usize) usize {
        return switch (self.charge_as) {
            .slot => slotSize(len),
            .payload => len,
        };
    }

    fn reserveBytes(self: *CountingAllocator, len: usize) bool {
        while (true) {
            const current = self.current_bytes.load(.monotonic);
            const sum, const overflow = @addWithOverflow(current, len);
            if (overflow != 0 or sum > self.max_bytes) return false;
            if (self.current_bytes.cmpxchgWeak(current, sum, .monotonic, .monotonic) == null) return true;
        }
    }

    fn countingAlloc(ctx: *anyopaque, len: usize, alignment: mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const c = self.charge(len);
        if (!self.reserveBytes(c)) return null;
        return self.backing.rawAlloc(len, alignment, ret_addr) orelse {
            _ = self.current_bytes.fetchSub(c, .monotonic);
            return null;
        };
    }

    fn countingResize(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const held = self.hold(buf.len, new_len) orelse return false;
        const ok = self.backing.rawResize(buf, alignment, new_len, ret_addr);
        self.settle(held, if (ok) new_len else buf.len);
        return ok;
    }

    fn countingRemap(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const held = self.hold(buf.len, new_len) orelse return null;
        const ptr = self.backing.rawRemap(buf, alignment, new_len, ret_addr);
        self.settle(held, if (ptr != null) new_len else buf.len);
        return ptr;
    }

    fn hold(self: *CountingAllocator, old_len: usize, new_len: usize) ?usize {
        const old_c = self.charge(old_len);
        const new_c = self.charge(new_len);
        if (new_c > old_c and !self.reserveBytes(new_c - old_c)) return null;
        return @max(old_c, new_c);
    }

    fn settle(self: *CountingAllocator, held: usize, len: usize) void {
        _ = self.current_bytes.fetchSub(held - self.charge(len), .monotonic);
    }

    fn countingFree(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        _ = self.current_bytes.fetchSub(self.charge(buf.len), .monotonic);
        self.backing.rawFree(buf, alignment, ret_addr);
    }
};

const testing = std.testing;

test "CountingAllocator: exact boundary, clean refusal, exact release" {
    var ca = CountingAllocator.init(testing.allocator, 1024, .payload);
    const a = ca.allocator();

    const buf = try a.alloc(u8, 1024);
    try testing.expectEqual(@as(usize, 1024), ca.current_bytes.load(.monotonic));

    try testing.expectError(error.OutOfMemory, a.alloc(u8, 1));
    try testing.expectEqual(@as(usize, 1024), ca.current_bytes.load(.monotonic));

    a.free(buf);
    try testing.expectEqual(@as(usize, 0), ca.current_bytes.load(.monotonic));

    const buf2 = try a.alloc(u8, 1024);
    a.free(buf2);
    try testing.expectEqual(@as(usize, 0), ca.current_bytes.load(.monotonic));
}

test "CountingAllocator: resize honors the cap and adjusts the counter both ways" {
    // FBA backing makes an in-place grow of the last allocation deterministic.
    var storage: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&storage);
    var ca = CountingAllocator.init(fba.allocator(), 1024, .payload);
    const a = ca.allocator();

    var buf = try a.alloc(u8, 256);
    try testing.expectEqual(@as(usize, 256), ca.current_bytes.load(.monotonic));

    try testing.expect(a.resize(buf, 768));
    buf.len = 768;
    try testing.expectEqual(@as(usize, 768), ca.current_bytes.load(.monotonic));

    try testing.expect(!a.resize(buf, 2048));
    try testing.expectEqual(@as(usize, 768), ca.current_bytes.load(.monotonic));

    try testing.expect(a.resize(buf, 128));
    buf.len = 128;
    try testing.expectEqual(@as(usize, 128), ca.current_bytes.load(.monotonic));

    a.free(buf);
    try testing.expectEqual(@as(usize, 0), ca.current_bytes.load(.monotonic));
}

test "CountingAllocator: slot rounding charges the pow2 slot, pages above 64 KiB" {
    try testing.expectEqual(@as(usize, 8), CountingAllocator.slotSize(1));
    try testing.expectEqual(@as(usize, 128), CountingAllocator.slotSize(100));
    try testing.expectEqual(@as(usize, 65536), CountingAllocator.slotSize(65536));
    try testing.expectEqual(mem.alignForward(usize, 70000, std.heap.pageSize()), CountingAllocator.slotSize(70000));

    var ca = CountingAllocator.init(testing.allocator, 256, .slot);
    const a = ca.allocator();
    const buf = try a.alloc(u8, 100);
    try testing.expectEqual(@as(usize, 128), ca.current_bytes.load(.monotonic));
    try testing.expectError(error.OutOfMemory, a.alloc(u8, 129));
    a.free(buf);
    try testing.expectEqual(@as(usize, 0), ca.current_bytes.load(.monotonic));
}
