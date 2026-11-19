//! A bounded memory of what failed lately: each entry stands until its own
//! time, and what it means is its owner's.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// `Context` hashes and compares keys, and owns and frees what a key borrows.
pub fn Memory(comptime K: type, comptime V: type, comptime Context: type) type {
    return struct {
        map: std.array_hash_map.Custom(K, Entry, Context, true) = .empty,

        const Entry = struct { until_ns: i64, is: V };
        pub const max_entries = 4096;

        pub fn deinit(m: *@This(), gpa: Allocator) void {
            for (m.map.keys()) |k| Context.free(gpa, k);
            m.map.deinit(gpa);
        }

        pub fn get(m: *const @This(), k: K, now_ns: i64) ?V {
            if (m.map.count() == 0) return null;
            const e = m.map.get(k) orelse return null;
            return if (e.until_ns > now_ns) e.is else null;
        }

        /// At `max_entries` another entry is evicted, picked by the keyed hash
        /// of this key so no asker can choose it.
        pub fn put(m: *@This(), gpa: Allocator, k: K, e: Entry) !void {
            if (m.map.getPtr(k)) |old| {
                old.* = e;
                return;
            }
            if (m.map.count() >= max_entries) {
                const at = Context.hash(.{}, k) % m.map.count();
                const old = m.map.keys()[at];
                m.map.swapRemoveAt(at);
                Context.free(gpa, old);
            }
            const own = try Context.own(gpa, k);
            errdefer Context.free(gpa, own);
            try m.map.put(gpa, own, e);
        }

        pub fn forget(m: *@This(), gpa: Allocator, k: K) void {
            if (m.map.fetchSwapRemove(k)) |kv| Context.free(gpa, kv.key);
        }
    };
}
