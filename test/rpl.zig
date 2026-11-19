//! Prints a scenario read from stdin as rpl.zig loads it, in JSON: the
//! live harness reads every scenario through it.
const std = @import("std");
const rpl = @import("hark").rpl;

pub fn main(init: std.process.Init) u8 {
    const arena = init.arena.allocator();
    var in_buf: [4096]u8 = undefined;
    var in = std.Io.File.stdin().reader(init.io, &in_buf);
    const text = in.interface.allocRemaining(arena, .unlimited) catch return 1;
    var diag: rpl.Diag = .{};
    const scenario = rpl.parse(arena, text, &diag) catch |err| {
        std.debug.print("line {d}: {s}\n", .{ diag.line, if (err == error.OutOfMemory) "out of memory" else diag.msg });
        return 1;
    };
    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writer(init.io, &out_buf);
    rpl.print(arena, scenario, &out.interface) catch return 1;
    out.interface.flush() catch return 1;
    return 0;
}
