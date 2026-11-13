//! bench <experiment> ...: hark's benchmarks, one program.
//!
//!   tp <rounds> <workload> side...               throughput (tp.zig)
//!   prof <rounds> hit|miss side...               where a query's time goes (prof.zig)
//!   overload <hark binary>                       what load beyond the ceiling costs (overload.zig)
//!   report tp|prof|overload [session] [side...]  a session's report again, the latest if none is named
//!   compare <dir> <A> <B>                        the live bench's two sides (compare.zig)
//!   load ...                                     the load generator by hand (load.zig)
//!
//! Run as bench/run, which builds it first, in `nix develop .#bench` on an
//! idle machine. What to run is said in arguments, how in the environment:
//! each experiment's file names its knobs, and rig.zig the rig's. Every run
//! lands in bench/out/ledger.jsonl.
const std = @import("std");
const linux = std.os.linux;
const os = @import("os.zig");
const load = @import("load.zig");
const tp = @import("tp.zig");
const prof = @import("prof.zig");
const overload = @import("overload.zig");
const compare = @import("compare.zig");
const Ledger = @import("ledger.zig");

const usage = "usage: bench tp|prof <rounds> <workload> side... | overload <binary> | report tp|prof|overload [session] [side...] | compare <dir> <A> <B> | load ...\n";

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    os.environ = init.minimal.environ.block.slice.ptr;
    os.vars = init.environ_map;
    var argv: std.ArrayList([]const u8) = .empty;
    var it = std.process.Args.Iterator.init(init.minimal.args);
    while (it.next()) |a| try argv.append(arena, a);
    if (argv.items.len < 2) return std.debug.print(usage, .{});
    const verb = argv.items[1];
    const args = argv.items[2..];
    // The binary is bench/zig-out/bin/bench.
    var exe: [4096]u8 = undefined;
    const len = linux.readlink("/proc/self/exe", &exe, exe.len);
    if (!os.ok(len)) return error.NoSelf;
    const dir = std.Io.Dir.path.dirname(std.Io.Dir.path.dirname(std.Io.Dir.path.dirname(exe[0..len]).?).?).?;
    const config = try arena.print("{s}/config", .{dir});
    if (std.mem.eql(u8, verb, "load")) return load.main(arena, args);
    const ledger: Ledger = try .open(arena, dir);
    const result = if (std.mem.eql(u8, verb, "compare"))
        compare.main(arena, args)
    else if (std.mem.eql(u8, verb, "tp"))
        tp.main(arena, config, &ledger, args)
    else if (std.mem.eql(u8, verb, "prof"))
        prof.main(arena, config, &ledger, args)
    else if (std.mem.eql(u8, verb, "overload"))
        overload.main(arena, config, &ledger, args)
    else if (std.mem.eql(u8, verb, "report"))
        report(arena, &ledger, args)
    else
        error.Usage;
    result catch |e| switch (e) {
        error.Usage => {
            std.debug.print(usage, .{});
            std.process.exit(2);
        },
        else => return e,
    };
}

fn report(arena: std.mem.Allocator, ledger: *const Ledger, args: []const []const u8) !void {
    if (args.len == 0) return error.Usage;
    const named = args.len > 1 and args[1].len == 16 and args[1][8] == 'T';
    const runs = try ledger.read(args[0], if (named) args[1] else null);
    if (std.mem.eql(u8, args[0], "tp")) return tp.report(arena, runs, args[1 + @as(usize, @intFromBool(named)) ..]);
    if (std.mem.eql(u8, args[0], "prof")) return prof.report(arena, runs);
    if (std.mem.eql(u8, args[0], "overload")) return overload.report(arena, runs);
    return error.Usage;
}
