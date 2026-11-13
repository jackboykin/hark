//! The bench, built apart from hark so it shares none of its code.
const std = @import("std");

pub fn build(b: *std.Build) void {
    b.installArtifact(b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = b.standardTargetOptions(.{}),
            .optimize = b.option(std.lang.Optimize, "optimize", "ReleaseFast unless said") orelse .ReleaseFast,
        }),
    }));
}
