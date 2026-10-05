//! The bench's own programs, built apart from hark so they share none of its code.
const std = @import("std");

pub fn build(b: *std.Build) void {
    b.installArtifact(b.addExecutable(.{
        .name = "load",
        .root_module = b.createModule(.{
            .root_source_file = b.path("load.zig"),
            .target = b.standardTargetOptions(.{}),
            .optimize = b.standardOptimizeOption(.{}),
        }),
    }));
}
