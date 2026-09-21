const std = @import("std");
const zon = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Test-only knobs (upstream-port, allow-loopback-upstreams) only parse
    // when this is true. Default false keeps production builds clean; the
    // pytest harness runs `zig build -Dtesting=true`.
    const testing_enabled = b.option(bool, "testing", "Enable test-only config knobs") orelse false;
    const strip = b.option(bool, "strip", "Omit debug info (default: on unless Debug)") orelse
        (optimize != .debug);
    const build_opts = b.addOptions();
    build_opts.addOption(bool, "testing_enabled", testing_enabled);
    build_opts.addOption([]const u8, "version", zon.version);
    const build_options_mod = build_opts.createModule();

    const mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "hark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .imports = &.{
                .{ .name = "hark", .module = mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    // main.zig has no test blocks and imports only the hark module, so a
    // second exe-rooted test binary would recompile the same graph mod_tests
    // already covers for zero added coverage. Test the module only.
    const mod_tests = b.addTest(.{ .root_module = mod, .use_llvm = true });

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(mod_tests).step);

    // `test` compiles synth-pellet without a consumer (sema only, no codegen):
    // a root outside the test binary rots silently on an API change.
    const pellet_mod = b.createModule(.{
        .root_source_file = b.path("bench/recursion/synth_pellet.zig"),
        .target = target,
        .optimize = .safe,
        .strip = true,
        .imports = &.{.{ .name = "hark", .module = mod }},
    });
    const synth_pellet_exe = b.addExecutable(.{ .name = "synth-pellet", .root_module = pellet_mod });
    test_step.dependOn(&b.addExecutable(.{ .name = "synth-pellet-check", .root_module = pellet_mod }).step);

    const synth_pellet_install = b.addInstallArtifact(synth_pellet_exe, .{});
    const synth_pellet_step = b.step("synth-pellet", "Build the recursion-bench pellet synthesizer (zig-out/bin/synth-pellet)");
    synth_pellet_step.dependOn(&synth_pellet_install.step);
}
