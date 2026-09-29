const std = @import("std");
const zon = @import("build.zig.zon");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Test-only knobs (upstream-port, allow-loopback-upstreams) only parse
    // when this is true. Default false keeps production builds clean; the
    // live harness runs `zig build -Dtesting=true`.
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
    if (b.option(bool, "bench-layout", "LLVM and lld, a section per function, for bench/layouts.sh") orelse false) {
        exe.use_llvm = true;
        exe.use_lld = true;
        exe.link_function_sections = true;
    }
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    // main.zig has no test blocks and imports only the hark module, so a
    // second exe-rooted test binary would recompile the same graph mod_tests
    // already covers for zero added coverage. Test the module only.
    const scenario = b.option([]const u8, "scenario", "Replay one scenario, tracing every completion");
    const asked = b.option([]const []const u8, "test-filter", "Skip tests that do not match any filter") orelse &.{};
    const filters = if (scenario != null) try std.mem.concat(b.graph.arena, []const u8, &.{ asked, &.{"trace one scenario"} }) else asked;
    const mod_tests = b.addTest(.{ .root_module = mod, .use_llvm = true, .filters = filters });

    const run_tests = b.addRunArtifact(mod_tests);
    // A HARK_SCENARIO in the shell never reaches the tests; -Dscenario does.
    run_tests.clearEnvironment();
    if (scenario) |path| {
        run_tests.setEnvironmentVariable("HARK_SCENARIO", path);
        run_tests.has_side_effects = true;
    }
    // The replays read their scenarios at run time: an edited one reruns
    // them, and an added or removed one reconfigures.
    for ([_][]const u8{ "test/scenarios/hark", "test/corpus/unbound" }) |root| try declareInputs(b, run_tests, root);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}

fn declareInputs(b: *std.Build, run: *std.Build.Step.Run, root: []const u8) !void {
    const io = b.graph.io;
    // A source tree without the tests (the flake's) declares nothing.
    var dir = b.root.openDir(io, root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close(io);
    b.dependOnDirectoryContents(b.path(root));
    var it = try dir.walk(b.graph.arena);
    while (try it.next(io)) |entry| {
        const path = b.pathJoin(&.{ root, entry.path });
        switch (entry.kind) {
            .directory => b.dependOnDirectoryContents(b.path(path)),
            .file => run.addFileInput(b.path(path)),
            else => {},
        }
    }
}
