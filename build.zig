const std = @import("std");
const zon = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Test-only knobs (upstream-port, allow-loopback-upstreams) only parse
    // when this is true. Default false keeps production builds clean; the
    // pytest harness runs `zig build -Dtesting=true`.
    const testing_enabled = b.option(bool, "testing", "Enable test-only config knobs") orelse false;
    const queue_instr = b.option(bool, "queue_instr", "Instrument WorkQueue mutex (acq count, hold/wait histograms)") orelse false;
    // TSan pulls in libc, which reshapes std.posix.sigset_t — see sys.signalfd.
    // It cannot model io_uring's kernel-shared rings, so the signal is in the
    // cache/resolver/DNSSEC layers, not the client plane. `?bool` matches
    // sanitize_thread: unspecified leaves every module on its default.
    const tsan = b.option(bool, "tsan", "Build with ThreadSanitizer");
    const build_opts = b.addOptions();
    build_opts.addOption(bool, "testing_enabled", testing_enabled);
    build_opts.addOption(bool, "queue_instr", queue_instr);
    build_opts.addOption([]const u8, "version", zon.version);
    const build_options_mod = build_opts.createModule();

    const tls_mod = b.addModule("tls", .{
        .root_source_file = b.path("src/vendor/tls-ianic/root.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = tsan,
    });

    const mod = b.addModule("hark", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = tsan,
        .imports = &.{
            .{ .name = "tls", .module = tls_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "hark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .sanitize_thread = tsan,
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
    const mod_tests = b.addTest(.{ .root_module = mod });

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(mod_tests).step);

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            // Under -Dtsan the timings are meaningless; the point is to run
            // the contention benches as a race workout the test suite can't
            // reach. Never compare a tsan run against bench/baselines/.
            .sanitize_thread = tsan,
            .imports = &.{
                .{ .name = "hark", .module = mod },
            },
        }),
    });
    const bench_step = b.step("bench", "Run microbenchmarks (optional filter: zig build bench -- <name_substring>)");
    const bench_run = b.addRunArtifact(bench_exe);
    bench_step.dependOn(&bench_run.step);
    bench_run.addPassthruArgs();

    const synth_pellet_exe = b.addExecutable(.{
        .name = "synth-pellet",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/recursion/synth_pellet.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .sanitize_thread = tsan,
            .imports = &.{.{ .name = "hark", .module = mod }},
        }),
    });
    const synth_pellet_install = b.addInstallArtifact(synth_pellet_exe, .{});
    const synth_pellet_step = b.step("synth-pellet", "Build the recursion-bench pellet synthesizer (zig-out/bin/synth-pellet)");
    synth_pellet_step.dependOn(&synth_pellet_install.step);
}
