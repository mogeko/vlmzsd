const std = @import("std");
/// The project version, read from `build.zig.zon` (single source of truth).
const version = @import("build.zig.zon").version;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mod = b.addModule("vlmzsd", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .link_libc = true,
    });

    // External dependency: zig-clap for CLI argument parsing.
    const clap_dep = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });
    const clap_mod = clap_dep.module("clap");

    // Expose the project version to source via `@import("build_options")`.
    const version_options = b.addOptions();
    version_options.addOption([]const u8, "version", version);

    const exe = b.addExecutable(.{
        .name = "vlmzsd",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vlmzsd", .module = mod },
                .{ .name = "clap", .module = clap_mod },
            },
        }),
    });

    exe.root_module.addOptions("build_options", version_options);

    const exe_install = b.addInstallArtifact(exe, .{});
    b.getInstallStep().dependOn(&exe_install.step);
    const vlmzsd_step = b.step("vlmzsd", "Build the vlmzsd server only");
    vlmzsd_step.dependOn(&exe_install.step);

    const vlmzs_exe = b.addExecutable(.{
        .name = "vlmzs",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/vlmzs.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vlmzsd", .module = mod },
            },
        }),
    });

    vlmzs_exe.root_module.addOptions("build_options", version_options);

    const vlmzs_install = b.addInstallArtifact(vlmzs_exe, .{});
    b.getInstallStep().dependOn(&vlmzs_install.step);
    const vlmzs_step = b.step("vlmzs", "Build the vlmzs client only");
    vlmzs_step.dependOn(&vlmzs_install.step);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const vlmzs_tests = b.addTest(.{
        .root_module = vlmzs_exe.root_module,
    });

    const run_vlmzs_tests = b.addRunArtifact(vlmzs_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_vlmzs_tests.step);
}
