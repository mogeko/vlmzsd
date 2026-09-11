const std = @import("std");
/// The project version, read from `build.zig.zon` (single source of truth).
const version = @import("build.zig.zon").version;

/// Short git commit hash of HEAD (e.g. "4c25aa9"), or "unknown" when the
/// build runs outside a git checkout.
fn gitCommitHash(b: *std.Build) []const u8 {
    var code: u8 = undefined;
    const out = b.runAllowFail(&.{ "git", "rev-parse", "--short", "HEAD" }, &code, .ignore) catch return "unknown";
    return std.mem.trim(u8, out, " \t\r\n");
}

/// Current UTC date as `YYYY-MM-DD`.
fn buildDate(b: *std.Build) []const u8 {
    const now = std.Io.Clock.now(.real, b.graph.io);
    const secs: u64 = @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_s));
    const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
    const yad = epoch.getEpochDay().calculateYearDay();
    const mad = yad.calculateMonthDay();
    return b.fmt("{d:0>4}-{d:0>2}-{d:0>2}", .{
        @as(u32, yad.year),
        @as(u32, @intFromEnum(mad.month)),
        @as(u32, mad.day_index) + 1,
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const git_hash = gitCommitHash(b);
    const build_date = buildDate(b);
    const mod = b.addModule("vlmzsd", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .link_libc = true,
    });

    // Expose build-time facts (version, git hash, build date, embedded-data
    // flag) to source via `@import("build_options")`.
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    build_options.addOption([]const u8, "git_hash", git_hash);
    build_options.addOption([]const u8, "build_date", build_date);
    build_options.addOption(bool, "embedded_data", !(b.option(bool, "no-embedded-data", "Do not embed the default .kmd data; vlmzsd then requires --data <file>") orelse false));

    const exe = b.addExecutable(.{
        .name = "vlmzsd",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vlmzsd", .module = mod },
            },
        }),
    });

    exe.root_module.addOptions("build_options", build_options);

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

    vlmzs_exe.root_module.addOptions("build_options", build_options);

    const vlmzs_install = b.addInstallArtifact(vlmzs_exe, .{});
    b.getInstallStep().dependOn(&vlmzs_install.step);
    const vlmzs_step = b.step("vlmzs", "Build the vlmzs client only");
    vlmzs_step.dependOn(&vlmzs_install.step);

    // kmdconv: developer tool (JSON <-> .kmd). Not installed by default — it
    // is not part of the user-facing surface, only built via `zig build kmdconv`.
    const kmdconv_exe = b.addExecutable(.{
        .name = "kmdconv",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/kmdconv.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vlmzsd", .module = mod },
            },
        }),
    });

    kmdconv_exe.root_module.addOptions("build_options", build_options);

    const kmdconv_install = b.addInstallArtifact(kmdconv_exe, .{});
    const kmdconv_step = b.step("kmdconv", "Build the kmdconv developer tool (JSON <-> .kmd)");
    kmdconv_step.dependOn(&kmdconv_install.step);

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

    const kmdconv_tests = b.addTest(.{
        .root_module = kmdconv_exe.root_module,
    });

    const run_kmdconv_tests = b.addRunArtifact(kmdconv_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_vlmzs_tests.step);
    test_step.dependOn(&run_kmdconv_tests.step);
}
