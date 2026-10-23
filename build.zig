const std = @import("std");
/// The project version, read from `build.zig.zon` (single source of truth).
const version = @import("build.zig.zon").version;

/// The commit hash to show in `--version`, or `""` when the build was not given
/// one. Release builds pass `-Dgit-sha=$GITHUB_SHA`: CI does, and the container
/// must because its context has no `.git` and its image installs no `git`. The
/// value is trimmed to 7 characters here, so a 40-character SHA prints exactly
/// like `git rev-parse --short`; a value that is not hex, or already short, is
/// kept as given.
///
/// Deliberately *not* read from `git` at configure time, and no build date: both
/// are untracked state, which 0.17 answers with a poisoned configuration cache —
/// a configurer process on every `zig build`, for a string that only decorates
/// `--version`. No `dependOn*` declaration replaces it either: none expresses
/// the wall clock, and a content dependency on the git ref dies when `git gc`
/// packs refs away. A build date on top would also make two builds of the same
/// commit differ between days.
fn commitHash(b: *std.Build) []const u8 {
    const given = b.option(
        []const u8,
        "git-sha",
        "Commit hash to embed in `--version`, trimmed to 7 characters; CI and the container pass it",
    ) orelse return "";
    const trimmed = std.mem.trim(u8, given, " \t\r\n");
    if (trimmed.len <= 7) return trimmed;
    for (trimmed) |c| {
        if (!std.ascii.isHex(c)) return trimmed;
    }
    return trimmed[0..7];
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const git_hash = commitHash(b);
    const mod = b.addModule("vlmzsd", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .link_libc = false,
    });

    // Expose build-time facts (version, commit hash, embedded-data flag) to
    // source via `@import("build_options")`.
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    // What `--version` prints: the bare semver, plus the commit when the build
    // was given one. The format lives here so the three binaries cannot drift.
    build_options.addOption([]const u8, "version_display", if (git_hash.len == 0)
        version
    else
        b.fmt("{s} ({s})", .{ version, git_hash }));
    build_options.addOption(bool, "embedded_data", !(b.option(bool, "no-embedded-data", "Do not embed the default .kmd data; vlmzsd then requires --data <file>") orelse false));

    const exe = b.addExecutable(.{
        .name = "vlmzsd",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
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

    run_cmd.addPassthruArgs();

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

    // `network.zig`, `cli_helper.zig` and `line_queue.zig` are internal to the
    // binaries and no longer imported by `root.zig`, so test them directly.
    // `network.zig` imports the `vlmzsd` module for the protocol layer.
    const network_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/network.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vlmzsd", .module = mod },
            },
        }),
    });

    const run_network_tests = b.addRunArtifact(network_tests);

    const cli_helper_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli_helper.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_cli_helper_tests = b.addRunArtifact(cli_helper_tests);

    const line_queue_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/line_queue.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_line_queue_tests = b.addRunArtifact(line_queue_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_vlmzs_tests.step);
    test_step.dependOn(&run_kmdconv_tests.step);
    test_step.dependOn(&run_network_tests.step);
    test_step.dependOn(&run_cli_helper_tests.step);
    test_step.dependOn(&run_line_queue_tests.step);
}
