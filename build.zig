const std = @import("std");
/// The project version, read from `build.zig.zon` (single source of truth).
const version = @import("build.zig.zon").version;

/// The commit hash embedded in `--version`, or `""` when `-Dgit-sha` was not
/// given. A hex value longer than 7 characters is trimmed the way
/// `git rev-parse --short` prints it; anything else is kept as given.
///
/// Not read from `git` at configure time: that is untracked state, and 0.17
/// answers it by poisoning the configure cache (see AGENTS.md).
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

/// The state the helpers below share: the build, its resolved target and
/// optimize mode, the `vlmzsd` library module, and `build_options`.
const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    /// The `vlmzsd` library module: the protocol layer, imported by all three
    /// binaries and by the test roots that need it.
    lib: *std.Build.Module,
    /// `build_options`, shared by the three binaries.
    options: *std.Build.Step.Options,

    /// One executable and what the graph wants from it: the artifact, its
    /// install step, and the `zig build <name>` step that produces just it. The
    /// module is kept so the tests can reuse it — a test compiled from the same
    /// module runs in the same configuration (target, optimize, libc, imports,
    /// build options) as the shipped binary.
    const Binary = struct {
        exe: *std.Build.Step.Compile,
        /// Needed by `run`, which installs before launching.
        install: *std.Build.Step.InstallArtifact,
    };

    const BinaryOptions = struct {
        /// Shown by `zig build --help`; derived from the name when empty.
        description: []const u8 = "",
        /// Part of `zig build` (the default install step).
        installed: bool = true,
        /// `true` only for the server: `src/main.zig` uses `std.c` for the
        /// self-pipe, `fcntl` and `getpid`.
        libc: bool = false,
    };

    fn binary(ctx: Context, name: []const u8, root: []const u8, opts: BinaryOptions) Binary {
        const exe = ctx.b.addExecutable(.{
            .name = name,
            .root_module = ctx.b.createModule(.{
                .root_source_file = ctx.b.path(root),
                .target = ctx.target,
                .optimize = ctx.optimize,
                .link_libc = opts.libc,
                .imports = &.{
                    .{ .name = "vlmzsd", .module = ctx.lib },
                },
            }),
        });
        exe.root_module.addOptions("build_options", ctx.options);

        const install = ctx.b.addInstallArtifact(exe, .{});
        if (opts.installed) ctx.b.getInstallStep().dependOn(&install.step);
        const description = if (opts.description.len == 0) ctx.b.fmt("Build {s}", .{name}) else opts.description;
        ctx.b.step(name, description).dependOn(&install.step);

        return .{ .exe = exe, .install = install };
    }

    /// A module rooted at one `src/` file, for tests the binaries' own roots do
    /// not reach. Zig discovers `test` blocks through semantic analysis, so a
    /// file whose tests nothing references would otherwise never run; a root of
    /// its own makes its coverage independent of what happens to import it. The
    /// `vlmzsd` import costs nothing for the files that do not use it: an unused
    /// import is never analyzed.
    fn fileModule(ctx: Context, path: []const u8) *std.Build.Module {
        return ctx.b.createModule(.{
            .root_source_file = ctx.b.path(path),
            .target = ctx.target,
            .optimize = ctx.optimize,
            .imports = &.{
                .{ .name = "vlmzsd", .module = ctx.lib },
            },
        });
    }

    /// Attach one test binary per root to `step`.
    fn addTests(ctx: Context, step: *std.Build.Step, roots: []const *std.Build.Module) void {
        for (roots) |root| {
            const tests = ctx.b.addTest(.{ .root_module = root });
            step.dependOn(&ctx.b.addRunArtifact(tests).step);
        }
    }
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const git_hash = commitHash(b);
    const embed_data = !(b.option(
        bool,
        "no-embedded-data",
        "Omit the default .kmd data; both binaries then require --data <file>",
    ) orelse false);

    // The protocol layer as a library: no `std.Io`, no libc. `optimize` is set
    // here as well as on each binary's module so that the library's own test
    // root compiles in the mode the caller asked for.
    const lib = b.addModule("vlmzsd", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    });

    // Build-time facts for `@import("build_options")`.
    const options = b.addOptions();
    options.addOption([]const u8, "version", version);
    // What `--version` prints: the bare semver, plus the commit when the build
    // was given one. The format lives here so the three binaries cannot drift.
    options.addOption([]const u8, "version_display", if (git_hash.len == 0)
        version
    else
        b.fmt("{s} ({s})", .{ version, git_hash }));
    options.addOption(bool, "embedded_data", embed_data);

    const ctx: Context = .{
        .b = b,
        .target = target,
        .optimize = optimize,
        .lib = lib,
        .options = options,
    };

    const server = ctx.binary("vlmzsd", "src/main.zig", .{ .libc = true });
    const client = ctx.binary("vlmzs", "src/vlmzs.zig", .{});
    // A developer tool (JSON <-> .kmd), deliberately outside the default install.
    const kmdconv = ctx.binary("kmdconv", "src/kmdconv.zig", .{
        .installed = false,
        .description = "Build the kmdconv developer tool (JSON <-> .kmd)",
    });

    // The `.kmd` data as a file too, so an installed tree can run without the
    // copy embedded in the binaries. `<prefix>/share/vlmzsd` is searched only
    // when the prefix is `/usr` or `/usr/local` (`cli_helper.fhs_system_dirs`);
    // anywhere else, pass `--data`.
    const install_data = b.addInstallFile(b.path("src/vlmcsd.kmd"), "share/vlmzsd/data.kmd");
    b.getInstallStep().dependOn(&install_data.step);

    const run_cmd = b.addRunArtifact(server.exe);
    run_cmd.step.dependOn(&server.install.step);
    run_cmd.addPassthruArgs();
    b.step("run", "Run the app").dependOn(&run_cmd.step);

    // One root per compilation unit. The binaries' modules cover the files their
    // tests reach; the three file roots cover sources they do not, and are why
    // some tests run in more than one root.
    ctx.addTests(b.step("test", "Run tests"), &.{
        lib,
        server.exe.root_module,
        client.exe.root_module,
        kmdconv.exe.root_module,
        ctx.fileModule("src/network.zig"),
        ctx.fileModule("src/cli_helper.zig"),
        ctx.fileModule("src/mpsc_queue.zig"),
    });
}
