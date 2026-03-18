const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- Link the pre-built Rust static library ---
    // By default, look in target/release. Override with -Drust-lib-path=<dir>.
    const rust_lib_path: []const u8 = b.option(
        []const u8,
        "rust-lib-path",
        "Path to the directory containing libves_stark_ffi.a",
    ) orelse "../../target/release";

    // Helper: configure a module to link the Rust FFI + system deps
    const configureFfi = struct {
        fn apply(mod: *std.Build.Module, include: std.Build.LazyPath, lib_path: []const u8) void {
            mod.addIncludePath(include);
            mod.addLibraryPath(.{ .cwd_relative = lib_path });
            mod.linkSystemLibrary("ves_stark_ffi", .{});
            mod.linkSystemLibrary("pthread", .{});
            mod.linkSystemLibrary("dl", .{});
            mod.linkSystemLibrary("m", .{});
            mod.link_libc = true;
        }
    }.apply;

    // --- Core prover/verifier module ---
    const ves_stark_mod = b.addModule("ves_stark", .{
        .root_source_file = b.path("zig/ves_stark.zig"),
        .target = target,
        .optimize = optimize,
    });
    configureFfi(ves_stark_mod, b.path("include"), rust_lib_path);

    // --- Sequencer HTTP client module ---
    const sequencer_mod = b.addModule("sequencer", .{
        .root_source_file = b.path("zig/sequencer.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- Bundle module ---
    const bundle_mod = b.addModule("bundle", .{
        .root_source_file = b.path("zig/bundle.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ves_stark", .module = ves_stark_mod },
        },
    });
    configureFfi(bundle_mod, b.path("include"), rust_lib_path);

    // --- Batch module ---
    const batch_mod = b.addModule("batch", .{
        .root_source_file = b.path("zig/batch.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ves_stark", .module = ves_stark_mod },
        },
    });
    configureFfi(batch_mod, b.path("include"), rust_lib_path);

    // --- Example executable ---
    const example = b.addExecutable(.{
        .name = "ves-stark-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("zig/example.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ves_stark", .module = ves_stark_mod },
                .{ .name = "sequencer", .module = sequencer_mod },
                .{ .name = "bundle", .module = bundle_mod },
                .{ .name = "batch", .module = batch_mod },
            },
        }),
    });
    configureFfi(example.root_module, b.path("include"), rust_lib_path);

    b.installArtifact(example);

    // --- Core tests ---
    const core_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("zig/ves_stark.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    configureFfi(core_tests.root_module, b.path("include"), rust_lib_path);

    const run_core_tests = b.addRunArtifact(core_tests);
    const test_step = b.step("test", "Run all VES STARK Zig tests");
    test_step.dependOn(&run_core_tests.step);

    // --- Sequencer client tests ---
    const seq_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("zig/sequencer.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_seq_tests = b.addRunArtifact(seq_tests);
    test_step.dependOn(&run_seq_tests.step);

    // --- Bundle tests ---
    const bundle_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("zig/bundle.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ves_stark", .module = ves_stark_mod },
            },
        }),
    });
    configureFfi(bundle_tests.root_module, b.path("include"), rust_lib_path);

    const run_bundle_tests = b.addRunArtifact(bundle_tests);
    test_step.dependOn(&run_bundle_tests.step);
}
