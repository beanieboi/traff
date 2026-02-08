const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Optional features
    const with_mysql = b.option(bool, "mysql", "Enable MySQL database dumping") orelse false;
    const with_psql = b.option(bool, "psql", "Enable PostgreSQL database dumping") orelse false;

    // Generate config.h
    const config_h = b.addConfigHeader(.{
        .style = .blank,
        .include_path = "config.h",
    }, .{
        .VERSION = "0.7.0",
        .WITH_MYSQL = with_mysql,
        .WITH_PSQL = with_psql,
    });

    const exe = b.addExecutable(.{
        .name = "traff",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    exe.addCSourceFiles(.{
        .files = &.{
            "traff.c",
            "ip_table.c",
            "readconfig.c",
        },
        .flags = &.{
            "-std=c99",
            "-Wall",
        },
    });

    exe.addConfigHeader(config_h);
    exe.linkSystemLibrary("pcap");

    if (with_mysql) {
        exe.linkSystemLibrary("mysqlclient");
    }
    if (with_psql) {
        exe.linkSystemLibrary("pq");
    }

    b.installArtifact(exe);

    // Run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run traff");
    run_step.dependOn(&run_cmd.step);
}
