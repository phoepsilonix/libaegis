const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const time = std.time;
const Timer = std.time.Timer;

const msg_len: usize = 16384;
const iterations = 100000;

const io = Io.Threaded.global_single_threaded.io();

fn bench_aegis256(stdout: *Io.Writer) !void {
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis256_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis256_encrypt(
            &buf,
            aegis.aegis256_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256x2(stdout: *Io.Writer) !void {
    var key: [aegis.aegis256x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis256x2_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis256x2_encrypt(
            &buf,
            aegis.aegis256x2_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256X2\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256x4(stdout: *Io.Writer) !void {
    var key: [aegis.aegis256x4_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256x4_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis256x4_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis256x4_encrypt(
            &buf,
            aegis.aegis256x4_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256X4\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128l(stdout: *Io.Writer) !void {
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128l_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis128l_encrypt(
            &buf,
            aegis.aegis128l_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128L\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x2(stdout: *Io.Writer) !void {
    var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128x2_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis128x2_encrypt(
            &buf,
            aegis.aegis128x2_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128X2\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x4(stdout: *Io.Writer) !void {
    var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128x4_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis128x4_encrypt(
            &buf,
            aegis.aegis128x4_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128X4\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128l_mac(stdout: *Io.Writer) !void {
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st: aegis.aegis128l_mac_state = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis128l_mac_init(&st, &key, &nonce);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        aegis.aegis128l_mac_reset(&st);
        _ = aegis.aegis128l_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis128l_mac_final(&st, &buf, aegis.aegis128l_ABYTES_MAX);
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128L MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x2_mac(stdout: *Io.Writer) !void {
    var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st: aegis.aegis128x2_mac_state = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis128x2_mac_init(&st, &key, &nonce);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        aegis.aegis128x2_mac_reset(&st);
        _ = aegis.aegis128x2_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis128x2_mac_final(&st, &buf, aegis.aegis128x2_ABYTES_MAX);
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128X2 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x4_mac(stdout: *Io.Writer) !void {
    var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st0: aegis.aegis128x4_mac_state = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis128x4_mac_init(&st0, &key, &nonce);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        var st: aegis.aegis128x4_mac_state = undefined;
        aegis.aegis128x4_mac_state_clone(&st, &st0);
        _ = aegis.aegis128x4_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis128x4_mac_final(&st, &buf, aegis.aegis128x4_ABYTES_MAX);
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128X4 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256_mac(stdout: *Io.Writer) !void {
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st: aegis.aegis256_mac_state = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis256_mac_init(&st, &key, &nonce);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        aegis.aegis256_mac_reset(&st);
        _ = aegis.aegis256_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis256_mac_final(&st, &buf, aegis.aegis256_ABYTES_MAX);
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256x2_mac(stdout: *Io.Writer) !void {
    var key: [aegis.aegis256x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st0: aegis.aegis256x2_mac_state = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis256x2_mac_init(&st0, &key, &nonce);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        var st: aegis.aegis256x2_mac_state = undefined;
        aegis.aegis256x2_mac_state_clone(&st, &st0);
        _ = aegis.aegis256x2_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis256x2_mac_final(&st, &buf, aegis.aegis256x2_ABYTES_MAX);
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256X2 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256x4_mac(stdout: *Io.Writer) !void {
    var key: [aegis.aegis256x4_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st0: aegis.aegis256x4_mac_state = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis256x4_mac_init(&st0, &key, &nonce);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        var st: aegis.aegis256x4_mac_state = undefined;
        aegis.aegis256x4_mac_state_clone(&st, &st0);
        _ = aegis.aegis256x4_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis256x4_mac_final(&st, &buf, aegis.aegis256x4_ABYTES_MAX);
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256X4 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

pub fn main() !void {
    if (aegis.aegis_init() != 0) {
        return error.InitFailed;
    }

    var stdout_buffer: [0x100]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    try bench_aegis256(stdout);
    try bench_aegis256x2(stdout);
    try bench_aegis256x4(stdout);
    try bench_aegis128l(stdout);
    try bench_aegis128x2(stdout);
    try bench_aegis128x4(stdout);

    try bench_aegis128l_mac(stdout);
    try bench_aegis128x2_mac(stdout);
    try bench_aegis128x4_mac(stdout);
    try bench_aegis256_mac(stdout);
    try bench_aegis256x2_mac(stdout);
    try bench_aegis256x4_mac(stdout);

    try stdout.flush();
}
