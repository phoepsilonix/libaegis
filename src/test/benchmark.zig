const aegis = @import("aegis");
const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const time = std.time;
const Timestamp = std.Io.Timestamp;

const msg_len: usize = 16384;
const iterations = 100000;

fn bench_aegis256(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis256_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Timestamp.now(io, .awake);
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
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256x2(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis256x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis256x2_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Timestamp.now(io, .awake);
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
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256X2\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256x4(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis256x4_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256x4_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis256x4_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Timestamp.now(io, .awake);
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
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256X4\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128l(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128l_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Timestamp.now(io, .awake);
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
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128L\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x2(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128x2_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Timestamp.now(io, .awake);
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
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128X2\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x4(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128x4_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Timestamp.now(io, .awake);
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
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128X4\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128l_mac(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st: aegis.aegis128l_mac_state align(32) = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis128l_mac_init(&st, &key, &nonce);

    const start = Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        aegis.aegis128l_mac_reset(&st);
        _ = aegis.aegis128l_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis128l_mac_final(&st, &buf, aegis.aegis128l_ABYTES_MAX);
    }
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128L MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x2_mac(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st: aegis.aegis128x2_mac_state align(64) = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis128x2_mac_init(&st, &key, &nonce);

    const start = Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        aegis.aegis128x2_mac_reset(&st);
        _ = aegis.aegis128x2_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis128x2_mac_final(&st, &buf, aegis.aegis128x2_ABYTES_MAX);
    }
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128X2 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x4_mac(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st0: aegis.aegis128x4_mac_state align(64) = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis128x4_mac_init(&st0, &key, &nonce);

    const start = Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        var st: aegis.aegis128x4_mac_state align(64) = undefined;
        aegis.aegis128x4_mac_state_clone(&st, &st0);
        _ = aegis.aegis128x4_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis128x4_mac_final(&st, &buf, aegis.aegis128x4_ABYTES_MAX);
    }
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-128X4 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256_mac(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st: aegis.aegis256_mac_state = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis256_mac_init(&st, &key, &nonce);

    const start = Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        aegis.aegis256_mac_reset(&st);
        _ = aegis.aegis256_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis256_mac_final(&st, &buf, aegis.aegis256_ABYTES_MAX);
    }
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256x2_mac(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis256x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st0: aegis.aegis256x2_mac_state align(32) = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis256x2_mac_init(&st0, &key, &nonce);

    const start = Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        var st: aegis.aegis256x2_mac_state align(32) = undefined;
        aegis.aegis256x2_mac_state_clone(&st, &st0);
        _ = aegis.aegis256x2_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis256x2_mac_final(&st, &buf, aegis.aegis256x2_ABYTES_MAX);
    }
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256X2 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256x4_mac(io: Io, stdout: *Io.Writer) !void {
    var key: [aegis.aegis256x4_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len]u8 = undefined;
    var st0: aegis.aegis256x4_mac_state align(64) = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);
    aegis.aegis256x4_mac_init(&st0, &key, &nonce);

    const start = Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        var st: aegis.aegis256x4_mac_state align(64) = undefined;
        aegis.aegis256x4_mac_state_clone(&st, &st0);
        _ = aegis.aegis256x4_mac_update(&st, &buf, msg_len);
        _ = aegis.aegis256x4_mac_final(&st, &buf, aegis.aegis256x4_ABYTES_MAX);
    }
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print("AEGIS-256X4 MAC\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_stream(io: Io, stdout: *Io.Writer, comptime variant: []const u8, comptime name: []const u8) !void {
    const stream = @field(aegis, variant ++ "_stream");
    var key: [@field(aegis, variant ++ "_KEYBYTES")]u8 = undefined;
    var nonce: [@field(aegis, variant ++ "_NPUBBYTES")]u8 = undefined;
    var buf: [msg_len]u8 = undefined;

    io.random(&key);
    io.random(&nonce);

    const start = Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        stream(&buf, msg_len, &nonce, &key);
    }
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print(name ++ " stream\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_stream_xor(io: Io, stdout: *Io.Writer, comptime variant: []const u8, comptime name: []const u8) !void {
    const stream_xor = @field(aegis, variant ++ "_stream_xor");
    var key: [@field(aegis, variant ++ "_KEYBYTES")]u8 = undefined;
    var nonce: [@field(aegis, variant ++ "_NPUBBYTES")]u8 = undefined;
    var buf: [msg_len]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        stream_xor(&buf, &buf, msg_len, &nonce, &key);
    }
    const end = Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end.nanoseconds - start.nanoseconds)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    try stdout.print(name ++ " stream_xor\t{d:10.2} Mb/s\n", .{throughput});
}

pub fn main(init: std.process.Init) !void {
    if (aegis.aegis_init() != 0) {
        return error.InitFailed;
    }

    const io = init.io;
    var stdout_buffer: [0x100]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    try bench_aegis256(io, stdout);
    try bench_aegis256x2(io, stdout);
    try bench_aegis256x4(io, stdout);
    try bench_aegis128l(io, stdout);
    try bench_aegis128x2(io, stdout);
    try bench_aegis128x4(io, stdout);

    try bench_aegis128l_mac(io, stdout);
    try bench_aegis128x2_mac(io, stdout);
    try bench_aegis128x4_mac(io, stdout);
    try bench_aegis256_mac(io, stdout);
    try bench_aegis256x2_mac(io, stdout);
    try bench_aegis256x4_mac(io, stdout);

    try bench_stream(io, stdout, "aegis256", "AEGIS-256");
    try bench_stream(io, stdout, "aegis256x2", "AEGIS-256X2");
    try bench_stream(io, stdout, "aegis256x4", "AEGIS-256X4");
    try bench_stream(io, stdout, "aegis128l", "AEGIS-128L");
    try bench_stream(io, stdout, "aegis128x2", "AEGIS-128X2");
    try bench_stream(io, stdout, "aegis128x4", "AEGIS-128X4");

    try bench_stream_xor(io, stdout, "aegis256", "AEGIS-256");
    try bench_stream_xor(io, stdout, "aegis256x2", "AEGIS-256X2");
    try bench_stream_xor(io, stdout, "aegis256x4", "AEGIS-256X4");
    try bench_stream_xor(io, stdout, "aegis128l", "AEGIS-128L");
    try bench_stream_xor(io, stdout, "aegis128x2", "AEGIS-128X2");
    try bench_stream_xor(io, stdout, "aegis128x4", "AEGIS-128X4");

    try stdout.flush();
}
