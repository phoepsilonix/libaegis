const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const testing = std.testing;

var io_source = std.Random.IoSource{ .io = testing.io };
const random = io_source.interface();

const MemoryFile = struct {
    data: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) MemoryFile {
        return .{
            .data = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *MemoryFile) void {
        self.data.deinit(self.allocator);
    }

    fn read_at(user: ?*anyopaque, buf: [*c]u8, len: usize, off: u64) callconv(.c) c_int {
        const self: *MemoryFile = @ptrCast(@alignCast(user));
        const offset = @as(usize, @intCast(off));
        if (offset + len > self.data.items.len) {
            return -1;
        }
        @memcpy(buf[0..len], self.data.items[offset .. offset + len]);
        return 0;
    }

    fn write_at(user: ?*anyopaque, buf: [*c]const u8, len: usize, off: u64) callconv(.c) c_int {
        const self: *MemoryFile = @ptrCast(@alignCast(user));
        const offset = @as(usize, @intCast(off));
        const end = offset + len;
        if (end > self.data.items.len) {
            return -1;
        }
        @memcpy(self.data.items[offset..end], buf[0..len]);
        return 0;
    }

    fn get_size(user: ?*anyopaque, size: [*c]u64) callconv(.c) c_int {
        const self: *MemoryFile = @ptrCast(@alignCast(user));
        size[0] = @intCast(self.data.items.len);
        return 0;
    }

    fn set_size(user: ?*anyopaque, size: u64) callconv(.c) c_int {
        const self: *MemoryFile = @ptrCast(@alignCast(user));
        const new_size = @as(usize, @intCast(size));
        self.data.resize(self.allocator, new_size) catch return -1;
        return 0;
    }

    fn sync(_: ?*anyopaque) callconv(.c) c_int {
        return 0;
    }

    fn io(self: *MemoryFile) aegis.aegis_raf_io {
        return .{
            .user = self,
            .read_at = read_at,
            .write_at = write_at,
            .get_size = get_size,
            .set_size = set_size,
            .sync = sync,
        };
    }
};

fn os_random(_: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
    random.bytes(out[0..len]);
    return 0;
}

fn rng() aegis.aegis_raf_rng {
    return .{
        .user = null,
        .random = os_random,
    };
}

const FailingRng = struct {
    calls_until_fail: usize,
    call_count: usize = 0,

    fn failingRandom(user: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
        const self: *FailingRng = @ptrCast(@alignCast(user));
        self.call_count += 1;
        if (self.call_count > self.calls_until_fail) {
            return -1;
        }
        io_source.interface().bytes(out[0..len]);
        return 0;
    }

    fn interface(self: *FailingRng) aegis.aegis_raf_rng {
        return .{
            .user = self,
            .random = failingRandom,
        };
    }
};

test "aegis128l_raf - create and basic write/read" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    const test_data = "Hello, AEGIS RAF!";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, test_data.len);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, test_data.len);

    var read_buf: [64]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, test_data.len);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - open existing file" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Test data for re-open";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, test_data.len);

    var read_buf: [64]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - random access write" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const data1 = "First block";
    const data2 = "Second block at offset 2048";
    var bytes_written: usize = undefined;

    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data1.ptr, data1.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data2.ptr, data2.len, 2048);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 2048 + data2.len);

    var read_buf1: [32]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf1, &bytes_read, data1.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, data1, read_buf1[0..bytes_read]);

    var read_buf2: [64]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf2, &bytes_read, data2.len, 2048);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, data2, read_buf2[0..bytes_read]);

    var zeros: [100]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &zeros, &bytes_read, 100, 100);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 100);
    for (zeros[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - truncate" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [2048]u8 = undefined;
    random.bytes(&data);
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 500);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 500);

    var read_buf: [500]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 500, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 500);
    try testing.expectEqualSlices(u8, data[0..500], read_buf[0..500]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - cross-chunk operations" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [2000]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, chunk_size - 500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, data.len);

    var read_buf: [2000]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, data.len, chunk_size - 500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, data.len);
    try testing.expectEqualSlices(u8, &data, read_buf[0..bytes_read]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - header tampering detection" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    file.data.items[20] ^= 0x01;

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expect(ret != 0);
}

test "aegis128l_raf - chunk tampering detection" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [1024]u8 = undefined;
    random.bytes(&data);
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    const chunk_offset = aegis.AEGIS_RAF_HEADER_SIZE + aegis.aegis128l_NPUBBYTES + 512;
    file.data.items[chunk_offset] ^= 0x01;

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    var read_buf: [1024]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 1024, 0);
    try testing.expect(ret != 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - wrong key detection" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key1: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var key2: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key1);
    random.bytes(&key2);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key1);
    try testing.expectEqual(ret, 0);

    const test_data = "Secret data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key2);
    try testing.expect(ret != 0);
}

test "aegis256_raf - basic operations" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS256_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis256_raf_ctx = undefined;

    var ret = aegis.aegis256_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "AEGIS-256 RAF test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis256_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis256_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis256_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    var read_buf: [64]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis256_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    aegis.aegis256_raf_close(&ctx);
}

test "aegis_raf - algorithm mismatch detection" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key128: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var key256: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key128);
    @memcpy(key256[0..16], &key128);
    @memcpy(key256[16..32], &key128);

    var scratch128_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch128 = aegis.aegis_raf_scratch{
        .buf = &scratch128_buf,
        .len = scratch128_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch128,
    };

    var ctx128: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx128, &file.io(), &rng(), &cfg, &key128);
    try testing.expectEqual(ret, 0);

    const test_data = "Test";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx128, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx128);

    var scratch256_buf: [aegis.AEGIS256_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch256 = aegis.aegis_raf_scratch{
        .buf = &scratch256_buf,
        .len = scratch256_buf.len,
    };

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch256,
    };

    var ctx256: aegis.aegis256_raf_ctx = undefined;
    ret = aegis.aegis256_raf_open(&ctx256, &file.io(), &rng(), &open_cfg, &key256);
    try testing.expect(ret != 0);
}

test "aegis128l_raf - EOF behavior" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Short data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var read_buf: [100]u8 = undefined;
    var bytes_read: usize = undefined;

    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 100, 100);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 0);

    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 100, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, test_data.len);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - empty file" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    var read_buf: [100]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 100, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 0);

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - create flags semantics" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg_create_only = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_create_only, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_create_only, &key);
    try testing.expect(ret != 0);

    const cfg_truncate = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE | aegis.AEGIS_RAF_TRUNCATE,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_truncate, &key);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - create without CREATE flag fails on empty file" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg_no_create = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = 0,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_no_create, &key);
    try testing.expect(ret != 0);
}

test "aegis128l_raf - truncate grow within same chunk" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Hello, grow test!";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, test_data.len);

    ret = aegis.aegis128l_raf_truncate(&ctx, 800);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 800);

    var read_buf: [64]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, test_data.len);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    var zeros: [100]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &zeros, &bytes_read, 100, test_data.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 100);
    for (zeros[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - truncate grow across chunk boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [1500]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, data.len);

    ret = aegis.aegis128l_raf_truncate(&ctx, 3500);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 3500);

    var read_buf: [1500]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, data.len);
    try testing.expectEqualSlices(u8, &data, read_buf[0..bytes_read]);

    var zeros: [500]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &zeros, &bytes_read, 500, 2500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 500);
    for (zeros[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 3500);

    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &data, read_buf[0..bytes_read]);

    ret = aegis.aegis128l_raf_read(&ctx, &zeros, &bytes_read, 500, 3000);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 500);
    for (zeros[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - shrink then grow within same chunk" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [800]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i ^ 0xAB);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 500);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 700);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 700);

    var read_buf: [500]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 500, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 500);
    try testing.expectEqualSlices(u8, data[0..500], read_buf[0..500]);

    var grown_region: [200]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &grown_region, &bytes_read, 200, 500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 200);
    for (grown_region[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - shrink then grow across chunk boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [2000]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i ^ 0xCD);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 1500);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 3000);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 3000);

    var read_buf: [1500]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 1500, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 1500);
    try testing.expectEqualSlices(u8, data[0..1500], read_buf[0..1500]);

    var tail_of_old_chunk: [chunk_size - 476]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &tail_of_old_chunk, &bytes_read, tail_of_old_chunk.len, 1500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, tail_of_old_chunk.len);
    for (tail_of_old_chunk[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    var new_chunks: [1000]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &new_chunks, &bytes_read, 1000, 2000);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 1000);
    for (new_chunks[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - RNG failure during truncate grow" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var failing_rng = FailingRng{ .calls_until_fail = 2 };

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &failing_rng.interface(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Initial data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var size_before: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size_before);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size_before, test_data.len);

    ret = aegis.aegis128l_raf_truncate(&ctx, 5000);
    try testing.expect(ret != 0);

    var size_after: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size_after);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size_after, test_data.len);

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    var read_buf: [32]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, test_data.len);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - null scratch rejected" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const cfg_no_scratch = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = null,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_no_scratch, &key);
    try testing.expect(ret != 0);
    try testing.expectEqual(std.c._errno().*, @intFromEnum(std.c.E.INVAL));
}

test "aegis128l_raf - undersized scratch rejected" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var small_scratch_buf: [64]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const small_scratch = aegis.aegis_raf_scratch{
        .buf = &small_scratch_buf,
        .len = small_scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &small_scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expect(ret != 0);
    try testing.expectEqual(std.c._errno().*, @intFromEnum(std.c.E.INVAL));
}

test "aegis128l_raf - misaligned scratch rejected" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096) + 64]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const misaligned_scratch = aegis.aegis_raf_scratch{
        .buf = scratch_buf[1..].ptr,
        .len = aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096),
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &misaligned_scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expect(ret != 0);
    try testing.expectEqual(std.c._errno().*, @intFromEnum(std.c.E.INVAL));
}

test "aegis_raf_probe - basic functionality" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Probe test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    var info: aegis.aegis_raf_info = undefined;
    ret = aegis.aegis_raf_probe(&file.io(), &info);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(info.alg_id, aegis.AEGIS_RAF_ALG_128L);
    try testing.expectEqual(info.chunk_size, 4096);
    try testing.expectEqual(info.file_size, test_data.len);
}

test "aegis256_raf_probe - basic functionality" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS256_RAF_SCRATCH_SIZE(2048)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 2048,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis256_raf_ctx = undefined;

    var ret = aegis.aegis256_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "AEGIS-256 probe test";
    var bytes_written: usize = undefined;
    ret = aegis.aegis256_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis256_raf_close(&ctx);

    var info: aegis.aegis_raf_info = undefined;
    ret = aegis.aegis_raf_probe(&file.io(), &info);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(info.alg_id, aegis.AEGIS_RAF_ALG_256);
    try testing.expectEqual(info.chunk_size, 2048);
    try testing.expectEqual(info.file_size, test_data.len);
}

test "aegis128l_raf_scratch_size - runtime helper matches macro" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const chunk_sizes = [_]u32{ 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

    for (chunk_sizes) |chunk_size| {
        const macro_size = aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size);
        const runtime_size = aegis.aegis128l_raf_scratch_size(chunk_size);
        try testing.expectEqual(macro_size, runtime_size);
    }

    try testing.expectEqual(aegis.aegis_raf_scratch_align(), aegis.AEGIS_RAF_SCRATCH_ALIGN);
}

test "aegis256_raf_scratch_size - runtime helper matches macro" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const chunk_sizes = [_]u32{ 1024, 2048, 4096, 8192 };

    for (chunk_sizes) |chunk_size| {
        const macro_size = aegis.AEGIS256_RAF_SCRATCH_SIZE(chunk_size);
        const runtime_size = aegis.aegis256_raf_scratch_size(chunk_size);
        try testing.expectEqual(macro_size, runtime_size);
    }
}

test "aegis128l_raf_scratch_validate - validates correctly" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;

    const valid_scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };
    try testing.expectEqual(aegis.aegis128l_raf_scratch_validate(&valid_scratch, 4096), 0);

    const undersized_scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = 64,
    };
    try testing.expect(aegis.aegis128l_raf_scratch_validate(&undersized_scratch, 4096) != 0);

    try testing.expect(aegis.aegis128l_raf_scratch_validate(null, 4096) != 0);
}

test "aegis128l_raf - partial overwrite preserves trailing data" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const initial_data = "AAAABBBB";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, initial_data.ptr, initial_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, initial_data.len);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 8);

    const overwrite_data = "XX";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, overwrite_data.ptr, overwrite_data.len, 4);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, overwrite_data.len);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 8);

    var read_buf: [8]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 8, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 8);
    try testing.expectEqualSlices(u8, "AAAAXXBB", &read_buf);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - partial overwrite preserves leading data" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const initial_data = "AAAABBBB";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, initial_data.ptr, initial_data.len, 0);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 8);

    const overwrite_data = "XX";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, overwrite_data.ptr, overwrite_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 8);

    var read_buf: [8]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 8, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 8);
    try testing.expectEqualSlices(u8, "XXAABBBB", &read_buf);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - multiple partial overwrites within chunk" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var initial_data: [1000]u8 = undefined;
    for (&initial_data, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &initial_data, initial_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, 1000);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 1000);

    const patch1 = "XXXXXXXXXX";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, patch1.ptr, patch1.len, 100);
    try testing.expectEqual(ret, 0);

    const patch2 = "YYYYYYYYYY";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, patch2.ptr, patch2.len, 500);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 1000);

    var read_buf: [1000]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 1000, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 1000);

    try testing.expectEqualSlices(u8, initial_data[0..100], read_buf[0..100]);
    try testing.expectEqualSlices(u8, patch1, read_buf[100..110]);
    try testing.expectEqualSlices(u8, initial_data[110..500], read_buf[110..500]);
    try testing.expectEqualSlices(u8, patch2, read_buf[500..510]);
    try testing.expectEqualSlices(u8, initial_data[510..1000], read_buf[510..1000]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - cross-chunk partial write preserves existing data" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var initial_data: [2000]u8 = undefined;
    for (&initial_data, 0..) |*b, i| {
        b.* = @truncate(i ^ 0x5A);
    }
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &initial_data, initial_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, 2000);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 2000);

    var patch: [100]u8 = undefined;
    @memset(&patch, 0xFF);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &patch, patch.len, 1000);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, 100);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 2000);

    var read_buf: [2000]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 2000, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 2000);

    try testing.expectEqualSlices(u8, initial_data[0..1000], read_buf[0..1000]);
    try testing.expectEqualSlices(u8, &patch, read_buf[1000..1100]);
    try testing.expectEqualSlices(u8, initial_data[1100..2000], read_buf[1100..2000]);

    aegis.aegis128l_raf_close(&ctx);
}
