const std = @import("std");
const dns = @import("hark").dns;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    var stdin_buf: [4096]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const input = stdin_reader.interface.allocRemaining(allocator, @enumFromInt(dns.max_udp_payload * 4)) catch |err| {
        std.debug.print("Failed to read stdin: {}\n", .{err});
        std.process.exit(1);
    };

    if (input.len == 0) {
        std.debug.print("No input. Pipe a raw DNS packet via stdin.\n", .{});
        std.process.exit(1);
    }

    const msg = dns.parseMessage(allocator, input) catch |err| {
        std.debug.print("Failed to parse DNS message: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    dns.printMessage(msg, stdout) catch |err| {
        std.debug.print("Failed to print message: {}\n", .{err});
        std.process.exit(1);
    };

    stdout.flush() catch {};
}
