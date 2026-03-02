const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const dns = @import("dns.zig");
const UdpTransport = @import("transport.zig").UdpTransport;

// ── Root Hints ─────────────────────────────────────────────────────────
// IPv4 addresses for a.root-servers.net through m.root-servers.net.
// Source: https://www.internic.net/domain/named.root

pub const root_hints: [13]std.net.Address = .{
    std.net.Address.initIp4(.{ 198, 41, 0, 4 }, 53), // a
    std.net.Address.initIp4(.{ 170, 247, 170, 2 }, 53), // b
    std.net.Address.initIp4(.{ 192, 33, 4, 12 }, 53), // c
    std.net.Address.initIp4(.{ 199, 7, 91, 13 }, 53), // d
    std.net.Address.initIp4(.{ 192, 203, 230, 10 }, 53), // e
    std.net.Address.initIp4(.{ 192, 5, 5, 241 }, 53), // f
    std.net.Address.initIp4(.{ 192, 112, 36, 4 }, 53), // g
    std.net.Address.initIp4(.{ 198, 97, 190, 53 }, 53), // h
    std.net.Address.initIp4(.{ 192, 36, 148, 17 }, 53), // i
    std.net.Address.initIp4(.{ 192, 58, 128, 30 }, 53), // j
    std.net.Address.initIp4(.{ 193, 0, 14, 129 }, 53), // k
    std.net.Address.initIp4(.{ 199, 7, 83, 42 }, 53), // l
    std.net.Address.initIp4(.{ 202, 12, 27, 33 }, 53), // m
};

const max_referrals = 10;
const max_servers_per_level = 13;

// ── RecursiveResolver ──────────────────────────────────────────────────

pub const RecursiveResolver = struct {
    transport: *UdpTransport,

    pub fn init(transport: *UdpTransport) RecursiveResolver {
        return .{ .transport = transport };
    }

    pub fn resolve(self: *RecursiveResolver, allocator: mem.Allocator, name: []const u8, qtype: dns.RType) !dns.Message {
        var servers: [max_servers_per_level]std.net.Address = undefined;
        var server_count: usize = root_hints.len;
        @memcpy(servers[0..root_hints.len], &root_hints);

        for (0..max_referrals) |_| {
            // Shuffle servers (Fisher-Yates)
            fisherYatesShuffle(std.net.Address, servers[0..server_count]);

            // Try each server until one responds
            var got_response = false;
            var response: dns.Message = undefined;

            for (servers[0..server_count]) |server| {
                // Generate random query ID
                var id_bytes: [2]u8 = undefined;
                std.crypto.random.bytes(&id_bytes);
                const query_id = mem.readInt(u16, &id_bytes, .big);

                // Build iterative query (rd=false)
                const query_msg = try dns.buildQueryWithOptions(allocator, query_id, name, qtype, .{ .rd = false });

                // Serialize
                var wire_buf: [dns.max_udp_payload]u8 = undefined;
                const wire_query = try dns.serializeMessage(&wire_buf, query_msg);

                // Send and receive
                const response_data = self.transport.query(wire_query, query_id, server) catch |err| switch (err) {
                    error.Timeout => continue, // try next server
                    else => return err,
                };

                // Parse response
                response = try dns.parseMessage(allocator, response_data);
                got_response = true;
                break;
            }

            if (!got_response) return error.Timeout;

            // Classify response
            if (response.header.rcode != .no_error) return response;
            if (response.answers.len > 0) return response;

            // Check for referral (NS records in authority section)
            const referral = extractReferral(response) orelse return response; // NODATA
            switch (referral) {
                .addresses => |addrs| {
                    server_count = addrs.len;
                    @memcpy(servers[0..addrs.len], addrs);
                },
                .no_glue => return error.NoGlueRecords,
            }
        }

        return error.MaxReferralsExceeded;
    }
};

// ── Referral extraction ────────────────────────────────────────────────

const ReferralResult = union(enum) {
    addresses: []const std.net.Address,
    no_glue,
};

fn extractReferral(response: dns.Message) ?ReferralResult {
    // Collect NS names from authority section
    var ns_count: usize = 0;
    var ns_names: [max_servers_per_level]dns.Name = undefined;
    for (response.authorities) |rr| {
        if (rr.rtype == .ns) {
            if (ns_count < max_servers_per_level) {
                ns_names[ns_count] = rr.rdata.ns;
                ns_count += 1;
            }
        }
    }

    if (ns_count == 0) return null;

    // Match glue A records from additionals
    var glue_count: usize = 0;
    // Static buffer — at most max_servers_per_level glue addresses
    var glue_addrs: [max_servers_per_level]std.net.Address = undefined;
    for (response.additionals) |rr| {
        if (rr.rtype == .a) {
            for (ns_names[0..ns_count]) |ns_name| {
                if (ns_name.eql(rr.name)) {
                    if (glue_count < max_servers_per_level) {
                        glue_addrs[glue_count] = std.net.Address.initIp4(rr.rdata.a, 53);
                        glue_count += 1;
                    }
                    break;
                }
            }
        }
    }

    if (glue_count == 0) return .no_glue;

    return .{ .addresses = glue_addrs[0..glue_count] };
}

fn fisherYatesShuffle(comptime T: type, items: []T) void {
    if (items.len <= 1) return;
    var i: usize = items.len - 1;
    while (i > 0) : (i -= 1) {
        const j = std.crypto.random.uintLessThan(usize, i + 1);
        const tmp = items[i];
        items[i] = items[j];
        items[j] = tmp;
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

test "root_hints has 13 entries, all port 53" {
    try testing.expectEqual(@as(usize, 13), root_hints.len);
    for (root_hints) |addr| {
        // All should be IPv4, port 53
        try testing.expectEqual(@as(u16, 53), addr.getPort());
    }
}

test "extractReferral with NS and glue A records" {
    // Build a synthetic referral response:
    //   authority: example.com NS ns1.example.com
    //   additional: ns1.example.com A 192.0.2.1
    const alloc = testing.allocator;

    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "example");
    ns_name_labels[2] = try alloc.dupe(u8, "com");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 2);
    zone_labels[0] = try alloc.dupe(u8, "example");
    zone_labels[1] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    // Glue record name (same as ns_name but separate allocation)
    const glue_name_labels = try alloc.alloc([]const u8, 3);
    glue_name_labels[0] = try alloc.dupe(u8, "ns1");
    glue_name_labels[1] = try alloc.dupe(u8, "example");
    glue_name_labels[2] = try alloc.dupe(u8, "com");
    const glue_name = dns.Name{ .labels = glue_name_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    const additionals = try alloc.alloc(dns.ResourceRecord, 1);
    additionals[0] = .{
        .name = glue_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .a = .{ 192, 0, 2, 1 } },
    };

    const response = dns.Message{
        .header = .{
            .id = 0x1234,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 1,
            .ar_count = 1,
        },
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = additionals,
    };
    defer {
        dns.freeMessage(alloc, response);
    }

    const result = extractReferral(response) orelse {
        try testing.expect(false); // should not be null
        return;
    };
    switch (result) {
        .addresses => |addrs| {
            try testing.expectEqual(@as(usize, 1), addrs.len);
            const ip = addrs[0].in.sa.addr;
            const expected = std.net.Address.initIp4(.{ 192, 0, 2, 1 }, 53);
            try testing.expectEqual(expected.in.sa.addr, ip);
            try testing.expectEqual(@as(u16, 53), addrs[0].getPort());
        },
        .no_glue => {
            try testing.expect(false); // should have glue
        },
    }
}

test "extractReferral with no NS records returns null" {
    const response = dns.Message{
        .header = .{
            .id = 0x1234,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };

    try testing.expect(extractReferral(response) == null);
}

test "extractReferral with NS but no glue returns no_glue" {
    const alloc = testing.allocator;

    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "example");
    ns_name_labels[2] = try alloc.dupe(u8, "com");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 2);
    zone_labels[0] = try alloc.dupe(u8, "example");
    zone_labels[1] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    const response = dns.Message{
        .header = .{
            .id = 0x1234,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 1,
            .ar_count = 0,
        },
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = &.{},
    };
    defer {
        dns.freeMessage(alloc, response);
    }

    const result = extractReferral(response) orelse {
        try testing.expect(false);
        return;
    };
    try testing.expect(result == .no_glue);
}

test "extractReferral case-insensitive glue matching" {
    const alloc = testing.allocator;

    // NS name in lowercase
    const ns_name_labels = try alloc.alloc([]const u8, 3);
    ns_name_labels[0] = try alloc.dupe(u8, "ns1");
    ns_name_labels[1] = try alloc.dupe(u8, "example");
    ns_name_labels[2] = try alloc.dupe(u8, "com");
    const ns_name = dns.Name{ .labels = ns_name_labels };

    const zone_labels = try alloc.alloc([]const u8, 2);
    zone_labels[0] = try alloc.dupe(u8, "example");
    zone_labels[1] = try alloc.dupe(u8, "com");
    const zone_name = dns.Name{ .labels = zone_labels };

    // Glue record name in UPPERCASE
    const glue_name_labels = try alloc.alloc([]const u8, 3);
    glue_name_labels[0] = try alloc.dupe(u8, "NS1");
    glue_name_labels[1] = try alloc.dupe(u8, "EXAMPLE");
    glue_name_labels[2] = try alloc.dupe(u8, "COM");
    const glue_name = dns.Name{ .labels = glue_name_labels };

    const authorities = try alloc.alloc(dns.ResourceRecord, 1);
    authorities[0] = .{
        .name = zone_name,
        .rtype = .ns,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .ns = ns_name },
    };

    const additionals = try alloc.alloc(dns.ResourceRecord, 1);
    additionals[0] = .{
        .name = glue_name,
        .rtype = .a,
        .rclass = .in,
        .ttl = 172800,
        .rdata = .{ .a = .{ 10, 0, 0, 1 } },
    };

    const response = dns.Message{
        .header = .{
            .id = 0x1234,
            .qr = true,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .rcode = .no_error,
            .qd_count = 0,
            .an_count = 0,
            .ns_count = 1,
            .ar_count = 1,
        },
        .questions = &.{},
        .answers = &.{},
        .authorities = authorities,
        .additionals = additionals,
    };
    defer {
        dns.freeMessage(alloc, response);
    }

    const result = extractReferral(response) orelse {
        try testing.expect(false);
        return;
    };
    switch (result) {
        .addresses => |addrs| {
            try testing.expectEqual(@as(usize, 1), addrs.len);
        },
        .no_glue => {
            try testing.expect(false);
        },
    }
}

// ── Integration tests (require Linux + io_uring + network) ─────────────

const EventLoop = @import("event_loop.zig").EventLoop;

fn skipIfNotLinux() !void {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
}

test "recursive resolve example.com A from root hints" {
    try skipIfNotLinux();

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{}) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver.init(&transport);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const response = resolver.resolve(arena.allocator(), "example.com", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        else => return err,
    };

    try testing.expect(response.header.qr);
    try testing.expectEqual(dns.RCode.no_error, response.header.rcode);
    try testing.expect(response.answers.len > 0);

    // Verify we got an A record
    var found_a = false;
    for (response.answers) |rr| {
        if (rr.rtype == .a) {
            found_a = true;
            break;
        }
    }
    try testing.expect(found_a);
}

test "recursive resolve nonexistent domain returns name_error" {
    try skipIfNotLinux();

    const loop = EventLoop.create(testing.allocator) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        else => return err,
    };
    defer loop.destroy();

    var transport = UdpTransport.init(loop, .{}) catch return error.SkipZigTest;
    defer transport.deinit();

    var resolver = RecursiveResolver.init(&transport);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const response = resolver.resolve(arena.allocator(), "this-domain-does-not-exist-xyzzy.example.com", .a) catch |err| switch (err) {
        error.Timeout => return error.SkipZigTest,
        error.NoGlueRecords => return error.SkipZigTest,
        else => return err,
    };

    try testing.expectEqual(dns.RCode.name_error, response.header.rcode);
}
