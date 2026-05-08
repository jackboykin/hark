//! Synthetic pellet generator for the recursion-time bench. Reads a list of
//! domain names, encodes a DNS query for each (using hark's own dns encoder),
//! wraps each in IPv6 + UDP + raw-IP framing, and writes a libpcap file
//! shotgun's `replay.py` accepts directly (DLT_RAW, linktype 12 — same shape
//! `extract-clients.lua` produces).
//!
//! No root, no scapy, no dnspython.
//!
//! Usage:
//!   synth-pellet --names path --qps N --duration N --clients N --out path
//!                [--qtype a|aaaa|ns|mx|...] [--unique-suffix]
//!
//! --unique-suffix prepends a per-query unique label so every query forces a
//! cold cache miss (e.g. "x42.example.com"). Useful for measuring real
//! recursion latency rather than cache-hit latency.

const std = @import("std");
const hark = @import("hark");
const dns = hark.dns;

const Args = struct {
    names_path: []const u8,
    qps: u32,
    duration_s: u32,
    clients: u32,
    out_path: []const u8,
    qtype: dns.RType,
    unique_suffix: bool,
};

fn usage(prog: []const u8) noreturn {
    std.debug.print(
        \\usage: {s} --names <file> --qps <n> --duration <s> --clients <n> --out <file>
        \\               [--qtype a|aaaa|ns|mx|...] [--unique-suffix]
        \\
        \\Reads names (one per line) and emits a shotgun-compatible PCAP pellet.
        \\
    , .{prog});
    std.process.exit(2);
}

fn nextArg(raw: []const [:0]const u8, idx: *usize) [:0]const u8 {
    idx.* += 1;
    if (idx.* >= raw.len) usage(raw[0]);
    return raw[idx.*];
}

fn parseArgs(raw: []const [:0]const u8) !Args {
    if (raw.len < 2) usage(raw[0]);
    var a: Args = .{
        .names_path = "",
        .qps = 0,
        .duration_s = 0,
        .clients = 1,
        .out_path = "",
        .qtype = .a,
        .unique_suffix = false,
    };

    var i: usize = 1;
    while (i < raw.len) : (i += 1) {
        const arg = raw[i];
        if (std.mem.eql(u8, arg, "--names")) {
            a.names_path = nextArg(raw, &i);
        } else if (std.mem.eql(u8, arg, "--qps")) {
            a.qps = try std.fmt.parseInt(u32, nextArg(raw, &i), 10);
        } else if (std.mem.eql(u8, arg, "--duration")) {
            a.duration_s = try std.fmt.parseInt(u32, nextArg(raw, &i), 10);
        } else if (std.mem.eql(u8, arg, "--clients")) {
            a.clients = try std.fmt.parseInt(u32, nextArg(raw, &i), 10);
        } else if (std.mem.eql(u8, arg, "--out")) {
            a.out_path = nextArg(raw, &i);
        } else if (std.mem.eql(u8, arg, "--qtype")) {
            const v = nextArg(raw, &i);
            a.qtype = std.meta.stringToEnum(dns.RType, v) orelse {
                std.debug.print("unknown qtype: {s}\n", .{v});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--unique-suffix")) {
            a.unique_suffix = true;
        } else {
            std.debug.print("unknown arg: {s}\n", .{arg});
            usage(raw[0]);
        }
    }

    if (a.names_path.len == 0 or a.qps == 0 or a.duration_s == 0 or a.out_path.len == 0) usage(raw[0]);
    if (a.clients == 0) a.clients = 1;
    return a;
}

fn parseNames(allocator: std.mem.Allocator, data: []const u8) ![][]const u8 {
    var names: std.ArrayListUnmanaged([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, data, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        try names.append(allocator, trimmed);
    }
    if (names.items.len == 0) return error.NoNames;
    return names.toOwnedSlice(allocator);
}

// ── PCAP framing ─────────────────────────────────────────────────────────

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const DLT_RAW: u32 = 12;
const SNAPLEN: u32 = 65535;
const IPV6_HDR_LEN: usize = 40;
const UDP_HDR_LEN: usize = 8;
const PROTO_UDP: u8 = 17;

fn appendPcapFileHeader(buf: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator) !void {
    var hdr: [24]u8 = undefined;
    std.mem.writeInt(u32, hdr[0..4], PCAP_MAGIC, .little);
    std.mem.writeInt(u16, hdr[4..6], 2, .little); // version major
    std.mem.writeInt(u16, hdr[6..8], 4, .little); // version minor
    std.mem.writeInt(u32, hdr[8..12], 0, .little); // thiszone
    std.mem.writeInt(u32, hdr[12..16], 0, .little); // sigfigs
    std.mem.writeInt(u32, hdr[16..20], SNAPLEN, .little);
    std.mem.writeInt(u32, hdr[20..24], DLT_RAW, .little);
    try buf.appendSlice(alloc, &hdr);
}

fn appendPcapRecord(
    buf: *std.ArrayListUnmanaged(u8),
    alloc: std.mem.Allocator,
    ts_sec: u32,
    ts_usec: u32,
    packet: []const u8,
) !void {
    var hdr: [16]u8 = undefined;
    std.mem.writeInt(u32, hdr[0..4], ts_sec, .little);
    std.mem.writeInt(u32, hdr[4..8], ts_usec, .little);
    std.mem.writeInt(u32, hdr[8..12], @intCast(packet.len), .little);
    std.mem.writeInt(u32, hdr[12..16], @intCast(packet.len), .little);
    try buf.appendSlice(alloc, &hdr);
    try buf.appendSlice(alloc, packet);
}

// IPv6 + UDP packet builder. Writes into `buf`, returns the prefix length.
fn writeIpv6UdpDns(
    buf: []u8,
    src: [16]u8,
    dst: [16]u8,
    src_port: u16,
    dst_port: u16,
    dns_payload: []const u8,
) usize {
    const udp_len: u16 = @intCast(UDP_HDR_LEN + dns_payload.len);

    // ── IPv6 header ──
    // version=6, traffic-class=0, flow-label=0
    std.mem.writeInt(u32, buf[0..4], 0x6000_0000, .big);
    std.mem.writeInt(u16, buf[4..6], udp_len, .big); // payload length
    buf[6] = PROTO_UDP;
    buf[7] = 64; // hop limit
    @memcpy(buf[8..24], &src);
    @memcpy(buf[24..40], &dst);

    // ── UDP header (checksum=0 for now) ──
    std.mem.writeInt(u16, buf[40..42], src_port, .big);
    std.mem.writeInt(u16, buf[42..44], dst_port, .big);
    std.mem.writeInt(u16, buf[44..46], udp_len, .big);
    std.mem.writeInt(u16, buf[46..48], 0, .big);
    @memcpy(buf[48 .. 48 + dns_payload.len], dns_payload);

    const total = IPV6_HDR_LEN + udp_len;
    const cksum = ipv6UdpChecksum(src, dst, buf[40..total]);
    std.mem.writeInt(u16, buf[46..48], cksum, .big);

    return total;
}

// RFC 8200 §8.1 — pseudo-header is src(16) + dst(16) + upper-layer length
// (u32 BE) + zeros(3) + next-header(1).
fn ipv6UdpChecksum(src: [16]u8, dst: [16]u8, udp: []const u8) u16 {
    var sum: u32 = 0;
    sum = addU16Slice(sum, &src);
    sum = addU16Slice(sum, &dst);

    const ull: u32 = @intCast(udp.len);
    sum +%= (ull >> 16) & 0xffff;
    sum +%= ull & 0xffff;
    sum +%= PROTO_UDP;

    sum = addU16Slice(sum, udp);

    while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
    var cs: u16 = @truncate(~sum);
    if (cs == 0) cs = 0xffff;
    return cs;
}

fn addU16Slice(start: u32, bytes: []const u8) u32 {
    var sum = start;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum +%= std.mem.readInt(u16, bytes[i..][0..2], .big);
    }
    if (i < bytes.len) sum +%= @as(u32, bytes[i]) << 8;
    return sum;
}

// fd00::<client_index> — RFC 4193 ULA, won't escape if accidentally routed.
fn clientAddress(idx: u32) [16]u8 {
    var a: [16]u8 = .{0} ** 16;
    a[0] = 0xfd;
    a[1] = 0x00;
    std.mem.writeInt(u32, a[12..16], idx + 1, .big);
    return a;
}

// ::1
const RESOLVER_ADDR: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    var argv: std.ArrayListUnmanaged([:0]const u8) = .empty;
    defer argv.deinit(allocator);
    while (args_iter.next()) |arg| try argv.append(allocator, arg);

    const args = try parseArgs(argv.items);

    const cwd = std.Io.Dir.cwd();
    const names_data = try cwd.readFileAlloc(io, args.names_path, allocator, .unlimited);
    defer allocator.free(names_data);
    const names = try parseNames(allocator, names_data);
    defer allocator.free(names);

    var pellet: std.ArrayListUnmanaged(u8) = .empty;
    defer pellet.deinit(allocator);

    try appendPcapFileHeader(&pellet, allocator);

    const total_queries: u64 = @as(u64, args.qps) * args.duration_s;
    const interval_us: u64 = 1_000_000 / args.qps;

    var rng: std.Random.DefaultPrng = .init(0xc0ffee);
    const r = rng.random();

    var query_arena: std.heap.ArenaAllocator = .init(allocator);
    defer query_arena.deinit();

    // Pellet packet buffer sized to fit the worst-case DNS message hark's
    // encoder will produce, plus IPv6+UDP framing.
    var packet_buf: [IPV6_HDR_LEN + UDP_HDR_LEN + dns.max_message_len]u8 = undefined;
    var dns_buf: [dns.max_message_len]u8 = undefined;

    var skipped_too_long: u64 = 0;
    var i: u64 = 0;
    while (i < total_queries) : (i += 1) {
        _ = query_arena.reset(.retain_capacity);
        const qa = query_arena.allocator();

        const client_idx: u32 = @intCast(i % args.clients);
        const name_idx: usize = @intCast(i % names.len);
        const base = names[name_idx];

        // Skip queries whose name would exceed RFC 1035 max (253 bytes) once
        // the unique-suffix prefix is prepended. Without this guard,
        // buildQuery returns NameTooLong and aborts mid-pellet.
        if (args.unique_suffix) {
            const prefix_len = std.fmt.count("x{d}.", .{i});
            if (prefix_len + base.len > dns.max_name_len) {
                skipped_too_long += 1;
                continue;
            }
        }

        const name = if (args.unique_suffix)
            try std.fmt.allocPrint(qa, "x{d}.{s}", .{ i, base })
        else
            base;

        const id: u16 = @truncate(r.int(u32));
        // EDNS+DO matches what real DNSSEC-aware clients send and what
        // shotgun's stock configs assume, so latency comparisons stay valid.
        const msg = try dns.buildQueryWithOptions(qa, id, name, args.qtype, .{
            .edns = .{ .do_bit = true },
        });
        const dns_payload = try dns.serializeMessage(&dns_buf, msg);

        const src = clientAddress(client_idx);
        // Per-client stable port: shotgun's extract-clients keys client
        // identity off (src_ip, src_port). Random ports turn every query
        // into a unique client and silently break --clients.
        const src_port: u16 = 30000 + @as(u16, @truncate(client_idx % 30000));
        const written = writeIpv6UdpDns(&packet_buf, src, RESOLVER_ADDR, src_port, 53, dns_payload);

        // Timestamps as deltas from t=0; replay.py reads them as relative.
        const total_us: u64 = i * interval_us;
        const ts_sec: u32 = @intCast(total_us / 1_000_000);
        const ts_usec: u32 = @intCast(total_us % 1_000_000);
        try appendPcapRecord(&pellet, allocator, ts_sec, ts_usec, packet_buf[0..written]);
    }

    try cwd.writeFile(io, .{ .sub_path = args.out_path, .data = pellet.items });
    if (skipped_too_long > 0) {
        std.debug.print("warn: skipped {d} queries (name + unique prefix > {d} bytes)\n", .{ skipped_too_long, dns.max_name_len });
    }
    std.debug.print("wrote {d} queries ({d} bytes) to {s}\n", .{ total_queries - skipped_too_long, pellet.items.len, args.out_path });
}
