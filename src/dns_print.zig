/// Pretty printing of DNS messages for the CLI (`hark dump`, `hark query`).
/// Wire-format codec lives in dns.zig — this is operator-readable output only.
const dns = @import("dns.zig");

pub fn printMessage(msg: dns.Message, writer: anytype) !void {
    const hdr = msg.header;
    var opcode_buf: [24]u8 = undefined;
    var rcode_buf: [24]u8 = undefined;
    try writer.print(";; ->>HEADER<<- opcode: {s}, status: {s}, id: {d}\n", .{
        dns.safeTagName(dns.OpCode, hdr.flags.opcode, &opcode_buf), dns.safeTagName(dns.RCode, hdr.flags.rcode, &rcode_buf), hdr.id,
    });
    try writer.print(";; flags:", .{});
    if (hdr.flags.qr) try writer.print(" qr", .{});
    if (hdr.flags.aa) try writer.print(" aa", .{});
    if (hdr.flags.tc) try writer.print(" tc", .{});
    if (hdr.flags.rd) try writer.print(" rd", .{});
    if (hdr.flags.ra) try writer.print(" ra", .{});
    if (hdr.flags.ad) try writer.print(" ad", .{});
    if (hdr.flags.cd) try writer.print(" cd", .{});
    try writer.print("; QUERY: {d}, ANSWER: {d}, AUTHORITY: {d}, ADDITIONAL: {d}\n\n", .{
        hdr.qd_count, hdr.an_count, hdr.ns_count, hdr.ar_count,
    });

    if (msg.opt) |opt| {
        try writer.print(";; OPT PSEUDOSECTION:\n", .{});
        try writer.print("; EDNS: version: {d}, flags:", .{opt.version});
        if (opt.do_bit) try writer.print(" do", .{});
        try writer.print("; udp: {d}\n", .{opt.udp_payload_size});
        if (opt.options.len > 0) {
            try writer.print("; OPTIONS: {d}\n", .{opt.options.len});
        }
        try writer.print("\n", .{});
    }

    if (msg.questions.len > 0) {
        try writer.print(";; QUESTION SECTION:\n", .{});
        for (msg.questions) |q| {
            try printName(q.name, writer);
            var qclass_buf: [24]u8 = undefined;
            var qtype_buf: [24]u8 = undefined;
            try writer.print("\t\t{s}\t{s}\n", .{ dns.safeTagName(dns.RClass, q.qclass, &qclass_buf), dns.safeTagName(dns.RType, q.qtype, &qtype_buf) });
        }
        try writer.print("\n", .{});
    }

    if (msg.answers.len > 0) {
        try writer.print(";; ANSWER SECTION:\n", .{});
        for (msg.answers) |rr| try printResourceRecord(rr, writer);
        try writer.print("\n", .{});
    }

    if (msg.authorities.len > 0) {
        try writer.print(";; AUTHORITY SECTION:\n", .{});
        for (msg.authorities) |rr| try printResourceRecord(rr, writer);
        try writer.print("\n", .{});
    }

    if (msg.additionals.len > 0) {
        try writer.print(";; ADDITIONAL SECTION:\n", .{});
        for (msg.additionals) |rr| try printResourceRecord(rr, writer);
        try writer.print("\n", .{});
    }
}

fn printName(name: dns.Name, writer: anytype) !void {
    if (name.labels.len == 0) {
        try writer.print(".", .{});
        return;
    }
    var buf: [dns.max_dotted_len + 1]u8 = undefined;
    try writer.print("{s}.", .{name.formatInto(&buf)});
}

fn printResourceRecord(rr: dns.ResourceRecord, writer: anytype) !void {
    try printName(rr.name, writer);
    var rclass_buf: [24]u8 = undefined;
    var rtype_buf: [24]u8 = undefined;
    try writer.print("\t{d}\t{s}\t{s}\t", .{ rr.ttl, dns.safeTagName(dns.RClass, rr.rclass, &rclass_buf), dns.safeTagName(dns.RType, rr.rtype, &rtype_buf) });
    switch (rr.rdata) {
        .a => |addr| try writer.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }),
        .aaaa => |addr| {
            for (0..8) |i| {
                if (i > 0) try writer.print(":", .{});
                try writer.print("{x:0>2}{x:0>2}", .{ addr[i * 2], addr[i * 2 + 1] });
            }
        },
        .ns, .cname, .dname, .ptr => |name| try printName(name, writer),
        .mx => |mx| {
            try writer.print("{d} ", .{mx.preference});
            try printName(mx.exchange, writer);
        },
        .soa => |soa| {
            try printName(soa.mname, writer);
            try writer.print(" ", .{});
            try printName(soa.rname, writer);
            try writer.print(" {d} {d} {d} {d} {d}", .{
                soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum,
            });
        },
        .txt => |txt| {
            for (txt.strings) |s| {
                try writer.print("\"{s}\" ", .{s});
            }
        },
        .rrsig => |rrsig| {
            var tc_buf: [24]u8 = undefined;
            var algo_buf: [24]u8 = undefined;
            try writer.print("{s} {d} {s} {d} {d} {d} {d} ", .{
                dns.safeTagName(dns.RType, rrsig.type_covered, &tc_buf),
                rrsig.labels,
                dns.safeTagName(dns.DnssecAlgorithm, rrsig.algorithm, &algo_buf),
                rrsig.original_ttl,
                rrsig.sig_expiration,
                rrsig.sig_inception,
                rrsig.key_tag,
            });
            try printName(rrsig.signer_name, writer);
        },
        .dnskey => |dnskey| {
            var dkalgo_buf: [24]u8 = undefined;
            try writer.print("{d} {d} {s}", .{
                dnskey.flags,
                dnskey.protocol,
                dns.safeTagName(dns.DnssecAlgorithm, dnskey.algorithm, &dkalgo_buf),
            });
        },
        .ds => |ds_data| {
            var dsalgo_buf: [24]u8 = undefined;
            var digest_buf: [24]u8 = undefined;
            try writer.print("{d} {s} {s} ", .{
                ds_data.key_tag,
                dns.safeTagName(dns.DnssecAlgorithm, ds_data.algorithm, &dsalgo_buf),
                dns.safeTagName(dns.DigestType, ds_data.digest_type, &digest_buf),
            });
            for (ds_data.digest) |b| {
                try writer.print("{X:0>2}", .{b});
            }
        },
        .nsec => |nsec_data| {
            try printName(nsec_data.next_domain_name, writer);
            try printTypeBitmap(nsec_data.type_bit_maps, writer);
        },
        .nsec3 => |nsec3| {
            try writer.print("{d} {d} {d} ", .{
                @backingInt(nsec3.hash_algorithm),
                nsec3.flags,
                nsec3.iterations,
            });
            if (nsec3.salt.len == 0) {
                try writer.print("- ", .{});
            } else {
                for (nsec3.salt) |b| try writer.print("{X:0>2}", .{b});
                try writer.print(" ", .{});
            }
            for (nsec3.next_hashed_owner) |b| {
                try writer.print("{X:0>2}", .{b});
            }
            try printTypeBitmap(nsec3.type_bit_maps, writer);
        },
        .nsec3param => |nsec3p| {
            try writer.print("{d} {d} {d} ", .{
                @backingInt(nsec3p.hash_algorithm),
                nsec3p.flags,
                nsec3p.iterations,
            });
            if (nsec3p.salt.len == 0) {
                try writer.print("-", .{});
            } else {
                for (nsec3p.salt) |b| try writer.print("{X:0>2}", .{b});
            }
        },
        .unknown => |data| try writer.print("<{d} bytes>", .{data.len}),
    }
    try writer.print("\n", .{});
}

fn printTypeBitmap(bitmap: []const u8, writer: anytype) !void {
    var pos: usize = 0;
    while (pos + 2 <= bitmap.len) {
        const window = bitmap[pos];
        const win_len = bitmap[pos + 1];
        pos += 2;
        if (pos + win_len > bitmap.len) break;
        for (0..win_len) |byte_idx| {
            const byte = bitmap[pos + byte_idx];
            if (byte == 0) continue;
            for (0..8) |bit_idx| {
                if (byte & (@as(u8, 0x80) >> @intCast(bit_idx)) != 0) {
                    const type_num = @as(u16, window) * 256 + @as(u16, @intCast(byte_idx)) * 8 + @as(u16, @intCast(bit_idx));
                    const rtype: dns.RType = @fromBackingInt(@intCast(type_num));
                    var tbm_buf: [24]u8 = undefined;
                    try writer.print(" {s}", .{dns.safeTagName(dns.RType, rtype, &tbm_buf)});
                }
            }
        }
        pos += win_len;
    }
}
