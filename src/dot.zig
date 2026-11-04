//! DNS over TLS to authoritative servers (RFC 7858, RFC 9539): a session as
//! bytes in and bytes out. No I/O.

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const tls = crypto.tls;
const tls13 = @import("tls13.zig");
const Keys = tls13.Keys;

pub const Error = tls13.Error || error{AlertHeard};

/// A session's read bytes between reads, opened or not: `buf[frame..opened]`
/// is the DNS stream, `buf[at..end]` records still sealed.
pub const Rx = struct {
    buf: []u8,
    frame: usize = 0,
    opened: usize = 0,
    at: usize = 0,
    end: usize = 0,

    /// The most a session leaves unread, plus room to read past it: a
    /// message short of its last byte and a record short of its.
    pub const min_buf = 96 * 1024;
};

pub const Event = union(enum) {
    established: []const u8,
    send: []const u8,
    /// A whole DNS message; lives until `Rx` is written to.
    reply: []u8,
    closed,
};

pub const max_sealed = 2048;

const padding_option: u16 = 12;
const pad_block = 128;
const max_frame = 2 + 512 + 4 + pad_block;

pub const Session = struct {
    gpa: mem.Allocator,
    handshake: ?*tls13.Handshake,
    phase: enum { hello, handshake, application } = .hello,
    read: Keys = undefined,
    write: Keys = undefined,
    plain: u32 = 0,
    next_id: u16 = 0,
    post: tls13.Framer = .{},

    pub fn begin(gpa: mem.Allocator, out: *[tls13.header_len + tls13.max_hello]u8, entropy: *const [tls13.entropy_len]u8) !struct { Session, []const u8 } {
        const h = try gpa.create(tls13.Handshake);
        errdefer gpa.destroy(h);
        const hello = try h.begin(out[tls13.header_len..], entropy, .{ .alpn = "dot" });
        out[0..tls13.header_len].* = [_]u8{@backingInt(tls.ContentType.handshake)} ++
            tls.int(u16, @backingInt(tls.ProtocolVersion.tls_1_0)) ++ tls.int(u16, @intCast(hello.len));
        return .{ .{ .gpa = gpa, .handshake = h }, out[0 .. tls13.header_len + hello.len] };
    }

    pub fn deinit(s: *Session) void {
        s.dropHandshake();
        crypto.secureZero(u8, mem.asBytes(&s.read));
        crypto.secureZero(u8, mem.asBytes(&s.write));
    }

    fn dropHandshake(s: *Session) void {
        const h = s.handshake orelse return;
        crypto.secureZero(u8, mem.asBytes(h));
        s.gpa.destroy(h);
        s.handshake = null;
    }

    /// The message id is the session's: out of a counter, none is in use twice
    /// on it, and inside TLS it guards nothing.
    pub fn query(s: *Session, out: []u8, wire: []const u8) struct { id: u16, sealed: []u8 } {
        var frame: [max_frame]u8 = undefined;
        std.debug.assert(wire.len >= 12 + 11 and wire.len <= 512);
        const id = s.next_id;
        s.next_id +%= 1;
        // RFC 9539 §4.6.8.1, RFC 8467 §4.1.
        const pad = mem.alignForward(usize, wire.len + 4, pad_block) - wire.len - 4;
        const n = wire.len + 4 + pad;
        mem.writeInt(u16, frame[0..2], @intCast(n), .big);
        @memcpy(frame[2..][0..wire.len], wire);
        mem.writeInt(u16, frame[2..4], id, .big);
        const options = mem.readInt(u16, wire[wire.len - 2 ..][0..2], .big);
        mem.writeInt(u16, frame[2 + wire.len - 2 ..][0..2], options + @as(u16, @intCast(4 + pad)), .big);
        mem.writeInt(u16, frame[2 + wire.len ..][0..2], padding_option, .big);
        mem.writeInt(u16, frame[2 + wire.len + 2 ..][0..2], @intCast(pad), .big);
        @memset(frame[2 + wire.len + 4 ..][0..pad], 0);
        return .{ .id = id, .sealed = s.write.seal(out, .application_data, frame[0 .. 2 + n]) };
    }

    pub fn alert(s: *Session, out: []u8, what: tls.Alert.Description) []const u8 {
        const body = [_]u8{ @backingInt(if (what == .close_notify) tls.Alert.Level.warning else tls.Alert.Level.fatal), @backingInt(what) };
        if (s.phase != .hello) return s.write.seal(out, .alert, &body);
        out[0..tls13.header_len].* = [_]u8{@backingInt(tls.ContentType.alert)} ++
            tls.int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++ tls.int(u16, body.len);
        @memcpy(out[tls13.header_len..][0..body.len], &body);
        return out[0 .. tls13.header_len + body.len];
    }

    pub fn next(s: *Session, rx: *Rx, out: []u8) Error!?Event {
        while (true) {
            const plain = rx.buf[rx.frame..rx.opened];
            if (plain.len >= 2) {
                const n = mem.readInt(u16, plain[0..2], .big);
                if (plain.len >= 2 + @as(usize, n)) {
                    if (n < 12) return error.DecodeError;
                    rx.frame += 2 + @as(usize, n);
                    return .{ .reply = plain[2..][0..n] };
                }
            }
            const len = try tls13.recordLen(rx.buf[rx.at..rx.end]) orelse return null;
            if (rx.at + len > rx.end) return null;
            const record = rx.buf[rx.at..][0..len];
            rx.at += len;
            if (try s.onRecord(record, rx, out)) |ev| return ev;
        }
    }

    /// What `rx` left unread, to go back at the front of its buffer, in order.
    /// Replies it gave out still lie in the buffer, so it moves nothing.
    pub fn leftover(s: *Session, rx: *const Rx) struct { plain: []const u8, sealed: []const u8 } {
        s.plain = @intCast(rx.opened - rx.frame);
        return .{ .plain = rx.buf[rx.frame..rx.opened], .sealed = rx.buf[rx.at..rx.end] };
    }

    pub fn reader(s: *const Session, buf: []u8, held: usize) Rx {
        return .{ .buf = buf, .opened = s.plain, .at = s.plain, .end = held };
    }

    fn onRecord(s: *Session, record: []u8, rx: *Rx, out: []u8) Error!?Event {
        const kind: tls.ContentType = @fromBackingInt(record[0]);
        if (s.phase == .hello or kind == .change_cipher_spec) {
            // §5: dropped until the peer's Finished, whatever else it says.
            if (kind == .change_cipher_spec) {
                if (s.phase == .application or record.len != tls13.header_len + 1 or record[tls13.header_len] != 1) return error.UnexpectedMessage;
                return null;
            }
            const body = record[tls13.header_len..];
            if (body.len > tls.max_ciphertext_inner_record_len) return error.RecordOverflow;
            return switch (kind) {
                .alert => heard(body),
                .handshake => switch (try s.handshake.?.read(body)) {
                    .more => null,
                    .handshake => |secrets| blk: {
                        s.read = .of(&secrets.server);
                        s.write = .of(&secrets.client);
                        s.phase = .handshake;
                        break :blk null;
                    },
                    .done => error.UnexpectedMessage,
                },
                else => error.UnexpectedMessage,
            };
        }
        const opened = try s.read.open(record);
        if (opened.kind == .alert) return heard(opened.data);
        if (s.phase == .handshake) {
            if (opened.kind != .handshake) return error.UnexpectedMessage;
            return switch (try s.handshake.?.read(opened.data)) {
                .more => null,
                .handshake => error.UnexpectedMessage,
                .done => |*done| blk: {
                    const sealed = s.write.seal(out, .handshake, done.flight());
                    s.read = .of(&done.application.server);
                    s.write = .of(&done.application.client);
                    s.phase = .application;
                    s.dropHandshake();
                    break :blk .{ .established = sealed };
                },
            };
        }
        return switch (opened.kind) {
            .application_data => blk: {
                // §5.1: nothing comes between a handshake message's records.
                if (s.post.head_len != 0) break :blk error.UnexpectedMessage;
                mem.copyForwards(u8, rx.buf[rx.opened..], opened.data);
                rx.opened += opened.data.len;
                break :blk null;
            },
            .handshake => s.postHandshake(opened.data, out),
            else => error.UnexpectedMessage,
        };
    }

    /// §4.6: a ticket hark can't use (it offers no resumption, and a server
    /// only SHOULD NOT send one then) passes; a key update turns.
    fn postHandshake(s: *Session, bytes: []const u8, out: []u8) Error!?Event {
        if (bytes.len == 0) return error.UnexpectedMessage;
        var rest = bytes;
        while (rest.len > 0) {
            if (!s.post.inBody() and !s.post.header(&rest)) return null;
            switch (s.post.kind()) {
                .new_session_ticket => {
                    _ = s.post.body(&rest);
                    if (s.post.left > 0) return null;
                    s.post.head_len = 0;
                },
                .key_update => {
                    if (s.post.left != 1) return error.DecodeError;
                    if (rest.len != 1) return error.UnexpectedMessage;
                    if (rest[0] > 1) return error.IllegalParameter;
                    s.post.head_len = 0;
                    s.read = s.read.updated();
                    if (rest[0] == 0) return null;
                    const reply = [_]u8{@backingInt(tls.HandshakeType.key_update)} ++ tls.int(u24, 1) ++ [_]u8{0};
                    const sealed = s.write.seal(out, .handshake, &reply);
                    s.write = s.write.updated();
                    return .{ .send = sealed };
                },
                else => return error.UnexpectedMessage,
            }
        }
        return null;
    }

    fn heard(body: []const u8) Error!?Event {
        if (body.len != 2) return error.DecodeError;
        if (body[1] == @backingInt(tls.Alert.Description.close_notify)) return .closed;
        return error.AlertHeard;
    }
};

test "a server's key update turns both ways when it asks" {
    const testing = std.testing;
    const secret: tls13.Secret = @splat(1);
    var s: Session = .{ .gpa = testing.allocator, .handshake = null, .phase = .application, .read = .of(&secret), .write = .of(&secret) };
    var server: Keys = .of(&secret);
    var client: Keys = .of(&secret);
    var buf: [Rx.min_buf]u8 = undefined;
    var rx: Rx = .{ .buf = &buf };
    var out: [max_sealed]u8 = undefined;
    const update = [_]u8{@backingInt(tls.HandshakeType.key_update)} ++ tls.int(u24, 1) ++ [_]u8{1};
    rx.end = server.seal(&buf, .handshake, &update).len;
    const said = (try s.next(&rx, &out)).?.send;
    var sealed: [64]u8 = undefined;
    @memcpy(sealed[0..said.len], said);
    const heard_ = try client.open(sealed[0..said.len]);
    try testing.expectEqual(.handshake, heard_.kind);
    try testing.expectEqual(0, heard_.data[4]);
    server = server.updated();
    client = client.updated();
    const frame = [_]u8{ 0, 12 } ++ @as([12]u8, @splat(7));
    rx = .{ .buf = &buf, .end = server.seal(&buf, .application_data, &frame).len };
    try testing.expectEqualSlices(u8, frame[2..], (try s.next(&rx, &out)).?.reply);
    const wire = [_]u8{ 0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0 };
    _ = try client.open(s.query(&out, &wire).sealed);
}

/// A server that speaks properly until the fuzzer has it lie, checking what
/// the session says back against a transcript of its own.
const Fake = struct {
    smith: *std.testing.Smith,
    s: *Session,
    rx: Rx,
    mirror: crypto.hash.sha2.Sha256 = .init(.{}),
    server: Keys = undefined,
    client: Keys = undefined,
    client_handshake: Secret = undefined,
    asked: bool = false,
    ended: bool = false,
    out: [max_sealed]u8 = undefined,
    sealed: [8192]u8 = undefined,

    const Secret = tls13.Secret;
    const Hkdf = crypto.kdf.hkdf.HkdfSha256;
    const Hmac = crypto.auth.hmac.sha2.HmacSha256;
    const testing = std.testing;

    fn lies(f: *Fake) bool {
        return f.smith.boolWeighted(23, 1);
    }

    fn deliver(f: *Fake, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0 and !f.ended) {
            const room = f.rx.buf.len - f.rx.end;
            // What a read leaves must leave a read room, or it reads as closed.
            try testing.expect(room > 0);
            const most = @min(rest.len, room);
            const n = if (f.smith.boolWeighted(3, 1)) most else 1 + f.smith.index(most);
            @memcpy(f.rx.buf[f.rx.end..][0..n], rest[0..n]);
            f.rx.end += n;
            rest = rest[n..];
            while (f.s.next(&f.rx, &f.out) catch {
                f.ended = true;
                return;
            }) |ev| switch (ev) {
                .established => |flight| try f.heardFlight(flight),
                .send => |said| {
                    @memcpy(f.sealed[0..said.len], said);
                    const opened = try f.client.open(f.sealed[0..said.len]);
                    try testing.expectEqual(.handshake, opened.kind);
                    try testing.expectEqualSlices(u8, &(.{@backingInt(tls.HandshakeType.key_update)} ++ tls.int(u24, 1) ++ [_]u8{0}), opened.data);
                    f.client = f.client.updated();
                },
                .reply => |m| try testing.expect(m.len >= 12),
                .closed => {
                    f.ended = true;
                    return;
                },
            };
            const left = f.s.leftover(&f.rx);
            mem.copyForwards(u8, f.rx.buf, left.plain);
            mem.copyForwards(u8, f.rx.buf[left.plain.len..], left.sealed);
            f.rx = f.s.reader(f.rx.buf, left.plain.len + left.sealed.len);
        }
    }

    fn heardFlight(f: *Fake, flight: []const u8) !void {
        @memcpy(f.sealed[0..flight.len], flight);
        var from: Keys = .of(&f.client_handshake);
        const opened = try from.open(f.sealed[0..flight.len]);
        try testing.expectEqual(.handshake, opened.kind);
        var seen = f.mirror;
        const empty = [_]u8{ 11, 0, 0, 4, 0, 0, 0, 0 };
        if (f.asked) {
            try testing.expectEqualSlices(u8, &empty, opened.data[0..empty.len]);
            seen.update(&empty);
        }
        const key = tls.hkdfExpandLabel(Hkdf, f.client_handshake, "finished", "", Hmac.key_length);
        const want = tls.hmac(Hmac, &seen.finalResult(), key);
        try testing.expectEqualSlices(u8, &want, opened.data[opened.data.len - want.len ..]);
        f.server = .of(&f.s.read.secret);
        f.client = .of(&f.s.write.secret);
    }

    fn plain(f: *Fake, kind: tls.ContentType, bytes: []const u8) !void {
        var record: [tls13.header_len + 2048]u8 = undefined;
        record[0..tls13.header_len].* = [_]u8{@backingInt(kind)} ++ tls.int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++ tls.int(u16, @intCast(bytes.len));
        @memcpy(record[tls13.header_len..][0..bytes.len], bytes);
        try f.deliver(record[0 .. tls13.header_len + bytes.len]);
    }

    fn seal(f: *Fake, kind: tls.ContentType, bytes: []const u8) !void {
        var record: [tls13.overhead + tls.max_ciphertext_inner_record_len]u8 = undefined;
        try f.deliver(f.server.seal(&record, kind, bytes));
    }

    fn message(buf: []u8, kind: tls.HandshakeType, body: []const u8) usize {
        buf[0] = @backingInt(kind);
        mem.writeInt(u24, buf[1..4], @intCast(body.len), .big);
        @memcpy(buf[4..][0..body.len], body);
        return 4 + body.len;
    }

    fn spoil(f: *Fake, bytes: []u8) []u8 {
        if (bytes.len == 0 or !f.lies()) return bytes;
        if (f.smith.value(bool)) {
            bytes[f.smith.index(bytes.len)] ^= @as(u8, 1) << f.smith.value(u3);
            return bytes;
        }
        return bytes[0..f.smith.index(bytes.len)];
    }

    fn serverHello(f: *Fake) !void {
        var body: [1400]u8 = undefined;
        var n: usize = 0;
        const put = struct {
            fn put(b: []u8, at: *usize, bytes: []const u8) void {
                @memcpy(b[at.*..][0..bytes.len], bytes);
                at.* += bytes.len;
            }
        }.put;
        put(&body, &n, &tls.int(u16, 0x0303));
        var random: [32]u8 = @splat(5);
        if (f.lies()) random = tls.hello_retry_request_sequence;
        put(&body, &n, &random);
        put(&body, &n, &.{ 0, 0x13, 0x01, 0 });

        var share: [1200]u8 = undefined;
        var share_len: usize = 0;
        const group: tls.NamedGroup = switch (f.smith.valueRangeAtMost(u8, 0, 7)) {
            0 => .secp256r1,
            1 => .x25519_ml_kem768,
            else => .x25519,
        };
        switch (group) {
            .secp256r1 => put(&share, &share_len, &crypto.ecc.P256.basePoint.toUncompressedSec1()),
            .x25519_ml_kem768 => {
                f.smith.bytes(share[0 .. crypto.kem.ml_kem.MLKem768.ciphertext_length + crypto.dh.X25519.public_length]);
                share_len = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                put(&share, &share_len, &crypto.ecc.Curve25519.basePoint.toBytes());
            },
            else => put(&share, &share_len, &crypto.ecc.Curve25519.basePoint.toBytes()),
        }
        const versions = tls.extension(.supported_versions, tls.int(u16, 0x0304));
        const exts_len = versions.len + 4 + 4 + share_len;
        put(&body, &n, &tls.int(u16, @intCast(exts_len)));
        put(&body, &n, &versions);
        put(&body, &n, &tls.int(u16, @backingInt(tls.ExtensionType.key_share)));
        put(&body, &n, &tls.int(u16, @intCast(4 + share_len)));
        put(&body, &n, &tls.int(u16, @backingInt(group)));
        put(&body, &n, &tls.int(u16, @intCast(share_len)));
        put(&body, &n, share[0..share_len]);

        var msg: [2048]u8 = undefined;
        const len = message(&msg, .server_hello, body[0..n]);
        const said = f.spoil(msg[0..len]);
        f.mirror.update(said);
        try f.plain(.handshake, said);
    }

    fn serverFlight(f: *Fake) !void {
        const h = f.s.handshake.?;
        f.server = .of(&h.traffic.server);
        f.client_handshake = h.traffic.client;
        if (f.smith.boolWeighted(3, 1)) try f.plain(.change_cipher_spec, &.{1});
        var buf: [4096]u8 = undefined;
        var n: usize = 0;
        var exts: [64]u8 = undefined;
        var exts_len: usize = 2;
        if (f.smith.boolWeighted(1, 3)) {
            const alpn = tls.extension(.application_layer_protocol_negotiation, tls.array(u16, u8, tls.array(u8, u8, "dot".*)));
            @memcpy(exts[exts_len..][0..alpn.len], &alpn);
            exts_len += alpn.len;
        }
        if (f.smith.boolWeighted(3, 1)) {
            const groups = tls.extension(.supported_groups, tls.array(u16, tls.NamedGroup, .{.x25519}));
            @memcpy(exts[exts_len..][0..groups.len], &groups);
            exts_len += groups.len;
        }
        mem.writeInt(u16, exts[0..2], @intCast(exts_len - 2), .big);
        n += message(buf[n..], .encrypted_extensions, exts[0..exts_len]);
        if (f.smith.boolWeighted(3, 1)) {
            f.asked = true;
            n += message(buf[n..], .certificate_request, &.{ 0, 0, 0 });
        }
        var junk: [1024]u8 = undefined;
        n += message(buf[n..], .certificate, junk[0..f.smith.slice(&junk)]);
        n += message(buf[n..], .certificate_verify, junk[0..f.smith.slice(&junk)]);
        const said = f.spoil(buf[0..n]);
        f.mirror.update(said);
        var rest: []const u8 = said;
        while (rest.len > 0 and !f.ended) {
            const take = 1 + f.smith.index(rest.len);
            try f.seal(.handshake, rest[0..take]);
            rest = rest[take..];
        }
        if (f.ended) return;

        var seen = f.mirror;
        const key = tls.hkdfExpandLabel(Hkdf, h.traffic.server, "finished", "", Hmac.key_length);
        var finished = tls.hmac(Hmac, &seen.finalResult(), key);
        if (f.lies()) finished[0] ^= 1;
        var msg: [64]u8 = undefined;
        const len = message(&msg, .finished, &finished);
        f.mirror.update(msg[0..len]);
        try f.seal(.handshake, msg[0..len]);
    }

    fn talk(f: *Fake) !void {
        var buf: [4096]u8 = undefined;
        while (!f.ended and !f.smith.eosWeightedSimple(15, 1)) {
            switch (f.smith.valueRangeAtMost(u8, 0, 7)) {
                0, 1 => {
                    const body = f.smith.slice(&buf);
                    if (f.lies() and body >= 2) {
                        mem.writeInt(u16, buf[0..2], 0xffff, .big);
                    } else if (body >= 2) mem.writeInt(u16, buf[0..2], @intCast(body - 2), .big);
                    try f.seal(.application_data, buf[0..body]);
                },
                2 => {
                    var msg: [4096 + 4]u8 = undefined;
                    const len = message(&msg, .new_session_ticket, buf[0..f.smith.slice(&buf)]);
                    const at = f.smith.index(len);
                    if (at > 0) try f.seal(.handshake, msg[0..at]);
                    if (!f.ended) try f.seal(.handshake, msg[at..len]);
                },
                3 => {
                    const ask = f.smith.valueRangeAtMost(u8, 0, 1);
                    var msg: [8]u8 = undefined;
                    const len = message(&msg, .key_update, &.{ask});
                    const said = f.spoil(msg[0..len]);
                    try f.seal(.handshake, said);
                    if (!f.ended and said.len == len) f.server = f.server.updated();
                },
                4 => {
                    const wire = [_]u8{ 0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0 };
                    var out: [max_sealed]u8 = undefined;
                    const opened = try f.client.open(f.s.query(&out, &wire).sealed);
                    try testing.expectEqual(.application_data, opened.kind);
                    try testing.expectEqual(0, (opened.data.len - 2) % pad_block);
                },
                5 => try f.seal(.alert, buf[0..f.smith.slice(buf[0..4])]),
                6 => try f.plain(.change_cipher_spec, &.{1}),
                else => try f.plain(.application_data, buf[0..f.smith.slice(buf[0..1024])]),
            }
        }
    }
};

test "fuzz: a session reads whatever a server says" {
    const testing = std.testing;
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            const h = try testing.allocator.create(tls13.Handshake);
            h.* = .{ .shares = .{ .x25519 = @splat(2), .p256 = @splat(3), .ml_kem = @splat(4) }, .offer = .{ .alpn = "dot" } };
            h.transcript.update("a hello");
            var s: Session = .{ .gpa = testing.allocator, .handshake = h };
            defer s.deinit();
            const buf = try testing.allocator.alloc(u8, Rx.min_buf);
            defer testing.allocator.free(buf);
            const f = try testing.allocator.create(Fake);
            defer testing.allocator.destroy(f);
            f.* = .{ .smith = smith, .s = &s, .rx = .{ .buf = buf } };
            f.mirror.update("a hello");
            try f.serverHello();
            if (f.ended or s.phase != .handshake) return;
            try f.serverFlight();
            if (f.ended or s.phase != .application) return;
            try f.talk();
        }
    }.one, .{});
}
