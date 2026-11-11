//! A QUIC version 1 client (RFC 9000, RFC 9001, RFC 9002) for DNS over QUIC
//! to authoritative servers (RFC 9250): a connection as datagrams in and
//! datagrams out, each query a stream of its own. No I/O; the clock is
//! passed in.

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const tls = crypto.tls;
const Allocator = mem.Allocator;
const dns = @import("dns.zig");
const tls13 = @import("tls13.zig");

const Hkdf = crypto.kdf.hkdf.HkdfSha256;
const Aead = crypto.aead.aes_gcm.Aes128Gcm;
const Aes = crypto.core.aes.Aes128;
const Secret = tls13.Secret;

const version: u32 = 1;
const initial_salt = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
const retry_key = hex("be0c690b9f66575a1d766b54e368c84e");
const retry_nonce = hex("461599d35d632bf2239825bb");

pub const max_datagram = 1200;
pub const max_received = 1472;
const alpn = "doq";

const packets_per_key = 1 << 23;
const forgeries_allowed = 1 << 52;

const stream_window = 2 + 65535;
const connection_window = 4 * stream_window;
const idle_ms: u64 = 30_000;

const packet_threshold = 3;
const granularity_ns: i64 = std.time.ns_per_ms;
const initial_rtt_ns: i64 = 333 * std.time.ns_per_ms;
const initial_window: u64 = 10 * max_datagram;
const minimum_window: u64 = 2 * max_datagram;
const persistent_threshold = 3;
pub const burst = initial_window / max_datagram;

const ack_delay_exponent = 3;
const max_ack_delay_ns: i64 = 25 * std.time.ns_per_ms;

const doq_no_error: u64 = 0x0;
const doq_protocol_error: u64 = 0x2;
const doq_request_cancelled: u64 = 0x3;

const max_varint: u64 = (1 << 62) - 1;

fn varintLen(v: u64) usize {
    std.debug.assert(v <= max_varint);
    if (v < 1 << 6) return 1;
    if (v < 1 << 14) return 2;
    if (v < 1 << 30) return 4;
    return 8;
}

fn putVarint(out: []u8, v: u64) usize {
    const n = varintLen(v);
    switch (n) {
        1 => out[0] = @intCast(v),
        2 => mem.writeInt(u16, out[0..2], @as(u16, @intCast(v)) | 0x4000, .big),
        4 => mem.writeInt(u32, out[0..4], @as(u32, @intCast(v)) | 0x8000_0000, .big),
        else => mem.writeInt(u64, out[0..8], v | 0xc000_0000_0000_0000, .big),
    }
    return n;
}

fn ReaderOf(comptime Bytes: type) type {
    return struct {
        rest: Bytes,

        const Self = @This();

        fn bytes(r: *Self, n: u64) error{Short}!Bytes {
            if (r.rest.len < n) return error.Short;
            defer r.rest = r.rest[@intCast(n)..];
            return r.rest[0..@intCast(n)];
        }

        fn byte(r: *Self) error{Short}!u8 {
            return (try r.bytes(1))[0];
        }

        fn varint(r: *Self) error{Short}!u64 {
            return (try r.varintSized()).value;
        }

        fn varintSized(r: *Self) error{Short}!struct { value: u64, len: usize } {
            if (r.rest.len == 0) return error.Short;
            const n = @as(usize, 1) << @intCast(r.rest[0] >> 6);
            const b = try r.bytes(n);
            var v: u64 = b[0] & 0x3f;
            for (b[1..]) |x| v = v << 8 | x;
            return .{ .value = v, .len = n };
        }
    };
}

const Reader = ReaderOf([]u8);
const ConstReader = ReaderOf([]const u8);

const Writer = struct {
    buf: []u8,
    at: usize = 0,

    fn room(w: *const Writer) usize {
        return w.buf.len - w.at;
    }

    fn varint(w: *Writer, v: u64) void {
        w.at += putVarint(w.buf[w.at..], v);
    }

    fn byte(w: *Writer, b: u8) void {
        w.buf[w.at] = b;
        w.at += 1;
    }

    fn put(w: *Writer, b: []const u8) void {
        @memcpy(w.buf[w.at..][0..b.len], b);
        w.at += b.len;
    }
};

const Cid = struct {
    len: u8 = 0,
    bytes: [20]u8 = undefined,

    pub fn of(b: []const u8) Cid {
        std.debug.assert(b.len <= 20);
        var c: Cid = .{ .len = @intCast(b.len) };
        @memcpy(c.bytes[0..b.len], b);
        return c;
    }

    pub fn slice(c: *const Cid) []const u8 {
        return c.bytes[0..c.len];
    }

    fn eql(a: *const Cid, b: []const u8) bool {
        return mem.eql(u8, a.slice(), b);
    }
};

const Keys = struct {
    secret: Secret,
    key: [Aead.key_length]u8,
    iv: [Aead.nonce_length]u8,
    hp: [Aes.key_bits / 8]u8,

    pub fn of(secret: *const Secret) Keys {
        return .{
            .secret = secret.*,
            .key = tls.hkdfExpandLabel(Hkdf, secret.*, "quic key", "", Aead.key_length),
            .iv = tls.hkdfExpandLabel(Hkdf, secret.*, "quic iv", "", Aead.nonce_length),
            .hp = tls.hkdfExpandLabel(Hkdf, secret.*, "quic hp", "", Aes.key_bits / 8),
        };
    }

    /// RFC 9001 §6.1: a key update never changes the header protection key.
    fn updated(k: *const Keys) Keys {
        const next = tls.hkdfExpandLabel(Hkdf, k.secret, "quic ku", "", Hkdf.prk_length);
        var u = Keys.of(&next);
        u.hp = k.hp;
        return u;
    }

    fn nonce(k: *const Keys, pn: u64) [Aead.nonce_length]u8 {
        var n = k.iv;
        var be: [8]u8 = undefined;
        mem.writeInt(u64, &be, pn, .big);
        for (n[n.len - 8 ..], be) |*b, x| b.* ^= x;
        return n;
    }

    fn mask(k: *const Keys, sample: *const [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        Aes.initEnc(k.hp).encrypt(&out, sample);
        return out;
    }

    pub fn seal(k: *const Keys, packet: []u8, head: usize, pn_len: usize, pn: u64) void {
        const body = packet[head .. packet.len - Aead.tag_length];
        Aead.encrypt(body, packet[packet.len - Aead.tag_length ..][0..Aead.tag_length], body, packet[0..head], k.nonce(pn), k.key);
        const pn_at = head - pn_len;
        const m = k.mask(packet[pn_at + 4 ..][0..16]);
        packet[0] ^= m[0] & @as(u8, if (packet[0] & 0x80 != 0) 0x0f else 0x1f);
        for (packet[pn_at..head], m[1..][0..pn_len]) |*b, x| b.* ^= x;
    }

    fn unmask(k: *const Keys, packet: []u8, pn_at: usize) struct { first: u8, truncated: u32, len: usize } {
        const m = k.mask(packet[pn_at + 4 ..][0..16]);
        packet[0] ^= m[0] & @as(u8, if (packet[0] & 0x80 != 0) 0x0f else 0x1f);
        const len = @as(usize, packet[0] & 3) + 1;
        var t: u32 = 0;
        for (packet[pn_at..][0..len], m[1..][0..len]) |*b, x| {
            b.* ^= x;
            t = t << 8 | b.*;
        }
        return .{ .first = packet[0], .truncated = t, .len = len };
    }

    fn open(k: *const Keys, packet: []u8, head: usize, pn: u64) ?[]u8 {
        if (packet.len < head + Aead.tag_length) return null;
        const body = packet[head .. packet.len - Aead.tag_length];
        const tag = packet[packet.len - Aead.tag_length ..][0..Aead.tag_length].*;
        Aead.decrypt(body, body, tag, packet[0..head], k.nonce(pn), k.key) catch return null;
        return body;
    }
};

fn initialKeys(dcid: []const u8) struct { client: Keys, server: Keys } {
    const initial = Hkdf.extract(&initial_salt, dcid);
    return .{
        .client = .of(&tls.hkdfExpandLabel(Hkdf, initial, "client in", "", Hkdf.prk_length)),
        .server = .of(&tls.hkdfExpandLabel(Hkdf, initial, "server in", "", Hkdf.prk_length)),
    };
}

fn retryValid(retry: []const u8, odcid: []const u8) bool {
    if (retry.len < Aead.tag_length) return false;
    var pseudo: [1 + 20 + 1500]u8 = undefined;
    const body = retry[0 .. retry.len - Aead.tag_length];
    if (1 + odcid.len + body.len > pseudo.len) return false;
    pseudo[0] = @intCast(odcid.len);
    @memcpy(pseudo[1..][0..odcid.len], odcid);
    @memcpy(pseudo[1 + odcid.len ..][0..body.len], body);
    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(&.{}, &tag, &.{}, pseudo[0 .. 1 + odcid.len + body.len], retry_nonce, retry_key);
    return crypto.timing_safe.eql([Aead.tag_length]u8, tag, retry[retry.len - Aead.tag_length ..][0..Aead.tag_length].*);
}

fn decodePn(largest: ?u64, truncated: u64, len: usize) u64 {
    const expected = if (largest) |l| l + 1 else 0;
    const win: u64 = @as(u64, 1) << @intCast(8 * len);
    const half = win / 2;
    const candidate = (expected & ~(win - 1)) | truncated;
    if (candidate + half <= expected and candidate < (1 << 62) - win) return candidate + win;
    if (candidate > expected + half and candidate >= win) return candidate - win;
    return candidate;
}

fn pnLen(pn: u64, largest_acked: ?u64) usize {
    const unacked = if (largest_acked) |l| pn - l else pn + 1;
    if (unacked <= 1 << 7) return 1;
    if (unacked <= 1 << 15) return 2;
    if (unacked <= 1 << 23) return 3;
    return 4;
}

const Param = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,
};

fn ourParams(out: *[tls13.max_quic_params]u8) []const u8 {
    var w: Writer = .{ .buf = out };
    inline for (.{
        .{ Param.max_idle_timeout, idle_ms },
        .{ Param.initial_max_data, connection_window },
        .{ Param.initial_max_stream_data_bidi_local, stream_window },
        .{ Param.max_udp_payload_size, max_received },
    }) |p| {
        w.varint(@backingInt(p[0]));
        w.varint(varintLen(p[1]));
        w.varint(p[1]);
    }
    w.varint(@backingInt(Param.initial_source_connection_id));
    w.varint(0);
    return out[0..w.at];
}

const Params = struct {
    idle_ms: u64 = 0,
    reset_token: ?[16]u8 = null,
    max_data: u64 = 0,
    stream_data: u64 = 0,
    max_streams: u64 = 0,
    ack_delay_exponent: u6 = 3,
    max_ack_delay_ns: i64 = 25 * std.time.ns_per_ms,
    original_dcid: ?Cid = null,
    initial_scid: ?Cid = null,
    retry_scid: ?Cid = null,
    preferred: ?struct { cid: Cid, token: [16]u8 } = null,

    fn read(bytes: []const u8) error{TransportParameterError}!Params {
        var p: Params = .{};
        var seen: std.bit_set.Static(0x11) = .empty;
        var r: ConstReader = .{ .rest = bytes };
        while (r.rest.len > 0) {
            const id = r.varint() catch return error.TransportParameterError;
            const value = r.bytes(r.varint() catch return error.TransportParameterError) catch return error.TransportParameterError;
            if (id < 0x11) {
                if (seen.isSet(@intCast(id))) return error.TransportParameterError;
                seen.set(@intCast(id));
            } else {
                var again: ConstReader = .{ .rest = r.rest };
                while (again.rest.len > 0) {
                    if ((again.varint() catch break) == id) return error.TransportParameterError;
                    _ = again.bytes(again.varint() catch break) catch break;
                }
                continue;
            }
            var v: ConstReader = .{ .rest = value };
            switch (@as(Param, @fromBackingInt(id))) {
                .original_destination_connection_id => p.original_dcid = try cidOf(value),
                .initial_source_connection_id => p.initial_scid = try cidOf(value),
                .retry_source_connection_id => p.retry_scid = try cidOf(value),
                .stateless_reset_token => {
                    if (value.len != 16) return error.TransportParameterError;
                    p.reset_token = value[0..16].*;
                },
                .max_idle_timeout => p.idle_ms = try number(&v),
                .max_udp_payload_size => if (try number(&v) < 1200) return error.TransportParameterError,
                .initial_max_data => p.max_data = try number(&v),
                .initial_max_stream_data_bidi_remote => p.stream_data = try number(&v),
                .initial_max_stream_data_bidi_local, .initial_max_stream_data_uni => _ = try number(&v),
                .initial_max_streams_bidi => {
                    p.max_streams = try number(&v);
                    if (p.max_streams > 1 << 60) return error.TransportParameterError;
                },
                .initial_max_streams_uni => if (try number(&v) > 1 << 60) return error.TransportParameterError,
                .ack_delay_exponent => {
                    const e = try number(&v);
                    if (e > 20) return error.TransportParameterError;
                    p.ack_delay_exponent = @intCast(e);
                },
                .max_ack_delay => {
                    const d = try number(&v);
                    if (d >= 1 << 14) return error.TransportParameterError;
                    p.max_ack_delay_ns = @intCast(d * std.time.ns_per_ms);
                },
                .disable_active_migration => if (value.len != 0) return error.TransportParameterError,
                .active_connection_id_limit => {
                    if (try number(&v) < 2) return error.TransportParameterError;
                },
                .preferred_address => {
                    if (value.len < 41) return error.TransportParameterError;
                    const len = value[40];
                    if (len == 0 or len > 20 or value.len != 41 + @as(usize, len) + 16) return error.TransportParameterError;
                    p.preferred = .{ .cid = .of(value[41..][0..len]), .token = value[41 + len ..][0..16].* };
                },
                _ => unreachable,
            }
        }
        if (p.original_dcid == null or p.initial_scid == null) return error.TransportParameterError;
        return p;
    }

    fn number(x: *ConstReader) error{TransportParameterError}!u64 {
        const n = x.varint() catch return error.TransportParameterError;
        if (x.rest.len != 0) return error.TransportParameterError;
        return n;
    }

    fn cidOf(value: []const u8) error{TransportParameterError}!Cid {
        if (value.len > 20) return error.TransportParameterError;
        return .of(value);
    }
};

fn Ranges(comptime cap: usize) type {
    return struct {
        lo: [cap]u64 = undefined,
        hi: [cap]u64 = undefined,
        n: usize = 0,
        floor: ?u64 = null,

        const Self = @This();

        fn known(r: *const Self, x: u64) bool {
            if (r.floor) |f| if (x <= f) return true;
            for (r.lo[0..r.n], r.hi[0..r.n]) |lo, hi| if (x >= lo and x <= hi) return true;
            return false;
        }

        fn add(r: *Self, lo_in: u64, hi_in: u64) void {
            var lo = lo_in;
            var hi = hi_in;
            var i: usize = 0;
            while (i < r.n and r.lo[i] > hi +| 1) i += 1;
            const first = i;
            while (i < r.n and r.hi[i] +| 1 >= lo) : (i += 1) {
                lo = @min(lo, r.lo[i]);
                hi = @max(hi, r.hi[i]);
            }
            const merged = i - first;
            if (merged == 0) {
                if (r.n == cap) {
                    if (first == cap) {
                        r.floor = @max(r.floor orelse 0, hi);
                        return;
                    }
                    r.floor = @max(r.floor orelse 0, r.hi[cap - 1]);
                    r.n -= 1;
                }
                mem.copyBackwards(u64, r.lo[first + 1 .. r.n + 1], r.lo[first..r.n]);
                mem.copyBackwards(u64, r.hi[first + 1 .. r.n + 1], r.hi[first..r.n]);
                r.n += 1;
            } else if (merged > 1) {
                mem.copyForwards(u64, r.lo[first + 1 ..], r.lo[i..r.n]);
                mem.copyForwards(u64, r.hi[first + 1 ..], r.hi[i..r.n]);
                r.n -= merged - 1;
            }
            r.lo[first] = lo;
            r.hi[first] = hi;
        }

        fn covers(r: *const Self, end: u64) bool {
            if (end == 0) return true;
            return r.n == 1 and r.lo[0] == 0 and r.hi[0] + 1 >= end;
        }
    };
}

const Owed = union(enum) {
    none,
    due,
    flying: u64,

    fn lost(o: *Owed, pn: u64) bool {
        if (o.* == .flying and o.flying == pn) {
            o.* = .due;
            return true;
        }
        return false;
    }

    fn acked(o: *Owed, pn: u64) bool {
        if (o.* == .flying and o.flying == pn) {
            o.* = .none;
            return true;
        }
        return false;
    }
};

const Sent = struct {
    pn: u64,
    sent_ns: i64,
    bytes: u16,
    ack_eliciting: bool,
    in_flight: bool,
    limited: bool,
    streams: ?Span = null,
    state: enum { flying, acked, lost } = .flying,
};

const Span = struct {
    from: u64,
    to: u64,

    fn widen(w: *?Span, n: u64) void {
        if (w.*) |*x| {
            x.from = @min(x.from, n);
            x.to = @max(x.to, n);
        } else w.* = .{ .from = n, .to = n };
    }
};

const Space = struct {
    tx: ?Keys = null,
    rx: ?Keys = null,
    next_pn: u64 = 0,
    largest_acked: ?u64 = null,
    sent: []Sent = &.{},
    sent_head: usize = 0,
    sent_len: usize = 0,
    eliciting_flying: u32 = 0,
    loss_ns: ?i64 = null,
    last_eliciting_ns: ?i64 = null,
    received: Ranges(32) = .{},
    largest_rx: ?u64 = null,
    largest_rx_ns: i64 = 0,
    unacked: u32 = 0,
    ack_by_ns: ?i64 = null,
    probes: u2 = 0,
    out: CryptoOut = .{},
    in: CryptoIn = .{},

    fn sentAt(s: *const Space, i: usize) *Sent {
        return &s.sent[(s.sent_head + i) % s.sent.len];
    }

    fn eliciting(s: *const Space) bool {
        return s.eliciting_flying > 0;
    }

    fn land(s: *Space, p: *Sent, state: @TypeOf(p.state)) void {
        p.state = state;
        if (p.ack_eliciting) s.eliciting_flying -= 1;
    }

    fn ackWanted(s: *const Space, level: Level, now: i64) bool {
        if (s.unacked == 0) return false;
        if (level != .application or s.unacked >= 2) return true;
        return now >= s.ack_by_ns.?;
    }
};

const CryptoOut = struct {
    data: []const u8 = &.{},
    chunks: [8]struct { off: u32, len: u32, owed: Owed } = undefined,
    n: usize = 0,

    fn set(c: *CryptoOut, data: []const u8) void {
        c.data = data;
        c.n = 1;
        c.chunks[0] = .{ .off = 0, .len = @intCast(data.len), .owed = .due };
    }

    fn all(c: *CryptoOut) []@TypeOf(c.chunks[0]) {
        return c.chunks[0..c.n];
    }
};

const CryptoIn = struct {
    at: u64 = 0,
    window: ?*Window = null,

    const Window = struct {
        bytes: [8192]u8,
        have: std.bit_set.Static(8192),
    };
};

const Level = enum { initial, handshake, application };

pub const End = enum { failed, closed };

pub const Event = union(enum) {
    established,
    reply: struct { id: u64, bytes: []u8 },
    refused: u64,
    room,
    ended: End,
};

const Stream = struct {
    n: u64,
    wire: []const u8,
    send: Owed = .due,
    went: bool = false,
    credit: u64,
    top: u64 = 0,
    final: ?u64 = null,
    got: Ranges(16) = .{},
    buf: []u8 = &.{},
    done: bool = false,
    stop: Owed = .none,
    reset: Owed = .none,

    fn id(s: *const Stream) u64 {
        return 4 * s.n;
    }

    /// The 2 is the length prefix; the 4 is an empty Padding option, which
    /// asks for a padded reply (RFC 7830 §4).
    fn dataLen(s: *const Stream) usize {
        return 2 + s.wire.len + 4;
    }

    fn frameLen(s: *const Stream) usize {
        const n = s.dataLen();
        return 1 + varintLen(s.id()) + varintLen(n) + n;
    }

    fn write(s: *const Stream, w: *Writer) void {
        const n = s.dataLen();
        w.byte(0x0b);
        w.varint(s.id());
        w.varint(n);
        mem.writeInt(u16, w.buf[w.at..][0..2], @intCast(n - 2), .big);
        const msg = dns.pad(w.buf[w.at + 2 ..][0 .. n - 2], s.wire, 1) catch unreachable;
        @memset(msg[0..2], 0);
        w.at += n;
    }
};

const Close = struct { app: bool, code: u64, frame: u64 = 0 };

const Error = error{
    InternalError,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIdLimitError,
    ProtocolViolation,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    DoqProtocolError,
    OutOfMemory,
} || tls13.Error;

fn closeFor(err: Error) Close {
    return switch (err) {
        error.InternalError, error.OutOfMemory => .{ .app = false, .code = 0x1 },
        error.FlowControlError => .{ .app = false, .code = 0x3 },
        error.StreamLimitError => .{ .app = false, .code = 0x4 },
        error.StreamStateError => .{ .app = false, .code = 0x5 },
        error.FinalSizeError => .{ .app = false, .code = 0x6 },
        error.FrameEncodingError => .{ .app = false, .code = 0x7 },
        error.TransportParameterError => .{ .app = false, .code = 0x8 },
        error.ConnectionIdLimitError => .{ .app = false, .code = 0x9 },
        error.ProtocolViolation => .{ .app = false, .code = 0xa },
        error.CryptoBufferExceeded => .{ .app = false, .code = 0xd },
        error.KeyUpdateError => .{ .app = false, .code = 0xe },
        error.AeadLimitReached => .{ .app = false, .code = 0xf },
        error.DoqProtocolError => .{ .app = true, .code = doq_protocol_error },
        else => |e| .{ .app = false, .code = 0x100 + @as(u64, @backingInt(tls13.alert(@errorCast(e)))) },
    };
}

pub const Conn = struct {
    gpa: Allocator,
    hs: ?*tls13.Handshake,
    hello: []u8,
    finished: [2 * 64]u8 = undefined,
    spaces: [3]Space = .{ .{}, .{}, .{} },
    phase: enum { hello, handshake, established, confirmed } = .hello,
    odcid: Cid,
    dcid: Cid,
    server_scid: ?Cid = null,
    retry_scid: ?Cid = null,
    token: []u8 = &.{},
    heard: bool = false,
    cids: [2]?struct { seq: u64, cid: Cid, token: ?[16]u8 } = .{ null, null },
    retire_below: u64 = 0,
    retiring: [8]struct { seq: u64, owed: Owed } = undefined,
    nretiring: usize = 0,
    peer: Params = .{},
    post: tls13.Framer = .{},

    latest_rtt: i64 = 0,
    smoothed_rtt: i64 = initial_rtt_ns,
    rttvar: i64 = initial_rtt_ns / 2,
    min_rtt: i64 = 0,
    first_rtt_ns: ?i64 = null,
    pto_count: u5 = 0,
    handshake_acked: bool = false,
    in_flight: u64 = 0,
    cwnd: u64 = initial_window,
    ssthresh: u64 = std.math.maxInt(u64),
    recovery_ns: ?i64 = null,

    key_phase: u1 = 0,
    prev_rx: ?Keys = null,
    prev_until_ns: i64 = 0,
    phase_from: u64 = 0,
    sealed: u64 = 0,
    forgeries: u64 = 0,

    streams: std.ArrayList(?*Stream) = .empty,
    streams_from: u64 = 0,
    next_n: u64 = 0,
    owe_sends: usize = 0,
    blocked: bool = false,
    streams_blocked: Owed = .none,
    data_blocked: Owed = .none,
    tx_data: u64 = 0,
    rx_data: u64 = 0,
    rx_consumed: u64 = 0,
    rx_max: u64 = connection_window,
    max_data: Owed = .none,
    path_response: ?[8]u8 = null,
    ping: Owed = .none,

    idle_ns: i64 = idle_ms * std.time.ns_per_ms,
    idle_from_ns: i64,
    eliciting_since_heard: bool = false,

    events: std.ArrayList(Event) = .empty,
    event_at: usize = 0,
    close: ?Close = null,
    ended: ?End = null,
    fault: []const u8 = "silence",

    pub fn begin(gpa: Allocator, entropy: *const [tls13.entropy_len + 8]u8, now: i64) !Conn {
        const h = try gpa.create(tls13.Handshake);
        errdefer gpa.destroy(h);
        var params: [tls13.max_quic_params]u8 = undefined;
        var out: [tls13.max_hello]u8 = undefined;
        const hello = try h.begin(&out, entropy[8..], .{ .alpn = alpn, .quic = ourParams(&params) });
        const owned = try gpa.dupe(u8, hello);
        errdefer gpa.free(owned);
        var c: Conn = .{ .gpa = gpa, .hs = h, .hello = owned, .odcid = .of(entropy[0..8]), .dcid = .of(entropy[0..8]), .idle_from_ns = now };
        const sizes = [3]usize{ 16, 16, 128 };
        for (&c.spaces, sizes) |*s, n| s.sent = try gpa.alloc(Sent, n);
        const keys = initialKeys(c.dcid.slice());
        c.spaces[0].tx = keys.client;
        c.spaces[0].rx = keys.server;
        c.spaces[0].out.set(owned);
        return c;
    }

    pub fn deinit(c: *Conn) void {
        const gpa = c.gpa;
        c.dropHandshake();
        gpa.free(c.hello);
        gpa.free(c.token);
        for (&c.spaces) |*s| {
            gpa.free(s.sent);
            if (s.in.window) |w| gpa.destroy(w);
            inline for (.{ &s.tx, &s.rx }) |k| if (k.*) |*x| crypto.secureZero(u8, mem.asBytes(x));
        }
        if (c.prev_rx) |*k| crypto.secureZero(u8, mem.asBytes(k));
        for (c.streams.items) |o| if (o) |st| c.freeStream(st);
        c.streams.deinit(gpa);
        c.events.deinit(gpa);
    }

    fn dropHandshake(c: *Conn) void {
        const h = c.hs orelse return;
        crypto.secureZero(u8, mem.asBytes(h));
        c.gpa.destroy(h);
        c.hs = null;
    }

    pub fn established(c: *const Conn) bool {
        return c.phase == .established or c.phase == .confirmed;
    }

    fn space(c: *Conn, l: Level) *Space {
        return &c.spaces[@backingInt(l)];
    }

    pub const Taken = union(enum) { id: u64, later };

    /// `wire` is borrowed: it must outlive the stream, until its reply or cancel.
    pub fn query(c: *Conn, wire: []const u8) !Taken {
        if (c.next_n >= c.peer.max_streams) {
            if (!c.blocked) {
                c.blocked = true;
                c.streams_blocked = .due;
            }
            return .later;
        }
        const st = try c.gpa.create(Stream);
        errdefer c.gpa.destroy(st);
        try c.streams.append(c.gpa, st);
        st.* = .{ .n = c.next_n, .wire = wire, .credit = c.peer.stream_data };
        c.next_n += 1;
        c.owe_sends += 1;
        return .{ .id = st.id() };
    }

    fn stream(c: *const Conn, id: u64) ?*Stream {
        const n = id / 4;
        if (n < c.streams_from or n >= c.next_n) return null;
        return c.streams.items[@intCast(n - c.streams_from)];
    }

    pub fn cancel(c: *Conn, id: u64) void {
        const st = c.stream(id) orelse return;
        if (st.done) return;
        st.done = true;
        st.stop = .due;
        c.abandonSend(st);
    }

    fn abandonSend(c: *Conn, st: *Stream) void {
        if (!(st.went and st.send == .none)) st.reset = .due;
        if (st.send == .due) c.owe_sends -= 1;
        st.send = .none;
        c.consume(st);
    }

    fn consume(c: *Conn, st: *Stream) void {
        c.rx_consumed += st.top;
        if (st.buf.len != 0) {
            c.gpa.free(st.buf);
            st.buf = &.{};
        }
        if (c.rx_max - c.rx_consumed < connection_window / 2) {
            c.rx_max = c.rx_consumed + connection_window;
            c.max_data = .due;
        }
        c.reap(st);
        c.compact();
    }

    fn reap(c: *Conn, st: *Stream) void {
        if (!st.done or st.send != .none or st.stop != .none or st.reset != .none) return;
        c.streams.items[@intCast(st.n - c.streams_from)] = null;
        c.freeStream(st);
    }

    fn compact(c: *Conn) void {
        var gone: usize = 0;
        while (gone < c.streams.items.len and c.streams.items[gone] == null) gone += 1;
        if (gone == 0) return;
        c.streams.replaceRangeAssumeCapacity(0, gone, &.{});
        c.streams_from += gone;
    }

    fn freeStream(c: *Conn, st: *Stream) void {
        if (st.buf.len != 0) c.gpa.free(st.buf);
        c.gpa.destroy(st);
    }

    pub fn next(c: *Conn) ?Event {
        if (c.event_at == c.events.items.len) {
            c.events.clearRetainingCapacity();
            c.event_at = 0;
            return null;
        }
        defer c.event_at += 1;
        return c.events.items[c.event_at];
    }

    fn emit(c: *Conn, ev: Event) !void {
        try c.events.append(c.gpa, ev);
    }

    fn fail(c: *Conn, err: Error, fault: []const u8) !void {
        if (c.ended != null) return;
        c.close = closeFor(err);
        c.fault = fault;
        c.ended = .failed;
        try c.emit(.{ .ended = .failed });
    }

    fn end(c: *Conn, how: End, fault: []const u8) !void {
        if (c.ended != null) return;
        c.fault = fault;
        c.ended = how;
        try c.emit(.{ .ended = how });
    }

    fn caught(c: *Conn, err: Error) !void {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        try c.fail(err, @errorName(err));
    }

    /// Reply bytes may point into `datagram`, which must live until the events
    /// are taken; the caller then frees what was put on `delivered`.
    pub fn input(c: *Conn, datagram: []u8, now: i64, delivered: *std.ArrayList([]u8)) !void {
        if (c.ended != null) return;
        var rest = datagram;
        var any = false;
        while (rest.len > 0) {
            const used = c.packet(rest, now, delivered, &any) catch |err| {
                try c.caught(err);
                return;
            } orelse break;
            if (c.ended != null) return;
            rest = rest[used..];
        }
        if (!any) {
            if (c.isReset(datagram)) return c.end(.closed, "stateless reset");
            return;
        }
        c.idle_from_ns = now;
        c.eliciting_since_heard = false;
    }

    /// RFC 9000 §10.3: a datagram no key opens, ending in a token the server
    /// gave with one of its connection ids.
    fn isReset(c: *const Conn, datagram: []const u8) bool {
        if (datagram.len < 21) return false;
        const tail = datagram[datagram.len - 16 ..][0..16].*;
        for (c.cids) |o| {
            const token = (o orelse continue).token orelse continue;
            if (crypto.timing_safe.eql([16]u8, token, tail)) return true;
        }
        return false;
    }

    fn packet(c: *Conn, rest: []u8, now: i64, delivered: *std.ArrayList([]u8), any: *bool) Error!?usize {
        const first = rest[0];
        if (first & 0x80 == 0) {
            if (first & 0x40 == 0) return null;
            const s = c.space(.application);
            if (s.rx == null or rest.len < 1 + 20) return null;
            try c.protected(.application, rest, 1, now, delivered, any);
            return rest.len;
        }
        var r: Reader = .{ .rest = rest };
        _ = r.byte() catch return null;
        const v = mem.readInt(u32, (r.bytes(4) catch return null)[0..4], .big);
        const dcid = r.bytes(r.byte() catch return null) catch return null;
        const scid_len = r.byte() catch return null;
        if (dcid.len > 20 or scid_len > 20) return null;
        const scid = r.bytes(scid_len) catch return null;
        if (v == 0) {
            try c.versionNegotiation(r.rest);
            return null;
        }
        if (first & 0x40 == 0 or v != version or dcid.len != 0) return null;
        const kind: u2 = @truncate(first >> 4);
        if (kind == 3) {
            try c.retry(rest, scid);
            return null;
        }
        if (kind == 1) return null;
        const level: Level = if (kind == 0) .initial else .handshake;
        if (level == .initial and (r.varint() catch return null) != 0) return null;
        const length = r.varint() catch return null;
        const pn_at = rest.len - r.rest.len;
        if (length > r.rest.len) return null;
        const size: usize = @intCast(pn_at + length);
        if (c.space(level).rx == null or length < 20) return size;
        if (c.server_scid) |known| {
            if (!known.eql(scid)) return size;
        } else if (level == .initial) {
            c.server_scid = .of(scid);
            c.dcid = .of(scid);
            c.cids[0] = .{ .seq = 0, .cid = .of(scid), .token = null };
        } else return size;
        try c.protected(level, rest[0..size], pn_at, now, delivered, any);
        return size;
    }

    fn versionNegotiation(c: *Conn, list: []const u8) !void {
        if (c.heard or list.len % 4 != 0) return;
        var i: usize = 0;
        while (i < list.len) : (i += 4) if (mem.readInt(u32, list[i..][0..4], .big) == version) return;
        try c.end(.failed, "version negotiation");
    }

    fn retry(c: *Conn, whole: []const u8, scid: []const u8) !void {
        if (c.heard or c.retry_scid != null) return;
        if (c.odcid.eql(scid)) return;
        if (!retryValid(whole, c.odcid.slice())) return;
        const head = 1 + 4 + 1 + 0 + 1 + scid.len;
        if (whole.len <= head + Aead.tag_length) return;
        const token = whole[head .. whole.len - Aead.tag_length];
        c.token = try c.gpa.dupe(u8, token);
        c.retry_scid = .of(scid);
        c.dcid = .of(scid);
        const keys = initialKeys(scid);
        const s = c.space(.initial);
        s.tx = keys.client;
        s.rx = keys.server;
        s.out.set(c.hello);
        c.forget(.initial);
        c.heard = true;
    }

    fn protected(c: *Conn, level: Level, pkt: []u8, pn_at: usize, now: i64, delivered: *std.ArrayList([]u8), any: *bool) Error!void {
        const s = c.space(level);
        if (pkt.len < pn_at + 4 + 16) return;
        var keys = s.rx.?;
        const h = keys.unmask(pkt, pn_at);
        const pn = decodePn(s.largest_rx, h.truncated, h.len);
        const head = pn_at + h.len;
        var update = false;
        if (level == .application) {
            const phase: u1 = @truncate(h.first >> 2);
            if (phase != c.key_phase) {
                if (pn < c.phase_from and c.prev_rx != null) {
                    keys = c.prev_rx.?;
                } else {
                    keys = keys.updated();
                    update = true;
                }
            }
        }
        const plain = keys.open(pkt, head, pn) orelse {
            c.forgeries += 1;
            if (c.forgeries >= forgeries_allowed) return error.AeadLimitReached;
            return;
        };
        if (s.received.known(pn)) return;
        any.* = true;
        c.heard = true;
        if (h.first & @as(u8, if (level == .application) 0x18 else 0x0c) != 0) return error.ProtocolViolation;
        if (update) {
            c.prev_rx = s.rx;
            c.prev_until_ns = now + 3 * c.pto(.application);
            s.rx = keys;
            s.tx = s.tx.?.updated();
            c.key_phase ^= 1;
            c.phase_from = pn;
        }
        const eliciting = try c.frames(level, plain, now, delivered);
        s.received.add(pn, pn);
        if (s.largest_rx == null or pn > s.largest_rx.?) {
            s.largest_rx = pn;
            s.largest_rx_ns = now;
        }
        if (eliciting) {
            s.unacked += 1;
            if (s.ack_by_ns == null) s.ack_by_ns = now + max_ack_delay_ns;
        }
    }

    fn frames(c: *Conn, level: Level, payload: []u8, now: i64, delivered: *std.ArrayList([]u8)) Error!bool {
        if (payload.len == 0) return error.ProtocolViolation;
        var r: Reader = .{ .rest = payload };
        var eliciting = false;
        const app = level == .application;
        while (r.rest.len > 0) {
            const t = r.varintSized() catch return error.FrameEncodingError;
            if (t.len != varintLen(t.value)) return error.ProtocolViolation;
            const kind = t.value;
            if (kind != 0x00 and !(kind >= 0x02 and kind <= 0x03) and kind != 0x1c) eliciting = true;
            if (!app and !(kind <= 0x03 or kind == 0x06 or kind == 0x1c)) return error.ProtocolViolation;
            c.frame(level, kind, &r, now, delivered) catch |err| switch (err) {
                error.Short => return error.FrameEncodingError,
                else => |e| return e,
            };
            if (c.ended != null) return eliciting;
        }
        return eliciting;
    }

    fn frame(c: *Conn, level: Level, kind: u64, r: *Reader, now: i64, delivered: *std.ArrayList([]u8)) (Error || error{Short})!void {
        switch (kind) {
            0x00 => while (r.rest.len > 0 and r.rest[0] == 0) {
                r.rest = r.rest[1..];
            },
            0x01 => {},
            0x02, 0x03 => try c.ack(level, kind == 0x03, r, now),
            0x04 => {
                const id = try r.varint();
                _ = try r.varint();
                const final = try r.varint();
                const st = try c.ours(id) orelse return;
                if (st.final) |f| if (f != final) return error.FinalSizeError;
                if (final < st.top) return error.FinalSizeError;
                try c.received(st, final);
                st.final = final;
                if (st.done) return;
                st.done = true;
                try c.emit(.{ .refused = id });
                c.abandonSend(st);
            },
            // RFC 9250 §4.3.3: STOP_SENDING toward the client is a protocol error.
            0x05 => {
                _ = try r.varint();
                _ = try r.varint();
                return error.DoqProtocolError;
            },
            0x06 => {
                const off = try r.varint();
                const data = try r.bytes(try r.varint());
                if (off + data.len > max_varint) return error.FrameEncodingError;
                try c.cryptoData(level, off, data);
            },
            0x07 => {
                const n = try r.varint();
                if (n == 0) return error.FrameEncodingError;
                _ = try r.bytes(n);
            },
            0x08...0x0f => {
                const id = try r.varint();
                const off = if (kind & 0x04 != 0) try r.varint() else 0;
                const data = if (kind & 0x02 != 0) try r.bytes(try r.varint()) else try r.bytes(r.rest.len);
                if (off + data.len > max_varint) return error.FrameEncodingError;
                try c.streamData(id, off, data, kind & 0x01 != 0, delivered);
            },
            0x10 => c.peer.max_data = @max(c.peer.max_data, try r.varint()),
            0x11 => {
                const id = try r.varint();
                const max = try r.varint();
                const st = try c.ours(id) orelse return;
                st.credit = @max(st.credit, max);
            },
            0x12, 0x13 => {
                const max = try r.varint();
                if (max > 1 << 60) return error.FrameEncodingError;
                if (kind == 0x13 or max <= c.peer.max_streams) return;
                c.peer.max_streams = max;
                if (c.blocked) {
                    c.blocked = false;
                    try c.emit(.room);
                }
            },
            0x14 => _ = try r.varint(),
            0x15 => {
                _ = try r.varint();
                _ = try r.varint();
            },
            0x16, 0x17 => if (try r.varint() > 1 << 60) return error.FrameEncodingError,
            0x18 => try c.newCid(r),
            0x19 => return error.ProtocolViolation,
            0x1a => c.path_response = (try r.bytes(8))[0..8].*,
            0x1b => return error.ProtocolViolation,
            0x1c, 0x1d => {
                const code = try r.varint();
                if (kind == 0x1c) _ = try r.varint();
                _ = try r.bytes(try r.varint());
                // No error, or DOQ_EXCESSIVE_LOAD: neither counts against the server.
                const quiet = code == 0 or (kind == 0x1d and code == 0x4);
                return c.end(if (quiet) .closed else .failed, if (quiet) "connection close" else "connection close with error");
            },
            0x1e => switch (c.phase) {
                .hello, .handshake => return error.ProtocolViolation,
                .established => {
                    c.phase = .confirmed;
                    c.discard(.handshake);
                },
                .confirmed => {},
            },
            else => return error.FrameEncodingError,
        }
    }

    fn ours(c: *Conn, id: u64) Error!?*Stream {
        if (id & 1 == 1) return error.StreamLimitError;
        if (id & 2 == 2 or id / 4 >= c.next_n) return error.StreamStateError;
        return c.stream(id);
    }

    fn received(c: *Conn, st: *Stream, top: u64) Error!void {
        if (top > stream_window) return error.FlowControlError;
        if (top <= st.top) return;
        c.rx_data += top - st.top;
        st.top = top;
        if (c.rx_data > c.rx_max) return error.FlowControlError;
    }

    fn streamData(c: *Conn, id: u64, off: u64, data: []u8, fin: bool, delivered: *std.ArrayList([]u8)) Error!void {
        const st = try c.ours(id) orelse return;
        const end_at = off + data.len;
        if (st.final) |f| {
            if (end_at > f or (fin and end_at != f)) return error.FinalSizeError;
        } else if (fin and end_at < st.top) return error.FinalSizeError;
        try c.received(st, end_at);
        if (fin) st.final = end_at;
        if (st.done) return;
        if (off == 0 and fin and st.buf.len == 0) return c.deliver(st, data);
        if (st.buf.len == 0) {
            const size: usize = if (off == 0 and data.len >= 2) 2 + @as(usize, mem.readInt(u16, data[0..2], .big)) else stream_window;
            st.buf = try c.gpa.alloc(u8, size);
        }
        if (end_at > st.buf.len) return error.DoqProtocolError;
        if (data.len > 0) {
            @memcpy(st.buf[@intCast(off)..][0..data.len], data);
            st.got.add(off, end_at - 1);
        }
        const f = st.final orelse return;
        if (!st.got.covers(f)) return;
        try delivered.append(c.gpa, st.buf);
        const whole = st.buf[0..@intCast(f)];
        st.buf = &.{};
        try c.deliver(st, whole);
    }

    /// RFC 9250 §4.3.3: a nonzero message id or a TCP keepalive option is a
    /// fatal error.
    fn deliver(c: *Conn, st: *Stream, data: []u8) Error!void {
        if (data.len < 2 + 12 or mem.readInt(u16, data[0..2], .big) != data.len - 2) return error.DoqProtocolError;
        const msg = data[2..];
        if (mem.readInt(u16, msg[0..2], .big) != 0) return error.DoqProtocolError;
        if (dns.hasOption(msg, dns.edns_opt_tcp_keepalive) catch false) return error.DoqProtocolError;
        st.done = true;
        if (st.send == .due) c.owe_sends -= 1;
        st.send = .none;
        try c.emit(.{ .reply = .{ .id = st.id(), .bytes = msg } });
        c.consume(st);
    }

    fn cryptoData(c: *Conn, level: Level, off: u64, data: []const u8) Error!void {
        const in = &c.space(level).in;
        const end_at = off + data.len;
        if (end_at <= in.at) return;
        if (end_at - in.at > 8192) return error.CryptoBufferExceeded;
        if (off > in.at) {
            const w = in.window orelse blk: {
                const w = try c.gpa.create(CryptoIn.Window);
                w.have = .empty;
                in.window = w;
                break :blk w;
            };
            for (data, off..) |b, at| {
                w.bytes[at % 8192] = b;
                w.have.set(at % 8192);
            }
            return;
        }
        try c.tlsIn(level, data[@intCast(in.at - off)..]);
        in.at = end_at;
        if (in.window) |w| {
            while (w.have.isSet(in.at % 8192)) {
                const from = in.at;
                while (w.have.isSet(in.at % 8192)) {
                    w.have.unset(in.at % 8192);
                    in.at += 1;
                    if (in.at % 8192 == 0) break;
                }
                try c.tlsIn(level, w.bytes[from % 8192 ..][0..@intCast(in.at - from)]);
            }
        }
    }

    fn tlsIn(c: *Conn, level: Level, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        const expected: Level = switch (c.phase) {
            .hello => .initial,
            .handshake => .handshake,
            .established, .confirmed => .application,
        };
        if (level != expected) return error.ProtocolViolation;
        if (level == .application) return c.postHandshake(bytes);
        const h = c.hs.?;
        switch (try h.read(bytes)) {
            .more => {},
            .handshake => |secrets| {
                const s = c.space(.handshake);
                s.tx = .of(&secrets.client);
                s.rx = .of(&secrets.server);
                c.phase = .handshake;
            },
            .done => |*done| {
                try c.adopt(try Params.read(h.peerParams()));
                const flight = done.flight();
                @memcpy(c.finished[0..flight.len], flight);
                c.space(.handshake).out.set(c.finished[0..flight.len]);
                const s = c.space(.application);
                s.tx = .of(&done.application.client);
                s.rx = .of(&done.application.server);
                c.phase = .established;
                c.dropHandshake();
                try c.emit(.established);
            },
        }
    }

    /// RFC 9001 §6: a TLS KeyUpdate message is an error in QUIC.
    fn postHandshake(c: *Conn, bytes: []const u8) Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            if (!c.post.inBody() and !c.post.header(&rest)) return;
            if (c.post.kind() != .new_session_ticket) return error.UnexpectedMessage;
            _ = c.post.body(&rest);
            if (c.post.left > 0) return;
            c.post.head_len = 0;
        }
    }

    fn adopt(c: *Conn, p: Params) Error!void {
        if (!p.original_dcid.?.eql(c.odcid.slice())) return error.TransportParameterError;
        if (!p.initial_scid.?.eql(c.server_scid.?.slice())) return error.TransportParameterError;
        if ((p.retry_scid == null) != (c.retry_scid == null)) return error.TransportParameterError;
        if (p.retry_scid) |r| if (!r.eql(c.retry_scid.?.slice())) return error.TransportParameterError;
        if (c.server_scid.?.len == 0 and p.preferred != null) return error.TransportParameterError;
        c.peer = p;
        c.cids[0].?.token = p.reset_token;
        if (p.preferred) |pref| c.cids[1] = .{ .seq = 1, .cid = pref.cid, .token = pref.token };
        if (p.idle_ms != 0) c.idle_ns = @min(c.idle_ns, @as(i64, @intCast(@min(p.idle_ms, idle_ms))) * std.time.ns_per_ms);
    }

    fn newCid(c: *Conn, r: *Reader) (Error || error{Short})!void {
        const seq = try r.varint();
        const prior = try r.varint();
        const len = try r.byte();
        if (len == 0 or len > 20 or prior > seq) return error.FrameEncodingError;
        const id: Cid = .of(try r.bytes(len));
        const token = (try r.bytes(16))[0..16].*;
        if (c.dcid.len == 0) return error.ProtocolViolation;
        for (c.cids) |o| if (o) |k| if (k.seq == seq) {
            if (!k.cid.eql(id.slice()) or !mem.eql(u8, &(k.token orelse token), &token)) return error.ProtocolViolation;
            return;
        };
        if (seq < c.retire_below) return c.retireCid(seq);
        c.retire_below = @max(c.retire_below, prior);
        var slot: ?usize = null;
        for (&c.cids, 0..) |*o, i| {
            if (o.*) |k| if (k.seq < c.retire_below) {
                try c.retireCid(k.seq);
                o.* = null;
            };
            if (o.* == null and slot == null) slot = i;
        }
        const at = slot orelse return error.ConnectionIdLimitError;
        c.cids[at] = .{ .seq = seq, .cid = id, .token = token };
        for (c.cids) |o| if (o) |k| if (k.cid.eql(c.dcid.slice())) return;
        c.dcid = c.cids[at].?.cid;
    }

    fn retireCid(c: *Conn, seq: u64) Error!void {
        if (c.nretiring == c.retiring.len) return error.ConnectionIdLimitError;
        c.retiring[c.nretiring] = .{ .seq = seq, .owed = .due };
        c.nretiring += 1;
    }

    fn ack(c: *Conn, level: Level, ecn: bool, r: *Reader, now: i64) (Error || error{Short})!void {
        const s = c.space(level);
        const largest = try r.varint();
        const delay_raw = try r.varint();
        const count = try r.varint();
        const first = try r.varint();
        if (largest >= s.next_pn) return error.ProtocolViolation;
        if (first > largest) return error.FrameEncodingError;
        var hi = largest;
        var lo = largest - first;
        var i: usize = s.sent_len;
        var newest_acked: ?*Sent = null;
        var any_eliciting = false;
        var ranges_left = count;
        while (true) {
            while (i > 0) {
                const p = s.sentAt(i - 1);
                if (p.pn < lo) break;
                i -= 1;
                if (p.pn > hi or p.state != .flying) continue;
                s.land(p, .acked);
                if (newest_acked == null) newest_acked = p;
                any_eliciting = any_eliciting or p.ack_eliciting;
                c.onAcked(level, p);
            }
            if (ranges_left == 0) break;
            ranges_left -= 1;
            const gap = try r.varint();
            const len = try r.varint();
            if (gap + 2 > lo or len > lo - gap - 2) return error.FrameEncodingError;
            hi = lo - gap - 2;
            lo = hi - len;
        }
        if (ecn) for (0..3) |_| {
            _ = try r.varint();
        };
        s.largest_acked = @max(s.largest_acked orelse 0, largest);
        const newest = newest_acked orelse return;
        if (level == .handshake) c.handshake_acked = true;
        if (newest.pn == largest and any_eliciting) {
            const delay: i64 = @intCast(@min(delay_raw << c.peer.ack_delay_exponent, std.math.maxInt(i32)) * std.time.ns_per_us);
            c.sampleRtt(now - newest.sent_ns, if (level == .application) delay else 0, now);
        }
        try c.detectLoss(level, now);
        if (c.handshake_acked or c.phase == .confirmed) c.pto_count = 0;
        c.trim(level);
    }

    fn sampleRtt(c: *Conn, latest: i64, ack_delay: i64, now: i64) void {
        c.latest_rtt = latest;
        if (c.first_rtt_ns == null) {
            c.first_rtt_ns = now;
            c.min_rtt = latest;
            c.smoothed_rtt = latest;
            c.rttvar = @divTrunc(latest, 2);
            return;
        }
        c.min_rtt = @min(c.min_rtt, latest);
        const delay = if (c.phase == .confirmed) @min(ack_delay, c.peer.max_ack_delay_ns) else ack_delay;
        const adjusted = if (latest >= c.min_rtt + delay) latest - delay else latest;
        c.rttvar = @divTrunc(3 * c.rttvar + @as(i64, @intCast(@abs(c.smoothed_rtt - adjusted))), 4);
        c.smoothed_rtt = @divTrunc(7 * c.smoothed_rtt + adjusted, 8);
    }

    fn onAcked(c: *Conn, level: Level, p: *const Sent) void {
        c.settle(level, p.pn, p.streams, true);
        if (!p.in_flight) return;
        c.in_flight -= p.bytes;
        if (!p.limited) return;
        if (c.recovery_ns) |r| if (p.sent_ns <= r) return;
        if (c.cwnd < c.ssthresh) c.cwnd += p.bytes else c.cwnd += max_datagram * @as(u64, p.bytes) / c.cwnd;
    }

    fn settle(c: *Conn, level: Level, pn: u64, window: ?Span, acked: bool) void {
        const s = c.space(level);
        for (s.out.all()) |*ch| _ = if (acked) ch.owed.acked(pn) else ch.owed.lost(pn);
        if (level != .application) return;
        const pairs = .{ &c.max_data, &c.streams_blocked, &c.data_blocked, &c.ping };
        inline for (pairs) |o| _ = if (acked) o.acked(pn) else o.lost(pn);
        for (c.retiring[0..c.nretiring]) |*x| _ = if (acked) x.owed.acked(pn) else x.owed.lost(pn);
        var i: usize = 0;
        while (i < c.nretiring) {
            if (c.retiring[i].owed == .none) {
                c.retiring[i] = c.retiring[c.nretiring - 1];
                c.nretiring -= 1;
            } else i += 1;
        }
        const w = window orelse return;
        const from = @max(w.from, c.streams_from);
        const to = @min(w.to + 1, c.streams_from + c.streams.items.len);
        if (from >= to) return;
        for (c.streams.items[@intCast(from - c.streams_from)..@intCast(to - c.streams_from)]) |o| {
            const st = o orelse continue;
            if (acked) {
                const a = st.send.acked(pn);
                const b = st.stop.acked(pn);
                if (a or b or st.reset.acked(pn)) c.reap(st);
            } else {
                if (st.send.lost(pn)) c.owe_sends += 1;
                _ = st.stop.lost(pn);
                _ = st.reset.lost(pn);
            }
        }
        if (acked) c.compact();
    }

    fn detectLoss(c: *Conn, level: Level, now: i64) !void {
        const s = c.space(level);
        const largest = s.largest_acked orelse return;
        s.loss_ns = null;
        const delay = @max(@divTrunc(9 * @max(c.latest_rtt, c.smoothed_rtt), 8), granularity_ns);
        const lost_before = now - delay;
        var last_loss_ns: ?i64 = null;
        var run_from: ?i64 = null;
        var persistent = false;
        const span = c.pto(.application) * persistent_threshold;
        for (0..s.sent_len) |i| {
            const p = s.sentAt(i);
            if (p.pn > largest) break;
            if (p.state == .acked) {
                if (p.ack_eliciting) run_from = null;
                continue;
            }
            if (p.state == .lost) continue;
            if (p.sent_ns > lost_before and largest < p.pn + packet_threshold) {
                const at = p.sent_ns + delay;
                s.loss_ns = @min(s.loss_ns orelse at, at);
                continue;
            }
            s.land(p, .lost);
            if (p.in_flight) {
                c.in_flight -= p.bytes;
                last_loss_ns = @max(last_loss_ns orelse p.sent_ns, p.sent_ns);
            }
            c.settle(level, p.pn, p.streams, false);
            if (!p.ack_eliciting or c.first_rtt_ns == null or p.sent_ns <= c.first_rtt_ns.?) continue;
            const from = run_from orelse {
                run_from = p.sent_ns;
                continue;
            };
            if (p.sent_ns - from > span) persistent = true;
        }
        if (last_loss_ns) |sent| c.congested(sent, now);
        if (persistent) {
            c.cwnd = minimum_window;
            c.recovery_ns = null;
        }
        c.trim(level);
    }

    fn congested(c: *Conn, sent_ns: i64, now: i64) void {
        if (c.recovery_ns) |r| if (sent_ns <= r) return;
        c.recovery_ns = now;
        c.ssthresh = c.cwnd / 2;
        c.cwnd = @max(c.ssthresh, minimum_window);
    }

    fn trim(c: *Conn, level: Level) void {
        const s = c.space(level);
        while (s.sent_len > 0 and s.sentAt(0).state != .flying) {
            s.sent_head = (s.sent_head + 1) % s.sent.len;
            s.sent_len -= 1;
        }
    }

    fn forget(c: *Conn, level: Level) void {
        const s = c.space(level);
        for (0..s.sent_len) |i| {
            const p = s.sentAt(i);
            if (p.state == .flying and p.in_flight) c.in_flight -= p.bytes;
        }
        s.sent_len = 0;
        s.eliciting_flying = 0;
        s.loss_ns = null;
        s.last_eliciting_ns = null;
        s.probes = 0;
        c.pto_count = 0;
    }

    fn discard(c: *Conn, level: Level) void {
        const s = c.space(level);
        if (s.tx == null) return;
        c.forget(level);
        s.tx = null;
        s.rx = null;
        s.unacked = 0;
        s.ack_by_ns = null;
        s.out = .{};
        if (s.in.window) |w| c.gpa.destroy(w);
        s.in.window = null;
    }

    const Timer = struct { at: i64, level: Level };

    fn pto(c: *const Conn, level: Level) i64 {
        var d = c.smoothed_rtt + @max(4 * c.rttvar, granularity_ns);
        if (level == .application) d += c.peer.max_ack_delay_ns;
        return d;
    }

    fn lossTime(c: *const Conn) ?Timer {
        var best: ?Timer = null;
        for (c.spaces, 0..) |s, i| if (s.loss_ns) |t| {
            if (best == null or t < best.?.at) best = .{ .at = t, .level = @fromBackingInt(@intCast(i)) };
        };
        return best;
    }

    fn ptoTime(c: *const Conn, now: i64) ?Timer {
        const backoff = @as(i64, 1) << c.pto_count;
        var flying = false;
        for (c.spaces) |s| flying = flying or s.eliciting();
        if (!flying) {
            if (c.handshake_acked or c.phase == .confirmed) return null;
            const level: Level = if (c.spaces[@backingInt(Level.handshake)].tx != null) .handshake else .initial;
            return .{ .at = now + c.pto(.initial) * backoff, .level = level };
        }
        var best: ?Timer = null;
        for ([_]Level{ .initial, .handshake, .application }) |l| {
            const s = &c.spaces[@backingInt(l)];
            if (!s.eliciting()) continue;
            if (l == .application and c.phase != .confirmed) break;
            const at = s.last_eliciting_ns.? + c.pto(l) * backoff;
            if (best == null or at < best.?.at) best = .{ .at = at, .level = l };
        }
        return best;
    }

    pub fn due(c: *const Conn, now: i64) ?i64 {
        if (c.ended != null) return null;
        var at: i64 = c.idleAt();
        if (c.lossTime()) |l| at = @min(at, l.at) else if (c.ptoTime(now)) |p| at = @min(at, p.at);
        const app = &c.spaces[@backingInt(Level.application)];
        if (app.ack_by_ns) |t| if (app.unacked > 0) {
            at = @min(at, t);
        };
        if (c.prev_rx != null) at = @min(at, c.prev_until_ns);
        return at;
    }

    fn idleAt(c: *const Conn) i64 {
        return c.idle_from_ns + @max(c.idle_ns, 3 * c.pto(.application));
    }

    pub fn fire(c: *Conn, now: i64) !void {
        if (c.ended != null) return;
        if (now >= c.idleAt()) return c.end(.closed, "idle");
        if (c.prev_rx != null and now >= c.prev_until_ns) {
            crypto.secureZero(u8, mem.asBytes(&c.prev_rx.?));
            c.prev_rx = null;
        }
        if (c.lossTime()) |l| {
            if (now >= l.at) try c.detectLoss(l.level, now);
            return;
        }
        const p = c.ptoTime(now) orelse return;
        if (now < p.at) return;
        const s = c.space(p.level);
        s.probes = 2;
        for (s.out.all()) |*ch| if (ch.owed == .flying) {
            ch.owed = .due;
        };
        if (p.level == .application) for (c.streams.items) |o| if (o) |st| if (st.send == .flying) {
            st.send = .due;
            c.owe_sends += 1;
            break;
        };
        c.pto_count +|= 1;
    }

    pub fn output(c: *Conn, buf: *[max_datagram]u8, now: i64) ?[]u8 {
        if (c.ended != null) return null;
        var plans: [3]Plan = undefined;
        var nplans: usize = 0;
        var used: usize = 0;
        var initial = false;
        var stream_carried = false;
        for ([_]Level{ .initial, .handshake, .application }) |l| {
            const s = c.space(l);
            if (s.tx == null) continue;
            const head = c.headLen(l, s);
            if (used + head + 16 + 8 > max_datagram) break;
            var p: Plan = .{ .level = l, .pn = s.next_pn, .pn_len = pnLen(s.next_pn, s.largest_acked), .head = head };
            var w: Writer = .{ .buf = p.body[0 .. max_datagram - used - head - 16] };
            if (!c.fill(l, &w, now, &p)) continue;
            if (p.acks) {
                s.unacked = 0;
                s.ack_by_ns = null;
            }
            p.len = w.at;
            used += head + w.at + 16;
            if (l == .initial) initial = true;
            if (p.asks) stream_carried = true;
            plans[nplans] = p;
            nplans += 1;
        }
        if (nplans == 0) return null;
        const last = &plans[nplans - 1];
        // RFC 9000 §14.1 and RFC 9250 §5.4: a datagram with an Initial or a
        // question is padded to the full 1200 bytes.
        var pad = if (initial or stream_carried) max_datagram - used else 0;
        if (last.pn_len + last.len + pad < 4) pad = 4 - last.pn_len - last.len;
        @memset(last.body[last.len..][0..pad], 0);
        last.len += pad;
        if (pad > 0) last.in_flight = true;
        var at: usize = 0;
        for (plans[0..nplans]) |*p| {
            const n = c.seal(p, buf[at..], now);
            at += n;
        }
        return buf[0..at];
    }

    const Plan = struct {
        level: Level,
        pn: u64,
        pn_len: usize,
        head: usize,
        body: [max_datagram]u8 = undefined,
        len: usize = 0,
        acks: bool = false,
        eliciting: bool = false,
        in_flight: bool = false,
        asks: bool = false,
        streams: ?Span = null,
    };

    fn headLen(c: *const Conn, l: Level, s: *const Space) usize {
        const pn_len = pnLen(s.next_pn, s.largest_acked);
        if (l == .application) return 1 + c.dcid.len + pn_len;
        var n: usize = 1 + 4 + 1 + c.dcid.len + 1 + 2 + pn_len;
        if (l == .initial) n += varintLen(c.token.len) + c.token.len;
        return n;
    }

    fn fill(c: *Conn, l: Level, w: *Writer, now: i64, p: *Plan) bool {
        const s = c.space(l);
        if (s.unacked > 0 and w.room() >= 64) {
            writeAck(s, w, now);
            p.acks = true;
        }
        const wanted = s.ackWanted(l, now);
        const room = s.sent_len < s.sent.len and (s.probes > 0 or c.in_flight + max_datagram <= c.cwnd);
        if (room) {
            for (s.out.all(), 0..) |*ch, i| {
                if (ch.owed != .due) continue;
                const over = 1 + varintLen(ch.off) + varintLen(ch.len);
                if (w.room() < over + 1) break;
                if (over + ch.len > w.room()) {
                    if (s.out.n == s.out.chunks.len) break;
                    const take: u32 = @intCast(w.room() - over);
                    mem.copyBackwards(@TypeOf(ch.*), s.out.chunks[i + 2 .. s.out.n + 1], s.out.chunks[i + 1 .. s.out.n]);
                    s.out.chunks[i + 1] = .{ .off = ch.off + take, .len = ch.len - take, .owed = .due };
                    s.out.n += 1;
                    ch.len = take;
                }
                w.byte(0x06);
                w.varint(ch.off);
                w.varint(ch.len);
                w.put(s.out.data[ch.off..][0..ch.len]);
                ch.owed = .{ .flying = p.pn };
                p.eliciting = true;
            }
            if (l == .application) c.fillApp(w, p);
            if (s.probes > 0 and !p.eliciting and w.room() >= 1) {
                w.byte(0x01);
                p.eliciting = true;
            }
        }
        if (s.probes > 0 and p.eliciting) s.probes -= 1;
        if (p.eliciting) p.in_flight = true;
        return wanted or p.eliciting;
    }

    fn fillApp(c: *Conn, w: *Writer, p: *Plan) void {
        if (c.path_response) |data| if (w.room() >= 9) {
            w.byte(0x1b);
            w.put(&data);
            c.path_response = null;
            p.eliciting = true;
        };
        if (c.max_data == .due and w.room() >= 9) {
            w.byte(0x10);
            w.varint(c.rx_max);
            c.max_data = .{ .flying = p.pn };
            p.eliciting = true;
        }
        if (c.streams_blocked == .due and w.room() >= 9) {
            if (c.blocked) {
                w.byte(0x16);
                w.varint(c.peer.max_streams);
                c.streams_blocked = .{ .flying = p.pn };
                p.eliciting = true;
            } else c.streams_blocked = .none;
        }
        for (c.retiring[0..c.nretiring]) |*x| if (x.owed == .due and w.room() >= 9) {
            w.byte(0x19);
            w.varint(x.seq);
            x.owed = .{ .flying = p.pn };
            p.eliciting = true;
        };
        for (c.streams.items) |o| {
            const st = o orelse continue;
            if (st.stop == .due and w.room() >= 17) {
                w.byte(0x05);
                w.varint(st.id());
                w.varint(doq_request_cancelled);
                st.stop = .{ .flying = p.pn };
                p.eliciting = true;
                Span.widen(&p.streams, st.n);
            }
            if (st.reset == .due and w.room() >= 25) {
                w.byte(0x04);
                w.varint(st.id());
                w.varint(doq_request_cancelled);
                w.varint(if (st.went) st.dataLen() else 0);
                st.reset = .{ .flying = p.pn };
                p.eliciting = true;
                Span.widen(&p.streams, st.n);
            }
        }
        if (c.owe_sends > 0) {
            for (c.streams.items) |o| {
                const st = o orelse continue;
                if (st.send != .due) continue;
                const n = st.dataLen();
                if (st.frameLen() > w.room()) continue;
                const fresh = if (st.went) 0 else n;
                if (n > st.credit or c.tx_data + fresh > c.peer.max_data) {
                    if (c.tx_data + fresh > c.peer.max_data and c.data_blocked == .none) c.data_blocked = .due;
                    continue;
                }
                st.write(w);
                c.tx_data += fresh;
                st.went = true;
                st.send = .{ .flying = p.pn };
                c.owe_sends -= 1;
                p.eliciting = true;
                p.asks = true;
                Span.widen(&p.streams, st.n);
                if (c.owe_sends == 0) break;
            }
        }
        if (c.data_blocked == .due and w.room() >= 9) {
            w.byte(0x14);
            w.varint(c.peer.max_data);
            c.data_blocked = .{ .flying = p.pn };
            p.eliciting = true;
        }
    }

    fn writeAck(s: *const Space, w: *Writer, now: i64) void {
        const r = &s.received;
        if (r.n == 0) return;
        const delay: u64 = @intCast(@max(now - s.largest_rx_ns, 0));
        w.byte(0x02);
        w.varint(r.hi[0]);
        w.varint((delay / std.time.ns_per_us) >> ack_delay_exponent);
        var n: usize = 1;
        var need: usize = 0;
        while (n < r.n) : (n += 1) {
            need += varintLen(r.lo[n - 1] - r.hi[n] - 2) + varintLen(r.hi[n] - r.lo[n]);
            if (need + 24 > w.room()) break;
        }
        w.varint(n - 1);
        w.varint(r.hi[0] - r.lo[0]);
        for (1..n) |i| {
            w.varint(r.lo[i - 1] - r.hi[i] - 2);
            w.varint(r.hi[i] - r.lo[i]);
        }
    }

    fn seal(c: *Conn, p: *Plan, out: []u8, now: i64) usize {
        const s = c.space(p.level);
        var w: Writer = .{ .buf = out };
        const pn_bits: u8 = @intCast(p.pn_len - 1);
        if (p.level == .application) {
            w.byte(0x40 | @as(u8, c.key_phase) << 2 | pn_bits);
            w.put(c.dcid.slice());
        } else {
            const kind: u8 = if (p.level == .initial) 0 else 2;
            w.byte(0xc0 | kind << 4 | pn_bits);
            w.put(&std.mem.toBytes(mem.nativeToBig(u32, version)));
            w.byte(c.dcid.len);
            w.put(c.dcid.slice());
            w.byte(0);
            if (p.level == .initial) {
                w.varint(c.token.len);
                w.put(c.token);
            }
            const length = p.pn_len + p.len + 16;
            mem.writeInt(u16, w.buf[w.at..][0..2], @as(u16, @intCast(length)) | 0x4000, .big);
            w.at += 2;
        }
        var pn_be: [4]u8 = undefined;
        mem.writeInt(u32, &pn_be, @truncate(p.pn), .big);
        w.put(pn_be[4 - p.pn_len ..]);
        const head = w.at;
        w.put(p.body[0..p.len]);
        w.at += 16;
        const keys = s.tx.?;
        keys.seal(out[0..w.at], head, p.pn_len, p.pn);
        s.next_pn += 1;
        if (p.level == .application) c.sealed += 1;
        // With no room in the ring only a padded ACK reaches here (`fill` holds
        // the rest back); it goes unremembered, as it carries nothing owed.
        if ((p.eliciting or p.in_flight) and s.sent_len < s.sent.len) {
            s.sentAt(s.sent_len).* = .{
                .pn = p.pn,
                .sent_ns = now,
                .bytes = @intCast(w.at),
                .ack_eliciting = p.eliciting,
                .in_flight = p.in_flight,
                .limited = 2 * (c.in_flight + w.at) >= c.cwnd,
                .streams = p.streams,
            };
            s.sent_len += 1;
            if (p.eliciting) s.eliciting_flying += 1;
            if (p.in_flight) c.in_flight += w.at;
            if (p.eliciting) {
                s.last_eliciting_ns = now;
                if (!c.eliciting_since_heard) {
                    c.eliciting_since_heard = true;
                    c.idle_from_ns = now;
                }
            }
        }
        if (p.level == .handshake) c.discard(.initial);
        return w.at;
    }

    pub fn closing(c: *Conn, buf: *[max_datagram]u8) ?[]u8 {
        const why: Close = c.close orelse blk: {
            if (c.ended != null or !c.established()) return null;
            break :blk .{ .app = true, .code = doq_no_error };
        };
        c.close = null;
        var at: usize = 0;
        for ([_]Level{ .initial, .handshake, .application }) |l| {
            const s = c.space(l);
            if (s.tx == null) continue;
            var p: Plan = .{ .level = l, .pn = s.next_pn, .pn_len = pnLen(s.next_pn, s.largest_acked), .head = c.headLen(l, s) };
            if (at + p.head + 16 + 32 > max_datagram) break;
            var w: Writer = .{ .buf = &p.body };
            if (why.app and l == .application) {
                w.byte(0x1d);
                w.varint(why.code);
            } else {
                w.byte(0x1c);
                w.varint(if (why.app) 0xc else why.code);
                w.varint(why.frame);
            }
            w.varint(0);
            p.len = w.at;
            const want = if (l == .initial) max_datagram - at - p.head - 16 else 4 -| p.pn_len;
            if (p.len < want) {
                @memset(p.body[p.len..want], 0);
                p.len = want;
            }
            at += c.seal(&p, buf[at..], 0);
            if (l == .initial) break;
        }
        return if (at == 0) null else buf[0..at];
    }

    pub fn spent(c: *const Conn, now: i64) bool {
        if (c.sealed >= packets_per_key) return true;
        return c.established() and now + c.pto(.application) >= c.idleAt();
    }
};

const hex = tls13.hex;

const testing = std.testing;

test "RFC 9001 A.1: Initial keys from the client's connection id" {
    const keys = initialKeys(&hex("8394c8f03e515708"));
    try testing.expectEqual(hex("1f369613dd76d5467730efcbe3b1a22d"), keys.client.key);
    try testing.expectEqual(hex("fa044b2f42a3fd3b46fb255c"), keys.client.iv);
    try testing.expectEqual(hex("9f50449e04a0e810283a1e9933adedd2"), keys.client.hp);
    try testing.expectEqual(hex("cf3a5331653c364c88f0f379b6067e37"), keys.server.key);
    try testing.expectEqual(hex("0ac1493ca1905853b0bba03e"), keys.server.iv);
    try testing.expectEqual(hex("c206b8d9b9f0f37644430b490eeaa314"), keys.server.hp);
}

test "RFC 9001 A.3: the server's Initial opens to its ACK and CRYPTO" {
    var packet = hex("cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" ++
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" ++
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" ++
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" ++
        "2158407dd074ee");
    const keys = initialKeys(&hex("8394c8f03e515708")).server;
    const pn_at = 1 + 4 + 1 + 0 + 1 + 8 + 1 + 2;
    const h = keys.unmask(&packet, pn_at);
    try testing.expectEqual(1, decodePn(null, h.truncated, h.len));
    const plain = keys.open(&packet, pn_at + h.len, 1).?;
    try testing.expectEqualSlices(u8, &hex("02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
        "020304"), plain);
}

test "RFC 9001 A.2: the client's Initial seals as in the sample" {
    const header = hex("c300000001088394c8f03e5157080000449e00000002");
    var packet: [1200]u8 = @splat(0);
    @memcpy(packet[0..header.len], &header);
    const payload = hex("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" ++
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" ++
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" ++
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" ++
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" ++
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100" ++
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" ++
        "75300901100f088394c8f03e51570806048000ffff");
    @memcpy(packet[header.len..][0..payload.len], &payload);
    const keys = initialKeys(&hex("8394c8f03e515708")).client;
    keys.seal(&packet, header.len, 4, 2);
    try testing.expectEqualSlices(u8, &hex("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"), packet[0..32]);
    try testing.expectEqualSlices(u8, &hex("e221af44860018ab0856972e194cd934"), packet[1184..]);
}

test "RFC 9001 A.4: a Retry's tag proves it answers the Initial sent" {
    const retry_packet = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    try testing.expect(retryValid(&retry_packet, &hex("8394c8f03e515708")));
    try testing.expect(!retryValid(&retry_packet, &hex("8394c8f03e515709")));
}

test "RFC 9000 A.3: a truncated packet number widens to the nearest" {
    try testing.expectEqual(0xa82f9b32, decodePn(0xa82f30ea, 0x9b32, 2));
    try testing.expectEqual(0, decodePn(null, 0, 1));
}

test "ranges merge what touches and keep the highest when full" {
    var r: Ranges(3) = .{};
    r.add(5, 5);
    r.add(7, 7);
    r.add(6, 6);
    try testing.expectEqual(1, r.n);
    try testing.expectEqual(5, r.lo[0]);
    try testing.expectEqual(7, r.hi[0]);
    r.add(1, 1);
    r.add(10, 10);
    r.add(20, 20);
    try testing.expectEqual(3, r.n);
    try testing.expect(r.known(1));
    try testing.expect(r.known(0));
    try testing.expect(!r.known(2));
    try testing.expect(!r.known(8));
    try testing.expect(r.known(20));
}

test "the hello leaves as full Initials that open back to it" {
    var entropy: [tls13.entropy_len + 8]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    var c = try Conn.begin(testing.allocator, &entropy, 0);
    defer c.deinit();
    const keys = initialKeys(entropy[0..8]).client;
    var got: [tls13.max_hello]u8 = undefined;
    var have: usize = 0;
    var buf: [max_datagram]u8 = undefined;
    while (c.output(&buf, 0)) |d| {
        try testing.expectEqual(max_datagram, d.len);
        const pn_at = 1 + 4 + 1 + 8 + 1 + 1 + 2;
        try testing.expectEqual(0xc0, d[0] & 0xf0);
        const h = keys.unmask(d, pn_at);
        const plain = keys.open(d, pn_at + h.len, decodePn(null, h.truncated, h.len)).?;
        var r: Reader = .{ .rest = plain };
        try testing.expectEqual(0x06, try r.byte());
        const off = try r.varint();
        const data = try r.bytes(try r.varint());
        try testing.expectEqual(have, off);
        @memcpy(got[have..][0..data.len], data);
        have += data.len;
        for (r.rest) |b| try testing.expectEqual(0, b);
    }
    try testing.expectEqualSlices(u8, c.hello, got[0..have]);
}

test "RFC 9001 A.3: the server's Initial moves the handshake on and is acknowledged" {
    var entropy: [tls13.entropy_len + 8]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    entropy[0..8].* = hex("8394c8f03e515708");
    var c = try Conn.begin(testing.allocator, &entropy, 0);
    defer c.deinit();
    var buf: [max_datagram]u8 = undefined;
    while (c.output(&buf, 0)) |_| {}
    var packet = hex("cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" ++
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" ++
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" ++
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" ++
        "2158407dd074ee");
    var delivered: std.ArrayList([]u8) = .empty;
    defer delivered.deinit(testing.allocator);
    try c.input(&packet, std.time.ns_per_ms, &delivered);
    try testing.expectEqual(null, c.next());
    try testing.expectEqual(.handshake, c.phase);
    try testing.expectEqualSlices(u8, &hex("f067a5502a4262b5"), c.dcid.slice());
    try testing.expectEqual(std.time.ns_per_ms, c.smoothed_rtt);
    const d = c.output(&buf, std.time.ns_per_ms).?;
    try testing.expectEqual(max_datagram, d.len);
    try testing.expectEqualSlices(u8, &hex("f067a5502a4262b5"), d[6..14]);
}
