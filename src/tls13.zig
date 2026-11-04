//! A TLS 1.3 client (RFC 8446) for DNS to authoritative servers: the
//! handshake as messages in and messages out, the secrets it reaches, and
//! the records that carry both over TCP. No I/O, no allocation.

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const tls = crypto.tls;
const X25519 = crypto.dh.X25519;
const P256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const MlKem = crypto.kem.ml_kem.MLKem768;

// The one suite RFC 8446 §9.1 makes mandatory, so one hash and one cipher.
const Sha256 = crypto.hash.sha2.Sha256;
const Hkdf = crypto.kdf.hkdf.HkdfSha256;
const Hmac = crypto.auth.hmac.sha2.HmacSha256;
const Aead = crypto.aead.aes_gcm.Aes128Gcm;
const suite: u16 = @backingInt(tls.CipherSuite.AES_128_GCM_SHA256);

const secret_len = Sha256.digest_length;
pub const Secret = [secret_len]u8;
pub const Secrets = struct { client: Secret, server: Secret };

pub const Error = error{
    BadRecordMac,
    DecodeError,
    DecryptError,
    HandshakeFailure,
    IllegalParameter,
    MissingExtension,
    ProtocolVersion,
    RecordOverflow,
    UnexpectedMessage,
    UnsupportedExtension,
};

pub fn alert(err: Error) tls.Alert.Description {
    return switch (err) {
        error.BadRecordMac => .bad_record_mac,
        error.DecodeError => .decode_error,
        error.DecryptError => .decrypt_error,
        error.HandshakeFailure => .handshake_failure,
        error.IllegalParameter => .illegal_parameter,
        error.MissingExtension => .missing_extension,
        error.ProtocolVersion => .protocol_version,
        error.RecordOverflow => .record_overflow,
        error.UnexpectedMessage => .unexpected_message,
        error.UnsupportedExtension => .unsupported_extension,
    };
}

pub const Offer = struct {
    alpn: ?[]const u8,
    answerable: []const tls.ExtensionType = &.{},
};

pub const entropy_len = 32 + X25519.secret_length + P256.SecretKey.encoded_length + MlKem.seed_length;
pub const max_hello = 1536;
const max_alpn = 16;
const finished_len = 4 + Hmac.mac_length;
const empty_certificate = [_]u8{@backingInt(tls.HandshakeType.certificate)} ++ tls.int(u24, 4) ++ [_]u8{ 0, 0, 0, 0 };

/// Past this, the two messages read whole fail: ServerHello with the hybrid
/// share needs ~1.2 KiB, EncryptedExtensions what few extensions it may hold.
const max_held = 1536;

const Shares = struct {
    x25519: [X25519.secret_length]u8,
    p256: [P256.SecretKey.encoded_length]u8,
    ml_kem: [MlKem.seed_length]u8,
};

pub const Step = union(enum) {
    more,
    handshake: Secrets,
    /// The server's Finished proved: send `flight` under the client's
    /// handshake secret, and everything after under these.
    done: Done,

    pub const Done = struct {
        application: Secrets,
        buf: [empty_certificate.len + finished_len]u8,
        len: u8,

        pub fn flight(d: *const Done) []const u8 {
            return d.buf[0..d.len];
        }
    };
};

const Stage = enum {
    server_hello,
    encrypted_extensions,
    certificate_request,
    certificate,
    certificate_verify,
    finished,
    done,

    fn expects(s: Stage) ?tls.HandshakeType {
        return switch (s) {
            .server_hello => .server_hello,
            .encrypted_extensions => .encrypted_extensions,
            .certificate_request => .certificate_request,
            .certificate => .certificate,
            .certificate_verify => .certificate_verify,
            .finished => .finished,
            .done => null,
        };
    }

    /// RFC 9539 §4.6.3.4: any certificate is accepted, so proof of holding
    /// its key proves nothing. Both go through the transcript and no further.
    fn held(s: Stage) bool {
        return switch (s) {
            .server_hello, .encrypted_extensions, .certificate_request, .finished => true,
            .certificate, .certificate_verify, .done => false,
        };
    }
};

pub const Framer = struct {
    head: [4]u8 = undefined,
    head_len: u8 = 0,
    left: u32 = 0,

    pub fn inBody(f: *const Framer) bool {
        return f.head_len == f.head.len;
    }

    pub fn header(f: *Framer, rest: *[]const u8) bool {
        const take = @min(f.head.len - f.head_len, rest.len);
        @memcpy(f.head[f.head_len..][0..take], rest.*[0..take]);
        f.head_len += @intCast(take);
        rest.* = rest.*[take..];
        if (!f.inBody()) return false;
        f.left = mem.readInt(u24, f.head[1..4], .big);
        return true;
    }

    pub fn kind(f: *const Framer) tls.HandshakeType {
        return @fromBackingInt(f.head[0]);
    }

    pub fn body(f: *Framer, rest: *[]const u8) []const u8 {
        const take = @min(f.left, rest.len);
        defer rest.* = rest.*[take..];
        f.left -= @intCast(take);
        return rest.*[0..take];
    }
};

pub const Handshake = struct {
    shares: Shares,
    offer: Offer,
    transcript: Sha256 = .init(.{}),
    stage: Stage = .server_hello,
    asked: bool = false,
    handshake_secret: Secret = undefined,
    traffic: Secrets = undefined,
    framer: Framer = .{},
    held: [max_held]u8 = undefined,
    held_len: u16 = 0,

    pub fn begin(h: *Handshake, out: *[max_hello]u8, entropy: *const [entropy_len]u8, offer: Offer) error{WeakEntropy}![]const u8 {
        const random = entropy[0..32];
        const x25519_secret = entropy[32..][0..X25519.secret_length];
        const p256_seed = entropy[32 + X25519.secret_length ..][0..P256.SecretKey.encoded_length];
        const ml_kem_seed = entropy[32 + X25519.secret_length + P256.SecretKey.encoded_length ..];
        const x25519 = X25519.recoverPublicKey(x25519_secret.*);
        const p256 = P256.KeyPair.generateDeterministic(p256_seed.*) catch return error.WeakEntropy;
        const ml_kem = MlKem.KeyPair.generateDeterministic(ml_kem_seed.*) catch return error.WeakEntropy;

        h.* = .{ .shares = .{ .x25519 = x25519_secret.*, .p256 = p256.secret_key.bytes, .ml_kem = ml_kem_seed.* }, .offer = offer };

        const fixed = tls.extension(.supported_versions, tls.array(u8, tls.ProtocolVersion, .{.tls_1_3})) ++
            tls.extension(.supported_groups, tls.array(u16, tls.NamedGroup, .{ .x25519_ml_kem768, .x25519, .secp256r1 })) ++
            // Nothing is checked against these, so the list turns no server away.
            tls.extension(.signature_algorithms, tls.array(u16, tls.SignatureScheme, .{
                .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ecdsa_secp521r1_sha512,
                .ed25519,                .ed448,                  .rsa_pss_rsae_sha256,
                .rsa_pss_rsae_sha384,    .rsa_pss_rsae_sha512,    .rsa_pss_pss_sha256,
                .rsa_pss_pss_sha384,     .rsa_pss_pss_sha512,     .rsa_pkcs1_sha256,
                .rsa_pkcs1_sha384,       .rsa_pkcs1_sha512,
            })) ++
            tls.extension(.key_share, tls.array(u16, u8, tls.int(u16, @backingInt(tls.NamedGroup.x25519_ml_kem768)) ++
                tls.array(u16, u8, ml_kem.public_key.toBytes() ++ x25519) ++
                tls.int(u16, @backingInt(tls.NamedGroup.x25519)) ++ tls.array(u16, u8, x25519) ++
                tls.int(u16, @backingInt(tls.NamedGroup.secp256r1)) ++ tls.array(u16, u8, p256.public_key.toUncompressedSec1())));

        // An empty legacy_session_id, so no middlebox compatibility mode (§D.4).
        const before = .{@backingInt(tls.HandshakeType.client_hello)} ++ [3]u8{ 0, 0, 0 } ++
            tls.int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++ random.* ++ [1]u8{0} ++
            tls.int(u16, 2) ++ tls.int(u16, suite) ++ [2]u8{ 1, 0 };

        comptime std.debug.assert(before.len + 2 + fixed.len + 7 + max_alpn <= max_hello);
        var n: usize = before.len + 2;
        @memcpy(out[0..before.len], &before);
        @memcpy(out[n..][0..fixed.len], &fixed);
        n += fixed.len;
        if (offer.alpn) |proto| {
            std.debug.assert(proto.len <= max_alpn);
            mem.writeInt(u16, out[n..][0..2], @backingInt(tls.ExtensionType.application_layer_protocol_negotiation), .big);
            mem.writeInt(u16, out[n + 2 ..][0..2], @intCast(2 + 1 + proto.len), .big);
            mem.writeInt(u16, out[n + 4 ..][0..2], @intCast(1 + proto.len), .big);
            out[n + 6] = @intCast(proto.len);
            @memcpy(out[n + 7 ..][0..proto.len], proto);
            n += 7 + proto.len;
        }
        mem.writeInt(u16, out[before.len..][0..2], @intCast(n - before.len - 2), .big);
        mem.writeInt(u24, out[1..4], @intCast(n - 4), .big);
        h.transcript.update(out[0..n]);
        return out[0..n];
    }

    pub fn read(h: *Handshake, record: []const u8) Error!Step {
        if (record.len == 0) return error.UnexpectedMessage;
        var rest = record;
        while (rest.len > 0) {
            if (!h.framer.inBody()) {
                if (!h.framer.header(&rest)) return .more;
                const kind = h.framer.kind();
                if (h.stage == .certificate_request and kind == .certificate) h.stage = .certificate;
                if (h.stage.expects() != kind) return error.UnexpectedMessage;
                if (h.stage.held()) {
                    if (h.framer.left > h.held.len) return error.DecodeError;
                } else h.transcript.update(&h.framer.head);
            }
            const piece = h.framer.body(&rest);
            if (h.stage.held()) {
                @memcpy(h.held[h.held_len..][0..piece.len], piece);
                h.held_len += @intCast(piece.len);
            } else h.transcript.update(piece);
            if (h.framer.left > 0) return .more;

            const step = try h.finish();
            h.framer.head_len = 0;
            h.held_len = 0;
            if (step != .more) {
                if (rest.len > 0) return error.UnexpectedMessage;
                return step;
            }
        }
        return .more;
    }

    fn finish(h: *Handshake) Error!Step {
        const body = h.held[0..h.held_len];
        switch (h.stage) {
            .server_hello => {
                const shared = try h.agree(body);
                h.transcript.update(&h.framer.head);
                h.transcript.update(body);
                const empty = tls.emptyHash(Sha256);
                const zero: Secret = @splat(0);
                const early = Hkdf.extract(&.{}, &zero);
                const derived = tls.hkdfExpandLabel(Hkdf, early, "derived", &empty, secret_len);
                h.handshake_secret = Hkdf.extract(&derived, shared.slice());
                const seen = h.transcriptNow();
                h.traffic = .{
                    .client = tls.hkdfExpandLabel(Hkdf, h.handshake_secret, "c hs traffic", &seen, secret_len),
                    .server = tls.hkdfExpandLabel(Hkdf, h.handshake_secret, "s hs traffic", &seen, secret_len),
                };
                crypto.secureZero(u8, mem.asBytes(&h.shares));
                h.stage = .encrypted_extensions;
                return .{ .handshake = h.traffic };
            },
            .encrypted_extensions => {
                try h.extensions(body);
                h.transcript.update(&h.framer.head);
                h.transcript.update(body);
                h.stage = .certificate_request;
                return .more;
            },
            .certificate_request => {
                if (body.len == 0 or body[0] != 0) return error.IllegalParameter;
                h.transcript.update(&h.framer.head);
                h.transcript.update(body);
                h.asked = true;
                h.stage = .certificate;
                return .more;
            },
            .certificate => {
                h.stage = .certificate_verify;
                return .more;
            },
            .certificate_verify => {
                h.stage = .finished;
                return .more;
            },
            .finished => {
                const seen = h.transcriptNow();
                if (body.len != Hmac.mac_length) return error.DecodeError;
                const key = tls.hkdfExpandLabel(Hkdf, h.traffic.server, "finished", "", Hmac.key_length);
                if (!crypto.timing_safe.eql([Hmac.mac_length]u8, tls.hmac(Hmac, &seen, key), body[0..Hmac.mac_length].*)) return error.DecryptError;
                h.transcript.update(&h.framer.head);
                h.transcript.update(body);
                const through = h.transcriptNow();
                const empty = tls.emptyHash(Sha256);
                const zero: Secret = @splat(0);
                const derived = tls.hkdfExpandLabel(Hkdf, h.handshake_secret, "derived", &empty, secret_len);
                const master = Hkdf.extract(&derived, &zero);
                var done: Step.Done = .{
                    .application = .{
                        .client = tls.hkdfExpandLabel(Hkdf, master, "c ap traffic", &through, secret_len),
                        .server = tls.hkdfExpandLabel(Hkdf, master, "s ap traffic", &through, secret_len),
                    },
                    .buf = undefined,
                    .len = 0,
                };
                if (h.asked) {
                    @memcpy(done.buf[0..empty_certificate.len], &empty_certificate);
                    done.len = empty_certificate.len;
                    h.transcript.update(&empty_certificate);
                }
                const client_key = tls.hkdfExpandLabel(Hkdf, h.traffic.client, "finished", "", Hmac.key_length);
                const verify = tls.hmac(Hmac, &h.transcriptNow(), client_key);
                done.buf[done.len..][0..finished_len].* = .{@backingInt(tls.HandshakeType.finished)} ++ tls.int(u24, Hmac.mac_length) ++ verify;
                done.len += finished_len;
                crypto.secureZero(u8, mem.asBytes(&h.handshake_secret));
                h.stage = .done;
                return .{ .done = done };
            },
            .done => unreachable,
        }
    }

    fn transcriptNow(h: *const Handshake) Secret {
        var copy = h.transcript;
        return copy.finalResult();
    }

    const Shared = struct {
        bytes: [MlKem.shared_length + X25519.shared_length]u8 = undefined,
        len: usize = 0,

        fn slice(s: *const Shared) []const u8 {
            return s.bytes[0..s.len];
        }
    };

    fn agree(h: *const Handshake, body: []const u8) Error!Shared {
        var r: Reader = .{ .rest = body };
        if (try r.int(u16) != @backingInt(tls.ProtocolVersion.tls_1_2)) return error.ProtocolVersion;
        // We offered a share for every group we named, so a retry could only
        // be for a cookie; that server stays on Do53.
        if (mem.eql(u8, try r.bytes(32), &tls.hello_retry_request_sequence)) return error.HandshakeFailure;
        if (try r.int(u8) != 0) return error.IllegalParameter;
        if (try r.int(u16) != suite) return error.IllegalParameter;
        if (try r.int(u8) != 0) return error.IllegalParameter;
        const list = try r.bytes(try r.int(u16));
        try r.end();

        var share: ?[]const u8 = null;
        var version = false;
        var exts: Extensions = .{ .list = list };
        while (try exts.next()) |e| switch (e.kind) {
            .supported_versions => {
                if (!mem.eql(u8, e.data, &tls.int(u16, @backingInt(tls.ProtocolVersion.tls_1_3)))) return error.IllegalParameter;
                version = true;
            },
            .key_share => share = e.data,
            else => return error.UnsupportedExtension,
        };
        if (!version) return error.ProtocolVersion;

        var s: Reader = .{ .rest = share orelse return error.MissingExtension };
        const group: tls.NamedGroup = @fromBackingInt(try s.int(u16));
        const key = try s.bytes(try s.int(u16));
        try s.end();
        var out: Shared = .{};
        switch (group) {
            .x25519 => {
                if (key.len != X25519.public_length) return error.IllegalParameter;
                out.bytes[0..X25519.shared_length].* = X25519.scalarmult(h.shares.x25519, key[0..X25519.public_length].*) catch return error.IllegalParameter;
                out.len = X25519.shared_length;
            },
            .secp256r1 => {
                if (key.len != P256.PublicKey.uncompressed_sec1_encoded_length) return error.IllegalParameter;
                const point = P256.PublicKey.fromSec1(key) catch return error.IllegalParameter;
                const product = point.p.mul(h.shares.p256, .big) catch return error.IllegalParameter;
                const x = product.affineCoordinates().x.toBytes(.big);
                @memcpy(out.bytes[0..x.len], &x);
                out.len = x.len;
            },
            .x25519_ml_kem768 => {
                if (key.len != MlKem.ciphertext_length + X25519.public_length) return error.IllegalParameter;
                const pair = MlKem.KeyPair.generateDeterministic(h.shares.ml_kem) catch return error.HandshakeFailure;
                const ml_kem = pair.secret_key.decaps(key[0..MlKem.ciphertext_length]) catch return error.IllegalParameter;
                const x25519 = X25519.scalarmult(h.shares.x25519, key[MlKem.ciphertext_length..][0..X25519.public_length].*) catch return error.IllegalParameter;
                out.bytes = ml_kem ++ x25519;
                out.len = out.bytes.len;
            },
            else => return error.IllegalParameter,
        }
        return out;
    }

    fn extensions(h: *const Handshake, body: []const u8) Error!void {
        var r: Reader = .{ .rest = body };
        const list = try r.bytes(try r.int(u16));
        try r.end();
        var exts: Extensions = .{ .list = list };
        while (try exts.next()) |e| switch (e.kind) {
            .application_layer_protocol_negotiation => {
                const offered = h.offer.alpn orelse return error.UnsupportedExtension;
                var names: Reader = .{ .rest = e.data };
                const name = try names.bytes(try names.int(u16));
                try names.end();
                var one: Reader = .{ .rest = name };
                const chosen = try one.bytes(try one.int(u8));
                try one.end();
                if (!mem.eql(u8, chosen, offered)) return error.IllegalParameter;
            },
            // §4.2.7: a server may tell its groups, for later hellos.
            .supported_groups => {},
            else => if (mem.findScalar(tls.ExtensionType, h.offer.answerable, e.kind) == null) return error.UnsupportedExtension,
        };
    }
};

const Reader = struct {
    rest: []const u8,

    fn bytes(r: *Reader, n: usize) Error![]const u8 {
        if (r.rest.len < n) return error.DecodeError;
        defer r.rest = r.rest[n..];
        return r.rest[0..n];
    }

    fn int(r: *Reader, comptime T: type) Error!T {
        return mem.readInt(T, (try r.bytes(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }

    fn end(r: *const Reader) Error!void {
        if (r.rest.len != 0) return error.DecodeError;
    }
};

const Extensions = struct {
    list: []const u8,
    at: usize = 0,

    fn next(x: *Extensions) Error!?struct { kind: tls.ExtensionType, data: []const u8 } {
        if (x.at == x.list.len) return null;
        var r: Reader = .{ .rest = x.list[x.at..] };
        const kind = try r.int(u16);
        const data = try r.bytes(try r.int(u16));
        var seen: Reader = .{ .rest = x.list[0..x.at] };
        while (seen.rest.len > 0) {
            if (try seen.int(u16) == kind) return error.IllegalParameter;
            _ = try seen.bytes(try seen.int(u16));
        }
        x.at = x.list.len - r.rest.len;
        return .{ .kind = @fromBackingInt(kind), .data = data };
    }
};

pub const header_len = tls.record_header_len;
pub const overhead = header_len + 1 + Aead.tag_length;

pub const Keys = struct {
    secret: Secret,
    key: [Aead.key_length]u8,
    iv: [Aead.nonce_length]u8,
    seq: u64 = 0,

    pub fn of(secret: *const Secret) Keys {
        return .{
            .secret = secret.*,
            .key = tls.hkdfExpandLabel(Hkdf, secret.*, "key", "", Aead.key_length),
            .iv = tls.hkdfExpandLabel(Hkdf, secret.*, "iv", "", Aead.nonce_length),
        };
    }

    pub fn updated(k: *const Keys) Keys {
        return .of(&tls.hkdfExpandLabel(Hkdf, k.secret, "traffic upd", "", secret_len));
    }

    fn nonce(k: *Keys) [Aead.nonce_length]u8 {
        var n = k.iv;
        const seq = mem.nativeToBig(u64, k.seq);
        for (n[n.len - 8 ..], mem.asBytes(&seq)) |*b, s| b.* ^= s;
        k.seq += 1;
        return n;
    }

    pub fn seal(k: *Keys, out: []u8, kind: tls.ContentType, plain: []const u8) []u8 {
        std.debug.assert(plain.len <= tls.max_ciphertext_inner_record_len);
        const n = plain.len + 1 + Aead.tag_length;
        const header = [1]u8{@backingInt(tls.ContentType.application_data)} ++ tls.int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++ tls.int(u16, @intCast(n));
        @memcpy(out[0..header_len], &header);
        const inner = out[header_len..][0 .. plain.len + 1];
        @memcpy(inner[0..plain.len], plain);
        inner[plain.len] = @backingInt(kind);
        Aead.encrypt(inner, out[header_len + inner.len ..][0..Aead.tag_length], inner, &header, k.nonce(), k.key);
        return out[0 .. header_len + n];
    }

    pub fn open(k: *Keys, record: []u8) Error!Opened {
        if (record.len < overhead or record[0] != @backingInt(tls.ContentType.application_data)) return error.UnexpectedMessage;
        const sealed = record[header_len..];
        const inner = sealed[0 .. sealed.len - Aead.tag_length];
        const tag = sealed[inner.len..][0..Aead.tag_length].*;
        Aead.decrypt(inner, inner, tag, record[0..header_len], k.nonce(), k.key) catch return error.BadRecordMac;
        var n = inner.len;
        while (n > 0 and inner[n - 1] == 0) n -= 1;
        if (n == 0) return error.UnexpectedMessage;
        if (n - 1 > tls.max_ciphertext_inner_record_len) return error.RecordOverflow;
        return .{ .kind = @fromBackingInt(inner[n - 1]), .data = inner[0 .. n - 1] };
    }
};

pub const Opened = struct { kind: tls.ContentType, data: []u8 };

pub fn recordLen(bytes: []const u8) Error!?usize {
    if (bytes.len < header_len) return null;
    const n = mem.readInt(u16, bytes[3..5], .big);
    if (n > tls.max_ciphertext_len) return error.RecordOverflow;
    return header_len + @as(usize, n);
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(4 * s.len);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// RFC 8448 §3, the simple 1-RTT handshake.
const trace = struct {
    const client_private = hex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
    const client_hello = hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece70000" ++
        "06130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d00" ++
        "17001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e" ++
        "435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603" ++
        "020308040805080604010501060102010402050206020202002d00020101001c00024001");
    const server_hello = hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e269280013" ++
        "0100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b0" ++
        "4e751f0f002b00020304");
    const server_flight = hex("080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000" ++
        "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b" ++
        "0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d323630" ++
        "3733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d01" ++
        "0101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826" ++
        "d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0cc" ++
        "b0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d0" ++
        "3e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304" ++
        "023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5" ++
        "b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf3" ++
        "6b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3e" ++
        "b7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4" ++
        "2b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52" ++
        "f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe" ++
        "8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be15" ++
        "2a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4de" ++
        "da4ab42c309572cb7fffee5454b78f0718");
    const server_flight_record = hex("17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40a" ++
        "a2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f5261" ++
        "34aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183e" ++
        "f3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2e" ++
        "d65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a" ++
        "8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a8" ++
        "9441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63" ++
        "d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26" ++
        "f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f1" ++
        "00d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f24" ++
        "3d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7c" ++
        "ca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe" ++
        "5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8af" ++
        "e67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614" ++
        "636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f" ++
        "60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5" ++
        "d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b");
    const client_finished = hex("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");
    const client_finished_record = hex("170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac" ++
        "98fc46deb384bd1caeacab6867d726c40546");
    const client_data = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627" ++
        "28292a2b2c2d2e2f3031");
    const client_data_record = hex("1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b39" ++
        "5bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4");
    const c_hs = hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    const s_hs = hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    const c_ap = hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
    const s_ap = hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
};

const testing = std.testing;
const record_size_limit: tls.ExtensionType = @fromBackingInt(28);

fn traced() Handshake {
    var h: Handshake = .{
        .shares = .{ .x25519 = trace.client_private, .p256 = undefined, .ml_kem = undefined },
        .offer = .{ .alpn = null, .answerable = &.{ .server_name, record_size_limit } },
    };
    h.transcript.update(&trace.client_hello);
    return h;
}

test "RFC 8448: the handshake reaches the trace's secrets and Finished" {
    var h = traced();
    const hs = (try h.read(&trace.server_hello)).handshake;
    try testing.expectEqual(trace.c_hs, hs.client);
    try testing.expectEqual(trace.s_hs, hs.server);
    const done = (try h.read(&trace.server_flight)).done;
    try testing.expectEqual(trace.c_ap, done.application.client);
    try testing.expectEqual(trace.s_ap, done.application.server);
    try testing.expectEqualSlices(u8, &trace.client_finished, done.flight());
}

test "a flight split anywhere reads the same" {
    for (1..trace.server_flight.len) |at| {
        var h = traced();
        _ = try h.read(&trace.server_hello);
        try testing.expect(try h.read(trace.server_flight[0..at]) == .more);
        const done = (try h.read(trace.server_flight[at..])).done;
        try testing.expectEqual(trace.c_ap, done.application.client);
    }
}

test "bytes after a key change in the same read are refused" {
    var h = traced();
    const both = trace.server_hello ++ trace.server_flight;
    try testing.expectError(error.UnexpectedMessage, h.read(&both));
}

test "a server's Finished that proves nothing fails" {
    var h = traced();
    _ = try h.read(&trace.server_hello);
    var flight = trace.server_flight;
    flight[flight.len - 1] ^= 1;
    try testing.expectError(error.DecryptError, h.read(&flight));
}

test "an extension nobody offered fails" {
    var h = traced();
    h.offer.answerable = &.{.server_name};
    _ = try h.read(&trace.server_hello);
    try testing.expectError(error.UnsupportedExtension, h.read(&trace.server_flight));
}

test "RFC 8448: records seal and open as in the trace" {
    var sealed: [1024]u8 = undefined;
    var out = Keys.of(&trace.c_hs);
    try testing.expectEqualSlices(u8, &trace.client_finished_record, out.seal(&sealed, .handshake, &trace.client_finished));
    var app = Keys.of(&trace.c_ap);
    try testing.expectEqualSlices(u8, &trace.client_data_record, app.seal(&sealed, .application_data, &trace.client_data));

    var in = Keys.of(&trace.s_hs);
    var record = trace.server_flight_record;
    try testing.expectEqual(record.len, (try recordLen(&record)).?);
    const opened = try in.open(&record);
    try testing.expectEqual(.handshake, opened.kind);
    try testing.expectEqualSlices(u8, &trace.server_flight, opened.data);
}
