//! DNS load over batched kernel UDP sockets, a flow each. Closed loop keeps
//! `inflight` out; `qps` sends on a schedule and times each query from when
//! it was due. Unanswered after `timeout_s` is lost.
//!
//! By hand, against any resolver:
//!   bench load -s ADDR -p PORT -d FILE [-l SECS] [-c SOCKETS] [-T THREADS] [-q INFLIGHT] [-Q QPS] [-t TIMEOUT]
//! FILE holds "name type" lines. Prints "key value" lines: sent completed
//! lost qps, rcodes, p50 p99 p999 µs.
const std = @import("std");
const linux = std.os.linux;
const os = @import("os.zig");

const batch = 64;
const max_query = 512;

pub const Opts = struct {
    addr: [4]u8 = .{ 127, 0, 0, 1 },
    port: u16 = 53,
    source: Source,
    secs: u32 = 10,
    sockets: u32 = 1,
    threads: u32 = 1,
    inflight: u32 = 100,
    qps: u64 = 0,
    timeout_s: u32 = 3,
    cpus: ?[]const u16 = null,
};

const Source = union(enum) {
    hit,
    miss: u64,
    mix: u64,
    table: Table,

    fn fill(src: Source, i: u64, buf: *[max_query]u8) usize {
        switch (src) {
            .table => |t| {
                const q = t.get(i % t.ends.len);
                @memcpy(buf[0..q.len], q);
                return q.len;
            },
            .hit => return host(buf, i),
            .miss => |seed| return fresh(buf, seed, i),
            .mix => |seed| return if (scramble(seed ^ i) & 1 == 0) host(buf, i >> 1) else fresh(buf, seed, i),
        }
    }

    fn host(buf: *[max_query]u8, i: u64) usize {
        var name: [16]u8 = undefined;
        return question(buf, std.mem.print(&name, "host{d}.bench", .{i % 8 + 1}) catch unreachable, 1);
    }

    fn fresh(buf: *[max_query]u8, seed: u64, i: u64) usize {
        var name: [20]u8 = undefined;
        for ([_]u64{ scramble(seed +% 2 *% i), scramble(seed +% 2 *% i +% 1) }, 0..) |h, half| {
            var left = h;
            for (name[half * 7 ..][0..7]) |*c| {
                c.* = "abcdefghijklmnopqrstuvwxyz0123456789"[left % 36];
                left /= 36;
            }
        }
        @memcpy(name[14..], ".bench");
        return question(buf, &name, 1);
    }

    /// splitmix64's finalizer.
    fn scramble(x: u64) u64 {
        var z = x +% 0x9e3779b97f4a7c15;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }
};

const Table = struct {
    wire: []const u8,
    ends: []const u32,

    fn get(t: Table, i: usize) []const u8 {
        const start = if (i == 0) 0 else t.ends[i - 1];
        return t.wire[start..t.ends[i]];
    }
};

pub fn question(buf: []u8, name: []const u8, rtype: u16) usize {
    @memcpy(buf[0..12], &[_]u8{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
    var n: usize = 12;
    var labels = std.mem.splitScalar(u8, std.mem.trimEnd(u8, name, "."), '.');
    while (labels.next()) |l| {
        buf[n] = @intCast(l.len);
        @memcpy(buf[n + 1 ..][0..l.len], l);
        n += 1 + l.len;
    }
    @memcpy(buf[n..][0..5], &[_]u8{ 0, @intCast(rtype >> 8), @truncate(rtype), 0, 1 });
    return n + 5;
}

pub const Result = struct {
    sent: u64,
    completed: u64,
    lost: u64,
    qps: f64,
    rcodes: [16]u64,
    p50_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
};

const Hist = struct {
    n: [64 * 8]u64 = @splat(0),

    fn add(h: *Hist, ns: u64) void {
        h.n[index(@max(ns, 1))] += 1;
    }

    fn index(ns: u64) usize {
        const e: u6 = @intCast(63 - @clz(ns));
        const frac = if (e >= 3) (ns >> (e - 3)) & 7 else (ns << (3 - e)) & 7;
        return @as(usize, e) * 8 + @as(usize, @intCast(frac));
    }

    fn pct(h: *const Hist, p: f64) u64 {
        var total: u64 = 0;
        for (h.n) |c| total += c;
        if (total == 0) return 0;
        const want: u64 = @intFromFloat(@ceil(@as(f64, @floatFromInt(total)) * p / 100));
        var seen: u64 = 0;
        for (h.n, 0..) |c, i| {
            seen += c;
            if (seen >= want) {
                const e: u6 = @intCast(i / 8);
                const base = @as(u64, 1) << e;
                return base + (base * (i % 8 + 1)) / 8;
            }
        }
        return 0;
    }
};

const Stats = struct {
    sent: u64 = 0,
    completed: u64 = 0,
    lost: u64 = 0,
    rcodes: [16]u64 = @splat(0),
    last_ns: i64 = 0,
    hist: Hist = .{},

    fn merge(a: *Stats, b: *const Stats) void {
        a.sent += b.sent;
        a.completed += b.completed;
        a.lost += b.lost;
        for (&a.rcodes, b.rcodes) |*x, y| x.* += y;
        a.last_ns = @max(a.last_ns, b.last_ns);
        for (&a.hist.n, b.hist.n) |*x, y| x.* += y;
    }
};

/// `due[id]` is when the query with that id was due, 0 if none is out: a
/// query is timed from then, so a stalled sender cannot flatter the server.
/// `ring` holds (id, due) in send order, so timeouts are found at its head
/// and entries already answered are stale.
const Sock = struct {
    fd: i32,
    out: u32 = 0,
    next_id: u16 = 0,
    due: []i64,
    ring: []Pending,
    head: u32 = 0,
    len: u32 = 0,

    const Pending = struct { id: u16, due: i64 };
};

const Shared = struct {
    opts: Opts,
    start: i64,
    end: i64,
};

/// One thread's send scratch and its place in the schedule and the queries.
const Sender = struct {
    buf: [batch][max_query]u8 = undefined,
    iov: [batch]std.posix.iovec_const = undefined,
    hdr: [batch]linux.mmsghdr = undefined,
    due: [batch]i64 = undefined,
    id: [batch]u16 = undefined,
    /// Nanoseconds between sends in open loop; 0 is closed loop.
    gap: i64,
    window: u32,
    next_due: i64,
    qi: u64,
    stride: u64,

    /// Queues up to `cap` queries on `s` and sends them; returns how many left.
    fn send(o: *Sender, sh: *const Shared, s: *Sock, cap: usize, t: i64) usize {
        var n: usize = 0;
        while (n < cap) : (n += 1) {
            if (s.len + n == s.ring.len) break;
            var due = t;
            if (o.gap > 0) {
                if (o.next_due > t) break;
                due = o.next_due;
                o.next_due += o.gap;
            } else if (s.out + n >= o.window) break;
            while (s.due[s.next_id] != 0) s.next_id +%= 1;
            const id = s.next_id;
            s.next_id +%= 1;
            const len = sh.opts.source.fill(o.qi, &o.buf[n]);
            o.qi += o.stride;
            std.mem.writeInt(u16, o.buf[n][0..2], id, .big);
            o.iov[n] = .{ .base = &o.buf[n], .len = len };
            o.hdr[n] = .{ .hdr = .{ .name = null, .namelen = 0, .iov = @ptrCast(&o.iov[n]), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
            o.due[n] = due;
            o.id[n] = id;
            s.due[id] = due;
        }
        if (n == 0) return 0;
        const rc = linux.sendmmsg(s.fd, &o.hdr, @intCast(n), linux.MSG.DONTWAIT);
        const sent: usize = if (linux.errno(rc) == .SUCCESS) rc else 0;
        for (sent..n) |k| s.due[o.id[k]] = 0;
        for (0..sent) |k| {
            s.ring[(s.head + s.len) % s.ring.len] = .{ .id = o.id[k], .due = o.due[k] };
            s.len += 1;
        }
        s.out += @intCast(sent);
        return sent;
    }
};

const Receiver = struct {
    buf: [batch][max_query]u8 = undefined,
    iov: [batch]std.posix.iovec = undefined,
    hdr: [batch]linux.mmsghdr = undefined,

    fn init(r: *Receiver) void {
        for (&r.iov, &r.hdr, &r.buf) |*v, *h, *b| {
            v.* = .{ .base = b, .len = b.len };
            h.* = .{ .hdr = .{ .name = null, .namelen = 0, .iov = @ptrCast(v), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
        }
    }

    /// Takes what has arrived on `s`; true if anything did.
    fn receive(r: *Receiver, s: *Sock, stats: *Stats) bool {
        const rc = linux.recvmmsg(s.fd, &r.hdr, batch, linux.MSG.DONTWAIT, null);
        if (linux.errno(rc) != .SUCCESS or rc == 0) return false;
        const at = os.now();
        for (r.hdr[0..rc], r.buf[0..rc]) |h, b| {
            if (h.len < 12) continue;
            const id = std.mem.readInt(u16, b[0..2], .big);
            if (s.due[id] == 0) continue;
            stats.hist.add(@intCast(at - s.due[id]));
            stats.rcodes[b[3] & 0xf] += 1;
            stats.completed += 1;
            s.due[id] = 0;
            s.out -= 1;
        }
        stats.last_ns = at;
        return true;
    }
};

/// Drops answered entries from the head of the ring, and lost ones once
/// `patient` no longer holds for them.
fn expire(s: *Sock, t: i64, timeout: i64, patient: bool, stats: *Stats) void {
    while (s.len > 0) {
        const p = s.ring[s.head];
        if (s.due[p.id] == p.due) {
            if (t - p.due < timeout and patient) break;
            s.due[p.id] = 0;
            s.out -= 1;
            stats.lost += 1;
        }
        s.head = @intCast((s.head + 1) % s.ring.len);
        s.len -= 1;
    }
}

fn drive(sh: *const Shared, socks: []Sock, first: u64, stats: *Stats) void {
    const o = sh.opts;
    if (o.cpus) |cpus| os.pin(cpus);
    // Settled on its cores before the first query is due.
    os.sleep(@intCast(@max(0, sh.start - os.now())));
    const timeout: i64 = @as(i64, o.timeout_s) * std.time.ns_per_s;
    const rate = o.qps / o.threads;
    var sender: Sender = .{
        .gap = if (rate > 0) @intCast(std.time.ns_per_s / rate) else 0,
        .window = @max(1, o.inflight / o.sockets),
        .next_due = sh.start,
        .qi = first,
        .stride = o.threads,
    };
    var receiver: Receiver = .{};
    receiver.init();
    var pfds: [256]linux.pollfd = undefined;
    for (socks, 0..) |s, i| pfds[i] = .{ .fd = s.fd, .events = linux.POLL.IN, .revents = 0 };
    // Open loop spreads what is due over the flows.
    const cap = if (sender.gap > 0) @max(1, batch / socks.len) else batch;

    while (true) {
        var progress = false;
        const t = os.now();
        const sending = t < sh.end;
        for (socks) |*s| {
            if (sending) {
                const sent = sender.send(sh, s, cap, t);
                stats.sent += sent;
                progress = progress or sent > 0;
            }
            if (receiver.receive(s, stats)) progress = true;
            expire(s, t, timeout, sending or t < sh.end + timeout, stats);
        }
        if (!sending) {
            var out: u32 = 0;
            for (socks) |s| out += s.out;
            if (out == 0 or t >= sh.end + timeout) {
                stats.lost += out;
                return;
            }
        }
        if (!progress) {
            const wait: i32 = if (sender.gap > 0 and sending) 0 else 1;
            _ = linux.poll(&pfds, @intCast(socks.len), wait);
        }
    }
}

fn qtype(name: []const u8) ?u16 {
    const types = .{ .{ "A", 1 }, .{ "NS", 2 }, .{ "CNAME", 5 }, .{ "SOA", 6 }, .{ "PTR", 12 }, .{ "MX", 15 }, .{ "TXT", 16 }, .{ "AAAA", 28 }, .{ "SRV", 33 }, .{ "DS", 43 }, .{ "DNSKEY", 48 }, .{ "SVCB", 64 }, .{ "HTTPS", 65 }, .{ "ANY", 255 } };
    inline for (types) |t| if (std.ascii.eqlIgnoreCase(name, t[0])) return t[1];
    return null;
}

fn parse(gpa: std.mem.Allocator, text: []const u8) !Table {
    var wire: std.ArrayList(u8) = .empty;
    var ends: std.ArrayList(u32) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const name = f.next() orelse continue;
        const t = qtype(f.next() orelse "A") orelse return error.UnknownType;
        var labels = std.mem.splitScalar(u8, std.mem.trimEnd(u8, name, "."), '.');
        while (labels.next()) |l| if (l.len == 0 or l.len > 63) return error.BadName;
        if (name.len > 253) return error.BadName;
        var buf: [max_query]u8 = undefined;
        try wire.appendSlice(gpa, buf[0..question(&buf, name, t)]);
        try ends.append(gpa, @intCast(wire.items.len));
    }
    if (ends.items.len == 0) return error.NoQueries;
    return .{ .wire = wire.items, .ends = ends.items };
}

pub fn run(gpa: std.mem.Allocator, o: Opts) !Result {
    if (o.threads == 0 or o.sockets < o.threads or o.sockets / o.threads > 256) return error.BadSockets;
    const addr: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, o.port), .addr = @bitCast(o.addr) };
    const socks = try gpa.alloc(Sock, o.sockets);
    defer gpa.free(socks);
    var opened: usize = 0;
    defer for (socks[0..opened]) |s| {
        _ = linux.close(s.fd);
        gpa.free(s.due);
        gpa.free(s.ring);
    };
    for (socks) |*s| {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
        if (!os.ok(rc)) return error.Socket;
        const fd: i32 = @intCast(rc);
        const buf: u32 = 4 << 20;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, std.mem.asBytes(&buf), 4);
        const due = try gpa.alloc(i64, 1 << 16);
        @memset(due, 0);
        s.* = .{ .fd = fd, .due = due, .ring = try gpa.alloc(Sock.Pending, 1 << 16) };
        opened += 1;
        if (!os.ok(linux.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))))) return error.Connect;
    }

    const start = os.now() + 5 * std.time.ns_per_ms;
    const sh: Shared = .{ .opts = o, .start = start, .end = start + @as(i64, o.secs) * std.time.ns_per_s };
    const stats = try gpa.alloc(Stats, o.threads);
    defer gpa.free(stats);
    @memset(stats, .{});
    const threads = try gpa.alloc(std.Thread, o.threads);
    defer gpa.free(threads);
    const per = o.sockets / o.threads;
    for (threads, stats, 0..) |*t, *st, i| {
        const mine = socks[i * per .. if (i + 1 == o.threads) socks.len else (i + 1) * per];
        t.* = try std.Thread.spawn(.{}, drive, .{ &sh, mine, i, st });
    }
    for (threads) |t| t.join();
    var total: Stats = .{};
    for (stats) |*st| total.merge(st);
    const secs = @as(f64, @floatFromInt(@max(total.last_ns, sh.end) - start)) / std.time.ns_per_s;
    return .{
        .sent = total.sent,
        .completed = total.completed,
        .lost = total.lost,
        .qps = @as(f64, @floatFromInt(total.completed)) / secs,
        .rcodes = total.rcodes,
        .p50_ns = total.hist.pct(50),
        .p99_ns = total.hist.pct(99),
        .p999_ns = total.hist.pct(99.9),
    };
}

fn opts(gpa: std.mem.Allocator, args: []const []const u8) !Opts {
    var o: Opts = .{ .source = .hit };
    var file: []const u8 = "";
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 2) {
        const v = args[i + 1];
        const flag = args[i];
        if (std.mem.eql(u8, flag, "-s")) {
            var it = std.mem.splitScalar(u8, v, '.');
            for (&o.addr) |*b| b.* = try std.fmt.parseInt(u8, it.next() orelse return error.BadAddress, 10);
        } else if (std.mem.eql(u8, flag, "-p")) o.port = try std.fmt.parseInt(u16, v, 10) else if (std.mem.eql(u8, flag, "-d")) file = v else if (std.mem.eql(u8, flag, "-l")) o.secs = try std.fmt.parseInt(u32, v, 10) else if (std.mem.eql(u8, flag, "-c")) o.sockets = try std.fmt.parseInt(u32, v, 10) else if (std.mem.eql(u8, flag, "-T")) o.threads = try std.fmt.parseInt(u32, v, 10) else if (std.mem.eql(u8, flag, "-q")) o.inflight = try std.fmt.parseInt(u32, v, 10) else if (std.mem.eql(u8, flag, "-Q")) o.qps = try std.fmt.parseInt(u64, v, 10) else if (std.mem.eql(u8, flag, "-t")) o.timeout_s = try std.fmt.parseInt(u32, v, 10) else return error.UnknownFlag;
    }
    if (i != args.len or file.len == 0) return error.Usage;
    o.source = .{ .table = try parse(gpa, try os.slurp(gpa, file)) };
    return o;
}

pub fn main(gpa: std.mem.Allocator, args: []const []const u8) !void {
    const o = opts(gpa, args) catch |e| {
        std.debug.print("load: {t}\nusage: bench load -s ADDR -p PORT -d FILE [-l SECS] [-c SOCKETS] [-T THREADS] [-q INFLIGHT] [-Q QPS] [-t TIMEOUT]\n", .{e});
        std.process.exit(2);
    };
    const r = try run(gpa, o);
    var out: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try w.print("sent {d}\ncompleted {d}\nlost {d}\nqps {d:.1}\n", .{ r.sent, r.completed, r.lost, r.qps });
    const names = [_][]const u8{ "noerror", "formerr", "servfail", "nxdomain", "notimp", "refused" };
    for (r.rcodes, 0..) |c, i| if (c > 0) {
        if (i < names.len) try w.print("{s} {d}\n", .{ names[i], c }) else try w.print("rcode{d} {d}\n", .{ i, c });
    };
    try w.print("p50 {d}\np99 {d}\np999 {d}\n", .{ r.p50_ns / 1000, r.p99_ns / 1000, r.p999_ns / 1000 });
    os.put(1, w.buffered());
}
