//! load -s ADDR -p PORT -d FILE [-l SECS] [-c SOCKETS] [-T THREADS] [-q INFLIGHT] [-Q QPS] [-t TIMEOUT]
//!
//! DNS load for the bench over batched kernel UDP sockets, a flow each,
//! from dnsperf's "name type" file. Closed loop keeps INFLIGHT out; -Q sends
//! on a schedule and times each query from when it was due, so a stalled
//! sender cannot flatter the server. Unanswered after TIMEOUT (3) s is lost.
//! Prints "key value" lines: sent completed lost qps, rcodes, p50 p99 p999 µs.
const std = @import("std");
const linux = std.os.linux;

const batch = 64;
const max_query = 512;

const Opts = struct {
    addr: [4]u8 = .{ 127, 0, 0, 1 },
    port: u16 = 53,
    file: []const u8 = "",
    secs: u32 = 10,
    sockets: u32 = 1,
    threads: u32 = 1,
    inflight: u32 = 100,
    qps: u64 = 0,
    timeout_s: u32 = 3,
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

/// `due[id]` is when the query with that id was due, 0 if none is out;
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

const Queries = struct {
    wire: []const u8,
    ends: []const u32,

    fn get(q: Queries, i: usize) []const u8 {
        const start = if (i == 0) 0 else q.ends[i - 1];
        return q.wire[start..q.ends[i]];
    }
};

fn now() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * std.time.ns_per_s + ts.nsec;
}

const Shared = struct {
    opts: Opts,
    queries: Queries,
    start: i64,
    end: i64,
};

fn run(sh: *const Shared, socks: []Sock, first: usize, stats: *Stats) void {
    const o = sh.opts;
    const timeout: i64 = @as(i64, o.timeout_s) * std.time.ns_per_s;
    const window = @max(1, o.inflight / o.sockets);
    const rate = o.qps / o.threads;
    const gap: i64 = if (rate > 0) @intCast(std.time.ns_per_s / rate) else 0;
    var next_due = sh.start;
    var qi = first;

    var sbuf: [batch][max_query]u8 = undefined;
    var siov: [batch]std.posix.iovec_const = undefined;
    var shdr: [batch]linux.mmsghdr = undefined;
    var sdue: [batch]i64 = undefined;
    var sid: [batch]u16 = undefined;
    var rbuf: [batch][max_query]u8 = undefined;
    var riov: [batch]std.posix.iovec = undefined;
    var rhdr: [batch]linux.mmsghdr = undefined;
    for (&riov, &rhdr, &rbuf) |*v, *h, *b| {
        v.* = .{ .base = b, .len = b.len };
        h.* = .{ .hdr = .{ .name = null, .namelen = 0, .iov = @ptrCast(v), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
    }
    var pfds: [256]linux.pollfd = undefined;
    for (socks, 0..) |s, i| pfds[i] = .{ .fd = s.fd, .events = linux.POLL.IN, .revents = 0 };

    while (true) {
        var progress = false;
        const t = now();
        const sending = t < sh.end;
        for (socks) |*s| {
            if (sending) {
                var n: usize = 0;
                // Open loop spreads what is due over the flows.
                const cap = if (gap > 0) @max(1, batch / socks.len) else batch;
                while (n < cap) : (n += 1) {
                    if (s.len + n == s.ring.len) break;
                    var due = t;
                    if (gap > 0) {
                        if (next_due > t) break;
                        due = next_due;
                        next_due += gap;
                    } else if (s.out + n >= window) break;
                    while (s.due[s.next_id] != 0) s.next_id +%= 1;
                    const id = s.next_id;
                    s.next_id +%= 1;
                    const q = sh.queries.get(qi);
                    qi = (qi + 1) % sh.queries.ends.len;
                    @memcpy(sbuf[n][0..q.len], q);
                    std.mem.writeInt(u16, sbuf[n][0..2], id, .big);
                    siov[n] = .{ .base = &sbuf[n], .len = q.len };
                    shdr[n] = .{ .hdr = .{ .name = null, .namelen = 0, .iov = @ptrCast(&siov[n]), .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
                    sdue[n] = due;
                    sid[n] = id;
                    s.due[id] = due;
                }
                if (n > 0) {
                    const rc = linux.sendmmsg(s.fd, &shdr, @intCast(n), linux.MSG.DONTWAIT);
                    const sent: usize = if (linux.errno(rc) == .SUCCESS) rc else 0;
                    for (sent..n) |k| s.due[sid[k]] = 0;
                    for (0..sent) |k| {
                        s.ring[(s.head + s.len) % s.ring.len] = .{ .id = sid[k], .due = sdue[k] };
                        s.len += 1;
                    }
                    s.out += @intCast(sent);
                    stats.sent += sent;
                    progress = progress or sent > 0;
                }
            }
            const rc = linux.recvmmsg(s.fd, &rhdr, batch, linux.MSG.DONTWAIT, null);
            if (linux.errno(rc) == .SUCCESS and rc > 0) {
                const at = now();
                for (rhdr[0..rc], rbuf[0..rc]) |h, b| {
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
                progress = true;
            }
            while (s.len > 0) {
                const p = s.ring[s.head];
                if (s.due[p.id] == p.due) {
                    if (t - p.due < timeout and (sending or t < sh.end + timeout)) break;
                    s.due[p.id] = 0;
                    s.out -= 1;
                    stats.lost += 1;
                }
                s.head = @intCast((s.head + 1) % s.ring.len);
                s.len -= 1;
            }
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
            const wait: i32 = if (gap > 0 and sending) 0 else 1;
            _ = linux.poll(&pfds, @intCast(socks.len), wait);
        }
    }
}

fn qtype(name: []const u8) ?u16 {
    const types = .{ .{ "A", 1 }, .{ "NS", 2 }, .{ "CNAME", 5 }, .{ "SOA", 6 }, .{ "PTR", 12 }, .{ "MX", 15 }, .{ "TXT", 16 }, .{ "AAAA", 28 }, .{ "SRV", 33 }, .{ "DS", 43 }, .{ "DNSKEY", 48 }, .{ "SVCB", 64 }, .{ "HTTPS", 65 }, .{ "ANY", 255 } };
    inline for (types) |t| if (std.ascii.eqlIgnoreCase(name, t[0])) return t[1];
    return null;
}

/// Each line as a query: id 0 (stamped at send), RD, one question, class IN.
fn parse(gpa: std.mem.Allocator, text: []const u8) !Queries {
    var wire: std.ArrayList(u8) = .empty;
    var ends: std.ArrayList(u32) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const name = f.next() orelse continue;
        const t = qtype(f.next() orelse "A") orelse return error.UnknownType;
        try wire.appendSlice(gpa, &.{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
        var labels = std.mem.splitScalar(u8, std.mem.trimEnd(u8, name, "."), '.');
        while (labels.next()) |l| {
            if (l.len == 0 or l.len > 63) return error.BadName;
            try wire.append(gpa, @intCast(l.len));
            try wire.appendSlice(gpa, l);
        }
        try wire.appendSlice(gpa, &.{ 0, @intCast(t >> 8), @truncate(t), 0, 1 });
        try ends.append(gpa, @intCast(wire.items.len));
    }
    if (ends.items.len == 0) return error.NoQueries;
    return .{ .wire = wire.items, .ends = ends.items };
}

fn opts(args: []const [:0]const u8) !Opts {
    var o: Opts = .{};
    var i: usize = 1;
    while (i + 1 < args.len) : (i += 2) {
        const v = args[i + 1];
        const flag = args[i];
        if (std.mem.eql(u8, flag, "-s")) {
            var it = std.mem.splitScalar(u8, v, '.');
            for (&o.addr) |*b| b.* = try std.fmt.parseInt(u8, it.next() orelse return error.BadAddress, 10);
        } else if (std.mem.eql(u8, flag, "-p")) o.port = try std.fmt.parseInt(u16, v, 10) else if (std.mem.eql(u8, flag, "-d")) o.file = v else if (std.mem.eql(u8, flag, "-l")) o.secs = try std.fmt.parseInt(u32, v, 10) else if (std.mem.eql(u8, flag, "-c")) o.sockets = try std.fmt.parseInt(u32, v, 10) else if (std.mem.eql(u8, flag, "-T")) o.threads = try std.fmt.parseInt(u32, v, 10) else if (std.mem.eql(u8, flag, "-q")) o.inflight = try std.fmt.parseInt(u32, v, 10) else if (std.mem.eql(u8, flag, "-Q")) o.qps = try std.fmt.parseInt(u64, v, 10) else if (std.mem.eql(u8, flag, "-t")) o.timeout_s = try std.fmt.parseInt(u32, v, 10) else return error.UnknownFlag;
    }
    if (i != args.len or o.file.len == 0) return error.Usage;
    if (o.threads == 0 or o.sockets < o.threads or o.sockets / o.threads > 256) return error.BadSockets;
    return o;
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.smp_allocator;
    var argv: std.ArrayList([:0]const u8) = .empty;
    var it = std.process.Args.Iterator.init(init.minimal.args);
    while (it.next()) |a| try argv.append(gpa, a);
    const o = opts(argv.items) catch |e| {
        std.debug.print("load: {t}\nusage: load -s ADDR -p PORT -d FILE [-l SECS] [-c SOCKETS] [-T THREADS] [-q INFLIGHT] [-Q QPS] [-t TIMEOUT]\n", .{e});
        std.process.exit(2);
    };
    const text = try std.Io.Dir.cwd().readFileAlloc(init.io, o.file, gpa, .unlimited);
    const queries = try parse(gpa, text);

    const addr: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, o.port), .addr = @bitCast(o.addr) };
    const socks = try gpa.alloc(Sock, o.sockets);
    for (socks) |*s| {
        const fd: i32 = @intCast(linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0));
        if (fd < 0) return error.Socket;
        const buf: u32 = 4 << 20;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, std.mem.asBytes(&buf), 4);
        if (linux.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))) != .SUCCESS) return error.Connect;
        const due = try gpa.alloc(i64, 1 << 16);
        @memset(due, 0);
        s.* = .{ .fd = fd, .due = due, .ring = try gpa.alloc(Sock.Pending, 1 << 16) };
    }

    const start = now();
    const sh: Shared = .{ .opts = o, .queries = queries, .start = start, .end = start + @as(i64, o.secs) * std.time.ns_per_s };
    const stats = try gpa.alloc(Stats, o.threads);
    @memset(stats, .{});
    const threads = try gpa.alloc(std.Thread, o.threads);
    const per = o.sockets / o.threads;
    for (threads, stats, 0..) |*t, *st, i| {
        const mine = socks[i * per .. if (i + 1 == o.threads) socks.len else (i + 1) * per];
        t.* = try std.Thread.spawn(.{}, run, .{ &sh, mine, i * queries.ends.len / o.threads, st });
    }
    for (threads) |t| t.join();
    var total: Stats = .{};
    for (stats) |*st| total.merge(st);

    const secs = @as(f64, @floatFromInt(@max(total.last_ns, sh.end) - start)) / std.time.ns_per_s;
    var out: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try w.print("sent {d}\ncompleted {d}\nlost {d}\nqps {d:.1}\n", .{ total.sent, total.completed, total.lost, @as(f64, @floatFromInt(total.completed)) / secs });
    const names = [_][]const u8{ "noerror", "formerr", "servfail", "nxdomain", "notimp", "refused" };
    for (total.rcodes, 0..) |c, i| if (c > 0) {
        if (i < names.len) try w.print("{s} {d}\n", .{ names[i], c }) else try w.print("rcode{d} {d}\n", .{ i, c });
    };
    try w.print("p50 {d}\np99 {d}\np999 {d}\n", .{ total.hist.pct(50) / 1000, total.hist.pct(99) / 1000, total.hist.pct(99.9) / 1000 });
    _ = linux.write(1, w.buffered().ptr, w.buffered().len);
}
