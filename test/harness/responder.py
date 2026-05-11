"""Scripted authoritative responder (UDP + TCP).

For each unique ADDRESS in a Scenario's RANGEs, binds a UDP socket and a TCP
listening socket on the same port. Answers queries according to the matching
ENTRY's directives. Logs every received query for CHECK_QUERY_LOG assertions.

Design: per address, one thread for UDP recvfrom and one thread for TCP
accept. TCP connections are handled synchronously, one query per connection
(RFC 7766 allows pipelining; the test load doesn't need it). Adequate for
scenarios with <20 fake auths and dozens of queries.
"""

from __future__ import annotations

import dataclasses
import socket
import threading
import time

import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from . import rpl


@dataclasses.dataclass
class QueryLog:
    """One received-query record. Used for CHECK_QUERY_LOG assertions."""
    ts: float
    address: str            # the fake-auth's bind address (which auth received it)
    src_port: int
    qname: str              # absolute dotted form, lowercase
    qtype: str              # uppercase mnemonic
    qclass: str = "IN"


class Responder:
    """Owns the sockets and worker threads for one scenario."""

    def __init__(self, scenario: rpl.Scenario, port: int):
        self.scenario = scenario
        self.port = port
        self.addresses: list[str] = sorted({r.address for r in scenario.ranges})
        self._udp_sockets: dict[str, socket.socket] = {}
        self._tcp_sockets: dict[str, socket.socket] = {}
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self.query_log: list[QueryLog] = []
        self._log_lock = threading.Lock()
        # Current step is bumped by the driver after each STEP CHECK_ANSWER /
        # QUERY pair so RANGE [start..end] activation tracks the scenario timeline.
        # Most scenarios use wide ranges (0..100) and never bump.
        self._current_step = 0
        self._step_lock = threading.Lock()
        # Drop count: number of next incoming queries to drop without
        # replying. The scenario runner pre-scans STEP n TIMEOUT directives
        # *before* the QUERY fires because QUERY is synchronous — by the
        # time the loop reaches a TIMEOUT step, hark's upstream queries
        # have already happened.
        self._pending_drops = 0
        self._drops_lock = threading.Lock()

    def start(self) -> None:
        for addr in self.addresses:
            udp = self._bind(addr, socket.SOCK_DGRAM)
            self._udp_sockets[addr] = udp
            self._spawn(self._serve_udp, addr, udp)

            tcp = self._bind(addr, socket.SOCK_STREAM)
            tcp.listen(8)
            self._tcp_sockets[addr] = tcp
            self._spawn(self._accept_tcp, addr, tcp)

    def _bind(self, addr: str, sock_type: int) -> socket.socket:
        # IPV6_V6ONLY keeps the v4 and v6 paths cleanly separated so
        # query_log records the actual transport the auth was reached on.
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        s = socket.socket(family, sock_type)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.settimeout(0.2)
        s.bind((addr, self.port))
        return s

    def _spawn(self, target, *args) -> None:
        t = threading.Thread(target=target, args=args, daemon=True)
        self._threads.append(t)
        t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2.0)
        for s in self._udp_sockets.values():
            s.close()
        for s in self._tcp_sockets.values():
            s.close()

    def set_step(self, n: int) -> None:
        with self._step_lock:
            self._current_step = n

    def set_drop_count(self, n: int) -> None:
        """Number of next incoming queries to drop without replying."""
        with self._drops_lock:
            self._pending_drops = n

    def _consume_drop(self) -> bool:
        with self._drops_lock:
            if self._pending_drops > 0:
                self._pending_drops -= 1
                return True
            return False

    # ── Serving loops ────────────────────────────────────────────────────

    def _serve_udp(self, address: str, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                data, src = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                query = dns.message.from_wire(data)
            except Exception:
                continue
            self._log(address, src, query)
            if self._consume_drop():
                continue  # simulate auth timeout
            response = self._build_response(address, query, transport="udp")
            if response is not None:
                sock.sendto(response.to_wire(), src)

    def _accept_tcp(self, address: str, listen_sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, src = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            # Track the handler thread so `stop()` can join it — otherwise a
            # mid-flight `_handle_tcp` can race the scenario teardown (the
            # ranges/log are about to be GC'd) and read freed state.
            self._spawn(self._handle_tcp, address, conn, src)

    def _handle_tcp(self, address: str, conn: socket.socket, src: tuple[str, int]) -> None:
        # RFC 1035 §4.2.2: TCP DNS framed as 2-byte big-endian length + message.
        try:
            conn.settimeout(2.0)
            hdr = _recv_exactly(conn, 2)
            if hdr is None:
                return
            length = int.from_bytes(hdr, "big")
            body = _recv_exactly(conn, length)
            if body is None:
                return
            try:
                query = dns.message.from_wire(body)
            except Exception:
                return
            self._log(address, src, query)
            if self._consume_drop():
                return  # simulate auth timeout (close without response)
            response = self._build_response(address, query, transport="tcp")
            if response is not None:
                wire = response.to_wire()
                conn.sendall(len(wire).to_bytes(2, "big") + wire)
        finally:
            conn.close()

    def _log(self, address: str, src: tuple[str, int], query: dns.message.Message) -> None:
        """Append a record to query_log unless the query is hark's RFC 8109
        root-priming probe (`. NS`) — including it would offset positional
        CHECK_OUT_QUERY indices and scenarios rarely declare a matcher."""
        if not query.question:
            return
        q = query.question[0]
        qname = q.name.to_text().lower()
        qtype = dns.rdatatype.to_text(q.rdtype)
        if qname == "." and qtype == "NS":
            return
        rec = QueryLog(
            ts=time.monotonic(),
            address=address,
            src_port=src[1],
            qname=qname,
            qtype=qtype,
            qclass=dns.rdataclass.to_text(q.rdclass),
        )
        with self._log_lock:
            self.query_log.append(rec)

    def _build_response(self, address: str, query: dns.message.Message, transport: str) -> dns.message.Message | None:
        entry = self._find_entry(address, query, transport)
        if entry is None:
            # Unmatched query: REFUSED. Mirrors a lame auth and surfaces
            # gaps in scenario coverage rather than silently dropping.
            r = dns.message.make_response(query)
            r.set_rcode(dns.rcode.REFUSED)
            return r

        # `make_response` copies the query's question verbatim — echoing
        # case is mandatory (RFC 1035 §3.1) and load-bearing for hark's
        # 0x20 randomization (RFC 5452 §9.2); replacing it with entry.question
        # would force hark into a lowercase retry per upstream query.
        r = dns.message.make_response(query, recursion_available=False)
        # Overwriting `flags` rather than OR-ing means scenarios must
        # include QR explicitly; force it here so that's structural, not
        # convention.
        r.flags = entry.reply_flags | dns.flags.QR
        r.set_rcode(entry.reply_rcode)

        r.answer = list(entry.answer)
        r.authority = list(entry.authority)
        r.additional = list(entry.additional)
        return r

    def _find_entry(self, address: str, query: dns.message.Message, transport: str) -> rpl.Entry | None:
        with self._step_lock:
            step = self._current_step
        for rng in self.scenario.ranges:
            if rng.address != address:
                continue
            if not (rng.start <= step <= rng.end):
                continue
            for entry in rng.entries:
                if _entry_matches_query(entry, query, transport):
                    return entry
        return None


def _recv_exactly(conn: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes from a TCP socket. None on EOF/timeout."""
    try:
        data = conn.recv(n, socket.MSG_WAITALL)
    except (socket.timeout, OSError):
        return None
    return data if len(data) == n else None


# ── Match logic ─────────────────────────────────────────────────────────


def _entry_matches_query(entry: rpl.Entry, query: dns.message.Message, transport: str) -> bool:
    """Apply an entry's MATCH directives against an incoming query.

    Empty match set is treated as `MATCH question` (the .rpl default convention).
    `question` expands to qname + qtype + qclass. `MATCH tcp` / `MATCH udp`
    restrict the entry to one transport — used by TC-fallback scenarios that
    want different responses on UDP vs TCP. If neither is set the entry
    matches both.
    """
    if not entry.question or not query.question:
        return False  # responder entries must declare what they answer
    flags = entry.match or {"question"}
    if "question" in flags:
        flags = flags | {"qname", "qtype", "qclass"}
    eq = entry.question[0]
    qq = query.question[0]

    if "tcp" in flags and transport != "tcp":
        return False
    if "udp" in flags and transport != "udp":
        return False
    if "opcode" in flags and entry.reply_opcode != query.opcode():
        return False
    if "qclass" in flags and eq.rdclass != qq.rdclass:
        return False
    if "qtype" in flags and eq.rdtype != qq.rdtype:
        return False
    if "qname" in flags and eq.name != qq.name:
        return False
    if "subdomain" in flags and not qq.name.is_subdomain(eq.name):
        return False
    return True
