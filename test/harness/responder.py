"""Scripted authoritative responder (UDP + TCP).

For each unique ADDRESS in a Scenario's RANGEs, binds a UDP socket and a TCP
listening socket on the same port. Answers queries according to the matching
ENTRY's directives. Logs every received query for CHECK_QUERY_LOG assertions.

Design: per address, one thread for UDP recvfrom and one thread for TCP
accept. TCP connections are handled synchronously, one query per connection
(RFC 7766 allows pipelining; the test load doesn't need it). Adequate for
scenarios with <20 fake auths and dozens of queries.

DNSSEC harness mode: when constructed with `signers={zone: KeyMaterial}`,
the responder pre-signs every RRset whose owner is under a signed zone and
auto-synthesizes DNSKEY responses for declared signed zones. See
test/harness/dnssec.py.
"""

from __future__ import annotations

import dataclasses
import socket
import threading
import time

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from . import dnssec as harness_dnssec
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

    def __init__(
        self,
        scenario: rpl.Scenario,
        port: int,
        signers: list[harness_dnssec.KeyMaterial] | None = None,
    ):
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
        # Empty list in non-DNSSEC scenarios. Pre-baking and DNSKEY
        # synthesis are no-ops when there are no signers.
        self._signers: list[harness_dnssec.KeyMaterial] = signers or []
        # Per-address signer routing: an auth synthesizes DNSKEY for zone Z
        # only if it actually serves entries under Z. Prevents the root auth
        # from answering authoritatively for `example.com DNSKEY` in a
        # nested-zone scenario — which would paper over a real hark
        # chain-walk bug.
        self._zones_by_address: dict[str, list[harness_dnssec.KeyMaterial]] = {}
        if self._signers:
            self._bake_signatures()
            self._zones_by_address = self._build_address_zone_map()

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
            # Recheck after blocking accept — stop() may have fired during
            # the 0.2s timeout window, in which case spawning an untracked
            # handler races teardown.
            if self._stop.is_set():
                conn.close()
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
            # No scenario entry matches; if it's a DNSKEY query for one of
            # our signed zones, synthesize the canonical response rather
            # than REFUSE. Scenarios that want to test DNSKEY-fetch failure
            # can still declare an explicit REFUSED/SERVFAIL entry.
            synth = self._synthesize_dnskey_response(address, query)
            if synth is not None:
                return synth
            # Otherwise: REFUSED. Mirrors a lame auth and surfaces gaps
            # in scenario coverage rather than silently dropping.
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

    # ── DNSSEC pre-baking + DNSKEY synthesis ──────────────────────────────

    def _bake_signatures(self) -> None:
        """Append an RRSIG to every signable RRset in every entry.

        Run once at construction time, before sockets are open. Records
        whose owner doesn't fall under any declared signed zone are left
        alone — the scenario can still declare unsigned auths.
        """
        for rng in self.scenario.ranges:
            for entry in rng.entries:
                for section in (entry.answer, entry.authority, entry.additional):
                    self._sign_section_inplace(section)

    def _sign_section_inplace(self, rrsets: list[dns.rrset.RRset]) -> None:
        # Snapshot original RRsets first — appending RRSIGs while iterating
        # would re-feed signatures back into the signer.
        originals = [rr for rr in rrsets if rr.rdtype != dns.rdatatype.RRSIG]
        for rrset in originals:
            signer = self._signer_for(rrset.name)
            if signer is None:
                continue
            if _has_covering_rrsig(rrsets, rrset):
                continue  # scenario declared its own — don't double-sign
            rrsets.append(signer.sign(rrset))

    def _signer_for(self, owner: dns.name.Name) -> harness_dnssec.KeyMaterial | None:
        """Return the deepest enclosing signed zone's KeyMaterial, or None.

        `example.com.` signed by both `.` and `example.com.` picks the
        latter — RRSIGs are minted by the closest enclosing zone.
        """
        best: harness_dnssec.KeyMaterial | None = None
        for km in self._signers:
            if not owner.is_subdomain(km.zone_name):
                continue
            if best is None or len(km.zone_name) > len(best.zone_name):
                best = km
        return best

    def _synthesize_dnskey_response(self, address: str, query: dns.message.Message) -> dns.message.Message | None:
        if not query.question:
            return None
        q = query.question[0]
        if q.rdtype != dns.rdatatype.DNSKEY:
            return None
        for km in self._zones_by_address.get(address, ()):
            if km.zone_name == q.name:
                r = dns.message.make_response(query, recursion_available=False)
                r.flags |= dns.flags.AA | dns.flags.QR
                r.answer = list(km.signed_dnskey_response)
                return r
        return None

    def _build_address_zone_map(self) -> dict[str, list[harness_dnssec.KeyMaterial]]:
        """For each bind address, the signed zones whose content it serves.

        An auth is considered to serve zone Z if any entry in any of its
        ranges declares an RR whose owner falls under Z. DNSKEY synthesis
        then only answers for those zones from that address — a root auth
        can't pretend to be authoritative for `example.com.` DNSKEY.
        """
        result: dict[str, list[harness_dnssec.KeyMaterial]] = {addr: [] for addr in self.addresses}
        for rng in self.scenario.ranges:
            for entry in rng.entries:
                for section in (entry.answer, entry.authority, entry.additional):
                    for rrset in section:
                        km = self._signer_for(rrset.name)
                        if km is not None and km not in result[rng.address]:
                            result[rng.address].append(km)
        return result

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


def _has_covering_rrsig(rrsets: list[dns.rrset.RRset], target: dns.rrset.RRset) -> bool:
    """True if `rrsets` already contains an RRSIG over `target`. Lets a
    scenario hand-roll its own signatures (e.g., to assert a *bogus*
    response) without the harness clobbering them."""
    for rr in rrsets:
        if rr.rdtype != dns.rdatatype.RRSIG or rr.name != target.name:
            continue
        for sig in rr:
            if sig.type_covered == target.rdtype:
                return True
    return False


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
