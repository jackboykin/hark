"""Scripted UDP authoritative responder.

For each unique ADDRESS in a Scenario's RANGEs, binds a UDP socket and answers
queries according to the matching ENTRY's directives. Logs every received
query for CHECK_QUERY_LOG assertions.

Design: one thread per address. Each thread blocks on recvfrom and serves
synchronously. Adequate for scenarios with <20 fake auths and dozens of
queries; switch to selectors if/when we hit scale issues.
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
        self._sockets: dict[str, socket.socket] = {}
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self.query_log: list[QueryLog] = []
        self._log_lock = threading.Lock()
        # Current step is bumped by the driver after each STEP CHECK_ANSWER /
        # QUERY pair so RANGE [start..end] activation tracks the scenario timeline.
        # Most scenarios use wide ranges (0..100) and never bump.
        self._current_step = 0
        self._step_lock = threading.Lock()

    def start(self) -> None:
        for addr in self.addresses:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0.2)
            s.bind((addr, self.port))
            self._sockets[addr] = s
            t = threading.Thread(target=self._serve, args=(addr, s), daemon=True)
            self._threads.append(t)
            t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2.0)
        for s in self._sockets.values():
            s.close()

    def set_step(self, n: int) -> None:
        with self._step_lock:
            self._current_step = n

    # ── Serving loop ─────────────────────────────────────────────────────

    def _serve(self, address: str, sock: socket.socket) -> None:
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
            response = self._build_response(address, query)
            if response is not None:
                sock.sendto(response.to_wire(), src)

    def _log(self, address: str, src: tuple[str, int], query: dns.message.Message) -> None:
        if not query.question:
            return
        q = query.question[0]
        rec = QueryLog(
            ts=time.monotonic(),
            address=address,
            src_port=src[1],
            qname=q.name.to_text().lower(),
            qtype=dns.rdatatype.to_text(q.rdtype),
            qclass=dns.rdataclass.to_text(q.rdclass),
        )
        with self._log_lock:
            self.query_log.append(rec)

    def _build_response(self, address: str, query: dns.message.Message) -> dns.message.Message | None:
        entry = self._find_entry(address, query)
        if entry is None:
            # Unmatched query: REFUSED. Mirrors a lame auth and surfaces
            # gaps in scenario coverage rather than silently dropping.
            r = dns.message.make_response(query)
            r.set_rcode(dns.rcode.REFUSED)
            return r

        # `dns.message.make_response` copies the query's ID into the response
        # (the `ADJUST copy_id` directive is therefore implicit and a no-op
        # under this responder — kept in scenarios for testbound compatibility).
        r = dns.message.make_response(query, recursion_available=False)
        # REPLY directive sets flags + rcode. Force QR=1 — `make_response`
        # would set it, but the explicit overwrite below clobbers anything
        # not in REPLY. Scenarios universally include `QR` but the convention
        # is load-bearing only by accident; this makes it structural.
        r.flags = entry.reply_flags | dns.flags.QR
        r.set_rcode(entry.reply_rcode)

        if "copy_query" in entry.adjust or not r.question:
            r.question = list(query.question)
        else:
            r.question = list(entry.question)

        r.answer = list(entry.answer)
        r.authority = list(entry.authority)
        r.additional = list(entry.additional)
        return r

    def _find_entry(self, address: str, query: dns.message.Message) -> rpl.Entry | None:
        with self._step_lock:
            step = self._current_step
        for rng in self.scenario.ranges:
            if rng.address != address:
                continue
            if not (rng.start <= step <= rng.end):
                continue
            for entry in rng.entries:
                if _entry_matches_query(entry, query):
                    return entry
        return None


# ── Match logic ─────────────────────────────────────────────────────────


def _entry_matches_query(entry: rpl.Entry, query: dns.message.Message) -> bool:
    """Apply an entry's MATCH directives against an incoming query.

    Empty match set is treated as `MATCH question` (the .rpl default convention).
    `question` expands to qname + qtype + qclass.
    """
    if not entry.question or not query.question:
        return False  # responder entries must declare what they answer
    flags = entry.match or {"question"}
    if "question" in flags:
        flags = flags | {"qname", "qtype", "qclass"}
    eq = entry.question[0]
    qq = query.question[0]

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
