"""Differential: hark obeys RFC 1035 §4.1.3 / RFC 2181 §8 on TTL=0; Unbound doesn't.

Both RFCs say a zero-TTL RR "should not be cached" — usable only for the
transaction in progress.

History (the cheeky part): Unbound used to cache TTL=0 records with a
~1-second grace period by default, in plain contradiction of the RFCs.
PR NLnetLabs/unbound#1337 ("0 TTL cached replies and some TTL behavior
changes", merged 2025-09-19) made TTL=0 records expire immediately and
upstream TTL=0 answers uncacheable; the change shipped in Unbound 1.24.0.
The shell.nix pins ≥1.24, so this default-behaviour contrast no longer
reproduces against the current oracle. The divergence below is what's
left after that fix.

Surviving divergence — the `cache-min-ttl` interpretation: both
resolvers expose a min-TTL floor for upstream-load shaping. Unbound
applies the floor uniformly; *including* records the auth marked TTL=0
to prevent caching. Hark explicitly excludes TTL=0 from the bump
(`src/cache.zig:776` for negative caching, `src/cache.zig:871` for
positive RRsets). With the same 60s floor configured on both, the
operator gets two RFC interpretations from one knob:
  hark    → 2 upstream queries (floor doesn't apply to TTL=0)
  Unbound → 1 upstream query  (floor applied; cache hit on the 2nd)

Run: `nix-shell test/shell.nix --run "cd test && pytest differential/ -v"`
"""

from __future__ import annotations

from pathlib import Path

import dns.message
import dns.query

from conftest import HARK_LISTEN as RESOLVER_LISTEN, RESP_PORT
from differential import unbound_proc
from harness import hark_proc, responder, rpl


SCENARIO_TEXT = """\
; hark: root-hints = 127.0.10.1

SCENARIO_BEGIN ttl_zero_no_cache
RANGE_BEGIN 0 100
  ADDRESS 127.0.10.1
  ; AA + RA both set: hark queries us recursively (sees AA, accepts as
  ; authoritative); unbound forwards (sees RA, accepts as recursive).
  ; The combo is contradictory in the wild but harmless here — the
  ; responder only exists to count whether the leaf query landed twice
  ; or once, not to be a model citizen.
  ENTRY_BEGIN
    MATCH opcode qname qtype
    ADJUST copy_id copy_query
    REPLY QR AA RA NOERROR
    SECTION QUESTION
      example.com. IN A
    SECTION ANSWER
      example.com. 0 IN A 192.0.2.1
  ENTRY_END
RANGE_END
SCENARIO_END
"""

QNAME = "example.com."
QTYPE = "A"


def _scenario(tmp_path: Path) -> rpl.Scenario:
    p = tmp_path / "ttl_zero.rpl"
    p.write_text(SCENARIO_TEXT)
    return rpl.parse(p)


def _fire_two_queries(addr: tuple[str, int]) -> None:
    for _ in range(2):
        msg = dns.message.make_query(QNAME, QTYPE)
        dns.query.udp(msg, addr[0], port=addr[1], timeout=5.0)


def _leaf_hits(log) -> int:
    return sum(1 for r in log if r.qname == QNAME and r.qtype == QTYPE)


def test_hark_obeys_zero_ttl_no_cache_unlike_unbound(tmp_path):
    scenario = _scenario(tmp_path)

    # ── Phase A: hark ───────────────────────────────────────────────────
    resp_h = responder.Responder(scenario, port=RESP_PORT)
    resp_h.start()
    try:
        binary = hark_proc.find_hark_binary()
        cfg = hark_proc.HarkConfig(
            listen_ip=RESOLVER_LISTEN[0],
            listen_port=RESOLVER_LISTEN[1],
            upstream_port=RESP_PORT,
            root_hints=[f"127.0.10.1:{RESP_PORT}"],
            qname_minimization=False,
            # Same operator-facing knob both resolvers expose. The contrast
            # is in interpretation: hark excludes TTL=0 from the floor;
            # unbound silently bumps TTL=0 to the floor.
            cache_min_ttl=60,
        )
        (tmp_path / "hark").mkdir(exist_ok=True)
        with hark_proc.HarkProcess(binary, cfg, tmp_path / "hark"):
            _fire_two_queries(RESOLVER_LISTEN)
        hark_hits = _leaf_hits(resp_h.query_log)
    finally:
        resp_h.stop()

    # ── Phase B: unbound ────────────────────────────────────────────────
    resp_u = responder.Responder(scenario, port=RESP_PORT)
    resp_u.start()
    try:
        ucfg = unbound_proc.UnboundConfig(
            listen_ip=RESOLVER_LISTEN[0],
            listen_port=RESOLVER_LISTEN[1],
            upstream_addr=f"127.0.10.1@{RESP_PORT}",
        )
        (tmp_path / "unbound").mkdir(exist_ok=True)
        with unbound_proc.UnboundProcess(ucfg, tmp_path / "unbound"):
            _fire_two_queries(RESOLVER_LISTEN)
        unbound_hits = _leaf_hits(resp_u.query_log)
    finally:
        resp_u.stop()

    # Hark: cache miss both times → upstream sees 2 queries.
    assert hark_hits == 2, (
        f"hark cached a TTL=0 answer in violation of RFC 1035 §4.1.3 / "
        f"RFC 2181 §8 — upstream received {hark_hits} queries, expected 2.\n"
        f"log: {resp_h.query_log}"
    )
    # Unbound: caches anyway → upstream sees only the first.
    assert unbound_hits == 1, (
        f"unbound is unexpectedly RFC-compliant on TTL=0 today "
        f"(upstream received {unbound_hits} queries, expected 1). "
        f"Either the cheeky premise no longer holds or the config drifted.\n"
        f"log: {resp_u.query_log}"
    )
