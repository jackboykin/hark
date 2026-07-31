"""NXNSAttack (CVE-2020-12667) query-amplification regression.

A malicious authoritative server (hark's only configured root) answers every
query with a GLUELESS delegation to fresh, globally-unique NS names. Each NS
name forces its own delegation walk, so one client query fans out across a tree
of `resolveImpl` calls.

Before the tree-wide `QueryBudget` (src/recursive.zig), each sub-resolution got
a fresh `max_upstream_queries` budget and a single client query amplified into
~500 upstream queries (measured 488-575). The shared, never-reset counter caps
that. This test asserts the resolver stays an order of magnitude below the old
behaviour for one client query.

A static `.rpl` can't express this — the amplification needs an unbounded supply
of distinct NS names — so it lives as a dynamic harness test around
nxns_evil.EvilRoot.
"""

from __future__ import annotations

import time
from pathlib import Path

import dns.flags
import dns.message
import dns.query
import pytest

from .hark_proc import HarkConfig, HarkProcess, find_hark_binary
from .nxns_evil import ROOT_LABEL, EvilRoot, decode


def test_evil_decode_is_case_insensitive() -> None:
    # hark 0x20-randomizes query case; a case-sensitive mock answers an
    # uncounted authoritative NODATA that the resolver rightly caches,
    # flaking the amplification test below (~20% of runs). See decode().
    assert decode("N-0-3") == [0, 3]
    assert decode("N") == []

EVIL_IP = "127.0.0.1"
EVIL_PORT = 18053
HARK_PORT = 15354
# Old (unpatched) behaviour was ~500 upstream queries. The shared budget caps
# at max_global_queries (100) plus a small concurrent-overshoot. 200 cleanly
# separates "fixed" from "amplifying" without being flaky on the exact count.
AMPLIFICATION_BOUND = 200


@pytest.mark.timeout(30)
def test_glueless_ns_fanout_is_bounded(tmp_path: Path) -> None:
    binary = find_hark_binary()
    cfg = HarkConfig(
        listen_ip="127.0.0.1",
        listen_port=HARK_PORT,
        upstream_port=EVIL_PORT,
        root_hints=[f"{EVIL_IP}:{EVIL_PORT}"],
        qname_minimization=True,
        dnssec=False,
    )
    with EvilRoot(EVIL_IP, EVIL_PORT) as evil, HarkProcess(binary, cfg, tmp_path) as hark:
        q = dns.message.make_query(f"victim.{ROOT_LABEL}.", "A")
        q.flags |= dns.flags.RD
        # Resend until the fan-out actually launches: a single client UDP packet
        # can be dropped if hark's UDP socket races its TCP-readiness signal, in
        # which case evil sees nothing — a harness hiccup, not the property under
        # test. Each attempt SERVFAILs (the NS names never resolve), so we only
        # look at how much upstream traffic it provoked.
        for _ in range(5):
            try:
                dns.query.udp(q, "127.0.0.1", port=HARK_PORT, timeout=20)
            except Exception:
                pass
            time.sleep(0.5)  # let in-flight fan-out threads drain
            if evil.total > 0:
                break
        assert hark.is_alive(), f"hark died:\n{hark.read_log()}"

    assert evil.total > 0, "evil root saw no queries — scenario wiring broke"
    assert evil.total <= AMPLIFICATION_BOUND, (
        f"NXNSAttack amplification: one client query produced {evil.total} "
        f"upstream queries (bound {AMPLIFICATION_BOUND}). The tree-wide "
        f"QueryBudget regressed — see src/recursive.zig:max_global_queries."
    )
