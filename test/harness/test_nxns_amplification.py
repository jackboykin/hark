"""NXNSAttack (CVE-2020-12667) query-amplification regression.

A malicious authoritative server (hark's only configured root) answers every
query with a GLUELESS delegation to fresh, globally-unique NS names. Each NS
name forces its own delegation walk, so one client query fans out across a tree
of resolutions.

Before the tree-wide query budget, each sub-resolution got a fresh budget and a
single client query amplified into ~500 upstream queries (measured 488-575). The
shared, never-reset counter caps that. This test asserts the resolver stays an
order of magnitude below the old behaviour for one client query.

A static `.rpl` can't express this — the amplification needs an unbounded supply
of distinct NS names — so it lives as a dynamic harness test around
nxns_evil.EvilRoot.
"""

from __future__ import annotations

from pathlib import Path

import dns.flags
import dns.message
import dns.query
import pytest

from .hark_proc import HarkConfig, HarkProcess, find_hark_binary
from .nxns_evil import ROOT_LABEL, EvilRoot


EVIL_IP = "127.0.0.1"
EVIL_PORT = 18053
HARK_PORT = 15354
# Old (unpatched) behaviour was ~500 upstream queries. The shared budget caps
# at max-queries (100) plus a small concurrent overshoot. 200 cleanly
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
        # It SERVFAILs (the NS names never resolve); only the upstream
        # traffic it provoked matters.
        dns.query.udp(q, "127.0.0.1", port=HARK_PORT, timeout=20)
        assert hark.is_alive(), f"hark died:\n{hark.read_log()}"

    assert evil.total > 0, "evil root saw no queries — scenario wiring broke"
    assert evil.total <= AMPLIFICATION_BOUND, (
        f"NXNSAttack amplification: one client query produced {evil.total} "
        f"upstream queries (bound {AMPLIFICATION_BOUND}). The tree-wide "
        f"query budget regressed (graph Budget, max-queries)."
    )
