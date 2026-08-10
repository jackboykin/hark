"""A `.secure` negative verdict must not outlive its NSEC proof.

Regression: hark cached signed NXDOMAIN/NODATA verdicts for the SOA-derived
TTL (here 3600s) with no bound from the RRSIG validity window, so a denial
kept being served — with AD=1 — long after every signature justifying it had
expired. This harness signs with a deliberately short window and asserts that
each negative artifact derived from the proof is bounded by it:

  - the live response's authority TTLs (what downstream caches are handed),
  - the cached negative verdict on a repeat query,
  - an aggressively-synthesized sibling NXDOMAIN (RFC 8198, NSEC cache).

TTL bounds, not clock sleeps: with the fix each TTL is <= the signatures'
remaining validity; without it they read ~3600.
"""

from __future__ import annotations

import datetime
import tempfile
import textwrap
from pathlib import Path

import dns.flags
import dns.message
import dns.query
import dns.rdatatype

import conftest

from . import dnssec as harness_dnssec
from . import hark_proc, responder, rpl

SIG_VALIDITY_S = 40

SCENARIO = textwrap.dedent(
    """\
    ; hark: root-hints = 127.0.10.1
    ; hark: dnssec-zone = .

    SCENARIO_BEGIN negative proofs signed with a short validity window

    ; Zone layout and NSEC geometry are scenario 004/007's: signed root,
    ; `a.` and `c.` exist, `a. NSEC c.` covers `b.` and `b2.`, `. NSEC a.`
    ; covers the wildcard. The scripted steps live in python because rpl
    ; CHECK_ANSWER can only match TTLs exactly, and these assertions are
    ; bounds against a moving signature-expiry clock.

    RANGE_BEGIN 0 100
      ADDRESS 127.0.10.1

      ENTRY_BEGIN
        MATCH opcode qname qtype
        ADJUST copy_id copy_query
        REPLY QR AA NXDOMAIN
        SECTION QUESTION
          b. IN A
        SECTION AUTHORITY
          . 3600 IN SOA root. nobody.invalid. 1 7200 3600 86400 3600
          . 3600 IN NSEC a. SOA NS DNSKEY RRSIG NSEC
          a. 3600 IN NSEC c. A RRSIG NSEC
      ENTRY_END

      ENTRY_BEGIN
        MATCH opcode qname qtype
        ADJUST copy_id copy_query
        REPLY QR AA NOERROR
        SECTION QUESTION
          a. IN AAAA
        SECTION AUTHORITY
          . 3600 IN SOA root. nobody.invalid. 1 7200 3600 86400 3600
          a. 3600 IN NSEC c. A RRSIG NSEC
      ENTRY_END
    RANGE_END

    STEP 1 QUERY
    ENTRY_BEGIN
      REPLY RD DO
      SECTION QUESTION
        b. IN A
    ENTRY_END
    SCENARIO_END
    """
)


def _ask(qname: str, rdtype: str) -> dns.message.Message:
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    return dns.query.udp(q, conftest.HARK_LISTEN[0], port=conftest.HARK_LISTEN[1], timeout=5.0)


def _max_authority_ttl(r: dns.message.Message) -> int:
    assert r.authority, "expected a negative response with authority records"
    return max(rr.ttl for rr in r.authority)


def test_negative_verdicts_bounded_by_sig_validity(tmp_path):
    path = tmp_path / "short_sig.rpl"
    path.write_text(SCENARIO)
    scenario = rpl.parse(path)

    binary = hark_proc.find_hark_binary()
    cfg = hark_proc.HarkConfig(
        listen_ip=conftest.HARK_LISTEN[0],
        listen_port=conftest.HARK_LISTEN[1],
        upstream_port=conftest.RESP_PORT,
        root_hints=[conftest._with_port(h, conftest.RESP_PORT) for h in scenario.root_hints],
    )
    validity = datetime.timedelta(seconds=SIG_VALIDITY_S)
    signers = [harness_dnssec.KeyMaterial.generate(z, sig_validity=validity) for z in scenario.dnssec_zones]
    cfg.dnssec = True
    cfg.trust_anchors = [signers[0].ds_presentation()]

    resp = responder.Responder(scenario, port=conftest.RESP_PORT, signers=signers)
    resp.start()
    try:
        with tempfile.TemporaryDirectory(prefix="harktest-") as td:
            with hark_proc.HarkProcess(binary, cfg, Path(td)) as proc:
                resp.set_step(1)

                # Live NXDOMAIN: verdict validates, and the TTLs handed to the
                # client are already trimmed to the proof's lifetime.
                live = _ask("b.", "A")
                assert live.rcode() == dns.rcode.NXDOMAIN
                assert live.flags & dns.flags.AD
                assert _max_authority_ttl(live) <= SIG_VALIDITY_S

                # Cached verdict: bounded by the proof, not the SOA's 3600.
                cached = _ask("b.", "A")
                assert cached.rcode() == dns.rcode.NXDOMAIN
                assert cached.flags & dns.flags.AD
                assert _max_authority_ttl(cached) <= SIG_VALIDITY_S

                # Aggressive-NSEC synthesis for a covered sibling (RFC 8198):
                # no upstream entry exists for b2., so NXDOMAIN+AD proves the
                # NSEC cache answered — and its TTL must carry the same bound.
                synth = _ask("b2.", "A")
                assert synth.rcode() == dns.rcode.NXDOMAIN
                assert synth.flags & dns.flags.AD
                assert _max_authority_ttl(synth) <= SIG_VALIDITY_S

                # NODATA rides the same machinery through its own store site.
                nodata = _ask("a.", "AAAA")
                assert nodata.rcode() == dns.rcode.NOERROR
                assert nodata.flags & dns.flags.AD
                assert _max_authority_ttl(nodata) <= SIG_VALIDITY_S
                cached_nodata = _ask("a.", "AAAA")
                assert _max_authority_ttl(cached_nodata) <= SIG_VALIDITY_S
    finally:
        resp.stop()
