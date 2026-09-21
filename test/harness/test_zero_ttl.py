"""A TTL-0 record is never cached, and `min-ttl` does not raise it.

RFC 1035 §4.1.3 / RFC 2181 §8: a zero TTL means "use for this transaction
only". `min-ttl` floors short TTLs to shape upstream load, but a zero is the
authority saying "do not cache", not a short TTL, so the second query must
reach the authority again. Unbound applies its floor to TTL 0 as well.
"""

from __future__ import annotations

import textwrap

import conftest

from . import rpl
from .client import send_raw_query

SCENARIO = textwrap.dedent(
    """\
    ; hark: root-hints = 127.0.10.1
    ; hark: min-ttl = 60
    ; hark: qname-minimisation = no

    SCENARIO_BEGIN a TTL-0 answer is fetched again under min-ttl
    RANGE_BEGIN 0 100
      ADDRESS 127.0.10.1
      ENTRY_BEGIN
        MATCH opcode qname qtype
        ADJUST copy_id copy_query
        REPLY QR AA NOERROR
        SECTION QUESTION
          example.com. IN A
        SECTION ANSWER
          example.com. 0 IN A 192.0.2.1
      ENTRY_END
    RANGE_END
    SCENARIO_END
    """
)


def test_ttl_zero_ignores_min_ttl(tmp_path):
    path = tmp_path / "ttl_zero.rpl"
    path.write_text(SCENARIO)
    with conftest.scenario_env(rpl.parse(path)) as (resp, _):
        for _ in range(2):
            send_raw_query("example.com.", "A", conftest.HARK_LISTEN)
        hits = [r for r in resp.query_log if r.qname == "example.com." and r.qtype == "A"]
    assert len(hits) == 2, f"a TTL-0 answer was served from cache: {resp.query_log}"
