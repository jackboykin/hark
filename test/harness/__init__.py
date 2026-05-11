"""L4 scenario-driven test harness for hark.

Conventions a scenario author needs to know (gathered from across the
modules so contributors don't have to spelunk):

  * **Loopback IPs.** Scenarios bind RANGE addresses on 127.0.10.* (the
    second octet is the per-worker /16 slice; see conftest.py:_worker_offset).
    Each scenario lives in its own subprocess; addresses don't collide.

  * **Ports.** Responders bind on RESP_PORT (default 5353, offset per
    xdist worker). Hark listens on RESP_PORT+1. Root-hints in `.rpl`
    scenarios are written as bare IPs — the harness stamps the port on
    via conftest.py:_with_port.

  * **`; hark: root-hints = <ip>[, <ip>...]`** — required header directive
    in every scenario. Names the fake roots hark will be configured with.

  * **`REPLY` without `QR`** is treated as `REPLY QR ...` by the
    responder (responder.py forces QR=1). Scenarios still SHOULD include
    `QR` for testbound compatibility.

  * **`ADJUST copy_id`** is a no-op in this responder — dnspython's
    `make_response` already copies the query ID. Kept in scenarios for
    testbound/Stelline compatibility.

  * **`CHECK_QUERY_LOG` with QUESTION-only** checks presence of each
    `(qname, qtype)` tuple in the upstream-query log. With ANSWER A
    records (where rdata is the destination IP), checks `(qname, qtype,
    dest)` — but qtype is constrained by the A-record encoding, so
    AAAA destinations cannot currently be expressed.

  * **`MATCH` defaults differ by context.** Responder entries default to
    `MATCH question` (qname + qtype + qclass). CHECK_ANSWER entries
    default to `MATCH all`. This matches .rpl convention but is a footgun.

  * **`TIME_PASSES`** is parsed but not yet implemented — requires hark
    test-clock support, deferred to Month 3.

  * **TCP retry** — the responder is UDP-only. Scenarios that need to
    test TC-bit fallback will need TCP responder support. Track in plan.
"""
