"""L4 scenario-driven test harness for hark.

Conventions a scenario author needs to know (gathered from across the
modules so contributors don't have to spelunk):

  * **Process model.** Scenarios run inside the pytest process; hark is
    the subprocess, spawned per scenario (hark_proc.py).

  * **Addresses & ports.** Responders bind fixed 127.0.10.* RANGE
    addresses on RESP_PORT (default 5353); hark listens on RESP_PORT+1.
    Under pytest-xdist each worker offsets the *ports* only
    (conftest.py:_worker_offset) — addresses never change. Root-hints in
    `.rpl` scenarios are bare IPs; conftest.py:_with_port stamps the
    port on.

  * **`; hark: root-hints = <ip>[, <ip>...]`** — required header directive
    in every scenario. Names the fake roots hark will be configured with.

  * **Transports.** The responder serves UDP and TCP on every address;
    `MATCH UDP` / `MATCH TCP` restrict an entry to one transport
    (TC-fallback scenarios).

  * **`REPLY` without `QR`** is treated as `REPLY QR ...` by the
    responder (responder.py forces QR=1). Scenarios still SHOULD include
    `QR` for testbound compatibility.

  * **`ADJUST copy_id`** is a no-op in this responder — dnspython's
    `make_response` already copies the query ID. Kept in scenarios for
    testbound/Stelline compatibility.

  * **`CHECK_QUERY_LOG`** takes `SECTION QUERY_LOG` rows of
    `<qname> <qtype> [<dest>]`. Presence check by default; `MATCH order`
    requires the rows as an ordered subsequence of the log; a row
    without `dest` wildcards the destination.

  * **`MATCH` defaults differ by context.** Responder entries default to
    `MATCH question` (qname + qtype + qclass). CHECK_ANSWER entries
    default to `MATCH all`. This matches .rpl convention but is a footgun.

  * **`TIME_PASSES`** advances hark's synthetic test clock via a
    `_advance-clock.<N>.testharness.invalid.` control query
    (conftest.py; requires a `-Dtesting=true` build).
"""
