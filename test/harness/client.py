"""Stub DNS client + assertion helpers for the L4 driver."""

from __future__ import annotations

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from . import rpl
from .responder import QueryLog


def send_query(entry: rpl.Entry, hark_addr: tuple[str, int], timeout: float = 5.0) -> dns.message.Message:
    """Build a query from a STEP QUERY entry and send it to hark."""
    if not entry.question:
        raise ValueError("STEP QUERY entry has no QUESTION section")
    q = entry.question[0]
    msg = dns.message.make_query(q.name, q.rdtype, q.rdclass)
    msg.flags = entry.reply_flags  # in QUERY entries, REPLY carries client flags
    return dns.query.udp(msg, hark_addr[0], port=hark_addr[1], timeout=timeout)


def send_raw_query(qname: str, rdtype: str, hark_addr: tuple[str, int], timeout: float = 5.0) -> dns.message.Message:
    """Send a query without an `Entry`. Used by the TIME_PASSES handler to
    hit hark's `_advance-clock` control channel without modelling it as a
    scenario query."""
    msg = dns.message.make_query(qname, rdtype)
    return dns.query.udp(msg, hark_addr[0], port=hark_addr[1], timeout=timeout)


_ALL_CHECKS = frozenset({"rcode", "flags", "question", "answer", "authority", "additional"})


def assert_answer_matches(actual: dns.message.Message, expected: rpl.Entry) -> None:
    """Assert that hark's response matches a CHECK_ANSWER entry's directives.

    Empty MATCH set defaults to `MATCH all` minus TTL comparison (TTLs differ
    between hark and any oracle in ways that are not bugs).
    """
    flags = expected.match or {"all"}
    checks = _ALL_CHECKS if "all" in flags else flags
    compare_ttl = "ttl" in flags

    # Rcode lives in the header alongside the flag bits — `MATCH flags`
    # covers it implicitly, as does `MATCH rcode`.
    if checks & {"rcode", "flags"} and actual.rcode() != expected.reply_rcode:
        raise AssertionError(
            f"rcode mismatch: expected {dns.rcode.to_text(expected.reply_rcode)} "
            f"got {dns.rcode.to_text(actual.rcode())}"
        )

    if "flags" in checks:
        # Compare only the response-relevant flag bits. RD is set by the
        # client; CD likewise. AA is for authoritative responses. AD/RA/TC
        # are response bits we genuinely care about.
        mask = dns.flags.QR | dns.flags.AA | dns.flags.TC | dns.flags.RA | dns.flags.AD
        if (actual.flags & mask) != (expected.reply_flags & mask):
            raise AssertionError(
                f"flags mismatch: expected {expected.reply_flags & mask:04x} "
                f"got {actual.flags & mask:04x}"
            )

    if "question" in checks:
        if [_q_tuple(r) for r in actual.question] != [_q_tuple(r) for r in expected.question]:
            raise AssertionError(f"QUESTION mismatch:\n  got: {actual.question}\n  want: {expected.question}")

    if "answer" in checks:
        _assert_section_matches("ANSWER", actual.answer, expected.answer, compare_ttl)
    if "authority" in checks:
        # Authority sections often include implementation-specific SOA TTLs
        # in NODATA/NXDOMAIN; only compare names/types/rdata.
        _assert_section_matches("AUTHORITY", actual.authority, expected.authority, compare_ttl)
    if "additional" in checks:
        # Skip OPT pseudo-RR in additional comparisons unless explicitly requested.
        filtered = [rs for rs in actual.additional if rs.rdtype != dns.rdatatype.OPT]
        _assert_section_matches("ADDITIONAL", filtered, expected.additional, compare_ttl)


def _q_tuple(r: dns.rrset.RRset) -> tuple:
    return (r.name.to_text().lower(), r.rdclass, r.rdtype)


def _assert_section_matches(label: str, actual: list, expected: list, compare_ttl: bool) -> None:
    got = sorted(_normalize_rrset(r, compare_ttl) for r in actual)
    want = sorted(_normalize_rrset(r, compare_ttl) for r in expected)
    if got != want:
        raise AssertionError(
            f"{label} mismatch:\n  got:  {got}\n  want: {want}"
        )


def _normalize_rrset(r: dns.rrset.RRset, compare_ttl: bool) -> tuple:
    ttl = r.ttl if compare_ttl else 0
    # DNS names are case-insensitive (RFC 4343), and 0x20 randomization +
    # wire-format compression leaks query-side randomized case into rdata
    # for name-bearing types (CNAME, NS, MX, PTR, ...). Compare in canonical
    # lowercase form. Non-name rdata (A, AAAA, TXT, etc.) are unaffected by
    # lowercase at the surface form used here, except TXT — but scenarios
    # that need case-preserved TXT can switch to `MATCH ttl` (deferred).
    rdatas = tuple(sorted(rd.to_text().lower() for rd in r))
    return (r.name.to_text().lower(), r.rdclass, r.rdtype, ttl, rdatas)


# ── Query-log assertions ─────────────────────────────────────────────────


def assert_out_query_matches(rec: QueryLog, expected: rpl.Entry) -> None:
    """Assert a single logged upstream query matches an expected ENTRY template.

    Used by `STEP n CHECK_OUT_QUERY`. The expected entry's QUESTION carries
    `qname [qclass] qtype`; MATCH flags pick which fields are compared.
    `qname`, `qtype`, `qclass`, and `opcode` are supported (opcode is checked
    only nominally since the responder always sees QUERY in test traffic).
    """
    if not expected.question:
        raise ValueError("CHECK_OUT_QUERY entry has no QUESTION section")
    flags = expected.match or {"question"}
    if "question" in flags:
        flags = flags | {"qname", "qtype", "qclass"}
    eq = expected.question[0]
    expected_qname = eq.name.to_text().lower()
    expected_qtype = dns.rdatatype.to_text(eq.rdtype)
    expected_qclass = dns.rdataclass.to_text(eq.rdclass)

    failures: list[str] = []
    if "qname" in flags and rec.qname != expected_qname:
        failures.append(f"qname: got {rec.qname!r}, want {expected_qname!r}")
    if "qtype" in flags and rec.qtype != expected_qtype:
        failures.append(f"qtype: got {rec.qtype!r}, want {expected_qtype!r}")
    if "qclass" in flags and rec.qclass != expected_qclass:
        failures.append(f"qclass: got {rec.qclass!r}, want {expected_qclass!r}")
    if failures:
        raise AssertionError(
            "CHECK_OUT_QUERY mismatch:\n  " + "\n  ".join(failures)
            + f"\n  (dest={rec.address})"
        )


def assert_query_log_matches(log: list[QueryLog], expected: rpl.Entry) -> None:
    """Assert that the captured upstream-query log matches a CHECK_QUERY_LOG entry.

    Expects `SECTION QUERY_LOG` rows of `<qname> <qtype> [<dest>]`. `MATCH order`
    requires the listed sequence to appear as an ordered subsequence of the log;
    otherwise we check presence only. If `dest` is present on a row, the log
    record's destination address is also asserted; otherwise dest is wildcarded
    on a row-by-row basis (mixing dest-bound and dest-free rows is allowed).
    """
    if not expected.query_log:
        raise ValueError("CHECK_QUERY_LOG entry has no SECTION QUERY_LOG rows")

    require_order = "order" in (expected.match or set())

    expected_records: list[tuple[str, str, str | None]] = [
        (qname.lower(), qtype, dest)
        for (qname, qtype, dest) in expected.query_log
    ]

    def matches(rec: QueryLog, want: tuple[str, str, str | None]) -> bool:
        qname, qtype, dest = want
        return (
            rec.qname == qname
            and rec.qtype == qtype
            and (dest is None or rec.address == dest)
        )

    log_records = [(rec.qname, rec.qtype, rec.address) for rec in log]

    if require_order:
        idx = 0
        for rec in log:
            if idx < len(expected_records) and matches(rec, expected_records[idx]):
                idx += 1
        if idx != len(expected_records):
            raise AssertionError(
                f"CHECK_QUERY_LOG order mismatch:\n  log:  {log_records}\n  want: {expected_records}"
            )
    else:
        missing = [w for w in expected_records if not any(matches(rec, w) for rec in log)]
        if missing:
            raise AssertionError(
                f"CHECK_QUERY_LOG missing entries: {missing}\n  log: {log_records}"
            )
