"""Stub DNS client + assertion helpers for the L4 driver."""

from __future__ import annotations

import dns.flags
import dns.message
import dns.query
import dns.rcode
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


def assert_query_log_matches(log: list[QueryLog], expected: rpl.Entry) -> None:
    """Assert that the captured upstream-query log matches a CHECK_QUERY_LOG entry.

    Expected entry's QUESTION section is interpreted as: each `name type` record
    is one expected upstream query. `MATCH order` requires the listed sequence
    to appear in the log in order; otherwise we check presence only.

    If the ANSWER section is present, each A record's rdata is interpreted as
    the expected destination address; otherwise the assertion is on (qname, qtype).
    """
    if not expected.answer and not expected.question:
        raise ValueError("CHECK_QUERY_LOG entry has no expectations")

    flags = expected.match or set()
    require_order = "order" in flags
    require_address = bool(expected.answer)

    # Build expected list. If ANSWER section has A records, those are the
    # destination IPs. Otherwise we only check (qname, qtype) in QUESTION.
    expected_records: list[tuple[str, str, str | None]] = []
    source = expected.answer if require_address else expected.question
    for rrset in source:
        qname = rrset.name.to_text().lower()
        qtype = dns.rdatatype.to_text(rrset.rdtype)
        if require_address:
            expected_records.extend((qname, qtype, rd.to_text()) for rd in rrset)
        else:
            expected_records.append((qname, qtype, None))

    log_records = [
        (rec.qname, rec.qtype, rec.address if require_address else None)
        for rec in log
    ]

    if require_order:
        # Subsequence check: expected must appear as an ordered subsequence of log.
        idx = 0
        for rec in log_records:
            if idx < len(expected_records) and rec == expected_records[idx]:
                idx += 1
        if idx != len(expected_records):
            raise AssertionError(
                f"CHECK_QUERY_LOG order mismatch:\n  log:  {log_records}\n  want: {expected_records}"
            )
    else:
        missing = [r for r in expected_records if r not in log_records]
        if missing:
            raise AssertionError(
                f"CHECK_QUERY_LOG missing entries: {missing}\n  log: {log_records}"
            )
