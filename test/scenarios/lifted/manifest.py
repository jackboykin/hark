"""Manifest of Unbound `.rpl` scenarios lifted from `vendor/unbound/testdata/`.

The .rpl source of truth lives in the submodule. This manifest is the
only hark-repo record of the lift: which files run, and which document a
hark/Unbound behavioural divergence. We don't copy or symlink — conftest
walks this manifest, applies the on-the-fly transform in
`test/harness/unbound_lift.py` (strips the `server:` / `CONFIG_END`
prelude, remaps real internet IPs to loopback), and yields pytest items.

Every entry runs. None are skipped:

  - `xfail_reason=None` → ordinary test, must pass.
  - `xfail_reason=<str>` → test runs and is **expected to fail strict**.
    If hark ever passes one of these, pytest reports an unexpected pass
    and the suite fails — forcing the divergence note to be revisited.

Currently blocked (NOT in the manifest, can't even run):

  - `iter_donotq127.rpl` — asserts hark blocks 127/8 upstreams; our test
    harness *requires* 127/8 (the responder binds 127.0.10.x). Would need
    a per-CIDR `allow-loopback-upstreams` whitelist in hark plus a lifter
    rule to preserve specific 127/8 IPs without remapping. Structural,
    1 scenario.

Previously blocked, now in the manifest:

  - `iter_cname_cache.rpl` (IPv6) — lifter maps the single v6 ADDRESS to
    `::1`; responder binds AF_INET6 sockets in parallel with AF_INET.
  - `iter_domain_sale.rpl`, `iter_domain_sale_nschange.rpl` (TIME_PASSES)
    — hark exposes a synthetic monotonic clock behind `-Dtesting=true`
    (`src/monotonic.zig:advanceTestClock`); the harness drives it via a
    control DNS query `_advance-clock.<N>.testharness.invalid.` on
    `STEP n TIME_PASSES`.

The cross-cutting picture of divergences is in
`~/.claude/projects/.../memory/cname-divergence-from-unbound.md` and
`iterative-dispatch-gaps.md`.
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class LiftedEntry:
    filename: str
    category: str
    xfail_reason: str | None  # None = run-and-must-pass; str = run-and-must-xfail (strict)


MANIFEST: list[LiftedEntry] = [
    # iter_resolve — basic delegation chase + QNAME-minimisation variants
    LiftedEntry("iter_resolve.rpl",                       "iter_resolve",     None),
    LiftedEntry("iter_resolve_minimised_nx.rpl",          "iter_resolve",     None),
    LiftedEntry("iter_resolve_minimised_refused.rpl",     "iter_resolve",     None),
    LiftedEntry("iter_resolve_minimised.rpl",             "iter_resolve",     "hark QMIN merges probe+final at the target name; Unbound sends an extra A-probe before the original-qtype query. RFC 9156 §3.2 permits both ('MAY use the original qtype for the QM query')."),
    LiftedEntry("iter_resolve_minimised_timeout.rpl",     "iter_resolve",     "same QMIN-at-target divergence as iter_resolve_minimised"),

    # iter_cname — CNAME-chase edges; cluster of hark divergences (xfail strict)
    LiftedEntry("iter_cname_double.rpl",                  "iter_cname",       None),
    LiftedEntry("iter_cname_minimise.rpl",                "iter_cname",       None),
    LiftedEntry("iter_cname_minimise_nx.rpl",             "iter_cname",       "scenario requires DNSSEC trust-anchor + fake-sha1 (CHECK_ANSWER asserts AD+RRSIG); harness doesn't model trust anchors yet — same blocker as iter_class_any"),
    LiftedEntry("iter_cname_nx.rpl",                      "iter_cname",       None),
    LiftedEntry("iter_cname_qnamecopy.rpl",               "iter_cname",       None),
    # iter_cname_cache uses an IPv6 ADDRESS (`2002::5`). The lifter maps
    # the single v6 address to `::1` (the only unprivileged v6 loopback)
    # and the responder binds an AF_INET6 socket alongside the v4 sockets.
    LiftedEntry("iter_cname_cache.rpl",                   "iter_cname",       "hark behaviour diverges: when one delegation NS's glue expires (TTL=1) and the remaining sibling NSes all SERVFAIL, hark doesn't re-resolve the expired NS's address (stale-glue corner of the lame-NS fallthrough class)"),

    # iter_cycle — NS-cycle / loop-detection
    LiftedEntry("iter_cycle.rpl",                         "iter_cycle",       None),
    LiftedEntry("iter_cycle_noh.rpl",                     "iter_cycle",       "scenario requires accepting out-of-bailiwick glue (Unbound `harden-glue: no`) to break a NS-A↔NS-B delegation cycle. Hark's strict-bailiwick default is the secure choice; a future `accept-promiscuous-glue` knob would let this pass — defensible difference."),

    # iter_dname — DNAME synthesis (RFC 6672); hark diverges across the board
    LiftedEntry("iter_dname_yx.rpl",                      "iter_dname",       None),
    LiftedEntry("iter_dname_insec.rpl",                   "iter_dname",       "hark behaviour diverges: DNAME synthesis (RFC 6672) not implemented"),
    LiftedEntry("iter_dname_ttl.rpl",                     "iter_dname",       "hark behaviour diverges: DNAME synthesis (RFC 6672) not implemented"),
    LiftedEntry("iter_dname_ttl0.rpl",                    "iter_dname",       "hark behaviour diverges: DNAME synthesis (RFC 6672) not implemented"),

    # iter_class_any — non-IN class handling. Scenario also requires DNSSEC
    # trust-anchor + fake-sha1 — out of scope for plain-DNS scenarios.
    LiftedEntry("iter_class_any.rpl",                     "iter_class_any",   "scenario requires DNSSEC trust-anchor + fake-sha1; harness doesn't model trust anchors yet"),

    # iter_domain_sale — needs test-clock to observe TTL expiry. Hark
    # implements one behind `-Dtesting=true` (see `src/monotonic.zig`); the
    # harness drives it via a control DNS query on `STEP n TIME_PASSES`.
    # TTL math works (cached records return decremented TTLs after the
    # clock advance), but the scenario's `MATCH all` also asserts the
    # AUTHORITY section, which hark intentionally strips from cached
    # positive responses per CVE-2025-11411 — Unbound caches authority,
    # we don't. Defensible difference.
    LiftedEntry("iter_domain_sale.rpl",                   "iter_domain_sale", "hark behaviour diverges: cached positive responses don't carry AUTHORITY NS records (CVE-2025-11411 mitigation; see src/cache.zig:storeResponse). TTL expiry itself works correctly."),
    LiftedEntry("iter_domain_sale_nschange.rpl",          "iter_domain_sale", "hark behaviour diverges: see iter_domain_sale (CVE-2025-11411 mitigation)"),
]


def all_entries() -> list[LiftedEntry]:
    return list(MANIFEST)
