"""Manifest of Unbound `.rpl` scenarios lifted from `test/corpus/unbound/`.

The .rpl files are vendored (BSD-3-Clause; see PROVENANCE for upstream
commit). This manifest is the hark-repo record of the lift: which files
run, and which document a hark/Unbound behavioural divergence. Conftest
walks this manifest, applies the on-the-fly transform in
`test/harness/unbound_lift.py` (strips the `server:` / `CONFIG_END`
prelude, remaps real internet IPs to loopback), and yields pytest items.

Every entry runs. None are skipped:

  - `xfail_reason=None` → ordinary test, must pass.
  - `xfail_reason=<str>` → test runs and is **expected to fail strict**.
    If hark ever passes one of these, pytest reports an unexpected pass
    and the suite fails — forcing the divergence note to be revisited.

Upstream fixtures deliberately not vendored (absent from
`test/corpus/unbound/` entirely):

  - `iter_donotq127.rpl` — asserts hark blocks 127/8 upstreams; this
    harness *requires* 127/8 (the responder binds 127.0.10.x), so the
    scenario cannot run here. The underlying behaviour is covered by the
    `isNonRoutableNs` unit test in `src/net_address.zig`.

  - `iter_cname_minimise_nx.rpl`, `iter_class_any.rpl` — both depend on
    Unbound's testbound-only `fake-sha1: yes` algorithm,
    `val-override-date` clock override, and a hardcoded test key fused
    into the Unbound binary. The signatures are unverifiable by any
    conformant validator. Replacement coverage is hark-authored DNSSEC
    scenarios under `test/scenarios/hark/dnssec/` using the harness's
    real ECDSA signing.

Previously blocked, now in the manifest:

  - `iter_cname_cache.rpl` (IPv6) — lifter maps the single v6 ADDRESS to
    `::1`; responder binds AF_INET6 sockets in parallel with AF_INET.
  - `iter_domain_sale.rpl`, `iter_domain_sale_nschange.rpl` (TIME_PASSES)
    — hark exposes a synthetic monotonic clock behind `-Dtesting=true`
    (`src/monotonic.zig:advanceTestClock`); the harness drives it via a
    control DNS query `_advance-clock.<N>.testharness.invalid.` on
    `STEP n TIME_PASSES`.

The cross-cutting picture — the handful of underlying reasons behind the
per-entry `xfail_reason` strings below, and whether each is a deliberate
choice, an unimplemented feature, or a harness limit — is in `DIVERGENCES.md`
alongside this file.
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
    # iter_cname_minimise_nx is not vendored — see the "deliberately not
    # vendored" section of the module docstring.
    LiftedEntry("iter_cname_nx.rpl",                      "iter_cname",       None),
    LiftedEntry("iter_cname_qnamecopy.rpl",               "iter_cname",       None),
    # iter_cname_cache uses an IPv6 ADDRESS (`2002::5`). The lifter maps
    # the single v6 address to `::1` (the only unprivileged v6 loopback)
    # and the responder binds an AF_INET6 socket alongside the v4 sockets.
    LiftedEntry("iter_cname_cache.rpl",                   "iter_cname",       None),

    # iter_cycle — NS-cycle / loop-detection
    LiftedEntry("iter_cycle.rpl",                         "iter_cycle",       None),
    LiftedEntry("iter_cycle_noh.rpl",                     "iter_cycle",       "scenario requires accepting out-of-bailiwick glue (Unbound `harden-glue: no`) to break a NS-A↔NS-B delegation cycle. Hark's strict-bailiwick default is the secure choice; a future `accept-promiscuous-glue` knob would let this pass — defensible difference."),

    # iter_dname — DNAME synthesis (RFC 6672); hark diverges across the board
    LiftedEntry("iter_dname_yx.rpl",                      "iter_dname",       None),
    LiftedEntry("iter_dname_insec.rpl",                   "iter_dname",       "hark behaviour diverges: DNAME synthesis (RFC 6672) not implemented"),
    LiftedEntry("iter_dname_ttl.rpl",                     "iter_dname",       "hark behaviour diverges: DNAME synthesis (RFC 6672) not implemented"),
    LiftedEntry("iter_dname_ttl0.rpl",                    "iter_dname",       "hark behaviour diverges: DNAME synthesis (RFC 6672) not implemented"),

    # iter_class_any is not vendored — see the "deliberately not vendored"
    # section of the module docstring.

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
