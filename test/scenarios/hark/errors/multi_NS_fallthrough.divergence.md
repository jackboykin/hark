# Multi-NS fallthrough on upstream error rcodes — divergence (mostly closed)

**Status (2026-05-29): fixed for SERVFAIL / REFUSED / FORMERR.** The two-NS
fallthrough scenarios are committed as `004_servfail_first_NS_fallthrough_to_second
.rpl`, `005_refused_first_NS_fallthrough_to_second.rpl`, and
`006_formerr_first_NS_fallthrough_to_second.rpl`, all green. The recovery
scenarios have probabilistic teeth (randomized cold NS pick — see 004's
header); the deterministic all-fail siblings with CHECK_QUERY_LOG teeth are
`007` (FORMERR), `008` (SERVFAIL), `009` (REFUSED), each ablation-verified
to fail every run on a no-fallthrough `shouldTrySiblingNs`. FORMERR now
counts as a sibling-fallthrough signal via `RCode.shouldTrySiblingNs`
(deliberately distinct from `isServerError`, which still keys lame-scoring
and the DoT guard on SERVFAIL/REFUSED only). Sole-NS FORMERR still surfaces
verbatim to the stub via the all-NSes-failed exhaustion path (see 003). The
remaining gap is the stale-glue fallback case surfaced by `iter_cname_cache`
(when one NS's glue TTL expires and the remaining sibling NSes all SERVFAIL,
hark doesn't re-resolve the expired NS's address).

The original narrative is preserved below for context.

## What the scenarios *wanted* to assert

The errors/ category was authored against the RFC 1034 §4.3.5 expectation
that when a zone is delegated to multiple authoritative nameservers, a
failing rcode from one NS does not condemn the resolution — the resolver
must iterate to the remaining NSes before giving up.

Three aspirational scenarios were drafted (and then simplified to the
single-NS shape currently committed):

1. **SERVFAIL one NS → fallthrough to second.** Zone delegated to ns1
   (127.0.10.3) and ns2 (127.0.10.4); ns1 returns SERVFAIL on the leaf,
   ns2 returns the real A record. Expected: client sees the A record.

2. **REFUSED (lame) on one NS → fallthrough to second.** Same shape;
   ns1 returns REFUSED (the textbook lame-delegation signal); ns2
   answers. Expected: client sees the A record.

3. **FORMERR on all NSes → SERVFAIL to client.** Both ns1 and ns2 return
   FORMERR. Expected: client sees SERVFAIL (hark synthesises the failure
   rather than passing FORMERR through).

## What hark actually does

Run as committed (single-NS shape), hark passes. With the original
two-NS shape, all three failed in the same pattern:

- For (1) and (2): hark queries whichever NS it picks first. If it picks
  the *healthy* NS, the lookup succeeds and the CHECK_QUERY_LOG
  assertion fails because the failing NS was never contacted. If it
  picks the *failing* NS, the failing rcode is propagated to the client
  verbatim and ns2 is **never tried**. There is no fallthrough.
- For (3): hark contacts one NS, receives FORMERR, and propagates
  FORMERR to the client without trying the sibling.

Observed responder log for the SERVFAIL case where hark picked the
failing NS first:

```
127.0.10.1 <- . NS
127.0.10.1 <- com. A
127.0.10.2 <- example.com. A
127.0.10.3 <- www.example.com. A    # SERVFAIL — hark stops here
```

ns2 at 127.0.10.4 never receives the leaf query.

## RFC references

- **RFC 1034 §4.3.5** — resolvers must iterate over the listed NSes;
  one failure is not authoritative for the zone.
- **RFC 2308 §7.1** — SERVFAIL caching is optional and very short
  precisely because it is not authoritative.
- **RFC 8914** — EDE-20 (NotAuthoritative), EDE-22 (NoReachableAuthority)
  are the standard advisory signals once *all* NSes have been tried.

## Why this is a real finding, not a test artifact

Real-world delegations frequently have a partially-broken NS — backend
outages at one provider, a misconfigured anycast node, a half-rolled
software upgrade. Resolvers that don't iterate over siblings either
report SERVFAIL to users for names that are otherwise reachable, or
exhibit flaky behaviour depending on which NS they happen to pick first.
Hark currently has the second mode (flaky picker) for SERVFAIL and
REFUSED, and the "passthrough FORMERR" mode for FORMERR.

## Remaining gaps

- Stale-glue fallback (see status note above): when one NS's glue TTL
  expires and the remaining siblings all SERVFAIL, hark doesn't
  re-resolve the expired NS's address.
- Rcode shaping at the client boundary: upstream FORMERR / REFUSED are
  passed through verbatim on the exhaustion path. Remapping them to
  SERVFAIL (they describe server-side conditions meaningless to a stub)
  remains an option; scenarios 002/003 pin the current passthrough.
