# Cross-cutting divergences: hark vs. Unbound

This is the human-readable companion to `manifest.py`. The manifest is the
machine-checked source of truth: every lifted Unbound `.rpl` scenario runs,
and each one that hark answers differently carries an `xfail_reason` string
and runs **xfail-strict** — if hark ever starts matching Unbound on that
scenario, pytest reports an *unexpected pass* and the suite goes red, forcing
whoever closed the gap to come back and revise this picture.

So the manifest tells you *which* scenarios diverge, one line each. This doc
groups them into the handful of underlying reasons and says, for each,
whether it is a deliberate choice, an unimplemented feature, or a limit of
the test harness.

The lifted `.rpl` fixtures themselves are vendored from Unbound under
BSD-3-Clause; see `../../corpus/unbound/PROVENANCE` for the upstream commit
and refresh procedure.

---

## 1. QNAME-minimisation probe shape — *defensible*

**Scenarios:** `iter_resolve_minimised.rpl`, `iter_resolve_minimised_timeout.rpl`

Unbound, when minimising QNAMEs, sends an extra explicit `A` probe to the
target name before issuing the query at the originally-requested qtype. Hark
merges the final probe and the original-qtype query at the target name, so it
emits one fewer upstream packet. The `CHECK_QUERY_LOG` assertion in these
scenarios counts the missing probe and fails.

RFC 9156 §3.2 explicitly permits both shapes — a resolver *MAY* use the
original qtype for the final QM query instead of a dedicated `A`/`NS` probe.
Hark takes the MAY. The behaviour visible to the stub client is identical;
only the on-the-wire upstream packet count differs.

**Verdict:** standards-compliant, fewer packets. Not a bug.

---

## 2. Strict bailiwick vs. promiscuous glue — *defensible (security)*

**Scenario:** `iter_cycle_noh.rpl`

This scenario breaks an `NS-A ↔ NS-B` delegation cycle by accepting
out-of-bailiwick glue — it is written for Unbound run with `harden-glue: no`.
Hark's default is strict bailiwick: glue that falls outside the delegated
zone is discarded, so hark cannot use the out-of-bailiwick address to break
the cycle and the resolution stalls where Unbound's would proceed.

Accepting promiscuous glue is a cache-poisoning vector; refusing it is the
secure default. A future `accept-promiscuous-glue` (or per-zone
`harden-glue: no` equivalent) knob would let this scenario pass without
weakening the default.

**Verdict:** hark is deliberately stricter than stock Unbound here. Gated
behind a knob that does not yet exist.

---

## 3. DNAME residue — *three separate reasons, none of them synthesis*

**Scenarios:** `iter_dname_insec.rpl`, `iter_dname_ttl.rpl`, `iter_dname_ttl0.rpl`
(note: `iter_dname_yx.rpl` *passes* — the YXDOMAIN error path needs no synthesis.)

DNAME → CNAME synthesis (RFC 6672) is implemented: from a DNAME in the
response, and from a cached one. Each remaining scenario fails for its own
unrelated reason.

`iter_dname_ttl` — **harness limit.** Everything but the AD bit matches,
including the §2.2 TTL of the cache-synthesised CNAME. Its zones are signed
with Unbound's testbound-only `fake-sha1` under trust anchors declared in the
`server:` prelude that the lifter strips, so no conformant validator can
authenticate them and hark cannot reach AD=1 here. Same class as the
`iter_cname_minimise_nx` / `iter_class_any` files that are not vendored at
all; this one is kept because the rest of it is real coverage.

`iter_dname_ttl0` — **deliberate.** Same AD limit, plus the DNAME carries
TTL 0. Unbound serves 0-TTL records from a one-second cache grace window;
hark refuses to cache a zero-TTL RRset at all, so the second query has no
cached DNAME to synthesise from.

`iter_dname_insec` — **deliberate.** Cases 1–8 pass. Cases 9–12 are DNAMEs
that redirect into themselves, producing a self-referential CNAME. Unbound
answers NOERROR with the partial chain; hark treats a CNAME loop as an error
and SERVFAILs (RFC 1034 §3.6.2 asks for an error, without naming one). That
is a loop-signalling choice, not a DNAME one.

**Verdict:** one harness limit and two choices hark makes elsewhere and
would have to reverse globally; none of it is a DNAME gap.

---

## 4. Cached positive responses carry no AUTHORITY — *defensible (security)*

**Scenarios:** `iter_domain_sale.rpl`, `iter_domain_sale_nschange.rpl`

These exercise TTL expiry over a simulated clock advance. Hark *does* model
the clock — a synthetic monotonic clock behind `-Dtesting=true`
(`src/monotonic.zig:advanceTestClock`), driven by the harness via a control
query `_advance-clock.<N>.testharness.invalid.` on each `STEP n TIME_PASSES`
— and the TTL math is correct, which
`regression/007_time_passes_actually_advances_the_clock.rpl` asserts directly.

The divergence is elsewhere: the scenarios' `MATCH all` also asserts the
AUTHORITY section, and hark intentionally strips AUTHORITY NS records from
*cached positive* responses (`src/cache.zig:storeResponse`) as the
CVE-2025-11411 mitigation. Unbound caches and replays the authority section;
hark does not. So the answer section matches but the authority section does
not, and `MATCH all` fails.

One wrinkle sits in front of that in the vendored file: its authority entry
matches on `opcode qname` without qtype, so the cousin AAAA prefetch is
answered with the A RRset and re-stores it at full TTL. The ANSWER section
therefore mismatches before the AUTHORITY one does. Tightening the entry to
match qtype makes the answer pass and the failure land where this section
says it does.

**Verdict:** the TTL-expiry behaviour the scenarios were written to test
works correctly; the failure is a deliberate security-driven shaping choice
on a section the scenario happens to also assert. The mitigation: a recursive
resolver owes the stub client a correct *answer* section, but replaying a
cached *authority* section lets a stale or attacker-influenced NS set linger
past its usefulness — so hark serves cached positive answers without it.

---

## 5. Multi-NS fallthrough & stale-glue re-resolution — *mostly closed*

Not its own lifted scenario, but the connective tissue between several:
`iter_cname_cache.rpl` exercises the case where one NS's glue TTL expires and
the remaining siblings all SERVFAIL. Hark does not re-resolve the expired
NS's address, so it can give up where a re-resolving resolver would recover.

The broader "one failing NS must not condemn the resolution" story (RFC 1034
§4.3.5) is **fixed** for SERVFAIL / REFUSED / FORMERR via
`RCode.shouldTrySiblingNs`; see
`../hark/errors/multi_NS_fallthrough.divergence.md` for the full narrative,
the committed `004`–`006` scenarios, and the one remaining stale-glue gap.

**Verdict:** sibling-fallthrough closed; stale-glue re-resolution is the live
remainder.

---

## Fixtures deliberately not vendored

Two reasons an upstream `.rpl` is absent from `../../corpus/unbound/`
entirely rather than run-as-xfail:

### Non-portable upstream signatures

**Files:** `iter_cname_minimise_nx.rpl`, `iter_class_any.rpl`

Both depend on Unbound testbound-only machinery: `fake-sha1: yes`, the
`val-override-date` clock override, and a hardcoded test key fused into the
Unbound binary. The DNSSEC signatures in these fixtures are unverifiable by
*any* conformant validator, so there is nothing for hark to match. Equivalent
coverage is hark-authored under `../hark/dnssec/` using the harness's real
ECDSA signing.

### Harness can't run it

**File:** `iter_donotq127.rpl`

Asserts hark refuses to query 127/8 upstreams — but the test harness itself
*requires* 127/8 (the responder binds `127.0.10.x`). Running it would need a
per-CIDR `allow-loopback-upstreams` whitelist in hark plus a lifter rule to
exempt specific 127/8 IPs from loopback remapping. The underlying behaviour
is covered by the `isNonRoutableNs` unit test in `src/net_address.zig`.

---

## A note on the CNAME cluster

The `iter_cname_*` family (`_double`, `_minimise`, `_nx`, `_qnamecopy`,
`_cache`) once carried hark's largest divergence cluster — this document's
predecessor was named for it. As of the current manifest they all pass; the
only CNAME-adjacent live gap is the stale-glue re-resolution under §5. The
xfail-strict guard means that if a regression reopens any of them, the suite
will say so.
