# Cross-cutting divergences: hark vs. Unbound

The sim replays every vendored Unbound `.rpl` here, and the ones hark
answers differently are listed in `src/sim/replay.zig` as expected failures,
strict: if hark ever matches Unbound on one, the gate goes red and this
picture needs revisiting. This doc groups them by underlying reason and says
whether each is a deliberate choice, an unimplemented feature, or a limit of
the fixtures.

The fixtures are vendored under BSD-3-Clause; see `PROVENANCE`.

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

`iter_dname_ttl` — **fixture limit.** Everything but the AD bit matches,
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

**Verdict:** one fixture limit and two choices hark makes elsewhere and
would have to reverse globally; none of it is a DNAME gap.

---

## 4. Cached positive responses carry no AUTHORITY — *defensible (security)*

**Scenarios:** `iter_domain_sale.rpl`, `iter_domain_sale_nschange.rpl`

These exercise TTL expiry over a clock advance. The TTL math is correct,
which `regression/007_time_passes_actually_advances_the_clock.rpl` asserts
directly.

The divergence is elsewhere: the scenarios' `MATCH all` also asserts the
AUTHORITY section, and hark intentionally strips AUTHORITY NS records from
*cached positive* responses as the
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

## 5. An NS name that is an alias — *passes, by another road*

**Scenario:** `iter_cname_cache.rpl`

`example.com.` is served by `ns.example.com.`, glued by `com.` for one
second and a CNAME to `ns.bla.nl.` in its own zone, and by
`ns2.example.com.`, which always SERVFAILs. Unbound follows the alias to
reach the zone. Hark passes without following it: a glued server is reached
at its glue alone, whatever its own zone says it is, and a referral lives no
longer than its glue, so once the second is up `com.` is asked again and the
glue it gives reaches the server.

An NS name with no glue is reached only through its own zone, and there hark
still does not follow an alias: RFC 2181 §10.3 says an NS name MUST NOT be
one, so such a name has no address for as long as the CNAME lives. Following
it means trusting an address whose cause is a record at another name, in
another zone. `../../scenarios/hark/glue/011_a_glued_server_is_reached_whatever_its_zone_says_it_is.rpl`
holds both.

**Verdict:** the same answer for a different reason; nothing to change.

The broader "one failing NS must not condemn the resolution" story (RFC 1034
§5.3.3) is covered by
`../../scenarios/hark/errors/001_any_rcode_but_an_answers_moves_to_a_sibling.rpl`.

---

## 6. A negative without its SOA is no answer — *deliberate (RFC 2308 §3)*

**Scenario:** `iter_cname_nx.rpl`

The fixture's `www.next.com` server answers AA NXDOMAIN with an empty
authority section. RFC 2308 §3 says an authoritative server MUST put its
zone's SOA there; without it the denial names no zone and carries no
negative TTL. Unbound takes the rcode anyway; hark treats any negative
without its SOA, NXDOMAIN or NODATA, as no answer and moves on, so with no
other server the chain ends SERVFAIL. Pinned in hark's own suite by
errors/033.

**Verdict:** strict on a broken server, by choice. Not a bug.

---

## Fixtures not vendored

Upstream `.rpl`s absent from this directory rather than run as expected
failures:

### Non-portable upstream signatures

**Files:** `iter_cname_minimise_nx.rpl`, `iter_class_any.rpl`

Both depend on Unbound testbound-only machinery: `fake-sha1: yes`, the
`val-override-date` clock override, and a hardcoded test key fused into the
Unbound binary. The DNSSEC signatures in these fixtures are unverifiable by
*any* conformant validator, so there is nothing for hark to match. Equivalent
coverage is hark-authored under `../../scenarios/hark/dnssec/`, signed for
real.

### Not yet tried

**File:** `iter_donotq127.rpl`

Asserts hark refuses to query 127/8 upstreams. It was left out because the
live harness's responders bound `127.0.10.x`; the sim binds nothing, so it
may run as is. The behaviour is covered by the `isNonRoutableNs` unit test in
`src/net_address.zig`.

---

## A note on the CNAME cluster

The `iter_cname_*` family (`_double`, `_minimise`, `_qnamecopy`) all
pass, and so does `_cache`, for the reason §5 gives; `_nx` diverges (§6).
If a regression reopens any of them, the gate says so.
