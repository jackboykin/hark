# Harness gap: cannot author "auth response carries OPT record" scenario

The `.rpl` responder builds replies via `dns.message.make_response(query, ...)`.
When hark's upstream query carries an EDNS OPT (which it always does — see
`src/resolver.zig:16` `dns.buildQuery(... .edns = .{})`), dnspython
auto-attaches its own OPT to the response and stores it on `msg.opt`,
*separate* from `msg.additional`. The responder then overwrites
`r.additional = list(entry.additional)` but the auto-OPT survives. Any OPT
record we add via `SECTION ADDITIONAL` (e.g., `. 1232 IN OPT`) becomes a
*second* OPT on the wire, which hark correctly rejects per RFC 6891 §6.1.1
(`error.MultipleOptRecords`) — so the test breaks before it can observe
the intended behavior.

Compounding this: `rpl._split_rr_line` hard-rejects non-`{IN,CH,HS}` class
tokens, so we can't write `. 0 CLASS1232 OPT` to put the requestor's
UDP-payload size in the CLASS slot per RFC 6891 §6.1.3 — the parser would
need to accept the dnspython `CLASS<n>` numeric class form.

To unlock this scenario, the harness would need either:
  (a) a responder knob like `ADJUST no_edns` that calls `r.use_edns(False)`
      before serializing, suppressing the auto-OPT so the scenario controls
      OPT presence end-to-end; or
  (b) extend `_split_rr_line` to accept `CLASS<n>` (RFC 3597 §5 generic
      class) and have the responder NOT add an auto-OPT when SECTION
      ADDITIONAL contains an explicit OPT.

The scenario this would unlock: assert that hark accepts (and round-trips)
upstream responses carrying EDNS options it doesn't recognize, e.g. EDE
(RFC 8914) or ECS (RFC 7871), in compliance with the RFC 6891 §6.1.2
"forward compatibility" rule that unknown options MUST NOT cause an
otherwise-valid response to be discarded.

In the meantime: dnspython's auto-OPT means every passing scenario in
this tree implicitly exercises hark's "parse a response that carries
EDNS OPT" path — the gap is specifically about *controlled* OPT shape
(payload size, version, DO bit, options).
