"""Parser for the `.rpl` scenario format.

Subset of the format used by Unbound's `testbound`, Knot's Deckard, and Rust's
Stelline. Covers what hark's day-one scenarios need; not a complete .rpl spec.

Reference: https://github.com/NLnetLabs/unbound/blob/master/testcode/testbound.c
           https://docs.rs/domain/latest/domain/stelline/

Step kinds split into *actions* (do something to the system under test) and
*assertions* (CHECK_* — observe and verify):
  actions     — QUERY, TIME_PASSES, TIMEOUT
  assertions  — CHECK_ANSWER, CHECK_QUERY_LOG, CHECK_OUT_QUERY, CHECK_MAX_QUERIES

`TIMEOUT` is a responder-side directive disguised as a step: it pre-positions
a "drop the next incoming query" on the responder before the QUERY fires.

Hark-only extensions:
  - ; hark: root-hints = <ip> [, <ip>...]   header directive (required)
  - ; hark: qname-minimisation = no         header directive (optional)
  - ; hark: workers = <n>                   header directive (optional)
  - ; hark: dnssec-zone = <name>            declare a zone the harness signs
  - SIGN_AS <zone>                          force this entry's signer (forgeries)
  - WILDCARD <owner>                        sign this entry's answers as expansions of wildcard <owner>
  - <child> <ttl> IN DS PLACEHOLDER         real digest substituted at load
  - STEP n CHECK_QUERY_LOG                  set-style upstream-query check
  - STEP n CHECK_OUT_QUERY                  positional upstream-query check
  - STEP n CHECK_MAX_QUERIES <N>            assert <= N total upstream queries
  - SECTION QUERY_LOG                       `<qname> <qtype> [<dest>]` rows
  - MATCH UDP / MATCH TCP                   per-transport entry discrimination
"""

from __future__ import annotations

import dataclasses
import re
import shlex
from pathlib import Path

import dns.flags
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset


# Union of MATCH flags accepted anywhere (responder entries, CHECK_ANSWER,
# CHECK_QUERY_LOG) — used at parse time to catch typos like `MATCH quesiton`.
# No per-context validation exists: flags that a context does not honour
# (e.g. `tcp` on CHECK_ANSWER) parse fine and are silently ignored.
MATCH_VALID_FLAGS = frozenset({
    # responder-side (entry-matching)
    "opcode", "qname", "qtype", "qclass", "question", "subdomain",
    # transport-discrimination (Unbound testbound convention; flags are
    # uppercase on the wire `MATCH TCP` / `MATCH UDP`, normalized to
    # lowercase at parse time)
    "tcp", "udp",
    # CHECK_ANSWER
    "all", "answer", "authority", "additional", "flags", "rcode", "ttl",
    # CHECK_QUERY_LOG
    "order",
})

# ADJUST directive: dnspython's make_response already copies the ID, so
# copy_id is a no-op; copy_query echoes the query's QUESTION section.
# `force_lower_qname` opts the response out of the verbatim-echo default
# and forces the question name to lowercase — used to test hark's 0x20
# echo verification (`eqlExact` mismatch → markCaseBroken + retry).
ADJUST_VALID_FLAGS = frozenset({"copy_id", "copy_query", "force_lower_qname"})

# Section names → dnspython section indices via parse helper. QUERY_LOG is a
# hark-only section used inside CHECK_QUERY_LOG entries; lines are
# `<qname> <qtype> [<dest_ip>]`, decoupling qtype from rdata-type so
# AAAA-on-IPv4-dest is expressible.
SECTION_NAMES = frozenset({"QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL", "QUERY_LOG"})

# Reply flag tokens that map to DNS header bits.
REPLY_FLAGS = {
    "QR": dns.flags.QR,
    "AA": dns.flags.AA,
    "TC": dns.flags.TC,
    "RD": dns.flags.RD,
    "RA": dns.flags.RA,
    "AD": dns.flags.AD,
    "CD": dns.flags.CD,
}

# Rcode tokens accepted in REPLY directives.
REPLY_RCODES = {
    "NOERROR": dns.rcode.NOERROR,
    "FORMERR": dns.rcode.FORMERR,
    "SERVFAIL": dns.rcode.SERVFAIL,
    "NXDOMAIN": dns.rcode.NXDOMAIN,
    "NOTIMP": dns.rcode.NOTIMP,
    "REFUSED": dns.rcode.REFUSED,
    "YXDOMAIN": dns.rcode.YXDOMAIN,
}

# `DO` lives in the EDNS OPT extended-flags, not the header. On a STEP
# QUERY entry it sets `want_dnssec` so the client asks for DNSSEC data;
# on response-template entries it's a no-op (the responder serves whatever
# records the scenario declared).

# Opcode tokens (rare in REPLY but valid in MATCH opcode contexts).
REPLY_OPCODES = {
    "QUERY": dns.opcode.QUERY,
    "NOTIFY": dns.opcode.NOTIFY,
    "UPDATE": dns.opcode.UPDATE,
}


@dataclasses.dataclass
class Entry:
    """One ENTRY_BEGIN..ENTRY_END block: a query template or response template."""
    match: set[str] = dataclasses.field(default_factory=set)
    reply_flags: int = 0
    reply_rcode: int = dns.rcode.NOERROR
    reply_opcode: int = dns.opcode.QUERY
    question: list[dns.rrset.RRset] = dataclasses.field(default_factory=list)
    answer: list[dns.rrset.RRset] = dataclasses.field(default_factory=list)
    authority: list[dns.rrset.RRset] = dataclasses.field(default_factory=list)
    additional: list[dns.rrset.RRset] = dataclasses.field(default_factory=list)
    # CHECK_QUERY_LOG: each row is (qname, qtype, dest_ip_or_None).
    query_log: list[tuple[str, str, str | None]] = dataclasses.field(default_factory=list)
    # `REPLY DO` on a STEP QUERY entry: request DNSSEC data via EDNS.
    # No-op on response-template entries (the responder always returns
    # whatever records the scenario declared).
    want_dnssec: bool = False
    # Parsed ADJUST flags the responder acts on (most are documentation-only).
    adjust: set[str] = dataclasses.field(default_factory=set)
    # SIGN_AS <zone>: force every signable RRset in this entry to be signed
    # by <zone>'s key, overriding the derive-from-owner rule. Exists so a
    # scenario can express a *wrong* signer — a parent forging data for a
    # delegated child — which is otherwise unconstructible.
    sign_as: str | None = None
    # WILDCARD <owner>: sign answer RRsets as expansions of that wildcard
    # (RFC 4035 §3.1.3.3).
    wildcard: str | None = None


@dataclasses.dataclass
class Range:
    """RANGE_BEGIN start end .. RANGE_END: entries live during steps [start, end]."""
    start: int
    end: int
    address: str
    entries: list[Entry] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Step:
    """STEP n KIND ..: a client action or assertion."""
    n: int
    kind: str
    entry: Entry | None = None
    time_seconds: int = 0
    # CHECK_MAX_QUERIES: upper bound on total upstream queries logged so far.
    max_queries: int | None = None


@dataclasses.dataclass
class Scenario:
    path: Path
    root_hints: list[str] = dataclasses.field(default_factory=list)
    ranges: list[Range] = dataclasses.field(default_factory=list)
    steps: list[Step] = dataclasses.field(default_factory=list)
    # Hark config overrides parsed from `; hark:` directives in the file
    # header. `None` means "harness default". Unbound scenarios that set
    # `qname-minimisation: no` come through here as `False`.
    qname_minimization: bool | None = None
    # `minimal-responses: no` in the Unbound config translates here. None
    # means "harness default" (hark default = True, matching Unbound's
    # default since 1.7.x). False = passthrough — the wire shaper skips
    # the delegation-NS / glue strip on positive answers.
    minimal_responses: bool | None = None
    # Zones the harness should sign on the fly. Each entry is an absolute
    # zone name (trailing dot canonical). Conftest generates a keypair per
    # entry, writes the DS as a hark trust anchor, and the responder signs
    # every RRset whose owner falls in/under the zone. Hark validates
    # trust anchors at root only, so the first declared zone must be the
    # root in the scripted setup (typically ".").
    dnssec_zones: list[str] = dataclasses.field(default_factory=list)
    # DNS rebinding protection. `None` means harness default (off — test
    # scenarios deliberately use TEST-NET / RFC 1918 addresses for their
    # scripted authoritatives, and production-side rebinding scrubbing
    # would empty those answers). Rebinding-focused scenarios opt in via
    # `; hark: rebinding-enabled = yes` and use the per-list directives
    # below to configure the allowlist / DNSBL escape hatch.
    rebinding_enabled: bool | None = None
    rebinding_allow_zones: list[str] = dataclasses.field(default_factory=list)
    rebinding_extra_block: list[str] = dataclasses.field(default_factory=list)
    rebinding_extra_allow: list[str] = dataclasses.field(default_factory=list)
    # NS-racing stagger override (ms). `; hark: stagger-ms = 0` forces the
    # deterministic sequential server loop so a fallthrough scenario can pin a
    # specific NS-failure order. None = harness/hark default.
    stagger_ms: int | None = None
    workers: int | None = None


# ── Parser ─────────────────────────────────────────────────────────────────

_HARK_DIRECTIVE_RE = re.compile(r"^\s*;\s*hark\s*:\s*([a-z\-]+)\s*=\s*(.+?)\s*$")


def parse(path: Path) -> Scenario:
    """Parse hark-shaped .rpl. Callers handling lifted Unbound corpus must
    run text through `unbound_lift.lift_unbound_text` first."""
    return parse_text(path, path.read_text())


def parse_text(path: Path, text: str) -> Scenario:
    return _Parser(path, text.splitlines()).parse()


class _ParseError(Exception):
    def __init__(self, path: Path, lineno: int, msg: str):
        super().__init__(f"{path}:{lineno}: {msg}")


class _Parser:
    def __init__(self, path: Path, lines: list[str]):
        self.path = path
        self.lines = lines
        self.i = 0  # 1-indexed via lineno() below
        self.scenario: Scenario | None = None

    def lineno(self) -> int:
        return self.i + 1

    def err(self, msg: str) -> _ParseError:
        return _ParseError(self.path, self.lineno(), msg)

    def _next_line(self) -> str | None:
        """Advance past blank/comment lines (skipping hark directives on the way)
        and return the next significant stripped line, or None at EOF."""
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            line = raw.strip()
            if not line or line.startswith(";"):
                if m := _HARK_DIRECTIVE_RE.match(raw):
                    self._apply_hark_directive(m.group(1), m.group(2))
                self.i += 1
                continue
            return line
        return None

    def _apply_hark_directive(self, key: str, val: str) -> None:
        # `parse()` creates the scenario sentinel before any line is read,
        # so this is always safe to call.
        assert self.scenario is not None
        if key == "root-hints":
            self.scenario.root_hints = [s.strip() for s in val.split(",") if s.strip()]
        elif key in {"qname-minimisation", "qname-minimization"}:
            self.scenario.qname_minimization = val.strip().lower() in {"yes", "true", "on", "1"}
        elif key == "minimal-responses":
            self.scenario.minimal_responses = val.strip().lower() in {"yes", "true", "on", "1"}
        elif key == "rebinding-enabled":
            self.scenario.rebinding_enabled = val.strip().lower() in {"yes", "true", "on", "1"}
        elif key == "rebinding-allow-zone":
            self.scenario.rebinding_allow_zones.append(val.strip())
        elif key == "rebinding-extra-block":
            self.scenario.rebinding_extra_block.append(val.strip())
        elif key == "rebinding-extra-allow":
            self.scenario.rebinding_extra_allow.append(val.strip())
        elif key == "stagger-ms":
            self.scenario.stagger_ms = int(val.strip())
        elif key == "workers":
            self.scenario.workers = int(val.strip())
        elif key == "dnssec-zone":
            # Canonicalize: lowercase, ensure trailing dot. Multiple
            # directives accumulate; same value collapses (idempotent).
            name = val.strip().lower()
            if not name.endswith("."):
                name = name + "."
            # Hark validates trust anchors at the root only, so the first
            # declared zone MUST be `.` — additional zones can be deeper
            # for content signing.
            if not self.scenario.dnssec_zones and name != ".":
                raise self.err(
                    f"first dnssec-zone must be `.` (hark validates trust "
                    f"anchors at root only); got {name!r}"
                )
            if name not in self.scenario.dnssec_zones:
                self.scenario.dnssec_zones.append(name)

    def parse(self) -> Scenario:
        # Header may contain `; hark: x = y` directives before SCENARIO_BEGIN.
        # Stash them on a sentinel scenario so _next_line can apply them.
        self.scenario = Scenario(path=self.path)
        line = self._next_line()
        if line is None or not line.startswith("SCENARIO_BEGIN"):
            raise self.err(f"expected SCENARIO_BEGIN, got {line!r}")
        self.i += 1

        seen_step_numbers: set[int] = set()
        while (line := self._next_line()) is not None:
            if line == "SCENARIO_END":
                self.i += 1
                return self.scenario
            head = line.split()[0]
            if head == "RANGE_BEGIN":
                self.scenario.ranges.append(self._parse_range(line))
            elif head == "STEP":
                step = self._parse_step(line)
                if step.n in seen_step_numbers:
                    raise self.err(f"duplicate STEP {step.n}")
                seen_step_numbers.add(step.n)
                self.scenario.steps.append(step)
            else:
                raise self.err(f"unexpected directive {head!r}")
        raise self.err("missing SCENARIO_END")

    def _parse_range(self, line: str) -> Range:
        parts = line.split()
        if len(parts) != 3:
            raise self.err("RANGE_BEGIN takes <start> <end>")
        try:
            start, end = int(parts[1]), int(parts[2])
        except ValueError as e:
            raise self.err(f"RANGE_BEGIN bounds: {e}")
        self.i += 1

        address: str | None = None
        entries: list[Entry] = []
        while (line := self._next_line()) is not None:
            if line.startswith("ADDRESS"):
                tokens = line.split()
                if len(tokens) != 2:
                    raise self.err("ADDRESS takes one IP")
                address = tokens[1]
                self.i += 1
            elif line == "ENTRY_BEGIN":
                self.i += 1
                entries.append(self._parse_entry())
            elif line == "RANGE_END":
                self.i += 1
                if address is None:
                    # Unbound's corpus omits ADDRESS for the default server;
                    # fall back to the scenario's first root hint.
                    if not self.scenario.root_hints:
                        raise self.err("RANGE without ADDRESS and no root-hints to default to")
                    address = self.scenario.root_hints[0]
                return Range(start=start, end=end, address=address, entries=entries)
            else:
                raise self.err(f"unexpected in RANGE: {line!r}")
        raise self.err("missing RANGE_END")

    def _parse_step(self, line: str) -> Step:
        parts = line.split()
        if len(parts) < 3:
            raise self.err("STEP takes <n> <KIND> ...")
        try:
            n = int(parts[1])
        except ValueError as e:
            raise self.err(f"STEP number: {e}")
        kind = parts[2]
        self.i += 1

        if kind == "TIME_PASSES":
            # Accept both `EVAL "<n>"` (docs) and `ELAPSE <n>` (corpus convention).
            # A bare TIME_PASSES would advance the clock by 0 — a silent no-op
            # assertion-launderer — so refuse it at parse time.
            m = re.search(r'EVAL\s+"(\d+)"', line) or re.search(r"ELAPSE\s+(\d+)", line)
            if m is None:
                raise self.err("TIME_PASSES needs `ELAPSE <n>` or `EVAL \"<n>\"`")
            return Step(n=n, kind=kind, time_seconds=int(m.group(1)))

        if kind == "TIMEOUT":
            # `STEP n TIMEOUT` — instructs the responder to drop the next
            # outgoing upstream query as if the auth had silently timed out.
            # No ENTRY block.
            return Step(n=n, kind=kind)

        if kind == "CHECK_MAX_QUERIES":
            # `STEP n CHECK_MAX_QUERIES <N>` — assert the resolver has emitted
            # at most N upstream queries so far. The NXNSAttack regression
            # guard. No ENTRY block.
            if len(parts) != 4:
                raise self.err("CHECK_MAX_QUERIES takes a single integer bound")
            try:
                return Step(n=n, kind=kind, max_queries=int(parts[3]))
            except ValueError as e:
                raise self.err(f"CHECK_MAX_QUERIES bound: {e}")

        # All remaining kinds wrap an ENTRY block.
        if self._next_line() != "ENTRY_BEGIN":
            raise self.err(f"STEP {n} {kind} requires an ENTRY block")
        self.i += 1
        return Step(n=n, kind=kind, entry=self._parse_entry())

    def _validate_flags(self, flags: list[str], valid: frozenset[str], kind: str) -> None:
        for flag in flags:
            if flag not in valid:
                raise self.err(f"unknown {kind} flag: {flag!r}")

    def _parse_entry(self) -> Entry:
        entry = Entry()
        current_section: str | None = None
        while (line := self._next_line()) is not None:
            if line == "ENTRY_END":
                self.i += 1
                return entry
            tokens = line.split()
            head = tokens[0]
            if head == "MATCH":
                flags = [t.lower() for t in tokens[1:]]
                self._validate_flags(flags, MATCH_VALID_FLAGS, "MATCH")
                entry.match.update(flags)
            elif head == "ADJUST":
                # `copy_id` / `copy_query` are implicit in `make_response`
                # + the verbatim-echo default; only `force_lower_qname` is
                # acted on by the responder.
                flags = [t.lower() for t in tokens[1:]]
                self._validate_flags(flags, ADJUST_VALID_FLAGS, "ADJUST")
                entry.adjust.update(flags)
            elif head == "SIGN_AS":
                if len(tokens) != 2:
                    raise self.err(f"SIGN_AS takes one zone name: {line!r}")
                entry.sign_as = tokens[1]
            elif head == "WILDCARD":
                if len(tokens) != 2 or not tokens[1].startswith("*."):
                    raise self.err(f"WILDCARD takes one wildcard owner: {line!r}")
                entry.wildcard = tokens[1]
            elif head == "REPLY":
                self._parse_reply(entry, tokens[1:])
            elif head == "SECTION":
                if len(tokens) != 2 or tokens[1] not in SECTION_NAMES:
                    raise self.err(f"bad SECTION: {line!r}")
                current_section = tokens[1]
            elif current_section is None:
                raise self.err(f"RR outside SECTION: {line!r}")
            else:
                self._add_rr(entry, current_section, line)
            self.i += 1
        raise self.err("missing ENTRY_END")

    def _parse_reply(self, entry: Entry, tokens: list[str]) -> None:
        for t in tokens:
            if t in REPLY_FLAGS:
                entry.reply_flags |= REPLY_FLAGS[t]
            elif t in REPLY_RCODES:
                entry.reply_rcode = REPLY_RCODES[t]
            elif t in REPLY_OPCODES:
                entry.reply_opcode = REPLY_OPCODES[t]
            elif t == "DO":
                entry.want_dnssec = True
            else:
                raise self.err(f"unknown REPLY token: {t!r}")

    def _add_rr(self, entry: Entry, section: str, line: str) -> None:
        # Heuristic split into ANSWER-style ("name ttl class type rdata") vs
        # QUESTION-style ("name [class] type"). dnspython's from_text handles
        # both, but we need to know which slot to drop the rrset into.
        if section == "QUERY_LOG":
            parts = line.split()
            if len(parts) not in (2, 3):
                raise self.err(f"bad QUERY_LOG line (want `qname qtype [dest]`): {line!r}")
            qname, qtype, *rest = parts
            dest: str | None = rest[0] if rest else None
            try:
                dns.rdatatype.from_text(qtype)
            except Exception as e:
                raise self.err(f"bad QUERY_LOG qtype: {e}")
            entry.query_log.append((qname, qtype.upper(), dest))
            return
        if section == "QUESTION":
            # "name [class] type"
            parts = line.split()
            if len(parts) == 2:
                name, qtype = parts[0], parts[1]
                rdclass = "IN"
            elif len(parts) == 3:
                name, rdclass, qtype = parts
            else:
                raise self.err(f"bad QUESTION line: {line!r}")
            try:
                rrset = dns.rrset.from_text_list(
                    _absolutize(name),
                    0,
                    dns.rdataclass.from_text(rdclass),
                    dns.rdatatype.from_text(qtype),
                    [],
                    origin=dns.name.root,
                    relativize=False,
                )
            except Exception as e:
                raise self.err(f"bad QUESTION rr: {e}")
            entry.question.append(rrset)
            return
        # Answer/authority/additional: full RR with rdata.
        try:
            args = _split_rr_line(_expand_ds_placeholder(line))
            rrset = dns.rrset.from_text_list(
                *args, origin=dns.name.root, relativize=False
            )
        except Exception as e:
            raise self.err(f"bad RR ({section}): {e}")
        getattr(entry, section.lower()).append(rrset)


# Unbound testbound's corpus omits TTLs on most RRs. Hark refuses to cache
# TTL=0 records (RFC 1035 §4.1.3 / RFC 2181 §8), so the default has to be
# non-zero or no delegation ever sticks. 3600 matches testbound's default.
_DEFAULT_RR_TTL = 3600


# A .rpl record is static text, but a DS digest covers a key that does not
# exist until the harness generates it at run time. `DS PLACEHOLDER` stands in
# for "the DS of whatever key this child zone gets"; the responder substitutes
# the real digest before signing. Expanded here to an all-zero SHA-256 digest
# purely so dnspython will parse it — it validates both digest type and length,
# so the sentinel has to be well-formed. Key tag 0 is what marks it.
_DS_PLACEHOLDER_RDATA = "0 13 2 " + "00" * 32


def _expand_ds_placeholder(line: str) -> str:
    parts = line.split()
    if len(parts) >= 2 and parts[-1].upper() == "PLACEHOLDER" and parts[-2].upper() == "DS":
        return " ".join(parts[:-1]) + " " + _DS_PLACEHOLDER_RDATA
    return line


def _absolutize(name: str) -> str:
    """Ensure trailing dot. Testbound treats partials as absolute, but
    dnspython's `to_wire()` raises `NeedAbsoluteNameOrOrigin` without it,
    killing the responder thread mid-reply."""
    return name if name.endswith(".") else name + "."


def _split_rr_line(line: str) -> tuple:
    """Split a zone-file RR line into (name, ttl, rdclass, rdtype, [rdata]).

    Handles the common forms:
        name ttl class type rdata...
        name class ttl type rdata...
        name ttl type rdata...        (class defaults to IN)
        name type rdata...            (ttl defaults to 3600 — see above)

    Multi-token rdata (SOA, MX, multi-string TXT) is preserved in full;
    quoted strings stay quoted so dnspython's from_text reads them as one
    rdata token rather than splitting on the embedded whitespace.
    """
    # `posix=False` preserves the surrounding quotes on quoted strings
    # (TXT rdata) so dnspython's from_text reads them as one rdata token.
    tokens = shlex.split(line, posix=False)
    if len(tokens) < 2:
        raise ValueError(f"too few tokens: {line!r}")
    name = _absolutize(tokens[0])
    rest = tokens[1:]
    ttl = _DEFAULT_RR_TTL
    rdclass = "IN"
    if rest[0].isdigit():
        ttl = int(rest[0])
        rest = rest[1:]
    if rest and rest[0].upper() in {"IN", "CH", "HS"}:
        rdclass = rest[0].upper()
        rest = rest[1:]
    if rest and rest[0].isdigit():  # class-then-ttl
        ttl = int(rest[0])
        rest = rest[1:]
    if not rest:
        raise ValueError(f"no rdtype in {line!r}")
    rdtype = rest[0]
    rdata = " ".join(rest[1:])
    return (
        name,
        ttl,
        dns.rdataclass.from_text(rdclass),
        dns.rdatatype.from_text(rdtype),
        [rdata] if rdata else [],
    )
