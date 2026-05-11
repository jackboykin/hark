"""Parser for the `.rpl` scenario format.

Subset of the format used by Unbound's `testbound`, Knot's Deckard, and Rust's
Stelline. Covers what hark's day-one scenarios need; not a complete .rpl spec.

Reference: https://github.com/NLnetLabs/unbound/blob/master/testcode/testbound.c
           https://docs.rs/domain/latest/domain/stelline/

Hark-only extensions:
  - ; hark: root-hints = <ip> [, <ip>...]   directive in scenario header
  - STEP n CHECK_QUERY_LOG                  (parsed, runtime support deferred)
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import dns.flags
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset


# Union of MATCH flags accepted anywhere (responder entries, CHECK_ANSWER,
# CHECK_QUERY_LOG) — used at parse time to catch typos like `MATCH quesiton`.
# Context-specific rejection is the responder's job; parse-time only filters
# obvious nonsense.
MATCH_VALID_FLAGS = frozenset({
    # responder-side (entry-matching)
    "opcode", "qname", "qtype", "qclass", "question", "subdomain",
    # CHECK_ANSWER
    "all", "answer", "authority", "additional", "flags", "rcode", "ttl",
    # CHECK_QUERY_LOG
    "order", "address",
})

# ADJUST directive: dnspython's make_response already copies the ID, so
# copy_id is a no-op; copy_query echoes the query's QUESTION section.
ADJUST_VALID_FLAGS = frozenset({"copy_id", "copy_query"})

# Section names → dnspython section indices via parse helper.
SECTION_NAMES = frozenset({"QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL"})

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
}

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
    adjust: set[str] = dataclasses.field(default_factory=set)
    reply_flags: int = 0
    reply_rcode: int = dns.rcode.NOERROR
    reply_opcode: int = dns.opcode.QUERY
    question: list[dns.rrset.RRset] = dataclasses.field(default_factory=list)
    answer: list[dns.rrset.RRset] = dataclasses.field(default_factory=list)
    authority: list[dns.rrset.RRset] = dataclasses.field(default_factory=list)
    additional: list[dns.rrset.RRset] = dataclasses.field(default_factory=list)


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
    kind: str          # "QUERY" | "CHECK_ANSWER" | "CHECK_QUERY_LOG" | "TIME_PASSES"
    entry: Entry | None = None
    time_seconds: int = 0


@dataclasses.dataclass
class Scenario:
    name: str
    path: Path
    root_hints: list[str] = dataclasses.field(default_factory=list)
    ranges: list[Range] = dataclasses.field(default_factory=list)
    steps: list[Step] = dataclasses.field(default_factory=list)


# ── Parser ─────────────────────────────────────────────────────────────────

_HARK_DIRECTIVE_RE = re.compile(r"^\s*;\s*hark\s*:\s*([a-z\-]+)\s*=\s*(.+?)\s*$")


def parse(path: Path) -> Scenario:
    text = path.read_text()
    lines = text.splitlines()
    return _Parser(path, lines).parse()


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
        if key == "root-hints" and self.scenario is not None:
            self.scenario.root_hints = [s.strip() for s in val.split(",") if s.strip()]

    def parse(self) -> Scenario:
        # Header may contain `; hark: x = y` directives before SCENARIO_BEGIN.
        # Stash them on a sentinel scenario so _next_line can apply them.
        self.scenario = Scenario(name=self.path.stem, path=self.path)
        line = self._next_line()
        if line is None or not line.startswith("SCENARIO_BEGIN"):
            raise self.err(f"expected SCENARIO_BEGIN, got {line!r}")
        name = line[len("SCENARIO_BEGIN"):].strip() or self.scenario.name
        self.scenario.name = name
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
                    raise self.err("RANGE without ADDRESS")
                return Range(start=start, end=end, address=address, entries=entries)
            else:
                raise self.err(f"unexpected in RANGE: {line!r}")
        raise self.err("missing RANGE_END")

    def _parse_step(self, line: str) -> Step:
        parts = line.split(maxsplit=2)
        if len(parts) < 3:
            raise self.err("STEP takes <n> <KIND> ...")
        try:
            n = int(parts[1])
        except ValueError as e:
            raise self.err(f"STEP number: {e}")
        kind = parts[2].strip()
        self.i += 1

        if kind == "TIME_PASSES":
            # `STEP n TIME_PASSES EVAL "<seconds>"`
            m = re.search(r'EVAL\s+"(\d+)"', line)
            return Step(n=n, kind=kind, time_seconds=int(m.group(1)) if m else 0)

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
                self._validate_flags(tokens[1:], MATCH_VALID_FLAGS, "MATCH")
                entry.match.update(tokens[1:])
            elif head == "ADJUST":
                self._validate_flags(tokens[1:], ADJUST_VALID_FLAGS, "ADJUST")
                entry.adjust.update(tokens[1:])
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
            else:
                raise self.err(f"unknown REPLY token: {t!r}")

    def _add_rr(self, entry: Entry, section: str, line: str) -> None:
        # Heuristic split into ANSWER-style ("name ttl class type rdata") vs
        # QUESTION-style ("name [class] type"). dnspython's from_text handles
        # both, but we need to know which slot to drop the rrset into.
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
                rrset = dns.rrset.from_text(
                    name,
                    0,
                    dns.rdataclass.from_text(rdclass),
                    dns.rdatatype.from_text(qtype),
                )
            except Exception as e:
                raise self.err(f"bad QUESTION rr: {e}")
            entry.question.append(rrset)
            return
        # Answer/authority/additional: full RR with rdata.
        try:
            rrset = dns.rrset.from_text_list(*_split_rr_line(line))
        except Exception as e:
            raise self.err(f"bad RR ({section}): {e}")
        getattr(entry, section.lower()).append(rrset)


def _split_rr_line(line: str) -> tuple:
    """Split a zone-file RR line into (name, ttl, rdclass, rdtype, [rdata]).

    Handles the common forms:
        name ttl class type rdata...
        name class ttl type rdata...
        name ttl type rdata...        (class defaults to IN)
        name type rdata...            (ttl defaults to 0)
    """
    tokens = line.split(maxsplit=4)
    if len(tokens) < 3:
        raise ValueError(f"too few tokens: {line!r}")
    name = tokens[0]
    rest = tokens[1:]
    ttl = 0
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
    rdata = rest[1] if len(rest) > 1 else ""
    return (
        name,
        ttl,
        dns.rdataclass.from_text(rdclass),
        dns.rdatatype.from_text(rdtype),
        [rdata] if rdata else [],
    )
