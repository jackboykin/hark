"""Lift Unbound's `.rpl` scenarios into the hark-flavoured subset.

Unbound's `testbound` corpus (`test/corpus/unbound/*.rpl`) is the
reference for delegation, CNAME, QMIN, and NSEC3 behaviour. Two shape
differences keep us from running them verbatim:

  1. **CONFIG block.** Files open with `server:` / `stub-zone:` /
     `CONFIG_END` carrying Unbound-specific knobs we don't need (and
     can't always honour). We strip it. Optionally, a known subset
     (e.g. `qname-minimisation: no`) is translated to a `; hark:`
     directive the scenario runner can act on.

  2. **Real internet IPs.** Upstream uses live root/TLD/auth addresses
     (`193.0.14.129`, `192.5.6.30`, `1.2.3.4`) as RANGE ADDRESSes and
     glue rdata. We can't bind those locally. We translate every IP
     that appears on an `ADDRESS` line to `127.0.10.<n>` and apply the
     same mapping wherever else that IP appears in the file — so glue
     records keep pointing at the right (now-loopback) auth. Answer-
     section IPs that aren't auth IPs (e.g. `10.20.30.40` in the
     scenario's final A record) are left untouched.

`lift_unbound_text(text) -> str` is idempotent on already-hark text.
"""

from __future__ import annotations

import re

# ── Detection ──────────────────────────────────────────────────────────

# Unbound's prelude opens with `server:` (or a comment, then `server:`).
# Hark's scenarios open with `; hark:` directives or `SCENARIO_BEGIN`.
_UNBOUND_PRELUDE_RE = re.compile(r"^\s*server\s*:", re.MULTILINE)

# `ADDRESS <ip>` line in a RANGE_BEGIN block. Tab- or space-indented.
_ADDRESS_RE = re.compile(r"^\s*ADDRESS\s+([0-9.]+|[0-9a-fA-F:]+)\s*$", re.MULTILINE)

# Loopback IPv6 (::1/128) is the only v6 address we can bind without root.
# Scenarios with at most one v6 ADDRESS can be lifted; the v6 auth maps to
# ::1 and binds on the shared port. Multiple distinct v6 ADDRESSes can't
# coexist without `ip -6 addr add` (privileged).
_IPV6_LOOPBACK = "::1"


# ── Transform ──────────────────────────────────────────────────────────


def lift_unbound_text(text: str) -> str:
    """Return hark-flavoured text. No-op if the input is already hark-shaped."""
    prelude, sep, rest = text.partition("CONFIG_END")
    if not sep or not _UNBOUND_PRELUDE_RE.search(prelude):
        return text
    body = rest.lstrip("\n")

    # Build the auth-IP mapping from all RANGE ADDRESS lines.
    ip_map = _build_ip_map(body)

    # Apply the mapping textually — substring-replace each auth IP
    # everywhere it appears. Word-boundary regex avoids `1.2.3.4` matching
    # inside `1.2.3.40`.
    body = _apply_ip_map(body, ip_map)

    # The root hint is whichever loopback IP got assigned to the file's
    # *first* mapped auth — typically the address corresponding to the
    # Unbound stub-zone's stub-addr.
    if ip_map:
        first_mapped = next(iter(ip_map.values()))
        root_hint = f"; hark: root-hints = {first_mapped}\n\n"
    else:
        root_hint = ""

    # Translate Unbound's `qname-minimisation: no` to hark's `; hark:` form;
    # conftest reads it via `Scenario.qname_minimization`.
    extras = ""
    if re.search(r"qname-minimisation\s*:\s*\"?no\"?", prelude):
        extras += "; hark: qname-minimisation = no\n"
    # Translate Unbound's `minimal-responses: no`. Unbound's default is yes
    # (since 1.7.x); hark's default also yes. Scenarios that need the
    # passthrough shape say so explicitly.
    if re.search(r"minimal-responses\s*:\s*\"?no\"?", prelude):
        extras += "; hark: minimal-responses = no\n"

    return root_hint + extras + body


# ── Helpers ────────────────────────────────────────────────────────────


def _build_ip_map(body: str) -> dict[str, str]:
    """Map every IP listed on an `ADDRESS` line to a bindable local address.

    IPv4 → 127.0.10.1, 127.0.10.2, ... in order first seen.
    IPv6 → `::1` (the single v6 loopback). At most one distinct v6 ADDRESS
    per scenario can be lifted unprivileged — adding more would require
    `ip -6 addr add`.
    """
    mapping: dict[str, str] = {}
    n = 1
    v6_seen: str | None = None
    for m in _ADDRESS_RE.finditer(body):
        ip = m.group(1)
        if ip in mapping:
            continue
        if ":" in ip:
            if v6_seen is not None:
                raise ValueError(
                    f"multiple v6 ADDRESSes in one scenario can't be lifted "
                    f"without privileged loopback setup: saw {v6_seen} and {ip}"
                )
            v6_seen = ip
            mapping[ip] = _IPV6_LOOPBACK
            continue
        mapping[ip] = f"127.0.10.{n}"
        n += 1
    return mapping


def _apply_ip_map(text: str, mapping: dict[str, str]) -> str:
    """Replace each mapped IP everywhere in `text`. Boundary rules:
      - IPv4 (digits/dots): not preceded/followed by a digit or dot, so
        `1.2.3.4` doesn't match inside `1.2.3.40`.
      - IPv6 (hex/colons): not preceded/followed by a hex digit or colon.
    Longest-first alternation: longer IPs match before any prefix-overlapping
    shorter ones, in one regex pass per family."""
    v4 = sorted((k for k in mapping if ":" not in k), key=len, reverse=True)
    v6 = sorted((k for k in mapping if ":" in k), key=len, reverse=True)
    if v4:
        pat = re.compile(r"(?<![0-9.])(" + "|".join(map(re.escape, v4)) + r")(?![0-9.])")
        text = pat.sub(lambda m: mapping[m.group(1)], text)
    if v6:
        pat = re.compile(r"(?<![0-9a-fA-F:])(" + "|".join(map(re.escape, v6)) + r")(?![0-9a-fA-F:])")
        text = pat.sub(lambda m: mapping[m.group(1)], text)
    return text
