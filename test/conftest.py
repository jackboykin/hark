"""Pytest configuration: scenario discovery + per-scenario lifecycle.

Each `.rpl` file under `scenarios/` becomes one pytest item. Running it:
  1. Parses the .rpl
  2. Starts a scripted UDP responder bound to each RANGE ADDRESS on `RESP_PORT`
  3. Spawns hark configured with `root-hints` and `upstream-port = RESP_PORT`
  4. Walks the STEP sequence: send QUERY, assert CHECK_ANSWER, assert CHECK_QUERY_LOG
  5. Tears down hark + responder
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

import pytest

from harness import client, hark_proc, responder, rpl


def _worker_offset() -> int:
    """Per-worker port offset for pytest-xdist parallelism.

    `PYTEST_XDIST_WORKER` is `gw0`, `gw1`, ... under xdist; unset otherwise.
    Each worker gets its own (RESP_PORT, hark listen port) tuple to avoid
    bind collisions when scenarios run in parallel.
    """
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    m = re.match(r"gw(\d+)", worker)
    return int(m.group(1)) if m else 0


# Fake-authoritative port. Non-privileged, distinct from hark's listen port.
RESP_PORT = 5353 + _worker_offset() * 10

# Hark listens here. Distinct IP from responders to avoid same-tuple bind clash.
HARK_LISTEN = ("127.0.0.1", 5354 + _worker_offset() * 10)


# ── Scenario collection ────────────────────────────────────────────────────


class RplFile(pytest.File):
    """Pytest File collector for .rpl scenarios."""

    def collect(self):
        yield RplItem.from_parent(self, name=self.path.stem)


class RplItem(pytest.Item):
    def __init__(self, *, name: str, parent: RplFile):
        super().__init__(name, parent)
        self.scenario_path = Path(parent.path)

    def runtest(self):
        run_scenario(self.scenario_path)

    def reportinfo(self):
        return self.scenario_path, 0, f"scenario: {self.name}"


def pytest_collect_file(parent, file_path: Path):
    if file_path.suffix == ".rpl":
        return RplFile.from_parent(parent, path=file_path)
    return None


# ── Scenario runner ────────────────────────────────────────────────────────


def run_scenario(path: Path) -> None:
    scenario = rpl.parse(path)
    if not scenario.root_hints:
        raise AssertionError(
            f"{path}: scenario must declare `; hark: root-hints = <ip>[, ...]` in header"
        )

    binary = hark_proc.find_hark_binary()

    # Map bare-IP root hints to "ip:RESP_PORT" so hark uses the test port.
    # IPv6 hints (`[::1]:5353` etc.) are passed through untouched.
    hinted = [_with_port(h, RESP_PORT) for h in scenario.root_hints]

    cfg = hark_proc.HarkConfig(
        listen_ip=HARK_LISTEN[0],
        listen_port=HARK_LISTEN[1],
        upstream_port=RESP_PORT,
        root_hints=hinted,
    )

    resp = responder.Responder(scenario, port=RESP_PORT)
    resp.start()
    try:
        with tempfile.TemporaryDirectory(prefix="harktest-") as td:
            with hark_proc.HarkProcess(binary, cfg, Path(td)) as proc:
                _run_steps(scenario, resp, proc, path)
    finally:
        resp.stop()


def _with_port(hint: str, default_port: int) -> str:
    """Stamp `default_port` onto bare IPv4 / bare IPv6 hints. Leave hints
    that already specify a port (`ip:port`, `[ip6]:port`) untouched."""
    # Already ported: `[ip6]:port` or `dotted.IPv4:port`.
    if "]:" in hint:
        return hint
    if hint.count(":") == 1 and hint.split(":")[0].count(".") == 3:
        return hint
    # Bare IPv6 (multiple colons, no brackets): bracket before stamping.
    if ":" in hint and not hint.startswith("["):
        return f"[{hint}]:{default_port}"
    # Bare IPv4, bare bracketed IPv6 (`[::1]`), or garbage we pass through to
    # hark's parser by way of `{hint}:{port}` — harmless for malformed input.
    return f"{hint}:{default_port}"


def _run_steps(
    scenario: rpl.Scenario,
    resp: responder.Responder,
    proc: hark_proc.HarkProcess,
    path: Path,
) -> None:
    last_response = None
    for step in scenario.steps:
        if not proc.is_alive():
            raise AssertionError(
                f"{path.name} step {step.n}: hark died mid-scenario; log:\n{proc.read_log()}"
            )
        resp.set_step(step.n)
        if step.kind == "QUERY":
            assert step.entry is not None
            last_response = client.send_query(step.entry, HARK_LISTEN)
        elif step.kind == "CHECK_ANSWER":
            assert step.entry is not None
            if last_response is None:
                raise AssertionError(f"step {step.n} CHECK_ANSWER before any QUERY")
            try:
                client.assert_answer_matches(last_response, step.entry)
            except AssertionError as e:
                raise AssertionError(
                    f"{path.name} step {step.n}: {e}\n---- responder log:\n"
                    + "\n".join(f"  {r.address} <- {r.qname} {r.qtype}" for r in resp.query_log)
                ) from None
        elif step.kind == "CHECK_QUERY_LOG":
            assert step.entry is not None
            client.assert_query_log_matches(resp.query_log, step.entry)
        elif step.kind == "TIME_PASSES":
            pass  # Deferred: requires hark test-clock support.
        else:
            raise AssertionError(f"unknown STEP kind: {step.kind}")
