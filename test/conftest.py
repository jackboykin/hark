"""Pytest configuration: scenario discovery + per-scenario lifecycle.

Each `.rpl` file under `scenarios/` becomes one pytest item. Running it:
  1. Parses the .rpl
  2. Starts a scripted UDP responder bound to each RANGE ADDRESS on `RESP_PORT`
  3. Spawns hark configured with `root-hints` and `upstream-port = RESP_PORT`
  4. Walks the STEP sequence: send QUERY, assert CHECK_ANSWER, assert CHECK_QUERY_LOG
  5. Tears down hark + responder
"""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from pathlib import Path

import pytest

from harness import client, hark_proc, responder, rpl, unbound_lift
from harness import dnssec as harness_dnssec


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

UNBOUND_CORPUS = Path(__file__).resolve().parent / "corpus" / "unbound"


class RplFile(pytest.File):
    """Pytest File collector for in-tree `.rpl` scenarios."""

    def collect(self):
        yield RplItem.from_parent(self, name=self.path.stem)


class RplItem(pytest.Item):
    def __init__(self, *, name: str, parent, scenario_path: Path | None = None, lift: bool = False):
        super().__init__(name, parent)
        self.scenario_path = scenario_path if scenario_path is not None else Path(parent.path)
        self.lift = lift  # True for Unbound corpus paths; runs the lift transform

    def runtest(self):
        run_scenario(self.scenario_path, lift=self.lift)

    def reportinfo(self):
        return self.scenario_path, 0, f"scenario: {self.name}"


class LiftedManifestCollector(pytest.Module):
    """Surfaces every manifest entry as a pytest item. Entries with an
    `xfail_reason` get a strict `xfail` marker — they run, and if hark
    ever passes one the suite fails so the marker can be revisited.
    Nothing in the manifest is skipped."""

    def collect(self):
        from scenarios.lifted import manifest as lifted_manifest
        for entry in lifted_manifest.all_entries():
            scenario_path = UNBOUND_CORPUS / entry.filename
            name = f"{entry.category}/{Path(entry.filename).stem}"
            item = RplItem.from_parent(self, name=name, scenario_path=scenario_path, lift=True)
            if entry.xfail_reason is not None:
                item.add_marker(pytest.mark.xfail(reason=entry.xfail_reason, strict=True))
            yield item


def pytest_collect_file(parent, file_path: Path):
    if file_path.suffix == ".rpl":
        return RplFile.from_parent(parent, path=file_path)
    # The manifest module is the single collection entry-point for the
    # Unbound corpus — pick it up here, not via .rpl auto-discovery.
    if file_path.name == "manifest.py" and file_path.parent.name == "lifted":
        return LiftedManifestCollector.from_parent(parent, path=file_path)
    return None


# ── Scenario runner ────────────────────────────────────────────────────────


def run_scenario(path: Path, lift: bool = False) -> None:
    text = path.read_text()
    if lift:
        text = unbound_lift.lift_unbound_text(text)
    scenario = rpl.parse_text(path, text)
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
    if scenario.qname_minimization is not None:
        cfg.qname_minimization = scenario.qname_minimization
    if scenario.minimal_responses is not None:
        cfg.minimal_responses = scenario.minimal_responses
    if scenario.stagger_ms is not None:
        cfg.stagger_ms = scenario.stagger_ms
    if scenario.rebinding_enabled is not None:
        cfg.rebinding_enabled = scenario.rebinding_enabled
    if scenario.rebinding_allow_zones:
        cfg.rebinding_allow_zones = list(scenario.rebinding_allow_zones)
    if scenario.rebinding_extra_block:
        cfg.rebinding_extra_block = list(scenario.rebinding_extra_block)
    if scenario.rebinding_extra_allow:
        cfg.rebinding_extra_allow = list(scenario.rebinding_extra_allow)

    # DNSSEC harness: generate a key per declared zone, publish the root's
    # DS as hark's trust anchor, and hand the keys to the responder for
    # on-the-fly RRSIG signing. The parser already enforces that the first
    # zone is `.` (hark validates trust anchors at root only).
    signers = [harness_dnssec.KeyMaterial.generate(z) for z in scenario.dnssec_zones]
    if signers:
        cfg.dnssec = True
        cfg.trust_anchors = [signers[0].ds_presentation()]

    resp = responder.Responder(scenario, port=RESP_PORT, signers=signers)
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
    try:
        ip = ipaddress.ip_address(hint)
    except ValueError:
        # Already-ported or bracketed forms (`1.2.3.4:53`, `[::1]:53`, `[::1]`)
        # fail to parse — pass through unchanged.
        return hint
    return f"[{ip}]:{default_port}" if isinstance(ip, ipaddress.IPv6Address) else f"{ip}:{default_port}"


def _step_failure(path: Path, step_n: int, msg: str, resp: responder.Responder, proc: hark_proc.HarkProcess) -> AssertionError:
    log_lines = "\n".join(f"  [{i}] {r.address} <- {r.qname} {r.qtype}" for i, r in enumerate(resp.query_log))
    return AssertionError(
        f"{path.name} step {step_n}: {msg}\n---- responder log:\n{log_lines}\n---- hark log:\n{proc.read_log()}"
    )


def _run_steps(
    scenario: rpl.Scenario,
    resp: responder.Responder,
    proc: hark_proc.HarkProcess,
    path: Path,
) -> None:
    # QUERY is synchronous, so by the time the loop reaches a TIMEOUT step
    # hark's upstream queries are already done. Pre-count TIMEOUTs so the
    # responder drops the right number of incoming queries on the live path.
    resp.set_drop_count(sum(1 for s in scenario.steps if s.kind == "TIMEOUT"))

    last_response = None
    out_query_cursor = 0
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
                raise _step_failure(path, step.n, str(e), resp, proc) from None
        elif step.kind == "CHECK_QUERY_LOG":
            assert step.entry is not None
            try:
                client.assert_query_log_matches(resp.query_log, step.entry)
            except AssertionError as e:
                raise _step_failure(path, step.n, str(e), resp, proc) from None
        elif step.kind == "CHECK_MAX_QUERIES":
            assert step.max_queries is not None
            sent = len(resp.query_log)
            if sent > step.max_queries:
                raise _step_failure(
                    path, step.n,
                    f"CHECK_MAX_QUERIES: resolver sent {sent} upstream queries, "
                    f"bound is {step.max_queries} (NXNSAttack amplification?)",
                    resp, proc,
                )
        elif step.kind == "CHECK_OUT_QUERY":
            # Strictly positional, distinct from CHECK_QUERY_LOG's set-style check.
            assert step.entry is not None
            if out_query_cursor >= len(resp.query_log):
                raise _step_failure(
                    path, step.n,
                    f"CHECK_OUT_QUERY: no upstream query at log position {out_query_cursor}; "
                    f"log has {len(resp.query_log)} entries",
                    resp, proc,
                )
            try:
                client.assert_out_query_matches(resp.query_log[out_query_cursor], step.entry)
            except AssertionError as e:
                raise _step_failure(path, step.n, f"(log position {out_query_cursor}): {e}", resp, proc) from None
            out_query_cursor += 1
        elif step.kind == "TIMEOUT":
            out_query_cursor += 1  # dropped query still gets logged
        elif step.kind == "TIME_PASSES":
            # Hark intercepts `_advance-clock.<N>.testharness.invalid` in
            # `resolveQueryWith` and bumps its synthetic monotonic offset
            # (`src/monotonic.zig:advanceTestClock`). Gated on -Dtesting=true.
            client.send_raw_query(
                f"_advance-clock.{step.time_seconds}.testharness.invalid.",
                "TXT", HARK_LISTEN,
            )
        else:
            raise AssertionError(f"unknown STEP kind: {step.kind}")
