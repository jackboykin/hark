"""Spawn and control a hark subprocess for one scenario.

Writes a generated TOML config (listen address, root hints, upstream port,
loopback bypass) to a temp file, launches hark, waits until it's ready by
probing it with a SOA query for the root, and tears it down at exit.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import IO


@dataclasses.dataclass
class HarkConfig:
    listen_ip: str = "127.0.0.1"
    listen_port: int = 5354
    upstream_port: int = 5353
    root_hints: list[str] = dataclasses.field(default_factory=list)
    workers: int = 1
    qname_minimization: bool = True
    dnssec: bool = False
    cache_min_ttl: int = 0
    minimal_responses: bool = True
    # Each entry is a `"<key-tag> <alg> <dtype> <hex>"` string fed to
    # hark's test-only `[resolver] trust-anchors = [...]` knob. Implies
    # `dnssec = true`; conftest enforces that pairing.
    trust_anchors: list[str] = dataclasses.field(default_factory=list)
    # Rebinding scrub. Harness default is *off* — scripted authoritatives
    # routinely answer with TEST-NET (RFC 5737) and RFC 1918 addresses
    # which production-side rebinding scrubbing would empty. Rebinding-
    # focused scenarios re-enable via `; hark: rebinding-enabled = yes`.
    rebinding_enabled: bool = False
    rebinding_allow_zones: list[str] = dataclasses.field(default_factory=list)
    rebinding_extra_block: list[str] = dataclasses.field(default_factory=list)
    rebinding_extra_allow: list[str] = dataclasses.field(default_factory=list)
    # Pass `--verbose` so per-query debug lines reach the test log.
    # Cheap; failing-scenario triage is impossible without them.
    verbose: bool = True

    def to_toml(self) -> str:
        # Root hints are passed in "ip:port" form so the existing parseAddress
        # path lifts them; the upstream-port knob covers glue records, which
        # have no port.
        # `opportunistic` is explicitly off: hark's TLS transport hardcodes
        # port 853 (src/tls_transport.zig:32) and would bypass `upstream_port`,
        # silently mis-targeting the responder. Future scenarios needing
        # encrypted upstreams will require threading a `tls_port` knob first.
        lines = [
            "[server]",
            f'listen = ["{self.listen_ip}:{self.listen_port}"]',
            f"workers = {self.workers}",
            f"minimal-responses = {str(self.minimal_responses).lower()}",
            "",
            "[resolver]",
            f"qname-minimization = {str(self.qname_minimization).lower()}",
            f"dnssec = {str(self.dnssec).lower()}",
            "opportunistic = false",
            f"upstream-port = {self.upstream_port}",
            "allow-loopback-upstreams = true",
        ]
        if self.root_hints:
            hints = ", ".join(f'"{h}"' for h in self.root_hints)
            lines.append(f"root-hints = [{hints}]")
        if self.trust_anchors:
            anchors = ", ".join(f'"{a}"' for a in self.trust_anchors)
            lines.append(f"trust-anchors = [{anchors}]")
        if self.cache_min_ttl:
            lines += ["", "[cache]", f"min-ttl = {self.cache_min_ttl}"]
        lines += [
            "",
            "[rebinding]",
            f"enabled = {str(self.rebinding_enabled).lower()}",
        ]
        if self.rebinding_allow_zones:
            zones = ", ".join(f'"{z}"' for z in self.rebinding_allow_zones)
            lines.append(f"allow-zones = [{zones}]")
        if self.rebinding_extra_block:
            cidrs = ", ".join(f'"{c}"' for c in self.rebinding_extra_block)
            lines.append(f"extra-block = [{cidrs}]")
        if self.rebinding_extra_allow:
            cidrs = ", ".join(f'"{c}"' for c in self.rebinding_extra_allow)
            lines.append(f"extra-allow = [{cidrs}]")
        return "\n".join(lines) + "\n"


class HarkProcess:
    """Wrap a running hark binary. Use as a context manager."""

    def __init__(self, binary: Path, config: HarkConfig, tmpdir: Path):
        self.binary = binary
        self.config = config
        self.tmpdir = tmpdir
        self.proc: subprocess.Popen | None = None
        self.config_path: Path | None = None
        self.log_path: Path | None = None
        self._log_fd: IO[bytes] | None = None

    def __enter__(self) -> "HarkProcess":
        self.config_path = self.tmpdir / "hark.toml"
        self.config_path.write_text(self.config.to_toml())
        self.log_path = self.tmpdir / "hark.log"
        self._log_fd = self.log_path.open("wb")
        env = os.environ.copy()
        # Hark logs to stderr.
        argv = [str(self.binary), "serve", "--config", str(self.config_path)]
        if self.config.verbose:
            argv.append("--verbose")
        self.proc = subprocess.Popen(
            argv,
            stdout=self._log_fd,
            stderr=self._log_fd,
            env=env,
        )
        self._wait_ready()
        return self

    def __exit__(self, *_exc) -> None:
        try:
            if self.proc is not None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=1.0)
        finally:
            if self._log_fd is not None:
                self._log_fd.close()
                self._log_fd = None

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def listen_addr(self) -> tuple[str, int]:
        return (self.config.listen_ip, self.config.listen_port)

    def read_log(self) -> str:
        return self.log_path.read_text() if self.log_path else ""

    def _wait_ready(self, timeout_s: float = 5.0) -> None:
        """Block until hark accepts a TCP connect on its listen port.

        Hark binds UDP and TCP in lockstep, so a successful TCP accept means
        the UDP socket is also live. TCP connect is the cleanest readiness
        signal — UDP send/recv would race the server's first poll.
        """
        deadline = time.monotonic() + timeout_s
        ip, port = self.listen_addr
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(
                    f"hark exited early (code={self.proc.returncode}); "
                    f"log:\n{self.read_log()}"
                )
            try:
                with socket.create_connection((ip, port), timeout=0.2):
                    return
            except (ConnectionRefusedError, socket.timeout, OSError):
                time.sleep(0.05)
        raise RuntimeError(
            f"hark did not become ready within {timeout_s}s; log:\n{self.read_log()}"
        )


@functools.cache
def find_hark_binary() -> Path:
    """Build hark with the test-only knobs enabled and return the binary path.

    Memoised so the per-session `zig build` runs once. `-Dtesting=true`
    enables the `[resolver] upstream-port` and `allow-loopback-upstreams`
    keys; without them hark refuses the test config with
    `error.TestOnlyConfigKey`.
    """
    repo = Path(__file__).resolve().parents[2]
    try:
        subprocess.run(
            ["zig", "build", "-Dtesting=true"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as e:
        raise RuntimeError("`zig` not found in PATH; install zig 0.16+") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"`zig build -Dtesting=true` failed:\n{e.stderr.decode(errors='replace')}"
        ) from e
    cand = repo / "zig-out" / "bin" / "hark"
    if not cand.exists():
        raise FileNotFoundError(f"hark binary not produced at {cand}")
    return cand
