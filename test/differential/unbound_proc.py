"""Spawn and control an Unbound subprocess for differential tests.

Mirrors `harness.hark_proc` in shape: a config dataclass + a context-manager
process wrapper. Stub-zone "." pointing at the test responder is the trick
that lets Unbound talk to a fake auth on a non-53 port without root —
Unbound's `forward-addr` / `stub-addr` directives accept `ip@port` syntax,
so we sidestep the same glue-port limitation hark has.
"""

from __future__ import annotations

import dataclasses
import socket
import subprocess
import time
from pathlib import Path
from typing import IO


@dataclasses.dataclass
class UnboundConfig:
    listen_ip: str = "127.0.0.1"
    listen_port: int = 5354
    # `ip@port` per unbound.conf(5) — bypasses the no-port-in-glue limitation.
    upstream_addr: str = "127.0.10.1@5353"
    # cache-min-ttl: when >0, Unbound silently bumps every record's TTL to
    # this floor — *including* records the auth marked TTL=0 to prevent
    # caching. Hark's parallel `[cache] min-ttl` knob explicitly excludes
    # TTL=0 from the bump (`cache.zig:871,776`). The differential test sets
    # this >0 to surface the divergence; production resolvers commonly run
    # cache-min-ttl=60-300 for upstream-load shaping.
    #
    # Before Unbound 1.24.0 (PR NLnetLabs/unbound#1337, 2025-09), Unbound
    # cached TTL=0 records by default with a ~1-second grace period even
    # without this floor set. shell.nix pins ≥1.24, so the divergence now
    # only surfaces under a non-zero floor.
    cache_min_ttl: int = 60

    def to_text(self) -> str:
        return (
            "server:\n"
            f"  interface: {self.listen_ip}\n"
            f"  port: {self.listen_port}\n"
            "  do-ip6: no\n"
            "  use-syslog: no\n"
            "  verbosity: 0\n"
            "  access-control: 127.0.0.0/8 allow\n"
            # Default blocks 127/8 as upstream — same rebinding-defence
            # posture hark has. Disable for the test.
            "  do-not-query-localhost: no\n"
            "  qname-minimisation: no\n"
            "  harden-glue: no\n"
            f"  cache-min-ttl: {self.cache_min_ttl}\n"
            "  pidfile: \"\"\n"
            "  chroot: \"\"\n"
            "  username: \"\"\n"
            "  directory: \"\"\n"
            # forward-zone (vs stub-zone) avoids root-priming entirely:
            # unbound treats the forwarder as a recursive resolver and sends
            # queries directly. Caching of forwarded answers is on by default
            # — that's the behaviour we exercise. `forward-first: no` keeps
            # unbound from falling back to the built-in IANA roots.
            "forward-zone:\n"
            "  name: \".\"\n"
            f"  forward-addr: {self.upstream_addr}\n"
            "  forward-first: no\n"
            "  forward-no-cache: no\n"
        )


class UnboundProcess:
    """Wrap a running unbound binary. Use as a context manager."""

    def __init__(self, config: UnboundConfig, tmpdir: Path):
        self.config = config
        self.tmpdir = tmpdir
        self.proc: subprocess.Popen | None = None
        self.config_path: Path | None = None
        self.log_path: Path | None = None
        self._log_fd: IO[bytes] | None = None

    def __enter__(self) -> "UnboundProcess":
        self.config_path = self.tmpdir / "unbound.conf"
        self.config_path.write_text(self.config.to_text())
        self.log_path = self.tmpdir / "unbound.log"
        self._log_fd = self.log_path.open("wb")
        # `-d` foreground, `-v` verbose to stderr (we capture both streams).
        self.proc = subprocess.Popen(
            ["unbound", "-d", "-c", str(self.config_path)],
            stdout=self._log_fd,
            stderr=self._log_fd,
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

    def read_log(self) -> str:
        return self.log_path.read_text() if self.log_path else ""

    @property
    def listen_addr(self) -> tuple[str, int]:
        return (self.config.listen_ip, self.config.listen_port)

    def _wait_ready(self, timeout_s: float = 5.0) -> None:
        deadline = time.monotonic() + timeout_s
        ip, port = self.listen_addr
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(
                    f"unbound exited early (code={self.proc.returncode}); "
                    f"log:\n{self.read_log()}"
                )
            try:
                with socket.create_connection((ip, port), timeout=0.2):
                    return
            except (ConnectionRefusedError, socket.timeout, OSError):
                time.sleep(0.05)
        raise RuntimeError(
            f"unbound did not become ready within {timeout_s}s; log:\n{self.read_log()}"
        )
