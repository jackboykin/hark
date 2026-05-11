"""Spawn and control a hark subprocess for one scenario.

Writes a generated TOML config (listen address, root hints, upstream port,
loopback bypass) to a temp file, launches hark, waits until it's ready by
probing it with a SOA query for the root, and tears it down at exit.
"""

from __future__ import annotations

import dataclasses
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

    def to_toml(self) -> str:
        listen = f'"{self.listen_ip}:{self.listen_port}"'
        # Root hints are passed in "ip:port" form so the existing parseAddress
        # path lifts them; the upstream-port knob covers glue records, which
        # have no port.
        hints = ", ".join(f'"{h}"' for h in self.root_hints) if self.root_hints else ""
        # `opportunistic` is explicitly off: hark's TLS transport hardcodes
        # port 853 (src/tls_transport.zig:32) and would bypass `upstream_port`,
        # silently mis-targeting the responder. Future scenarios needing
        # encrypted upstreams will require threading a `tls_port` knob first.
        return (
            f"[server]\n"
            f"listen = [{listen}]\n"
            f"workers = {self.workers}\n"
            f"\n"
            f"[resolver]\n"
            f"mode = \"recursive\"\n"
            f"qname-minimization = {str(self.qname_minimization).lower()}\n"
            f"dnssec = {str(self.dnssec).lower()}\n"
            f"opportunistic = false\n"
            f"upstream-port = {self.upstream_port}\n"
            f"allow-loopback-upstreams = true\n"
            + (f"root-hints = [{hints}]\n" if hints else "")
        )


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
        self.proc = subprocess.Popen(
            [str(self.binary), "serve", "--config", str(self.config_path)],
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


def find_hark_binary() -> Path:
    """Locate the hark binary built by `zig build`. Fails fast if any
    source under `src/` is newer than the binary — silent stale-binary
    runs mask regressions."""
    repo = Path(__file__).resolve().parents[2]
    cand = repo / "zig-out" / "bin" / "hark"
    if not cand.exists():
        raise FileNotFoundError(f"hark binary not found at {cand}; run `zig build`")
    binary_mtime = cand.stat().st_mtime
    for src in (repo / "src").rglob("*.zig"):
        if src.stat().st_mtime > binary_mtime:
            raise RuntimeError(
                f"hark binary at {cand} is stale (older than {src.relative_to(repo)}); "
                f"run `zig build`"
            )
    return cand
