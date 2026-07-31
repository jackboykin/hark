"""Shared plumbing for wrapped server subprocesses (hark, unbound).

Subclasses spawn the process in `__enter__` (setting `self.proc` and
`self.log_path`/`self._log_fd`), expose a `config` with `listen_ip` /
`listen_port`, and set `name` for error messages. This base carries
teardown, log access, and the TCP-readiness wait.
"""

from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path
from typing import IO


class ServerProcess:
    name = "server"

    proc: subprocess.Popen | None
    log_path: Path | None
    _log_fd: IO[bytes] | None

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
        """Block until the server accepts a TCP connect on its listen port.

        Both hark and unbound bind UDP and TCP in lockstep, so a successful
        TCP accept means the UDP socket is also live. TCP connect is the
        cleanest readiness signal — UDP send/recv would race the server's
        first poll.
        """
        deadline = time.monotonic() + timeout_s
        ip, port = self.listen_addr
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(
                    f"{self.name} exited early (code={self.proc.returncode}); "
                    f"log:\n{self.read_log()}"
                )
            try:
                with socket.create_connection((ip, port), timeout=0.2):
                    return
            except (ConnectionRefusedError, socket.timeout, OSError):
                time.sleep(0.05)
        raise RuntimeError(
            f"{self.name} did not become ready within {timeout_s}s; log:\n{self.read_log()}"
        )
