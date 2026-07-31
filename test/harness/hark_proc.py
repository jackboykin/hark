"""Spawn and control a hark subprocess for one scenario.

Writes a generated TOML config (listen address, root hints, upstream port,
loopback bypass) to a temp file, launches hark, waits until it's ready by
probing it with a SOA query for the root, and tears it down at exit.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import shlex
import subprocess
from pathlib import Path
from typing import IO

from .proc import ServerProcess


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
    # NS-racing stagger in ms; None = hark default (150). 0 disables the
    # staggered race, forcing the deterministic sequential server loop.
    stagger_ms: int | None = None
    # Each entry is a `"<key-tag> <alg> <dtype> <hex>"` string fed to
    # hark's test-only `[resolver] trust-anchors = [...]` knob. Requires
    # `dnssec = true`; to_toml enforces that pairing.
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
        if self.trust_anchors and not self.dnssec:
            raise ValueError(
                "trust_anchors set without dnssec=True — hark would never "
                "consult the anchors and the scenario would test nothing"
            )
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
        if self.stagger_ms is not None:
            lines.append(f"stagger-ms = {self.stagger_ms}")
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


class HarkProcess(ServerProcess):
    """Wrap a running hark binary. Use as a context manager."""

    name = "hark"

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
        argv = [str(self.binary), "serve", "--config", str(self.config_path)]
        if self.config.verbose:
            argv.append("--verbose")
        # Hark logs to stderr; capture both streams in one log file.
        self.proc = subprocess.Popen(
            argv,
            stdout=self._log_fd,
            stderr=self._log_fd,
        )
        self._wait_ready()
        return self

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


@functools.cache
def find_hark_binary() -> Path:
    """Build hark with the test-only knobs enabled and return the binary path.

    Memoised so the per-session `zig build` runs once. `-Dtesting=true`
    enables the `[resolver] upstream-port` and `allow-loopback-upstreams`
    keys; without them hark refuses the test config with
    `error.TestOnlyConfigKey`.

    `HARK_BUILD_ARGS` appends flags, so the pre-tag release check needs no
    second code path: `HARK_BUILD_ARGS=-Doptimize=ReleaseFast pytest`.
    Output-prefix flags are refused: the returned path is hardcoded below,
    so `-p` would silently hand back whatever stale binary sits in
    `zig-out/bin`.
    """
    repo = Path(__file__).resolve().parents[2]
    extra = shlex.split(os.environ.get("HARK_BUILD_ARGS", ""))
    for i, arg in enumerate(extra):
        if arg in ("-p", "--prefix") or arg.startswith("--prefix="):
            raise RuntimeError(
                f"HARK_BUILD_ARGS[{i}]={arg!r} redirects the install prefix, but "
                f"find_hark_binary() always returns zig-out/bin/hark — the suite "
                f"would silently test a stale binary. Remove it."
            )
    try:
        subprocess.run(
            ["zig", "build", "-Dtesting=true", *extra],
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
