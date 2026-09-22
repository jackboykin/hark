"""Out of file descriptors, an upstream exchange never leaves the host.

That silence is hark's own: it is counted as unsent, not as a timeout
against the server or the question, and the resolver answers again once
fds free up, the question that failed included.
"""

from __future__ import annotations

import os
import re
import resource
import signal
import textwrap
import time

import conftest
import dns.rcode

from . import rpl
from .client import send_raw_query

SCENARIO = textwrap.dedent(
    """\
    ; hark: root-hints = 127.0.10.1

    SCENARIO_BEGIN one authority for everything
    RANGE_BEGIN 0 100
      ADDRESS 127.0.10.1
      ENTRY_BEGIN
        MATCH opcode
        ADJUST copy_id copy_query
        REPLY QR AA NOERROR
        SECTION QUESTION
          example.com. IN A
        SECTION ANSWER
          example.com. 60 IN A 192.0.2.1
      ENTRY_END
    RANGE_END
    SCENARIO_END
    """
)


def lowest_free_fd(pid: int) -> int:
    used = {int(fd) for fd in os.listdir(f"/proc/{pid}/fd")}
    return next(n for n in range(len(used) + 1) if n not in used)


def test_fd_exhaustion_is_unsent_not_a_timeout(tmp_path):
    path = tmp_path / "fds.rpl"
    path.write_text(SCENARIO)
    with conftest.scenario_env(rpl.parse(path)) as (_, proc):
        pid = proc.proc.pid
        assert send_raw_query("a.example.com.", "A", conftest.HARK_LISTEN).rcode() == dns.rcode.NOERROR
        before = resource.prlimit(pid, resource.RLIMIT_NOFILE)
        # The next socket hark opens is past the limit.
        n = lowest_free_fd(pid)
        resource.prlimit(pid, resource.RLIMIT_NOFILE, (n, before[1]))
        assert send_raw_query("b.example.com.", "A", conftest.HARK_LISTEN).rcode() == dns.rcode.SERVFAIL
        resource.prlimit(pid, resource.RLIMIT_NOFILE, before)
        # Not RFC 8914's cached error: the failure was hark's, not b's.
        assert send_raw_query("b.example.com.", "A", conftest.HARK_LISTEN).rcode() == dns.rcode.NOERROR

        os.kill(pid, signal.SIGUSR1)
        deadline = time.monotonic() + 2
        while not (m := re.search(r"timeout (\d+)  unsent (\d+)", proc.read_log())) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert m, proc.read_log()
        timeouts, unsent = map(int, m.groups())
        assert unsent >= 1
        assert timeouts == 0
