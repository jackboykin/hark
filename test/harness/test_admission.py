"""Admission: what hark takes on while it is loaded."""

from __future__ import annotations

import re
import signal
import socket
import textwrap
import time

import conftest
import dns.exception
import dns.message
import dns.rcode
import pytest

from . import rpl
from .client import send_raw_query

# Sixteen silent servers: a resolution there outlives its client's
# timeout (2 s), trying each in turn, and ends at the deadline (7 s).
SILENT = range(10, 26)

SCENARIO = (
    textwrap.dedent(
        """\
        ; hark: root-hints = 127.0.10.1
        ; hark: qname-minimisation = no

        SCENARIO_BEGIN a silent zone beside a live one
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.1
          ENTRY_BEGIN
            MATCH opcode subdomain
            ADJUST copy_id copy_query
            REPLY QR NOERROR
            SECTION QUESTION
              silent. IN A
            SECTION AUTHORITY
        """
    )
    + "".join(f"          silent. 86400 IN NS ns{i}.silent.\n" for i in SILENT)
    + "        SECTION ADDITIONAL\n"
    + "".join(f"          ns{i}.silent. 86400 IN A 127.0.10.{i}\n" for i in SILENT)
    + textwrap.dedent(
        """\
          ENTRY_END
          ENTRY_BEGIN
            MATCH opcode subdomain
            ADJUST copy_id copy_query
            REPLY QR NOERROR
            SECTION QUESTION
              live. IN A
            SECTION AUTHORITY
              live. 86400 IN NS ns.live.
            SECTION ADDITIONAL
              ns.live. 86400 IN A 127.0.10.2
          ENTRY_END
        RANGE_END
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.2
          ENTRY_BEGIN
            MATCH opcode subdomain
            ADJUST copy_id copy_query
            REPLY QR AA NOERROR
            SECTION QUESTION
              live. IN A
            SECTION ANSWER
              live. 3600 IN A 192.0.2.1
          ENTRY_END
        RANGE_END
        """
    )
    + "".join(
        textwrap.dedent(
            f"""\
            RANGE_BEGIN 0 100
              ADDRESS 127.0.10.{i}
              ENTRY_BEGIN
                MATCH opcode
                ADJUST drop
                REPLY QR AA NOERROR
                SECTION QUESTION
                  silent. IN A
              ENTRY_END
            RANGE_END
            """
        )
        for i in SILENT
    )
    + "SCENARIO_END\n"
)

# Room for a handful of resolutions' counted work.
TINY_CACHE = 32 * 1024


def fire(names: list[str]) -> None:
    """UDP questions nobody waits on."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for n in names:
            s.sendto(dns.message.make_query(n, "A").to_wire(), conftest.HARK_LISTEN)


def advance(seconds: int) -> None:
    send_raw_query(f"_advance-clock.{seconds}.testharness.invalid.", "A", conftest.HARK_LISTEN)
    # A reply asking nothing upstream: the loop looks at its timers.
    send_raw_query("localhost.", "A", conftest.HARK_LISTEN)


def stats(proc) -> dict[str, int]:
    before = proc.read_log().count("stats clients")
    proc.proc.send_signal(signal.SIGUSR1)
    deadline = time.monotonic() + 2
    while proc.read_log().count("stats clients") == before and time.monotonic() < deadline:
        time.sleep(0.01)
    line = proc.read_log().split("stats clients")[-1].split("\n")[0]
    return {k: int(v) for k, v in re.findall(r"([a-z]+) (\d+)", line)}


@pytest.fixture
def hark(tmp_path):
    path = tmp_path / "admission.rpl"
    path.write_text(SCENARIO)
    with conftest.scenario_env(rpl.parse(path), cache_size=TINY_CACHE) as (_, proc):
        yield proc


def test_late_waiters_make_room_for_new_questions(hark):
    fire([f"q{i}.silent." for i in range(64)])
    # Past the ceiling, a new question is turned away while the silent
    # zone's clients are still owed an answer.
    with pytest.raises(dns.exception.Timeout):
        send_raw_query("a.live.", "A", conftest.HARK_LISTEN, timeout=0.3)
    # Past their timeout (2 s) the next question makes them let go, oldest
    # first; what they had in flight ends as orphans, and there is room.
    advance(3)
    fire(["b.live."])
    advance(2)
    assert send_raw_query("c.live.", "A", conftest.HARK_LISTEN, timeout=2).rcode() == dns.rcode.NOERROR
    assert stats(hark)["reaped"] > 0
