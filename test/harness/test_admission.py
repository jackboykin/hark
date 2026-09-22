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
            MATCH opcode qname
            ADJUST copy_id copy_query
            REPLY QR AA NOERROR
            SECTION QUESTION
              popular.live. IN A
            SECTION ANSWER
              popular.live. 1 IN A 192.0.2.7
          ENTRY_END
          ENTRY_BEGIN
            MATCH opcode qname
            ADJUST copy_id copy_query
            REPLY QR AA NOERROR
            SECTION QUESTION
              hit.live. IN A
            SECTION ANSWER
              hit.live. 3600 IN A 192.0.2.8
          ENTRY_END
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


def serve(tmp_path, cache_size: int | None = None):
    path = tmp_path / "admission.rpl"
    path.write_text(SCENARIO)
    return conftest.scenario_env(rpl.parse(path), cache_size=cache_size)


@pytest.fixture
def hark(tmp_path):
    with serve(tmp_path, TINY_CACHE) as (_, proc):
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


def test_a_crowded_queue_sheds_novel_names_only(tmp_path):
    with serve(tmp_path) as (_, proc):
        for name in ("hit.live.", "popular.live."):
            assert send_raw_query(name, "A", conftest.HARK_LISTEN).rcode() == dns.rcode.NOERROR
        advance(2)  # popular.live's TTL (1 s) lapses; its answer stays on record.
        # Queued while hark is stopped, the burst fills its 2 MB receive
        # buffer (a loopback datagram takes ~1 KB of it) and the kernel drops
        # the overflow: hark's first wake finds the queue crowded.
        burst = ["novel.live.", "popular.live."] + ["hit.live."] * 3000
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
            proc.proc.send_signal(signal.SIGSTOP)
            try:
                for name in burst:
                    s.sendto(dns.message.make_query(name, "A").to_wire(), conftest.HARK_LISTEN)
            finally:
                proc.proc.send_signal(signal.SIGCONT)
            s.settimeout(1)
            answered: dict[str, int] = {}
            try:
                while True:
                    reply = dns.message.from_wire(s.recv(4096))
                    assert reply.rcode() == dns.rcode.NOERROR
                    name = reply.question[0].name.to_text().lower()
                    answered[name] = answered.get(name, 0) + 1
            except socket.timeout:
                pass
        assert answered.get("hit.live.", 0) > 1000
        assert answered.get("popular.live.") == 1
        assert "novel.live." not in answered
        assert stats(proc)["shed"] == 1
        # Drained, a novel name gets in.
        assert send_raw_query("novel.live.", "A", conftest.HARK_LISTEN).rcode() == dns.rcode.NOERROR
