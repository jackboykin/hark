"""A UDP reply later than a stub's timeout is never sent; TCP's still is."""

from __future__ import annotations

import socket
import struct
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor

import conftest
import dns.exception
import dns.message
import dns.query
import dns.rcode
import pytest

from . import rpl
from .client import send_raw_query

SILENT = "".join(
    textwrap.dedent(
        f"""\
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.{3 + i}
          ENTRY_BEGIN
            MATCH opcode
            ADJUST drop
            REPLY QR AA NOERROR
            SECTION QUESTION
              example.com. IN A
          ENTRY_END
        RANGE_END
        """
    )
    for i in range(2)
)

SCENARIO = (
    textwrap.dedent(
        """\
        ; hark: root-hints = 127.0.10.1
        ; hark: qname-minimisation = no

        SCENARIO_BEGIN two silent authorities outlast a stub
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.1
          ENTRY_BEGIN
            MATCH opcode subdomain
            ADJUST copy_id copy_query
            REPLY QR NOERROR
            SECTION QUESTION
              example.com. IN A
            SECTION AUTHORITY
              example.com. 86400 IN NS ns1.example.com.
              example.com. 86400 IN NS ns2.example.com.
            SECTION ADDITIONAL
              ns1.example.com. 86400 IN A 127.0.10.3
              ns2.example.com. 86400 IN A 127.0.10.4
          ENTRY_END
        RANGE_END
        """
    )
    + SILENT
    + "SCENARIO_END\n"
)


def tcp_query(name: str, timeout: float) -> tuple[dns.message.Message, float]:
    t0 = time.monotonic()
    with socket.create_connection(conftest.HARK_LISTEN, timeout=timeout) as s:
        wire = dns.message.make_query(name, "A").to_wire()
        s.sendall(struct.pack("!H", len(wire)) + wire)
        (n,) = struct.unpack("!H", s.recv(2))
        buf = b""
        while len(buf) < n:
            buf += s.recv(n - len(buf))
    return dns.message.from_wire(buf), time.monotonic() - t0


def test_late_udp_is_silent_and_tcp_is_answered(tmp_path):
    path = tmp_path / "late.rpl"
    path.write_text(SCENARIO)
    with conftest.scenario_env(rpl.parse(path)), ThreadPoolExecutor() as pool:
        udp = pool.submit(send_raw_query, "b.example.com.", "A", conftest.HARK_LISTEN, timeout=4.5)
        reply, took = tcp_query("a.example.com.", timeout=4.5)
        assert reply.rcode() == dns.rcode.SERVFAIL
        assert 2.0 < took < 4.0, f"{took:.2f} s: the test needs a reply due past 2 s and inside the UDP wait"
        # Asked together, so the UDP reply was due with TCP's.
        with pytest.raises(dns.exception.Timeout):
            udp.result()

        # The silent resolution finished and was remembered.
        t0 = time.monotonic()
        again = send_raw_query("b.example.com.", "A", conftest.HARK_LISTEN, timeout=2)
        assert again.rcode() == dns.rcode.SERVFAIL
        assert time.monotonic() - t0 < 0.5
