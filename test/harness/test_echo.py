"""A UDP client that joins a resolution waits as long as the first one did."""

from __future__ import annotations

import socket
import textwrap
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import conftest
import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from . import rpl
from .client import send_raw_query
from .test_late_replies import tcp_query

GATE = "127.0.10.5"

SCENARIO = textwrap.dedent(
    f"""\
    ; hark: root-hints = 127.0.10.1
    ; hark: qname-minimisation = no

    SCENARIO_BEGIN a gated authority settles a name two clients wait on
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
        SECTION ADDITIONAL
          ns1.example.com. 86400 IN A {GATE}
      ENTRY_END
    RANGE_END
    SCENARIO_END
    """
)


class Gate:
    """An authority that holds every question until `open` is set."""

    def __init__(self) -> None:
        self.open = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((GATE, conftest.RESP_PORT))
        self.sock.settimeout(0.05)
        self.held: list[tuple[dns.message.Message, tuple]] = []
        self.done = False
        self.thread = threading.Thread(target=self.run, daemon=True)

    def __enter__(self) -> Gate:
        self.thread.start()
        return self

    def __exit__(self, *_) -> None:
        self.done = True
        self.thread.join()
        self.sock.close()

    def run(self) -> None:
        while not self.done:
            try:
                wire, addr = self.sock.recvfrom(4096)
                self.held.append((dns.message.from_wire(wire), addr))
            except TimeoutError:
                pass
            if self.open.is_set():
                for q, addr in self.held:
                    r = dns.message.make_response(q)
                    r.flags |= dns.flags.AA
                    r.answer.append(dns.rrset.from_text(q.question[0].name, 300, "IN", "A", "192.0.2.7"))
                    self.sock.sendto(r.to_wire(), addr)
                self.held.clear()


def test_a_joiner_waits_as_long_as_the_first(tmp_path):
    path = tmp_path / "echo.rpl"
    path.write_text(SCENARIO)
    with conftest.scenario_env(rpl.parse(path)), Gate() as gate, ThreadPoolExecutor() as pool:
        def udp():
            send_raw_query("a.example.com.", "A", conftest.HARK_LISTEN, timeout=3)
            return time.monotonic()

        def tcp():
            tcp_query("a.example.com.", timeout=3)
            return time.monotonic()

        first = pool.submit(udp)
        time.sleep(1.0)
        joiner = pool.submit(udp)
        unspoofable = pool.submit(tcp)
        time.sleep(0.1)
        gate.open.set()
        opened = time.monotonic()

        assert first.result() - opened < 0.5
        assert unspoofable.result() - opened < 0.5
        # Asked ~1 s after the first, so due ~1 s after the answer.
        assert 0.5 < joiner.result() - opened < 1.8

        # Settled and remembered: the next ask is a hit, answered at once.
        t0 = time.monotonic()
        assert send_raw_query("a.example.com.", "A", conftest.HARK_LISTEN, timeout=1).rcode() == dns.rcode.NOERROR
        assert time.monotonic() - t0 < 0.5
