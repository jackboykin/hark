"""TCP clients: pipelining, many concurrent connections, idle close.

`.invalid` is RFC 6761 special-use: hark synthesises NXDOMAIN with zero
upstream work, so no responder is needed.
"""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

import dns.message
import dns.rcode
import pytest

from .hark_proc import HarkConfig, HarkProcess, find_hark_binary

HARK_PORT = 15355
IDLE_MS = 1500


@pytest.fixture(scope="module")
def hark(tmp_path_factory: pytest.TempPathFactory):
    cfg = HarkConfig(listen_port=HARK_PORT, tcp_idle_timeout_ms=IDLE_MS)
    with HarkProcess(find_hark_binary(), cfg, tmp_path_factory.mktemp("tcp")) as h:
        yield h


def framed(name: str, qid: int) -> bytes:
    q = dns.message.make_query(name, "A")
    q.id = qid
    wire = q.to_wire()
    return struct.pack("!H", len(wire)) + wire


def read_responses(sock: socket.socket, count: int) -> dict[int, dns.message.Message]:
    buf = b""
    out: dict[int, dns.message.Message] = {}
    while len(out) < count:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 2:
            (n,) = struct.unpack("!H", buf[:2])
            if len(buf) < 2 + n:
                break
            msg = dns.message.from_wire(buf[2 : 2 + n])
            out[msg.id] = msg
            buf = buf[2 + n :]
    return out


def connect() -> socket.socket:
    return socket.create_connection(("127.0.0.1", HARK_PORT), timeout=10)


def test_frames_split_across_reads(hark: HarkProcess) -> None:
    """Length prefix and body each straddle a read; the tail frame is whole."""
    ids = list(range(1, 9))
    wire = b"".join(framed(f"p{i}.invalid.", i) for i in ids)
    with connect() as s:
        for cut in (1, 7, len(wire) - 20):
            s.sendall(wire[:cut])
            time.sleep(0.05)
            wire = wire[cut:]
        s.sendall(wire)
        got = read_responses(s, len(ids))
    assert sorted(got) == ids
    assert all(m.rcode() == dns.rcode.NXDOMAIN for m in got.values())


def test_half_close_still_answered(hark: HarkProcess) -> None:
    with connect() as s:
        s.sendall(framed("half.invalid.", 9))
        s.shutdown(socket.SHUT_WR)
        assert list(read_responses(s, 1)) == [9]


def test_oversized_frame_closes(hark: HarkProcess) -> None:
    with connect() as s:
        s.sendall(struct.pack("!H", 65535) + b"\0" * 64)
        assert s.recv(16) == b""


def test_slots_recycle(hark: HarkProcess) -> None:
    # One worker, 64 ring slots: a leaked slot or client shows up here.
    for i in range(200):
        with connect() as s:
            s.sendall(framed(f"r{i}.invalid.", i))
            assert list(read_responses(s, 1)) == [i]


def test_many_concurrent_connections(hark: HarkProcess) -> None:
    socks = [connect() for _ in range(16)]
    try:
        for i, s in enumerate(socks, start=100):
            s.sendall(framed(f"c{i}.invalid.", i))
        for i, s in enumerate(socks, start=100):
            got = read_responses(s, 1)
            assert list(got) == [i]
    finally:
        for s in socks:
            s.close()


def test_idle_connection_is_closed(hark: HarkProcess) -> None:
    with connect() as s:
        s.sendall(framed("idle.invalid.", 7))
        assert list(read_responses(s, 1)) == [7]
        t0 = time.monotonic()
        assert s.recv(16) == b""
        elapsed = time.monotonic() - t0
    # Sweep runs once a second on top of the configured idle timeout.
    assert IDLE_MS / 1000 - 0.2 <= elapsed <= IDLE_MS / 1000 + 2
