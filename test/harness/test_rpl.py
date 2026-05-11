"""Parser robustness tests.

Each scenario file under `scenarios/` is also implicitly an integration test
of the parser, but those run hark and take seconds. These tests exercise the
parser directly with adversarial inputs at unit speed.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from . import rpl


def _parse(text: str, tmp_path: Path) -> rpl.Scenario:
    path = tmp_path / "scenario.rpl"
    path.write_text(textwrap.dedent(text))
    return rpl.parse(path)


def _parse_fails(text: str, tmp_path: Path, match: str) -> None:
    with pytest.raises(Exception) as exc_info:
        _parse(text, tmp_path)
    assert match in str(exc_info.value), f"expected {match!r} in {exc_info.value!r}"


# ── Happy-path baseline ──────────────────────────────────────────────────


def test_minimal_scenario_parses(tmp_path):
    s = _parse(
        """\
        ; hark: root-hints = 127.0.10.1

        SCENARIO_BEGIN minimal
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.1
          ENTRY_BEGIN
            MATCH opcode qname
            ADJUST copy_id copy_query
            REPLY QR AA NOERROR
            SECTION QUESTION
              example.com. IN A
            SECTION ANSWER
              example.com. 3600 IN A 1.2.3.4
          ENTRY_END
        RANGE_END
        STEP 1 QUERY
        ENTRY_BEGIN
          REPLY RD
          SECTION QUESTION
            example.com. IN A
        ENTRY_END
        SCENARIO_END
        """,
        tmp_path,
    )
    assert s.root_hints == ["127.0.10.1"]
    assert len(s.ranges) == 1
    assert s.ranges[0].address == "127.0.10.1"
    assert len(s.steps) == 1


# ── Malformed input the parser must reject at parse time ─────────────────


@pytest.mark.parametrize(
    "entry_body,expected",
    [
        # The typo `quesiton` would silently match-anything if accepted.
        ("MATCH opcode quesiton\n    REPLY QR NOERROR", "unknown MATCH flag"),
        ("ADJUST copy_idd\n    REPLY QR NOERROR", "unknown ADJUST flag"),
        ("REPLY QR NXOMAIN", "unknown REPLY token"),
    ],
)
def test_entry_body_rejections(tmp_path, entry_body, expected):
    _parse_fails(
        f"""\
        SCENARIO_BEGIN typo
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.1
          ENTRY_BEGIN
            {entry_body}
            SECTION QUESTION
              x. IN A
          ENTRY_END
        RANGE_END
        SCENARIO_END
        """,
        tmp_path,
        match=expected,
    )


def test_duplicate_step_number_rejected(tmp_path):
    _parse_fails(
        """\
        SCENARIO_BEGIN dup
        STEP 1 QUERY
        ENTRY_BEGIN
          REPLY RD
          SECTION QUESTION
            x. IN A
        ENTRY_END
        STEP 1 CHECK_ANSWER
        ENTRY_BEGIN
          MATCH all
          REPLY QR
          SECTION QUESTION
            x. IN A
        ENTRY_END
        SCENARIO_END
        """,
        tmp_path,
        match="duplicate STEP 1",
    )


def test_range_without_address_rejected(tmp_path):
    _parse_fails(
        """\
        SCENARIO_BEGIN no_addr
        RANGE_BEGIN 0 100
          ENTRY_BEGIN
            REPLY QR NOERROR
            SECTION QUESTION
              x. IN A
          ENTRY_END
        RANGE_END
        SCENARIO_END
        """,
        tmp_path,
        match="RANGE without ADDRESS",
    )


def test_missing_scenario_begin_rejected(tmp_path):
    _parse_fails(
        """\
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.1
        RANGE_END
        """,
        tmp_path,
        match="expected SCENARIO_BEGIN",
    )


def test_missing_scenario_end_rejected(tmp_path):
    _parse_fails(
        """\
        SCENARIO_BEGIN unterminated
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.1
        RANGE_END
        """,
        tmp_path,
        match="missing SCENARIO_END",
    )


def test_step_without_entry_rejected(tmp_path):
    _parse_fails(
        """\
        SCENARIO_BEGIN bad_step
        STEP 1 QUERY
        SCENARIO_END
        """,
        tmp_path,
        match="requires an ENTRY block",
    )


def test_rr_outside_section_rejected(tmp_path):
    _parse_fails(
        """\
        SCENARIO_BEGIN no_section
        RANGE_BEGIN 0 100
          ADDRESS 127.0.10.1
          ENTRY_BEGIN
            REPLY QR NOERROR
            example.com. IN A
          ENTRY_END
        RANGE_END
        SCENARIO_END
        """,
        tmp_path,
        match="RR outside SECTION",
    )


# ── Header directives ────────────────────────────────────────────────────


def test_root_hints_directive_parsed(tmp_path):
    s = _parse(
        """\
        ; hark: root-hints = 127.0.10.1, 127.0.10.2

        SCENARIO_BEGIN multi
        SCENARIO_END
        """,
        tmp_path,
    )
    assert s.root_hints == ["127.0.10.1", "127.0.10.2"]


def test_missing_root_hints_is_empty(tmp_path):
    # Parser is neutral; conftest decides whether to require root-hints.
    s = _parse(
        """\
        SCENARIO_BEGIN none
        SCENARIO_END
        """,
        tmp_path,
    )
    assert s.root_hints == []
