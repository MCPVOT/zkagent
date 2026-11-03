#!/usr/bin/env python3
"""Tests for the loop ledger's reproducibility fields.

The ledger is consumed by `loop.py next`; a row that cannot be reproduced is a
row that will be cited wrongly a month later. These tests pin the two fields
that make a row checkable: the commit it was measured on and the artifact
format that was current at the time.

Run: python3 tools/test_loop.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import loop  # noqa: E402


class LedgerRowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"
        self._saved = loop.LEDGER
        loop.LEDGER = self.ledger

    def tearDown(self) -> None:
        loop.LEDGER = self._saved
        self.tmp.cleanup()

    def record(self, commit: str | None = None, hint: str = "") -> dict:
        args = argparse.Namespace(
            phase="verifier",
            action="a test row",
            result="pass",
            metric="x=1",
            note="",
            commit=commit,
            next_hint=hint,
        )
        loop.cmd_record(args)
        return json.loads(self.ledger.read_text(encoding="utf-8").splitlines()[-1])

    def test_row_carries_commit_and_format(self) -> None:
        row = self.record()
        self.assertTrue(row["commit"], "a row with no commit cannot be reproduced")
        self.assertRegex(row["commit"], r"^[0-9a-f]{4,40}$")
        # Derived, never hardcoded: the format moves when the circuit moves.
        self.assertEqual(row["format"], loop.format_version())
        self.assertRegex(row["format"], r"^\d+$")

    def test_explicit_commit_wins(self) -> None:
        row = self.record(commit="deadbee")
        self.assertEqual(row["commit"], "deadbee")

    def test_status_flags_rows_that_predate_capture(self) -> None:
        self.ledger.write_text(
            json.dumps({"ts": "2026-01-01T00:00:00+00:00", "phase": "docs",
                        "action": "old row", "result": "pass"}) + "\n"
            + json.dumps(self.record()) + "\n",
            encoding="utf-8",
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            loop.cmd_status(argparse.Namespace())
        out = buf.getvalue()
        self.assertIn("1 row(s) predate commit capture", out)

    def test_status_is_silent_when_every_row_is_checkable(self) -> None:
        self.ledger.write_text(json.dumps(self.record()) + "\n", encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            loop.cmd_status(argparse.Namespace())
        self.assertNotIn("predate", buf.getvalue())


class HandOffTest(unittest.TestCase):
    """A unit that leaves work behind must say so, or the loop only sees counters."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"
        self._saved = loop.LEDGER
        loop.LEDGER = self.ledger

    def tearDown(self) -> None:
        loop.LEDGER = self._saved
        self.tmp.cleanup()

    def add(self, action: str, hint: str) -> None:
        loop.cmd_record(
            argparse.Namespace(
                phase="docs",
                action=action,
                result="pass",
                metric="",
                note="",
                commit="cafe123",
                next_hint=hint,
            )
        )

    def test_a_hint_is_printed_first_and_newest_first(self) -> None:
        self.add("first unit", "do the second thing")
        self.add("second unit", "do the third thing")
        out = loop.recommend(loop.read_rows())
        self.assertTrue(out[0].startswith("handed off: do the third thing"), out)
        self.assertTrue(out[1].startswith("handed off: do the second thing"), out)

    def test_hints_are_capped_and_deduplicated(self) -> None:
        self.add("a", "same hint")
        self.add("b", "same hint")
        for i in range(5):
            self.add(f"unit {i}", f"hint {i}")
        out = [line for line in loop.recommend(loop.read_rows()) if line.startswith("handed off:")]
        self.assertEqual(len(out), 3, out)
        self.assertEqual(len(out), len(set(out)), out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
