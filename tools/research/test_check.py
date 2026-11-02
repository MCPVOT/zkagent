"""Tests for the research-corpus checker.

The corpus is 400 KB of cited markdown that no test has ever read. A claim in it
is load-bearing — `ARCHITECTURE.md` points at these reports as the evidence for
its decisions — so the things that rot silently need a check: a report nobody
listed, a manifest entry pointing at a file that was renamed, a date that is not
a date, two documents claiming the same id.

Stdlib only, same rule as `tools/leaderboard/test_generate.py`, because CI runs
it on both ubuntu and windows with whatever python exists there.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from tools.research import check  # noqa: E402


def write(root: pathlib.Path, rel: str, text: str) -> pathlib.Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def corpus(root: pathlib.Path, docs: list[dict], files: dict[str, str], readme: str) -> pathlib.Path:
    write(root, "docs/research/README.md", readme)
    for rel, text in files.items():
        write(root, f"docs/research/{rel}", text)
    return write(
        root,
        "docs/research/corpus.json",
        json.dumps({"version": 1, "documents": docs}, indent=2),
    )


DOC = {
    "id": "01",
    "path": "01-example.md",
    "title": "Example",
    "as_of": "2026-10-27",
    "status": "current",
    "slices": ["proving-stack"],
    "sources_checked": "2026-10-27",
}
BODY = "# Example\n\nSee [a](https://example.org/a) and [b](https://example.org/b).\n"


class CorpusCheck(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_check(self) -> tuple[int, str]:
        return check.run(self.root, quiet=True)

    def test_a_consistent_corpus_passes(self) -> None:
        corpus(self.root, [DOC], {"01-example.md": BODY}, "# Research\n\n- [Example](01-example.md)\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, out)
        self.assertIn("1 document", out)

    def test_a_report_missing_from_the_manifest_fails(self) -> None:
        corpus(
            self.root,
            [DOC],
            {"01-example.md": BODY, "02-orphan.md": "# Orphan\n"},
            "# Research\n\n- [Example](01-example.md)\n",
        )
        code, out = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("02-orphan.md", out)

    def test_a_manifest_entry_with_no_file_fails(self) -> None:
        corpus(self.root, [DOC], {}, "# Research\n")
        code, out = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("01-example.md", out)

    def test_duplicate_ids_fail(self) -> None:
        second = dict(DOC, path="02-example.md")
        corpus(
            self.root,
            [DOC, second],
            {"01-example.md": BODY, "02-example.md": BODY},
            "# Research\n\n- [Example](01-example.md)\n- [Two](02-example.md)\n",
        )
        code, out = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("duplicate", out.lower())

    def test_a_date_that_is_not_a_date_fails(self) -> None:
        bad = dict(DOC, as_of="last tuesday")
        corpus(self.root, [bad], {"01-example.md": BODY}, "# Research\n\n- [E](01-example.md)\n")
        code, out = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("as_of", out)

    def test_an_unknown_status_fails(self) -> None:
        bad = dict(DOC, status="probably-fine")
        corpus(self.root, [bad], {"01-example.md": BODY}, "# Research\n\n- [E](01-example.md)\n")
        code, out = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("status", out)

    def test_supersedes_must_name_a_real_id(self) -> None:
        bad = dict(DOC, supersedes="07")
        corpus(self.root, [bad], {"01-example.md": BODY}, "# Research\n\n- [E](01-example.md)\n")
        code, out = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("supersedes", out)

    def test_readme_must_link_every_report(self) -> None:
        corpus(self.root, [DOC], {"01-example.md": BODY}, "# Research\n\nno links here\n")
        code, out = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("README", out)

    def test_a_document_with_no_sources_is_reported(self) -> None:
        corpus(self.root, [DOC], {"01-example.md": "# Example\n\nno urls\n"}, "# Research\n\n- [E](01-example.md)\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, "a source-less doc is a warning, not a failure")
        self.assertIn("0 sources", out)

    def test_source_counting_counts_unique_urls(self) -> None:
        body = "# Example\n\n[a](https://example.org/a) [a again](https://example.org/a) [b](https://example.org/b)\n"
        corpus(self.root, [DOC], {"01-example.md": body}, "# Research\n\n- [E](01-example.md)\n")
        code, out = self.run_check()
        self.assertEqual(code, 0)
        self.assertIn("2 sources", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
