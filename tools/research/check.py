"""Check the research corpus is coherent, not merely committed.

`docs/research/` is 400 KB of cited markdown, and `docs/ARCHITECTURE.md` points
at it as the evidence for its decisions. Nothing has ever verified that the
corpus stays coherent as it is edited: a report renamed out from under the index,
a manifest entry pointing at a file that no longer exists, two documents claiming
the same id, a date that is not a date.

**One producer, one consumer** — the rule `tools/loop.py` taught this repo. The
producer is `docs/research/corpus.json`; the consumer is this checker, which is
also the only thing that reads it. Adding a field to the manifest without adding
a branch here is how a loop becomes a report.

What this does NOT check: whether a cited URL still resolves, or whether a claim
is true. Resolvability is a network test that would make CI flaky and would still
prove nothing about the claim; those stay a human (or agent) act, recorded in the
manifest's `sources_checked` date.

Usage:

    python tools/research/check.py            # exit 1 on any error
    python tools/research/check.py --quiet    # one line per document only

Stdlib only: CI runs this on ubuntu and windows with whatever python exists.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import re
import sys

DOCS_DIR = "docs/research"
MANIFEST = "corpus.json"
README = "README.md"
STATUSES = {"current", "superseded"}
REQUIRED = ("id", "path", "title", "as_of", "status")

_URL = re.compile(r"https?://[^\s)>\]\"'`]+")


def _manifest_path(root: pathlib.Path) -> pathlib.Path:
    return root / DOCS_DIR / MANIFEST


def _load(root: pathlib.Path, errors: list[str]) -> dict:
    p = _manifest_path(root)
    if not p.exists():
        errors.append(f"missing manifest: {p}")
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"manifest is not JSON: {exc}")
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("documents"), list):
        errors.append("manifest must be an object with a `documents` list")
        return {}
    return data


def sources_in(text: str) -> int:
    """Unique source URLs in a report. Deduplicated because a citation repeated
    in a table and again in prose is one source, not two."""
    return len({u.rstrip(".,;") for u in _URL.findall(text)})


def run(root: pathlib.Path, quiet: bool = False) -> tuple[int, str]:
    """Returns (exit_code, report_text)."""
    errors: list[str] = []
    warnings: list[str] = []
    lines: list[str] = []

    data = _load(root, errors)
    documents = data.get("documents", []) if isinstance(data, dict) else []
    if isinstance(data, dict) and not isinstance(data.get("version"), int):
        errors.append("manifest needs an integer `version`")

    seen_ids: dict[str, int] = {}
    listed: set[str] = set()
    readme = root / DOCS_DIR / README
    readme_text = readme.read_text(encoding="utf-8") if readme.exists() else ""
    if not readme.exists():
        errors.append(f"missing {DOCS_DIR}/{README}")

    total_sources = 0
    for i, doc in enumerate(documents):
        where = f"documents[{i}]"
        if not isinstance(doc, dict):
            errors.append(f"{where} is not an object")
            continue
        for key in REQUIRED:
            if not doc.get(key):
                errors.append(f"{where} has no `{key}`")

        doc_id = str(doc.get("id", ""))
        seen_ids[doc_id] = seen_ids.get(doc_id, 0) + 1

        path = str(doc.get("path", ""))
        listed.add(path)

        as_of = str(doc.get("as_of", ""))
        try:
            datetime.date.fromisoformat(as_of)
        except ValueError:
            errors.append(f"{doc_id}: `as_of` is not an ISO date: {as_of!r}")

        checked = doc.get("sources_checked")
        if checked:
            try:
                datetime.date.fromisoformat(str(checked))
            except ValueError:
                errors.append(f"{doc_id}: `sources_checked` is not an ISO date: {checked!r}")

        status = str(doc.get("status", ""))
        if status not in STATUSES:
            errors.append(f"{doc_id}: `status` must be one of {sorted(STATUSES)}, got {status!r}")

        target = root / DOCS_DIR / path
        if not path:
            continue
        if not target.exists():
            errors.append(f"{doc_id}: manifest names a file that does not exist: {path}")
            continue

        source_count = sources_in(target.read_text(encoding="utf-8"))
        total_sources += source_count
        if source_count == 0:
            warnings.append(f"{doc_id}: no source URLs at all ({path}) — a report with no sources is an opinion")

        if readme_text and f"]({path})" not in readme_text and f"]({DOCS_DIR}/{path})" not in readme_text:
            errors.append(f"{doc_id}: {README} does not link {path} — a report nobody indexes is a report nobody finds")

        if not quiet:
            lines.append(f"  {doc_id:<3} {as_of}  {status:<10} {source_count:>4} sources  {path}")

    for doc_id, count in seen_ids.items():
        if count > 1:
            errors.append(f"duplicate id {doc_id!r} appears {count} times — ids are how other reports cite it")

    for doc in documents:
        if not isinstance(doc, dict):
            continue
        target = doc.get("supersedes")
        if target and str(target) not in seen_ids:
            errors.append(f"{doc.get('id')}: `supersedes` names unknown id {target!r}")

    for report in sorted((root / DOCS_DIR).glob("*.md")):
        if report.name == README:
            continue
        if report.name not in listed:
            errors.append(f"{report.name} exists but is not in the manifest — an unlisted report is unversioned")

    n = len(documents)
    summary = f"research corpus: {n} document{'s' if n != 1 else ''}, {total_sources} sources"
    out = [summary, *lines]
    for w in warnings:
        out.append(f"WARN  {w}")
    for e in errors:
        out.append(f"ERROR {e}")
    if not errors:
        out.append("OK")

    return (1 if errors else 0), "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check the research corpus manifest and index.")
    ap.add_argument("--root", default=".", help="repository root (default: cwd)")
    ap.add_argument("--quiet", action="store_true", help="do not print the per-document table")
    a = ap.parse_args(argv)
    code, text = run(pathlib.Path(a.root), quiet=a.quiet)
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
