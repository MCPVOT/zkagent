#!/usr/bin/env python3
"""Fail when the version numbers disagree.

Checks, in order: the workspace version, the first changelog entry and its date, and, when tags are
present, the newest tag. The failure message names the file to edit, because the usual cause is a
bump that touched one place out of three.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^v?(\d+\.\d+\.\d+)\+(\d{4}-\d{2}-\d{2})$")


def workspace_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    found = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not found:
        raise SystemExit("Cargo.toml has no workspace version")
    return found.group(1)


def changelog_head() -> tuple[str, str]:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    found = re.search(r"^## (\d+\.\d+\.\d+)\+(\d{4}-\d{2}-\d{2})", text, re.M)
    if not found:
        raise SystemExit("CHANGELOG.md has no '## X.Y.Z+YYYY-MM-DD' entry")
    return found.group(1), found.group(2)


def newest_tag() -> tuple[str, str] | None:
    out = subprocess.run(["git", "describe", "--tags", "--abbrev=0"],
                         capture_output=True, text=True, check=False, cwd=ROOT)
    tag = out.stdout.strip()
    if not tag:
        return None
    found = SEMVER.match(tag)
    if not found:
        raise SystemExit(f"newest tag {tag!r} is not vX.Y.Z+YYYY-MM-DD")
    commit = subprocess.run(["git", "rev-list", "-n1", tag],
                            capture_output=True, text=True, check=False, cwd=ROOT).stdout.strip()
    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"],
                              capture_output=True, check=False, cwd=ROOT)
    if ancestor.returncode != 0:
        raise SystemExit(
            f"newest tag {tag} is not an ancestor of HEAD: the tag points at a commit this branch "
            "does not contain (usually a branch that was squash-merged). git describe will report an "
            "older version than the code. Cut a new patch version on master and tag the merge commit."
        )
    return found.group(1), found.group(2)


def main() -> int:
    problems: list[str] = []
    cargo = workspace_version()
    cl_version, cl_date = changelog_head()

    if cargo != cl_version:
        problems.append(f"Cargo.toml says {cargo}, CHANGELOG.md says {cl_version}: add the entry or fix the bump")

    tag = newest_tag()
    pending = False
    if tag is not None:
        tag_version, tag_date = tag
        def key(v: str) -> tuple[int, ...]:
            return tuple(int(part) for part in v.split("."))
        if key(tag_version) > key(cargo):
            problems.append(f"newest tag is {tag_version}, ahead of Cargo.toml {cargo}: a tag must not lead the code")
        elif tag_version != cargo:
            # A version ahead of the newest tag is a release in progress: the tag is created after
            # the merge, so this state has to be allowed or the release can never be made.
            pending = True
        elif tag_date != cl_date:
            problems.append(f"newest tag date is {tag_date}, changelog entry date is {cl_date}")

    if problems:
        print("version consistency: FAIL")
        for problem in problems:
            print("  -", problem)
        return 1

    where = f", newest tag {tag[0]}+{tag[1]}" if tag else ", no tags yet"
    state = f", {cargo} pending release (tag it after the merge)" if pending else ""
    print(f"version consistency: OK ({cargo}+{cl_date}{where}{state})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
