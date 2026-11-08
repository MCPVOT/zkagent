#!/usr/bin/env python3
"""Generate docs/SCHEMAS.md from the Rust structs, and fail when the doc drifts.

The field list is the public contract: a verifier reads those fields and nothing else. Written by
hand it drifts. Written here it cannot.

    python3 tools/gen_schemas.py            # rewrite docs/SCHEMAS.md
    python3 tools/gen_schemas.py --check    # exit 1 if the doc is stale
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs/SCHEMAS.md"
CRATES = ROOT / "crates"
STRUCT = re.compile(r"^pub struct (\w+)\b[^{]*\{", re.M)
FIELD = re.compile(r"^\s*pub (\w+):\s*([^,]+),", re.M)
DOC_LINE = re.compile(r"^\s*///\s?(.*)$")


def structs() -> dict[str, list[tuple[str, str, str]]]:
    """{struct: [(field, type, first doc line), …]} across the crates."""
    found: dict[str, list[tuple[str, str, str]]] = {}
    for path in sorted(CRATES.glob("*/src/**/*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in STRUCT.finditer(text):
            name = match.group(1)
            body_start = match.end()
            depth, index = 1, body_start
            while index < len(text) and depth:
                if text[index] == "{":
                    depth += 1
                elif text[index] == "}":
                    depth -= 1
                index += 1
            body = text[body_start:index]
            fields: list[tuple[str, str, str]] = []
            lines = body.splitlines()
            for number, line in enumerate(lines):
                field = FIELD.match(line)
                if not field:
                    continue
                # A doc comment spans several lines; join them in reading order rather than
                # keeping whichever line the walk happened to end on.
                parts: list[str] = []
                back = number - 1
                while back >= 0 and DOC_LINE.match(lines[back] or ""):
                    parts.append(DOC_LINE.match(lines[back]).group(1).strip())
                    back -= 1
                comment = " ".join(reversed(parts)).strip()
                fields.append((field.group(1), field.group(2).strip(), comment))
            if fields:
                found[name] = fields
    return found


def render(data: dict[str, list[tuple[str, str, str]]]) -> str:
    out = [
        "# Schemas",
        "",
        "Generated from the Rust structs by `tools/gen_schemas.py`. Do not edit by hand: the check in",
        "CI fails when a field exists in code and not here.",
        "",
        "`pub` fields are the wire surface. A field that is not `pub` is an implementation detail and",
        "never appears in an artifact.",
        "",
    ]
    for name in sorted(data):
        out += [f"## `{name}`", "", "| field | type | meaning |", "| --- | --- | --- |"]
        for field, kind, comment in data[name]:
            comment = comment.replace("|", "\\|")
            out.append(f"| `{field}` | `{kind}` | {comment} |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    check = "--check" in sys.argv[1:]
    wanted = render(structs())
    current = DOC.read_text(encoding="utf-8") if DOC.is_file() else ""
    if check:
        if wanted != current:
            stale = [
                line for line in wanted.splitlines() if line.startswith("| `") and line not in current.splitlines()
            ]
            missing = ", ".join(dict.fromkeys(l.split("`")[1] for l in stale)) or "structure differs"
            print("schemas: FAIL docs/SCHEMAS.md is stale")
            print("  missing or changed:", missing)
            print("  run: python3 tools/gen_schemas.py")
            return 1
        print("schemas: OK (docs/SCHEMAS.md matches the structs)")
        return 0
    DOC.parent.mkdir(parents=True, exist_ok=True)
    DOC.write_text(wanted, encoding="utf-8")
    print(f"schemas: wrote {DOC.relative_to(ROOT)} ({len(structs())} structs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
