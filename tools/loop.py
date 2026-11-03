#!/usr/bin/env python3
"""Loop-learning ledger for the zkagent project.

The failure this file exists to prevent
---------------------------------------
A "learning loop" that writes findings nobody reads is a *report*, not a loop.
This repo has exactly one consumer for its ledger — `loop.py next` — and the
skill instructs the operator to call it at the start of every session. If you
add a field here, add the branch in `recommend()` that reads it, or the loop is
open again.

Usage
-----
    python tools/loop.py record --phase circuit --action "add range check" \
        --result pass --metric "constraints=2162" --note "..."
    python tools/loop.py status
    python tools/loop.py next

Exit codes: 0 = ok, 1 = ledger unreadable/corrupt (fail loudly, never silently).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

LEDGER = Path(os.environ.get("ZKAGENT_LEDGER", Path(__file__).resolve().parent.parent / "docs" / "loop-ledger.jsonl"))

PHASES = ["research", "design", "circuit", "prover", "verifier", "docs", "publish"]

REPO = Path(__file__).resolve().parent.parent


def git_commit() -> str:
    """The commit this row was measured on.

    A metric without a commit is not reproducible: "prove 0.061s" is worth nothing if the
    reader cannot check out the tree that produced it. Returns "" when git is unavailable,
    and `status` counts those rows, so the gap stays visible instead of being assumed.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def format_version() -> str:
    """The artifact format constant, read from the source that defines it."""
    try:
        text = (REPO / "crates" / "zkagent-wire" / "src" / "lib.rs").read_text(encoding="utf-8")
    except OSError:
        return ""
    m = re.search(r"FORMAT_VERSION:\s*u32\s*=\s*(\d+)", text)
    return m.group(1) if m else ""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_rows() -> list[dict]:
    if not LEDGER.exists():
        return []
    rows = []
    for i, line in enumerate(LEDGER.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            # A corrupt ledger must fail loudly: silently skipping rows is how
            # a loop reports a healthy history it does not have.
            print(f"error: corrupt ledger line {i}: {exc}", file=sys.stderr)
            raise SystemExit(1)
    return rows


def append_row(row: dict) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def aggregate(rows: list[dict]) -> dict:
    """Reduce the ledger to the numbers `recommend()` actually uses."""
    per_phase: dict[str, dict[str, int]] = {}
    for r in rows:
        p = r.get("phase", "unknown")
        bucket = per_phase.setdefault(p, {"pass": 0, "fail": 0, "unknown": 0})
        res = r.get("result", "unknown")
        bucket[res if res in bucket else "unknown"] += 1

    # Consecutive failures at the tail: the single most useful signal, because
    # it means the CURRENT approach is not working and repeating it is waste.
    streak = 0
    for r in reversed(rows):
        if r.get("result") == "fail":
            streak += 1
        else:
            break

    last_fail = next((r for r in reversed(rows) if r.get("result") == "fail"), None)
    return {
        "total": len(rows),
        "per_phase": per_phase,
        "fail_streak": streak,
        "last_fail": last_fail,
        "keys": sorted({k for r in rows for k in r.keys()}),
    }


def recommend(rows: list[dict]) -> list[str]:
    """The CONSUMER. Every recommendation must cite ledger evidence."""
    if not rows:
        return [
            "Ledger is empty. Start with: python tools/loop.py record --phase research --action \"read intel\" --result pass",
        ]

    agg = aggregate(rows)
    out: list[str] = []

    # 1. A failure streak means stop repeating the approach.
    if agg["fail_streak"] >= 3:
        lf = agg["last_fail"] or {}
        out.append(
            f"STOP: {agg['fail_streak']} consecutive failures. Last failure in phase "
            f"'{lf.get('phase')}': {lf.get('note', '(no note)')}. "
            "Re-read references/soundness-checklist.md before the next attempt; "
            "do not retry the same shape a fourth time."
        )

    # 2. A phase with failures and no later pass is unfinished business.
    for phase, counts in agg["per_phase"].items():
        if counts["fail"] and not counts["pass"]:
            out.append(
                f"Phase '{phase}' has {counts['fail']} failure(s) and zero passes - it is not done."
            )

    # 3. Never-published work is the default failure mode of a private repo.
    if "publish" not in agg["per_phase"]:
        out.append(
            "No 'publish' row: the repo is still private. Before flipping it public, "
            "run references/publish-checklist.md (licence, secrets scan, CI green, README)."
        )

    # 4. Circuit changes without a verifier row are unverified changes.
    if agg["per_phase"].get("circuit", {}).get("pass") and not agg["per_phase"].get("verifier"):
        out.append(
            "Circuit passes but the verifier has no rows: a circuit proven to satisfy its "
            "own witness is not a protocol that verifies. Run the end-to-end test."
        )

    if not out:
        out.append("No blockers found in the ledger. Continue with the next roadmap item.")
    return out


def cmd_record(args: argparse.Namespace) -> int:
    if args.phase not in PHASES:
        print(f"error: --phase must be one of {PHASES}", file=sys.stderr)
        return 2
    if args.result not in ("pass", "fail", "unknown"):
        print("error: --result must be pass|fail|unknown", file=sys.stderr)
        return 2
    row = {
        "ts": now(),
        "phase": args.phase,
        "action": args.action,
        "result": args.result,
        "metric": args.metric or "",
        "note": args.note or "",
        "commit": args.commit if getattr(args, "commit", None) else git_commit(),
        "format": format_version(),
    }
    append_row(row)
    print(f"recorded: {row['phase']} / {row['result']} / {row['action']}")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    rows = read_rows()
    agg = aggregate(rows)
    print(f"ledger: {LEDGER}")
    print(f"rows:   {agg['total']}")
    legacy = sum(1 for r in rows if not r.get("commit"))
    if legacy:
        print(
            f"        {legacy} row(s) predate commit capture -- unverifiable, "
            "do not cite them as reproduced"
        )
    for phase in PHASES:
        c = agg["per_phase"].get(phase)
        if c:
            print(f"  {phase:10} pass={c['pass']:<3} fail={c['fail']:<3} unknown={c['unknown']}")
    if agg["fail_streak"]:
        print(f"fail streak: {agg['fail_streak']}")
    return 0


def cmd_next(_: argparse.Namespace) -> int:
    rows = read_rows()
    print("NEXT ACTIONS (derived from the ledger, not from opinion):")
    for i, line in enumerate(recommend(rows), 1):
        print(f"  {i}. {line}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record", help="append one experiment/outcome row")
    r.add_argument("--phase", required=True)
    r.add_argument("--action", required=True)
    r.add_argument("--result", required=True)
    r.add_argument("--metric", default="")
    r.add_argument("--note", default="")
    r.add_argument(
        "--commit",
        default=None,
        help="commit the measurement was taken on (default: HEAD)",
    )
    r.set_defaults(func=cmd_record)

    s = sub.add_parser("status", help="summarise the ledger")
    s.set_defaults(func=cmd_status)

    n = sub.add_parser("next", help="derive the next actions (the consumer)")
    n.set_defaults(func=cmd_next)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
