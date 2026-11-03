"""Check the crate dependency graph against the architecture we intend.

Layering erodes one `use` at a time, and nobody notices until a "pure verifier"
depends on the prover and a CLI reaches into four crates to do its job. A comment
in `docs/CODE-MAP.md` does not stop that; a check does.

Two kinds of rule:

* **invariants** — must hold today, CI fails when one breaks;
* **targets** — known layering debt, reported on every run and not failed, so the
  debt is visible in the log instead of living in somebody's memory. Move a rule
  from `TARGETS` to `INVARIANTS` in the commit that pays it off.

Stdlib only. Cargo.toml parsing here is deliberately narrow: it only looks for
`zkagent-*` keys under `[dependencies]`, which is the only thing that matters for
the graph, and it does not pretend to be a TOML parser.

    python tools/arch/check.py           # exit 1 on an invariant violation
    python tools/arch/check.py --json    # machine-readable
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Every crate in the workspace, in dependency order (leaves first).
CRATES = [
    "zkagent-core",
    "zkagent-wire",
    "zkagent-ipfs",
    "zkagent-proofs",
    "zkagent-verifier",
    "zkagent-service",
    "zkagent-cli",
    "zkagent-mcp",
]

SHELLS = {"zkagent-cli", "zkagent-mcp"}

# Must hold today.
INVARIANTS: list[tuple[str, str]] = [
    ("zkagent-core", "nothing"),  # core is the vocabulary: no internal deps at all
    ("zkagent-ipfs", "nothing"),
    ("zkagent-verifier", "not zkagent-service"),  # the verifier has no host state
    ("zkagent-verifier", "not zkagent-proofs"),   # and it does not carry the prover
    ("zkagent-service", "not shell"),             # the service must not own a shell
    ("shell", "service-only"),                    # a shell talks to the service, nothing deeper
]

# Known debt. Reported, never failed, until the commit that removes it.
#
# Empty since the shells were pointed at the service's re-exports. When the next
# piece of debt appears, add it here rather than in a comment: a target that is
# printed on every run is a target somebody will eventually pay.
TARGETS: list[tuple[str, str]] = []


def deps_of(crate: str) -> list[str]:
    manifest = ROOT / "crates" / crate / "Cargo.toml"
    if not manifest.exists():
        return []
    text = manifest.read_text(encoding="utf-8")
    block = re.search(r"^\[dependencies\](.*?)(?=^\[|\Z)", text, re.S | re.M)
    if not block:
        return []
    return sorted(set(re.findall(r"^(zkagent-[a-z-]+)\s*=", block.group(1), re.M)))


def graph() -> dict[str, list[str]]:
    return {c: deps_of(c) for c in CRATES}


def check_rule(who: str, rule: str, g: dict[str, list[str]]) -> list[str]:
    """Returns the violations for one rule; empty means it holds."""
    targets = CRATES if who == "shell" else [who]
    bad: list[str] = []
    for crate in targets:
        deps = g.get(crate, [])
        if rule == "nothing":
            if deps:
                bad.append(f"{crate} depends on {', '.join(deps)} but should depend on nothing")
        elif rule == "not shell":
            hits = [d for d in deps if d in SHELLS]
            if hits:
                bad.append(f"{crate} depends on a shell ({', '.join(hits)})")
        elif rule == "service-only":
            if crate in SHELLS:
                extra = [d for d in deps if d != "zkagent-service"]
                if extra:
                    bad.append(f"{crate} reaches past the service into {', '.join(extra)}")
        elif rule.startswith("not "):
            forbidden = rule[4:].strip()
            if forbidden in deps:
                bad.append(f"{crate} depends on {forbidden}")
        else:  # pragma: no cover - guards a typo in the tables above
            raise ValueError(f"unknown rule {rule!r}")
    return bad


def cycles(g: dict[str, list[str]]) -> list[str]:
    seen: dict[str, int] = {}
    found: list[str] = []

    def walk(node: str, stack: list[str]) -> None:
        if seen.get(node) == 1:
            found.append(" -> ".join(stack + [node]))
            return
        if seen.get(node) == 2:
            return
        seen[node] = 1
        for dep in g.get(node, []):
            walk(dep, stack + [node])
        seen[node] = 2

    for crate in CRATES:
        walk(crate, [])
    return found


def workspace_version_drift(root: pathlib.Path | None = None) -> list[str]:
    """One version, one copy.

    `[workspace.package] version` means nothing if the crates hardcode their own, or if
    their `zkagent-*` path dependencies still pin the previous number. Bumping the
    workspace then produces a binary that reports the old version: it happened twice in
    one day, and the second symptom was a build error three crates away from the cause.
    """
    root = root or ROOT
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(
        r"^\[workspace\.package\][^\[]*?^version\s*=\s*\"([^\"]+)\"", text, re.S | re.M
    )
    if not m:
        return ["[workspace.package] version not found in Cargo.toml"]
    want = m.group(1)

    bad: list[str] = []
    for crate_toml in sorted((root / "crates").glob("*/Cargo.toml")):
        name = crate_toml.parent.name
        body = crate_toml.read_text(encoding="utf-8")
        if not re.search(r"^version\.workspace\s*=\s*true", body, re.M):
            bad.append(f"{name} does not inherit version.workspace (workspace is {want})")
        for dep, ver in re.findall(
            r"^(zkagent-[a-z0-9-]+)\s*=\s*\{[^}]*version\s*=\s*\"([^\"]+)\"", body, re.M
        ):
            if ver != want:
                bad.append(f"{name} pins {dep} at {ver}, workspace is {want}")
    return bad


def run() -> tuple[int, str]:
    g = graph()
    failures: list[str] = []
    notes: list[str] = []

    for who, rule in INVARIANTS:
        failures.extend(check_rule(who, rule, g))
    for who, rule in TARGETS:
        notes.extend(f"target not met: {v}" for v in check_rule(who, rule, g))

    failures.extend(workspace_version_drift())

    failures.extend(f"dependency cycle: {c}" for c in cycles(g))

    lines = ["crate graph:"]
    for crate in CRATES:
        lines.append(f"  {crate:<20} -> {', '.join(g.get(crate, [])) or '(nothing)'}")
    lines.extend(f"  NOTE  {n}" for n in notes)
    lines.extend(f"  ERROR {f}" for f in failures)
    lines.append(
        "OK: invariants hold" if not failures else f"FAILED: {len(failures)} invariant violation(s)"
    )
    return (1 if failures else 0), "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check the crate dependency graph.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    code, text = run()
    if args.json:
        g = graph()
        print(json.dumps({
            "graph": g,
            "invariants": [{"crate": c, "rule": r} for c, r in INVARIANTS],
            "targets": [{"crate": c, "rule": r} for c, r in TARGETS],
            "cycles": cycles(g),
            "ok": code == 0,
        }, indent=1))
    else:
        print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
