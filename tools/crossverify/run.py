"""Tier 4 — ask an independent implementation to verify our artifacts.

`references/soundness-checklist.md` is blunt about this gap: until a second,
independent verifier consumes the same artifacts, "this proof verifies" rests on
one implementation. Groth16 over BN254 is a standard; arkworks' encoding is not.
So this script drives the whole loop end to end:

  1. build a real, honest execution with the shipped CLI (setup, policy, prove);
  2. ask that CLI to verify it (must be ACCEPT — the baseline);
  3. convert the verifying key, proof and public inputs to the `snarkjs` shape;
  4. let `snarkjs` verify the same bytes (must be OK);
  5. mutate the artifacts one at a time — a public input, a proof coordinate, a
     verifying-key entry — and require `snarkjs` to refuse every one.

Step 5 is the whole point. An independent verifier that answers OK to everything
is not a verifier, and a green check without negative controls is a claim about
plumbing, not about soundness.

Usage:

    python tools/crossverify/run.py            # builds nothing; uses target/debug
    python tools/crossverify/run.py --build    # `cargo build` the two binaries first

The conversion is deliberately in Python and deliberately dumb: hex -> int ->
decimal, one line per artefact. If a future arkworks release changes the encoding,
this is the file that should fail loudly rather than a comment that goes stale.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

SNARKJS = ["npx", "-y", "snarkjs@latest", "groth16", "verify"]


def _dec(x: str) -> str:
    return str(int(x, 16))


def _g1(p) -> list[str]:
    return [_dec(p[0]), _dec(p[1]), "1"]


def _g2(p) -> list:
    return [[_dec(p[0][0]), _dec(p[0][1])], [_dec(p[1][0]), _dec(p[1][1])], ["1", "0"]]


def to_snarkjs(raw: dict) -> tuple[dict, dict, list[str]]:
    """Convert the exporter's hex document into (vk, proof, public)."""
    vk = {
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": raw["n_public"],
        "vk_alpha_1": _g1(raw["alpha"]),
        "vk_beta_2": _g2(raw["beta"]),
        "vk_gamma_2": _g2(raw["gamma"]),
        "vk_delta_2": _g2(raw["delta"]),
        # snarkjs' verifier does not read alphabeta (it is used by the Solidity
        # exporter), so a zeroed Fq12 is honest rather than wrong. Written as a
        # placeholder instead of computed nonsense.
        "vk_alphabeta_12": [
            [["0", "0"], ["0", "0"], ["0", "0"]],
            [["0", "0"], ["0", "0"], ["0", "0"]],
        ],
        "IC": [_g1(p) for p in raw["ic"]],
    }
    proof = {
        "protocol": "groth16",
        "curve": "bn128",
        "pi_a": _g1(raw["pi_a"]),
        "pi_b": _g2(raw["pi_b"]),
        "pi_c": _g1(raw["pi_c"]),
    }
    public = [_dec(p) for p in raw["public_inputs"]]
    return vk, proof, public


def _run(cmd: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900)


def _verdict(r: subprocess.CompletedProcess) -> str:
    text = (r.stdout + r.stderr).strip().splitlines()
    for line in text:
        if "OK" in line or "Invalid" in line or "ERROR" in line:
            return line.strip()[:80]
    return text[-1].strip()[:80] if text else "(no output)"


def snark_verify(work: pathlib.Path, vk: dict, proof: dict, public: list[str]) -> subprocess.CompletedProcess:
    (work / "_vk.json").write_text(json.dumps(vk))
    (work / "_proof.json").write_text(json.dumps(proof))
    (work / "_public.json").write_text(json.dumps(public))
    return _run(
        [*SNARKJS, str(work / "_vk.json"), str(work / "_public.json"), str(work / "_proof.json")],
        work,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Ask snarkjs to verify zkagent's Groth16 artifacts, then try to fool it."
    )
    ap.add_argument("--cli", default="target/debug/zkagent")
    # The example is a standalone crate, so cargo puts its binary under its own
    # target dir, not the workspace one.
    ap.add_argument(
        "--exporter", default="examples/crossverify/target/debug/zkagent-crossverify"
    )
    ap.add_argument("--build", action="store_true", help="cargo build the two binaries first")
    ap.add_argument("--keep", action="store_true", help="keep the work directory")
    args = ap.parse_args(argv)

    root = pathlib.Path(__file__).resolve().parents[2]
    if args.build:
        b = _run(["cargo", "build", "-p", "zkagent-cli", "--bin", "zkagent"], root)
        if b.returncode != 0:
            print(b.stderr[-2000:])
            return 1
        b = _run(
            ["cargo", "build", "--manifest-path", "examples/crossverify/Cargo.toml"], root
        )
        if b.returncode != 0:
            print(b.stderr[-2000:])
            return 1

    cli = (root / args.cli).resolve()
    exporter = (root / args.exporter).resolve()
    for binary in (cli, exporter):
        if not binary.exists():
            print(f"FAIL: missing binary {binary} (run with --build)")
            return 1

    work = pathlib.Path(tempfile.mkdtemp(prefix="zkagent-crossverify-"))
    try:
        keys = work / "keys"
        steps = [
            [str(cli), "setup", "--seed", "7", "--out", str(keys)],
            [str(cli), "policy", "--max-amount", "1000", "--max-per-action", "300",
             "--expires-at", "2000", "--chain-id", "1", "--targets", "3,7,9",
             "--seed", "99", "--out", str(work / "policy.json")],
        ]
        for step in steps:
            r = _run(step, work)
            if r.returncode != 0:
                print(r.stdout, r.stderr)
                return 1

        (work / "receipt.json").write_text(
            '{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1,"execution_id":1001}'
        )
        (work / "actions.json").write_text(
            '[{"target":3,"amount":250,"trace_digest":11},{"target":7,"amount":150,"trace_digest":22}]'
        )

        r = _run([str(cli), "prove", "--keys", str(keys), "--policy", str(work / "policy.json"),
                  "--receipt", str(work / "receipt.json"), "--actions", str(work / "actions.json"),
                  "--out", str(work / "proof.json")], work)
        if r.returncode != 0:
            print(r.stdout, r.stderr)
            return 1

        # Baseline: our own verifier must accept. If this fails, the experiment is
        # measuring a broken fixture rather than a cross-implementation agreement.
        r = _run([str(cli), "verify", "--keys", str(keys), "--policy", str(work / "policy.json"),
                  "--receipt", str(work / "receipt.json"), "--proof", str(work / "proof.json"),
                  "--now", "1600"], work)
        baseline = r.stdout.strip()
        if r.returncode != 0 or baseline != "ACCEPT":
            print(f"FAIL: our own verifier rejected the fixture: {baseline} {r.stderr[-400:]}")
            return 1

        r = _run([str(exporter), str(keys), str(work / "proof.json")], work)
        if r.returncode != 0:
            print("FAIL: exporter:", r.stderr[-800:])
            return 1
        raw = json.loads(r.stdout)
        vk, proof, public = to_snarkjs(raw)

        rows: list[tuple[str, bool, str]] = []
        r = snark_verify(work, vk, proof, public)
        rows.append(("honest artifacts", r.returncode == 0, _verdict(r)))

        tampered = list(public)
        tampered[0] = str(int(tampered[0]) + 1)
        r = snark_verify(work, vk, proof, tampered)
        rows.append(("public input +1", r.returncode != 0, _verdict(r)))

        bad_proof = json.loads(json.dumps(proof))
        bad_proof["pi_a"][1] = str(int(bad_proof["pi_a"][1]) + 1)
        r = snark_verify(work, vk, bad_proof, public)
        rows.append(("proof pi_a.y +1", r.returncode != 0, _verdict(r)))

        bad_vk = json.loads(json.dumps(vk))
        bad_vk["IC"][1][0] = str(int(bad_vk["IC"][1][0]) + 1)
        r = snark_verify(work, bad_vk, proof, public)
        rows.append(("vk IC[1].x +1", r.returncode != 0, _verdict(r)))

        zeroed = list(public)
        zeroed[0] = "0"
        r = snark_verify(work, vk, proof, zeroed)
        rows.append(("public[0] = 0", r.returncode != 0, _verdict(r)))

        print(f"fixture: nPublic={vk['nPublic']} IC={len(vk['IC'])} public={len(public)}")
        print(f"our verifier: {baseline}")
        print()
        for label, ok, verdict in rows:
            print(f"  {'PASS' if ok else 'FAIL'}  {label:<22} {verdict}")

        failed = [label for label, ok, _ in rows if not ok]
        print()
        if failed:
            print(f"CROSS-VERIFY FAILED: {', '.join(failed)}")
            return 1
        print("CROSS-VERIFY OK: an independent verifier accepts our proof and refuses every mutation")
        return 0
    finally:
        if args.keep:
            print(f"work dir kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
