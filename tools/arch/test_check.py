"""Tests for the architecture check.

The check is only worth having if it fails on the thing it claims to catch, so
each rule gets a synthetic graph that violates it. These run without cargo.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from tools.arch import check  # noqa: E402


class Rules(unittest.TestCase):
    def graph(self, **deps: list[str]) -> dict[str, list[str]]:
        g = {c: [] for c in check.CRATES}
        g.update(deps)
        return g

    def test_a_clean_graph_passes_every_invariant(self) -> None:
        # The clean shape: the statement lives in `zkagent-wire`, so the prover and
        # the verifier are siblings rather than one depending on the other.
        g = self.graph(
            **{
                "zkagent-wire": ["zkagent-core"],
                "zkagent-proofs": ["zkagent-core", "zkagent-wire"],
                "zkagent-verifier": ["zkagent-core", "zkagent-wire"],
                "zkagent-service": ["zkagent-core", "zkagent-verifier"],
                "zkagent-cli": ["zkagent-service"],
                "zkagent-mcp": ["zkagent-service"],
            }
        )
        for who, rule in check.INVARIANTS:
            self.assertEqual(check.check_rule(who, rule, g), [], f"{who}/{rule}")

    def test_core_may_depend_on_nothing(self) -> None:
        g = self.graph(**{"zkagent-core": ["zkagent-proofs"]})
        self.assertTrue(check.check_rule("zkagent-core", "nothing", g))

    def test_ipfs_may_depend_on_nothing(self) -> None:
        g = self.graph(**{"zkagent-ipfs": ["zkagent-core"]})
        self.assertTrue(check.check_rule("zkagent-ipfs", "nothing", g))

    def test_the_verifier_must_not_depend_on_the_service(self) -> None:
        g = self.graph(**{"zkagent-verifier": ["zkagent-core", "zkagent-service"]})
        self.assertTrue(check.check_rule("zkagent-verifier", "not zkagent-service", g))

    def test_a_shell_must_not_be_depended_on(self) -> None:
        g = self.graph(**{"zkagent-service": ["zkagent-cli"]})
        self.assertTrue(check.check_rule("zkagent-service", "not shell", g))

    def test_the_target_rule_flags_a_shell_reaching_past_the_service(self) -> None:
        g = self.graph(**{"zkagent-cli": ["zkagent-service", "zkagent-proofs", "zkagent-ipfs"]})
        violations = check.check_rule("shell", "service-only", g)
        self.assertEqual(len(violations), 1)
        self.assertIn("zkagent-proofs", violations[0])

    def test_the_target_rule_is_quiet_when_shells_use_only_the_service(self) -> None:
        g = self.graph(**{"zkagent-cli": ["zkagent-service"], "zkagent-mcp": ["zkagent-service"]})
        self.assertEqual(check.check_rule("shell", "service-only", g), [])

    def test_a_cycle_is_reported(self) -> None:
        g = self.graph(**{"zkagent-core": ["zkagent-proofs"], "zkagent-proofs": ["zkagent-core"]})
        self.assertTrue(check.cycles(g))

    def test_an_unknown_rule_raises_rather_than_passing_silently(self) -> None:
        with self.assertRaises(ValueError):
            check.check_rule("zkagent-core", "looks fine to me", self.graph())


class WorkspaceVersions(unittest.TestCase):
    """One version, one copy — the drift that hid behind a workspace bump."""

    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "crates" / "zkagent-wire").mkdir(parents=True)
        (self.root / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "0.2.0"\n', encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_crate(self, body: str) -> None:
        (self.root / "crates" / "zkagent-wire" / "Cargo.toml").write_text(body, encoding="utf-8")

    def test_a_crate_that_does_not_inherit_is_reported(self) -> None:
        self.write_crate('[package]\nname = "zkagent-wire"\nversion = "0.1.0"\n')
        bad = check.workspace_version_drift(self.root)
        self.assertTrue(any("does not inherit" in b for b in bad), bad)

    def test_a_stale_dependency_pin_is_reported(self) -> None:
        self.write_crate(
            '[package]\nname = "zkagent-wire"\nversion.workspace = true\n\n'
            '[dependencies]\nzkagent-core = { path = "../zkagent-core", version = "0.1.0" }\n'
        )
        bad = check.workspace_version_drift(self.root)
        self.assertTrue(any("pins zkagent-core at 0.1.0" in b for b in bad), bad)

    def test_a_consistent_crate_passes(self) -> None:
        self.write_crate(
            '[package]\nname = "zkagent-wire"\nversion.workspace = true\n\n'
            '[dependencies]\nzkagent-core = { path = "../zkagent-core", version = "0.2.0" }\n'
        )
        self.assertEqual(check.workspace_version_drift(self.root), [])


class RealRepository(unittest.TestCase):
    def test_the_current_tree_holds_every_invariant(self) -> None:
        code, text = check.run()
        self.assertEqual(code, 0, text)
        self.assertIn("OK: invariants hold", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
