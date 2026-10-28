#!/usr/bin/env python3
"""Tests for the leaderboard generator.

The attribution rules are the load-bearing part: they decide whether a
contributor keeps credit when a maintainer rebases or re-lands their work. So
they are tested directly, with synthetic PR data, rather than being taken on
trust from a live run.

Run: python tools/leaderboard/test_generate.py
Standard library only.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate as g  # noqa: E402


def commit(*lines: str) -> dict:
    body = "\n".join(lines)
    head, _, rest = body.partition("\n")
    return {"messageHeadline": head, "messageBody": rest}


def pr(number: int, author: str, *, body: str = "", state: str = "MERGED", merged: str = "2026-10-01T00:00:00Z") -> dict:
    return {
        "number": number,
        "state": state,
        "author": {"login": author, "is_bot": author.endswith("[bot]")},
        "body": body,
        "mergedAt": merged,
    }


def no_resolve(name: str, email: str) -> str | None:
    return None


class TrailerThreshold(unittest.TestCase):
    def test_trailer_in_half_the_commits_credits(self):
        commits = [
            commit("a", "Co-Authored-By: Ada <ada@example.com>"),
            commit("b", "Co-Authored-By: Ada <ada@example.com>"),
            commit("c"),
            commit("d"),
        ]
        credited = g.credit_for_pr(pr(1, "MCPVOT"), commits, {}, no_resolve)
        self.assertEqual(credited, ["Ada"])

    def test_trailer_in_less_than_half_does_not_credit(self):
        # One commit out of three carries the trailer: a stacked PR that merely
        # carries a few of someone's commits. Credit stays with the relay.
        commits = [
            commit("a", "Co-Authored-By: Ada <ada@example.com>"),
            commit("b"),
            commit("c"),
        ]
        credited = g.credit_for_pr(pr(2, "MCPVOT"), commits, {}, no_resolve)
        self.assertEqual(credited, ["MCPVOT"])

    def test_trailer_in_the_pr_body_counts_at_full_strength(self):
        commits = [commit(f"c{i}") for i in range(10)]
        credited = g.credit_for_pr(
            pr(3, "MCPVOT", body="Ported work.\n\nCo-Authored-By: Ada <ada@example.com>"),
            commits,
            {},
            no_resolve,
        )
        self.assertEqual(credited, ["Ada"])

    def test_bot_co_authors_never_get_credit(self):
        commits = [commit("a", "Co-Authored-By: dependabot[bot] <dependabot[bot]@users.noreply.github.com>")]
        credited = g.credit_for_pr(pr(4, "MCPVOT"), commits, {}, no_resolve)
        self.assertEqual(credited, ["MCPVOT"])


class AttributionSources(unittest.TestCase):
    def test_a_supersedes_reference_credits_the_original_author(self):
        original = pr(10, "grace")
        credited = g.credit_for_pr(
            pr(11, "MCPVOT", body="Supersedes #10"),
            [commit("re-land")],
            {10: original, 11: pr(11, "MCPVOT")},
            no_resolve,
        )
        self.assertEqual(credited, ["grace"])

    def test_a_non_relay_pr_is_credited_to_its_author_only(self):
        # Attribution machinery exists for relays. A normal author keeps their
        # own credit even if the body carries someone else's trailer.
        commits = [commit("a", "Co-Authored-By: Ada <ada@example.com>")]
        credited = g.credit_for_pr(pr(12, "grace", body="Co-Authored-By: Ada <ada@example.com>"), commits, {}, no_resolve)
        self.assertEqual(credited, ["grace"])

    def test_noreply_addresses_resolve_to_the_login(self):
        commits = [commit("a", "Co-Authored-By: Ada <12345+ada@users.noreply.github.com>")]
        credited = g.credit_for_pr(pr(13, "MCPVOT"), commits, {}, no_resolve)
        self.assertEqual(credited, ["ada"])

    def test_a_bot_authored_pr_is_unattributed(self):
        credited = g.credit_for_pr(pr(14, "github-actions[bot]"), [commit("a")], {}, no_resolve)
        self.assertEqual(credited, [])


class CreditOnce(unittest.TestCase):
    def test_only_the_first_credited_name_counts(self):
        commits = [commit("a", "Co-Authored-By: Ada <ada@example.com>", "Co-Authored-By: Grace <grace@example.com>")]
        credited = g.credit_for_pr(pr(15, "MCPVOT"), commits, {}, no_resolve)
        self.assertEqual(len(credited), 2, "both are returned, in priority order")
        # build_leaderboard credits only credited[0]; asserted in the build test.

    def test_build_counts_each_pr_exactly_once(self):
        prs = [pr(1, "MCPVOT"), pr(2, "MCPVOT"), pr(3, "grace")]
        commits = {
            1: [commit("a", "Co-Authored-By: Ada <ada@example.com>", "Co-Authored-By: Grace <grace@example.com>")],
            2: [commit("b", "Co-Authored-By: Ada <ada@example.com>")],
            3: [commit("c")],
        }
        doc = g.build_leaderboard("o/r", prs, [], commits, datetime(2026, 10, 2, tzinfo=timezone.utc), no_resolve)
        total = sum(r["merged_prs"] for r in doc["contributors"])
        self.assertEqual(total, 3, "3 merged PRs must yield 3 credited PRs in total")
        self.assertEqual({r["login"] for r in doc["contributors"]}, {"Ada", "grace"})


class PacificDay(unittest.TestCase):
    def test_pacific_midnight_is_dst_aware(self):
        summer = g.pacific_midnight(datetime(2026, 7, 15, 20, 0, tzinfo=timezone.utc))
        winter = g.pacific_midnight(datetime(2026, 1, 15, 20, 0, tzinfo=timezone.utc))
        self.assertEqual(summer.strftime("%Y-%m-%dT%H:%M:%SZ"), "2026-07-15T07:00:00Z")
        self.assertEqual(winter.strftime("%Y-%m-%dT%H:%M:%SZ"), "2026-01-15T08:00:00Z")

    def test_today_counts_are_inclusive_of_the_boundary(self):
        cutoff = g.pacific_midnight(datetime(2026, 7, 15, 20, 0, tzinfo=timezone.utc))
        dates = ["2026-07-15T07:00:00Z", "2026-07-15T06:59:59Z"]
        self.assertEqual(g.count_since(dates, cutoff), 1)

    def test_the_badge_is_html_with_an_inline_arrow(self):
        self.assertIn("delta-none", g.today_badge(0))
        up = g.today_badge(7)
        self.assertIn("delta-up", up)
        self.assertIn("+7", up)
        self.assertIn("<svg", up)


class Ranking(unittest.TestCase):
    def test_order_is_merged_prs_then_earliest_contribution_then_login(self):
        prs = [
            pr(1, "grace", merged="2026-10-01T00:00:00Z"),
            pr(2, "ada", merged="2026-10-02T00:00:00Z"),
            pr(3, "ada", merged="2026-10-03T00:00:00Z"),
            pr(4, "zoe", merged="2026-10-05T00:00:00Z"),
            pr(5, "bob", merged="2026-10-04T00:00:00Z"),
        ]
        doc = g.build_leaderboard("o/r", prs, [], {}, datetime(2026, 10, 6, tzinfo=timezone.utc), no_resolve)
        logins = [r["login"] for r in doc["contributors"]]
        # ada has 2. The three with 1 are ordered by earliest merged date:
        # grace 10-01, bob 10-04, zoe 10-05.
        self.assertEqual(logins, ["ada", "grace", "bob", "zoe"])
        self.assertEqual([r["rank"] for r in doc["contributors"]], [1, 2, 3, 4])

    def test_tie_on_count_is_broken_by_earlier_first_contribution(self):
        prs = [pr(1, "zed", merged="2026-10-05T00:00:00Z"), pr(2, "amy", merged="2026-10-01T00:00:00Z")]
        doc = g.build_leaderboard("o/r", prs, [], {}, datetime(2026, 10, 6, tzinfo=timezone.utc), no_resolve)
        self.assertEqual([r["login"] for r in doc["contributors"]], ["amy", "zed"])

    def test_an_empty_repository_produces_an_honest_empty_board(self):
        doc = g.build_leaderboard("o/r", [], [], {}, datetime(2026, 10, 6, tzinfo=timezone.utc), no_resolve)
        self.assertEqual(doc["contributors"], [])
        self.assertEqual(doc["merged_pr_total"], 0)
        self.assertEqual(doc["today_total"], 0)
        self.assertIsInstance(doc["unattributed_prs"], list)

    def test_issues_never_put_someone_on_the_board(self):
        issues = [{"number": 9, "author": {"login": "lurker"}}]
        doc = g.build_leaderboard("o/r", [], issues, {}, datetime(2026, 10, 6, tzinfo=timezone.utc), no_resolve)
        self.assertEqual(doc["contributors"], [], "an issue-only contributor is not ranked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
