#!/usr/bin/env python3
"""Generate the zkagent contributor leaderboard.

Ranked by **merged pull requests**, credited to the ORIGINATING contributor even
when a maintainer re-landed their work (counted once).

This is a deliberate reimplementation of the mechanism used by
`obs-rust/obs-studio`, because that project solved the problem this repository
will have the moment it goes public: many contributors, several of them AI
agents, work in parallel, and credit has to survive rebases and re-landings.

What is kept, and why:

- **Trailer attribution.** A `Co-Authored-By:` trailer present in at least half
  the PR's commits (or anywhere in the PR body) credits the named human, not
  whoever pushed it. Without this, a maintainer who rebases someone's work
  silently steals their credit.
- **Body references.** "supersedes #N" / "re-lands #N" / "rebased from #N"
  credits the author of PR #N.
- **Completeness gate.** The merged-PR total is read first, then the list is
  fetched; if the list is shorter than the total the run fails instead of
  publishing a truncated leaderboard.
- **Pacific midnight** for the "new today" delta, DST-aware.
- **Credit once.** A PR credits exactly one person; the rest are logged, not
  counted.

What is different, and why:

- **No fake rows.** An empty repository publishes an empty leaderboard with an
  explicit "no merged PRs yet" state. There is no placeholder contributor and
  no sample data anywhere in this pipeline.
- **The scoring key is honest about itself.** `score` equals `merged_prs`
  because merged PRs is the only thing counted; issues are collected for
  context but never scored. If that changes, the number changes with it.

Usage:
    python tools/leaderboard/generate.py --repo MCPVOT/zkagent --out site/leaderboard.json

Requires the `gh` CLI on PATH (authenticated via GH_TOKEN/GITHUB_TOKEN in CI).
Standard library only.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None  # type: ignore[assignment]

# --- Attribution configuration -------------------------------------------------

# Logins treated as *relays*: they re-land other people's work. A PR authored by
# a relay is searched for the real originator; a PR authored by anyone else is
# credited to its author directly.
RELAYS = {"MCPVOT"}

# Bots never earn credit and are never treated as originators.
BOT_RE = re.compile(
    r"(\[bot\]$|^(claude|copilot|dependabot|github-actions|coderabbit)|anthropic|noreply@github\.com$)",
    re.I,
)

# Co-Authored-By: Name <email>
TRAILER = re.compile(r"(?im)^\s*co-authored-by:\s*(.+?)\s*<([^>]*)>")

# "supersedes #12", "re-lands #12", "rebased from #12", "carries over #12"
REFS = re.compile(
    r"(?i)(?:supersedes|superseding|re-?lands?|rebase of|rebased from|carr(?:y|ies) over)\s+#(\d+)"
)

# 123+login@users.noreply.github.com  ->  login
NOREPLY = re.compile(r"^(?:\d+\+)?([^@]+)@users\.noreply\.github\.com$", re.I)

PACIFIC = ZoneInfo("America/Los_Angeles") if ZoneInfo else timezone(timedelta(hours=-7))
SINCE_CAPTION = "new since 12:00 AM Pacific (America/Los_Angeles)"
RANKED_BY = "merged_prs"


# --- Pure helpers (unit-tested) -------------------------------------------------


def is_bot(login_or_name: str | None, email: str | None = None) -> bool:
    """Whether an identity is a bot and therefore earns no credit."""
    return bool(BOT_RE.search(login_or_name or "")) or bool(BOT_RE.search(email or ""))


def parse_trailers(text: str | None) -> list[tuple[str, str]]:
    """Every distinct `(name, email)` in the Co-Authored-By trailers of `text`."""
    if not text:
        return []
    # A set: one commit can contribute at most one count per identity, even if
    # the trailer appears twice.
    return sorted({(name.strip(), email.strip()) for name, email in TRAILER.findall(text)})


def parse_refs(text: str | None) -> list[int]:
    """PR numbers referenced as the origin of this work."""
    if not text:
        return []
    return [int(n) for n in REFS.findall(text)]


def pacific_midnight(now: datetime) -> datetime:
    """Most recent 00:00 America/Los_Angeles at or before `now`, as aware UTC."""
    local = now.astimezone(PACIFIC)
    return local.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)


def count_since(dates: list[str], cutoff: datetime) -> int:
    """How many ISO-8601 timestamps are at or after `cutoff`."""
    total = 0
    for d in dates:
        if datetime.fromisoformat(d.replace("Z", "+00:00")) >= cutoff:
            total += 1
    return total


def default_login_from_noreply(name: str, email: str) -> str | None:
    """Map `login@users.noreply.github.com` to `login`, else None."""
    m = NOREPLY.match(email.strip())
    return m.group(1) if m else None


def credit_for_pr(
    pr: dict,
    commits: list[dict],
    by_number: dict[int, dict],
    resolve: "callable",
) -> list[str]:
    """Everyone who deserves credit for `pr`, in priority order.

    `resolve(name, email) -> login | None` maps a co-author to a GitHub login.

    Rules (in order of strength):
      1. a Co-Authored-By trailer in the PR BODY credits at full strength;
      2. a Co-Authored-By trailer in at least half the COMMITS credits;
      3. a body reference ("supersedes #N") credits the author of #N;
      4. otherwise the PR author, if human.
    """
    author = ((pr.get("author") or {}).get("login") or "").strip()
    login = author
    is_relay = login in RELAYS or is_bot(login) or bool((pr.get("author") or {}).get("is_bot"))

    credited: list[str] = []

    # A PR authored by a normal human is credited to them and nothing else. The
    # attribution machinery exists for relays, not to second-guess authors.
    if not is_relay:
        return [login] if login and not is_bot(login) else []

    seen: dict[tuple[str, str], int] = {}
    for commit in commits:
        text = (commit.get("messageHeadline") or "") + "\n" + (commit.get("messageBody") or "")
        for identity in parse_trailers(text):
            seen[identity] = seen.get(identity, 0) + 1

    body_trailers = [t for t in parse_trailers(pr.get("body")) if not is_bot(t[0], t[1])]
    for identity in body_trailers:
        seen[identity] = len(commits)

    n_commits = len(commits)
    for (name, email), count in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0])):
        if is_bot(name, email):
            continue
        # A trailer has to cover at least half the commits to count; otherwise a
        # stacked PR that merely carries a few of someone's commits would credit
        # them for work they did not do here.
        if n_commits and count * 2 < n_commits:
            continue
        resolved = resolve(name, email) or default_login_from_noreply(name, email) or name
        if resolved and resolved != login and resolved not in credited:
            credited.append(resolved)

    for number in parse_refs(pr.get("body")):
        source = by_number.get(number) or {}
        source_login = ((source.get("author") or {}).get("login") or "").strip()
        if (
            source_login
            and source_login != login
            and not is_bot(source_login)
            and source_login not in credited
        ):
            credited.append(source_login)

    if not credited and login and not is_bot(login):
        credited = [login]
    return credited


def build_leaderboard(
    repo: str,
    prs: list[dict],
    issues: list[dict],
    commits_by_pr: dict[int, list[dict]],
    now: datetime,
    resolve: "callable",
) -> dict:
    """The leaderboard document, from raw GitHub data."""
    merged = [p for p in prs if p.get("state") == "MERGED"]
    by_number = {int(p["number"]): p for p in prs}
    cutoff = pacific_midnight(now)

    people: dict[str, dict] = {}
    assigned: dict[int, str] = {}
    unattributed: list[int] = []
    notes: list[str] = []

    for pr in sorted(merged, key=lambda p: int(p["number"])):
        number = int(pr["number"])
        merge_date = pr.get("mergedAt") or ""
        credited = credit_for_pr(pr, commits_by_pr.get(number, []), by_number, resolve)

        if not credited:
            unattributed.append(number)
            notes.append(f"#{number}: no human originator, not credited")
            continue

        first = credited[0]
        if len(credited) > 1:
            notes.append(f"#{number}: also named {', '.join(credited[1:])} (credited {first} only)")

        assigned[number] = first
        row = people.setdefault(
            first,
            {
                "login": first,
                "avatar_url": f"https://github.com/{first}.png?size=200",
                "merged_prs": 0,
                "issues_filed": 0,
                "today_prs": 0,
                "pr_numbers": [],
                "issue_numbers": [],
                "dates": [],
            },
        )
        row["merged_prs"] += 1
        row["pr_numbers"].append(number)
        if merge_date:
            row["dates"].append(merge_date)

    # Issues are context only: counted for people who already earned a merged PR,
    # never scored. An issue-only contributor is not on the board.
    for issue in issues:
        login = ((issue.get("author") or {}).get("login") or "").strip()
        if login in people:
            people[login]["issues_filed"] += 1
            people[login]["issue_numbers"].append(int(issue["number"]))

    rows = []
    for row in people.values():
        dates = sorted(row.pop("dates"))
        today = count_since(dates, cutoff)
        rows.append(
            {
                "login": row["login"],
                "avatar_url": row["avatar_url"],
                "merged_prs": row["merged_prs"],
                "issues_filed": row["issues_filed"],
                "today_prs": today,
                "today_badge": today_badge(today),
                "score": row["merged_prs"],
                "first_contribution": dates[0] if dates else "",
                "last_contribution": dates[-1] if dates else "",
                "pr_numbers": sorted(row["pr_numbers"]),
                "issue_numbers": row["issue_numbers"],
            }
        )

    # Ranked by merged PRs, then by who got there first, then by login.
    rows.sort(
        key=lambda r: (-r["merged_prs"], r["first_contribution"], r["login"].lower())
    )
    for position, row in enumerate(rows, start=1):
        row["rank"] = position

    total_credited = sum(r["merged_prs"] for r in rows)
    assert total_credited + len(unattributed) == len(merged), "credit accounting does not add up"

    document = {
        "repo": repo,
        "generated_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_pacific": now.astimezone(PACIFIC).strftime("%b %d, %Y %I:%M %p %Z"),
        "since": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "since_caption": SINCE_CAPTION,
        "today_total": sum(r["today_prs"] for r in rows),
        "ranked_by": RANKED_BY,
        "merged_pr_total": len(merged),
        "unattributed_prs": sorted(unattributed),
        "contributors": rows,
    }
    document["_notes"] = notes
    return document


def today_badge(today: int) -> str:
    """The little delta badge. Inline SVG so it needs no icon font."""
    if today <= 0:
        return (
            '<span class="delta delta-none" title="none since midnight Pacific">'
            "&ndash;</span>"
        )
    return (
        '<span class="delta delta-up" title="+%d new since 12:00 AM Pacific '
        '(America/Los_Angeles)"><svg viewBox="0 0 10 9" width="14" height="12" '
        'aria-label="up"><polygon points="5,0 10,9 0,9"/></svg>+%d</span>' % (today, today)
    )


# --- GitHub access (impure, thin) ----------------------------------------------


def run_gh(*args: str) -> str:
    """Run `gh` and return stdout, or leave with its error."""
    proc = subprocess.run(["gh", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr or "")
        raise SystemExit(f"gh {' '.join(args)} failed ({proc.returncode})")
    return proc.stdout


def make_resolver(repo: str):
    """Resolve a co-author to a login via GitHub user search, or None."""
    cache: dict[tuple[str, str], str | None] = {}

    def resolve(name: str, email: str) -> str | None:
        direct = default_login_from_noreply(name, email)
        if direct:
            return direct
        key = (name, email)
        if key in cache:
            return cache[key]
        result = None
        for query in (f"{email} in:email", f"{name} in:fullname"):
            try:
                data = json.loads(run_gh("api", "-X", "GET", "search/users", "-f", f"q={query}"))
            except SystemExit:
                break
            if data.get("total_count") == 1:
                result = data["items"][0]["login"]
                break
        cache[key] = result
        return result

    return resolve


def load_repo_data(repo: str) -> tuple[list[dict], list[dict], dict[int, list[dict]], int]:
    """Fetch every PR, every issue, and the commits of merged PRs."""
    total = json.loads(
        run_gh("api", "-X", "GET", "search/issues", "-f", f"q=repo:{repo} is:pr is:merged", "-f", "per_page=1")
    )["total_count"]

    prs = json.loads(
        run_gh(
            "pr", "list", "-R", repo, "--state", "all", "-L", "1000000",
            "--json", "number,state,author,body,mergedAt",
        )
    )
    issues = json.loads(
        run_gh("issue", "list", "-R", repo, "--state", "all", "-L", "1000000", "--json", "number,author")
    )

    merged = [p for p in prs if p.get("state") == "MERGED"]
    # The total is read BEFORE the list, so a merge mid-run can only lengthen the
    # list. A shorter list means pagination or query drift, and publishing a
    # truncated leaderboard is worse than not publishing.
    if len(merged) < total:
        raise SystemExit(f"INCOMPLETE: fetched {len(merged)} merged PRs, GitHub reports {total}")

    commits_by_pr: dict[int, list[dict]] = {}
    for pr in merged:
        number = int(pr["number"])
        raw = run_gh("api", "--paginate", "--slurp", f"repos/{repo}/pulls/{number}/commits")
        pages = json.loads(raw)
        commits: list[dict] = []
        for page in pages if isinstance(pages, list) else [pages]:
            for commit in page or []:
                c = commit.get("commit") or {}
                commits.append(
                    {
                        "messageHeadline": c.get("message", "").split("\n", 1)[0],
                        "messageBody": c.get("message", "").split("\n", 1)[1]
                        if "\n" in c.get("message", "")
                        else "",
                    }
                )
        commits_by_pr[number] = commits

    return prs, issues, commits_by_pr, total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the zkagent contributor leaderboard.")
    parser.add_argument("--repo", default="MCPVOT/zkagent", help="owner/repo")
    parser.add_argument("--out", default="leaderboard.json", help="where to write the JSON")
    args = parser.parse_args(argv)

    now = datetime.now(timezone.utc)
    prs, issues, commits_by_pr, total = load_repo_data(args.repo)

    document = build_leaderboard(args.repo, prs, issues, commits_by_pr, now, make_resolver(args.repo))
    notes = document.pop("_notes", [])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    for note in notes:
        sys.stderr.write(note + "\n")
    sys.stderr.write(
        "leaderboard: %d merged PRs, %d credited, %d unattributed -> %s\n"
        % (
            document["merged_pr_total"],
            len(document["contributors"]),
            len(document["unattributed_prs"]),
            out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
