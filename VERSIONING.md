# Versioning

`semver + date`, the form this project has used since the first tag:

```
v0.4.0+2026-11-08
 │ │ │  └── release date, UTC, YYYY-MM-DD
 │ │ └───── patch
 │ └─────── minor
 └───────── major
```

The date is part of the identity, not decoration. Two builds of `0.4.0` a month apart are not the
same artifact, and a tag that hides the date invites exactly that confusion.

## What each part means before 1.0

| change | bump | examples |
| --- | --- | --- |
| artefact format, public inputs, circuit shape, verifying-key layout | **minor** | a format version change, a new public input |
| behaviour of a verdict, a refusal reason, an exit code | **minor** | a new `reason_code`, a stricter replay rule |
| bug fix, performance, docs, internal refactor | **patch** | fresh blinding per proof, a faster prover |
| removing a command or a field | **minor** | pre-1.0 there is no stable-major promise |

Before 1.0 the minor number carries the breaking changes. Say so in the changelog, do not rely on
the reader to infer it.

## The rules CI enforces

1. `Cargo.toml` workspace version equals the newest `CHANGELOG.md` entry.
2. The newest git tag is `v<version>+<YYYY-MM-DD>` and its version part equals `Cargo.toml`.
3. The changelog entry's date equals the date in the tag.
4. A release without a changelog entry fails the build.

`tools/check_version.py` implements those, and the `version consistency` job runs it on every push.
Run it before tagging:

```bash
python3 tools/check_version.py
```

## Release checklist

```bash
# 1. the tree is green and master is up to date
gh pr checks --watch && git pull --ff-only

# 2. bump, with the changelog entry in the same commit
#    Cargo.toml: version = "X.Y.Z"
#    CHANGELOG.md: "## X.Y.Z+YYYY-MM-DD" as the first entry
cargo metadata --format-version 1 > /dev/null      # refresh Cargo.lock
python3 tools/check_version.py

# 3. ship it through a PR, because master is protected
git checkout -b release/X.Y.Z
git commit -am "chore: X.Y.Z, <one line>"
gh pr create --fill && gh pr checks --watch && gh pr merge --squash

# 4. tag the merge commit, not the branch
git checkout master && git pull --ff-only
git tag -a "vX.Y.Z+YYYY-MM-DD" -m "X.Y.Z: <one line>"
git push origin "vX.Y.Z+YYYY-MM-DD"
```

Pushing the tag triggers the release workflow, which builds Linux, macOS and Windows assets,
generates `SHA256SUMS`, and attaches build provenance.

## Consumers pin, they do not float

Anything that installs this project pins a commit and a checksum. Two live examples:

- `MCPVOT/hermes-zkagent` pins the release tag and verifies each asset against `SHA256SUMS`
- `MCPVOT/hermes-agent` catalog entry pins a plugin commit, which pins this release

When a version moves, the pins move in the same session. A pin that lags is how a fixed defect keeps
shipping: `0.3.1` had a prover with fixed blinding and stayed reachable for a day after `0.4.0`
existed.
