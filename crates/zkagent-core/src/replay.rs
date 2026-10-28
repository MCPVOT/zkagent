//! Persistent anti-replay state for the verifying side.
//!
//! A Groth16 proof says "some execution inside this policy produced this
//! receipt". It does *not* say "and I have never seen this execution before" —
//! freshness is stateful, so it belongs to the verifier. Without a set of ids
//! it has already accepted, a verifier will happily accept the same proof twice,
//! which is exactly the replay a receipts protocol must refuse.
//!
//! # Why this is a type and not a sentence in the docs
//!
//! The gap this closes was previously described in prose ("a verifier that must
//! accept a receipt at most once keeps that set") with a helper nobody called.
//! Documentation is not a mechanism: if the shipped binary cannot refuse a
//! replay, the property does not exist. This type is wired into `zkagent
//! verify --seen`, so the guarantee is exercised by the CLI and by CI.
//!
//! # Failure policy: fail closed
//!
//! A *missing* state file is a first run and loads empty. A state file that
//! exists but cannot be read or parsed is an **error**, never an empty set:
//! silently treating a corrupt ledger as "nothing seen yet" would turn
//! "truncate this file" into a replay attack, and the attacker controls nothing
//! but the file name.
//!
//! # Durability
//!
//! Writes go to a sibling temp file and are then renamed over the target, so an
//! interrupted write leaves the previous set intact rather than a half-written
//! file. On both Unix and Windows `rename` replaces the destination, and same-
//! directory placement keeps it atomic.
//!
//! # Limits
//!
//! The set only grows; there is no pruning or expiry (see the roadmap). It also
//! assumes a single writer — two verifiers sharing one file can interleave a
//! load/record pair. Both are stated rather than papered over.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Why the seen-set could not be loaded or persisted.
#[derive(Debug)]
pub enum ReplayError {
    /// The file could not be read or written.
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying cause.
        detail: String,
    },
    /// The file exists but is not a seen-set document.
    ///
    /// Deliberately fatal: see the module docs on failing closed.
    Corrupt {
        /// The path involved.
        path: PathBuf,
        /// What was wrong with it.
        detail: String,
    },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::Io { path, detail } => {
                write!(f, "replay state {}: {detail}", path.display())
            }
            ReplayError::Corrupt { path, detail } => write!(
                f,
                "replay state {} is unreadable ({detail}); refusing to verify against an \
                 unknown set of accepted executions",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ReplayError {}

/// On-disk shape. Kept separate from [`SeenExecutions`] so the wire format is
/// explicit and stable.
#[derive(serde::Serialize, serde::Deserialize)]
struct SeenFile {
    execution_ids: Vec<u64>,
}

/// The set of execution ids a verifier has already accepted.
#[derive(Debug, Clone, Default)]
pub struct SeenExecutions {
    path: PathBuf,
    ids: BTreeSet<u64>,
}

impl SeenExecutions {
    /// Load the set at `path`, treating a missing file as an empty set.
    ///
    /// # Errors
    /// Returns [`ReplayError::Corrupt`] if the file exists but is not valid
    /// seen-set JSON, and [`ReplayError::Io`] if it cannot be read.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, ReplayError> {
        let path = path.into();
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            // First run. Not an error — there is nothing to protect yet.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    ids: BTreeSet::new(),
                })
            }
            Err(e) => {
                return Err(ReplayError::Io {
                    path,
                    detail: e.to_string(),
                })
            }
        };

        let parsed: SeenFile = serde_json::from_str(&raw).map_err(|e| ReplayError::Corrupt {
            path: path.clone(),
            detail: e.to_string(),
        })?;

        Ok(Self {
            path,
            ids: parsed.execution_ids.into_iter().collect(),
        })
    }

    /// The backing file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many ids are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Whether this id has already been accepted.
    #[must_use]
    pub fn contains(&self, execution_id: u64) -> bool {
        self.ids.contains(&execution_id)
    }

    /// Record an accepted id and persist the set.
    ///
    /// Returns `Ok(false)` when the id was already present, so a caller can
    /// treat "already recorded" as the replay signal without a separate check.
    ///
    /// # Errors
    /// Returns [`ReplayError::Io`] if the set could not be persisted. The
    /// in-memory set is only updated after the write succeeds, so a failed save
    /// cannot leave the verifier believing it recorded something it did not.
    pub fn record(&mut self, execution_id: u64) -> Result<bool, ReplayError> {
        if self.ids.contains(&execution_id) {
            return Ok(false);
        }

        let mut next = self.ids.clone();
        next.insert(execution_id);
        self.persist(&next)?;
        self.ids = next;
        Ok(true)
    }

    /// Write `ids` to disk atomically (temp file + rename).
    fn persist(&self, ids: &BTreeSet<u64>) -> Result<(), ReplayError> {
        let doc = SeenFile {
            execution_ids: ids.iter().copied().collect(),
        };
        let text = serde_json::to_string_pretty(&doc).map_err(|e| ReplayError::Io {
            path: self.path.clone(),
            detail: e.to_string(),
        })?;

        // Same directory, so the rename stays on one filesystem and is atomic.
        let tmp = self.path.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            // Durability: without this the rename can land while the contents
            // are still buffered, which on power loss yields an empty file.
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &self.path)
        };
        write().map_err(|e| ReplayError::Io {
            path: self.path.clone(),
            detail: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "zkagent-replay-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after 1970")
                .as_nanos()
        ));
        fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    #[test]
    fn a_missing_file_is_an_empty_set() {
        let dir = tmpdir("missing");
        let seen = SeenExecutions::load(dir.join("ids.json")).expect("missing file loads");
        assert!(seen.is_empty());
        assert!(!seen.contains(1001));
    }

    #[test]
    fn recording_persists_across_reload() {
        let dir = tmpdir("persist");
        let path = dir.join("ids.json");

        let mut seen = SeenExecutions::load(&path).expect("load");
        assert!(seen.record(1001).expect("record"));
        assert!(seen.contains(1001));

        let reloaded = SeenExecutions::load(&path).expect("reload");
        assert!(reloaded.contains(1001));
        assert_eq!(reloaded.len(), 1);
    }

    #[test]
    fn re_recording_is_reported_as_already_present() {
        let dir = tmpdir("dup");
        let mut seen = SeenExecutions::load(dir.join("ids.json")).expect("load");
        assert!(seen.record(7).expect("first record is new"));
        assert!(!seen.record(7).expect("second record is a duplicate"));
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn a_corrupt_file_fails_closed() {
        let dir = tmpdir("corrupt");
        let path = dir.join("ids.json");
        fs::write(&path, b"{\"execution_ids\": [1, 2").expect("write partial json");

        match SeenExecutions::load(&path) {
            Err(ReplayError::Corrupt { .. }) => {}
            other => panic!("corrupt state must be fatal, got {other:?}"),
        }
    }

    #[test]
    fn a_wrong_shape_file_fails_closed() {
        // Valid JSON, wrong document: must not be read as "empty".
        let dir = tmpdir("shape");
        let path = dir.join("ids.json");
        fs::write(&path, b"{\"other\": []}").expect("write wrong shape");
        match SeenExecutions::load(&path) {
            Err(ReplayError::Corrupt { .. }) => {}
            other => panic!("wrong-shape state must be fatal, got {other:?}"),
        }
    }

    #[test]
    fn saving_leaves_no_temp_file_behind() {
        let dir = tmpdir("atomic");
        let path = dir.join("ids.json");
        let mut seen = SeenExecutions::load(&path).expect("load");
        seen.record(42).expect("record");

        let leftover: Vec<_> = fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "temp files left behind: {leftover:?}");
    }

    #[test]
    fn ids_are_written_in_sorted_order() {
        // A stable file means a verifier's state diffs cleanly in review; an
        // unordered set would churn on every write.
        let dir = tmpdir("sorted");
        let path = dir.join("ids.json");
        let mut seen = SeenExecutions::load(&path).expect("load");
        seen.record(9).expect("record 9");
        seen.record(3).expect("record 3");
        seen.record(5).expect("record 5");

        let text = fs::read_to_string(&path).expect("read back");
        let parsed: SeenFile = serde_json::from_str(&text).expect("parse");
        assert_eq!(parsed.execution_ids, vec![3, 5, 9]);
    }

    #[test]
    fn zero_is_recordable_at_this_layer() {
        // Rejecting id 0 is the circuit's and the verifier's job, not this
        // container's. Keeping the container oblivious means it cannot silently
        // disagree with them about what a valid id is.
        let dir = tmpdir("zero");
        let mut seen = SeenExecutions::load(dir.join("ids.json")).expect("load");
        assert!(seen.record(0).expect("record"));
        assert!(seen.contains(0));
    }
}
