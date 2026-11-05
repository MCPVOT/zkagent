//! One parsed proving key, kept for the life of the server process.
//!
//! # Why (measured, not assumed)
//!
//! `pk.bin` is 1.45 MB of compressed G1/G2 points, and reading it means one
//! field square root per point. Even with the parallel reader in
//! `zkagent-proofs/src/keyfile.rs` that is ~258 ms of a ~600 ms one-shot
//! `zkagent prove` on this laptop. A CLI pays it once and exits, which is why
//! nothing was cached before. An MCP server is the opposite: one process, many
//! `tools/call`s, so the same 258 ms was paid on **every** prove. Measured over
//! stdio, four consecutive prove calls in one server took ~0.40 s, ~0.40 s,
//! ~0.39 s, ~0.41 s — flat, because nothing was reused.
//!
//! # What is cached, and what is not
//!
//! The parsed [`Keys`] (proving and verifying key) for **one** keys directory.
//! One slot, not an LRU: a server serves one workspace in practice, a second
//! entry would only ever be a mistake, and an LRU would add eviction policy to
//! test for no measured gain. A parsed key is ~45 k points, ~3 MB of G1/G2
//! structures, and retaining it is invisible in the process's RSS — 26.1 MB
//! after two proves with the cache against 27.7 MB without it — so one slot is
//! bounded by construction and needs no size ceiling.
//!
//! # Staleness
//!
//! The entry is keyed by the canonical keys directory plus a fingerprint of both
//! key files: length, mtime, ctime (unix) and a 64-bit hash of the first and
//! last 4 KiB. Only identical fingerprints reuse the key. `zkagent_setup`
//! rewrites `pk.bin` to **exactly the same length** — the circuit shape is fixed
//! — so length alone can never detect a rerun, and on a filesystem with coarse
//! timestamps neither can mtime. The content probe is what makes the
//! same-length rewrite visible; ctime covers a rewrite that preserves mtime
//! (utime cannot set ctime).
//!
//! A miss **drops the old entry before loading**, so a failed load leaves the
//! cache empty and the next call retries, rather than serving a key that no
//! longer matches the files on disk. The key is still parsed and validated by
//! [`zkagent_service::load_keys`] — same `Compress::Yes`, `Validate::Yes` — so
//! caching changes how often the key is read, never whether it is checked.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use zkagent_service::{load_keys, Keys, ServiceError};

/// How much of each end of a key file goes into its fingerprint.
///
/// 4 KiB per end is ~8 KiB read from the page cache per call — microseconds,
/// against the ~258 ms the cache saves — and covers the verifying key at the
/// head plus the tail of the last point vector, which is where a regenerated
/// key differs with overwhelming probability.
const PROBE_BYTES: u64 = 4096;

/// The identity of one key file, as cheap to compute as `stat` plus a short read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FileStamp {
    len: u64,
    modified_ns: Option<u128>,
    changed_ns: Option<i128>,
    probe: u64,
}

impl FileStamp {
    fn of(path: &Path) -> Result<Self, ServiceError> {
        let meta = fs::metadata(path).map_err(|e| ServiceError::io(path, e))?;
        Ok(Self {
            len: meta.len(),
            modified_ns: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos()),
            changed_ns: changed_ns(&meta),
            probe: probe(path, meta.len()).map_err(|e| ServiceError::io(path, e))?,
        })
    }
}

/// Inode change time, where the platform has one.
///
/// Any write or metadata change moves it, and unlike mtime it cannot be set from
/// user space, so it catches a rewrite that deliberately restores the mtime.
#[cfg(unix)]
fn changed_ns(meta: &fs::Metadata) -> Option<i128> {
    use std::os::unix::fs::MetadataExt;
    Some(i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()))
}

#[cfg(not(unix))]
fn changed_ns(_meta: &fs::Metadata) -> Option<i128> {
    None
}

/// FNV-1a over the head and tail of a file. A change detector, not a checksum:
/// it never leaves the process and guards nothing against a chosen-input
/// collision, only against "these bytes are not those bytes".
fn probe(path: &Path, len: u64) -> std::io::Result<u64> {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; PROBE_BYTES.min(len) as usize];
    if buf.is_empty() {
        return Ok(hash);
    }
    file.read_exact(&mut buf)?;
    for b in &buf {
        hash = (hash ^ u64::from(*b)).wrapping_mul(PRIME);
    }
    if len > PROBE_BYTES {
        file.seek(SeekFrom::End(-(PROBE_BYTES as i64)))?;
        file.read_exact(&mut buf)?;
        for b in &buf {
            hash = (hash ^ u64::from(*b)).wrapping_mul(PRIME);
        }
    }
    Ok(hash)
}

/// The fingerprint of a key pair: both files, because a proving key and a
/// verifying key from different setups are not a pair at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct KeyStamp {
    pk: FileStamp,
    vk: FileStamp,
}

struct Slot {
    keys_dir: PathBuf,
    stamp: KeyStamp,
    keys: Arc<Keys>,
}

/// A single-slot cache of the parsed key pair for one keys directory.
pub(crate) struct KeyCache {
    slot: Mutex<Option<Slot>>,
    /// How many times the key was actually parsed. Test-only: it is the
    /// difference between "the call returned the right answer" and "the call
    /// returned the right answer without reloading".
    #[cfg(test)]
    loads: std::sync::atomic::AtomicU64,
}

impl KeyCache {
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(None),
            #[cfg(test)]
            loads: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The parsed key pair for `keys_dir`, loading it only when the files have
    /// changed since the cached copy was read.
    ///
    /// The lock is held across the load. Concurrent callers would otherwise all
    /// miss and all parse the same 1.45 MB key; serialising them means the
    /// second one finds the entry the first just stored. The server handles one
    /// request at a time, so this is a formality today, but it keeps the
    /// invariant true if a host ever drives `Server` from a thread pool.
    pub(crate) fn get(&self, keys_dir: &Path) -> Result<Arc<Keys>, ServiceError> {
        // Canonicalise, so `./keys`, `keys` and `/abs/keys` are one entry and a
        // symlink cannot be used to keep serving a key from another directory.
        let canonical = fs::canonicalize(keys_dir).map_err(|e| ServiceError::io(keys_dir, e))?;
        let stamp = KeyStamp {
            pk: FileStamp::of(&canonical.join("pk.bin"))?,
            vk: FileStamp::of(&canonical.join("vk.bin"))?,
        };

        // A poisoned lock means a previous caller panicked while holding it.
        // The cache itself is still consistent (it is one Option assignment),
        // so recover rather than turning every later prove into a panic.
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(hit) = slot.as_ref() {
            if hit.keys_dir == canonical && hit.stamp == stamp {
                return Ok(Arc::clone(&hit.keys));
            }
        }

        // Miss. Drop the old entry BEFORE loading: if the new key is corrupt or
        // unreadable, the cache must be empty, not holding the key it had
        // before under a fingerprint that no longer matches the files.
        *slot = None;
        let keys = Arc::new(load_keys(&canonical)?);
        #[cfg(test)]
        self.loads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *slot = Some(Slot {
            keys_dir: canonical,
            stamp,
            keys: Arc::clone(&keys),
        });
        Ok(keys)
    }

    /// How many times a key was actually parsed. Test-only.
    #[cfg(test)]
    pub(crate) fn loads(&self) -> u64 {
        self.loads.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A setup, a cache miss, a cache hit, and — the point — a regenerated key
    /// that must not be served from the old entry.
    #[test]
    fn a_hit_reuses_the_key_and_a_regenerated_pair_forces_a_reload() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keys_dir = dir.path().join("keys");
        zkagent_service::setup(&keys_dir, 7).expect("setup");

        let cache = KeyCache::new();
        let first = cache.get(&keys_dir).expect("first load");
        assert_eq!(cache.loads(), 1);

        let second = cache.get(&keys_dir).expect("second load");
        assert_eq!(cache.loads(), 1, "the second call re-read the key");
        assert!(Arc::ptr_eq(&first, &second), "a different key came back");

        // A relative path and a trailing form of the same directory are the
        // same entry; the canonical path is the key, not the spelling.
        let spelled_differently = keys_dir.join(".");
        let third = cache.get(&spelled_differently).expect("third load");
        assert!(Arc::ptr_eq(&first, &third));
        assert_eq!(cache.loads(), 1);

        // Regenerate: `setup` rewrites both files to the same byte count.
        zkagent_service::setup(&keys_dir, 99).expect("setup again");
        let fourth = cache.get(&keys_dir).expect("load after regeneration");
        assert_eq!(cache.loads(), 2, "the regenerated key was not re-read");
        assert!(
            !Arc::ptr_eq(&first, &fourth),
            "the stale key was served after a regeneration"
        );
        // And it really is the key now on disk, not merely a rebuild of the old
        // one.
        let vk_on_disk = fs::read(keys_dir.join("vk.bin")).expect("read vk");
        assert_eq!(
            fourth.verifying_key_bytes().expect("serialise vk"),
            vk_on_disk
        );
    }

    /// A key that has become unreadable is an error every time, never the copy
    /// that was cached before it changed.
    #[test]
    fn a_broken_key_is_an_error_not_a_stale_hit() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keys_dir = dir.path().join("keys");
        zkagent_service::setup(&keys_dir, 7).expect("setup");

        let cache = KeyCache::new();
        cache.get(&keys_dir).expect("first load");

        fs::write(keys_dir.join("pk.bin"), b"not a proving key").expect("corrupt the key");
        assert!(cache.get(&keys_dir).is_err(), "a corrupt key was accepted");
        assert!(cache.get(&keys_dir).is_err(), "the old key came back");
        assert_eq!(cache.loads(), 1, "a failed load must not count as a load");

        // Missing files fail the same way they did before there was a cache.
        fs::remove_file(keys_dir.join("vk.bin")).expect("remove vk");
        assert!(cache.get(&keys_dir).is_err());
    }

    /// Touching a key file — mtime moved, bytes identical — costs a reload. That
    /// is the conservative direction on purpose: the fingerprint is an identity
    /// check, and a file that cannot be cheaply proven identical gets re-read.
    /// Pinned here so the trade is visible if someone later "optimises" it into
    /// a stale-key bug.
    #[test]
    fn touching_a_key_file_forces_a_reload() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keys_dir = dir.path().join("keys");
        zkagent_service::setup(&keys_dir, 7).expect("setup");

        let cache = KeyCache::new();
        let first = cache.get(&keys_dir).expect("first load");

        let pk = keys_dir.join("pk.bin");
        let bytes = fs::read(&pk).expect("read pk");
        fs::write(&pk, &bytes).expect("rewrite the same bytes");

        let second = cache.get(&keys_dir).expect("second load");
        assert_eq!(cache.loads(), 2, "a touched key was served from cache");
        // Same key material either way, so the reload is a cost, not a change in
        // behaviour.
        assert_eq!(first.proving, second.proving);
    }
}
