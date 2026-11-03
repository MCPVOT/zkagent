//! Stamp the binary with the commit it was built from.
//!
//! A verifier that cannot say which tree it is running is a verifier whose
//! behaviour you cannot reproduce from an artifact. The commit is a build-time
//! fact, so it is captured here and printed by `zkagent version`; when git is
//! unavailable (a source tarball, a container build) it degrades to "unknown"
//! rather than failing the build.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    // Re-run when HEAD moves so a new commit is not reported as the old one.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    let sha = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = git(&["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    println!("cargo:rustc-env=ZKAGENT_GIT_SHA={sha}");
    println!("cargo:rustc-env=ZKAGENT_GIT_DIRTY={}", u8::from(dirty));
}
