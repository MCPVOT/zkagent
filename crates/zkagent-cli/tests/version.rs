//! `zkagent version` is the answer to "which tree is this", so its shape is a contract.
//!
//! Three numbers get confused in this project — the crate version (which code), FORMAT_VERSION
//! (which artifacts it can read) and the commit (which tree). A verifier that cannot say which
//! tree it is running cannot be reproduced from an artifact, so the output stays stable and the
//! format it reports must match the constant the verifier actually enforces.

use std::process::Command;

fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_zkagent"))
        .args(args)
        .output()
        .expect("the binary under test should run");
    assert!(
        out.status.success(),
        "version must exit 0, got {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout is utf-8")
}

#[test]
fn the_human_line_names_all_three_numbers() {
    let line = run(&["version"]);
    let line = line.trim();
    assert!(line.starts_with("zkagent "), "unexpected line: {line}");
    assert!(
        line.contains(&format!(
            "zkagent {} (artifact format ",
            env!("CARGO_PKG_VERSION")
        )),
        "crate version missing: {line}"
    );
    assert!(line.contains(") commit "), "commit missing: {line}");
    // Either a real short sha, or the honest fallback outside a git checkout.
    let commit = line.split(") commit ").nth(1).expect("commit segment");
    let commit = commit.split(' ').next().unwrap_or("");
    assert!(
        commit == "unknown" || (commit.len() >= 7 && commit.chars().all(|c| c.is_ascii_hexdigit())),
        "commit is neither unknown nor a short sha: {commit}"
    );
}

#[test]
fn the_json_form_is_parseable_and_matches_the_enforced_format() {
    let text = run(&["--json", "version"]);
    let doc: serde_json::Value = serde_json::from_str(&text).expect("version --json must be JSON");

    assert_eq!(doc["name"], "zkagent");
    assert_eq!(doc["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        doc["format"].as_u64().expect("format is a number"),
        u64::from(zkagent_service::FORMAT_VERSION),
        "the reported format must be the one the verifier enforces"
    );
    assert!(doc["commit"].is_string());
    assert!(doc["dirty"].is_boolean());
}

#[test]
fn the_flag_and_the_subcommand_agree() {
    let via_flag = run(&["--version"]).trim().to_string();
    let via_sub = run(&["version"]).trim().to_string();
    assert!(
        via_sub.contains(&via_flag.replace("zkagent ", "")),
        "--version said {via_flag}, version said {via_sub}"
    );
}
