//! Every rejection must be machine-readable.
//!
//! An agent decides what to do next from the verdict. `Display` prose is for a
//! human reading a terminal; a harness needs a stable identifier it can branch
//! on without parsing English. `RejectReason::code()` is that identifier, and
//! this file is what keeps it stable: renaming a variant or adding one without a
//! code fails here rather than in somebody's integration.

use zkagent_verifier::RejectReason;

#[test]
fn every_reject_reason_has_a_stable_code() {
    let cases: Vec<(RejectReason, &str)> = vec![
        (
            RejectReason::FormatMismatch {
                artifact: 1,
                expected: 2,
            },
            "format_mismatch",
        ),
        (RejectReason::PublicInputMismatch, "public_input_mismatch"),
        (RejectReason::UnauthorisedPolicy, "unauthorised_policy"),
        (RejectReason::ChainMismatch, "chain_mismatch"),
        (RejectReason::Expired, "expired"),
        (RejectReason::MissingExecutionId, "missing_execution_id"),
        (RejectReason::AlreadyAccepted(7), "already_accepted"),
        (RejectReason::InvalidProof, "invalid_proof"),
        (RejectReason::MalformedProof("truncated".into()), "malformed_proof"),
    ];

    for (reason, expected) in cases {
        assert_eq!(
            reason.code(),
            expected,
            "the code for {reason:?} changed; a harness may branch on it"
        );
    }
}

#[test]
fn codes_are_unique_lowercase_and_underscored() {
    let reasons = [
        RejectReason::FormatMismatch {
            artifact: 1,
            expected: 2,
        },
        RejectReason::PublicInputMismatch,
        RejectReason::UnauthorisedPolicy,
        RejectReason::ChainMismatch,
        RejectReason::Expired,
        RejectReason::MissingExecutionId,
        RejectReason::AlreadyAccepted(0),
        RejectReason::InvalidProof,
        RejectReason::MalformedProof(String::new()),
    ];

    let mut seen = Vec::new();
    for reason in &reasons {
        let code = reason.code();
        assert!(
            !code.is_empty() && code.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "code {code:?} must be lowercase snake_case"
        );
        assert!(!seen.contains(&code), "code {code:?} is not unique");
        seen.push(code);
    }
    assert_eq!(seen.len(), reasons.len());
}

#[test]
fn the_code_is_not_the_prose() {
    // A code that merely repeats `Display` gives a harness nothing to branch on,
    // and silently re-couples the machine contract to an English sentence.
    let reason = RejectReason::Expired;
    assert_ne!(reason.code(), reason.to_string());
}
