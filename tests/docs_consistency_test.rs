//! Guards the *numeric* claims in the documentation against the code.
//!
//! `verification_matrix_test` already pins the test **names** referenced by
//! `docs/VERIFICATION.md`. This file covers the other half of the audit
//! surface: the constraint counts, assertion counts, and security levels quoted
//! in `docs/SOUNDNESS.md` and `README.md`.
//!
//! Those numbers are exactly what an auditor reads to decide what the system
//! proves, and they have drifted before — the salted-commitment change freed
//! four boundary assertions (80 -> 76) and left `SOUNDNESS.md` describing a
//! scheme in which the blinding salt was pinned to zero, i.e. a *non-hiding*
//! one. A stale security claim is a correctness defect in the artifact
//! reviewers trust most, so it is asserted rather than proofread.

use std::fs;
use std::path::Path;

use ves_stark_air::compliance::{NUM_BOUNDARY_ASSERTIONS, NUM_CONSTRAINTS};
use ves_stark_air::options::{ASSUMED_MAX_TRACE_LENGTH, MIN_ACCEPTABLE_SECURITY_BITS};
use ves_stark_air::ProofOptions;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_doc(rel: &str) -> String {
    fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel} must exist: {e}"))
}

/// Extract the integer in a heading of the form `### <label> (<N> total)`.
fn parenthesized_total(doc: &str, label: &str) -> usize {
    let line = doc
        .lines()
        .find(|l| l.contains(label) && l.contains("total)"))
        .unwrap_or_else(|| panic!("no `{label} (... total)` heading found"));
    let open = line.rfind('(').expect("heading must contain `(`");
    let rest = &line[open + 1..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits
        .parse()
        .unwrap_or_else(|e| panic!("could not parse a count from `{line}`: {e}"))
}

/// `docs/SOUNDNESS.md` must quote the real transition-constraint count.
#[test]
fn soundness_doc_transition_constraint_count_matches_air() {
    let doc = read_doc("docs/SOUNDNESS.md");
    let documented = parenthesized_total(&doc, "Transition Constraints");
    assert_eq!(
        documented, NUM_CONSTRAINTS,
        "docs/SOUNDNESS.md claims {documented} transition constraints, \
         but ComplianceAir declares {NUM_CONSTRAINTS}"
    );
}

/// `docs/SOUNDNESS.md` must quote the real boundary-assertion count.
///
/// This is the assertion that would have caught the salted-commitment drift:
/// the code dropped to 76 while the document still said 80.
#[test]
fn soundness_doc_boundary_assertion_count_matches_air() {
    let doc = read_doc("docs/SOUNDNESS.md");
    let documented = parenthesized_total(&doc, "Boundary Assertions");
    assert_eq!(
        documented, NUM_BOUNDARY_ASSERTIONS,
        "docs/SOUNDNESS.md claims {documented} boundary assertions, but the AIR \
         emits {NUM_BOUNDARY_ASSERTIONS} (tied to the AIR by `test_air_assertions`)"
    );
}

/// `SOUNDNESS.md` must not describe the salt limbs as constrained to zero.
///
/// Asserting `AMOUNT[2..6] = 0` would pin the blinding salt and destroy the
/// hiding property; an earlier revision of the document said exactly that while
/// the code did not.
#[test]
fn soundness_doc_does_not_claim_the_salt_limbs_are_pinned() {
    let doc = read_doc("docs/SOUNDNESS.md");
    assert!(
        !doc.contains("`AMOUNT[2..7] = 0`"),
        "docs/SOUNDNESS.md still claims AMOUNT limbs 2-7 are asserted zero; the AIR \
         constrains only limbs 6-7 so that limbs 2-5 can carry the blinding salt"
    );
}

/// Every security number quoted in the README must be the number the estimator
/// actually returns for that preset.
#[test]
fn readme_security_levels_match_the_estimator() {
    let readme = read_doc("README.md");
    for (name, opts) in [
        ("default", ProofOptions::default()),
        ("fast", ProofOptions::fast()),
        ("secure", ProofOptions::secure()),
    ] {
        let bits = opts.security_level();
        let needle = format!("{bits}");
        assert!(
            readme.contains(&needle),
            "README does not mention the {bits}-bit level that `{name}` reports"
        );
    }
}

/// The README must not carry the pre-correction security claims. These were
/// mutually contradictory (the `secure` preset was described as 100+, 190, and
/// 128 bits in one file) and were produced by an estimator that ignored the
/// field-size bound.
#[test]
fn readme_does_not_carry_superseded_security_claims() {
    let readme = read_doc("README.md");
    for stale in [
        "82-bit",
        "~190 bits",
        "100+-bit",
        "~80 bits estimated",
        "~128-bit security",
    ] {
        assert!(
            !readme.contains(stale),
            "README still contains the superseded security claim `{stale}`"
        );
    }
}

/// Ship-blocking: the preset an integrator gets by default must clear the
/// documented floor. This duplicates a unit test on purpose — it is the one
/// invariant whose regression would be silently shipped.
#[test]
fn default_preset_clears_the_documented_security_floor() {
    let bits = ProofOptions::default().security_level();
    assert!(
        bits >= MIN_ACCEPTABLE_SECURITY_BITS,
        "default preset reports {bits} bits, below the documented \
         {MIN_ACCEPTABLE_SECURITY_BITS}-bit floor"
    );
}

/// The permutation is canonical Rescue-Prime (Rescue-XLIX). The docs must say so
/// and must not describe the retired non-standard variant, so that a regression
/// to the old round ordering (or stale wording) is caught here.
#[test]
fn docs_describe_canonical_rescue_prime() {
    let soundness = read_doc("docs/SOUNDNESS.md");
    assert!(
        soundness.contains("canonical Rescue-Prime"),
        "docs/SOUNDNESS.md must state the permutation is canonical Rescue-Prime"
    );
    assert!(
        !soundness.contains("Rescue variant"),
        "docs/SOUNDNESS.md still calls the permutation a variant; it is now canonical"
    );
}

/// `security_level()` assumes a trace of [`ASSUMED_MAX_TRACE_LENGTH`] rows so
/// that its no-argument estimate is a *lower* bound on the real level. That is
/// only true while no AIR in the workspace can produce a longer trace.
///
/// The largest trace here is a full 128-event batch. If `MAX_BATCH_SIZE` or the
/// per-event row counts grow past the assumption, the reported security number
/// silently becomes an overstatement — so the relationship is asserted rather
/// than left as a comment.
#[test]
fn assumed_max_trace_length_bounds_every_real_trace() {
    use ves_stark_batch::air::trace_layout::{calculate_trace_length, MAX_BATCH_SIZE};

    let largest = calculate_trace_length(MAX_BATCH_SIZE);
    assert!(
        largest <= ASSUMED_MAX_TRACE_LENGTH,
        "the largest batch trace is {largest} rows, exceeding the \
         ASSUMED_MAX_TRACE_LENGTH of {ASSUMED_MAX_TRACE_LENGTH} that \
         `security_level()` assumes — the reported security level would be an \
         overstatement. Raise ASSUMED_MAX_TRACE_LENGTH."
    );

    // Sanity: the assumption should not be so loose it is meaningless.
    assert!(
        largest * 128 >= ASSUMED_MAX_TRACE_LENGTH,
        "ASSUMED_MAX_TRACE_LENGTH ({ASSUMED_MAX_TRACE_LENGTH}) is more than 128x \
         the largest real trace ({largest}); the no-argument estimate is \
         needlessly pessimistic"
    );
}
