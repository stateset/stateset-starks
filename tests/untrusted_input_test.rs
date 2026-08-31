//! Untrusted-input robustness for the verification entry points.
//!
//! `docs/VERIFICATION.md` §11 claims the untrusted-input surfaces never panic —
//! they return `Ok`/`Err`. That claim covers a real trust boundary: a
//! verification service accepts proof bytes from anyone, and a panic there is a
//! denial of service rather than a rejected proof.
//!
//! The inputs below came from `cargo +nightly fuzz run
//! fuzz_proof_deserialization`, which found two distinct upstream defects
//! within a minute. Both are recorded in `docs/THREAT_MODEL.md`.
//!
//! 1. **Integer overflow (contained).** `winter-air-0.10.3`
//!    `src/air/trace_info.rs:311` validates only the *lower* bound of the log2
//!    trace-length byte, then evaluates `2_usize.pow(n)` for an `n` read from
//!    the input, so any byte >= 64 overflows. Eleven bytes suffice. The
//!    verifiers now wrap deserialization in
//!    `ves_stark_primitives::panic_guard::guard_untrusted`, turning the panic
//!    into a `DeserializationError`. These tests lock that in.
//!
//! 2. **Unbounded allocation (contained).** `winter-utils-0.10.2`
//!    `src/serde/byte_reader.rs:194` does `Vec::with_capacity(num_elements)`
//!    where `num_elements` is a length prefix never checked against the bytes
//!    remaining, so a 39-byte proof could request ~72 PB and abort the process.
//!    Both verifiers now parse through `bounded_reader::deserialize_bounded`,
//!    whose `read_many` rejects such a count before allocating.
//!
//! These are regression tests: they must keep passing under both
//! `overflow-checks` settings, so run them in debug (where the check is on) as
//! well as release.

use ves_stark_air::policy::Policy;
use ves_stark_primitives::public_inputs::{
    compute_policy_hash, CompliancePublicInputs, PolicyParams,
};
use ves_stark_verifier::verify_compliance_proof;

fn public_inputs_for(threshold: u64) -> CompliancePublicInputs {
    let params = PolicyParams::threshold(threshold);
    let policy_hash = compute_policy_hash("aml.threshold", &params)
        .expect("policy hash")
        .to_hex();
    CompliancePublicInputs {
        event_id: uuid::Uuid::nil(),
        tenant_id: uuid::Uuid::nil(),
        store_id: uuid::Uuid::nil(),
        sequence_number: 1,
        payload_kind: 1,
        payload_plain_hash: "0".repeat(64),
        payload_cipher_hash: "0".repeat(64),
        event_signing_hash: "0".repeat(64),
        policy_id: "aml.threshold".to_string(),
        policy_params: params,
        policy_hash,
        witness_commitment: None,
        authorization_receipt_hash: None,
        amount_binding_hash: None,
    }
}

fn verify_bytes(bytes: &[u8], threshold: u64) -> Result<bool, String> {
    let public_inputs = public_inputs_for(threshold);
    let policy = Policy::aml_threshold(threshold);
    match verify_compliance_proof(bytes, &public_inputs, &policy, &[0u64; 4]) {
        Ok(result) => Ok(result.valid),
        Err(e) => Err(e.to_string()),
    }
}

/// The exact input `fuzz_proof_deserialization` crashed on.
///
/// Eleven bytes reach `TraceInfo::read_from`, where a trace width read straight
/// from the input is multiplied without a checked operation. This must be a
/// rejected proof, not a panic.
#[test]
fn fuzzer_crash_input_is_rejected_not_panicked_on() {
    let bytes = [89u8, 4, 255, 98, 255, 255, 255, 255, 255, 255, 43];
    let outcome = verify_bytes(&bytes, 18_374_967_952_014_311_423);
    assert!(
        matches!(outcome, Err(_) | Ok(false)),
        "malformed proof bytes must be rejected, got {outcome:?}"
    );
}

/// Structurally similar inputs around the same code path.
#[test]
fn malformed_headers_are_rejected_not_panicked_on() {
    let cases: [&[u8]; 8] = [
        &[],
        &[0xff],
        &[0xff; 11],
        &[89, 4, 255, 98, 255, 255, 255, 255, 255, 255, 43, 0],
        &[89, 4, 255, 98],
        &[0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        &[0xff, 0xff, 0xff, 0xff, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f],
        &[
            0x59, 0x04, 0xff, 0x62, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2b,
        ],
    ];
    for (i, bytes) in cases.iter().enumerate() {
        let outcome = verify_bytes(bytes, u64::MAX);
        assert!(
            matches!(outcome, Err(_) | Ok(false)),
            "case {i} ({bytes:?}) must be rejected, got {outcome:?}"
        );
    }
}

/// Every byte length up to a small bound, filled with the byte values most
/// likely to drive a length or width field to its maximum.
#[test]
fn no_short_input_of_any_length_panics() {
    for fill in [0x00u8, 0x01, 0x7f, 0x80, 0xfe, 0xff] {
        for len in 0..64usize {
            let bytes = vec![fill; len];
            let outcome = verify_bytes(&bytes, u64::MAX);
            assert!(
                matches!(outcome, Err(_) | Ok(false)),
                "fill {fill:#04x} len {len} must be rejected, got {outcome:?}"
            );
        }
    }
}

/// The threshold is caller-supplied and reaches limit arithmetic
/// (`aml.threshold` verifies against `threshold - 1`). Extremes must not panic.
#[test]
fn extreme_thresholds_do_not_panic() {
    let bytes = [89u8, 4, 255, 98, 255, 255, 255, 255, 255, 255, 43];
    for threshold in [0u64, 1, u64::MAX, u64::MAX - 1, 1 << 63] {
        let outcome = verify_bytes(&bytes, threshold);
        assert!(
            matches!(outcome, Err(_) | Ok(false)),
            "threshold {threshold} must be rejected, got {outcome:?}"
        );
    }
}

/// Second finding: a 39-byte proof drives an unbounded allocation.
///
/// `winter-utils`'s `read_many` calls `Vec::with_capacity(num_elements)` with a
/// length prefix taken straight from the input. Measured here: a request for
/// 72,057,607,577,400,833 bytes, which aborted the process with SIGABRT in both
/// debug and release — an abort that no `catch_unwind` can contain.
///
/// Fixed by `ves_stark_primitives::bounded_reader`, which overrides `read_many`
/// to reject any declared count larger than the bytes remaining. This test
/// once had to be `#[ignore]`d because it took the whole test binary down.
#[test]
fn oversized_declared_allocation_is_rejected_not_attempted() {
    let bytes = [
        246u8, 3, 39, 3, 0, 0, 1, 168, 1, 4, 1, 1, 8, 1, 3, 3, 39, 3, 0, 0, 1, 246, 3, 39, 3, 0, 0,
        1, 246, 3, 39, 3, 0, 0, 1, 168, 1, 4, 1,
    ];
    let outcome = verify_bytes(&bytes, 18_374_393_966_444_478_721);
    assert!(
        matches!(outcome, Err(_) | Ok(false)),
        "a proof declaring an impossible trace size must be rejected, got {outcome:?}"
    );
}
