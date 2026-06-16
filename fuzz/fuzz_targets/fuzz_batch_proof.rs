//! Fuzz target for batch-proof deserialization and verification.
//!
//! The batch path is the most complex untrusted-input surface in the system and
//! is reached directly by the `ves_batch_verify_json` FFI entry point. This target
//! ensures:
//! 1. `SerializableBatchProof::from_json` never panics on arbitrary input.
//! 2. `verify_batch_proof` never panics on arbitrary proof bytes / public inputs
//!    (it must always return `Ok(invalid)` or `Err`, never crash the host).

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ves_stark_batch::{
    verify_batch_proof, BatchPolicyKind, BatchPublicInputs, SerializableBatchProof,
};
use ves_stark_primitives::felt_from_u64;

#[derive(Debug, Arbitrary)]
struct BatchInput {
    /// Raw bytes interpreted (lossily) as a JSON document for `from_json`.
    json_bytes: Vec<u8>,
    /// Raw bytes tried as a serialized proof.
    proof_bytes: Vec<u8>,
    prev_state_root: [u64; 4],
    new_state_root: [u64; 4],
    batch_id: [u64; 4],
    tenant_id: [u64; 4],
    store_id: [u64; 4],
    sequence_start: u64,
    sequence_end: u64,
    timestamp: u64,
    // Bounded so a pathological count never drives a huge allocation; the verifier
    // rejects anything over MAX_BATCH_SIZE long before allocating regardless.
    num_events: u16,
    all_compliant: bool,
    policy_kind_aml: bool,
    policy_limit: u64,
    accumulator: [u64; 8],
}

fuzz_target!(|input: BatchInput| {
    // 1) JSON deserialization must never panic on arbitrary input.
    let json = String::from_utf8_lossy(&input.json_bytes);
    let _ = SerializableBatchProof::from_json(&json);

    // 2) Verification must never panic on arbitrary proof bytes / public inputs.
    let proof_bytes: Vec<u8> = input.proof_bytes.into_iter().take(10_000).collect();
    let to_felts4 = |a: [u64; 4]| a.map(felt_from_u64);
    let policy_kind = if input.policy_kind_aml {
        BatchPolicyKind::AmlThreshold
    } else {
        BatchPolicyKind::OrderTotalCap
    };
    let public_inputs = BatchPublicInputs::new(
        to_felts4(input.prev_state_root),
        to_felts4(input.new_state_root),
        to_felts4(input.batch_id),
        to_felts4(input.tenant_id),
        to_felts4(input.store_id),
        input.sequence_start,
        input.sequence_end,
        input.timestamp,
        input.num_events as usize,
        input.all_compliant,
        policy_kind,
        input.policy_limit,
        input.accumulator.map(felt_from_u64),
    );
    let _ = verify_batch_proof(&proof_bytes, &public_inputs);
});
