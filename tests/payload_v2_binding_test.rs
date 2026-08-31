//! `payload_kind == 2`: the proved amount is the amount on the event.
//!
//! The verifier recomputes `payload_plain_hash = SHA-256(domain ‖ C ‖ restHash)`
//! for the commitment `C` the proof was verified against. Because the AIR
//! already proves `C = Rescue(amount ‖ salt)`, this binds the proved amount to
//! the event with no circuit change. See `docs/AMOUNT_BINDING_DESIGN.md`.
//!
//! Order of operations mirrors production: the salt exists first, the
//! sequencer forms the hash from `C`, and only then is the proof made over
//! public inputs that carry that hash.

use ves_stark_air::policy::Policy;
use ves_stark_primitives::hash::Hash256;
use ves_stark_primitives::payload_amount::amount_witness_commitment_salted;
use ves_stark_primitives::payload_v2::{payload_plain_hash_v2, PAYLOAD_KIND_V2};
use ves_stark_primitives::public_inputs::{
    compute_policy_hash, CompliancePublicInputs, PolicyParams,
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_verifier::{verify_compliance_proof, ComplianceVerification, VerifierError};

const THRESHOLD: u64 = 10_000;
const AMOUNT: u64 = 4_242;
const SALT: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];

fn commitment(amount: u64, salt: &[u32; 4]) -> [u64; 4] {
    amount_witness_commitment_salted(amount, salt)
}

/// V2 public inputs whose `payload_plain_hash` commits to `c`.
fn v2_inputs(c: &[u64; 4], rest: &[u8; 32]) -> CompliancePublicInputs {
    let params = PolicyParams::threshold(THRESHOLD);
    let policy_hash = compute_policy_hash("aml.threshold", &params)
        .unwrap()
        .to_hex();
    CompliancePublicInputs {
        event_id: uuid::Uuid::from_u128(1),
        tenant_id: uuid::Uuid::from_u128(2),
        store_id: uuid::Uuid::from_u128(3),
        sequence_number: 1,
        payload_kind: PAYLOAD_KIND_V2,
        payload_plain_hash: payload_plain_hash_v2(c, rest).to_hex(),
        payload_cipher_hash: "0".repeat(64),
        event_signing_hash: "0".repeat(64),
        policy_id: "aml.threshold".into(),
        policy_params: params,
        policy_hash,
        witness_commitment: None,
        authorization_receipt_hash: None,
        amount_binding_hash: None,
        rest_hash: Some(Hash256::from_bytes(*rest).to_hex()),
    }
}

fn prove(inputs: &CompliancePublicInputs) -> (Vec<u8>, [u64; 4]) {
    let witness = ComplianceWitness::try_new_with_salt(AMOUNT, SALT, inputs.clone()).unwrap();
    let proof = ComplianceProver::with_policy(Policy::aml_threshold(THRESHOLD))
        .prove(&witness)
        .expect("proof");
    (proof.proof_bytes, proof.witness_commitment)
}

/// Honest V2 flow verifies, and the proof's commitment equals the one the
/// sequencer hashed — the two computations of `C` agree.
#[test]
fn test_v2_honest_event_verifies() {
    let rest = [0x11u8; 32];
    let c = commitment(AMOUNT, &SALT);
    let inputs = v2_inputs(&c, &rest);
    let (bytes, proof_c) = prove(&inputs);
    assert_eq!(proof_c, c, "native and prover commitments must agree");
    let r =
        verify_compliance_proof(&bytes, &inputs, &Policy::aml_threshold(THRESHOLD), &c).unwrap();
    assert!(r.valid);
}

/// The attack the design closes: a valid proof over a compliant amount,
/// presented with an event whose payload hash was formed from a *different*
/// commitment (i.e. a different amount). Rejected.
#[test]
fn test_commitment_not_in_payload_rejected() {
    let rest = [0x11u8; 32];
    let c_other = commitment(999_999, &SALT); // the amount actually on the order
    let inputs = v2_inputs(&c_other, &rest); // sequencer hashed the real amount
                                             // Prover proves a compliant amount whose commitment is NOT in the payload.
    let (bytes, c) = prove(&inputs);
    let err = verify_compliance_proof(&bytes, &inputs, &Policy::aml_threshold(THRESHOLD), &c)
        .unwrap_err();
    assert!(
        matches!(err, VerifierError::PayloadV2BindingMismatch(_)),
        "{err}"
    );
}

/// `restHash` swapped after the fact: the recomputed hash no longer matches.
#[test]
fn test_payload_hash_mismatch_rejected_v2() {
    let c = commitment(AMOUNT, &SALT);
    let inputs = v2_inputs(&c, &[0x11u8; 32]);
    let (bytes, _) = prove(&inputs);
    let mut tampered = inputs.clone();
    tampered.rest_hash = Some(Hash256::from_bytes([0x22u8; 32]).to_hex());
    let err = verify_compliance_proof(&bytes, &tampered, &Policy::aml_threshold(THRESHOLD), &c)
        .unwrap_err();
    // Either the proof rejects the changed public inputs, or the V2 binding does;
    // both are refusals. It must never verify.
    assert!(
        !matches!(err, VerifierError::PayloadAmountBindingRequired(_)),
        "{err}"
    );
}

/// `payload_kind == 2` without `restHash` cannot be verified at all.
#[test]
fn test_v2_requires_rest_hash() {
    let c = commitment(AMOUNT, &SALT);
    let mut inputs = v2_inputs(&c, &[0x11u8; 32]);
    inputs.rest_hash = None;
    let (bytes, _) = prove(&inputs);
    let err = verify_compliance_proof(&bytes, &inputs, &Policy::aml_threshold(THRESHOLD), &c)
        .unwrap_err();
    assert!(
        matches!(err, VerifierError::PayloadV2BindingMismatch(_)),
        "{err}"
    );
}

/// V1 events are untouched: the binding is a no-op for `payload_kind != 2`.
#[test]
fn test_v1_events_unaffected() {
    let c = commitment(AMOUNT, &SALT);
    let mut inputs = v2_inputs(&c, &[0x11u8; 32]);
    inputs.payload_kind = 1;
    inputs.payload_plain_hash = "0".repeat(64);
    inputs.rest_hash = None;
    let (bytes, _) = prove(&inputs);
    assert!(
        verify_compliance_proof(&bytes, &inputs, &Policy::aml_threshold(THRESHOLD), &c)
            .unwrap()
            .valid
    );
}

/// The builder's witness-only path still gets the V2 binding: it lives in the
/// core verifier, so no entry point can skip it for a kind-2 event.
#[test]
fn test_builder_witness_only_still_binds_v2() {
    let rest = [0x11u8; 32];
    let c_other = commitment(999_999, &SALT);
    let inputs = v2_inputs(&c_other, &rest);
    let (bytes, c) = prove(&inputs);
    let err = ComplianceVerification::new(&bytes, &inputs)
        .witness_commitment(&c)
        .strict()
        .run()
        .unwrap_err();
    assert!(
        matches!(err, VerifierError::PayloadV2BindingMismatch(_)),
        "{err}"
    );
}
