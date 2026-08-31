//! End-to-end tests for the salted witness commitment scheme.
//!
//! The salted commitment closes the hiding gap of the legacy scheme: an
//! unsalted commitment is a deterministic Rescue hash of the amount alone,
//! so a verifier holding the published commitment can confirm a guessed
//! amount by hashing candidates (dollar amounts are low-entropy). A salted
//! commitment binds (amount, salt) with a random 128-bit salt in the sponge
//! limbs the unsalted scheme leaves zero — same circuit, hiding commitment.

use uuid::Uuid;
use ves_stark_primitives::payload_amount::{
    amount_witness_commitment, amount_witness_commitment_salted,
};
use ves_stark_primitives::public_inputs::{
    compute_policy_hash, CompliancePublicInputs, PolicyParams,
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};
use ves_stark_verifier::verify_compliance_proof;

fn cap_inputs(cap: u64) -> CompliancePublicInputs {
    let policy_id = "order_total.cap";
    let params = PolicyParams::cap(cap);
    let hash = compute_policy_hash(policy_id, &params).unwrap();
    CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        sequence_number: 1,
        payload_kind: 1,
        payload_plain_hash: "a".repeat(64),
        payload_cipher_hash: "b".repeat(64),
        event_signing_hash: "c".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
        witness_commitment: None,
        authorization_receipt_hash: None,
        amount_binding_hash: None,
        rest_hash: None,
    }
}

#[test]
fn a_salted_proof_proves_and_verifies_end_to_end() {
    let cap = 100_000;
    let amount = 62_000;
    let witness = ComplianceWitness::new_salted(amount, cap_inputs(cap));
    let commitment_hex = witness.public_inputs.witness_commitment.clone().unwrap();

    let proof = ComplianceProver::with_policy(Policy::order_total_cap(cap))
        .prove(&witness)
        .expect("salted witness must prove");

    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &witness.public_inputs,
        &Policy::order_total_cap(cap),
        &proof.witness_commitment,
    )
    .expect("verification must run");
    assert!(result.valid, "salted proof must verify");

    // The published commitment is the salted one the witness was bound to.
    assert_eq!(
        ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex(
            &proof.witness_commitment
        ),
        commitment_hex
    );
}

#[test]
fn a_salted_commitment_defeats_guess_confirmation() {
    let amount = 62_000;
    let witness = ComplianceWitness::new_salted(amount, cap_inputs(100_000));
    let salted = witness.public_inputs.witness_commitment.clone().unwrap();

    // The dictionary attack against the unsalted scheme: hash every plausible
    // amount and compare against the published commitment. Against a salted
    // commitment it confirms nothing — not even the true amount matches.
    let unsalted_of_true_amount =
        ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex(
            &amount_witness_commitment(amount),
        );
    assert_ne!(
        salted, unsalted_of_true_amount,
        "the salted commitment must not equal the unsalted hash of the amount"
    );
    for guess in (0..200_000).step_by(500) {
        let candidate = ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex(
            &amount_witness_commitment(guess),
        );
        assert_ne!(salted, candidate, "guess {guess} must not be confirmable");
    }
}

#[test]
fn different_salts_give_unlinkable_commitments_for_the_same_amount() {
    let amount = 62_000;
    let w1 = ComplianceWitness::new_salted(amount, cap_inputs(100_000));
    let w2 = ComplianceWitness::new_salted(amount, cap_inputs(100_000));
    assert_ne!(
        w1.public_inputs.witness_commitment, w2.public_inputs.witness_commitment,
        "two commitments to the same amount must be unlinkable"
    );
}

#[test]
fn zero_salt_reproduces_the_legacy_commitment_exactly() {
    for amount in [0u64, 1, 62_000, u32::MAX as u64, u64::MAX] {
        assert_eq!(
            amount_witness_commitment(amount),
            amount_witness_commitment_salted(amount, &[0u32; 4]),
        );
    }
    // And a legacy (unsalted) witness still proves and verifies.
    let cap = 100_000;
    let witness = ComplianceWitness::new(62_000, cap_inputs(cap));
    let proof = ComplianceProver::with_policy(Policy::order_total_cap(cap))
        .prove(&witness)
        .expect("legacy witness must still prove");
    let result = verify_compliance_proof(
        &proof.proof_bytes,
        &witness.public_inputs,
        &Policy::order_total_cap(cap),
        &proof.witness_commitment,
    )
    .expect("verification must run");
    assert!(result.valid, "legacy zero-salt proof must still verify");
}

#[test]
fn a_salted_over_cap_amount_still_cannot_be_proven() {
    let cap = 100_000;
    let result = std::panic::catch_unwind(|| {
        let witness = ComplianceWitness::new_salted(150_000, cap_inputs(cap));
        ComplianceProver::with_policy(Policy::order_total_cap(cap)).prove(&witness)
    });
    // Sound outcomes are: the prover returned an error, or it panicked (caught
    // here). Anything else means an over-cap amount produced a proof.
    if let Ok(Ok(_)) = result {
        panic!("an over-cap amount must not produce a proof, salted or not");
    }
}

#[test]
fn a_salted_proof_rejects_a_mismatched_commitment() {
    let cap = 100_000;
    let witness = ComplianceWitness::new_salted(62_000, cap_inputs(cap));
    let proof = ComplianceProver::with_policy(Policy::order_total_cap(cap))
        .prove(&witness)
        .expect("prove");

    // A different salted commitment to the same amount must not verify this proof.
    let other = ComplianceWitness::new_salted(62_000, cap_inputs(cap));
    let mut other_inputs = witness.public_inputs.clone();
    other_inputs.witness_commitment = other.public_inputs.witness_commitment.clone();
    let other_commitment = ves_stark_primitives::public_inputs::witness_commitment_hex_to_u64(
        other.public_inputs.witness_commitment.as_deref().unwrap(),
    )
    .unwrap();

    let outcome = verify_compliance_proof(
        &proof.proof_bytes,
        &other_inputs,
        &Policy::order_total_cap(cap),
        &other_commitment,
    );
    let rejected = match outcome {
        Ok(r) => !r.valid,
        Err(_) => true,
    };
    assert!(
        rejected,
        "a proof must be bound to its own salted commitment"
    );
}
