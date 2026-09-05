use uuid::Uuid;
use ves_stark_batch::{
    verify_batch_with_event_proofs, BatchMetadata, BatchPolicyKind, BatchProver, BatchPublicInputs,
    BatchWitnessBuilder,
};
use ves_stark_primitives::{
    hash_to_felts,
    payload_amount::amount_witness_commitment,
    payload_v2::payload_plain_hash_v2,
    privacy::ProofPrivacy,
    public_inputs::{compute_policy_hash, CompliancePublicInputs, PolicyParams},
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};

#[test]
fn batch_v2_composition_binds_expected_events_and_proven_commitments() {
    let tenant = Uuid::new_v4();
    let store = Uuid::new_v4();
    let params = PolicyParams::cap(1000);
    let policy_hash = compute_policy_hash("order_total.cap", &params).unwrap();
    let metadata = BatchMetadata::new(Uuid::new_v4(), tenant, store, 0, 1, 100);
    let mut builder = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_limit(1000)
        .policy_hash(hash_to_felts(&policy_hash));
    let mut inputs = Vec::new();
    let mut proofs = Vec::new();
    for (seq, amount) in [100, 200].into_iter().enumerate() {
        let public_inputs: CompliancePublicInputs = serde_json::from_value(serde_json::json!({
            "eventId": Uuid::new_v4(), "tenantId": tenant, "storeId": store,
            "sequenceNumber": seq, "payloadKind": 2,
            "payloadPlainHash": payload_plain_hash_v2(&amount_witness_commitment(amount), &[0x11;32]).to_hex(),
            "payloadCipherHash": "0".repeat(64), "eventSigningHash": "0".repeat(64),
            "policyId": "order_total.cap", "policyParams": params, "policyHash": policy_hash.to_hex(),
            "restHash": "11".repeat(32)
        })).unwrap();
        let witness = ComplianceWitness::try_new(amount, public_inputs).unwrap();
        let proof = ComplianceProver::with_policy(Policy::order_total_cap(1000))
            .prove(&witness)
            .unwrap();
        builder = builder
            .add_event(amount, witness.public_inputs.clone())
            .unwrap();
        inputs.push(witness.public_inputs.clone());
        proofs.push(proof.proof_bytes);
    }
    let witness = builder.build().unwrap();
    let batch = BatchProver::new().prove(&witness).unwrap();
    let public = BatchPublicInputs::new(
        witness.prev_state_root.root,
        witness.compute_new_state_root().unwrap().root,
        witness.batch_id_felts(),
        witness.tenant_id_felts(),
        witness.store_id_felts(),
        0,
        1,
        100,
        2,
        true,
        BatchPolicyKind::OrderTotalCap,
        1000,
        witness.public_inputs_accumulator().unwrap(),
    );
    let verify = |p: &BatchPublicInputs, i: &[CompliancePublicInputs], b: &[Vec<u8>]| {
        verify_batch_with_event_proofs(&batch.proof_bytes, p, i, b, ProofPrivacy::AllowDisclosure)
    };
    let result = verify(&public, &inputs, &proofs).unwrap();
    assert!(result.valid && result.payload_binding_verified);
    assert!(
        !ves_stark_batch::verify_batch_proof(&batch.proof_bytes, &public)
            .unwrap()
            .payload_binding_verified
    );
    assert!(verify_batch_with_event_proofs(
        &batch.proof_bytes,
        &public,
        &inputs,
        &proofs,
        ProofPrivacy::Confidential
    )
    .is_err());
    assert!(verify(&public, &inputs, &proofs[..1]).is_err());
    let mut changed = proofs.clone();
    changed.swap(0, 1);
    assert!(verify(&public, &inputs, &changed).is_err());
    let mut changed = inputs.clone();
    changed[0].payload_kind = 1;
    assert!(verify(&public, &changed, &proofs).is_err());
    let mut changed = inputs.clone();
    changed[0].payload_plain_hash = "0".repeat(64);
    assert!(verify(&public, &changed, &proofs).is_err());
    let mut changed = public.clone();
    changed.new_state_root[0] += ves_stark_primitives::FELT_ONE;
    assert!(verify(&changed, &inputs, &proofs).is_err());
    let mut changed = public.clone();
    changed.public_inputs_accumulator[0] += ves_stark_primitives::FELT_ONE;
    assert!(verify(&changed, &inputs, &proofs).is_err());
}
