//! Criterion benchmark for batch proof verification.
//!
//! Pairs with the existing `bench_*` test in `ves-stark-prover` which measures prove
//! time only. This bench measures the verify side of the batch AIR with µs precision
//! across a few representative batch sizes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use uuid::Uuid;
use winter_verifier::AcceptableOptions;

use ves_stark_air::options::ProofOptions;
use ves_stark_batch::{
    BatchMetadata, BatchPolicyKind, BatchProver, BatchProverConfig, BatchPublicInputs,
    BatchVerifier, BatchWitnessBuilder,
};
use ves_stark_primitives::hash_to_felts;
use ves_stark_primitives::public_inputs::{
    compute_policy_hash, witness_commitment_u64_to_hex, CompliancePublicInputs, PolicyParams,
};
use ves_stark_primitives::{felt_from_u64, rescue::rescue_hash, Felt};

fn sample_event_inputs(
    threshold: u64,
    amount: u64,
    sequence_number: u64,
    tenant_id: Uuid,
    store_id: Uuid,
) -> CompliancePublicInputs {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(threshold);
    let hash = compute_policy_hash(policy_id, &params).unwrap();
    let amount_limbs = [
        felt_from_u64(amount & 0xFFFFFFFF),
        felt_from_u64(amount >> 32),
        felt_from_u64(0),
        felt_from_u64(0),
        felt_from_u64(0),
        felt_from_u64(0),
        felt_from_u64(0),
        felt_from_u64(0),
    ];
    let commitment = rescue_hash(&amount_limbs);

    CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id,
        store_id,
        sequence_number,
        payload_kind: 1,
        payload_plain_hash: "0".repeat(64),
        payload_cipher_hash: "0".repeat(64),
        event_signing_hash: "0".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
        witness_commitment: Some(witness_commitment_u64_to_hex(&[
            commitment[0].as_int(),
            commitment[1].as_int(),
            commitment[2].as_int(),
            commitment[3].as_int(),
        ])),
        authorization_receipt_hash: None,
        amount_binding_hash: None,
    }
}

fn sample_policy_hash(threshold: u64) -> [Felt; 8] {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(threshold);
    let hash = compute_policy_hash(policy_id, &params).unwrap();
    hash_to_felts(&hash)
}

fn build_batch_proof(num_events: usize) -> (Vec<u8>, BatchPublicInputs) {
    let threshold = 10_000u64;
    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let metadata = BatchMetadata::with_ids(
        Uuid::new_v4(),
        tenant_id,
        store_id,
        0,
        (num_events as u64).saturating_sub(1),
    );

    let mut builder = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(sample_policy_hash(threshold))
        .policy_limit(threshold);

    for i in 0..num_events {
        let amount = 5_000 + i as u64;
        builder = builder
            .add_event(
                amount,
                sample_event_inputs(threshold, amount, i as u64, tenant_id, store_id),
            )
            .unwrap();
    }

    let witness = builder.build().unwrap();

    let prover = BatchProver::with_config(
        BatchProverConfig::default().with_options(ProofOptions::fast()),
    );
    let proof = prover.prove(&witness).unwrap();
    let public_inputs = BatchPublicInputs::new(
        witness.prev_state_root.root,
        witness.compute_new_state_root().unwrap().root,
        witness.batch_id_felts(),
        witness.tenant_id_felts(),
        witness.store_id_felts(),
        witness.metadata.sequence_start,
        witness.metadata.sequence_end,
        witness.metadata.timestamp,
        witness.num_events(),
        witness.all_compliant(),
        BatchPolicyKind::AmlThreshold,
        witness.policy_limit,
        witness.public_inputs_accumulator().unwrap(),
    );

    (proof.proof_bytes, public_inputs)
}

fn fast_verifier() -> BatchVerifier {
    BatchVerifier::with_options(AcceptableOptions::OptionSet(vec![ProofOptions::fast()
        .try_to_winterfell()
        .unwrap()]))
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verify");
    group.sample_size(20);

    for num_events in [1usize, 4, 16] {
        let (proof_bytes, public_inputs) = build_batch_proof(num_events);
        let verifier = fast_verifier();

        group.bench_with_input(
            BenchmarkId::new("events", num_events),
            &(proof_bytes, public_inputs),
            |b, (bytes, inputs)| {
                b.iter(|| {
                    let result = verifier
                        .verify(black_box(bytes), black_box(inputs))
                        .expect("verification call failed");
                    assert!(result.valid);
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_batch_verify);
criterion_main!(benches);
