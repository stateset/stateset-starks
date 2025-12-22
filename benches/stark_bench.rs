//! VES STARK benchmarks using Criterion
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use uuid::Uuid;

use ves_stark_air::policies::aml_threshold::AmlThresholdPolicy;
use ves_stark_primitives::public_inputs::{
    CompliancePublicInputs, PolicyParams, compute_policy_hash,
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_verifier::verify_compliance_proof;

fn sample_inputs(threshold: u64) -> CompliancePublicInputs {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(threshold);
    let hash = compute_policy_hash(policy_id, &params);

    CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        sequence_number: 1,
        payload_kind: 1,
        payload_plain_hash: "0".repeat(64),
        payload_cipher_hash: "0".repeat(64),
        event_signing_hash: "0".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
    }
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation");

    // Test with different threshold values
    for threshold in [1_000u64, 10_000, 100_000, 1_000_000].iter() {
        let policy = AmlThresholdPolicy::new(*threshold);
        let prover = ComplianceProver::new(policy);
        let amount = threshold / 2; // Amount is half the threshold
        let inputs = sample_inputs(*threshold);
        let witness = ComplianceWitness::new(amount, inputs);

        group.bench_with_input(
            BenchmarkId::new("threshold", threshold),
            threshold,
            |b, _| {
                b.iter(|| {
                    prover.prove(black_box(&witness)).expect("proof generation failed")
                })
            },
        );
    }

    group.finish();
}

fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification");

    // Pre-generate proofs for verification benchmarks
    for threshold in [1_000u64, 10_000, 100_000].iter() {
        let policy = AmlThresholdPolicy::new(*threshold);
        let prover = ComplianceProver::new(policy.clone());
        let amount = threshold / 2;
        let inputs = sample_inputs(*threshold);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let proof = prover.prove(&witness).expect("proof generation failed");

        group.throughput(Throughput::Bytes(proof.proof_bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("threshold", threshold),
            &(proof.proof_bytes, inputs, policy),
            |b, (proof_bytes, inputs, policy)| {
                b.iter(|| {
                    verify_compliance_proof(black_box(proof_bytes), black_box(inputs), black_box(policy))
                        .expect("verification failed")
                })
            },
        );
    }

    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");

    let threshold = 10_000u64;
    let policy = AmlThresholdPolicy::new(threshold);
    let prover = ComplianceProver::new(policy.clone());

    group.bench_function("prove_and_verify", |b| {
        b.iter(|| {
            let amount = 5000;
            let inputs = sample_inputs(threshold);
            let witness = ComplianceWitness::new(amount, inputs.clone());

            let proof = prover.prove(&witness).expect("proof generation failed");
            verify_compliance_proof(&proof.proof_bytes, &inputs, &policy)
                .expect("verification failed")
        })
    });

    group.finish();
}

fn bench_witness_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("witness_creation");

    let threshold = 10_000u64;
    let inputs = sample_inputs(threshold);

    group.bench_function("new_witness", |b| {
        b.iter(|| {
            ComplianceWitness::new(black_box(5000), black_box(inputs.clone()))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_proof_generation,
    bench_verification,
    bench_end_to_end,
    bench_witness_creation,
);

criterion_main!(benches);
