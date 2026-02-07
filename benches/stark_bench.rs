//! # VES STARK Benchmarks
//!
//! Comprehensive performance benchmarks for the VES STARK proving system.
//!
//! ## Running Benchmarks
//!
//! ```bash
//! # Run all benchmarks
//! cargo bench
//!
//! # Run specific benchmark group
//! cargo bench -- proof_generation
//!
//! # Run with baseline comparison
//! cargo bench -- --save-baseline main
//! cargo bench -- --baseline main
//!
//! # Generate HTML report
//! cargo bench -- --verbose
//! # Open target/criterion/report/index.html
//! ```
//!
//! ## Benchmark Categories
//!
//! 1. **proof_generation**: Time to generate STARK proofs
//! 2. **verification**: Time to verify proofs
//! 3. **end_to_end**: Complete prove + verify cycle
//! 4. **witness_creation**: Witness generation overhead
//! 5. **rescue_hash**: Cryptographic hash performance
//! 6. **serialization**: Proof serialization/deserialization
//! 7. **policy_comparison**: AML threshold vs Order total cap
//!
//! ## Performance Targets
//!
//! | Operation | Target | Notes |
//! |-----------|--------|-------|
//! | Proof generation | < 500ms | For typical thresholds |
//! | Verification | < 10ms | Must be fast for batch processing |
//! | Witness creation | < 1ms | Negligible overhead |
//! | Serialization | < 1ms | For network transmission |

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use uuid::Uuid;

use ves_stark_primitives::felt_from_u64;
use ves_stark_primitives::public_inputs::{
    compute_policy_hash, CompliancePublicInputs, PolicyParams,
};
use ves_stark_primitives::rescue::{rescue_hash, rescue_hash_pair};
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};
use ves_stark_verifier::verify_compliance_proof;

/// Create sample public inputs for AML threshold policy
fn sample_aml_inputs(threshold: u64) -> CompliancePublicInputs {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(threshold);
    let hash = compute_policy_hash(policy_id, &params).unwrap();

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
        witness_commitment: None,
    }
}

/// Create sample public inputs for order total cap policy
fn sample_cap_inputs(cap: u64) -> CompliancePublicInputs {
    let policy_id = "order_total.cap";
    let params = PolicyParams::cap(cap);
    let hash = compute_policy_hash(policy_id, &params).unwrap();

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
        witness_commitment: None,
    }
}

// Legacy alias
fn sample_inputs(threshold: u64) -> CompliancePublicInputs {
    sample_aml_inputs(threshold)
}

// =============================================================================
// Proof Generation Benchmarks
// =============================================================================

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation");
    group.sample_size(10); // STARK proofs are slow, reduce sample size

    // Test with different threshold values
    for threshold in [1_000u64, 10_000, 100_000, 1_000_000].iter() {
        let policy = Policy::aml_threshold(*threshold);
        let prover = ComplianceProver::with_policy(policy);
        let amount = threshold / 2; // Amount is half the threshold
        let inputs = sample_inputs(*threshold);
        let witness = ComplianceWitness::new(amount, inputs);

        group.bench_with_input(
            BenchmarkId::new("aml_threshold", threshold),
            threshold,
            |b, _| {
                b.iter(|| {
                    prover
                        .prove(black_box(&witness))
                        .expect("proof generation failed")
                })
            },
        );
    }

    group.finish();
}

fn bench_proof_generation_by_amount(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation_by_amount");
    group.sample_size(10);

    let threshold = 1_000_000_000u64; // 1 billion

    // Test with different amount values (relative to threshold)
    for (label, amount) in [
        ("zero", 0u64),
        ("tiny", 1),
        ("small", threshold / 1000),
        ("medium", threshold / 2),
        ("large", threshold - 1),
    ] {
        let policy = Policy::aml_threshold(threshold);
        let prover = ComplianceProver::with_policy(policy);
        let inputs = sample_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs);

        group.bench_with_input(BenchmarkId::new("amount", label), &amount, |b, _| {
            b.iter(|| {
                prover
                    .prove(black_box(&witness))
                    .expect("proof generation failed")
            })
        });
    }

    group.finish();
}

// =============================================================================
// Verification Benchmarks
// =============================================================================

fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification");

    // Pre-generate proofs for verification benchmarks
    for threshold in [1_000u64, 10_000, 100_000].iter() {
        let policy = Policy::aml_threshold(*threshold);
        let prover = ComplianceProver::with_policy(policy.clone());
        let amount = threshold / 2;
        let inputs = sample_inputs(*threshold);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let proof = prover.prove(&witness).expect("proof generation failed");

        group.throughput(Throughput::Bytes(proof.proof_bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("threshold", threshold),
            &(
                proof.proof_bytes.clone(),
                proof.witness_commitment,
                inputs,
                policy,
            ),
            |b, (proof_bytes, commitment, inputs, policy)| {
                b.iter(|| {
                    verify_compliance_proof(
                        black_box(proof_bytes),
                        black_box(inputs),
                        black_box(policy),
                        black_box(commitment),
                    )
                    .expect("verification failed")
                })
            },
        );
    }

    group.finish();
}

// =============================================================================
// End-to-End Benchmarks
// =============================================================================

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(10);

    let threshold = 10_000u64;
    let policy = Policy::aml_threshold(threshold);
    let prover = ComplianceProver::with_policy(policy.clone());

    group.bench_function("prove_and_verify", |b| {
        b.iter(|| {
            let amount = 5000;
            let inputs = sample_inputs(threshold);
            let witness = ComplianceWitness::new(amount, inputs.clone());

            let proof = prover.prove(&witness).expect("proof generation failed");
            verify_compliance_proof(
                &proof.proof_bytes,
                &inputs,
                &policy,
                &proof.witness_commitment,
            )
            .expect("verification failed")
        })
    });

    group.finish();
}

// =============================================================================
// Witness Creation Benchmarks
// =============================================================================

fn bench_witness_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("witness_creation");

    let threshold = 10_000u64;
    let inputs = sample_inputs(threshold);

    group.bench_function("new_witness", |b| {
        b.iter(|| ComplianceWitness::new(black_box(5000), black_box(inputs.clone())))
    });

    // Benchmark witness validation
    let witness = ComplianceWitness::new(5000, inputs.clone());
    let policy = Policy::aml_threshold(threshold);
    group.bench_function("validate_witness", |b| {
        b.iter(|| {
            witness
                .validate(black_box(&policy))
                .expect("validation failed")
        })
    });

    group.finish();
}

// =============================================================================
// Rescue Hash Benchmarks
// =============================================================================

fn bench_rescue_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("rescue_hash");

    // Hash single element
    let single_input = vec![felt_from_u64(12345)];
    group.bench_function("single_element", |b| {
        b.iter(|| rescue_hash(black_box(&single_input)))
    });

    // Hash 8 elements (full rate)
    let rate_input: Vec<_> = (0u64..8).map(felt_from_u64).collect();
    group.bench_function("full_rate_8", |b| {
        b.iter(|| rescue_hash(black_box(&rate_input)))
    });

    // Hash 16 elements (2x rate, requires 2 absorb rounds)
    let double_rate: Vec<_> = (0u64..16).map(felt_from_u64).collect();
    group.bench_function("double_rate_16", |b| {
        b.iter(|| rescue_hash(black_box(&double_rate)))
    });

    // Hash pair (for Merkle tree)
    let left = [
        felt_from_u64(1),
        felt_from_u64(2),
        felt_from_u64(3),
        felt_from_u64(4),
    ];
    let right = [
        felt_from_u64(5),
        felt_from_u64(6),
        felt_from_u64(7),
        felt_from_u64(8),
    ];
    group.bench_function("hash_pair", |b| {
        b.iter(|| rescue_hash_pair(black_box(&left), black_box(&right)))
    });

    group.finish();
}

// =============================================================================
// Serialization Benchmarks
// =============================================================================

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    // Generate a proof to serialize
    let threshold = 10_000u64;
    let policy = Policy::aml_threshold(threshold);
    let prover = ComplianceProver::with_policy(policy);
    let inputs = sample_inputs(threshold);
    let witness = ComplianceWitness::new(5000, inputs.clone());
    let proof = prover.prove(&witness).expect("proof generation failed");

    group.throughput(Throughput::Bytes(proof.proof_bytes.len() as u64));

    // Benchmark proof serialization to JSON
    group.bench_function("proof_to_json", |b| {
        b.iter(|| serde_json::to_string(black_box(&proof)).expect("serialization failed"))
    });

    let json = serde_json::to_string(&proof).expect("serialization failed");
    group.bench_function("proof_from_json", |b| {
        b.iter(|| {
            serde_json::from_str::<ves_stark_prover::ComplianceProof>(black_box(&json))
                .expect("deserialization failed")
        })
    });

    // Benchmark public inputs serialization
    group.bench_function("inputs_to_json", |b| {
        b.iter(|| serde_json::to_string(black_box(&inputs)).expect("serialization failed"))
    });

    let inputs_json = serde_json::to_string(&inputs).expect("serialization failed");
    group.bench_function("inputs_from_json", |b| {
        b.iter(|| {
            serde_json::from_str::<CompliancePublicInputs>(black_box(&inputs_json))
                .expect("deserialization failed")
        })
    });

    group.finish();
}

// =============================================================================
// Policy Comparison Benchmarks
// =============================================================================

fn bench_policy_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_comparison");
    group.sample_size(10);

    let limit = 10_000u64;
    let amount = 5_000u64;

    // AML Threshold policy (amount < threshold)
    let aml_inputs = sample_aml_inputs(limit);
    let aml_witness = ComplianceWitness::new(amount, aml_inputs);
    let aml_policy = Policy::aml_threshold(limit);
    let aml_prover = ComplianceProver::with_policy(aml_policy);

    group.bench_function("aml_threshold_prove", |b| {
        b.iter(|| {
            aml_prover
                .prove(black_box(&aml_witness))
                .expect("proof failed")
        })
    });

    // Order Total Cap policy (amount <= cap)
    let cap_inputs = sample_cap_inputs(limit);
    let cap_witness = ComplianceWitness::new(amount, cap_inputs);
    let cap_policy = Policy::order_total_cap(limit);
    let cap_prover = ComplianceProver::with_policy(cap_policy);

    group.bench_function("order_total_cap_prove", |b| {
        b.iter(|| {
            cap_prover
                .prove(black_box(&cap_witness))
                .expect("proof failed")
        })
    });

    // Boundary case: amount == limit (only cap policy should succeed)
    let boundary_cap_inputs = sample_cap_inputs(limit);
    let boundary_witness = ComplianceWitness::new(limit, boundary_cap_inputs);

    group.bench_function("boundary_cap_prove", |b| {
        b.iter(|| {
            cap_prover
                .prove(black_box(&boundary_witness))
                .expect("proof failed")
        })
    });

    group.finish();
}

// =============================================================================
// Criterion Groups
// =============================================================================

criterion_group!(
    benches,
    bench_proof_generation,
    bench_proof_generation_by_amount,
    bench_verification,
    bench_end_to_end,
    bench_witness_creation,
    bench_rescue_hash,
    bench_serialization,
    bench_policy_comparison,
);

criterion_main!(benches);
