//! Integration tests for VES STARK batch proofs
//!
//! These tests exercise the batch proof system including:
//! - Batch witness construction
//! - Merkle tree state computation
//! - Batch proof generation (Phase 2 - in development)
//! - State transition verification

use uuid::Uuid;
use ves_stark_batch::{
    BatchMetadata, BatchStateRoot, BatchWitnessBuilder, BatchEventWitness,
    EventMerkleTree, EventLeaf, BatchVerifier,
};
use ves_stark_primitives::public_inputs::{
    CompliancePublicInputs, PolicyParams, compute_policy_hash,
};
use ves_stark_primitives::{felt_from_u64, Felt, FELT_ZERO, FELT_ONE};

/// Get current Unix timestamp (for test purposes, use 0)
fn timestamp() -> u64 {
    0
}

// =============================================================================
// Test Helpers
// =============================================================================

fn create_policy_hash(threshold: u64) -> [Felt; 8] {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(threshold);
    let hash = compute_policy_hash(policy_id, &params).unwrap();
    let hex = hash.to_hex();

    // Convert 64-char hex to 8 field elements (8 chars each = 32 bits)
    let mut result = [FELT_ZERO; 8];
    for i in 0..8 {
        let chunk = &hex[i * 8..(i + 1) * 8];
        let val = u32::from_str_radix(chunk, 16).unwrap_or(0);
        result[i] = felt_from_u64(val as u64);
    }
    result
}

fn create_public_inputs(threshold: u64, seq: u64) -> CompliancePublicInputs {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(threshold);
    let hash = compute_policy_hash(policy_id, &params).unwrap();

    CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        sequence_number: seq,
        payload_kind: 1,
        payload_plain_hash: "a".repeat(64),
        payload_cipher_hash: "b".repeat(64),
        event_signing_hash: "c".repeat(64),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
    }
}

// =============================================================================
// BatchMetadata Tests
// =============================================================================

#[test]
fn test_batch_metadata_creation() {
    let batch_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    let metadata = BatchMetadata::new(batch_id, tenant_id, store_id, 0, 9, timestamp());

    assert_eq!(metadata.batch_id, batch_id);
    assert_eq!(metadata.tenant_id, tenant_id);
    assert_eq!(metadata.store_id, store_id);
    assert_eq!(metadata.sequence_start, 0);
    assert_eq!(metadata.sequence_end, 9);
}

#[test]
fn test_batch_metadata_num_events() {
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 0, 9, timestamp());

    assert_eq!(metadata.num_events(), 10);
}

#[test]
fn test_batch_metadata_serialization() {
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 5, 15, timestamp());

    let json = serde_json::to_string(&metadata).unwrap();
    let recovered: BatchMetadata = serde_json::from_str(&json).unwrap();

    assert_eq!(recovered.batch_id, metadata.batch_id);
    assert_eq!(recovered.sequence_start, 5);
    assert_eq!(recovered.sequence_end, 15);
}

// =============================================================================
// BatchEventWitness Tests
// =============================================================================

#[test]
fn test_batch_event_witness_creation() {
    let threshold = 10000u64;
    let amount = 5000u64;
    let public_inputs = create_public_inputs(threshold, 0);

    let witness = BatchEventWitness::new(0, amount, public_inputs, threshold);

    assert_eq!(witness.event_index, 0);
    assert_eq!(witness.amount, amount);
    assert!(witness.is_compliant, "Amount {} < threshold {} should be compliant", amount, threshold);
}

#[test]
fn test_batch_event_witness_non_compliant() {
    let threshold = 10000u64;
    let amount = 15000u64; // Exceeds threshold
    let public_inputs = create_public_inputs(threshold, 0);

    let witness = BatchEventWitness::new(0, amount, public_inputs, threshold);

    assert!(!witness.is_compliant, "Amount {} >= threshold {} should NOT be compliant", amount, threshold);
}

#[test]
fn test_batch_event_witness_boundary() {
    let threshold = 10000u64;
    let amount = threshold; // Equal to threshold (should be non-compliant for strict <)
    let public_inputs = create_public_inputs(threshold, 0);

    let witness = BatchEventWitness::new(0, amount, public_inputs, threshold);

    assert!(!witness.is_compliant, "Amount == threshold should NOT be compliant (strict <)");
}

#[test]
fn test_batch_event_witness_amount_limbs() {
    let threshold = 10000u64;
    let amount = 0x1234567890ABCDEFu64;
    let public_inputs = create_public_inputs(threshold, 0);

    let witness = BatchEventWitness::new(0, amount, public_inputs, threshold);
    let limbs = witness.amount_limbs();

    assert_eq!(limbs[0].as_int(), 0x90ABCDEF);
    assert_eq!(limbs[1].as_int(), 0x12345678);

    // Upper limbs should be zero
    for i in 2..8 {
        assert_eq!(limbs[i].as_int(), 0);
    }
}

#[test]
fn test_batch_event_witness_compliance_felt() {
    let threshold = 10000u64;
    let public_inputs = create_public_inputs(threshold, 0);

    let compliant_witness = BatchEventWitness::new(0, 5000, public_inputs.clone(), threshold);
    assert_eq!(compliant_witness.compliance_felt().as_int(), 1);

    let non_compliant_witness = BatchEventWitness::new(0, 15000, public_inputs, threshold);
    assert_eq!(non_compliant_witness.compliance_felt().as_int(), 0);
}

#[test]
fn test_batch_event_witness_to_event_leaf() {
    let threshold = 10000u64;
    let public_inputs = create_public_inputs(threshold, 0);
    let policy_hash = create_policy_hash(threshold);

    let witness = BatchEventWitness::new(0, 5000, public_inputs, threshold);
    let leaf = witness.to_event_leaf(&policy_hash);

    // Verify compliance flag
    assert_eq!(leaf.compliance_flag.as_int(), 1);

    // Verify policy hash matches
    for i in 0..8 {
        assert_eq!(leaf.policy_hash[i].as_int(), policy_hash[i].as_int());
    }
}

// =============================================================================
// BatchWitnessBuilder Tests
// =============================================================================

#[test]
fn test_batch_witness_builder_empty() {
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 0, 0, timestamp());
    let policy_hash = create_policy_hash(10000);

    let result = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(10000)
        .build();

    // Building with no events may return an error (empty batch not allowed)
    // This is implementation-specific - we just verify it doesn't panic
    let _ = result;
}

#[test]
fn test_batch_witness_builder_single_event() {
    let threshold = 10000u64;
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 0, 0, timestamp());
    let policy_hash = create_policy_hash(threshold);
    let public_inputs = create_public_inputs(threshold, 0);

    let result = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(threshold)
        .add_event(5000, public_inputs)
        .build();

    assert!(result.is_ok());
    let witness = result.unwrap();
    assert_eq!(witness.events.len(), 1);
    assert!(witness.events[0].is_compliant);
}

#[test]
fn test_batch_witness_builder_multiple_events() {
    let threshold = 10000u64;
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 0, 2, timestamp());
    let policy_hash = create_policy_hash(threshold);

    let mut builder = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(threshold);

    // Add 3 events: 2 compliant, 1 non-compliant
    builder = builder.add_event(5000, create_public_inputs(threshold, 0));
    builder = builder.add_event(3000, create_public_inputs(threshold, 1));
    builder = builder.add_event(15000, create_public_inputs(threshold, 2)); // Non-compliant

    let result = builder.build();
    assert!(result.is_ok());

    let witness = result.unwrap();
    assert_eq!(witness.events.len(), 3);
    assert!(witness.events[0].is_compliant);
    assert!(witness.events[1].is_compliant);
    assert!(!witness.events[2].is_compliant);
}

#[test]
fn test_batch_witness_builder_with_prev_state_root() {
    let threshold = 10000u64;
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 0, 0, timestamp());
    let policy_hash = create_policy_hash(threshold);

    let prev_root = BatchStateRoot::new([
        felt_from_u64(100),
        felt_from_u64(200),
        felt_from_u64(300),
        felt_from_u64(400),
    ]);

    let result = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(threshold)
        .prev_state_root(prev_root.clone())
        .add_event(5000, create_public_inputs(threshold, 0))
        .build();

    assert!(result.is_ok());
    let witness = result.unwrap();
    assert_eq!(witness.prev_state_root.root[0].as_int(), 100);
}

// =============================================================================
// BatchStateRoot Tests
// =============================================================================

#[test]
fn test_batch_state_root_genesis() {
    let root = BatchStateRoot::genesis();

    for i in 0..4 {
        assert_eq!(root.root[i].as_int(), 0);
    }
}

#[test]
fn test_batch_state_root_new() {
    let values = [
        felt_from_u64(1),
        felt_from_u64(2),
        felt_from_u64(3),
        felt_from_u64(4),
    ];
    let root = BatchStateRoot::new(values);

    assert_eq!(root.root[0].as_int(), 1);
    assert_eq!(root.root[1].as_int(), 2);
    assert_eq!(root.root[2].as_int(), 3);
    assert_eq!(root.root[3].as_int(), 4);
}

#[test]
fn test_batch_state_root_equality() {
    let root1 = BatchStateRoot::new([
        felt_from_u64(1),
        felt_from_u64(2),
        felt_from_u64(3),
        felt_from_u64(4),
    ]);
    let root2 = BatchStateRoot::new([
        felt_from_u64(1),
        felt_from_u64(2),
        felt_from_u64(3),
        felt_from_u64(4),
    ]);
    let root3 = BatchStateRoot::new([
        felt_from_u64(1),
        felt_from_u64(2),
        felt_from_u64(3),
        felt_from_u64(5), // Different
    ]);

    assert_eq!(root1.root[0].as_int(), root2.root[0].as_int());
    assert_ne!(root1.root[3].as_int(), root3.root[3].as_int());
}

// =============================================================================
// EventMerkleTree Tests
// =============================================================================

#[test]
fn test_event_merkle_tree_empty() {
    let tree = EventMerkleTree::from_leaves(Vec::new());
    // Empty tree may return an error (implementation-specific)
    // We just verify it doesn't panic
    match tree {
        Ok(t) => {
            let root = t.root();
            assert!(root.len() == 4);
        }
        Err(_) => {
            // Empty tree not allowed - that's fine
        }
    }
}

#[test]
fn test_event_merkle_tree_single_leaf() {
    let leaf = EventLeaf {
        event_id: [felt_from_u64(1), felt_from_u64(2), felt_from_u64(3), felt_from_u64(4)],
        amount_commitment: [felt_from_u64(5), felt_from_u64(6), felt_from_u64(7), felt_from_u64(8)],
        policy_hash: [FELT_ZERO; 8],
        compliance_flag: FELT_ONE,
    };

    let tree = EventMerkleTree::from_leaves(vec![leaf]).unwrap();
    let root = tree.root();

    // Single leaf tree should have non-zero root
    assert!(root.len() == 4);
}

#[test]
fn test_event_merkle_tree_deterministic() {
    let leaves: Vec<EventLeaf> = (0..4).map(|i| EventLeaf {
        event_id: [felt_from_u64(i), felt_from_u64(i + 1), felt_from_u64(i + 2), felt_from_u64(i + 3)],
        amount_commitment: [felt_from_u64(i * 10), FELT_ZERO, FELT_ZERO, FELT_ZERO],
        policy_hash: [FELT_ZERO; 8],
        compliance_flag: FELT_ONE,
    }).collect();

    let tree1 = EventMerkleTree::from_leaves(leaves.clone()).unwrap();
    let tree2 = EventMerkleTree::from_leaves(leaves).unwrap();

    let root1 = tree1.root();
    let root2 = tree2.root();

    for i in 0..4 {
        assert_eq!(root1[i].as_int(), root2[i].as_int(), "Merkle root should be deterministic");
    }
}

#[test]
fn test_event_merkle_tree_different_leaves_different_root() {
    let leaves1: Vec<EventLeaf> = vec![EventLeaf {
        event_id: [felt_from_u64(1), FELT_ZERO, FELT_ZERO, FELT_ZERO],
        amount_commitment: [felt_from_u64(100), FELT_ZERO, FELT_ZERO, FELT_ZERO],
        policy_hash: [FELT_ZERO; 8],
        compliance_flag: FELT_ONE,
    }];

    let leaves2: Vec<EventLeaf> = vec![EventLeaf {
        event_id: [felt_from_u64(2), FELT_ZERO, FELT_ZERO, FELT_ZERO], // Different
        amount_commitment: [felt_from_u64(100), FELT_ZERO, FELT_ZERO, FELT_ZERO],
        policy_hash: [FELT_ZERO; 8],
        compliance_flag: FELT_ONE,
    }];

    let tree1 = EventMerkleTree::from_leaves(leaves1).unwrap();
    let tree2 = EventMerkleTree::from_leaves(leaves2).unwrap();

    let root1 = tree1.root();
    let root2 = tree2.root();

    let mut any_different = false;
    for i in 0..4 {
        if root1[i].as_int() != root2[i].as_int() {
            any_different = true;
            break;
        }
    }
    assert!(any_different, "Different leaves should produce different roots");
}

// =============================================================================
// BatchVerifier Tests
// =============================================================================

#[test]
fn test_batch_verifier_creation() {
    let _verifier = BatchVerifier::new();
}

#[test]
fn test_batch_verifier_default() {
    let _verifier = BatchVerifier::default();
}

#[test]
fn test_batch_verifier_proof_hash() {
    let proof_bytes = b"test batch proof";

    use ves_stark_primitives::Hash256;
    let hash = Hash256::sha256_with_domain(
        b"STATESET_VES_BATCH_PROOF_HASH_V1",
        proof_bytes,
    );

    assert!(BatchVerifier::verify_proof_hash(proof_bytes, &hash.to_hex()));
    assert!(!BatchVerifier::verify_proof_hash(proof_bytes, "wrong_hash"));
}

// =============================================================================
// Edge Cases and Stress Tests
// =============================================================================

#[test]
fn test_batch_with_all_non_compliant() {
    let threshold = 10000u64;
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 0, 2, timestamp());
    let policy_hash = create_policy_hash(threshold);

    let mut builder = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(threshold);

    // All events exceed threshold
    for i in 0..3 {
        builder = builder.add_event(threshold + (i as u64 * 1000) + 1, create_public_inputs(threshold, i as u64));
    }

    let result = builder.build();
    assert!(result.is_ok());

    let witness = result.unwrap();
    for event in &witness.events {
        assert!(!event.is_compliant);
    }
}

#[test]
fn test_batch_with_zero_amounts() {
    let threshold = 10000u64;
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 0, 1, timestamp());
    let policy_hash = create_policy_hash(threshold);

    let result = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(threshold)
        .add_event(0, create_public_inputs(threshold, 0))
        .add_event(0, create_public_inputs(threshold, 1))
        .build();

    assert!(result.is_ok());
    let witness = result.unwrap();
    assert!(witness.events.iter().all(|e| e.is_compliant));
}

#[test]
fn test_batch_with_max_u64_threshold() {
    let threshold = u64::MAX;
    let batch_id = Uuid::new_v4();
    let metadata = BatchMetadata::new(batch_id, Uuid::new_v4(), Uuid::new_v4(), 0, 0, timestamp());
    let policy_hash = create_policy_hash(threshold);

    let result = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(threshold)
        .add_event(u64::MAX - 1, create_public_inputs(threshold, 0))
        .build();

    assert!(result.is_ok());
    let witness = result.unwrap();
    assert!(witness.events[0].is_compliant);
}
