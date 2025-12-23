//! VES STARK Batch Proofs
//!
//! This crate provides batch state transition proofs for VES compliance.
//! It enables proving that N compliance events were all verified correctly
//! with a single STARK proof, along with state transition integrity.
//!
//! # Experimental
//!
//! Batch proofs are Phase 2+ per the PRD and are **not** yet sound:
//! - Event compliance proofs are not embedded or verified in this AIR
//! - Merkle/state transition constraints are still incomplete
//!
//! Do not use this crate for production verification.
//!
//! # Architecture
//!
//! The batch proof system consists of:
//! - **State Model**: Rescue-based Merkle tree of compliance events
//! - **Batch AIR**: Extended constraints for multi-event verification
//! - **Batch Prover**: Generates proofs for event batches
//! - **Batch Verifier**: Verifies batch proofs
//!
//! # Usage
//!
//! ```ignore
//! use ves_stark_batch::{
//!     BatchProver, BatchProverConfig, BatchWitness, BatchWitnessBuilder,
//!     BatchEventWitness, BatchMetadata, BatchVerifier
//! };
//!
//! // Create batch metadata
//! let metadata = BatchMetadata::new(batch_id, tenant_id, store_id, 0, 9);
//!
//! // Build batch witness
//! let witness = BatchWitnessBuilder::new()
//!     .metadata(metadata)
//!     .policy_hash(policy_hash)
//!     .policy_limit(10000)
//!     .add_event(5000, public_inputs1)
//!     .add_event(3000, public_inputs2)
//!     .build()?;
//!
//! // Generate batch proof
//! let prover = BatchProver::new();
//! let proof = prover.prove(&witness)?;
//!
//! // Verify batch proof
//! let verifier = BatchVerifier::new();
//! let result = verifier.verify(&proof.proof_bytes, &public_inputs)?;
//! assert!(result.valid);
//! ```

pub mod state;
pub mod air;
pub mod prover;
pub mod verifier;
pub mod public_inputs;
pub mod serialization;
pub mod error;

// Re-exports for convenience
pub use error::BatchError;
pub use public_inputs::BatchPublicInputs;

// Prover types
pub use prover::{
    BatchProver, BatchProverConfig,
    BatchWitness, BatchWitnessBuilder, BatchEventWitness,
    BatchTraceBuilder, BatchProof, BatchProofMetadata,
};

// Verifier types
pub use verifier::{BatchVerifier, BatchVerificationResult, verify_batch_proof};

// Serialization
pub use serialization::{SerializableBatchProof, SerializableBatchPublicInputs};

// State types
pub use state::{BatchStateRoot, EventMerkleTree, EventLeaf, BatchMetadata};
