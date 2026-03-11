//! VES STARK Batch Proofs
//!
//! This crate provides batch state transition proofs for VES compliance.
//! It enables proving that N compliance events were all verified correctly
//! with a single STARK proof, along with state transition integrity.
//!
//! # Batch proofs production-hardening note
//!
//! Batch proofs are production-focused:
//! - They bind per-event policy consistency, sequence continuity, and witness commitments.
//! - They compute compliance/accumulator state inside the AIR and enforce Merkle and finalization hashing
//!   in-circuit.
//! - They expose a public ordered accumulator over canonical per-event public-input hashes so
//!   external verifiers can bind proofs to an expected event stream.
//!
//! Security note: batch proofs still do not embed payload-to-amount linkage inside this crate.
//! If protocol security requires that, that linkage must be enforced by upstream policy
//! ingestion/validation logic.
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

pub mod air;
pub mod error;
pub(crate) mod json_num;
pub mod prover;
pub mod public_inputs;
pub mod serialization;
pub mod state;
pub mod verifier;

// Re-exports for convenience
pub use error::BatchError;
pub use public_inputs::{compute_public_inputs_accumulator, BatchPolicyKind, BatchPublicInputs};

// Prover types
pub use prover::{
    BatchEventWitness, BatchProof, BatchProofMetadata, BatchProver, BatchProverConfig,
    BatchTraceBuilder, BatchWitness, BatchWitnessBuilder,
};

// Verifier types
pub use verifier::{verify_batch_proof, BatchVerificationResult, BatchVerifier};

// Serialization
pub use serialization::{SerializableBatchProof, SerializableBatchPublicInputs};

// State types
pub use state::{BatchMetadata, BatchStateRoot, EventLeaf, EventMerkleTree};
