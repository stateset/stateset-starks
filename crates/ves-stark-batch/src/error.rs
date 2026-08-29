//! Error types for batch proof operations

use thiserror::Error;

/// Errors that can occur during batch proof operations
#[derive(Debug, Error)]
pub enum BatchError {
    /// An event in the batch does not comply with the policy
    #[error("Event {event_index} not compliant: {message}")]
    EventNotCompliant {
        /// Zero-based position of the offending event within the batch.
        event_index: usize,
        /// Which compliance check failed, and why.
        message: String,
    },

    /// Batch is empty
    #[error("Batch cannot be empty")]
    EmptyBatch,

    /// Batch exceeds maximum size
    #[error("Batch size {size} exceeds maximum {max}")]
    BatchTooLarge {
        /// Number of events submitted.
        size: usize,
        /// Largest batch the AIR can accommodate.
        max: usize,
    },

    /// Invalid previous state root
    #[error("Invalid previous state root")]
    InvalidPrevStateRoot,

    /// State root computation failed
    #[error("State root computation failed: {0}")]
    StateRootError(String),

    /// Trace construction failed
    #[error("Trace construction failed: {0}")]
    TraceConstructionError(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Proof verification failed for a specific batch
    #[error("Batch {batch_index} verification failed: {message}")]
    VerificationFailed {
        /// Position of the failing batch within the verified chain.
        batch_index: usize,
        /// Reason verification was rejected.
        message: String,
    },

    /// Invalid state chain (new root doesn't match expected)
    #[error(
        "Invalid state chain at batch {batch_index}: expected root {:?}, got {:?}",
        expected,
        actual
    )]
    InvalidStateChain {
        /// Position within the chain where linkage broke.
        batch_index: usize,
        /// `new_state_root` published by the preceding batch.
        expected: [u64; 4],
        /// `prev_state_root` declared by this batch.
        actual: [u64; 4],
    },

    /// Invalid witness
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    /// Deserialization error
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    /// Serialization error
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Invalid public inputs
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    /// Merkle tree error
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(String),

    /// Witness validation error
    #[error("Witness validation error: {0}")]
    WitnessValidationError(String),

    /// Proof is too large
    #[error("Proof too large: {size} bytes exceeds maximum of {max_size} bytes")]
    ProofTooLarge {
        /// Size of the submitted proof, in bytes.
        size: usize,
        /// Hard ceiling enforced before deserialization.
        max_size: usize,
    },
}

/// Result type for batch operations
pub type BatchResult<T> = Result<T, BatchError>;
