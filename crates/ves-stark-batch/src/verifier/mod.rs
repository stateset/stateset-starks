//! Batch verifier module
//!
//! This module provides verification for batch state transition proofs.

mod batch_verifier;
mod event_proofs;
pub use event_proofs::verify_batch_with_event_proofs;

pub use batch_verifier::{
    verify_batch_proof, BatchVerificationResult, BatchVerifier, MAX_BATCH_PROOF_SIZE,
};
