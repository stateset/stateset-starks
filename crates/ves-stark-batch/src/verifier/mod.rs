//! Batch verifier module
//!
//! This module provides verification for batch state transition proofs.

mod batch_verifier;

pub use batch_verifier::{verify_batch_proof, BatchVerificationResult, BatchVerifier};
