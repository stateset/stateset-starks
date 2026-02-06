//! Batch prover module
//!
//! This module provides the prover components for batch state transition proofs.

mod batch_prover;
mod batch_trace;
mod witness;

pub use batch_prover::{BatchProof, BatchProofMetadata, BatchProver, BatchProverConfig};
pub use batch_trace::BatchTraceBuilder;
pub use witness::{BatchEventWitness, BatchWitness, BatchWitnessBuilder};
