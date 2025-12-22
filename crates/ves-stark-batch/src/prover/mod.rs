//! Batch prover module
//!
//! This module provides the prover components for batch state transition proofs.

mod witness;
mod batch_trace;
mod batch_prover;

pub use witness::{BatchEventWitness, BatchWitness, BatchWitnessBuilder};
pub use batch_trace::BatchTraceBuilder;
pub use batch_prover::{BatchProver, BatchProverConfig, BatchProof, BatchProofMetadata};
