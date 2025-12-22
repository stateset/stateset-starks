//! VES STARK Client
//!
//! HTTP client for submitting VES compliance proofs to the StateSet sequencer
//! and batch proofs to Set Chain.
//!
//! # Example - Single Event Proofs
//!
//! ```no_run
//! use ves_stark_client::{SequencerClient, ProofSubmission};
//! use uuid::Uuid;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = SequencerClient::new("http://localhost:8080", "api_key_here");
//!
//!     // Get public inputs for an event
//!     let event_id = Uuid::new_v4();
//!     let inputs = client.get_public_inputs(event_id, "aml.threshold", 10000).await.unwrap();
//!     println!("Public inputs: {:?}", inputs);
//! }
//! ```
//!
//! # Example - Batch Proofs to Set Chain
//!
//! ```no_run
//! use ves_stark_client::{SetChainClient, SetChainConfig, BatchProofSubmission};
//! use uuid::Uuid;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = SetChainConfig::testnet();
//!     let client = SetChainClient::new("http://localhost:8080", "api_key_here", config);
//!
//!     // Check if a batch has a proof anchored
//!     let batch_id = Uuid::new_v4();
//!     let has_proof = client.has_stark_proof(batch_id).await.unwrap();
//!     println!("Has proof: {}", has_proof);
//! }
//! ```
//!
//! # Feature Flags
//!
//! - `batch` - Enable integration with ves-stark-batch for batch proof submissions

mod client;
mod error;
mod set_chain;
mod types;

#[cfg(feature = "batch")]
mod batch_integration;

pub use client::SequencerClient;
pub use error::ClientError;
pub use set_chain::{
    BatchProofResponse, BatchProofStatus, BatchProofSubmission, BatchProofVerification,
    SetChainClient, SetChainConfig,
};
pub use types::*;

#[cfg(feature = "batch")]
pub use batch_integration::BatchSubmissionBuilder;
