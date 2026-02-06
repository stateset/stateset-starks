//! State model for batch proofs
//!
//! This module implements the state representation for batch state transitions:
//! - `BatchStateRoot`: The root commitment to a batch of events
//! - `EventMerkleTree`: Rescue-based Merkle tree for event commitments
//! - `BatchMetadata`: Metadata about the batch (id, sequence range, timestamp)

mod merkle;
mod metadata;
mod root;

pub use merkle::{EventLeaf, EventMerkleTree};
pub use metadata::BatchMetadata;
pub use root::BatchStateRoot;
