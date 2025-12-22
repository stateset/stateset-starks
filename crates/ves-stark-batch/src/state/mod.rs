//! State model for batch proofs
//!
//! This module implements the state representation for batch state transitions:
//! - `BatchStateRoot`: The root commitment to a batch of events
//! - `EventMerkleTree`: Rescue-based Merkle tree for event commitments
//! - `BatchMetadata`: Metadata about the batch (id, sequence range, timestamp)

mod root;
mod merkle;
mod metadata;

pub use root::BatchStateRoot;
pub use merkle::{EventMerkleTree, EventLeaf};
pub use metadata::BatchMetadata;
