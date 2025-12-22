//! Batch state root computation
//!
//! The batch state root combines:
//! - Event Merkle tree root (commitment to all events)
//! - Batch metadata hash (commitment to batch identity and sequence)

use ves_stark_primitives::{Felt, FELT_ZERO, felt_from_u64};
use super::merkle::{EventMerkleTree, rescue_hash_pair};
use super::metadata::BatchMetadata;

/// The state root for a batch of compliance events
///
/// Computed as: Rescue_Hash(event_tree_root || metadata_hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchStateRoot {
    /// The 4-element state root (256 bits as 4x64-bit field elements)
    pub root: [Felt; 4],
}

impl BatchStateRoot {
    /// Create a new state root from the raw field elements
    pub fn new(root: [Felt; 4]) -> Self {
        Self { root }
    }

    /// Compute state root from event tree and metadata
    pub fn compute(
        event_tree: &EventMerkleTree,
        metadata: &BatchMetadata,
    ) -> Self {
        let event_root = event_tree.root();
        let metadata_hash = metadata.to_rescue_hash();

        let state_root = rescue_hash_pair(&event_root, &metadata_hash);

        Self { root: state_root }
    }

    /// Compute state root from pre-computed event root and metadata hash
    pub fn from_components(
        event_root: &[Felt; 4],
        metadata_hash: &[Felt; 4],
    ) -> Self {
        let state_root = rescue_hash_pair(event_root, metadata_hash);
        Self { root: state_root }
    }

    /// Create a zero/genesis state root
    pub fn genesis() -> Self {
        Self { root: [FELT_ZERO; 4] }
    }

    /// Check if this is the genesis (zero) state root
    pub fn is_genesis(&self) -> bool {
        self.root == [FELT_ZERO; 4]
    }

    /// Get the root as a slice
    pub fn as_slice(&self) -> &[Felt] {
        &self.root
    }

    /// Get the root as an array
    pub fn as_array(&self) -> [Felt; 4] {
        self.root
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        let bytes: Vec<u8> = self.root.iter()
            .flat_map(|f| f.as_int().to_le_bytes())
            .collect();
        hex::encode(bytes)
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("Expected 32 bytes, got {}", bytes.len()));
        }

        let root = [
            felt_from_u64(u64::from_le_bytes(bytes[0..8].try_into().unwrap())),
            felt_from_u64(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
            felt_from_u64(u64::from_le_bytes(bytes[16..24].try_into().unwrap())),
            felt_from_u64(u64::from_le_bytes(bytes[24..32].try_into().unwrap())),
        ];

        Ok(Self { root })
    }
}

impl Default for BatchStateRoot {
    fn default() -> Self {
        Self::genesis()
    }
}

impl std::fmt::Display for BatchStateRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}...", &self.to_hex()[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::merkle::EventLeaf;
    use uuid::Uuid;

    fn create_test_leaf(index: usize) -> EventLeaf {
        EventLeaf {
            event_id: [felt_from_u64(index as u64); 4],
            amount_commitment: [felt_from_u64(1000 + index as u64); 4],
            policy_hash: [felt_from_u64(2000 + index as u64); 8],
            compliance_flag: felt_from_u64(1),
        }
    }

    #[test]
    fn test_genesis_state_root() {
        let genesis = BatchStateRoot::genesis();
        assert!(genesis.is_genesis());
        assert_eq!(genesis.root, [FELT_ZERO; 4]);
    }

    #[test]
    fn test_state_root_computation() {
        let leaves: Vec<EventLeaf> = (0..4).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();

        let metadata = BatchMetadata::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            0,
            3,
            1234567890,
        );

        let state_root = BatchStateRoot::compute(&tree, &metadata);

        // Should not be genesis
        assert!(!state_root.is_genesis());
    }

    #[test]
    fn test_state_root_deterministic() {
        let leaves: Vec<EventLeaf> = (0..4).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();

        let metadata = BatchMetadata::new(
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            Uuid::parse_str("6ba7b811-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            0,
            3,
            1234567890,
        );

        let root1 = BatchStateRoot::compute(&tree, &metadata);
        let root2 = BatchStateRoot::compute(&tree, &metadata);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let leaves: Vec<EventLeaf> = (0..4).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();

        let metadata = BatchMetadata::with_sequence(
            Uuid::new_v4(),
            Uuid::new_v4(),
            0,
            3,
        );

        let original = BatchStateRoot::compute(&tree, &metadata);
        let hex = original.to_hex();
        let recovered = BatchStateRoot::from_hex(&hex).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_different_events_different_roots() {
        let leaves1: Vec<EventLeaf> = (0..4).map(|i| create_test_leaf(i)).collect();
        let leaves2: Vec<EventLeaf> = (10..14).map(|i| create_test_leaf(i)).collect();

        let tree1 = EventMerkleTree::from_leaves(leaves1).unwrap();
        let tree2 = EventMerkleTree::from_leaves(leaves2).unwrap();

        let metadata = BatchMetadata::with_sequence(
            Uuid::new_v4(),
            Uuid::new_v4(),
            0,
            3,
        );

        let root1 = BatchStateRoot::compute(&tree1, &metadata);
        let root2 = BatchStateRoot::compute(&tree2, &metadata);

        assert_ne!(root1, root2);
    }
}
