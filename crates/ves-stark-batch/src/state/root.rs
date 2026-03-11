//! Batch state root computation
//!
//! The batch state root combines:
//! - Event Merkle tree root (commitment to all events)
//! - A chained metadata hash (commitment to the previous state root and batch identity/sequence)

use super::merkle::{rescue_hash_pair, EventMerkleTree};
use super::metadata::BatchMetadata;
use ves_stark_primitives::{felt_from_u64, Felt, FELT_ZERO};

/// The state root for a batch of compliance events
///
/// Computed as: `Rescue_Hash(event_tree_root || metadata_hash)`, where
/// `metadata_hash = Rescue_Hash(prev_state_root || batch_metadata)`.
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

    /// Compute state root from the previous root, event tree, and batch metadata.
    pub fn compute(
        prev_state_root: &BatchStateRoot,
        event_tree: &EventMerkleTree,
        metadata: &BatchMetadata,
    ) -> Self {
        let event_root = event_tree.root();
        let metadata_hash = metadata.to_chained_rescue_hash(&prev_state_root.root);

        let state_root = rescue_hash_pair(&event_root, &metadata_hash);

        Self { root: state_root }
    }

    /// Compute state root from a pre-computed event root and metadata hash.
    ///
    /// Callers are responsible for ensuring `metadata_hash` already binds the
    /// previous state root if they require chained-state semantics.
    pub fn from_components(event_root: &[Felt; 4], metadata_hash: &[Felt; 4]) -> Self {
        let state_root = rescue_hash_pair(event_root, metadata_hash);
        Self { root: state_root }
    }

    /// Create a zero/genesis state root
    pub fn genesis() -> Self {
        Self {
            root: [FELT_ZERO; 4],
        }
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
        self.to_hex_le()
    }

    /// Convert state root to a 32-byte little-endian hex string.
    /// Each 64-bit limb is serialized in native u64 little-endian byte order.
    pub fn to_hex_le(&self) -> String {
        let bytes: Vec<u8> = self
            .root
            .iter()
            .flat_map(|f| f.as_int().to_le_bytes())
            .collect();
        hex::encode(bytes)
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        Self::from_hex_le(hex_str)
    }

    /// Parse from a 32-byte little-endian hex string.
    /// Each 64-bit limb is expected in u64 little-endian byte order.
    pub fn from_hex_le(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("Expected 32 bytes, got {}", bytes.len()));
        }

        let mut chunk0 = [0u8; 8];
        let mut chunk1 = [0u8; 8];
        let mut chunk2 = [0u8; 8];
        let mut chunk3 = [0u8; 8];
        chunk0.copy_from_slice(&bytes[0..8]);
        chunk1.copy_from_slice(&bytes[8..16]);
        chunk2.copy_from_slice(&bytes[16..24]);
        chunk3.copy_from_slice(&bytes[24..32]);

        let root = [
            felt_from_u64(u64::from_le_bytes(chunk0)),
            felt_from_u64(u64::from_le_bytes(chunk1)),
            felt_from_u64(u64::from_le_bytes(chunk2)),
            felt_from_u64(u64::from_le_bytes(chunk3)),
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
    use super::super::merkle::EventLeaf;
    use super::*;
    use uuid::Uuid;

    fn create_test_leaf(index: usize) -> EventLeaf {
        EventLeaf {
            event_id: [felt_from_u64(index as u64); 4],
            amount_commitment: [felt_from_u64(1000 + index as u64); 4],
            policy_hash: [felt_from_u64(2000 + index as u64); 8],
            public_inputs_hash: [felt_from_u64(3000 + index as u64); 8],
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
        let prev_root = BatchStateRoot::genesis();

        let metadata = BatchMetadata::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            0,
            3,
            1234567890,
        );

        let state_root = BatchStateRoot::compute(&prev_root, &tree, &metadata);

        // Should not be genesis
        assert!(!state_root.is_genesis());
    }

    #[test]
    fn test_state_root_deterministic() {
        let leaves: Vec<EventLeaf> = (0..4).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();
        let prev_root = BatchStateRoot::genesis();

        let metadata = BatchMetadata::new(
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            Uuid::parse_str("6ba7b811-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            0,
            3,
            1234567890,
        );

        let root1 = BatchStateRoot::compute(&prev_root, &tree, &metadata);
        let root2 = BatchStateRoot::compute(&prev_root, &tree, &metadata);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let leaves: Vec<EventLeaf> = (0..4).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();
        let prev_root = BatchStateRoot::genesis();

        let metadata = BatchMetadata::with_sequence(Uuid::new_v4(), Uuid::new_v4(), 0, 3);

        let original = BatchStateRoot::compute(&prev_root, &tree, &metadata);
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

        let metadata = BatchMetadata::with_sequence(Uuid::new_v4(), Uuid::new_v4(), 0, 3);
        let prev_root = BatchStateRoot::genesis();

        let root1 = BatchStateRoot::compute(&prev_root, &tree1, &metadata);
        let root2 = BatchStateRoot::compute(&prev_root, &tree2, &metadata);

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_different_prev_roots_different_state_roots() {
        let leaves: Vec<EventLeaf> = (0..4).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();

        let metadata = BatchMetadata::with_sequence(Uuid::new_v4(), Uuid::new_v4(), 0, 3);
        let prev_root_a = BatchStateRoot::new([felt_from_u64(1); 4]);
        let prev_root_b = BatchStateRoot::new([felt_from_u64(2); 4]);

        let root_a = BatchStateRoot::compute(&prev_root_a, &tree, &metadata);
        let root_b = BatchStateRoot::compute(&prev_root_b, &tree, &metadata);

        assert_ne!(root_a, root_b);
    }
}
