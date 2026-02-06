//! Rescue-based Merkle tree for event commitments
//!
//! This implements a STARK-friendly Merkle tree using Rescue-Prime hash.

use crate::error::{BatchError, BatchResult};
use ves_stark_primitives::{felt_from_u64, rescue::rescue_hash, Felt, FELT_ZERO};

/// A leaf in the event Merkle tree
#[derive(Debug, Clone)]
pub struct EventLeaf {
    /// Event ID as field elements (4 elements from UUID)
    pub event_id: [Felt; 4],

    /// Amount commitment (Rescue hash of private amount)
    pub amount_commitment: [Felt; 4],

    /// Policy hash as field elements (8 elements from SHA-256)
    pub policy_hash: [Felt; 8],

    /// Compliance flag (1 = compliant, 0 = not compliant)
    pub compliance_flag: Felt,
}

impl EventLeaf {
    /// Create a new event leaf
    pub fn new(
        event_id: [Felt; 4],
        amount_commitment: [Felt; 4],
        policy_hash: [Felt; 8],
        is_compliant: bool,
    ) -> Self {
        Self {
            event_id,
            amount_commitment,
            policy_hash,
            compliance_flag: if is_compliant {
                felt_from_u64(1)
            } else {
                FELT_ZERO
            },
        }
    }

    /// Compute the leaf hash using Rescue
    pub fn hash(&self) -> [Felt; 4] {
        // Concatenate all fields: 4 + 4 + 8 + 1 = 17 elements
        let mut input = Vec::with_capacity(17);
        input.extend_from_slice(&self.event_id);
        input.extend_from_slice(&self.amount_commitment);
        input.extend_from_slice(&self.policy_hash);
        input.push(self.compliance_flag);

        rescue_hash(&input)
    }
}

/// Rescue-based Merkle tree for event commitments
#[derive(Debug, Clone)]
pub struct EventMerkleTree {
    /// Leaf hashes (bottom level)
    leaves: Vec<[Felt; 4]>,

    /// Internal nodes organized by level (level 0 = leaves, higher = internal)
    /// Each level contains the hashes at that level
    levels: Vec<Vec<[Felt; 4]>>,

    /// The root hash
    root: [Felt; 4],
}

impl EventMerkleTree {
    /// Build a Merkle tree from event leaves
    pub fn from_leaves(leaves: Vec<EventLeaf>) -> BatchResult<Self> {
        if leaves.is_empty() {
            return Err(BatchError::EmptyBatch);
        }

        // Compute leaf hashes
        let leaf_hashes: Vec<[Felt; 4]> = leaves.iter().map(|l| l.hash()).collect();

        Self::from_leaf_hashes(leaf_hashes)
    }

    /// Build a Merkle tree from pre-computed leaf hashes
    pub fn from_leaf_hashes(leaf_hashes: Vec<[Felt; 4]>) -> BatchResult<Self> {
        if leaf_hashes.is_empty() {
            return Err(BatchError::EmptyBatch);
        }

        // Pad to power of 2 if needed
        let n = leaf_hashes.len().next_power_of_two();
        let mut padded_leaves = leaf_hashes.clone();
        while padded_leaves.len() < n {
            // Pad with zero hashes
            padded_leaves.push([FELT_ZERO; 4]);
        }

        // Build tree bottom-up
        let mut levels = Vec::new();
        levels.push(padded_leaves.clone());

        let mut current_level = padded_leaves;
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);

            for pair in current_level.chunks(2) {
                let parent = rescue_hash_pair(&pair[0], &pair[1]);
                next_level.push(parent);
            }

            levels.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level[0];

        Ok(Self {
            leaves: leaf_hashes,
            levels,
            root,
        })
    }

    /// Get the root hash
    pub fn root(&self) -> [Felt; 4] {
        self.root
    }

    /// Get the number of leaves (excluding padding)
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Get the tree depth (number of levels excluding leaves)
    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Get all nodes at a specific level (0 = leaves)
    pub fn level(&self, level: usize) -> Option<&Vec<[Felt; 4]>> {
        self.levels.get(level)
    }

    /// Get all internal levels (excluding leaves)
    /// Returns levels 1 to n where n is the root level
    pub fn levels(&self) -> &[Vec<[Felt; 4]>] {
        if self.levels.len() > 1 {
            &self.levels[1..]
        } else {
            &[]
        }
    }

    /// Get all leaf hashes
    pub fn leaf_hashes(&self) -> &[[Felt; 4]] {
        &self.leaves
    }

    /// Get a Merkle proof for a specific leaf index
    pub fn get_proof(&self, leaf_index: usize) -> BatchResult<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(BatchError::MerkleTreeError(format!(
                "Leaf index {} out of bounds (num leaves: {})",
                leaf_index,
                self.leaves.len()
            )));
        }

        let mut siblings = Vec::new();
        let mut path_indices = Vec::new();
        let mut index = leaf_index;

        // Walk up the tree collecting siblings
        for level in 0..self.levels.len() - 1 {
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };

            if let Some(level_nodes) = self.levels.get(level) {
                if sibling_index < level_nodes.len() {
                    siblings.push(level_nodes[sibling_index]);
                } else {
                    siblings.push([FELT_ZERO; 4]); // Padding node
                }
            }

            path_indices.push(index.is_multiple_of(2)); // true = left child, false = right child
            index /= 2;
        }

        Ok(MerkleProof {
            leaf_index,
            siblings,
            path_indices,
        })
    }

    /// Verify a Merkle proof
    pub fn verify_proof(root: &[Felt; 4], leaf_hash: &[Felt; 4], proof: &MerkleProof) -> bool {
        let mut current_hash = *leaf_hash;

        for (sibling, is_left) in proof.siblings.iter().zip(proof.path_indices.iter()) {
            current_hash = if *is_left {
                rescue_hash_pair(&current_hash, sibling)
            } else {
                rescue_hash_pair(sibling, &current_hash)
            };
        }

        current_hash == *root
    }
}

/// A Merkle proof for inclusion of a leaf
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Index of the leaf being proven
    pub leaf_index: usize,

    /// Sibling hashes along the path to root
    pub siblings: Vec<[Felt; 4]>,

    /// Path indices (true = current node is left child)
    pub path_indices: Vec<bool>,
}

/// Compute Rescue hash of two child nodes to get parent
pub fn rescue_hash_pair(left: &[Felt; 4], right: &[Felt; 4]) -> [Felt; 4] {
    let mut input = Vec::with_capacity(8);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    rescue_hash(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_leaf(index: usize) -> EventLeaf {
        EventLeaf {
            event_id: [felt_from_u64(index as u64); 4],
            amount_commitment: [felt_from_u64(1000 + index as u64); 4],
            policy_hash: [felt_from_u64(2000 + index as u64); 8],
            compliance_flag: felt_from_u64(1),
        }
    }

    #[test]
    fn test_leaf_hash_deterministic() {
        let leaf = create_test_leaf(0);
        let hash1 = leaf.hash();
        let hash2 = leaf.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_leaves_different_hashes() {
        let leaf1 = create_test_leaf(0);
        let leaf2 = create_test_leaf(1);
        assert_ne!(leaf1.hash(), leaf2.hash());
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![create_test_leaf(0)];
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();

        assert_eq!(tree.num_leaves(), 1);
        // Single leaf is already a power of two, so there are no internal levels.
        assert_eq!(tree.depth(), 0);
    }

    #[test]
    fn test_merkle_tree_power_of_two() {
        let leaves: Vec<EventLeaf> = (0..8).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();

        assert_eq!(tree.num_leaves(), 8);
        assert_eq!(tree.depth(), 3); // log2(8) = 3
    }

    #[test]
    fn test_merkle_tree_non_power_of_two() {
        let leaves: Vec<EventLeaf> = (0..5).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();

        assert_eq!(tree.num_leaves(), 5);
        // Padded to 8, so depth is 3
        assert_eq!(tree.depth(), 3);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves: Vec<EventLeaf> = (0..8).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves.clone()).unwrap();

        // Verify proof for each leaf
        for i in 0..8 {
            let proof = tree.get_proof(i).unwrap();
            let leaf_hash = leaves[i].hash();
            assert!(
                EventMerkleTree::verify_proof(&tree.root(), &leaf_hash, &proof),
                "Proof verification failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_merkle_proof_invalid_leaf() {
        let leaves: Vec<EventLeaf> = (0..8).map(|i| create_test_leaf(i)).collect();
        let tree = EventMerkleTree::from_leaves(leaves).unwrap();

        let proof = tree.get_proof(0).unwrap();
        let wrong_leaf_hash = create_test_leaf(100).hash(); // Wrong leaf

        assert!(
            !EventMerkleTree::verify_proof(&tree.root(), &wrong_leaf_hash, &proof),
            "Should not verify with wrong leaf hash"
        );
    }

    #[test]
    fn test_root_changes_with_different_leaves() {
        let leaves1: Vec<EventLeaf> = (0..4).map(|i| create_test_leaf(i)).collect();
        let leaves2: Vec<EventLeaf> = (10..14).map(|i| create_test_leaf(i)).collect();

        let tree1 = EventMerkleTree::from_leaves(leaves1).unwrap();
        let tree2 = EventMerkleTree::from_leaves(leaves2).unwrap();

        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_rescue_hash_pair() {
        let left = [felt_from_u64(1); 4];
        let right = [felt_from_u64(2); 4];

        let hash1 = rescue_hash_pair(&left, &right);
        let hash2 = rescue_hash_pair(&left, &right);

        assert_eq!(hash1, hash2);

        // Order matters
        let hash3 = rescue_hash_pair(&right, &left);
        assert_ne!(hash1, hash3);
    }
}
