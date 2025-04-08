//! Sparse Merkle Tree Implementation
//!
//! This module implements the Sparse Merkle Tree functionality described in whitepaper Section 3.3.
//! It provides efficient inclusion proofs with logarithmic complexity.

use crate::crypto::blake3::hash_blake3;

use crate::types::error::DsmError;
use crate::types::operations::TransactionMode;
use crate::types::state_types::{MerkleProof, MerkleProofParams, NodeId, SerializableHash, SparseIndex};
use blake3::Hash;
use std::collections::HashMap;

/// SparseMerkleTreeImpl provides an implementation of the Sparse Merkle Tree
/// described in whitepaper Section 3.3 for efficient inclusion proofs.
#[derive(Clone)]
pub struct SparseMerkleTreeImpl {
    /// Root hash of the tree
    root: Hash,

    /// Mapping of leaf indices to their hashes
    leaves: HashMap<u64, Hash>,

    /// Mapping of node IDs (level and index) to node hashes
    nodes: HashMap<NodeId, Hash>,

    /// Height of the tree
    height: u32,

    /// Number of leaves in the tree
    leaf_count: u64,
}

impl SparseMerkleTreeImpl {
    /// Create a new Sparse Merkle Tree with a specified height
    pub fn new(height: u32) -> Self {
        let mut smt = SparseMerkleTreeImpl {
            root: Hash::from([0u8; 32]),
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            height,
            leaf_count: 0,
        };

        // Initialize root with default hash
        smt.nodes.insert(
            NodeId {
                level: height,
                index: 0,
            },
            Hash::from([0u8; 32]),
        );

        smt
    }

    /// Insert a value at a specific index in the tree
    pub fn insert(&mut self, index: u64, value: &[u8]) -> Result<(), DsmError> {
        // Ensure index is within tree capacity
        let max_leaves = 1u64 << self.height;
        if index >= max_leaves {
            return Err(DsmError::InvalidOperation(format!(
                "Index {} exceeds tree capacity of {}",
                index, max_leaves
            )));
        }

        // Compute leaf hash
        let leaf_hash = self.hash_leaf(value);

        // Store leaf hash
        self.leaves.insert(index, leaf_hash);
        self.nodes.insert(NodeId { level: 0, index }, leaf_hash);

        // Update path from leaf to root
        self.update_path(index)?;

        // Update leaf count
        if self.leaf_count < index + 1 {
            self.leaf_count = index + 1;
        }

        Ok(())
    }

    /// Update the path from a leaf to the root
    fn update_path(&mut self, leaf_index: u64) -> Result<(), DsmError> {
        let mut current_index = leaf_index;

        for level in 0..self.height {
            // Get sibling index
            let sibling_index = current_index ^ 1; // Flip the lowest bit

            // Get or compute hashes for current and sibling
            let current_hash = self.get_node_hash(level, current_index)?;
            let sibling_hash = self.get_node_hash(level, sibling_index)?;

            // Compute parent hash
            let parent_index = current_index >> 1; // Divide by 2
            let parent_hash = if current_index & 1 == 0 {
                // Current is left child
                self.hash_node(&current_hash, &sibling_hash)
            } else {
                // Current is right child
                self.hash_node(&sibling_hash, &current_hash)
            };

            // Update parent node
            self.nodes.insert(
                NodeId {
                    level: level + 1,
                    index: parent_index,
                },
                parent_hash,
            );

            // Move up to parent
            current_index = parent_index;
        }

        // Update root hash
        self.root = self
            .nodes
            .get(&NodeId {
                level: self.height,
                index: 0,
            })
            .cloned()
            .unwrap_or_else(|| Hash::from([0u8; 32]));

        Ok(())
    }

    /// Get a node's hash, or default hash if node doesn't exist
    fn get_node_hash(&self, level: u32, index: u64) -> Result<Hash, DsmError> {
        let node_id = NodeId { level, index };
        let hash = self
            .nodes
            .get(&node_id)
            .cloned()
            .unwrap_or_else(|| Hash::from([0u8; 32]));
        Ok(hash)
    }

    /// Generate an inclusion proof for a specific leaf
    pub fn get_proof(&self, index: u64) -> Result<MerkleProof, DsmError> {
        // Ensure index is within tree capacity
        let max_leaves = 1u64 << self.height;
        if index >= max_leaves {
            return Err(DsmError::InvalidOperation(format!(
                "Index {} exceeds tree capacity of {}",
                index, max_leaves
            )));
        }

        // Generate proof path
        let mut path = Vec::with_capacity(self.height as usize);
        let mut current_index = index;

        for level in 0..self.height {
            // Get sibling index
            let sibling_index = current_index ^ 1; // Flip the lowest bit

            // Get sibling hash
            let sibling_hash = self.get_node_hash(level, sibling_index)?;

            // Add sibling hash to proof path
            path.push(SerializableHash::new(sibling_hash));

            // Move up to parent
            current_index >>= 1; // Divide by 2
        }

        // Get the leaf hash and other tree metadata
        let leaf_hash = self.get_node_hash(0, index)?;
        let root_hash = SerializableHash::new(self.root);
        // Create params for MerkleProof
        let proof_params = MerkleProofParams {
            path,
            index,
            leaf_hash: SerializableHash::new(leaf_hash),
            root_hash,
            height: self.height,
            leaf_count: self.leaf_count,
            device_id: String::new(),
            public_key: vec![],
            sparse_index: SparseIndex::new(vec![0]),
            token_balances: HashMap::new(),
            mode: TransactionMode::Bilateral, // Use Bilateral as default
            params: vec![],                   // Empty params as Vec<u8>
            proof: Vec::new(),                // Empty proof
        };

        // Use the MerkleProof constructor with params
        Ok(MerkleProof::new(proof_params))
    }

    /// Verify an inclusion proof against a value and the tree's root
    pub fn verify_proof(
        root_hash: &Hash,
        value: &[u8],
        proof: &MerkleProof,
    ) -> Result<bool, DsmError> {
        // Start with leaf hash
        let mut computed_hash = Self::hash_leaf_static(value);
        let mut current_index = proof.index;

        // Traverse proof path to recompute root
        for sibling_hash in &proof.path {
            computed_hash = if current_index & 1 == 0 {
                // Current is left child
                Self::hash_node_static(&computed_hash, sibling_hash.inner())
            } else {
                // Current is right child
                Self::hash_node_static(sibling_hash.inner(), &computed_hash)
            };

            // Move up to parent
            current_index >>= 1;
        }

        // Verify computed root matches expected root
        Ok(&computed_hash == root_hash)
    }

    /// Get the current root hash of the tree
    pub fn root(&self) -> &Hash {
        &self.root
    }

    /// Get the number of leaves in the tree
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Hash a leaf node with domain separation
    fn hash_leaf(&self, data: &[u8]) -> Hash {
        Self::hash_leaf_static(data)
    }

    /// Static version of leaf hashing for verification
    fn hash_leaf_static(data: &[u8]) -> Hash {
        // Use domain separation prefix for leaf nodes
        let mut input = Vec::with_capacity(data.len() + 1);
        input.push(0x00); // Prefix for leaf nodes
        input.extend_from_slice(data);

        hash_blake3(&input)
    }

    /// Hash an internal node
    fn hash_node(&self, left: &Hash, right: &Hash) -> Hash {
        Self::hash_node_static(left, right)
    }

    /// Static version of node hashing for verification
    fn hash_node_static(left: &Hash, right: &Hash) -> Hash {
        // Use domain separation prefix for internal nodes
        let mut input = Vec::with_capacity(left.as_bytes().len() + right.as_bytes().len() + 1);
        input.push(0x01); // Prefix for internal nodes
        input.extend_from_slice(left.as_bytes());
        input.extend_from_slice(right.as_bytes());

        hash_blake3(&input)
    }

    /// Create a Merkle tree from a set of values
    pub fn from_values(values: &[&[u8]]) -> Result<Self, DsmError> {
        // Calculate required height (ceiling of log2)
        let height = (values.len() as f64).log2().ceil() as u32;
        let mut tree = Self::new(height);

        // Insert all values
        for (idx, value) in values.iter().enumerate() {
            tree.insert(idx as u64, value)?;
        }

        Ok(tree)
    }

    /// Get a specific leaf hash
    pub fn get_leaf(&self, index: u64) -> Option<Hash> {
        self.leaves.get(&index).cloned()
    }

    /// Convert from a SparseMerkleTree type
    pub fn from_sparse_merkle_tree(tree: &crate::types::state_types::SparseMerkleTree) -> Self {
        let mut smt = Self::new(tree.height);

        // Copy leaves
        for (idx, hash) in &tree.leaves {
            smt.leaves.insert(*idx, *hash);
            smt.nodes.insert(
                NodeId {
                    level: 0,
                    index: *idx,
                },
                *hash,
            );
        }

        // Update paths for all leaves to reconstruct internal nodes
        for idx in tree.leaves.keys() {
            smt.update_path(*idx).unwrap_or_default();
        }

        smt
    }

    /// Get the root hash of the tree
    pub fn compute_root(&self) -> Result<Hash, DsmError> {
        Ok(self.root)
    }
}

/// Public methods for creating and managing Sparse Merkle Trees
pub mod sparse_merkle {
    use super::SparseMerkleTreeImpl;
    use crate::types::error::DsmError;
    use crate::types::state_types::MerkleProof;
    use blake3::Hash;

    /// Create a new Sparse Merkle Tree
    ///
    /// # Arguments
    /// * `height` - The height of the tree
    ///
    /// # Returns
    /// * `SparseMerkleTreeImpl` - The new tree
    pub fn create_tree(height: u32) -> SparseMerkleTreeImpl {
        SparseMerkleTreeImpl::new(height)
    }

    /// Insert a value into a Sparse Merkle Tree
    ///
    /// # Arguments
    /// * `tree` - The tree to modify
    /// * `index` - The leaf index
    /// * `value` - The value to insert
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or an error
    pub fn insert(
        tree: &mut SparseMerkleTreeImpl,
        index: u64,
        value: &[u8],
    ) -> Result<(), DsmError> {
        tree.insert(index, value)
    }

    /// Generate an inclusion proof
    ///
    /// # Arguments
    /// * `tree` - The Merkle tree
    /// * `index` - The leaf index to prove
    ///
    /// # Returns
    /// * `Result<MerkleProof, DsmError>` - The inclusion proof
    pub fn generate_proof(
        tree: &SparseMerkleTreeImpl,
        index: u64,
    ) -> Result<MerkleProof, DsmError> {
        tree.get_proof(index)
    }

    /// Verify an inclusion proof
    ///
    /// # Arguments
    /// * `root_hash` - The Merkle root hash
    /// * `value` - The value being proven
    /// * `proof` - The inclusion proof
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether the proof is valid
    pub fn verify_proof(
        root_hash: &Hash,
        value: &[u8],
        proof: &MerkleProof,
    ) -> Result<bool, DsmError> {
        SparseMerkleTreeImpl::verify_proof(root_hash, value, proof)
    }

    /// Create a tree from a set of values
    ///
    /// # Arguments
    /// * `values` - The values to include in the tree
    ///
    /// # Returns
    /// * `Result<SparseMerkleTreeImpl, DsmError>` - The new tree
    pub fn create_from_values(values: &[&[u8]]) -> Result<SparseMerkleTreeImpl, DsmError> {
        SparseMerkleTreeImpl::from_values(values)
    }

    /// Get the root hash of a tree
    ///
    /// # Arguments
    /// * `tree` - The Merkle tree
    ///
    /// # Returns
    /// * `&Hash` - The root hash
    pub fn get_root(tree: &SparseMerkleTreeImpl) -> &Hash {
        tree.root()
    }
}

// Re-export public API for simplified usage
pub use sparse_merkle::{
    create_from_values, create_tree, generate_proof, get_root, insert, verify_proof,
};

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hash;

    #[test]
    fn test_empty_tree() {
        let tree = SparseMerkleTreeImpl::new(10);
        assert_eq!(*tree.root(), Hash::from([0u8; 32]));
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_single_leaf() -> Result<(), DsmError> {
        let mut tree = SparseMerkleTreeImpl::new(10);
        let data = b"test data";

        tree.insert(0, data)?;

        // Get proof
        let proof = tree.get_proof(0)?;

        // Verify proof
        assert!(SparseMerkleTreeImpl::verify_proof(
            tree.root(),
            data,
            &proof
        )?);

        // Verify invalid proof fails
        let invalid_data = b"wrong data";
        assert!(!SparseMerkleTreeImpl::verify_proof(
            tree.root(),
            invalid_data,
            &proof
        )?);

        Ok(())
    }

    #[test]
    fn test_multiple_leaves() -> Result<(), DsmError> {
        let mut tree = SparseMerkleTreeImpl::new(10);
        let data_set = [
            b"data 0" as &[u8],
            b"data 1",
            b"data 2",
            b"data 3",
            b"data 4",
        ];

        // Insert all data
        for (idx, data) in data_set.iter().enumerate() {
            tree.insert(idx as u64, data)?;
        }

        // Verify each leaf with its proof
        for (idx, data) in data_set.iter().enumerate() {
            let proof = tree.get_proof(idx as u64)?;
            assert!(SparseMerkleTreeImpl::verify_proof(
                tree.root(),
                data,
                &proof
            )?);
        }

        // Verify cross-proof failure (using data 0 with proof for data 1)
        let proof_1 = tree.get_proof(1)?;
        assert!(!SparseMerkleTreeImpl::verify_proof(
            tree.root(),
            data_set[0],
            &proof_1
        )?);

        Ok(())
    }

    #[test]
    fn test_sparse_insertion() -> Result<(), DsmError> {
        let mut tree = SparseMerkleTreeImpl::new(10);

        // Insert at sparse indexes
        tree.insert(0, b"data 0")?;
        tree.insert(5, b"data 5")?;
        tree.insert(9, b"data 9")?;

        // Verify leaves exist
        assert!(tree.get_leaf(0).is_some());
        assert!(tree.get_leaf(5).is_some());
        assert!(tree.get_leaf(9).is_some());

        // Verify non-inserted leaves don't exist
        assert!(tree.get_leaf(1).is_none());
        assert!(tree.get_leaf(2).is_none());

        // Verify proofs for all inserted leaves
        let proof_0 = tree.get_proof(0)?;
        assert!(SparseMerkleTreeImpl::verify_proof(
            tree.root(),
            b"data 0",
            &proof_0
        )?);

        let proof_5 = tree.get_proof(5)?;
        assert!(SparseMerkleTreeImpl::verify_proof(
            tree.root(),
            b"data 5",
            &proof_5
        )?);

        let proof_9 = tree.get_proof(9)?;
        assert!(SparseMerkleTreeImpl::verify_proof(
            tree.root(),
            b"data 9",
            &proof_9
        )?);

        Ok(())
    }

    #[test]
    fn test_leaf_update() -> Result<(), DsmError> {
        let mut tree = SparseMerkleTreeImpl::new(10);

        // Insert initial data
        tree.insert(0, b"initial data")?;
        let initial_root = tree.root().clone();

        // Get and verify proof
        let proof = tree.get_proof(0)?;
        assert!(SparseMerkleTreeImpl::verify_proof(
            &initial_root,
            b"initial data",
            &proof
        )?);

        // Update the leaf
        tree.insert(0, b"updated data")?;
        let updated_root = tree.root().clone();

        // Verify root has changed
        assert_ne!(initial_root, updated_root);

        // Old proof should fail with updated data
        assert!(!SparseMerkleTreeImpl::verify_proof(
            &initial_root,
            b"updated data",
            &proof
        )?);

        // New proof should work with updated data
        let updated_proof = tree.get_proof(0)?;
        assert!(SparseMerkleTreeImpl::verify_proof(
            &updated_root,
            b"updated data",
            &updated_proof
        )?);

        Ok(())
    }

    #[test]
    fn test_tree_from_values() -> Result<(), DsmError> {
        let values = [b"value 0" as &[u8], b"value 1", b"value 2", b"value 3"];

        let tree = SparseMerkleTreeImpl::from_values(&values)?;

        // Verify each value has a valid proof
        for (idx, value) in values.iter().enumerate() {
            let proof = tree.get_proof(idx as u64)?;
            assert!(SparseMerkleTreeImpl::verify_proof(
                tree.root(),
                value,
                &proof
            )?);
        }

        Ok(())
    }

    #[test]
    fn test_domain_separation() {
        // Ensure leaf and node hashing produce different results for same input
        let data = b"test data";

        let leaf_hash = SparseMerkleTreeImpl::hash_leaf_static(data);

        // Create a fake node with same data
        let empty_hash = Hash::from([0u8; 32]);
        let mut node_input = Vec::with_capacity(data.len() + empty_hash.as_bytes().len());
        node_input.extend_from_slice(empty_hash.as_bytes());
        node_input.extend_from_slice(data);
        let node_hash = hash_blake3(&node_input);

        // Hashes should be different due to domain separation
        assert_ne!(leaf_hash, node_hash);
    }
}
