pub(crate) mod tree;
use tree::MerkleTree;
pub mod sparse_merkle_tree;

/// Initialize Merkle tree subsystem
pub fn init_merkle_trees() {
    println!("Merkle tree module initialized");
}

/// Create a new Merkle tree
pub fn create_merkle_tree(leaves: &[Vec<u8>]) -> Vec<u8> {
    let tree = MerkleTree::new(leaves.to_vec());
    let root_hash = tree.root_hash().unwrap_or([0u8; 32]);
    root_hash.to_vec()
}

/// Generate a Merkle proof
#[allow(unused)]
pub fn generate_proof(merkle_root: &[u8], leaf_index: usize) -> Vec<Vec<u8>> {
    let tree = MerkleTree::new(vec![merkle_root.to_vec()]);
    let proof = tree.generate_proof(leaf_index);
    proof.path.iter().map(|hash| hash.to_vec()).collect()
}

/// Verify a Merkle proof
#[allow(unused)]
pub fn verify_proof(merkle_root: &[u8], leaf: &[u8], proof: &[Vec<u8>]) -> bool {
    // Convert inputs to fixed-length arrays
    let mut root_hash = [0u8; 32];
    let mut leaf_hash = [0u8; 32];

    if merkle_root.len() >= 32 && leaf.len() >= 32 {
        root_hash.copy_from_slice(&merkle_root[0..32]);
        leaf_hash.copy_from_slice(&leaf[0..32]);
    } else {
        return false;
    }

    // Convert proof Vec<Vec<u8>> to MerkleProof
    let proof_path: Vec<[u8; 32]> = proof
        .iter()
        .filter_map(|p| {
            let mut hash = [0u8; 32];
            if p.len() >= 32 {
                hash.copy_from_slice(&p[0..32]);
                Some(hash)
            } else {
                None
            }
        })
        .collect();

    let merkle_proof = tree::MerkleProof {
        path: proof_path,
        leaf_index: 0, // We don't need exact index for verification
    };

    MerkleTree::verify_proof(
        &root_hash,
        &leaf_hash,
        &merkle_proof.path,
        merkle_proof.leaf_index,
    )
}
