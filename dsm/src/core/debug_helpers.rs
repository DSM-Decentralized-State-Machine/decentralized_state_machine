// Debug helper functions for DSM
use crate::types::error::DsmError;
use crate::types::state_types::State;

// Debug function to print state hash and properties
pub fn debug_state(label: &str, state: &State) -> Result<(), DsmError> {
    let hash = state.hash()?;

    println!(
        "DEBUG {}: State #{} with hash: {:?}",
        label, state.state_number, hash
    );
    println!("  - prev_hash: {:?}", state.prev_state_hash);
    println!("  - entropy len: {}", state.entropy.len());
    println!("  - device_id: {}", state.device_info.device_id);

    // Also check state hash integrity
    let computed_hash = state.compute_hash()?;
    let hash_valid = computed_hash == state.hash;
    println!("  - hash integrity: {}", hash_valid);

    Ok(())
}

// Debug function to trace entropy evolution
pub fn trace_entropy_evolution(
    state: &State,
    operation_data: &[u8],
    next_state_number: u64,
) -> Result<Vec<u8>, DsmError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&state.entropy);
    hasher.update(operation_data);
    hasher.update(&next_state_number.to_le_bytes());

    let entropy = hasher.finalize().as_bytes().to_vec();
    println!("DEBUG Entropy evolution:");
    println!("  - current entropy: {:?}", state.entropy);
    println!("  - operation bytes len: {}", operation_data.len());
    println!("  - next state number: {}", next_state_number);
    println!("  - new entropy: {:?}", entropy);

    Ok(entropy)
}
