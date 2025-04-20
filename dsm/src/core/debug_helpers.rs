//! # Debug Helper Functions
//!
//! This module provides utility functions specifically designed for development
//! and debugging of the DSM system. These functions provide detailed logging and
//! tracing capabilities to help understand the internal state of the system.
//!
//! Note: These functions are primarily intended for development use and may have
//! performance implications if used in production environments.

use crate::types::error::DsmError;
use crate::types::state_types::State;

/// Display detailed information about a state for debugging purposes
///
/// This function prints detailed diagnostic information about a DSM state,
/// including its hash, state number, previous hash, entropy information,
/// and hash integrity verification.
///
/// # Arguments
///
/// * `label` - A descriptive label to identify this state in the debug output
/// * `state` - Reference to the State object to debug
///
/// # Returns
///
/// * `Ok(())` - If the debugging information was successfully printed
/// * `Err(DsmError)` - If there was an error accessing state properties
///
/// # Examples
///
/// ```
/// use dsm::core::debug_helpers;
/// use dsm::types::state_types::{State, DeviceInfo};
///
/// // Create a test state
/// let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
/// let state = State::new_genesis(vec![5, 6, 7, 8], device_info);
///
/// // Debug the state
/// debug_helpers::debug_state("Genesis", &state).unwrap();
/// ```
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

/// Trace the evolution of entropy during state transitions
///
/// This function computes and displays how entropy evolves from one state to
/// the next based on the current state, operation data, and the next state number.
/// It helps in debugging deterministic entropy evolution, which is critical for
/// the security properties of the DSM system.
///
/// # Arguments
///
/// * `state` - Reference to the current State object
/// * `operation_data` - The operation data bytes that will be used in the transition
/// * `next_state_number` - The state number for the next state
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The newly calculated entropy if successful
/// * `Err(DsmError)` - If there was an error in the entropy calculation
///
/// # Examples
///
/// ```
/// use dsm::core::debug_helpers;
/// use dsm::types::state_types::{State, DeviceInfo};
///
/// // Create a test state
/// let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
/// let state = State::new_genesis(vec![5, 6, 7, 8], device_info);
///
/// // Trace entropy evolution for an operation
/// let op_data = b"test operation";
/// let next_number = 1; // First state after genesis
/// let new_entropy = debug_helpers::trace_entropy_evolution(
///     &state, 
///     op_data, 
///     next_number
/// ).unwrap();
///
/// // new_entropy can now be used in creating the next state
/// ```
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
