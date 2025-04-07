use crate::types::error::DsmError;
use crate::types::state_types::{IdentityAnchor, DeviceInfo};
use blake3;
use sphincsplus;

/// Implements identity anchor verification from whitepaper Section 25.1
pub struct IdentityVerifier;

impl IdentityVerifier {
    /// Verify an identity anchor's cryptographic binding
    pub fn verify_identity_anchor(
        anchor: &IdentityAnchor,
        device: &DeviceInfo,
    ) -> Result<bool, DsmError> {
        // Verify uniqueness probability according to whitepaper equation (96):
        // Pr[Collision(DeviceIDi,DeviceIDj)] ≤ 1/2^λID
        if !Self::verify_id_uniqueness(anchor)? {
            return Ok(false);
        }

        // Verify derivation from device seed according to equation (97):
        // Verify(seed,state) = (state.genesis_hash == H(Derive(seed).public))
        if !Self::verify_device_binding(anchor, device)? {
            return Ok(false);
        }

        // Verify quantum-resistant signature
        if !Self::verify_anchor_signature(anchor)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify identity uniqueness probability
    fn verify_id_uniqueness(anchor: &IdentityAnchor) -> Result<bool, DsmError> {
        // Identity must be at least 32 bytes for 256-bit security
        if anchor.id.len() < 32 {
            return Ok(false);
        }

        // Verify id was derived from hash function
        let mut hasher = blake3::Hasher::new();
        hasher.update(anchor.genesis_hash.as_slice());
        hasher.update(anchor.device_binding.as_slice());
        
        let derived_id = hasher.finalize();
        if derived_id.as_bytes() != anchor.id.as_bytes() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify binding to device
    fn verify_device_binding(
        anchor: &IdentityAnchor,
        device: &DeviceInfo,
    ) -> Result<bool, DsmError> {
        // Verify device public key matches binding
        let mut hasher = blake3::Hasher::new();
        hasher.update(&device.public_key);
        let binding = hasher.finalize();

        if binding.as_bytes() != anchor.device_binding.as_slice() {
            return Ok(false);
        }

        // Verify genesis hash matches device derivation
        let mut hasher = blake3::Hasher::new();
        hasher.update(&device.seed);
        let derived = hasher.finalize();

        if derived.as_bytes() != anchor.genesis_hash.as_slice() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify quantum-resistant signature on anchor
    fn verify_anchor_signature(anchor: &IdentityAnchor) -> Result<bool, DsmError> {
        // Verify SPHINCS+ signature
        let message = [
            anchor.id.as_bytes(),
            anchor.genesis_hash.as_slice(),
            anchor.device_binding.as_slice()
        ].concat();

        sphincsplus::verify(
            &message,
            &anchor.signature,
            &anchor.public_key
        ).map_err(|_| DsmError::InvalidSignature)
    }
}