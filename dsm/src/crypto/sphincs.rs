use crate::types::error::DsmError;
use std::sync::atomic::{AtomicBool, Ordering};

static SPHINCS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the SPHINCS+ signature subsystem
pub fn init_sphincs() {
    if !SPHINCS_INITIALIZED.load(Ordering::SeqCst) {
        // Perform any necessary initialization for SPHINCS+
        // Currently this is just a placeholder for future expansion
        tracing::info!("SPHINCS+ signature subsystem initialized");
        SPHINCS_INITIALIZED.store(true, Ordering::SeqCst);
    }
}
use pqcrypto_sphincsplus::sphincssha2256fsimple::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

/// Generate SPHINCS+ key pair using the pqcrypto library
pub fn generate_sphincs_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Sign a message using SPHINCS+
pub fn sphincs_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, DsmError> {
    // Recreate secret key from bytes
    let sk = SecretKey::from_bytes(secret_key_bytes).map_err(|_| DsmError::InvalidSecretKey)?;

    // Sign the message
    let signature = detached_sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

/// Verify a SPHINCS+ signature
pub fn sphincs_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, DsmError> {
    if message.is_empty() {
        return Err(DsmError::crypto(
            "Empty message".to_string(),
            None::<std::io::Error>,
        ));
    }

    // Recreate public key from bytes
    let pk = PublicKey::from_bytes(public_key_bytes).map_err(|_| DsmError::InvalidPublicKey)?;

    // Recreate signature from bytes
    let signature = DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| DsmError::crypto("Invalid signature".to_string(), None::<std::io::Error>))?;

    // Verify the signature
    match verify_detached_signature(&signature, message, &pk) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Convenience function to both sign a message and return the signature with the message
pub fn sphincs_sign_message(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, DsmError> {
    let signature = sphincs_sign(secret_key_bytes, message)?;

    // Combine signature and message
    let mut signed_message = Vec::with_capacity(signature.len() + message.len());
    signed_message.extend_from_slice(&signature);
    signed_message.extend_from_slice(message);

    Ok(signed_message)
}

/// Convenience function to verify and extract message from a signed message
pub fn sphincs_verify_and_extract(
    public_key_bytes: &[u8],
    signed_message: &[u8],
) -> Result<Vec<u8>, DsmError> {
    let signature_size = pqcrypto_sphincsplus::sphincssha2256fsimple::signature_bytes;

    if signed_message.len() < signature_size() {
        return Err(DsmError::crypto(
            "Invalid signature length".to_string(),
            None::<std::io::Error>,
        ));
    }

    let (signature, message) = signed_message.split_at(signature_size());

    if message.is_empty() {
        return Err(DsmError::crypto(
            "Empty message".to_string(),
            None::<std::io::Error>,
        ));
    }

    let verification = sphincs_verify(public_key_bytes, message, signature)?;
    if !verification {
        return Err(DsmError::crypto(
            "Signature verification failed".to_string(),
            None::<std::io::Error>,
        ));
    }

    Ok(message.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_keypair_generation() {
        let (pk, sk) = generate_sphincs_keypair();
        let message = b"Test message";
        let modified = b"Modified message";

        let signature = sphincs_sign(&sk, message).expect("Signing should succeed");
        let result =
            sphincs_verify(&pk, modified, &signature).expect("Verification should succeed");

        assert!(!result);
    }

    #[test]
    fn test_sphincs_sign_message_and_verify() {
        let message = b"Test message for combined signature";
        let (pk, sk) = generate_sphincs_keypair();

        let signed = sphincs_sign_message(&sk, message).expect("Sign message should succeed");
        let extracted = sphincs_verify_and_extract(&pk, &signed)
            .expect("Verification and extraction should succeed");

        assert_eq!(extracted, message);
    }
}
