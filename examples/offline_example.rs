// DSM Offline Example
// This example demonstrates offline identity verification using DSM

use blake3::hash;
use dsm::{crypto, types::error::DsmError};

fn main() -> Result<(), DsmError> {
    println!("DSM Offline Example");

    // Generate a key pair for demonstration
    let (kyber_pk, _kyber_sk, sphincs_pk, sphincs_sk) = crypto::generate_keypair();

    println!("Generated quantum-resistant keypair");
    println!("Kyber public key size: {} bytes", kyber_pk.len());
    println!("SPHINCS+ public key size: {} bytes", sphincs_pk.len());

    // Create a test message
    let message = b"This is a test message for offline verification";

    // Sign the message
    let signature = crypto::sign_data(message, &sphincs_sk).expect("Failed to sign message");

    println!("Message signed successfully");
    println!("Signature size: {} bytes", signature.len());

    // Verify the signature
    let verification_result = crypto::verify_signature(message, &signature, &sphincs_pk);

    println!("Signature verification result: {}", verification_result);

    // Hash the message for demonstration using blake3
    let hash = hash(message);
    println!("Message hash: {} bytes", hash.as_bytes().len());

    Ok(())
}
