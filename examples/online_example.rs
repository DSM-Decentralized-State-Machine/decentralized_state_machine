// DSM Online Example
// This example demonstrates encrypted communication using DSM

use dsm::{crypto, types::error::DsmError};

fn main() -> Result<(), DsmError> {
    println!("DSM Online Communication Example");

    // === Alice's side ===
    // Generate Alice's key pair
    let (_alice_kyber_pk, _alice_kyber_sk, alice_sphincs_pk, alice_sphincs_sk) =
        crypto::generate_keypair();

    println!("Alice generated her quantum-resistant keypair");

    // === Bob's side ===
    // Generate Bob's key pair
    let (bob_kyber_pk, bob_kyber_sk, _bob_sphincs_pk, _bob_sphincs_sk) = crypto::generate_keypair();

    println!("Bob generated his quantum-resistant keypair");

    // === Key Exchange ===
    // In a real scenario, Alice and Bob would exchange their public keys securely

    // === Alice sends a message to Bob ===
    let message = b"Hello Bob, this is a secret message from Alice!";

    // Alice signs the message with her private key
    let signature = crypto::sign_data(message, &alice_sphincs_sk).expect("Failed to sign message");

    // Alice encrypts the message and signature using Bob's public key
    let mut combined = Vec::with_capacity(message.len() + signature.len() + 4);

    // Add message length as a 4-byte prefix
    let msg_len = (message.len() as u32).to_le_bytes();
    combined.extend_from_slice(&msg_len);

    // Add message
    combined.extend_from_slice(message);

    // Add signature
    combined.extend_from_slice(&signature);

    // Encrypt the combined data
    let encrypted =
        crypto::encrypt_for_recipient(&bob_kyber_pk, &combined).expect("Failed to encrypt message");

    println!("Alice encrypted and signed a message for Bob");

    // === Bob receives and decrypts the message ===
    // Bob decrypts the message using his private key
    let decrypted =
        crypto::decrypt_from_sender(&bob_kyber_sk, &encrypted).expect("Failed to decrypt message");

    // Extract message and signature
    let msg_len_bytes = &decrypted[0..4];
    let mut msg_len_array = [0u8; 4];
    msg_len_array.copy_from_slice(msg_len_bytes);
    let msg_len = u32::from_le_bytes(msg_len_array) as usize;

    let received_message = &decrypted[4..4 + msg_len];
    let received_signature = &decrypted[4 + msg_len..];

    // Bob verifies the signature using Alice's public key
    let verified =
        crypto::verify_signature(received_message, received_signature, &alice_sphincs_pk);

    println!("Bob decrypted the message and verified Alice's signature");
    println!("Signature verification result: {}", verified);

    if verified {
        println!(
            "Message from Alice: {}",
            String::from_utf8_lossy(received_message)
        );
    } else {
        println!("Warning: The message signature could not be verified!");
    }

    Ok(())
}
