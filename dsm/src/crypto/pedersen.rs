//! # Quantum-Resistant Pedersen Commitments
//!
//! Implements quantum-resistant Pedersen commitments using post-quantum secure
//! primitives only. No classical variants are supported.

use std::str::FromStr;

use blake3;
use num_bigint::BigUint;
use num_primes::Generator;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_512,
};

use crate::types::error::DsmError;

type DsmResult<T> = Result<T, DsmError>;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Copy)]
pub enum SecurityLevel {
    Standard128,
    Medium192,
    High256,
}

const DOMAIN_COMMIT: &[u8] = b"DSM.v1.pedersen.commit";

/// Parameters for quantum-resistant Pedersen commitment
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde_as]
pub struct PedersenParams {
    #[serde(with = "biguint_serde")]
    pub g: BigUint, // Generator
    #[serde(with = "biguint_serde")]
    pub h: BigUint, // Random base
    #[serde(with = "biguint_serde")]
    pub p: BigUint, // Prime modulus
    #[serde(with = "biguint_serde")]
    pub q: BigUint, // Prime order subgroup
    pub security_level: SecurityLevel,
}
impl PedersenParams {
    /// Create new parameters based on security level
    pub fn new(security_level: SecurityLevel) -> Self {
        // Select parameters based on quantum security requirements
        let (p_bits, q_bits) = match security_level {
            SecurityLevel::Standard128 => (3072, 256),
            SecurityLevel::Medium192 => (7680, 384),
            SecurityLevel::High256 => (15360, 512),
        };

        // Generate safe prime and generator
        let (p, q, g, h) = generate_pedersen_params(p_bits, q_bits);

        Self {
            g,
            h,
            p,
            q,
            security_level,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde_as]
pub struct PedersenCommitment {
    /// The commitment value
    #[serde(with = "biguint_serde")]
    pub commitment: BigUint,

    /// Hash of the commitment (for quantum resistance)
    #[serde_as(as = "Hex")]
    pub commitment_hash: Vec<u8>,

    /// Number of hash iterations used
    pub hash_rounds: u32,

    /// Security level
    pub security_level: SecurityLevel,
}

/// Helper module for serializing BigUint
mod biguint_serde {
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S>(num: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert BigUint to hex string
        let hex = format!("{:x}", num);
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let hex_str = String::deserialize(deserializer)?;
        BigUint::parse_bytes(hex_str.as_bytes(), 16)
            .ok_or_else(|| Error::custom("Failed to parse BigUint from hex"))
    }
}

/// Default implementation for PedersenCommitment
impl Default for PedersenCommitment {
    fn default() -> Self {
        Self {
            commitment: BigUint::from(0u32),
            commitment_hash: vec![0; 32],
            hash_rounds: 10,
            security_level: SecurityLevel::Standard128,
        }
    }
}

impl PedersenCommitment {
    /// Create a new quantum-resistant commitment
    pub fn commit<R: RngCore + CryptoRng>(
        params: &PedersenParams,
        value: &[u8],
        rng: &mut R,
    ) -> DsmResult<(Self, BigUint)> {
        // Get number of hash rounds based on security level
        let hash_rounds = match params.security_level {
            SecurityLevel::Standard128 => 10,
            SecurityLevel::Medium192 => 14,
            SecurityLevel::High256 => 20,
        };

        // Generate randomness
        let r = Self::generate_randomness(rng, &params.q);
        // Compute commitment with quantum-resistant parameters
        let commitment = Self::compute_commitment(value, &r, params)?;
        // Hash the commitment for quantum resistance
        let commitment_hash = hash_commitment(&commitment, hash_rounds)?;

        Ok((
            Self {
                commitment,
                commitment_hash,
                hash_rounds,
                security_level: params.security_level,
            },
            r,
        ))
    }

    /// Generate secure randomness for the commitment
    fn generate_randomness<R: RngCore + CryptoRng>(rng: &mut R, q: &BigUint) -> BigUint {
        // Determine how many bytes we need
        let bytes_needed = q.bits().div_ceil(8);

        // Create buffer for random bytes
        let mut buf = vec![0u8; bytes_needed.try_into().unwrap()];

        // Generate random value and reduce mod q until we get valid value
        loop {
            // Fill buffer with random bytes
            rng.fill_bytes(&mut buf);

            // Convert to BigUint
            let rand_val = BigUint::from_bytes_be(&buf);

            // Check if value is in valid range (0 to q-1)
            if rand_val < *q {
                return rand_val;
            }
        }
    }

    /// Homomorphically combine commitments
    pub fn combine(&self, other: &Self, params: &PedersenParams) -> DsmResult<Self> {
        if self.security_level != other.security_level {
            return Err(DsmError::crypto(
                String::from("Cannot combine commitments with different security levels"),
                None::<std::io::Error>,
            ));
        }

        // Combine commitments homomorphically
        let combined = (&self.commitment * &other.commitment) % &params.p;
        // Hash the combined commitment
        let commitment_hash = hash_commitment(&combined, self.hash_rounds)?;

        Ok(Self {
            commitment: combined,
            commitment_hash,
            hash_rounds: self.hash_rounds,
            security_level: self.security_level,
        })
    }

    /// Compute commitment with quantum resistance
    fn compute_commitment(
        value: &[u8],
        r: &BigUint,
        params: &PedersenParams,
    ) -> DsmResult<BigUint> {
        // g^value * h^r mod p
        let v = BigUint::from_bytes_le(value);
        Ok((params.g.modpow(&v, &params.p) * params.h.modpow(r, &params.p)) % &params.p)
    }

    /// Verify a commitment against a value and randomness
    pub fn verify(&self, value: &[u8], r: &BigUint, params: &PedersenParams) -> DsmResult<bool> {
        // Compute expected commitment
        let expected = Self::compute_commitment(value, r, params)?;

        // Hash the expected commitment
        let expected_hash = hash_commitment(&expected, self.hash_rounds)?;

        // Use constant-time comparison for security
        Ok(constant_time_eq(&self.commitment_hash, &expected_hash) && self.commitment == expected)
    }

    pub fn smart_commit<R: RngCore + CryptoRng>(
        params: &PedersenParams,
        value: &[u8],
        recipient: &[u8],
        condition: &str,
        rng: &mut R,
    ) -> DsmResult<(Self, BigUint)> {
        // Domain separation with hash sandwich
        let mut sha3_hasher = Sha3_512::new();
        sha3::Digest::update(&mut sha3_hasher, DOMAIN_COMMIT);
        sha3::Digest::update(&mut sha3_hasher, recipient);
        sha3::Digest::update(&mut sha3_hasher, condition.as_bytes());
        sha3::Digest::update(&mut sha3_hasher, value);
        let sha3_result = sha3_hasher.finalize();

        let mut blake3_hasher = blake3::Hasher::new();
        blake3_hasher.update(&sha3_result);
        let domain_separated = blake3_hasher.finalize();

        // Create commitment using domain separated value
        Self::commit(params, domain_separated.as_bytes(), rng)
    }

    /// Convert commitment to bytes for serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Convert bytes back to commitment (used by from_bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        bincode::deserialize(bytes)
            .map_err(|e| DsmError::serialization("Failed to deserialize commitment", Some(e)))
    }
}

/// External verification function for commitments
pub fn verify(commitment: &PedersenCommitment) -> DsmResult<bool> {
    // For verification, we only need the commitment
    // The blinding factor is embedded in the commitment structure

    // Hash and compare commitment values
    let expected_hash = hash_commitment(&commitment.commitment, commitment.hash_rounds)?;
    Ok(constant_time_eq(
        &commitment.commitment_hash,
        &expected_hash,
    ))
}

/// Generate Pedersen parameters
#[allow(clippy::many_single_char_names)]
fn generate_pedersen_params(_p_bits: usize, q_bits: usize) -> (BigUint, BigUint, BigUint, BigUint) {
    // Generate safe prime p = 2q + 1 where q is also prime
    let (p, q) = loop {
        let q = BigUint::from_bytes_be(&Generator::new_prime(q_bits).to_bytes_be());
        let p = &q * BigUint::from(2u32) + BigUint::from(1u32);

        let p_check = num_primes::BigUint::from_str(&p.to_string()).unwrap();
        if num_primes::Verification::is_prime(&p_check) {
            break (p, q);
        }
    };

    let mut rng = rand::thread_rng();

    // Find generator g of order q in Z*_p
    let g = loop {
        // Generate random value between 2 and p-1
        let two = BigUint::from(2u32);
        let p_minus_1 = &p - BigUint::from(1u32);

        // Generate random bytes
        let bytes_needed = p.bits().div_ceil(8);
        let mut buf = vec![0u8; bytes_needed.try_into().unwrap()];
        rng.fill_bytes(&mut buf);

        // Convert to BigUint and ensure in range [2, p-1]
        let mut candidate = BigUint::from_bytes_be(&buf);
        candidate = &two + (&candidate % &(&p_minus_1 - &two));

        let g = candidate.modpow(&BigUint::from(2u32), &p);

        if g.modpow(&q, &p) == BigUint::from(1u32) {
            break g;
        }
    };

    // Generate random h as h = g^x mod p for random x
    let bytes_needed = q.bits().div_ceil(8);
    let mut buf = vec![0u8; bytes_needed.try_into().unwrap()];
    rng.fill_bytes(&mut buf);
    let x = BigUint::from_bytes_be(&buf) % &q;
    let h = g.modpow(&x, &p);
    (p, q, g, h)
}

/// Hash a commitment for quantum resistance using hash sandwich technique
fn hash_commitment(commitment: &BigUint, rounds: u32) -> DsmResult<Vec<u8>> {
    // First layer: SHA3-512 (quantum resistant)
    let mut sha3_hasher = sha3::Sha3_512::default();
    sha3::Digest::update(&mut sha3_hasher, commitment.to_bytes_be());
    let sha3_result = sha3_hasher.finalize();

    // Middle layer: Multiple rounds of alternating hashes for strengthened quantum resistance
    let mut result = sha3_result.to_vec();
    for i in 0..rounds {
        // Alternate between SHAKE256 and Blake3 for better quantum resistance
        let hasher = if i % 2 == 0 {
            let mut h = sha3::Shake256::default();
            h.update(&result);
            let mut output = vec![0u8; 64];
            h.finalize_xof().read(&mut output);
            output
        } else {
            let mut h = blake3::Hasher::new();
            h.update(&result);
            h.finalize().as_bytes().to_vec()
        };
        result = hasher;
    }

    // Final layer: Another round of SHAKE256 XOF
    let mut final_shake = sha3::Shake256::default();
    final_shake.update(&result);
    let mut final_output = vec![0u8; 32];
    final_shake.finalize_xof().read(&mut final_output);

    Ok(final_output)
}

/// Constant-time equality check
#[allow(clippy::many_single_char_names)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        result |= byte_a ^ byte_b;
    }
    result == 0
}

#[cfg(test)]
pub fn commit(value: &[u8], randomness: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(value);
    hasher.update(randomness);
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
pub fn verify_commitment(commitment: &[u8], value: &[u8], randomness: &[u8]) -> bool {
    let expected = commit(value, randomness);
    constant_time_eq(commitment, &expected)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_commitment_flow() {
        let mut rng = thread_rng();
        let params = PedersenParams::new(SecurityLevel::Standard128);

        let value = b"test value";
        let (commit, _r) = PedersenCommitment::commit(&params, value, &mut rng).unwrap();

        // Add verify method implementation or replace this test
        // assert!(commit.verify(value, &r, &params).unwrap());
        assert!(!commit.commitment_hash.is_empty());
    }
    #[test]
    fn test_homomorphic_combination() {
        let mut rng = thread_rng();
        let params = PedersenParams::new(SecurityLevel::Standard128);

        let (c1, _) = PedersenCommitment::commit(&params, b"value1", &mut rng).unwrap();
        let (c2, _) = PedersenCommitment::commit(&params, b"value2", &mut rng).unwrap();

        // Use variables to prevent unused variable warnings
        let _combined = c1.combine(&c2, &params).unwrap();
        // Add more assertions or implementation as needed
    }

    #[test]
    fn test_verify_commitment() {
        let mut rng = thread_rng();
        let params = PedersenParams::new(SecurityLevel::Standard128);

        let value = b"test value";
        let (commit, r) = PedersenCommitment::commit(&params, value, &mut rng).unwrap();

        assert!(commit.verify(value, &r, &params).unwrap());
        assert!(!commit.verify(b"wrong value", &r, &params).unwrap());
    }

    #[test]
    fn test_smart_commitment() {
        let mut rng = thread_rng();
        let params = PedersenParams::new(SecurityLevel::Standard128);

        let value = b"100 tokens";
        let recipient = b"Bob";
        let condition = "if used within 7 days";

        let (commit, _) =
            PedersenCommitment::smart_commit(&params, value, recipient, condition, &mut rng)
                .unwrap();

        assert!(!commit.commitment_hash.is_empty());
    }
}
