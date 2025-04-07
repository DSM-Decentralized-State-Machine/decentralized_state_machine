#[cfg(test)]
mod tests {
    use crate::common::{
        constants, helpers, pq, HASH_LENGTH, KEY_SIZE, MAX_BUFFER_SIZE, PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
    };

    #[test]
    fn test_constants() {
        assert_eq!(PROTOCOL_VERSION, "0.1.0");
        assert_eq!(HASH_LENGTH, 32); // 256-bit hash length for quantum resistance
        assert_eq!(KEY_SIZE, 32); // 256-bit key size for quantum resistance
        assert_eq!(MAX_BUFFER_SIZE, 4096);
        assert_eq!(PROTOCOL_MAGIC, [0x53, 0x45, 0x43, 0x49]); // "SECI" magic bytes
    }

    #[test]
    fn test_constants_module() {
        assert_eq!(constants::DEFAULT_TIMEOUT_MS, 30_000);
        assert_eq!(constants::RETRY_DELAY_MS, 5_000);
        assert_eq!(constants::MAX_RETRIES, 3);
        assert_eq!(constants::DEFAULT_PORT, 8421);
        assert_eq!(constants::DEFAULT_BUFFER_SIZE, 8_192);
        assert_eq!(constants::DEFAULT_DB_PATH, "./seci_data");
        assert_eq!(constants::MIN_PASSWORD_LENGTH, 12);
        assert_eq!(constants::DEFAULT_KEY_DERIVATION_ITERATIONS, 100_000);
    }

    #[test]
    fn test_pq_module() {
        assert_eq!(pq::KYBER_PUBLIC_KEY_SIZE, 1184);
        assert_eq!(pq::KYBER_SECRET_KEY_SIZE, 2400);
        assert_eq!(pq::SPHINCSPLUS_PUBLIC_KEY_SIZE, 32);
        assert_eq!(pq::SPHINCSPLUS_SECRET_KEY_SIZE, 64);
        assert_eq!(pq::SPHINCSPLUS_SIGNATURE_SIZE, 7856);
    }

    #[test]
    fn test_helpers_is_all_zeros() {
        assert!(helpers::is_all_zeros(&[0, 0, 0]));
        assert!(!helpers::is_all_zeros(&[0, 1, 0]));
    }

    #[test]
    fn test_helpers_hex_to_bytes() {
        assert_eq!(
            helpers::hex_to_bytes("48656c6c6f"),
            Some(vec![72, 101, 108, 108, 111])
        );
        assert_eq!(helpers::hex_to_bytes("48656c6c6f7"), None);
    }

    #[test]
    fn test_helpers_bytes_to_hex() {
        assert_eq!(
            helpers::bytes_to_hex(&[72, 101, 108, 108, 111]),
            "48656c6c6f"
        );
    }
}
