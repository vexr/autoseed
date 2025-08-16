pub mod parallel;

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VanityResult {
    #[zeroize(skip)]
    pub address: String,
    pub secret: String, // Either mnemonic or hex
    #[zeroize(skip)]
    pub matches: usize,
    #[zeroize(skip)]
    pub offset: usize,
    #[zeroize(skip)]
    pub attempts: u64, // Number of attempts to find this result
    #[zeroize(skip)]
    pub ss58_prefix: u16, // Network prefix used to generate this address
}

pub struct GenerationStats {
    pub total_attempts: u64,
    pub elapsed_secs: u64,
    pub elapsed_nanos: u128, // Store nanoseconds for maximum precision
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_vanity_result_hex_mode() {
        // Create a valid hex result
        let seed = [42u8; 32];
        let hex_secret = hex::encode(seed);
        let address = crate::wallet::hex_to_address_with_prefix(&seed, 6094);

        let result = VanityResult {
            address: address.clone(),
            secret: hex_secret,
            matches: 3,
            offset: 2,
            attempts: 1000,
            ss58_prefix: 6094, // Autonomys Network
        };

        // Should verify successfully
        assert!(verify_vanity_result(&result, true));

        // Test with wrong address
        let mut wrong_result = result.clone();
        wrong_result.address = "suWrongAddress123".to_string();
        assert!(!verify_vanity_result(&wrong_result, true));

        // Test with invalid hex
        let mut invalid_hex_result = result.clone();
        invalid_hex_result.secret = "invalid_hex".to_string();
        assert!(!verify_vanity_result(&invalid_hex_result, true));
    }

    #[test]
    fn test_verify_vanity_result_mnemonic_mode() {
        use crate::crypto::bip39::Mnemonic;

        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .expect("Known valid mnemonic");
        let address = crate::crypto::mnemonic_to_address_with_prefix(&mnemonic, 6094);

        let result = VanityResult {
            address: address.clone(),
            secret: mnemonic.to_string(),
            matches: 3,
            offset: 2,
            attempts: 1000,
            ss58_prefix: 6094, // Autonomys Network
        };

        // Should verify successfully
        assert!(verify_vanity_result(&result, false));

        // Test with wrong address
        let mut wrong_result = result.clone();
        wrong_result.address = "suWrongAddress123".to_string();
        assert!(!verify_vanity_result(&wrong_result, false));

        // Test with invalid mnemonic
        let mut invalid_mnemonic_result = result.clone();
        invalid_mnemonic_result.secret = "invalid mnemonic words".to_string();
        assert!(!verify_vanity_result(&invalid_mnemonic_result, false));
    }

    #[test]
    fn test_vanity_result_zeroize() {
        let mut result = VanityResult {
            address: "suTestAddress123".to_string(),
            secret: "test secret key".to_string(),
            matches: 3,
            offset: 2,
            attempts: 1000,
            ss58_prefix: 6094, // Autonomys Network
        };

        // Clone the secret to verify it gets zeroized
        let secret_copy = result.secret.clone();

        // Manually zeroize
        result.secret.zeroize();

        // Secret should be empty (zeroized)
        assert_eq!(result.secret, "");
        assert_ne!(result.secret, secret_copy);

        // Address should not be zeroized (has skip attribute)
        assert_eq!(result.address, "suTestAddress123");
    }

    #[test]
    fn test_generation_stats() {
        let stats = GenerationStats {
            total_attempts: 1_000_000,
            elapsed_secs: 60,
            elapsed_nanos: 60_000_000_000,
        };

        assert_eq!(stats.total_attempts, 1_000_000);
        assert_eq!(stats.elapsed_secs, 60);
        assert_eq!(stats.elapsed_nanos, 60_000_000_000);
    }
}
