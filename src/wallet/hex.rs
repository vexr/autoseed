// Use substrate implementations for cryptographic operations
use crate::crypto::substrate::sr25519::{Pair, IdentifyAccount};
use crate::crypto::substrate::crypto::{Ss58Codec, Ss58AddressFormat};


pub fn generate_hex_seed() -> [u8; 32] {
    use crate::crypto::rng::ChaCha20Rng;
    
    thread_local! {
        static RNG: std::cell::RefCell<Option<ChaCha20Rng>> = std::cell::RefCell::new(None);
    }
    
    let mut seed = [0u8; 32];
    
    // Use thread-local cryptographically secure RNG
    RNG.with(|rng_cell| {
        let mut rng_opt = rng_cell.borrow_mut();
        
        // Initialize RNG if not already done
        if rng_opt.is_none() {
            *rng_opt = Some(ChaCha20Rng::from_system_entropy()
                .expect("Failed to initialize cryptographically secure RNG"));
        }
        
        // Generate cryptographically secure entropy
        if let Some(ref mut rng) = *rng_opt {
            rng.fill_bytes(&mut seed);
        }
    });
    
    seed
}



pub fn hex_to_address_with_prefix(seed: &[u8; 32], ss58_prefix: u16) -> String {
    let pair = Pair::from_seed_slice(seed).expect("Failed to create pair from seed");
    let account_id = pair.public().into_account();
    account_id.to_ss58check_with_version(Ss58AddressFormat::custom(ss58_prefix))
}

pub fn seed_to_hex_string(seed: &[u8; 32]) -> String {
    hex::encode(seed)
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hex_to_address_standalone() {
        println!("Testing standalone hex_to_address_with_prefix implementation:");
        
        // Test with known seed
        let seed = [0u8; 32]; // All zeros
        let result = hex_to_address_with_prefix(&seed, 6094);
        
        println!("  Zeros seed address: {}", result);
        
        // Test with different seed
        let seed2 = [42u8; 32];
        let result2 = hex_to_address_with_prefix(&seed2, 6094);
        
        // Different seeds should produce different addresses
        assert_ne!(result, result2, "Different seeds must produce different addresses");
        
        println!("✓ Standalone hex_to_address_with_prefix implementation works correctly");
    }

    #[test]
    fn test_generate_hex_seed() {
        let seed1 = generate_hex_seed();
        let seed2 = generate_hex_seed();

        // Seeds should be 32 bytes
        assert_eq!(seed1.len(), 32);
        assert_eq!(seed2.len(), 32);

        // Seeds should be different (extremely unlikely to be the same)
        assert_ne!(seed1, seed2);

        // Seeds should not be all zeros
        assert_ne!(seed1, [0u8; 32]);
        assert_ne!(seed2, [0u8; 32]);
    }

    #[test]
    fn test_hex_to_address_with_prefix() {
        // Test with a known seed
        let seed = [1u8; 32];
        let address = hex_to_address_with_prefix(&seed, 6094);

        // Address should start with expected prefix for Autonomys Network
        assert!(address.starts_with("su"));
        assert!(address.len() > 40); // Substrate addresses are typically 47-48 chars
    }

    #[test]
    fn test_seed_to_hex_string_and_back() {
        let original_seed = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x0f, 0x1e, 0x2d, 0x3c,
            0x4b, 0x5a, 0x69, 0x78,
        ];

        let hex_string = seed_to_hex_string(&original_seed);
        assert_eq!(hex_string.len(), 64); // 32 bytes * 2 chars per byte

        let recovered_seed = hex_string_to_seed(&hex_string).unwrap();
        assert_eq!(original_seed, recovered_seed);
    }

    #[test]
    fn test_hex_string_to_seed_errors() {
        // Test invalid hex
        assert!(hex_string_to_seed("invalid_hex").is_err());
        assert!(hex_string_to_seed("zz").is_err());

        // Test wrong length
        assert!(hex_string_to_seed("1234").is_err()); // Too short
        assert!(hex_string_to_seed(&"00".repeat(33)).is_err()); // Too long (66 chars)
        assert!(hex_string_to_seed(&"00".repeat(31)).is_err()); // Too short (62 chars)

        // Test valid length passes
        assert!(hex_string_to_seed(&"00".repeat(32)).is_ok()); // Exactly 64 chars
    }

    #[test]
    fn test_address_deterministic() {
        // Same seed should always produce same address
        let seed = [42u8; 32];
        let address1 = hex_to_address_with_prefix(&seed, 6094);
        let address2 = hex_to_address_with_prefix(&seed, 6094);
        assert_eq!(address1, address2);
    }
}
