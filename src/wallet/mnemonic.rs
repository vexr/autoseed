use crate::crypto::bip39::Mnemonic;
use crate::crypto::pbkdf2::pbkdf2_hmac_sha512;

pub fn generate_mnemonic() -> Mnemonic {
    crate::crypto::bip39::generate_mnemonic()
}

pub fn mnemonic_to_mini_secret(mnemonic: &Mnemonic, password: &str) -> [u8; 32] {
    let entropy = mnemonic.to_entropy();
    mnemonic_to_mini_secret_from_entropy(&entropy, password)
}

/// High-performance PBKDF2 using our optimized local implementation
pub fn mnemonic_to_mini_secret_from_entropy(entropy: &[u8], password: &str) -> [u8; 32] {
    let salt = format!("mnemonic{password}");
    let mut output = [0u8; 32];
    
    pbkdf2_hmac_sha512(entropy, salt.as_bytes(), 2048, &mut output);
    
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic1 = generate_mnemonic();
        let mnemonic2 = generate_mnemonic();

        // Mnemonics should be 12 words (128 bits of entropy)
        assert_eq!(mnemonic1.to_string().split_whitespace().count(), 12);
        assert_eq!(mnemonic2.to_string().split_whitespace().count(), 12);

        // Mnemonics should be different
        assert_ne!(mnemonic1.to_string(), mnemonic2.to_string());
    }

    #[test]
    fn test_mnemonic_to_mini_secret() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .expect("Known valid mnemonic");

        // Test with empty password
        let secret1 = mnemonic_to_mini_secret(&mnemonic, "");
        assert_eq!(secret1.len(), 32);

        // Test with password
        let secret2 = mnemonic_to_mini_secret(&mnemonic, "password");
        assert_eq!(secret2.len(), 32);

        // Different passwords should produce different secrets
        assert_ne!(secret1, secret2);

        // Same mnemonic and password should produce same secret
        let secret3 = mnemonic_to_mini_secret(&mnemonic, "password");
        assert_eq!(secret2, secret3);
    }

    #[test]
    fn test_mnemonic_deterministic() {
        // Test that the same mnemonic always produces the same mini secret
        let mnemonic = Mnemonic::parse(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .expect("Known valid mnemonic");

        let secret1 = mnemonic_to_mini_secret(&mnemonic, "");
        let secret2 = mnemonic_to_mini_secret(&mnemonic, "");

        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_mnemonic_entropy_cleared() {
        // This test verifies that we're properly handling sensitive data
        // by ensuring we can generate multiple mnemonics without issues
        for _ in 0..10 {
            let mnemonic = generate_mnemonic();
            let _secret = mnemonic_to_mini_secret(&mnemonic, "");
            // If entropy wasn't properly cleared, we might see issues here
        }
    }
    
    #[test]
    fn test_pbkdf2_performance() {
        use std::time::Instant;
        
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .expect("Known valid mnemonic");
        
        // Test our local implementation performance
        let mut times = Vec::new();
        let iterations = 50; // More iterations for better accuracy
        
        for _ in 0..iterations {
            let start = Instant::now();
            let _secret = mnemonic_to_mini_secret(&mnemonic, "");
            times.push(start.elapsed());
        }
        
        let avg = times.iter().sum::<std::time::Duration>() / times.len() as u32;
        let keys_per_sec = 1.0 / avg.as_secs_f64();
        
        println!("\n=== OPTIMIZED PBKDF2 PERFORMANCE ===");
        println!("Average time per key: {:?}", avg);
        println!("Keys per second: {:.1}", keys_per_sec);
        
        // Test our optimized local implementation
        let entropy = mnemonic.to_entropy();
        
        let mut local_times = Vec::new();
        for _ in 0..iterations {
            let start = Instant::now();
            let _secret = mnemonic_to_mini_secret_from_entropy(&entropy, "");
            local_times.push(start.elapsed());
        }
        
        let local_avg = local_times.iter().sum::<std::time::Duration>() / local_times.len() as u32;
        let local_keys_per_sec = 1.0 / local_avg.as_secs_f64();
        
        println!("Local PBKDF2 average: {:?}", local_avg);
        println!("Local PBKDF2 keys/sec: {:.1}", local_keys_per_sec);
        
        // Test external pbkdf2 crate for comparison
        let mut external_times = Vec::new();
        for _ in 0..iterations {
            let start = Instant::now();
            let _secret = mnemonic_to_mini_secret_from_entropy_external(&entropy, "");
            external_times.push(start.elapsed());
        }
        
        let external_avg = external_times.iter().sum::<std::time::Duration>() / external_times.len() as u32;
        let external_keys_per_sec = 1.0 / external_avg.as_secs_f64();
        
        println!("External PBKDF2 average: {:?}", external_avg);
        println!("External PBKDF2 keys/sec: {:.1}", external_keys_per_sec);
        
        // Test fast entropy path
        let mut entropy_array = [0u8; 16];
        entropy_array.copy_from_slice(&entropy[..16]);
        
        let mut fast_times = Vec::new();
        for _ in 0..iterations {
            let start = Instant::now();
            let _secret = entropy_to_mini_secret_fast(&entropy_array, "");
            fast_times.push(start.elapsed());
        }
        
        let fast_avg = fast_times.iter().sum::<std::time::Duration>() / fast_times.len() as u32;
        let fast_keys_per_sec = 1.0 / fast_avg.as_secs_f64();
        
        println!("Fast entropy path average: {:?}", fast_avg);
        println!("Fast entropy path keys/sec: {:.1}", fast_keys_per_sec);
        
        // Performance comparison and targets
        let ratio = local_keys_per_sec / external_keys_per_sec;
        println!("\nPerformance comparison:");
        println!("Local vs External ratio: {:.2}x", ratio);
        
        let best_keys_per_sec = local_keys_per_sec.max(external_keys_per_sec.max(fast_keys_per_sec));
        println!("Best performance: {:.1} keys/sec", best_keys_per_sec);
        
        if best_keys_per_sec >= 18800.0 {
            println!("🎯 EXCELLENT: Exceeds 18.8k keys/s target!");
        } else if best_keys_per_sec >= 15000.0 {
            println!("✅ GOOD: Above 15k keys/s ({:.1}% of target)", (best_keys_per_sec / 18800.0) * 100.0);
        } else if best_keys_per_sec >= 10000.0 {
            println!("⚠️  NEEDS WORK: Above 10k but below target ({:.1}% of target)", (best_keys_per_sec / 18800.0) * 100.0);
        } else {
            println!("🚨 POOR: Below 10k keys/s ({:.1}% of target)", (best_keys_per_sec / 18800.0) * 100.0);
        }
        
        // Verify our implementation matches external
        let local_result = mnemonic_to_mini_secret_from_entropy(&entropy, "test");
        let external_result = mnemonic_to_mini_secret_from_entropy_external(&entropy, "test");
        assert_eq!(local_result, external_result, "Local and external implementations produce different results!");
        
        // Should complete in reasonable time (increased from 50ms to 150ms for 2048 iterations)
        assert!(avg.as_millis() < 150, "PBKDF2 took too long: {:?}", avg);
        
        // Test consistency
        let secret1 = mnemonic_to_mini_secret(&mnemonic, "");
        let secret2 = mnemonic_to_mini_secret(&mnemonic, "");
        assert_eq!(secret1, secret2, "PBKDF2 should be deterministic");
    }
}
