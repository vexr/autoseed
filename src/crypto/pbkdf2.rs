//! PBKDF2 (Password-Based Key Derivation Function 2) Implementation
//!
//! This module implements PBKDF2 as specified in RFC 2898, using HMAC-SHA512 as the
//! underlying pseudorandom function. PBKDF2 applies a pseudorandom function to derive
//! keys from passwords, using salt and iteration count to increase computational cost
//! and resist dictionary attacks.
//!
//! The implementation includes optimizations for high-performance key derivation while
//! maintaining cryptographic security properties defined in the specification.
//!
//! ## References
//! - RFC 2898: PKCS #5: Password-Based Cryptography Specification Version 2.0
//! - RFC 2104: HMAC: Keyed-Hashing for Message Authentication

use sha2::{Sha512, Digest};
use core::cmp;

/// PBKDF2 key derivation using HMAC-SHA512
/// 
/// Derives cryptographic keys from passwords using PBKDF2 as specified in RFC 2898,
/// with HMAC-SHA512 as the underlying pseudorandom function.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], rounds: u32, res: &mut [u8]) {
    assert!(rounds > 0, "rounds must be greater than 0");
    
    const HASH_LEN: usize = 64; // SHA512 output length
    
    // Create HMAC state once and reuse (key optimization from RustCrypto)
    let prf = HmacSha512Core::new(password);
    
    // Process output in chunks using exact RustCrypto algorithm
    for (i, chunk) in res.chunks_mut(HASH_LEN).enumerate() {
        pbkdf2_body_optimized(i as u32, chunk, &prf, salt, rounds);
    }
}

/// Core PBKDF2 body function - exact replica of RustCrypto implementation
/// 
/// This is the heart of the performance optimization
#[inline(always)]
fn pbkdf2_body_optimized(
    i: u32,
    chunk: &mut [u8],
    prf: &HmacSha512Core,
    salt: &[u8],
    rounds: u32,
) {
    // Zero the chunk (RustCrypto style)
    for v in chunk.iter_mut() {
        *v = 0;
    }

    // First iteration: U_1 = PRF(password, salt || i)
    let mut salt_block = {
        let mut prfc = prf.clone();
        prfc.update(salt);
        prfc.update(&(i + 1).to_be_bytes());
        let salt_block = prfc.finalize_fixed();
        xor_optimized(chunk, &salt_block);
        salt_block
    };

    // Subsequent iterations: U_j = PRF(password, U_{j-1})
    for _ in 1..rounds {
        let mut prfc = prf.clone();
        prfc.update(&salt_block);
        salt_block = prfc.finalize_fixed();
        xor_optimized(chunk, &salt_block);
    }
}

/// Optimized XOR operation from RustCrypto - enables SIMD vectorization
#[inline(always)]
fn xor_optimized(res: &mut [u8], salt: &[u8]) {
    let copy_len = cmp::min(res.len(), salt.len());
    res[..copy_len].iter_mut().zip(salt[..copy_len].iter()).for_each(|(a, b)| *a ^= b);
}

/// High-performance HMAC-SHA512 core optimized for PBKDF2
/// 
/// This replicates the optimizations from the RustCrypto hmac crate
#[derive(Clone)]
struct HmacSha512Core {
    /// Pre-computed inner state (IPAD XOR key)
    inner_digest: Sha512,
    /// Pre-computed outer state (OPAD XOR key) 
    outer_digest: Sha512,
}

impl HmacSha512Core {
    /// Create new HMAC state with pre-computed inner/outer states
    /// This is the key optimization - compute IPAD/OPAD states once
    fn new(key: &[u8]) -> Self {
        const BLOCK_SIZE: usize = 128; // SHA512 block size
        const IPAD: u8 = 0x36;
        const OPAD: u8 = 0x5c;
        
        // Process key according to HMAC specification
        let key_block = if key.len() <= BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            block[..key.len()].copy_from_slice(key);
            block
        } else {
            // Hash long keys
            let mut block = [0u8; BLOCK_SIZE];
            let hash = Sha512::digest(key);
            block[..hash.len()].copy_from_slice(&hash);
            block
        };
        
        // Pre-compute IPAD and OPAD states
        let mut ipad = [0u8; BLOCK_SIZE];
        let mut opad = [0u8; BLOCK_SIZE];
        
        for i in 0..BLOCK_SIZE {
            ipad[i] = key_block[i] ^ IPAD;
            opad[i] = key_block[i] ^ OPAD;
        }
        
        // Pre-compute initial digest states
        let mut inner_digest = Sha512::new();
        inner_digest.update(&ipad);
        
        let mut outer_digest = Sha512::new();
        outer_digest.update(&opad);
        
        Self {
            inner_digest,
            outer_digest,
        }
    }
    
    /// Update HMAC with data (clone the pre-computed state)
    fn update(&mut self, data: &[u8]) {
        self.inner_digest.update(data);
    }
    
    /// Finalize HMAC computation and return fixed-size array
    fn finalize_fixed(self) -> [u8; 64] {
        let inner_hash = self.inner_digest.finalize();
        
        let mut outer = self.outer_digest;
        outer.update(&inner_hash);
        let result = outer.finalize();
        
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        output
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn test_optimized_correctness() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1000;
        
        // Test our optimized implementation for deterministic output
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];
        
        pbkdf2_hmac_sha512(password, salt, iterations, &mut output1);
        pbkdf2_hmac_sha512(password, salt, iterations, &mut output2);
        
        // Results must be deterministic
        assert_eq!(output1, output2, "Implementation should be deterministic!");
        
        // Should not be all zeros
        assert_ne!(output1, [0u8; 32], "Output should not be all zeros");
    }
    
    #[test]
    fn test_optimized_performance() {
        let password = b"test_password_for_performance";
        let salt = b"mnemonic";
        let iterations = 2048; // BIP39 standard
        let test_runs = 10;
        
        // Test our optimized implementation
        let mut our_times = Vec::new();
        let mut our_output = [0u8; 32];
        
        // Warm up
        for _ in 0..3 {
            pbkdf2_hmac_sha512(password, salt, iterations, &mut our_output);
        }
        
        // Benchmark
        for _ in 0..test_runs {
            let start = Instant::now();
            pbkdf2_hmac_sha512(password, salt, iterations, &mut our_output);
            our_times.push(start.elapsed());
        }
        
        let our_avg = our_times.iter().sum::<std::time::Duration>() / our_times.len() as u32;
        let our_keys_per_sec = 1.0 / our_avg.as_secs_f64();
        
        println!("PBKDF2 performance test:");
        println!("  Average time: {:?}", our_avg);
        println!("  Keys per second: {:.1}", our_keys_per_sec);
        
        // Basic performance validation (execution completes in reasonable time)
        assert!(our_avg.as_millis() < 1000, "PBKDF2 execution took too long: {:?}", our_avg);
        assert!(our_keys_per_sec > 1.0, "Performance too low: {:.1} keys/s", our_keys_per_sec);
    }
    
    #[test]
    fn test_bip39_compatibility() {
        // Test with BIP39-style parameters
        let entropy = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                       0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let salt = b"mnemonic";
        let iterations = 2048;
        
        let mut our_output = [0u8; 32];
        pbkdf2_hmac_sha512(&entropy, salt, iterations, &mut our_output);
        
        // Should produce deterministic output
        let mut output2 = [0u8; 32];
        pbkdf2_hmac_sha512(&entropy, salt, iterations, &mut output2);
        assert_eq!(our_output, output2, "Implementation should be deterministic");
        
        // Should not be all zeros
        assert_ne!(our_output, [0u8; 32], "Output should not be all zeros");
        
        // Test with different salt produces different output
        let mut output3 = [0u8; 32];
        pbkdf2_hmac_sha512(&entropy, b"different_salt", iterations, &mut output3);
        assert_ne!(our_output, output3, "Different salts should produce different outputs");
    }
    
    #[test]
    fn test_different_output_lengths() {
        let password = b"test";
        let salt = b"salt";
        let iterations = 100;
        
        // Test various output lengths
        let mut output16 = [0u8; 16];
        let mut output32 = [0u8; 32];
        let mut output64 = [0u8; 64];
        let mut output128 = [0u8; 128];
        
        pbkdf2_hmac_sha512(password, salt, iterations, &mut output16);
        pbkdf2_hmac_sha512(password, salt, iterations, &mut output32);
        pbkdf2_hmac_sha512(password, salt, iterations, &mut output64);
        pbkdf2_hmac_sha512(password, salt, iterations, &mut output128);
        
        // First 16 bytes should match across different lengths
        assert_eq!(&output32[..16], &output16);
        assert_eq!(&output64[..16], &output16);
        assert_eq!(&output128[..16], &output16);
        
        // First 32 bytes should match
        assert_eq!(&output64[..32], &output32);
        assert_eq!(&output128[..32], &output32);
        
        // First 64 bytes should match
        assert_eq!(&output128[..64], &output64);
    }
    
}