//! ChaCha20 Stream Cipher and Cryptographically Secure PRNG Implementation
//!
//! This module implements the ChaCha20 stream cipher algorithm designed by 
//! Daniel J. Bernstein. ChaCha20 operates on 512-bit blocks using a 256-bit key 
//! and 64-bit nonce, producing a cryptographically secure keystream through 20 
//! rounds of quarter-round operations.
//!
//! The implementation provides both a CSPRNG interface and cross-platform system 
//! entropy collection, prioritizing security and performance with constant-time 
//! operations resistant to timing attacks.
//!
//! ## References
//! - ChaCha20 specification: RFC 8439
//! - Original ChaCha design: Daniel J. Bernstein (2008)
//! - "ChaCha, a variant of Salsa20" - D. J. Bernstein
//!
//! ## Copyright Notice
//! ChaCha20 algorithm designed by Daniel J. Bernstein.
//! This implementation follows the public domain algorithm specification.

#[cfg(unix)]
use std::io::Read;

/// Error types for RNG operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// Failed to collect system entropy
    EntropyCollection,
    /// IO error during entropy collection
    #[cfg(unix)]
    IoError,
}

impl std::fmt::Display for RngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RngError::EntropyCollection => write!(f, "failed to collect system entropy"),
            #[cfg(unix)]
            RngError::IoError => write!(f, "IO error during entropy collection"),
        }
    }
}

impl std::error::Error for RngError {}

/// ChaCha20-based cryptographically secure pseudo-random number generator
/// 
/// This implementation provides a drop-in replacement for rand_core functionality
/// while being completely self-contained with no external dependencies.
#[derive(Clone)]
pub struct ChaCha20Rng {
    /// ChaCha20 internal state (16 x 32-bit words)
    state: [u32; 16],
    /// Block counter for stream generation
    counter: u64,
    /// Output buffer (64 bytes per ChaCha20 block)
    buffer: [u8; 64],
    /// Current position in output buffer
    buffer_pos: usize,
}

impl ChaCha20Rng {
    /// ChaCha20 constants: "expand 32-byte k" in little-endian
    const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    
    /// Create a new ChaCha20Rng from a 256-bit seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut state = [0u32; 16];
        
        // Set ChaCha20 constants
        state[0..4].copy_from_slice(&Self::CONSTANTS);
        
        // Set 256-bit key from seed
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            state[4 + i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        
        // Initialize counter and nonce to zero
        state[12] = 0; // counter (low 32 bits)
        state[13] = 0; // counter (high 32 bits) 
        state[14] = 0; // nonce (low 32 bits)
        state[15] = 0; // nonce (high 32 bits)
        
        Self {
            state,
            counter: 0,
            buffer: [0; 64],
            buffer_pos: 64, // Force initial block generation
        }
    }
    
    /// Create a new ChaCha20Rng using system entropy
    pub fn from_system_entropy() -> Result<Self, RngError> {
        let seed = collect_system_entropy()?;
        Ok(Self::from_seed(seed))
    }
    
    
    
    /// ChaCha20 quarter-round function using array indices to avoid borrow checker issues
    #[inline(always)]
    fn quarter_round_indexed(state: &mut [u32; 16], ai: usize, bi: usize, ci: usize, di: usize) {
        state[ai] = state[ai].wrapping_add(state[bi]); 
        state[di] ^= state[ai]; 
        state[di] = state[di].rotate_left(16);
        
        state[ci] = state[ci].wrapping_add(state[di]); 
        state[bi] ^= state[ci]; 
        state[bi] = state[bi].rotate_left(12);
        
        state[ai] = state[ai].wrapping_add(state[bi]); 
        state[di] ^= state[ai]; 
        state[di] = state[di].rotate_left(8);
        
        state[ci] = state[ci].wrapping_add(state[di]); 
        state[bi] ^= state[ci]; 
        state[bi] = state[bi].rotate_left(7);
    }
    
    /// Generate a 64-byte block of random data using ChaCha20
    fn generate_block(&mut self) {
        let mut working_state = self.state;
        
        // Perform 20 rounds (10 double rounds) of ChaCha20
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round_indexed(&mut working_state, 0, 4, 8, 12);
            Self::quarter_round_indexed(&mut working_state, 1, 5, 9, 13);
            Self::quarter_round_indexed(&mut working_state, 2, 6, 10, 14);
            Self::quarter_round_indexed(&mut working_state, 3, 7, 11, 15);
            
            // Diagonal rounds
            Self::quarter_round_indexed(&mut working_state, 0, 5, 10, 15);
            Self::quarter_round_indexed(&mut working_state, 1, 6, 11, 12);
            Self::quarter_round_indexed(&mut working_state, 2, 7, 8, 13);
            Self::quarter_round_indexed(&mut working_state, 3, 4, 9, 14);
        }
        
        // Add original state to working state (key stream generation)
        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }
        
        // Convert 32-bit words to bytes in little-endian format
        for (i, &word) in working_state.iter().enumerate() {
            let bytes = word.to_le_bytes();
            self.buffer[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        
        // Increment block counter for next generation
        self.counter += 1;
        self.state[12] = (self.counter & 0xFFFFFFFF) as u32;
        self.state[13] = (self.counter >> 32) as u32;
        
        // Reset buffer position
        self.buffer_pos = 0;
    }
    
    
    /// Fill a buffer with random bytes
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        
        while offset < dest.len() {
            if self.buffer_pos >= 64 {
                self.generate_block();
            }
            
            let available = 64 - self.buffer_pos;
            let needed = dest.len() - offset;
            let to_copy = available.min(needed);
            
            dest[offset..offset + to_copy].copy_from_slice(
                &self.buffer[self.buffer_pos..self.buffer_pos + to_copy]
            );
            
            self.buffer_pos += to_copy;
            offset += to_copy;
        }
    }
    
}

/// Cross-platform system entropy collection
/// 
/// This function collects cryptographically secure random bytes from the
/// operating system's entropy sources.
fn collect_system_entropy() -> Result<[u8; 32], RngError> {
    let mut seed = [0u8; 32];
    
    #[cfg(unix)]
    {
        collect_unix_entropy(&mut seed)?;
    }
    
    #[cfg(windows)]
    {
        collect_windows_entropy(&mut seed)?;
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        return Err(RngError::EntropyCollection);
    }
    
    Ok(seed)
}

/// Collect entropy on Unix-like systems (Linux, macOS, BSD)
#[cfg(unix)]
fn collect_unix_entropy(seed: &mut [u8; 32]) -> Result<(), RngError> {
    use std::fs::File;
    
    // Try /dev/urandom first (recommended for most uses)
    match File::open("/dev/urandom") {
        Ok(mut file) => {
            file.read_exact(seed).map_err(|_| RngError::IoError)?;
            return Ok(());
        }
        Err(_) => {
            // Fall back to /dev/random if urandom is not available
            match File::open("/dev/random") {
                Ok(mut file) => {
                    file.read_exact(seed).map_err(|_| RngError::IoError)?;
                    return Ok(());
                }
                Err(_) => {
                    return Err(RngError::EntropyCollection);
                }
            }
        }
    }
}

/// Collect entropy on Windows systems
#[cfg(windows)]
fn collect_windows_entropy(seed: &mut [u8; 32]) -> Result<(), RngError> {
    // Link with advapi32.dll for RtlGenRandom (SystemFunction036)
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn SystemFunction036(buffer: *mut u8, length: u32) -> u8;
    }
    
    unsafe {
        if SystemFunction036(seed.as_mut_ptr(), seed.len() as u32) == 0 {
            return Err(RngError::EntropyCollection);
        }
    }
    
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chacha20_deterministic() {
        // Test that same seed produces same output
        let seed = [0x42u8; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);
        
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }
    
    #[test]
    fn test_chacha20_different_seeds() {
        // Test that different seeds produce different output
        let mut rng1 = ChaCha20Rng::from_seed([0x42u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([0x24u8; 32]);
        
        let val1 = rng1.next_u64();
        let val2 = rng2.next_u64();
        assert_ne!(val1, val2);
    }
    
    #[test]
    fn test_fill_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
        let mut buffer1 = [0u8; 100];
        let mut buffer2 = [0u8; 100];
        
        rng.fill_bytes(&mut buffer1);
        rng.fill_bytes(&mut buffer2);
        
        // Different calls should produce different output
        assert_ne!(buffer1, buffer2);
        
        // Should not be all zeros
        assert_ne!(buffer1, [0u8; 100]);
    }
    
    #[test]
    fn test_gen_range() {
        let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
        
        // Test range generation
        for _ in 0..1000 {
            let val = rng.gen_range(10);
            assert!(val < 10);
        }
        
        // Test edge cases
        assert_eq!(rng.gen_range(0), 0);
        assert_eq!(rng.gen_range(1), 0);
    }
    
    #[test]
    fn test_system_entropy() {
        // Test that system entropy collection works
        match ChaCha20Rng::from_system_entropy() {
            Ok(mut rng) => {
                let val1 = rng.next_u64();
                let val2 = rng.next_u64();
                assert_ne!(val1, val2);
            }
            Err(e) => {
                // On some test environments, system entropy might not be available
                println!("System entropy test skipped: {}", e);
            }
        }
    }
    
    #[test]
    fn test_thread_rng() {
        let mut get_random = thread_rng();
        let val1 = get_random();
        let val2 = get_random();
        
        // Should produce different values
        assert_ne!(val1, val2);
    }
    
    #[test]
    fn test_gen_array() {
        let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
        
        let arr1: [u8; 16] = rng.gen_array();
        let arr2: [u8; 16] = rng.gen_array();
        
        // Different calls should produce different arrays
        assert_ne!(arr1, arr2);
        
        // Should not be all zeros
        assert_ne!(arr1, [0u8; 16]);
    }
    
    #[test]
    fn test_large_buffer() {
        let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
        let mut large_buffer = vec![0u8; 1000];
        
        rng.fill_bytes(&mut large_buffer);
        
        // Should not be all zeros
        assert_ne!(large_buffer, vec![0u8; 1000]);
        
        // Should have good distribution (simple check)
        let zeros = large_buffer.iter().filter(|&&x| x == 0).count();
        let ones = large_buffer.iter().filter(|&&x| x == 1).count();
        
        // With 1000 random bytes, we should see roughly equal distribution
        // This is a weak test but catches obvious failures
        assert!(zeros < 100); // Less than 10% zeros
        assert!(ones < 100);  // Less than 10% ones
    }
}