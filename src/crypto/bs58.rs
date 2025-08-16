//! Base58 Encoding Implementation for SS58 Addresses
//!
//! This module provides Base58 encoding functionality specifically for
//! encoding Substrate SS58 addresses in the vanity address generator.
//! This is a minimal implementation that includes only the encoding functions
//! needed by our codebase.
//!
//! ## Attribution
//! Based on the bs58 implementation:
//! - Original source: https://github.com/Nullus157/bs58-rs
//! - Version: bs58 v0.5.0 
//! - License: Apache-2.0 OR MIT
//! - Copyright: Steven Fackler
//!
//! ## Usage
//! This implementation supports only the encoding operations needed for SS58:
//!
//! ```rust
//! use crate::crypto::bs58;
//! 
//! let data = [0x04, 0x30, 0x5e, 0x2b, 0x24, 0x73, 0xf0, 0x58];
//! let encoded = bs58::encode(data).into_string();
//! ```
//!
//! ## References
//! - Base58 encoding: https://en.wikipedia.org/wiki/Base58
//! - SS58 address format: https://docs.substrate.io/reference/address-formats/

use std::string::String;

/// Bitcoin Base58 alphabet used for SS58 addresses
const BITCOIN_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Errors that can occur during Base58 encoding
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The output buffer was too small to contain the entire input
    BufferTooSmall,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BufferTooSmall => write!(f, "output buffer too small for base58 encoding"),
        }
    }
}

impl std::error::Error for Error {}

/// A builder for Base58 encoding operations
pub struct EncodeBuilder<I: AsRef<[u8]>> {
    input: I,
}

impl<I: AsRef<[u8]>> EncodeBuilder<I> {
    /// Create a new encoder for the given input
    fn new(input: I) -> Self {
        Self { input }
    }

    /// Encode the input as a Base58 string
    ///
    /// This is the primary method used by the SS58 address generation code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let data = [0x04, 0x30, 0x5e, 0x2b, 0x24, 0x73, 0xf0, 0x58];
    /// let encoded = bs58::encode(data).into_string();
    /// assert_eq!("he11owor1d", encoded);
    /// ```
    pub fn into_string(self) -> String {
        let input = self.input.as_ref();
        
        // Calculate maximum possible output length
        // For base58: ceil(log(256) / log(58) * input_len) + 1
        // Approximation: input_len * 138 / 100 + 1
        let max_len = input.len() * 138 / 100 + 1;
        let mut output = vec![0u8; max_len];
        
        let actual_len = encode_into(input, &mut output).expect("buffer size calculation error");
        output.truncate(actual_len);
        
        // Convert to string using the alphabet
        let mut result = String::with_capacity(actual_len);
        for &byte in output.iter().rev() {
            result.push(BITCOIN_ALPHABET[byte as usize] as char);
        }
        
        // Add leading zeros as '1' characters
        for &byte in input {
            if byte != 0 {
                break;
            }
            result.insert(0, '1');
        }
        
        result
    }
}

/// Create a Base58 encoder for the given input
///
/// This is the main entry point for Base58 encoding in the codebase.
/// It creates an `EncodeBuilder` that can be used to encode the input.
///
/// # Examples
///
/// ```rust
/// let data = [0x04, 0x30, 0x5e, 0x2b, 0x24, 0x73, 0xf0, 0x58];
/// let encoded = bs58::encode(data).into_string();
/// ```
pub fn encode<I: AsRef<[u8]>>(input: I) -> EncodeBuilder<I> {
    EncodeBuilder::new(input)
}

/// Core Base58 encoding algorithm
///
/// This function implements the mathematical base conversion from base 256 (bytes)
/// to base 58. The algorithm processes the input bytes and produces the base58
/// representation in reverse order (most significant digit first in the output array).
///
/// # Arguments
/// - `input`: The bytes to encode
/// - `output`: Buffer to store the encoded result (will be in reverse order)
///
/// # Returns
/// The number of bytes written to the output buffer
///
/// # Algorithm
/// This implements the standard base conversion algorithm:
/// 1. For each input byte, multiply the current result by 256 and add the byte
/// 2. Convert to base 58 by repeatedly dividing by 58 and collecting remainders
/// 3. The result is naturally produced in reverse order (little-endian)
fn encode_into(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let mut index = 0;
    
    // Process each input byte
    for &val in input {
        let mut carry = val as usize;
        
        // Multiply existing digits by 256 and add new byte
        for byte in &mut output[..index] {
            carry += (*byte as usize) << 8; // multiply by 256
            *byte = (carry % 58) as u8;     // store remainder
            carry /= 58;                    // prepare for next digit
        }
        
        // Handle remaining carry
        while carry > 0 {
            if index == output.len() {
                return Err(Error::BufferTooSmall);
            }
            output[index] = (carry % 58) as u8;
            index += 1;
            carry /= 58;
        }
    }
    
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encoding() {
        let input = [0x04, 0x30, 0x5e, 0x2b, 0x24, 0x73, 0xf0, 0x58];
        let result = encode(input).into_string();
        assert_eq!("he11owor1d", result);
    }

    #[test]
    fn test_empty_input() {
        let input = [];
        let result = encode(input).into_string();
        assert_eq!("", result);
    }

    #[test]
    fn test_leading_zeros() {
        let input = [0x00, 0x00, 0x01];
        let result = encode(input).into_string();
        assert_eq!("112", result);
    }

    #[test]
    fn test_single_byte() {
        let input = [0x01];
        let result = encode(input).into_string();
        assert_eq!("2", result);
    }
}