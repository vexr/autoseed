//! Direct 1:1 implementation copied from official BLAKE2 reference
//!
//! Original source: https://github.com/BLAKE2/BLAKE2/tree/master/ref
//! File: blake2b-ref.c
//!
//! Copyright 2012, Samuel Neves <sneves@dei.uc.pt>. You may use this under the
//! terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
//! your option. The terms of these licenses can be found at:
//!
//! - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
//! - OpenSSL license   : https://www.openssl.org/source/license.html
//! - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
//!
//! More information about the BLAKE2 hash function can be found at
//! https://blake2.net.

const BLAKE2B_BLOCKBYTES: usize = 128;
const BLAKE2B_OUTBYTES: usize = 64;

// BLAKE2b initialization vector
const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

// BLAKE2b permutation matrix
const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b state structure
#[derive(Clone)]
pub struct Blake2b512 {
    h: [u64; 8],
    t: [u64; 2],
    f: [u64; 2],
    buf: [u8; BLAKE2B_BLOCKBYTES],
    buflen: usize,
}

impl Blake2b512 {
    /// Create a new BLAKE2b-512 hasher
    pub fn new() -> Self {
        let mut state = Blake2b512 {
            h: BLAKE2B_IV,
            t: [0; 2],
            f: [0; 2],
            buf: [0; BLAKE2B_BLOCKBYTES],
            buflen: 0,
        };

        // Create parameter block for BLAKE2b-512
        let mut param_block = [0u8; 64];
        param_block[0] = BLAKE2B_OUTBYTES as u8; // digest_length
        param_block[1] = 0; // key_length  
        param_block[2] = 1; // fanout
        param_block[3] = 1; // depth
        // leaf_length, node_offset, xof_length are already 0
        // node_depth, inner_length, reserved are already 0
        // salt and personal are already 0

        // XOR the parameter block with IV
        for i in 0..8 {
            let param_word = u64::from_le_bytes([
                param_block[i * 8],
                param_block[i * 8 + 1],
                param_block[i * 8 + 2],
                param_block[i * 8 + 3],
                param_block[i * 8 + 4],
                param_block[i * 8 + 5],
                param_block[i * 8 + 6],
                param_block[i * 8 + 7],
            ]);
            state.h[i] ^= param_word;
        }

        state
    }

    /// Update the hasher with input data
    pub fn update(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }

        let mut inlen = input.len();
        let mut offset = 0;

        let left = self.buflen;
        let fill = BLAKE2B_BLOCKBYTES - left;

        if inlen > fill {
            self.buflen = 0;
            self.buf[left..BLAKE2B_BLOCKBYTES].copy_from_slice(&input[offset..offset + fill]);
            self.increment_counter(BLAKE2B_BLOCKBYTES as u64);
            self.compress(&self.buf.clone());
            offset += fill;
            inlen -= fill;

            while inlen > BLAKE2B_BLOCKBYTES {
                self.increment_counter(BLAKE2B_BLOCKBYTES as u64);
                let block = &input[offset..offset + BLAKE2B_BLOCKBYTES];
                self.compress(block);
                offset += BLAKE2B_BLOCKBYTES;
                inlen -= BLAKE2B_BLOCKBYTES;
            }
        }

        self.buf[self.buflen..self.buflen + inlen].copy_from_slice(&input[offset..offset + inlen]);
        self.buflen += inlen;
    }

    /// Finalize the hash and return the result
    pub fn finalize(mut self) -> [u8; BLAKE2B_OUTBYTES] {
        self.increment_counter(self.buflen as u64);
        self.set_lastblock();

        // Pad buffer with zeros
        for i in self.buflen..BLAKE2B_BLOCKBYTES {
            self.buf[i] = 0;
        }

        self.compress(&self.buf.clone());

        // Output hash
        let mut output = [0u8; BLAKE2B_OUTBYTES];
        for (i, &h) in self.h.iter().enumerate() {
            let start = i * 8;
            output[start..start + 8].copy_from_slice(&h.to_le_bytes());
        }
        output
    }

    fn increment_counter(&mut self, inc: u64) {
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn set_lastblock(&mut self) {
        self.f[0] = u64::MAX;
    }

    fn compress(&mut self, block: &[u8]) {
        let mut m = [0u64; 16];
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            m[i] = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
        }

        let mut v = [0u64; 16];
        for i in 0..8 {
            v[i] = self.h[i];
        }
        for i in 0..8 {
            v[i + 8] = BLAKE2B_IV[i];
        }

        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        v[14] ^= self.f[0];
        v[15] ^= self.f[1];

        // 12 rounds of mixing
        for round in 0..12 {
            let s = &BLAKE2B_SIGMA[round];

            // Column mixing
            self.blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            self.blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            self.blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            self.blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

            // Diagonal mixing  
            self.blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            self.blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            self.blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            self.blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    fn blake2b_g(&self, v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }
}

impl Default for Blake2b512 {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_512_empty() {
        let mut hasher = Blake2b512::new();
        hasher.update(&[]);
        let result = hasher.finalize();
        
        // BLAKE2b-512 of empty string
        let expected = [
            0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03,
            0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72,
            0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61,
            0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19,
            0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53,
            0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b,
            0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
            0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce,
        ];
        
        assert_eq!(result, expected);
    }

    #[test]
    fn test_blake2b_512_abc() {
        let mut hasher = Blake2b512::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        
        // BLAKE2b-512 of "abc"
        let expected = [
            0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
            0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
            0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
            0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
            0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
            0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
            0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
            0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
        ];
        
        assert_eq!(result, expected);
    }
}