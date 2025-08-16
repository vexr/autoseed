//! Schnorr signatures on Ristretto25519 for SR25519 key generation
//!
//! Based on schnorrkel v0.11.5
//! Source: https://github.com/w3f/schnorrkel
//! Authors: Isis Lovecruft, Jeff Burdges, Web3 Foundation
//! License: BSD-3-Clause

use core::convert::AsRef;
use core::fmt::{Debug, Display};
use sha2::{Sha512, digest::{Update, FixedOutput}};
use zeroize::Zeroize;

use crate::crypto::curve25519_dalek::constants;
use crate::crypto::curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use crate::crypto::curve25519_dalek::scalar::Scalar;
use crate::crypto::subtle::{Choice, ConstantTimeEq};

// ===== Constants =====

/// The length of a Ristretto Schnorr `MiniSecretKey`, in bytes.
pub const MINI_SECRET_KEY_LENGTH: usize = 32;

/// The length of a Ristretto Schnorr `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The length of the "key" portion of a Ristretto Schnorr secret key, in bytes.
const SECRET_KEY_KEY_LENGTH: usize = 32;

/// The length of the "nonce" portion of a Ristretto Schnorr secret key, in bytes.
const SECRET_KEY_NONCE_LENGTH: usize = 32;

/// The length of a Ristretto Schnorr key, `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = SECRET_KEY_KEY_LENGTH + SECRET_KEY_NONCE_LENGTH;

/// Compressed Ristretto point length
pub const RISTRETTO_POINT_LENGTH: usize = 32;

// ===== Error Types =====

/// `Result` specialized to this crate for convenience.
pub type SignatureResult<T> = Result<T, SignatureError>;

/// Errors which may occur while processing signatures and keypairs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SignatureError {
    /// Invalid point provided, usually to `verify` methods.
    PointDecompressionError,
    /// An error in the length of bytes handed to a constructor.
    BytesLengthError {
        /// Identifies the type returning the error
        name: &'static str,
        /// Describes the type returning the error
        description: &'static str,
        /// Length expected by the constructor in bytes
        length: usize,
    },
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use self::SignatureError::*;
        match *self {
            PointDecompressionError =>
                write!(f, "Cannot decompress Ristretto point"),
            BytesLengthError { name, length, .. } =>
                write!(f, "{name} must be {length} bytes in length"),
        }
    }
}

// ===== Scalar Utilities =====

/// Divide scalar bytes by cofactor (8) for Ed25519 compatibility
pub(crate) fn divide_scalar_bytes_by_cofactor(scalar: &mut [u8; 32]) {
    let mut low = 0u8;
    for i in scalar.iter_mut().rev() {
        let r = *i & 0b00000111; // save remainder
        *i >>= 3; // divide by 8
        *i += low;
        low = r << 5;
    }
}

/// Multiply scalar bytes by cofactor (8) for Ed25519 compatibility
pub(crate) fn multiply_scalar_bytes_by_cofactor(scalar: &mut [u8; 32]) {
    let mut high = 0u8;
    for i in scalar.iter_mut() {
        let r = *i & 0b11100000; // carry bits
        *i <<= 3; // multiply by 8
        *i += high;
        high = r >> 5;
    }
}

// ===== Ristretto Point Utilities =====

/// A `RistrettoBoth` contains both an uncompressed `RistrettoPoint`
/// as well as the corresponding `CompressedRistretto`. This provides
/// a convenient middle ground for protocols that both hash compressed
/// points to derive scalars for use with uncompressed points.
#[derive(Copy, Clone, Default, Eq)]
pub struct RistrettoBoth {
    compressed: CompressedRistretto,
    point: RistrettoPoint,
}


impl ConstantTimeEq for RistrettoBoth {
    fn ct_eq(&self, other: &RistrettoBoth) -> Choice {
        self.compressed.ct_eq(&other.compressed)
    }
}

impl RistrettoBoth {
    /// Access the compressed Ristretto form
    pub fn as_compressed(&self) -> &CompressedRistretto { 
        &self.compressed 
    }

    /// Decompress into the `RistrettoBoth` format that also retains the compressed form.
    pub fn from_compressed(compressed: CompressedRistretto) -> SignatureResult<RistrettoBoth> {
        Ok(RistrettoBoth {
            point: compressed.decompress().ok_or(SignatureError::PointDecompressionError)?,
            compressed,
        })
    }

    /// Compress into the `RistrettoBoth` format that also retains the uncompressed form.
    pub fn from_point(point: RistrettoPoint) -> RistrettoBoth {
        RistrettoBoth {
            compressed: point.compress(),
            point,
        }
    }

    /// Create from bytes with detailed error information
    #[inline]
    pub fn from_bytes_ser(name: &'static str, description: &'static str, bytes: &[u8]) -> SignatureResult<RistrettoBoth> {
        if bytes.len() != RISTRETTO_POINT_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name, description, length: RISTRETTO_POINT_LENGTH,
            });
        }
        let mut compressed = CompressedRistretto([0u8; RISTRETTO_POINT_LENGTH]);
        compressed.0.copy_from_slice(&bytes[..32]);
        RistrettoBoth::from_compressed(compressed)
    }
}

/// Compare only the compressed forms for efficiency
impl PartialEq<Self> for RistrettoBoth {
    fn eq(&self, other: &Self) -> bool {
        let r = self.compressed.eq(&other.compressed);
        debug_assert_eq!(r, self.point.eq(&other.point));
        r
    }
}

impl PartialOrd<RistrettoBoth> for RistrettoBoth {
    fn partial_cmp(&self, other: &RistrettoBoth) -> Option<::core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RistrettoBoth {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.compressed.0.cmp(&other.compressed.0)
    }
}

impl core::hash::Hash for RistrettoBoth {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.compressed.0.hash(state);
    }
}

// ===== Key Types =====

/// Methods for expanding a `MiniSecretKey` into a `SecretKey`.
#[derive(Debug)]
pub enum ExpansionMode {
    /// Expand this `MiniSecretKey` into a `SecretKey` using ed25519-style bit clamping.
    Ed25519,
}

/// An EdDSA-like "secret" key seed.
///
/// These are seeds from which we produce a real `SecretKey` by hashing.
/// We require homomorphic properties unavailable from these seeds, so we
/// reserve `SecretKey` for what EdDSA calls an extended secret key.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MiniSecretKey(pub(crate) [u8; MINI_SECRET_KEY_LENGTH]);

impl Debug for MiniSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MiniSecretKey: {:?}", &self.0[..])
    }
}

impl Eq for MiniSecretKey {}
impl PartialEq for MiniSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for MiniSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl MiniSecretKey {
    const DESCRIPTION: &'static str = "Analogous to ed25519 secret key as 32 bytes, see RFC8032.";

    /// Expand this `MiniSecretKey` into a `SecretKey` using ed25519-style bit clamping.
    ///
    /// This method permits compatible schnorrkel and ed25519 keys by using
    /// the same expansion method as Ed25519.
    fn expand_ed25519(&self) -> SecretKey {
        let mut h = Sha512::default();
        h.update(self.as_bytes());
        let r = h.finalize_fixed();

        // Apply Ed25519 bit clamping for compatibility
        let mut key = [0u8; 32];
        key.copy_from_slice(&r.as_slice()[0..32]);
        key[0] &= 248;
        key[31] &= 63;
        key[31] |= 64;
        
        // Divide by cofactor to keep clean representation mod l
        divide_scalar_bytes_by_cofactor(&mut key);

        #[allow(deprecated)] // Scalar's always reduced here, so this is OK.
        let key = Scalar::from_bits(key);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&r.as_slice()[32..64]);

        SecretKey { key, nonce }
    }

    /// Derive the `SecretKey` corresponding to this `MiniSecretKey`.
    pub fn expand(&self, mode: ExpansionMode) -> SecretKey {
        match mode {
            ExpansionMode::Ed25519 => self.expand_ed25519(),
        }
    }

    /// Derive the `Keypair` corresponding to this `MiniSecretKey`.
    pub fn expand_to_keypair(&self, mode: ExpansionMode) -> Keypair {
        self.expand(mode).into()
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; MINI_SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Construct a `MiniSecretKey` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<MiniSecretKey> {
        if bytes.len() != MINI_SECRET_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "MiniSecretKey",
                description: MiniSecretKey::DESCRIPTION,
                length: MINI_SECRET_KEY_LENGTH,
            });
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(MiniSecretKey(bits))
    }
}

/// A secret key for use with Ristretto Schnorr signatures.
///
/// Internally, these consist of a scalar mod l along with a seed for
/// nonce generation. This ensures all scalar arithmetic works smoothly
/// in operations like threshold or multi-signatures.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    /// Actual secret key represented as a scalar.
    pub(crate) key: Scalar,
    /// Seed for deriving the nonces used in signing.
    pub(crate) nonce: [u8; 32],
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey {{ key: {:?} nonce: {:?} }}", &self.key, &self.nonce)
    }
}

impl Eq for SecretKey {}
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

impl SecretKey {
    /// Convert this `SecretKey` into an array of 64 bytes, corresponding to
    /// an Ed25519 expanded secret key.
    #[inline]
    pub fn to_ed25519_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];
        let mut key = self.key.to_bytes();
        // Multiply by cofactor for ed25519 compatibility
        multiply_scalar_bytes_by_cofactor(&mut key);
        bytes[..32].copy_from_slice(&key[..]);
        bytes[32..].copy_from_slice(&self.nonce[..]);
        bytes
    }

    /// Derive the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey {
        // No clamping necessary in the ristretto255 group
        PublicKey::from_point(&self.key * constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

/// A Ristretto Schnorr public key.
///
/// Internally, these are represented as a `RistrettoPoint`, meaning
/// an Edwards point with a static guarantee to be 2-torsion free.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub(crate) RistrettoBoth);


impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &PublicKey) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_compressed().as_bytes()
    }
}

impl PublicKey {
    const DESCRIPTION: &'static str = "A Ristretto Schnorr public key represented as a 32-byte Ristretto compressed point";

    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.as_compressed().to_bytes()
    }

    /// Access the compressed Ristretto form
    pub fn as_compressed(&self) -> &CompressedRistretto { 
        self.0.as_compressed() 
    }

    /// Compress into the `PublicKey` format that also retains the uncompressed form.
    pub fn from_point(point: RistrettoPoint) -> PublicKey {
        PublicKey(RistrettoBoth::from_point(point))
    }

    /// Construct a `PublicKey` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<PublicKey> {
        Ok(PublicKey(RistrettoBoth::from_bytes_ser("PublicKey", PublicKey::DESCRIPTION, bytes)?))
    }
}

impl From<SecretKey> for PublicKey {
    fn from(source: SecretKey) -> PublicKey {
        source.to_public()
    }
}

/// A Ristretto Schnorr keypair.
#[derive(Clone)]
pub struct Keypair {
    /// The secret half of this keypair.
    pub secret: SecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

impl Zeroize for Keypair {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        let public = secret.to_public();
        Keypair { secret, public }
    }
}

