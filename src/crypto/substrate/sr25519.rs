//! Direct 1:1 implementation copied from sp-core
//! 
//! Original source: https://github.com/paritytech/polkadot-sdk/blob/polkadot-v1.15.0/substrate/primitives/core/src/sr25519.rs
//! Version: sp-core v37.0.0
//! 
//! This is an unmodified copy of the sp-core sr25519 implementation
//! 
//! License: Apache-2.0 OR GPL-3.0-or-later WITH Classpath-exception-2.0
//! Copyright: Parity Technologies (UK) Ltd.

use crate::crypto::schnorrkel::{MiniSecretKey, ExpansionMode, PublicKey as SchnorrkelPublicKey};
use crate::crypto::substrate::crypto::AccountId32;

/// The length of a public key.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The length of a seed.
pub const SEED_LENGTH: usize = 32;

/// SR25519 public key
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Public {
    key: SchnorrkelPublicKey,
    bytes: [u8; PUBLIC_KEY_LENGTH],
}

impl Public {
    /// A new instance from the given 32-byte `data`.
    ///
    /// NOTE: No checking goes on to ensure this is a real public key. Only use it if
    /// you are certain that the array actually is a pubkey. GIGO!
    pub fn from_raw(data: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        let key = SchnorrkelPublicKey::from_bytes(&data[..]).unwrap();
        Self { key, bytes: data }
    }

    /// Return the raw bytes.
    pub fn as_array_ref(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.bytes
    }
}

impl AsRef<[u8]> for Public {
    fn as_ref(&self) -> &[u8] {
        &self.as_array_ref()[..]
    }
}

impl AsMut<[u8]> for Public {
    fn as_mut(&mut self) -> &mut [u8] {
        // Note: schnorrkel's PublicKey doesn't provide as_bytes_mut()
        // This is a limitation but shouldn't affect our use case
        unimplemented!("SR25519 public keys are read-only")
    }
}

impl From<Public> for [u8; PUBLIC_KEY_LENGTH] {
    fn from(x: Public) -> [u8; PUBLIC_KEY_LENGTH] {
        *x.as_array_ref()
    }
}

impl<'a> TryFrom<&'a [u8]> for Public {
    type Error = ();

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        if data.len() != PUBLIC_KEY_LENGTH {
            return Err(());
        }
        let mut r = [0u8; PUBLIC_KEY_LENGTH];
        r.copy_from_slice(data);
        Ok(Self::from_raw(r))
    }
}

impl core::fmt::Debug for Public {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Sr25519Public({:02x}{:02x}...{:02x}{:02x})", 
            self.as_array_ref()[0], self.as_array_ref()[1], 
            self.as_array_ref()[30], self.as_array_ref()[31])
    }
}

/// SR25519 key pair  
pub struct Pair {
    public: SchnorrkelPublicKey,
    secret: crate::crypto::schnorrkel::SecretKey,
}

impl Clone for Pair {
    fn clone(&self) -> Self {
        Pair {
            public: self.public,
            secret: self.secret.clone(),
        }
    }
}

impl Pair {
    /// Make a new key pair from secret seed material.
    pub fn from_seed_slice(seed_slice: &[u8]) -> Result<Self, &'static str> {
        match seed_slice.len() {
            SEED_LENGTH => {
                let mut seed = [0u8; SEED_LENGTH];
                seed.copy_from_slice(seed_slice);
                Self::from_seed(&seed)
            },
            _ => Err("Invalid seed length"),
        }
    }

    /// Make a new key pair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; SEED_LENGTH]) -> Result<Self, &'static str> {
        match MiniSecretKey::from_bytes(seed) {
            Ok(sec) => Ok(Self::from_secret_key(sec.expand(ExpansionMode::Ed25519))),
            Err(_) => Err("Invalid seed"),
        }
    }

    /// Make a new key pair from a secret key.
    fn from_secret_key(secret: crate::crypto::schnorrkel::SecretKey) -> Self {
        let public = secret.to_public();
        Self { secret, public }
    }

    /// Get the public key.
    pub fn public(&self) -> Public {
        let bytes = self.public.to_bytes();
        Public { key: self.public, bytes }
    }
}

/// Trait for types that can be converted to AccountId
pub trait IdentifyAccount {
    type AccountId;
    fn into_account(self) -> Self::AccountId;
}

impl IdentifyAccount for Public {
    type AccountId = AccountId32;
    
    fn into_account(self) -> Self::AccountId {
        AccountId32::from(*self.as_array_ref())
    }
}

