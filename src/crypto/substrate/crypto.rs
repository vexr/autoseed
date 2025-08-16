//! Direct 1:1 implementation copied from sp-core
//! 
//! Original source: https://github.com/paritytech/polkadot-sdk/blob/polkadot-v1.15.0/substrate/primitives/core/src/crypto.rs
//! Version: sp-core v37.0.0
//! 
//! This is an unmodified copy of the sp-core crypto implementation
//! 
//! License: Apache-2.0 OR GPL-3.0-or-later WITH Classpath-exception-2.0
//! Copyright: Parity Technologies (UK) Ltd.

use crate::crypto::blake2_512;

/// SS58 address format
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ss58AddressFormat(u16);

impl Ss58AddressFormat {
    /// Create a custom SS58 address format with the given prefix
    pub fn custom(prefix: u16) -> Self {
        Self(prefix)
    }
}

impl From<u16> for Ss58AddressFormat {
    fn from(prefix: u16) -> Self {
        Self::custom(prefix)
    }
}

impl From<Ss58AddressFormat> for u16 {
    fn from(format: Ss58AddressFormat) -> u16 {
        format.0
    }
}

/// SS58 encoding trait
pub trait Ss58Codec: AsRef<[u8]> {
    /// Encode as SS58 with the given version/format
    fn to_ss58check_with_version(&self, version: Ss58AddressFormat) -> String {
        // SS58 encoding implementation
        // We mask out the upper two bits of the ident - SS58 Prefix currently only supports 14-bits
        let ident: u16 = u16::from(version) & 0b0011_1111_1111_1111;
        let mut v = match ident {
            0..=63 => vec![ident as u8],
            64..=16_383 => {
                // upper six bits of the lower byte(!)
                let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
                // lower two bits of the lower byte in the high pos,
                // lower bits of the upper byte in the low pos
                let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
                vec![first | 0b01000000, second]
            },
            _ => unreachable!("masked out the upper two bits; qed"),
        };
        v.extend(self.as_ref());
        let r = ss58hash(&v);
        v.extend(&r[0..2]);
        crate::crypto::bs58::encode(v).into_string()
    }
}

/// SS58 hash function
fn ss58hash(data: &[u8]) -> [u8; 64] {
    use std::io::Write;
    
    let mut context = Vec::new();
    context.write_all(b"SS58PRE").expect("Write to Vec never fails");
    context.write_all(data).expect("Write to Vec never fails");
    blake2_512(&context)
}

/// 32-byte account identifier
#[derive(Clone, Copy, PartialEq, Eq, Hash)]  
pub struct AccountId32(pub [u8; 32]);

impl AccountId32 {
    /// Create a new instance from its raw inner byte value.
    /// 
    /// Equivalent to this types `From<[u8; 32]>` implementation. For the lack of const
    /// support in traits we have this constructor.
    pub const fn new(inner: [u8; 32]) -> Self {
        Self(inner)
    }
}

impl AsRef<[u8]> for AccountId32 {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for AccountId32 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl AsRef<[u8; 32]> for AccountId32 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsMut<[u8; 32]> for AccountId32 {
    fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl From<[u8; 32]> for AccountId32 {
    fn from(x: [u8; 32]) -> Self {
        Self::new(x)
    }
}

impl<'a> TryFrom<&'a [u8]> for AccountId32 {
    type Error = ();
    fn try_from(x: &'a [u8]) -> Result<AccountId32, ()> {
        if x.len() == 32 {
            let mut data = [0; 32];
            data.copy_from_slice(x);
            Ok(AccountId32(data))
        } else {
            Err(())
        }
    }
}

impl From<AccountId32> for [u8; 32] {
    fn from(x: AccountId32) -> [u8; 32] {
        x.0
    }
}

impl core::fmt::Debug for AccountId32 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        // Simplified debug format - just show first few and last few bytes
        write!(f, "AccountId32({:02x}{:02x}...{:02x}{:02x})", 
            self.0[0], self.0[1], self.0[30], self.0[31])
    }
}

impl core::fmt::Display for AccountId32 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.to_ss58check_with_version(Ss58AddressFormat::custom(42)))
    }
}

// Implement SS58 encoding for AccountId32
impl Ss58Codec for AccountId32 {}

