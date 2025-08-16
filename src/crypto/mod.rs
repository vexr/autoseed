pub mod blake2b;
pub mod bip39;
pub mod bs58;
pub mod pbkdf2;
pub mod rng;
pub mod substrate;

// External crate re-exports for substrate compatibility
pub mod cfg_if;
pub mod curve25519_dalek;
pub mod schnorrkel;
pub mod subtle;

use crate::crypto::bip39::Mnemonic;
use crate::crypto::substrate::sr25519::{Pair, IdentifyAccount};
use crate::crypto::substrate::crypto::{Ss58Codec, Ss58AddressFormat};
use crate::wallet::mnemonic_to_mini_secret;


pub fn mnemonic_to_address_with_prefix(mnemonic: &Mnemonic, ss58_prefix: u16) -> String {
    let mini_secret = mnemonic_to_mini_secret(mnemonic, "");
    let pair = Pair::from_seed_slice(&mini_secret).expect("Failed to create pair");
    let account_id = pair.public().into_account();
    account_id.to_ss58check_with_version(Ss58AddressFormat::custom(ss58_prefix))
}

/// Blake2b-512 hash function for SS58 checksums
pub fn blake2_512(data: &[u8]) -> [u8; 64] {
    use crate::crypto::blake2b::Blake2b512;
    
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mnemonic_to_address_integration() {
        // Test with known mnemonic and Autonomys Network (6094)
        let mnemonic1 = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .expect("Known valid mnemonic");
        let address1 = mnemonic_to_address_with_prefix(&mnemonic1, 6094);
        
        // Test with different mnemonic
        let mnemonic2 = Mnemonic::parse("legal winner thank year wave sausage worth useful legal winner thank yellow")
            .expect("Known valid mnemonic");
        let address2 = mnemonic_to_address_with_prefix(&mnemonic2, 6094);
        
        // Address validation for Autonomys Network
        assert!(address1.starts_with("su"), "Address should start with 'su' for Autonomys Network");
        assert!(address1.len() >= 40 && address1.len() <= 60, "Address should have reasonable length");
        
        // Deterministic behavior
        let address1_repeat = mnemonic_to_address_with_prefix(&mnemonic1, 6094);
        assert_eq!(address1, address1_repeat, "Same mnemonic should always produce same address");
        
        // Different mnemonics produce different addresses
        assert_ne!(address1, address2, "Different mnemonics must produce different addresses");
        
        // Test different networks produce different addresses
        let polkadot_address = mnemonic_to_address_with_prefix(&mnemonic1, 0);
        assert!(polkadot_address.starts_with('1'), "Polkadot address should start with '1'");
        assert_ne!(address1, polkadot_address, "Different networks should produce different addresses");
    }
}
