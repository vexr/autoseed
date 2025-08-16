/// JSON wallet export implementation with Polkadot ecosystem compatibility
/// 
/// This module exports wallets in the standard Polkadot JSON format that is
/// compatible with Talisman, polkadot.js, and other Substrate wallets.
/// 
/// NOTE: We use scrypt params N=32768 instead of the newer N=131072 because
/// Talisman wallet (as of v1.x) uses @polkadot/keyring v10.1.11 which has a
/// hardcoded whitelist that doesn't include the newer parameters. Using N=131072
/// will cause Talisman to reject the wallet with "Invalid injected scrypt params".
/// This ensures maximum compatibility across all wallet versions.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crate::crypto::rng::ChaCha20Rng;
use scrypt::{scrypt, Params};
use xsalsa20poly1305::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    XSalsa20Poly1305,
};
use serde_json::json;
use std::fs;
use crate::crypto::schnorrkel::{MiniSecretKey, ExpansionMode, Keypair};


/// Scrypt parameters for wallet encryption
/// N=32768 (2^15) for Talisman compatibility - newer N=131072 is not in their whitelist
const SCRYPT_N: u32 = 32768;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DKLEN: usize = 64;


/// Export a wallet to JSON format from a hex seed
/// 
/// # Arguments
/// * `seed_hex` - The private key seed in hex format
/// * `vanity_address` - The vanity address (with Autonomys prefix)
/// * `password` - The password to encrypt the wallet
/// * `output_path` - Path where the JSON wallet file will be saved
/// 
/// # Returns
/// * `Ok(String)` - The JSON string of the exported wallet
/// * `Err(String)` - Error message if export fails
fn wallet_json_from_seed(
    seed_hex: &str,
    vanity_address: &str,
    password: &str,
    output_path: &str,
    search_term: &str,
) -> Result<String, String> {
    // Parse and validate the seed
    let seed = hex::decode(seed_hex)
        .map_err(|e| format!("Invalid hex seed: {}", e))?;
    
    if seed.len() != 32 {
        return Err("Seed must be exactly 32 bytes".to_string());
    }
    
    // Generate the sr25519 keypair
    let mini_secret = MiniSecretKey::from_bytes(&seed)
        .map_err(|e| format!("Failed to create mini secret key: {}", e))?;
    let keypair = mini_secret.expand_to_keypair(ExpansionMode::Ed25519);
    
    // Extract key material in the format expected by Polkadot wallets
    let expanded = keypair_to_polkadot_format(&keypair);
    let secret_bytes: [u8; 64] = expanded[0..64].try_into().unwrap();
    let public_bytes: [u8; 32] = expanded[64..96].try_into().unwrap();
    
    // Create the SS58 address
    let address = create_ss58_address(&public_bytes);
    
    // Generate random salt and nonce for encryption
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    let mut rng = ChaCha20Rng::from_system_entropy()
        .map_err(|e| format!("Failed to initialize RNG: {}", e))?;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    
    // Derive encryption key using scrypt
    let mut derived_key = vec![0u8; SCRYPT_DKLEN];
    let params = Params::new(15, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
        .map_err(|e| format!("Invalid scrypt params: {}", e))?;
    
    scrypt(password.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| format!("Scrypt failed: {}", e))?;
    
    // Encode keypair in PKCS8 format
    let pkcs8_data = encode_pkcs8(&secret_bytes, &public_bytes);
    
    // Encrypt the PKCS8 data
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&derived_key[..32]));
    let encrypted = cipher.encrypt(GenericArray::from_slice(&nonce), pkcs8_data.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    // Build the encoded blob: salt + scrypt params + nonce + encrypted data
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&salt);
    encoded.extend_from_slice(&encode_scrypt_params());
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&encrypted);
    
    // Create the JSON wallet
    let wallet_json = json!({
        "encoded": BASE64.encode(&encoded),
        "encoding": {
            "content": ["pkcs8", "sr25519"],
            "type": ["scrypt", "xsalsa20-poly1305"],
            "version": "3"
        },
        "address": address,
        "meta": {
            "name": create_wallet_name(vanity_address, search_term)
        }
    });
    
    // Write to file
    let json_str = serde_json::to_string_pretty(&wallet_json)
        .map_err(|e| format!("Failed to serialize JSON: {}", e))?;
    
    fs::write(output_path, &json_str)
        .map_err(|e| format!("Failed to write file: {}", e))?;
    
    Ok(json_str)
}

/// Convert a schnorrkel keypair to Polkadot's expected format
/// Returns 96 bytes: 64-byte secret + 32-byte public
fn keypair_to_polkadot_format(keypair: &Keypair) -> Vec<u8> {
    let mut result = Vec::with_capacity(96);
    
    // Use Ed25519 representation for compatibility
    let ed_secret = keypair.secret.to_ed25519_bytes();
    result.extend_from_slice(&ed_secret);
    result.extend_from_slice(&keypair.public.to_bytes());
    
    result
}

/// Encode a keypair in PKCS8 format as used by Polkadot
fn encode_pkcs8(secret_key: &[u8; 64], public_key: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::new();
    
    // ASN.1 structure for sr25519 keys
    result.extend_from_slice(&[0x30, 0x53]); // SEQUENCE, length 83
    result.extend_from_slice(&[0x02, 0x01, 0x01]); // Version 1
    result.extend_from_slice(&[0x30, 0x05]); // Algorithm identifier
    result.extend_from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]); // OID
    result.extend_from_slice(&[0x04, 0x22]); // Private key wrapper
    result.extend_from_slice(&[0x04, 0x20]); // Private key data
    result.extend_from_slice(&secret_key[0..32]); // First 32 bytes of secret
    result.extend_from_slice(&secret_key[32..64]); // Remaining 32 bytes
    result.push(0xa1); // Public key context tag
    result.push(0x23); // Public key length
    result.extend_from_slice(&[0x03, 0x21, 0x00]); // BIT STRING header
    result.extend_from_slice(public_key); // Public key
    
    result
}

/// Encode scrypt parameters as 12 bytes: N(4) + p(4) + r(4) in little-endian
fn encode_scrypt_params() -> [u8; 12] {
    let mut params = [0u8; 12];
    params[0..4].copy_from_slice(&SCRYPT_N.to_le_bytes());
    params[4..8].copy_from_slice(&SCRYPT_P.to_le_bytes());
    params[8..12].copy_from_slice(&SCRYPT_R.to_le_bytes());
    params
}

/// Create an SS58 address from a public key (uses Substrate prefix 42)
fn create_ss58_address(public_key: &[u8]) -> String {
    use crate::crypto::substrate::sr25519::Public;
    use crate::crypto::substrate::crypto::{Ss58Codec, Ss58AddressFormat};
    use crate::crypto::substrate::sr25519::IdentifyAccount;
    
    let public = Public::from_raw(public_key.try_into().expect("Invalid public key length"));
    let account = public.into_account();
    account.to_ss58check_with_version(Ss58AddressFormat::custom(42))
}

/// Create a wallet name in the format: ⯈ <first six>…<last six>
fn create_wallet_name(address: &str, _search_term: &str) -> String {
    if address.len() >= 12 {
        let first_six = &address[..6];
        let last_six = &address[address.len()-6..];
        format!("⯈ {}…{}", first_six, last_six)
    } else {
        format!("⯈ {}", address)
    }
}

/// Save wallet as encrypted JSON (for hex mode)
pub fn save_wallet_json(
    result: &crate::runner::VanityResult,
    password: &str,
    search_term: &str,
    output_dir: &str,
) -> Result<(), String> {
    let filename = format!("{}.json", result.address);
    let output_path = format!("{}/{}", output_dir, filename);
    
    wallet_json_from_seed(
        &result.secret,
        &result.address,
        password,
        &output_path,
        search_term,
    )?;
    
    Ok(())
}

/// Save wallet mnemonic as text file (for mnemonic mode)
pub fn save_wallet_mnemonic(
    result: &crate::runner::VanityResult,
    output_dir: &str,
) -> Result<(), String> {
    let filename = format!("{}.txt", result.address);
    let output_path = format!("{}/{}", output_dir, filename);
    
    let content = format!("Address: {}\nMnemonic: {}\n", result.address, result.secret);
    
    fs::write(&output_path, content)
        .map_err(|e| format!("Failed to write mnemonic file: {}", e))?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wallet_export() {
        let test_path = ".devonly/test_wallet.json";
        std::fs::create_dir_all(".devonly").ok();
        
        let result = wallet_json_from_seed(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "suTestVanityAddress1234",  // Example vanity address
            "testpass123",
            test_path,
            "test"
        );
        
        assert!(result.is_ok());
        
        // Verify wallet structure
        let json = result.unwrap();
        let wallet: serde_json::Value = serde_json::from_str(&json).unwrap();
        
        assert_eq!(wallet["address"], "5DP4qTec9XxffaALGWsEPhS1oWrDWMBjzhBmyzShREMJpymt");
        assert!(wallet["encoded"].is_string());
        assert_eq!(wallet["encoding"]["version"], "3");
        assert_eq!(wallet["encoding"]["type"][0], "scrypt");
        assert_eq!(wallet["encoding"]["type"][1], "xsalsa20-poly1305");
        assert_eq!(wallet["encoding"]["content"][0], "pkcs8");
        assert_eq!(wallet["encoding"]["content"][1], "sr25519");
        
        std::fs::remove_file(test_path).ok();
    }
}