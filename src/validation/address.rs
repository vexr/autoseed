use crate::crypto::bip39::Mnemonic;
use crate::crypto::mnemonic_to_address_with_prefix;
use crate::wallet::hex_to_address_with_prefix;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum ValidationResult {
    Valid,
    Mismatch,
    Error,
}

impl ValidationResult {
    pub fn status_symbol(&self) -> &'static str {
        match self {
            ValidationResult::Valid => "✔",
            ValidationResult::Mismatch => "✗", 
            ValidationResult::Error => "⚠",
        }
    }
}

fn validate_mnemonic_address(mnemonic: &str, expected_address: &str, ss58_prefix: u16) -> Result<bool, String> {
    let mnemonic_parsed = Mnemonic::from_str(mnemonic)
        .map_err(|e| format!("Failed to parse mnemonic: {:?}", e))?;
    
    let generated_address = mnemonic_to_address_with_prefix(&mnemonic_parsed, ss58_prefix);
    Ok(generated_address == expected_address)
}

fn validate_hex_address(hex_seed: &str, expected_address: &str, ss58_prefix: u16) -> Result<bool, String> {
    let hex_clean = if hex_seed.starts_with("0x") {
        &hex_seed[2..]
    } else {
        hex_seed
    };
    
    let seed_bytes = hex::decode(hex_clean)
        .map_err(|e| format!("Failed to decode hex seed: {}", e))?;
    
    if seed_bytes.len() != 32 {
        return Err(format!("Hex seed must be exactly 32 bytes, got {}", seed_bytes.len()));
    }
    
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes);
    let generated_address = hex_to_address_with_prefix(&seed_array, ss58_prefix);
    
    Ok(generated_address == expected_address)
}

pub fn validate_wallet(secret: &str, address: &str, ss58_prefix: u16, is_hex_mode: bool) -> ValidationResult {
    let result = if is_hex_mode {
        validate_hex_address(secret, address, ss58_prefix)
    } else {
        validate_mnemonic_address(secret, address, ss58_prefix)
    };
    
    match result {
        Ok(true) => ValidationResult::Valid,
        Ok(false) => ValidationResult::Mismatch,
        Err(_) => ValidationResult::Error,
    }
}