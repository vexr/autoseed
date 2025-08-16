pub const fn is_valid_ss58_character(ch: char) -> bool {
    matches!(ch, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
}

fn get_expected_address_prefixes(ss58_prefix: u16) -> Option<&'static [&'static str]> {
    if let Some(network) = crate::networks::find_network_by_prefix(ss58_prefix) {
        Some(network.address_prefixes)
    } else {
        None
    }
}

fn get_network_name_for_prefix(ss58_prefix: u16) -> String {
    if let Some(network) = crate::networks::find_network_by_prefix(ss58_prefix) {
        network.name.to_string()
    } else {
        "Custom network".to_string()
    }
}

const fn can_appear_in_address(ch: char, case_sensitive: bool) -> bool {
    if ch == '?' {
        return true; // Wildcard
    }

    if case_sensitive {
        is_valid_ss58_character(ch)
    } else {
        is_valid_ss58_character(ch)
            || (ch.is_ascii_alphabetic()
                && (is_valid_ss58_character(ch.to_ascii_uppercase())
                    || is_valid_ss58_character(ch.to_ascii_lowercase())))
    }
}

pub fn validate_search_term_with_prefix(
    term: &str,
    case_sensitive: bool,
    suffix: bool,
    within: usize,
    ss58_prefix: u16,
) -> Result<(), String> {
    let mut invalid_chars = Vec::new();

    for ch in term.chars() {
        if !can_appear_in_address(ch, case_sensitive) {
            invalid_chars.push(ch);
        }
    }

    if !invalid_chars.is_empty() {
        invalid_chars.sort_unstable();
        invalid_chars.dedup();

        let invalid_str = invalid_chars
            .iter()
            .map(|c| format!("'{c}'"))
            .collect::<Vec<_>>()
            .join(", ");

        if case_sensitive {
            return Err(format!(
                "Search term contains invalid characters: {invalid_str}. Valid characters are: 1-9, A-Z (excluding I, O), a-z (excluding l). Use '?' as a wildcard to match any character."
            ));
        }
        return Err(format!(
            "Search term contains characters that cannot appear in any form in addresses: {invalid_str}. \n\
            Note: In case-insensitive mode, characters are valid if ANY case variant is valid. \n\
            For example, 'L' is valid but 'l' is not, so 'vault' can match 'VAULT' or 'vAuLT' but not 'vault' with lowercase 'l'."
        ));
    }

    let term_len = term.len();
    if term_len > within {
        return Err(format!(
            "Search term '{}' ({} characters) cannot fit within --within {} characters limit",
            term, term_len, within
        ));
    }

    if !suffix {
        if let Some(expected_prefixes) = get_expected_address_prefixes(ss58_prefix) {
            let max_prefix_len = expected_prefixes.iter().map(|p| p.len()).max().unwrap_or(0);
            
            if case_sensitive {
                let mut can_match_prefix = false;
                for expected_prefix in expected_prefixes {
                    if term.starts_with(expected_prefix) {
                        can_match_prefix = true;
                        break;
                    }
                }
                
                if can_match_prefix {
                    if max_prefix_len + term_len > within {
                        let network_name = get_network_name_for_prefix(ss58_prefix);
                        let prefixes_display = if expected_prefixes.len() == 1 {
                            format!("'{}'", expected_prefixes[0])
                        } else {
                            expected_prefixes.iter().map(|p| format!("'{}'", p)).collect::<Vec<_>>().join(" or ")
                        };
                        
                        let min_required = max_prefix_len + term_len;
                        return Err(format!(
                            "{} addresses start with {} ({} chars) + your term '{}' ({} chars) = {} total characters\nThis exceeds --within {} limit\nSUGGESTION: Use --within {} or higher, or try --suffix mode instead",
                            network_name, prefixes_display, max_prefix_len, term, term_len, min_required, within, min_required
                        ));
                    }
                } else {
                    if term_len + max_prefix_len > within {
                        let network_name = get_network_name_for_prefix(ss58_prefix);
                        let prefixes_display = if expected_prefixes.len() == 1 {
                            format!("'{}'", expected_prefixes[0])
                        } else {
                            expected_prefixes.iter().map(|p| format!("'{}'", p)).collect::<Vec<_>>().join(" or ")
                        };
                        
                        return Err(format!(
                            "Case-sensitive search: {} addresses start with {} ({} chars)\nYour term '{}' ({} chars) cannot match the prefix, so it needs {} chars after the prefix\nTotal needed: {} chars, but --within limit is {}\nSUGGESTION: Use --within {} or higher, or try case-insensitive mode",
                            network_name, prefixes_display, max_prefix_len, term, term_len, term_len, max_prefix_len + term_len, within, max_prefix_len + term_len
                        ));
                    }
                }
            } else {
                if max_prefix_len + term_len > within {
                    let network_name = get_network_name_for_prefix(ss58_prefix);
                    let prefixes_display = if expected_prefixes.len() == 1 {
                        format!("'{}'", expected_prefixes[0])
                    } else {
                        expected_prefixes.iter().map(|p| format!("'{}'", p)).collect::<Vec<_>>().join(" or ")
                    };
                    
                    let min_required = max_prefix_len + term_len;
                    return Err(format!(
                        "{} addresses start with {} ({} chars) + your term '{}' ({} chars) = {} total characters\nThis exceeds --within {} limit\nSUGGESTION: Use --within {} or higher, or try --suffix mode instead",
                        network_name, prefixes_display, max_prefix_len, term, term_len, min_required, within, min_required
                    ));
                }
            }
        }
    }

    Ok(())
}