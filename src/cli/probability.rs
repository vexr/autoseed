


/// Calculate how many characters overlap with the network prefix
fn calculate_prefix_overlap(pattern: &str, ss58_prefix: u16, within: usize) -> usize {
    // Get expected network prefixes
    let expected_prefixes = if let Some(network) = crate::networks::find_network_by_prefix(ss58_prefix) {
        network.address_prefixes
    } else {
        return 0; // Unknown network, no overlap
    };
    
    let pattern_lower = pattern.to_lowercase();
    let mut max_overlap = 0;
    
    // Check each possible network prefix
    for network_prefix in expected_prefixes {
        let prefix_lower = network_prefix.to_lowercase();
        let prefix_len = prefix_lower.len();
        
        // Check if pattern could overlap with network prefix within the character limit
        if pattern.len() <= within && prefix_len <= within {
            let overlap_check_len = pattern.len().min(prefix_len);
            let mut overlap = 0;
            
            // Check character by character from the start of pattern
            for i in 0..overlap_check_len {
                let pattern_char = pattern_lower.chars().nth(i).unwrap_or('?');
                let prefix_char = prefix_lower.chars().nth(i).unwrap_or('\0');
                
                if pattern_char == '?' || pattern_char == prefix_char {
                    overlap += 1;
                } else {
                    break; // No more consecutive overlap
                }
            }
            
            max_overlap = max_overlap.max(overlap);
        }
    }
    
    max_overlap
}

/// Determine the effective character set size for a specific character in Base58
fn get_character_set_size(ch: char, case_sensitive: bool) -> u64 {
    if ch == '?' {
        return 1; // Wildcard matches any character, so no difficulty
    }
    
    if case_sensitive {
        return 58; // All Base58 characters are distinct
    }
    
    // For case-insensitive mode, check if the character has case variants
    match ch {
        // Digits (0-9) - but 0 is not in Base58, so only 1-9
        '1'..='9' => 58, // Numbers have no case variants, must match exactly
        
        // Letters that exist in both cases in Base58
        // Base58 includes: A-H, J-N, P-Z (uppercase) and a-k, m-z (lowercase)
        // Missing: I, O, l (to avoid confusion)
        'A' | 'a' => 33, // 'A' and 'a' are both valid
        'B' | 'b' => 33, // 'B' and 'b' are both valid  
        'C' | 'c' => 33, // 'C' and 'c' are both valid
        'D' | 'd' => 33, // 'D' and 'd' are both valid
        'E' | 'e' => 33, // 'E' and 'e' are both valid
        'F' | 'f' => 33, // 'F' and 'f' are both valid
        'G' | 'g' => 33, // 'G' and 'g' are both valid
        'H' | 'h' => 33, // 'H' and 'h' are both valid
        'J' | 'j' => 33, // 'J' and 'j' are both valid
        'K' | 'k' => 33, // 'K' and 'k' are both valid
        'M' | 'm' => 33, // 'M' and 'm' are both valid
        'N' | 'n' => 33, // 'N' and 'n' are both valid
        'P' | 'p' => 33, // 'P' and 'p' are both valid
        'Q' | 'q' => 33, // 'Q' and 'q' are both valid
        'R' | 'r' => 33, // 'R' and 'r' are both valid
        'S' | 's' => 33, // 'S' and 's' are both valid
        'T' | 't' => 33, // 'T' and 't' are both valid
        'U' | 'u' => 33, // 'U' and 'u' are both valid
        'V' | 'v' => 33, // 'V' and 'v' are both valid
        'W' | 'w' => 33, // 'W' and 'w' are both valid
        'X' | 'x' => 33, // 'X' and 'x' are both valid
        'Y' | 'y' => 33, // 'Y' and 'y' are both valid
        'Z' | 'z' => 33, // 'Z' and 'z' are both valid
        
        // Characters that only exist in one case in Base58
        // These must match exactly even in case-insensitive mode
        _ => 58, // All other characters (or invalid ones) default to case-sensitive
    }
}

/// Calculate the probability for a pattern at a specific position
fn calculate_probability_at_position(
    pattern: &str,
    position: usize,
    case_sensitive: bool,
    ss58_prefix: u16,
) -> u64 {
    let mut probability = 1u64;
    
    // Check if this position allows prefix overlap (position 0)
    let prefix_overlap = if position == 0 {
        calculate_prefix_overlap(pattern, ss58_prefix, pattern.len())
    } else {
        0
    };
    
    // Calculate probability for each character
    let mut processed_chars = 0;
    for ch in pattern.chars() {
        // Skip characters that overlap with network prefix at position 0
        if position == 0 && processed_chars < prefix_overlap {
            processed_chars += 1;
            continue;
        }
        
        let char_set_size = get_character_set_size(ch, case_sensitive);
        probability = probability.saturating_mul(char_set_size);
        processed_chars += 1;
    }
    
    probability
}

/// Calculate expected attempts for finding a match using harmonic mean
pub fn calculate_expected_attempts(
    pattern: &str,
    case_sensitive: bool,
    suffix: bool,
    anywhere: bool,
    within: usize,
    ss58_prefix: u16,
) -> u64 {
    const SS58_ADDRESS_LENGTH: usize = 49;
    let pattern_len = pattern.chars().count();
    
    // Get the network prefix to check for locked positions
    let network_prefixes = if let Some(network) = crate::networks::find_network_by_prefix(ss58_prefix) {
        network.address_prefixes
    } else {
        &[] // Unknown network, no locked positions
    };
    
    let max_prefix_len = network_prefixes.iter().map(|p| p.len()).max().unwrap_or(0);
    
    // Helper function to check if pattern can match at a given position
    let can_match_at_position = |pos: usize| -> bool {
        if pos >= max_prefix_len {
            // Position is beyond any prefix constraints
            return true;
        }
        
        // Check if pattern at this position could match with the network prefix
        for prefix in network_prefixes {
            let prefix_len = prefix.len();
            if pos >= prefix_len {
                // This position is past this particular prefix
                continue;
            }
            
            // Check if pattern starting at 'pos' is compatible with the prefix
            let mut matches = true;
            let pattern_chars: Vec<char> = pattern.chars().collect();
            let prefix_chars: Vec<char> = prefix.chars().collect();
            
            for i in 0..pattern_len.min(prefix_len - pos) {
                let pattern_char = pattern_chars[i];
                let prefix_char = prefix_chars[pos + i];
                
                if pattern_char == '?' {
                    continue; // Wildcard always matches
                }
                
                if case_sensitive {
                    if pattern_char != prefix_char {
                        matches = false;
                        break;
                    }
                } else {
                    if !pattern_char.eq_ignore_ascii_case(&prefix_char) {
                        matches = false;
                        break;
                    }
                }
            }
            
            if matches {
                return true; // Pattern can match with at least one prefix variant
            }
        }
        
        false // Pattern conflicts with all prefix requirements at this position
    };
    
    // Determine valid positions based on mode
    let positions: Vec<usize> = if anywhere {
        let max_pos = SS58_ADDRESS_LENGTH.saturating_sub(pattern_len);
        let positions_range = if within >= SS58_ADDRESS_LENGTH {
            // Pattern can appear anywhere (but respect prefix locks)
            0..=max_pos
        } else if within >= pattern_len {
            // Limited to within window
            0..=within.saturating_sub(pattern_len).min(max_pos)
        } else {
            return u64::MAX; // Pattern doesn't fit
        };
        
        // Filter out positions that conflict with network prefix
        positions_range.filter(|&pos| can_match_at_position(pos)).collect()
    } else if suffix {
        if within >= SS58_ADDRESS_LENGTH {
            // Can appear anywhere that ends within address
            (0..=SS58_ADDRESS_LENGTH.saturating_sub(pattern_len)).collect()
        } else if within >= pattern_len {
            // Must END within the last 'within' characters
            let start = SS58_ADDRESS_LENGTH.saturating_sub(within);
            let end = SS58_ADDRESS_LENGTH.saturating_sub(pattern_len);
            (start..=end).collect()
        } else {
            vec![] // Pattern doesn't fit
        }
    } else {
        // Prefix mode: must START within first 'within' characters
        if within >= pattern_len {
            (0..=within.saturating_sub(pattern_len)).collect()
        } else {
            vec![] // Pattern doesn't fit
        }
    };
    
    if positions.is_empty() {
        // No valid positions, pattern can't be found
        return u64::MAX;
    }
    
    if positions.len() == 1 {
        // Only one position, simple calculation
        return calculate_probability_at_position(pattern, positions[0], case_sensitive, ss58_prefix);
    }
    
    // Calculate harmonic mean for multiple positions with different probabilities
    // Expected attempts = 1 / (sum of 1/probability for each position)
    let mut reciprocal_sum = 0.0_f64;
    
    for &pos in &positions {
        let probability = calculate_probability_at_position(pattern, pos, case_sensitive, ss58_prefix);
        if probability > 0 {
            reciprocal_sum += 1.0 / probability as f64;
        }
    }
    
    if reciprocal_sum > 0.0 {
        // Return the harmonic mean
        (1.0 / reciprocal_sum).round() as u64
    } else {
        u64::MAX
    }
}


/// Calculate the luck factor based on actual attempts vs median expected
pub fn calculate_luck_factor(actual_attempts: u64, median_expected: u64) -> f64 {
    if actual_attempts == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    {
        (median_expected as f64 / actual_attempts as f64) * 100.0
    }
}

/// Print detailed probability breakdown for debugging
pub fn print_probability_breakdown(
    pattern: &str,
    case_sensitive: bool,
    suffix: bool,
    anywhere: bool,
    within: usize,
    ss58_prefix: u16,
) {
    use crate::cli::terminal::colors;
    use num_format::{SystemLocale, ToFormattedString};
    
    const SS58_ADDRESS_LENGTH: usize = 49;
    let pattern_len = pattern.chars().count();
    let locale = SystemLocale::default().unwrap();
    
    println!("{}", colors::cyan("PROBABILITY CALCULATION"));

    // Pattern Analysis
    println!("\n{} '{}'", colors::blue("→ Pattern Analysis:"), colors::bright_yellow(pattern));
    
    let mut calculations = Vec::new();
    let mut calc_string = String::new();
    let mut base_probability = 1u64;
    
    // Check for prefix overlap in prefix mode
    let prefix_overlap = if !suffix && !anywhere {
        calculate_prefix_overlap(pattern, ss58_prefix, within)
    } else {
        0
    };
    
    let mut processed_chars = 0;
    for (i, ch) in pattern.chars().enumerate() {
        let char_probability = if !suffix && !anywhere && processed_chars < prefix_overlap {
            // This character overlaps with network prefix
            println!("├─ '{}' = {} (no randomness)", 
                     ch, colors::green("MATCHES network prefix ✓"));
            calculations.push("1".to_string());
            1
        } else if ch == '?' {
            println!("├─ '{}' = {} (matches anything - no randomness!)", 
                     ch, colors::green("1"));
            calculations.push("1".to_string());
            1
        } else {
            let set_size = get_character_set_size(ch, case_sensitive);
            if case_sensitive {
                println!("├─ '{}' = {} possible matches (exact '{}' only in Base58)", 
                         ch, colors::yellow("58"), ch);
            } else if ch.is_ascii_digit() {
                println!("├─ '{}' = {} possible matches (digit - must match exactly)", 
                         ch, colors::yellow("58"));
            } else {
                let upper = ch.to_ascii_uppercase();
                let lower = ch.to_ascii_lowercase();
                println!("├─ '{}' = {} possible matches ({} or {} in Base58)", 
                         ch, colors::yellow("33"), upper, lower);
            }
            calculations.push(set_size.to_string());
            set_size
        };
        
        if i > 0 {
            calc_string.push_str(" × ");
        }
        calc_string.push_str(&calculations[i]);
        base_probability = base_probability.saturating_mul(char_probability);
        processed_chars += 1;
    }
    
    // Base Calculation
    println!("\n{}", colors::blue("→ Base Calculation:"));
    println!("{} = {}", calc_string, colors::yellow(&base_probability.to_formatted_string(&locale)));
    
    if base_probability == 1 {
        println!("{}", colors::green("(Pattern matches network prefix or uses only wildcards - guaranteed match!)"));
    } else {
        println!("(This is how many random addresses you'd need to check if there was only ONE position)");
    }
    
    // Position Analysis
    let mode_name = if anywhere {
        "Anywhere Mode"
    } else if suffix {
        "Suffix Mode"
    } else {
        "Prefix Mode"
    };
    
    println!("\n{}", colors::blue(&format!("→ Position Analysis ({}):", mode_name)));
    println!("Address structure: [49 total characters]");
    
    // Get the network prefix to check for locked positions
    let network_prefixes = if let Some(network) = crate::networks::find_network_by_prefix(ss58_prefix) {
        network.address_prefixes
    } else {
        &[]
    };
    
    let max_prefix_len = network_prefixes.iter().map(|p| p.len()).max().unwrap_or(0);
    
    // Helper to check if pattern can match at a position
    let can_match_at_position = |pos: usize| -> bool {
        if pos >= max_prefix_len {
            return true;
        }
        
        for prefix in network_prefixes {
            let prefix_len = prefix.len();
            if pos >= prefix_len {
                continue;
            }
            
            let mut matches = true;
            let pattern_chars: Vec<char> = pattern.chars().collect();
            let prefix_chars: Vec<char> = prefix.chars().collect();
            
            for i in 0..pattern_len.min(prefix_len - pos) {
                let pattern_char = pattern_chars[i];
                let prefix_char = prefix_chars[pos + i];
                
                if pattern_char == '?' {
                    continue;
                }
                
                if case_sensitive {
                    if pattern_char != prefix_char {
                        matches = false;
                        break;
                    }
                } else {
                    if !pattern_char.eq_ignore_ascii_case(&prefix_char) {
                        matches = false;
                        break;
                    }
                }
            }
            
            if matches {
                return true;
            }
        }
        
        false
    };
    
    // Determine valid positions based on mode
    let positions: Vec<usize> = if anywhere {
        let max_pos = SS58_ADDRESS_LENGTH.saturating_sub(pattern_len);
        let positions_range = if within >= SS58_ADDRESS_LENGTH {
            0..=max_pos
        } else if within >= pattern_len {
            0..=within.saturating_sub(pattern_len).min(max_pos)
        } else {
            return; // Pattern doesn't fit
        };
        
        positions_range.filter(|&pos| can_match_at_position(pos)).collect()
    } else if suffix {
        if within >= SS58_ADDRESS_LENGTH {
            (0..=SS58_ADDRESS_LENGTH.saturating_sub(pattern_len)).collect()
        } else if within >= pattern_len {
            let start = SS58_ADDRESS_LENGTH.saturating_sub(within);
            let end = SS58_ADDRESS_LENGTH.saturating_sub(pattern_len);
            (start..=end).collect()
        } else {
            vec![]
        }
    } else {
        // Prefix mode
        if within >= pattern_len {
            (0..=within.saturating_sub(pattern_len)).collect()
        } else {
            vec![]
        }
    };
    
    let possible_positions = positions.len();
    
    // Get network prefixes for display
    let network_prefixes = if let Some(network) = crate::networks::find_network_by_prefix(ss58_prefix) {
        network.address_prefixes
    } else {
        &["??"] // Unknown network
    };
    
    // For display purposes, use the first prefix but handle multiple prefixes in logic
    let display_prefix = network_prefixes.first().unwrap_or(&"??");
    
    // Visual representation
    if suffix {
        let search_start = SS58_ADDRESS_LENGTH.saturating_sub(within);
        println!("  [{}{}{}]", 
                 display_prefix,
                 ".".repeat(search_start.saturating_sub(display_prefix.len())),
                 colors::yellow(&"x".repeat(within.min(SS58_ADDRESS_LENGTH - display_prefix.len()))));
        let prefix_info = if network_prefixes.len() > 1 {
            format!("└─ Network prefixes: {} (showing: {})                        └─ Search zone (last {} chars)", 
                    network_prefixes.join(", "), display_prefix, within)
        } else {
            format!("└─ Network prefix: {}                        └─ Search zone (last {} chars)", 
                    display_prefix, within)
        };
        println!("   {}", colors::yellow(&prefix_info));
        
        println!("\n  Where can \"{}\" ({} chars) fit in the last {} characters?", pattern, pattern_len, within);
        
        // Show positions with their individual probabilities
        if !positions.is_empty() {
            println!("\n  {}", colors::blue("Per-Position Probability Analysis:"));
            
            // Check if position 0 is included (for prefix overlap detection)
            let has_position_zero = positions.contains(&0);
            
            for (i, &pos) in positions.iter().enumerate() {
                if i >= 5 && positions.len() > 6 {
                    println!("... and {} more positions with similar probabilities", positions.len() - 5);
                    break;
                }
                
                let prob = calculate_probability_at_position(pattern, pos, case_sensitive, ss58_prefix);
                let dots_before = pos.saturating_sub(display_prefix.len()).min(37);
                let dashes_after = SS58_ADDRESS_LENGTH.saturating_sub(pos + pattern_len).min(10);
                
                if pos == 0 && has_position_zero {
                    // Special case for position 0 with prefix overlap
                    let prefix_overlap = calculate_prefix_overlap(pattern, ss58_prefix, pattern_len);
                    if prefix_overlap > 0 {
                        println!("Position {}: [{}{}{}{}]   Probability: {} {}", 
                                 pos,
                                 colors::green(display_prefix),
                                 ".".repeat(dots_before),
                                 colors::green(pattern),
                                 "-".repeat(dashes_after),
                                 prob.to_formatted_string(&locale),
                                 colors::green("(prefix overlap!)"));
                    } else {
                        println!("Position {}: [{}{}{}{}]   Probability: {}", 
                                 pos,
                                 display_prefix,
                                 ".".repeat(dots_before),
                                 colors::yellow(pattern),
                                 "-".repeat(dashes_after),
                                 prob.to_formatted_string(&locale));
                    }
                } else {
                    println!("Position {}: [{}{}{}{}]   Probability: {}", 
                             pos,
                             display_prefix,
                             ".".repeat(dots_before),
                             colors::yellow(pattern),
                             "-".repeat(dashes_after),
                             prob.to_formatted_string(&locale));
                }
            }
        }
    } else if anywhere {
        println!("  Pattern can appear {} in the address", colors::yellow("anywhere"));
        if within < SS58_ADDRESS_LENGTH {
            println!("  Limited to a window of {} characters", within);
        }
        
        // Show position probabilities for anywhere mode
        if !positions.is_empty() {
            println!("\n  {}", colors::blue("Per-Position Probability Analysis:"));
            
            let has_position_zero = positions.contains(&0);
            let pos0_prob = if has_position_zero {
                Some(calculate_probability_at_position(pattern, 0, case_sensitive, ss58_prefix))
            } else {
                None
            };
            
            let other_prob = if positions.len() > 1 {
                Some(calculate_probability_at_position(pattern, positions[1], case_sensitive, ss58_prefix))
            } else {
                None
            };
            
            if let Some(p0) = pos0_prob {
                let prefix_overlap = calculate_prefix_overlap(pattern, ss58_prefix, pattern_len);
                if prefix_overlap > 0 {
                    println!("Position  0: Probability {} {}", 
                             p0.to_formatted_string(&locale), colors::green("(network prefix overlap!)"));
                } else {
                    println!("Position  0: Probability {}", p0.to_formatted_string(&locale));
                }
            }
            
            if let Some(op) = other_prob {
                let remaining = positions.len() - (if has_position_zero { 1 } else { 0 });
                if remaining > 0 {
                    println!("Positions {}: Probability {} each ({} positions)",
                             if has_position_zero { "1-46" } else { "all" },
                             op.to_formatted_string(&locale),
                             remaining);
                }
            }
        }
    } else {
        // Prefix mode
        println!("  [{}{}]", 
                 colors::yellow(&"x".repeat(within.min(SS58_ADDRESS_LENGTH))),
                 ".".repeat(SS58_ADDRESS_LENGTH.saturating_sub(within)));
        println!("   {}", 
                 colors::yellow(&format!("└─ Search zone (first {} chars)", within)));
        
        // Show position probabilities for prefix mode
        if !positions.is_empty() {
            println!("\n  {}", colors::blue("Per-Position Probability Analysis:"));
            
            for (i, &pos) in positions.iter().enumerate() {
                if i >= 5 && positions.len() > 6 {
                    println!("... and {} more positions", positions.len() - 5);
                    break;
                }
                
                let prob = calculate_probability_at_position(pattern, pos, case_sensitive, ss58_prefix);
                
                if pos == 0 {
                    let prefix_overlap = calculate_prefix_overlap(pattern, ss58_prefix, pattern_len);
                    if prefix_overlap > 0 {
                        println!("Position {}: Probability {} {}", 
                                 pos,
                                 prob.to_formatted_string(&locale),
                                 colors::green("(network prefix overlap!)"));
                    } else {
                        println!("Position {}: Probability {}", pos, prob.to_formatted_string(&locale));
                    }
                } else {
                    println!("Position {}: Probability {}", pos, prob.to_formatted_string(&locale));
                }
            }
        }
    }
    
    println!("\n  {} {} valid positions possible",
             colors::gray("Result:"), possible_positions);
    
    // Final Calculation
    println!("\n{}", colors::blue("→ FINAL CALCULATION:"));
    println!("  {}", colors::gray("─────────────────────────"));
    
    let expected_attempts = if positions.is_empty() {
        println!("{}", colors::red("No valid positions found - pattern cannot match!"));
        u64::MAX
    } else if positions.len() == 1 {
        let prob = calculate_probability_at_position(pattern, positions[0], case_sensitive, ss58_prefix);
        println!("  Only 1 position available (position {})", positions[0]);
        prob
    } else {
        // Multiple positions - use harmonic mean
        println!("  Using harmonic mean for {} positions:", positions.len());
        
        let mut reciprocal_sum = 0.0_f64;
        let mut unique_probs = std::collections::HashMap::new();
        
        // Calculate and group probabilities
        for &pos in &positions {
            let prob = calculate_probability_at_position(pattern, pos, case_sensitive, ss58_prefix);
            *unique_probs.entry(prob).or_insert(0) += 1;
            if prob > 0 {
                reciprocal_sum += 1.0 / prob as f64;
            }
        }
        
        // Show unique probabilities and their counts
        let mut prob_entries: Vec<_> = unique_probs.iter().collect();
        prob_entries.sort_by_key(|&(prob, _)| prob);
        
        for (prob, count) in prob_entries {
            if *count == 1 {
                println!("    • 1 position with probability {}", prob.to_formatted_string(&locale));
            } else {
                println!("    • {} positions with probability {} each", count, prob.to_formatted_string(&locale));
            }
        }
        
        println!("\n  {}", colors::gray("Formula:"));
        println!("    Expected = 1 / (sum of 1/probability for each position)");
        
        // Show the calculation
        if unique_probs.len() == 1 {
            // All positions have same probability
            let (prob, _) = unique_probs.iter().next().unwrap();
            println!("             = 1 / ({} × 1/{})", positions.len(), prob.to_formatted_string(&locale));
            println!("             = {} / {}", prob.to_formatted_string(&locale), positions.len());
        } else {
            // Different probabilities
            let mut calc_str = String::from("             = 1 / (");
            let mut first = true;
            for (prob, count) in unique_probs.iter() {
                if !first {
                    calc_str.push_str(" + ");
                }
                if *count == 1 {
                    calc_str.push_str(&format!("1/{}", prob.to_formatted_string(&locale)));
                } else {
                    calc_str.push_str(&format!("{}/{}",  count, prob.to_formatted_string(&locale)));
                }
                first = false;
            }
            calc_str.push(')');
            println!("{}", calc_str);
        }
        
        let result = if reciprocal_sum > 0.0 {
            (1.0 / reciprocal_sum).round() as u64
        } else {
            u64::MAX
        };
        
        result
    };
    
    // Show probability as percentage
    #[allow(clippy::cast_precision_loss)]
    let percentage = 100.0 / expected_attempts as f64;
    
    // Dynamically determine decimal places needed to show at least 3 significant digits
    let percentage_str = if percentage >= 0.01 {
        // For percentages >= 0.01%, show up to 4 decimal places
        format!("{:.4}%", percentage)
    } else {
        // For smaller percentages, calculate how many decimal places we need
        // to show at least the first non-zero digit plus 2 more digits
        let neg_log = -percentage.log10();
        let decimal_places = (neg_log.ceil() as usize) + 2; // +2 for additional precision
        format!("{:.prec$}%", percentage, prec = decimal_places)
    };
    
    println!("\n{} Expected {} attempts • {} ({})",
             colors::yellow("→ SUMMARY:"),
             colors::bright_yellow(&format!("~{}", expected_attempts.to_formatted_string(&locale))),
             colors::gray(&format!("1 in {}", expected_attempts.to_formatted_string(&locale))),
             percentage_str);
    
    println!();
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_attempts_calculation() {
        // Test mixed pattern: letters + number (case-insensitive) in prefix mode
        let attempts = calculate_expected_attempts("ai3", false, false, false, 5, 6094);
        // Base: 'a' = 33, 'i' = 33, '3' = 58 -> 33 * 33 * 58 = 63,162
        // Within 5, pattern len 3, so 5 - 3 + 1 = 3 positions
        // 63162 / 3 = 21,054
        assert_eq!(attempts, (33 * 33 * 58) / 3);

        // Test suffix mode with same pattern
        let attempts_suffix = calculate_expected_attempts("ai3", false, true, false, 3, 6094);
        // Same base probability, but suffix with within=3 (pattern length)
        // Only 1 position where it fits exactly at the end
        assert_eq!(attempts_suffix, 33 * 33 * 58);

        // Test suffix mode with larger within
        let attempts_suffix_5 = calculate_expected_attempts("ai3", false, true, false, 5, 6094);
        // Within 5, pattern len 3, so 5 - 3 + 1 = 3 positions in the last 5 chars
        assert_eq!(attempts_suffix_5, (33 * 33 * 58) / 3);

        // Test anywhere mode - most positions available
        let attempts_anywhere = calculate_expected_attempts("ai3", false, false, true, 49, 6094);
        // 49 - 3 + 1 = 47 possible positions
        assert_eq!(attempts_anywhere, (33 * 33 * 58) / 47);
        
        // Test with wildcards - should be easier
        let attempts_wildcard = calculate_expected_attempts("ai?", false, false, false, 5, 6094);
        // 'a' = 33, 'i' = 33, '?' = 1 -> base = 1089
        // Within 5, pattern len 3, so 3 positions
        assert_eq!(attempts_wildcard, (33 * 33) / 3);
        assert!(attempts_wildcard < attempts);

        // Test case-sensitive - should be harder
        let attempts_case_sens = calculate_expected_attempts("ai3", true, false, false, 5, 6094);
        // Base: 58^3, with 3 positions
        assert_eq!(attempts_case_sens, 58_u64.pow(3) / 3);
        assert!(attempts_case_sens > attempts);
    }

    #[test]
    fn test_prefix_overlap() {
        // Test Autonomys prefix overlap
        let attempts_su = calculate_expected_attempts("su", false, false, false, 2, 6094);
        assert_eq!(attempts_su, 1); // Complete overlap, no random chars, 1 position

        let attempts_sub = calculate_expected_attempts("sub", false, false, false, 3, 6094);
        assert_eq!(attempts_sub, 33); // "su" overlaps, "b" is random, exactly 1 position

        // Test with larger within allowing multiple positions
        let attempts_sub_within5 = calculate_expected_attempts("sub", false, false, false, 5, 6094);
        // "su" overlaps, "b" is random (base = 33)
        // Within 5, pattern len 3, so 5 - 3 + 1 = 3 positions
        assert_eq!(attempts_sub_within5, 33 / 3);

        // Test no overlap with within
        let attempts_within = calculate_expected_attempts("test", false, false, false, 5, 6094);
        // No overlap, base = 33^4
        // Within 5, pattern len 4, so 5 - 4 + 1 = 2 positions
        assert_eq!(attempts_within, 33_u64.pow(4) / 2);
    }

    #[test]
    fn test_character_set_size() {
        // Test wildcard
        assert_eq!(get_character_set_size('?', false), 1);
        assert_eq!(get_character_set_size('?', true), 1);

        // Test numbers (no case variants)
        assert_eq!(get_character_set_size('1', false), 58);
        assert_eq!(get_character_set_size('5', false), 58);
        assert_eq!(get_character_set_size('9', false), 58);

        // Test letters with case variants
        assert_eq!(get_character_set_size('a', false), 33);
        assert_eq!(get_character_set_size('A', false), 33);
        assert_eq!(get_character_set_size('z', false), 33);
        assert_eq!(get_character_set_size('Z', false), 33);

        // Test case-sensitive mode (all characters = 58)
        assert_eq!(get_character_set_size('a', true), 58);
        assert_eq!(get_character_set_size('1', true), 58);
        assert_eq!(get_character_set_size('?', true), 1); // Wildcard is special
    }

}