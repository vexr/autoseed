/// Standard Substrate address length in characters
const SS58_ADDRESS_LENGTH: usize = 49;

/// Pre-computed search configuration for optimal performance
/// This struct is immutable and can be safely shared across threads
#[derive(Debug, Clone)]
pub struct OptimizedSearchConfig {
    /// Original search pattern
    pub pattern: String,
    /// Pattern length in characters (pre-computed)
    pub pattern_len: usize,
    /// Whether search is case-sensitive
    pub case_sensitive: bool,
    /// Pre-computed valid search range (start, end inclusive) for both modes
    pub search_range: Option<(usize, usize)>,
}

impl OptimizedSearchConfig {
    /// Create a new optimized search configuration  
    /// Pre-computes all values that would otherwise be calculated per-address
    pub fn new(pattern: &str, case_sensitive: bool, suffix: bool, anywhere: bool, within: usize) -> Self {
        let pattern_len = pattern.chars().count();

        // Pre-compute search positions based on mode
        let search_range = if pattern_len > SS58_ADDRESS_LENGTH {
            None // Pattern longer than address
        } else if anywhere {
            // For anywhere mode: pattern can appear anywhere in the address
            if within >= SS58_ADDRESS_LENGTH || within >= pattern_len {
                // Search entire valid range
                // Note: We don't filter by network prefix here because we don't know
                // the ss58_prefix at this point. The search will still work but may
                // check some impossible positions. This is OK for correctness.
                Some((0, SS58_ADDRESS_LENGTH - pattern_len))
            } else {
                None // Within constraint too restrictive for pattern length
            }
        } else if suffix {
            // For suffix mode: pattern must appear within the last `within` characters
            if within >= SS58_ADDRESS_LENGTH {
                // Search window covers entire address, so pattern can be anywhere
                Some((0, SS58_ADDRESS_LENGTH - pattern_len))
            } else {
                // Pattern must end within the last `within` characters
                // So it can start from (length - within) to (length - pattern_len)
                let earliest_start = SS58_ADDRESS_LENGTH.saturating_sub(within);
                let latest_start = SS58_ADDRESS_LENGTH - pattern_len;
                if earliest_start <= latest_start {
                    Some((earliest_start, latest_start))
                } else {
                    None // Pattern too long for the within constraint
                }
            }
        } else {
            // For prefix mode: entire pattern must fit within the first `within` characters
            if within >= pattern_len {
                let latest_start = within - pattern_len;
                Some((0, latest_start))
            } else {
                None // Pattern too long for the within constraint
            }
        };

        Self {
            pattern: pattern.to_string(),
            pattern_len,
            case_sensitive,
            search_range,
        }
    }

    /// Check if this configuration can possibly find matches
    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.search_range.is_some()
    }

    /// Get the pattern to use for comparison
    #[inline]
    pub fn get_pattern(&self) -> &str {
        &self.pattern
    }
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub count: usize,
    pub offset: usize,
}

/// Optimized byte-based comparison for ASCII-only Base58 addresses
#[inline]
fn compare_bytes_at_offset(
    pattern: &[u8],
    address: &[u8],
    offset: usize,
    case_sensitive: bool,
) -> usize {
    let pattern_len = pattern.len();
    let address_len = address.len();

    // Bounds check
    if offset + pattern_len > address_len {
        return 0;
    }

    let mut count = 0;
    for i in 0..pattern_len {
        let p_byte = pattern[i];
        let a_byte = address[offset + i];

        if p_byte == b'?' {
            count += 1;
        } else if case_sensitive {
            if p_byte == a_byte {
                count += 1;
            } else {
                break;
            }
        } else {
            // Case-insensitive ASCII comparison
            if p_byte.eq_ignore_ascii_case(&a_byte) {
                count += 1;
            } else {
                break;
            }
        }
    }

    count
}

/// Optimized search using pre-computed configuration
#[inline]
pub fn search_with_config(config: &OptimizedSearchConfig, address: &str) -> SearchResult {
    // Early exit if config is invalid
    if !config.is_valid() {
        return SearchResult {
            count: 0,
            offset: 0,
        };
    }

    let pattern_bytes = config.get_pattern().as_bytes();
    let address_bytes = address.as_bytes();

    if let Some((start, end)) = config.search_range {
        // Try each position in the range
        for pos in start..=end {
            let count =
                compare_bytes_at_offset(pattern_bytes, address_bytes, pos, config.case_sensitive);

            if count == config.pattern_len {
                return SearchResult { count, offset: pos };
            }
        }
    }

    SearchResult {
        count: 0,
        offset: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Config tests
    #[test]
    fn test_prefix_config() {
        let config = OptimizedSearchConfig::new("test", false, false, false, 0);
        assert!(config.is_valid());
        assert_eq!(config.search_range, Some((0, 0))); // Can only be at position 0
        assert_eq!(config.pattern_len, 4);

        // With within 5, pattern can be at positions 0-5
        let config2 = OptimizedSearchConfig::new("test", false, false, false, 5);
        assert!(config2.is_valid());
        assert_eq!(config2.search_range, Some((0, 5)));
    }

    #[test]
    fn test_suffix_config() {
        // With within 5, "ai" can appear anywhere in last 5 chars
        let config = OptimizedSearchConfig::new("ai", false, true, false, 5);
        assert!(config.is_valid());
        assert_eq!(config.search_range, Some((42, 47))); // positions 42-47

        // With within 2, must be at very end (pattern length is 2)
        let config2 = OptimizedSearchConfig::new("ai", false, true, false, 2);
        assert!(config2.is_valid());
        assert_eq!(config2.search_range, Some((47, 47)));
    }

    #[test]
    fn test_invalid_config() {
        // Pattern too long for address (50 chars)
        let config = OptimizedSearchConfig::new(&"a".repeat(50), false, false, false, 0);
        assert!(!config.is_valid());
    }

    // Search tests
    #[test]
    fn test_compare_bytes_at_offset_exact_match() {
        let pattern = b"ai3";
        let address = b"suai3xyz";

        // Exact match at offset 2
        assert_eq!(compare_bytes_at_offset(pattern, address, 2, true), 3);

        // No match at offset 0
        assert_eq!(compare_bytes_at_offset(pattern, address, 0, true), 0);
    }

    #[test]
    fn test_compare_bytes_at_offset_case_insensitive() {
        let pattern = b"AI3";
        let address = b"suai3xyz";

        // Should match case-insensitive
        assert_eq!(compare_bytes_at_offset(pattern, address, 2, false), 3);

        // Should not match case-sensitive
        assert_eq!(compare_bytes_at_offset(pattern, address, 2, true), 0);
    }

    #[test]
    fn test_compare_bytes_at_offset_wildcards() {
        let pattern = b"a?3";
        let address = b"suai3xyz";

        // Should match with wildcard
        assert_eq!(compare_bytes_at_offset(pattern, address, 2, true), 3);

        // Also works with different character at wildcard position
        let address2 = b"suax3xyz";
        assert_eq!(compare_bytes_at_offset(pattern, address2, 2, true), 3);
    }

    #[test]
    fn test_compare_bytes_at_offset_bounds() {
        let pattern = b"test";
        let address = b"short";

        // Should return 0 when pattern extends beyond address
        assert_eq!(compare_bytes_at_offset(pattern, address, 3, true), 0);
    }

    #[test]
    fn test_search_with_config_prefix() {
        let config = OptimizedSearchConfig::new("ai3", true, false, false, 5);
        let address = "suai3testaddress";

        let result = search_with_config(&config, address);
        assert_eq!(result.count, 3);
        assert_eq!(result.offset, 2);
    }

    #[test]
    fn test_search_with_config_suffix() {
        // Real addresses are 49 chars according to SS58_ADDRESS_LENGTH
        let config = OptimizedSearchConfig::new("xyz", true, true, false, 3);
        // Create a 49-character address ending with "xyz"
        let address = "su12345678901234567890123456789012345678901234xyz";
        assert_eq!(address.len(), 49); // Verify length

        let result = search_with_config(&config, address);
        assert_eq!(result.count, 3);
        assert_eq!(result.offset, 46); // 49 - 3 = 46
    }

    #[test]
    fn test_search_with_config_no_match() {
        let config = OptimizedSearchConfig::new("notfound", true, false, false, 5);
        let address = "sutestaddress";

        let result = search_with_config(&config, address);
        assert_eq!(result.count, 0);
        assert_eq!(result.offset, 0);
    }

    #[test]
    fn test_search_with_config_invalid() {
        // Create an invalid config (prefix search starting at position 0 without "su")
        let config = OptimizedSearchConfig::new("test", true, false, false, 0);
        let address = "sutestaddress";

        let result = search_with_config(&config, address);
        // Should return no match for invalid config
        assert_eq!(result.count, 0);
        assert_eq!(result.offset, 0);
    }
}