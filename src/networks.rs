/// Network configuration for different Substrate-based chains
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub name: &'static str,
    pub ss58_prefix: u16,
    pub address_prefixes: &'static [&'static str],
}

impl NetworkConfig {
    pub const fn new(name: &'static str, ss58_prefix: u16, address_prefixes: &'static [&'static str]) -> Self {
        Self {
            name,
            ss58_prefix,
            address_prefixes,
        }
    }
}

/// Network reference table
pub const NETWORKS: &[NetworkConfig] = &[
    NetworkConfig::new("Autonomys", 6094, &["su"]),  // Single prefix
    NetworkConfig::new("Polkadot", 0, &["1"]),
    NetworkConfig::new("Substrate", 42, &["5"]),
    // Example with multiple prefixes (commented out):
    // NetworkConfig::new("Autonomys", 6094, &["su", "sub", "suc", "sue"]),
];

/// Find network configuration by name
pub fn find_network(name: &str) -> Option<&'static NetworkConfig> {
    NETWORKS.iter().find(|network| network.name.eq_ignore_ascii_case(name))
}

/// Find network configuration by SS58 prefix
pub fn find_network_by_prefix(ss58_prefix: u16) -> Option<&'static NetworkConfig> {
    NETWORKS.iter().find(|network| network.ss58_prefix == ss58_prefix)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_network() {
        assert!(find_network("autonomys").is_some());
        assert!(find_network("Autonomys").is_some());
        assert!(find_network("AUTONOMYS").is_some());
        assert!(find_network("polkadot").is_some());
        assert!(find_network("Polkadot").is_some());
        assert!(find_network("invalid").is_none());
    }

    #[test]
    fn test_autonomys_network() {
        let autonomys = find_network("autonomys").unwrap();
        assert_eq!(autonomys.name, "Autonomys");
        assert_eq!(autonomys.ss58_prefix, 6094);
        assert_eq!(autonomys.address_prefixes, &["su"]);
    }

    #[test]
    fn test_case_insensitive_lookup() {
        assert!(find_network("AUTONOMYS").is_some());
        assert!(find_network("polkadot").is_some());
        assert!(find_network("POLKADOT").is_some());
        assert!(find_network("substrate").is_some());
        assert!(find_network("SUBSTRATE").is_some());
    }
}