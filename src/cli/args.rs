use clap::{Arg, ArgAction, Command};
use crate::cli::terminal::{colors, print_header};
use crate::cli::probability::calculate_expected_attempts;
use num_format::{SystemLocale, ToFormattedString};

/// Application header for display
const APP_HEADER: &str = r"
    ___    _________         _    __            _ __       
   /   |  /  _/__  /_  __   | |  / /___ _____  (_) /___  __
  / /| |  / /  /_ <| |/_/   | | / / __ `/ __ \/ / __/ / / /
 / ___ |_/ / ___/ />  <     | |/ / /_/ / / / / / /_/ /_/ / 
/_/  |_/___//____/_/|_|     |___/\__,_/_/ /_/_/\__/\__, /  
                                                  /____/   
";

#[derive(Debug, Clone)]
pub struct Config {
    pub count: usize,
    pub case_sensitive: bool,
    pub hex_mode: bool,
    pub ss58_prefix: u16,
    pub within: usize,
    pub output_dir: String,
    pub password: Option<String>,
    pub suffix: bool,
    pub anywhere: bool,
    pub term: String,
    pub threads: usize,
    pub probability: bool,
}

fn get_default_wallet_dir() -> String {
    "wallets".to_string()
}

fn show_error_with_search_params(
    term: &str,
    suffix: bool,
    anywhere: bool,
    within: usize,
    case_sensitive: bool,
    hex_mode: bool,
    threads: usize,
    ss58_prefix: u16,
    count: usize,
    error_msg: &str,
) {
    // Show search parameters like during normal execution
    let header_length = print_header(term, suffix, anywhere, within, case_sensitive, hex_mode, threads);
    
    let wallet_text = if count == 1 { "wallet" } else { "wallets" };
    
    // Get network name or show custom prefix
    let network_info = if let Some(network) = crate::networks::find_network_by_prefix(ss58_prefix) {
        format!("{} (SS58: {})", network.name, ss58_prefix)
    } else {
        format!("Custom Network (SS58: {})", ss58_prefix)
    };
    
    // Calculate and display odds
    let expected_attempts = calculate_expected_attempts(
        term,
        case_sensitive,
        suffix,
        false, // anywhere - this is for error display, use false as default
        within,
        ss58_prefix,
    );
    let odds_str = expected_attempts.to_formatted_string(&SystemLocale::default().unwrap());
    
    println!("Generating {} {} for {} Expected: ~{} searches per wallet", 
             count, wallet_text, network_info, odds_str);
    println!("{}", "─".repeat(header_length));
    println!(); // Extra line before error
    
    // Parse error message to separate ERROR and SUGGESTION parts
    if let Some(suggestion_pos) = error_msg.find("SUGGESTION:") {
        let (error_part, suggestion_part) = error_msg.split_at(suggestion_pos);
        eprintln!("{}: {}", colors::red("ERROR"), error_part.trim());
        eprintln!("{}: {}", colors::yellow("SUGGESTION"), &suggestion_part[11..].trim()); // Skip "SUGGESTION:"
    } else {
        eprintln!("{}: {}", colors::red("ERROR"), error_msg);
    }
    
    crate::cli::terminal::reset_terminal();
    std::process::exit(1);
}

fn build_cli() -> Command {
    Command::new("autoseed")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Vanity Address Generator for Substrate Networks\nSupports Autonomys, Polkadot, Substrate, and custom networks\n\nCreated by vexr (github.com/vexr)")
        .long_about(APP_HEADER)
        .author("vexr")
        .arg(
            Arg::new("anywhere")
                .long("anywhere")
                .short('a')
                .help("Search for term anywhere in the address")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["prefix", "suffix"]),
        )
        .arg(
            Arg::new("case-sensitive")
                .long("case-sensitive")
                .short('C')
                .help("Case sensitive search (default: case insensitive)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("count")
                .long("count")
                .short('c')
                .value_name("COUNT")
                .help("Number of wallets to generate")
                .value_parser(clap::value_parser!(usize))
                .default_value("3"),
        )
        .arg(
            Arg::new("hex")
                .long("hex")
                .short('x')
                .help("Use hex mode for faster generation (shows hex seed instead of mnemonic)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("network")
                .long("network")
                .value_name("NETWORK")
                .help("Network to generate addresses for (Autonomys, Polkadot, Substrate)")
                .conflicts_with("ss58-prefix"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .value_name("DIR")
                .help("Directory to save wallets"),
        )
        .arg(
            Arg::new("pass")
                .long("pass")
                .value_name("PASSWORD")
                .help("Password for encrypting wallets (non-interactive mode)"),
        )
        .arg(
            Arg::new("prefix")
                .long("prefix")
                .short('p')
                .help("Search for term at start of address (after network prefix)")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["suffix", "anywhere"]),
        )
        .arg(
            Arg::new("ss58-prefix")
                .long("ss58-prefix")
                .value_name("PREFIX")
                .help("SS58 prefix number for custom networks (6094=Autonomys, 0=Polkadot, 42=Substrate)")
                .value_parser(clap::value_parser!(u16))
                .conflicts_with("network"),
        )
        .arg(
            Arg::new("suffix")
                .long("suffix")
                .short('s')
                .help("Search for term at end of address (default)")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["prefix", "anywhere"]),
        )
        .arg(
            Arg::new("term")
                .long("term")
                .short('t')
                .value_name("SEARCH_TERM")
                .help("Search term to find in the address")
                .default_value("ai3"),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .value_name("COUNT")
                .help("Number of threads to use (default: number of CPU cores)")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("within")
                .long("within")
                .value_name("CHARS")
                .help("Max characters from start (prefix) or end (suffix) to search within. Default: term length (suffix), 5 (prefix)")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("probability")
                .long("probability")
                .short('P')
                .help("Show detailed probability calculations and expected attempts")
                .action(ArgAction::SetTrue),
        )
}

pub fn parse_and_validate_args() -> Config {
    let mut cmd = build_cli();

    // Check if any arguments were provided
    if std::env::args().count() == 1 {
        // No arguments provided, show help (header already shown in main)
        let _ = cmd.print_help();
        println!(); // Add newline after help
        std::process::exit(0);
    }

    let matches = cmd.get_matches();

    let hex_mode = matches.get_flag("hex");
    let count = *matches.get_one::<usize>("count").unwrap();

    // Determine SS58 prefix from either --network or --ss58-prefix
    let ss58_prefix = if let Some(network_name) = matches.get_one::<String>("network") {
        // Validate network name and get its prefix
        if let Some(network_config) = crate::networks::find_network(network_name) {
            network_config.ss58_prefix
        } else {
            eprintln!("{}: Unknown network '{}'. Available networks: Autonomys, Polkadot, Substrate", 
                     colors::red("ERROR"), network_name);
            crate::cli::terminal::reset_terminal();
            std::process::exit(1);
        }
    } else if let Some(prefix) = matches.get_one::<u16>("ss58-prefix") {
        // Use the provided SS58 prefix directly
        *prefix
    } else {
        // Default to Autonomys (6094)
        6094
    };

    // Validate count
    if count == 0 {
        eprintln!("{}: Count must be at least 1", colors::red("ERROR"));
        crate::cli::terminal::reset_terminal();
        std::process::exit(1);
    }
    if count > 1000 {
        eprintln!("{}: Count too large (maximum: 1000)", colors::red("ERROR"));
        crate::cli::terminal::reset_terminal();
        std::process::exit(1);
    }

    let threads = matches
        .get_one::<usize>("threads")
        .map_or_else(num_cpus::get, |t| *t);
    
    if threads == 0 {
        eprintln!("{}: Thread count must be at least 1", colors::red("ERROR"));
        crate::cli::terminal::reset_terminal();
        std::process::exit(1);
    }

    let prefix_flag = matches.get_flag("prefix");
    let suffix_flag = matches.get_flag("suffix");
    let anywhere_flag = matches.get_flag("anywhere");
    
    // Default to suffix mode if none are specified
    let (prefix, suffix, anywhere) = match (prefix_flag, suffix_flag, anywhere_flag) {
        (true, false, false) => (true, false, false),
        (false, true, false) => (false, true, false),
        (false, false, true) => (false, false, true),
        (false, false, false) => (false, true, false), // Default to suffix mode
        _ => unreachable!(), // clap prevents conflicting combinations
    };

    let term = matches.get_one::<String>("term").unwrap().to_string();
    
    // Calculate default within value based on mode
    let within = if let Some(within_value) = matches.get_one::<usize>("within") {
        *within_value
    } else {
        // Default: term length for suffix mode, 5 for prefix mode, full address for anywhere
        if suffix {
            term.chars().count()
        } else if anywhere {
            49 // Full SS58 address length
        } else {
            5 // prefix mode
        }
    };
    
    // Validate impossible prefix combinations early
    if prefix && !suffix && !anywhere {
        if let Some(expected_prefixes) = crate::networks::find_network_by_prefix(ss58_prefix).map(|n| n.address_prefixes) {
            let max_prefix_len = expected_prefixes.iter().map(|p| p.len()).max().unwrap_or(0);
            
            if within < max_prefix_len {
                // Check if the search term could possibly match any network prefix
                let case_sensitive = matches.get_flag("case-sensitive");
                let mut could_match = false;
                
                for network_prefix in expected_prefixes {
                    // For case-sensitive, compare exact case. For case-insensitive, use lowercase
                    let (term_to_check, prefix_to_check) = if case_sensitive {
                        (term.clone(), network_prefix.to_string())
                    } else {
                        (term.to_lowercase(), network_prefix.to_lowercase())
                    };
                    
                    // Check if term starts with the network prefix or valid wildcard pattern
                    if term_to_check.starts_with(&prefix_to_check) {
                        could_match = true;
                        break;
                    }
                    
                    // Check wildcard patterns
                    for i in 0..network_prefix.len() {
                        let mut pattern = prefix_to_check.clone();
                        pattern.replace_range(i..i+1, "?");
                        if term_to_check.starts_with(&pattern) {
                            could_match = true;
                            break;
                        }
                    }
                    
                    if could_match {
                        break;
                    }
                }
                
                if !could_match {
                    let network_name = if let Some(network) = crate::networks::find_network_by_prefix(ss58_prefix) {
                        network.name
                    } else {
                        "Custom network"
                    };
                    
                    let prefixes_display = if expected_prefixes.len() == 1 {
                        format!("'{}'", expected_prefixes[0])
                    } else {
                        expected_prefixes.iter().map(|p| format!("'{}'", p)).collect::<Vec<_>>().join(" or ")
                    };
                    
                    let case_info = if case_sensitive {
                        " (case-sensitive mode)"
                    } else {
                        ""
                    };
                    
                    let error_msg = format!("Impossible prefix match! {} addresses start with {}, but search term '{}' cannot fit within {} characters{}\nSUGGESTION: Use --within {} or higher, or try --suffix mode instead.", 
                             network_name, prefixes_display, term, within, case_info, max_prefix_len);
                    
                    show_error_with_search_params(
                        &term,
                        suffix,
                        anywhere,
                        within,
                        case_sensitive,
                        matches.get_flag("hex"),
                        threads,
                        ss58_prefix,
                        count,
                        &error_msg,
                    );
                }
            }
        }
    }

    Config {
        count,
        case_sensitive: matches.get_flag("case-sensitive"),
        hex_mode,
        ss58_prefix,
        within,
        output_dir: matches
            .get_one::<String>("output")
            .map(|s| s.to_string())
            .unwrap_or_else(get_default_wallet_dir),
        password: matches.get_one::<String>("pass").map(|s| s.to_string()),
        suffix,
        anywhere,
        term,
        threads,
        probability: matches.get_flag("probability"),
    }
}

pub fn validate_output_directory(dir: &str) -> Result<(), String> {
    use std::fs;
    use std::path::Path;

    let path = Path::new(dir);

    // Try to create the directory if it doesn't exist
    if !path.exists() {
        fs::create_dir_all(path)
            .map_err(|e| format!("Failed to create output directory '{dir}': {e}"))?;
    }

    // Check if we can write to the directory
    let test_file = path.join(".write_test");
    match fs::write(&test_file, b"test") {
        Ok(_) => {
            // Clean up test file
            let _ = fs::remove_file(test_file);
            Ok(())
        }
        Err(e) => Err(format!("Output directory '{dir}' is not writable: {e}")),
    }
}