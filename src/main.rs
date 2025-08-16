mod cli;
mod crypto;
mod networks;
mod runner;
mod search;
mod validation;
mod wallet;

use cli::{
    args::{parse_and_validate_args, validate_output_directory},
    display::{display_save_location, display_statistics, process_individual_wallet},
    password::get_password_interactive,
    probability::{calculate_expected_attempts, print_probability_breakdown},
    terminal::{clear_screen_completely, hide_cursor, print_header, print_progress, reset_terminal, colors, enable_ansi_support, terminal_codes},
};
use runner::parallel::{generate_vanity_addresses, ProgressInfo};
use std::io::Write;
use zeroize::Zeroize;
use num_format::{SystemLocale, ToFormattedString};

/// Application header for display
const APP_HEADER: &str = r"
    ___         __       _____               __
   /   | __  __/ /_____ / ___/___  ___  ____/ /
  / /| |/ / / / __/ __ \\__ \/ _ \/ _ \/ __  / 
 / ___ / /_/ / /_/ /_/ /__/ /  __/  __/ /_/ /  
/_/  |_\__,_/\__/\____/____/\___/\___/\__,_/   
";


fn setup_signal_handler() {
    ctrlc::set_handler(move || {
        // Restore terminal echo (platform-specific)
        #[cfg(unix)]
        {
            std::process::Command::new("stty").arg("echo").status().ok();
        }

        reset_terminal();
        println!("\n"); // Two new lines so prompt has space
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");
}

fn main() {
    // Enable ANSI color support on Windows
    enable_ansi_support();
    
    setup_signal_handler();
    
    let config = parse_and_validate_args();
    
    // Clear screen and show header first
    clear_screen_completely(); // Clear scrollback + screen like Linux `clear` command
    println!("{}", colors::blue(APP_HEADER));

    // Get password once if in hex mode
    let password = if config.hex_mode {
        if let Some(pwd) = &config.password {
            Some(pwd.clone())
        } else {
            Some(get_password_interactive())
        }
    } else {
        None
    };

    let header_length = print_header(
        &config.term,
        config.suffix,
        config.anywhere,
        config.within,
        config.case_sensitive,
        config.hex_mode,
        config.threads,
    );

    let wallet_text = if config.count == 1 { "wallet" } else { "wallets" };
    
    // Get network name or show custom prefix
    let network_info = if let Some(network) = networks::find_network_by_prefix(config.ss58_prefix) {
        format!("{} (SS58: {})", network.name, config.ss58_prefix)
    } else {
        format!("Custom Network (SS58: {})", config.ss58_prefix)
    };
    
    // Calculate and display odds
    let expected_attempts = calculate_expected_attempts(
        &config.term,
        config.case_sensitive,
        config.suffix,
        config.anywhere,
        config.within,
        config.ss58_prefix,
    );
    let odds_str = expected_attempts.to_formatted_string(&SystemLocale::default().unwrap());
    
    let generating_line = format!("Generating {} {} for {} Expected: ~{} searches per wallet", 
                                  config.count, wallet_text, network_info, odds_str);
    println!("{}", generating_line);
    
    // Show output directory path
    let output_path = std::path::Path::new(&config.output_dir);
    let wallet_type = if config.hex_mode { "Encrypted" } else { "Mnemonic" };
    
    // Get absolute path but handle Windows UNC gracefully
    let absolute_path = output_path.canonicalize().unwrap_or_else(|_| {
        // If canonicalize fails, try to make it absolute manually
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(output_path)
    });
    
    // Convert to string and clean up Windows UNC prefix if present
    let mut path_str = absolute_path.display().to_string();
    
    // Remove Windows UNC prefix for user-friendly display
    if path_str.starts_with(r"\\?\") {
        path_str = path_str[4..].to_string();
    }
    
    // Ensure it ends with platform-appropriate separator
    let display_path = if path_str.ends_with(['/', '\\']) {
        path_str
    } else {
        format!("{}{}", path_str, std::path::MAIN_SEPARATOR)
    };
    
    let output_line = format!("{} wallets will be saved to: {}", wallet_type, display_path);
    println!("{}", output_line);
    
    // Use the longest of the three lines for the separator
    let separator_length = header_length.max(generating_line.len()).max(output_line.len());
    println!("{}", "─".repeat(separator_length));
    println!(); // Extra line before progress

    // Validate output directory after showing search parameters
    if let Err(e) = validate_output_directory(&config.output_dir) {
        eprintln!("{}: {e}", colors::red("ERROR"));
        reset_terminal();
        std::process::exit(1);
    }

    // Validate the search term based on case sensitivity mode and network
    if let Err(e) = validation::validate_search_term_with_prefix(
        &config.term,
        config.case_sensitive,
        config.suffix,
        config.within,
        config.ss58_prefix,
    ) {
        eprintln!("{}: {e}", colors::red("ERROR"));
        reset_terminal();
        std::process::exit(1);
    }

    // Show probability breakdown if flag is set
    if config.probability {
        print_probability_breakdown(
            &config.term,
            config.case_sensitive,
            config.suffix,
            config.anywhere,
            config.within,
            config.ss58_prefix,
        );
    }

    // Hide cursor during search
    hide_cursor();

    // Track wallet number for streaming display
    let wallet_counter = std::sync::atomic::AtomicUsize::new(0);
    let start_time = std::time::Instant::now();
    // Use Mutex to store Instant for precise timing
    let last_wallet_instant = std::sync::Arc::new(std::sync::Mutex::new(start_time));

    // Use multi-threaded generator with ETA and luck
    let (results, total_stats) = generate_vanity_addresses(
        config.count,
        config.case_sensitive,
        config.hex_mode,
        config.ss58_prefix,
        config.within,
        config.suffix,
        config.anywhere,
        &config.term,
        config.threads,
        |info: ProgressInfo| {
            print_progress(
                info.keys_per_second,
                info.total_attempts,
                info.elapsed_secs,
                info.eta.as_deref(),
                info.luck,
                info.found_count,
                info.count,
            );
        },
        {
            let last_wallet_instant = last_wallet_instant.clone();
            let config_clone = config.clone();
            let password_clone = password.clone();
            move |result: &runner::VanityResult| {
                let wallet_num = wallet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let current_instant = std::time::Instant::now();
                
                // Calculate time for this specific wallet with nanosecond precision
                let wallet_duration = {
                    let mut last_instant = last_wallet_instant.lock().unwrap();
                    let duration = current_instant.duration_since(*last_instant);
                    *last_instant = current_instant; // Update for next wallet
                    duration
                };
                
                let wallet_elapsed_secs = wallet_duration.as_secs();
                let wallet_elapsed_nanos = wallet_duration.as_nanos();
                
                // Clear the progress line completely and ensure clean display
                // For all wallets, we need to clear the current progress line and move cursor to start
                print!("{}", terminal_codes::CR_CLEAR_LINE); // Clear the progress line
                std::io::stdout().flush().unwrap();
                
                process_individual_wallet(result, &config_clone, &password_clone, wallet_num, wallet_elapsed_secs, wallet_elapsed_nanos);
            }
        },
    );

    // Clear the final progress line since it's redundant after all wallets are found
    print!("{}", terminal_codes::CR_CLEAR_LINE); // Clear the final progress line
    std::io::stdout().flush().unwrap();

    // Display statistics
    display_statistics(&results, &total_stats, &config);

    // Show save location
    display_save_location(&config);

    // Restore terminal state
    reset_terminal();

    // Clear password from memory
    if let Some(mut pwd) = password {
        pwd.zeroize();
    }
}
