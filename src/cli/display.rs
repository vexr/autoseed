use crate::validation::{validate_wallet, ValidationResult};
use crate::cli::args::Config;
use crate::cli::probability::{calculate_luck_factor, calculate_expected_attempts};
use crate::cli::terminal::{format_runtime_with_nanos, get_luck_color, failed_indicator, colors};
use crate::runner::{VanityResult, GenerationStats};
use crate::wallet;
use num_format::{SystemLocale, ToFormattedString};
use std::io::{self, Write};

pub fn process_individual_wallet(
    result: &VanityResult, 
    config: &Config, 
    password: &Option<String>,
    wallet_number: usize,
    elapsed_secs: u64,
    elapsed_nanos: u128,
) {
    // Calculate luck for this individual wallet using mean-based calculation
    let expected_attempts = calculate_expected_attempts(
        &config.term,
        config.case_sensitive,
        config.suffix,
        config.anywhere,
        config.within,
        config.ss58_prefix,
    );
    let luck = calculate_luck_factor(result.attempts, expected_attempts);
    
    // Validate wallet and get validation status
    let validation_result = validate_wallet(&result.secret, &result.address, result.ss58_prefix, config.hex_mode);
    let validation_status = match validation_result {
        ValidationResult::Valid => format!("{} {} {} {}",
            colors::gray("Validated:"), colors::green(validation_result.status_symbol()),
            colors::gray("Saved:"), colors::green("✔")),
        ValidationResult::Mismatch => format!("{} {}",
            colors::gray("Validated:"), colors::red(validation_result.status_symbol())),
        ValidationResult::Error => format!("{} {}",
            colors::gray("Validated:"), colors::yellow(validation_result.status_symbol())),
    };

    crate::cli::terminal::print_result(result, config.hex_mode, wallet_number, elapsed_secs, elapsed_nanos, luck, &validation_status);
    io::stdout().flush().unwrap();

    // Save wallet files based on mode
    if config.hex_mode {
        // Save encrypted JSON for hex mode
        if let Some(pwd) = password
            && let Err(e) =
                wallet::save_wallet_json(result, pwd, &config.term, &config.output_dir)
        {
            eprintln!("  {} Failed to save wallet: {e}", failed_indicator());
        }
    } else {
        // Save mnemonic as text file for mnemonic mode
        if let Err(e) = wallet::save_wallet_mnemonic(result, &config.output_dir) {
            eprintln!("  {} Failed to save mnemonic: {e}", failed_indicator());
        }
    }
    
    // Add line break before progress counter continues
    println!();
}

pub fn display_statistics(
    results: &[VanityResult],
    total_stats: &GenerationStats,
    config: &Config,
) {
    // Only show overall summary if we generated multiple wallets
    if results.len() > 1 {
        // Calculate expected attempts for luck display using mean-based calculation
        let expected_attempts = calculate_expected_attempts(
            &config.term,
            config.case_sensitive,
            config.suffix,
            config.anywhere,
            config.within,
            config.ss58_prefix,
        );
        
        // Calculate speed using nanoseconds for maximum precision
        // Even at 100M keys/s, we'd need 10ns per key, so nanosecond precision is sufficient
        let avg_speed = if total_stats.elapsed_nanos > 0 {
            // Convert to keys per second: (attempts * 1_000_000_000) / nanos
            ((total_stats.total_attempts as u128 * 1_000_000_000) / total_stats.elapsed_nanos) as u64
        } else {
            0
        };
        let locale = SystemLocale::default().unwrap();
        let avg_speed_str = avg_speed.to_formatted_string(&locale);
        let found_in_str = format_runtime_with_nanos(total_stats.elapsed_secs, total_stats.elapsed_nanos);
        
        // Calculate overall luck based on total attempts vs expected total attempts
        #[allow(clippy::cast_precision_loss)]
        let expected_total_attempts = expected_attempts * results.len() as u64;
        let overall_luck = calculate_luck_factor(total_stats.total_attempts, expected_total_attempts);
        let formatted_overall_luck = (overall_luck as u64).to_formatted_string(&locale);
        let luck_text = format!("{}%", formatted_overall_luck);
        let overall_luck_color = get_luck_color(overall_luck, &luck_text);
        
        println!();
        let total_attempts_str = total_stats.total_attempts.to_formatted_string(&locale);
        println!(
            "Overall Stats: {} {} {} {} {} {} {} {}",
            colors::gray("Found in:"), found_in_str,
            colors::gray("Total Attempts:"), total_attempts_str,
            colors::gray("Speed:"), format!("{} keys/s", avg_speed_str),
            colors::gray("Overall Luck:"), overall_luck_color
        );
    }
}

pub fn display_save_location(_config: &Config) {
    // No longer display save location at the end since it's shown in the header
}