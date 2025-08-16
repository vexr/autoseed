use crate::runner::VanityResult;
use num_format::{SystemLocale, ToFormattedString};
use std::io::{self, Write};

#[cfg(windows)]
use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
#[cfg(windows)]
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
#[cfg(windows)]
use winapi::um::processenv::GetStdHandle;
#[cfg(windows)]
use winapi::um::winbase::STD_OUTPUT_HANDLE;
#[cfg(windows)]
use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_PROCESSING;

// ===== Terminal Control =====

/// Initialize ANSI color support on Windows
#[cfg(windows)]
pub fn enable_ansi_support() {
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle != INVALID_HANDLE_VALUE {
            let mut mode = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

/// Initialize ANSI color support (no-op on non-Windows platforms)
#[cfg(not(windows))]
pub fn enable_ansi_support() {
    // No-op on Unix-like systems
}


/// Cross-platform color helper functions
pub mod colors {
    use colored::Colorize;
    
    pub fn red(text: &str) -> String {
        text.red().to_string()
    }
    
    pub fn green(text: &str) -> String {
        text.green().to_string()
    }
    
    pub fn yellow(text: &str) -> String {
        text.yellow().to_string()
    }
    
    pub fn blue(text: &str) -> String {
        text.blue().to_string()
    }
    
    pub fn cyan(text: &str) -> String {
        text.cyan().to_string()
    }
    
    pub fn gray(text: &str) -> String {
        text.bright_black().to_string()
    }
    
    pub fn bright_yellow(text: &str) -> String {
        text.bright_yellow().to_string()
    }
    
    pub fn orange(text: &str) -> String {
        text.truecolor(255, 165, 0).to_string()
    }
    
}

/// Terminal control sequences
pub mod terminal_codes {
    pub const HIDE_CURSOR: &str = "\x1b[?25l";
    pub const SHOW_CURSOR: &str = "\x1b[?25h";
    pub const CLEAR_LINE: &str = "\x1b[2K";
    pub const CR_CLEAR_LINE: &str = "\r\x1b[2K";
    pub const CURSOR_UP_CLEAR: &str = "\x1b[1A\x1b[2K";
}

/// Helper functions for formatted indicators
pub fn failed_indicator() -> String {
    colors::red("✗")
}

pub fn success_indicator() -> String {
    colors::green("✔")
}

pub fn hide_cursor() {
    print!("{}", terminal_codes::HIDE_CURSOR);
    let _ = io::stdout().flush();
}

pub fn reset_terminal() {
    print!("\r{}", terminal_codes::CLEAR_LINE);
    print!("{}", terminal_codes::SHOW_CURSOR);
    let _ = io::stdout().flush();
}

pub fn clear_screen_completely() {
    // Complete screen clear like Linux `clear` command
    // Works on Windows 11+, macOS, and Linux
    print!("\x1b[3J\x1b[2J\x1b[H");
    let _ = io::stdout().flush();
}

/// Format ETA showing the two largest time components
pub fn format_eta(seconds: u64) -> String {
    use num_format::{SystemLocale, ToFormattedString};
    
    if seconds == 0 {
        return "~0s".to_string();
    }

    let locale = SystemLocale::default().unwrap();
    let years = seconds / (365 * 24 * 3600);
    let months = (seconds % (365 * 24 * 3600)) / (30 * 24 * 3600);
    let weeks = (seconds % (30 * 24 * 3600)) / (7 * 24 * 3600);
    let days = (seconds % (7 * 24 * 3600)) / (24 * 3600);
    let hours = (seconds % (24 * 3600)) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let components = vec![
        (years, "y"),
        (months, "mo"),
        (weeks, "w"),
        (days, "d"),
        (hours, "h"),
        (minutes, "m"),
        (secs, "s"),
    ];

    let non_zero: Vec<_> = components.into_iter().filter(|(val, _)| *val > 0).collect();

    match non_zero.len() {
        0 => "~0s".to_string(),
        1 => {
            let (val, unit) = non_zero[0];
            if unit == "y" {
                format!("~{}{}", val.to_formatted_string(&locale), unit)
            } else {
                format!("~{}{}", val, unit)
            }
        }
        _ => {
            let (val1, unit1) = non_zero[0];
            let (val2, unit2) = non_zero[1];
            let formatted_val1 = if unit1 == "y" {
                val1.to_formatted_string(&locale)
            } else {
                val1.to_string()
            };
            format!("~{}{} {}{}", formatted_val1, unit1, val2, unit2)
        }
    }
}

/// Format negative ETA (how long we've been over the expected time)
pub fn format_eta_negative(seconds: u64) -> String {
    use num_format::{SystemLocale, ToFormattedString};
    
    if seconds == 0 {
        return "-1s".to_string();
    }

    let locale = SystemLocale::default().unwrap();
    let years = seconds / (365 * 24 * 3600);
    let months = (seconds % (365 * 24 * 3600)) / (30 * 24 * 3600);
    let weeks = (seconds % (30 * 24 * 3600)) / (7 * 24 * 3600);
    let days = (seconds % (7 * 24 * 3600)) / (24 * 3600);
    let hours = (seconds % (24 * 3600)) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let components = vec![
        (years, "y"),
        (months, "mo"),
        (weeks, "w"),
        (days, "d"),
        (hours, "h"),
        (minutes, "m"),
        (secs, "s"),
    ];

    let non_zero: Vec<_> = components.into_iter().filter(|(val, _)| *val > 0).collect();

    match non_zero.len() {
        0 => "-1s".to_string(),
        1 => {
            let (val, unit) = non_zero[0];
            if unit == "y" {
                format!("-{}{}", val.to_formatted_string(&locale), unit)
            } else {
                format!("-{}{}", val, unit)
            }
        }
        _ => {
            let (val1, unit1) = non_zero[0];
            let (val2, unit2) = non_zero[1];
            let formatted_val1 = if unit1 == "y" {
                val1.to_formatted_string(&locale)
            } else {
                val1.to_string()
            };
            format!("-{}{} {}{}", formatted_val1, unit1, val2, unit2)
        }
    }
}

/// Get colored text for luck factor
pub fn get_luck_color(luck: f64, text: &str) -> String {
    match luck {
        l if l >= 80.0 => colors::green(text),
        l if l >= 50.0 => colors::yellow(text),
        l if l >= 25.0 => colors::orange(text),
        _ => colors::red(text),
    }
}

pub fn format_runtime(elapsed_secs: u64) -> String {
    format_runtime_with_nanos(elapsed_secs, elapsed_secs as u128 * 1_000_000_000)
}

pub fn format_runtime_with_nanos(elapsed_secs: u64, elapsed_nanos: u128) -> String {
    // Handle sub-second durations
    if elapsed_secs == 0 && elapsed_nanos > 0 {
        let millis = (elapsed_nanos / 1_000_000) as u64;
        if millis == 0 {
            return "1ms".to_string(); // Show at least 1ms for very fast operations
        }
        return format!("{}ms", millis);
    }
    
    let days = elapsed_secs / (24 * 3600);
    let hours = (elapsed_secs % (24 * 3600)) / 3600;
    let minutes = (elapsed_secs % 3600) / 60;
    let seconds = elapsed_secs % 60;

    if days > 0 {
        if hours > 0 || minutes > 0 {
            format!(
                "{} day{} {:02}:{:02}",
                days,
                if days == 1 { "" } else { "s" },
                hours,
                minutes
            )
        } else {
            format!("{} day{}", days, if days == 1 { "" } else { "s" })
        }
    } else if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

pub fn print_progress(
    keys_per_second: u64,
    total_attempts: u64,
    elapsed_secs: u64,
    eta: Option<&str>,
    luck: Option<f64>,
    found_count: usize,
    count: usize,
) {
    let time_str = format_runtime(elapsed_secs);

    // Build progress string - ALWAYS show full progress info during search
    let locale = SystemLocale::default().unwrap();
    let mut progress = format!(
        "\r{}{} {} {} · {} {} keys/s {} · {} {}",
        terminal_codes::CLEAR_LINE,
        colors::gray("Attempts:"),
        total_attempts.to_formatted_string(&locale),
        colors::gray("·"),
        colors::gray("Speed:"),
        keys_per_second.to_formatted_string(&locale),
        colors::gray("·"),
        colors::gray("Runtime:"),
        time_str
    );

    // Add batch progress if generating multiple wallets
    if count > 1 {
        use std::fmt::Write;
        let _ = write!(
            progress,
            " {} {} {found_count}/{count}",
            colors::gray("·"),
            colors::gray("Progress:")
        );
    }

    // Add ETA if provided
    if let Some(eta_str) = eta {
        use std::fmt::Write;
        let _ = write!(
            progress, 
            " {} {} {eta_str}",
            colors::gray("·"),
            colors::gray("ETA:")
        );
    }

    // Add luck factor if provided
    if let Some(luck_val) = luck {
        use std::fmt::Write;
        let formatted_luck = (luck_val as u64).to_formatted_string(&locale);
        let luck_text = format!("{}%", formatted_luck);
        let colored_luck = get_luck_color(luck_val, &luck_text);
        let _ = write!(
            progress,
            " {} {} {}",
            colors::gray("·"),
            colors::gray("Luck:"),
            colored_luck
        );
    }

    let mut stdout = io::stdout();
    let _ = stdout.write_all(progress.as_bytes());
    let _ = stdout.flush();
}

pub fn print_result(result: &VanityResult, hex_mode: bool, wallet_number: usize, elapsed_secs: u64, elapsed_nanos: u128, luck: f64, validation_status: &str) {
    use num_format::{SystemLocale, ToFormattedString};
    
    let address = &result.address;
    let highlighted_address = if result.matches > 0 {
        let start = result.offset;
        let end = start + result.matches;
        format!(
            "{}{}{}",
            &address[..start],
            colors::bright_yellow(&address[start..end]),
            &address[end..]
        )
    } else {
        address.clone()
    };

    println!("{} Address {}: {}", colors::blue("•"), wallet_number, highlighted_address);

    let secret_label = if hex_mode { "Private Key" } else { "Mnemonic" };
    println!("  {} {}: {}", colors::gray("└"), secret_label, result.secret);
    
    let found_in_str = format_runtime_with_nanos(elapsed_secs, elapsed_nanos);
    let locale = SystemLocale::default().unwrap();
    let attempts_str = result.attempts.to_formatted_string(&locale);
    let formatted_luck = (luck as u64).to_formatted_string(&locale);
    let luck_text = format!("{}%", formatted_luck);
    let colored_luck = get_luck_color(luck, &luck_text);
    println!(
        "  {} Stats: {} {} {} {} {} {} {}",
        colors::gray("└"),
        colors::gray("Luck:"),
        colored_luck,
        colors::gray("Found in:"),
        found_in_str,
        colors::gray("Attempts:"),
        attempts_str,
        validation_status
    );
}

pub fn print_header(
    target: &str,
    suffix: bool,
    anywhere: bool,
    within: usize,
    case_sensitive: bool,
    hex_mode: bool,
    threads: usize,
) -> usize {
    let position_str = if anywhere {
        "anywhere"
    } else if suffix {
        "as suffix"
    } else {
        "as prefix"
    };
    let case_str = if case_sensitive {
        "case-sensitive"
    } else {
        "case-insensitive"
    };
    let mode_str = if hex_mode { "hex" } else { "mnemonic" };

    let (header, plain_header) = if within > 0 {
        (
            format!(
                "Searching for '{}' {position_str} \
                 ({case_str}, within: {within}, mode: {mode_str}, \
                 threads: {threads})",
                colors::bright_yellow(target)
            ),
            format!(
                "Searching for '{target}' {position_str} \
                 ({case_str}, within: {within}, mode: {mode_str}, \
                 threads: {threads})"
            ),
        )
    } else {
        (
            format!(
                "Searching for '{}' {position_str} \
                 ({case_str}, mode: {mode_str}, threads: {threads})",
                colors::bright_yellow(target)
            ),
            format!(
                "Searching for '{target}' {position_str} \
                 ({case_str}, mode: {mode_str}, threads: {threads})"
            ),
        )
    };

    let length = plain_header.len();
    println!("{header}");
    length
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_format_eta() {
        assert_eq!(format_eta(45), "~45s");
        assert_eq!(format_eta(125), "~2m 5s");
        assert_eq!(format_eta(3_665), "~1h 1m");
        assert_eq!(format_eta(90_000), "~1d 1h");
        // Exactly 1 year shows as 1y 1d due to calculation
        assert_eq!(format_eta(31_536_000), "~1y 1d");
    }
    
    #[test]
    fn test_format_runtime_with_nanos() {
        // Test sub-second durations
        assert_eq!(format_runtime_with_nanos(0, 500_000_000), "500ms");
        assert_eq!(format_runtime_with_nanos(0, 1_500_000), "1ms");
        assert_eq!(format_runtime_with_nanos(0, 999_999_999), "999ms");
        assert_eq!(format_runtime_with_nanos(0, 100_000), "1ms"); // Less than 1ms shows as 1ms
        
        // Test normal durations (should work the same as before)
        assert_eq!(format_runtime_with_nanos(45, 45_000_000_000), "00:45");
        assert_eq!(format_runtime_with_nanos(125, 125_000_000_000), "02:05");
        assert_eq!(format_runtime_with_nanos(3665, 3_665_000_000_000), "01:01:05");
    }
}