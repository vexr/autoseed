use crate::cli::terminal::{colors, terminal_codes, failed_indicator, success_indicator};
use std::io::{self, Write};
use zeroize::Zeroize;

pub fn get_password_interactive() -> String {
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║ {}: If you lose this password, you will NOT be able to access   ║", colors::yellow("WARNING"));
    println!("║ your wallet! Make sure to store it in a safe place.                  ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();

    loop {
        print!("Enter a password to encrypt your wallets: ");
        io::stdout().flush().unwrap();
        let mut pwd1 = match rpassword::read_password() {
            Ok(pwd) => {
                // Move cursor up one line and clear it
                print!("{}", terminal_codes::CURSOR_UP_CLEAR);
                if pwd.is_empty() {
                    print!("{} Password cannot be empty. Please try again.", failed_indicator());
                    io::stdout().flush().unwrap();
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    print!("{}", terminal_codes::CR_CLEAR_LINE);
                    continue;
                }
                pwd
            }
            Err(e) => {
                print!("{}", terminal_codes::CURSOR_UP_CLEAR);
                crate::cli::terminal::reset_terminal(); // Restore terminal state
                eprintln!("{} Failed to read password: {e}. Exiting.", failed_indicator());
                std::process::exit(1);
            }
        };

        print!("Confirm password: ");
        io::stdout().flush().unwrap();
        let mut pwd2 = match rpassword::read_password() {
            Ok(pwd) => {
                print!("{}", terminal_codes::CURSOR_UP_CLEAR); // Move up and clear
                pwd
            }
            Err(e) => {
                print!("{}", terminal_codes::CURSOR_UP_CLEAR);
                crate::cli::terminal::reset_terminal(); // Restore terminal state
                eprintln!("{} Failed to read password: {e}. Exiting.", failed_indicator());
                std::process::exit(1);
            }
        };

        if pwd1 != pwd2 {
            // Zeroize passwords before retry
            pwd1.zeroize();
            pwd2.zeroize();
            print!("{} Passwords do not match. Please try again.", failed_indicator());
            io::stdout().flush().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(2));
            print!("{}", terminal_codes::CR_CLEAR_LINE);
            continue;
        }

        // Zeroize pwd2 as it's no longer needed
        pwd2.zeroize();

        println!("{} Password confirmed.", success_indicator());
        println!(); // Add blank line after confirmation
        break pwd1;
    }
}