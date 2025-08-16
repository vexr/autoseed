use crate::wallet::{
    generate_hex_seed, generate_mnemonic, seed_to_hex_string,
};
use crate::cli::{
    format_eta, format_eta_negative, calculate_luck_factor, calculate_expected_attempts,
};
use crate::runner::{GenerationStats, VanityResult};
use crate::search::OptimizedSearchConfig;
use crate::search::search_with_config;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct WorkerConfig {
    hex_mode: bool,
    search_config: OptimizedSearchConfig,
    ss58_prefix: u16,
    target: String,
}

struct SharedState {
    count: usize,
    found_count: AtomicUsize,
    last_wallet_attempts: AtomicU64, // Track attempts since last wallet found
    should_stop: AtomicBool,
    total_attempts: AtomicU64,
}

pub struct ProgressInfo {
    pub count: usize,
    pub elapsed_secs: u64,
    pub eta: Option<String>,
    pub found_count: usize,
    pub keys_per_second: u64,
    pub luck: Option<f64>,
    pub total_attempts: u64,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn generate_vanity_addresses<F, W>(
    count: usize,
    case_sensitive: bool,
    hex_mode: bool,
    ss58_prefix: u16,
    within: usize,
    suffix: bool,
    anywhere: bool,
    target: &str,
    thread_count: usize,
    mut progress_callback: F,
    mut wallet_callback: W,
) -> (Vec<VanityResult>, GenerationStats)
where
    F: FnMut(ProgressInfo),
    W: FnMut(&VanityResult),
{
    let start_time = Instant::now();

    // Calculate expected attempts using mean-based calculation
    let expected_attempts = calculate_expected_attempts(target, case_sensitive, suffix, anywhere, within, ss58_prefix);

    // Create shared configuration
    let worker_config = WorkerConfig {
        hex_mode,
        search_config: OptimizedSearchConfig::new(target, case_sensitive, suffix, anywhere, within),
        ss58_prefix,
        target: target.to_string(),
    };

    // Validate search config
    if !worker_config.search_config.is_valid() {
        eprintln!("{}: Invalid search configuration: pattern '{}' cannot be found with current settings", 
                 crate::cli::terminal::colors::red("ERROR"), target);
        crate::cli::terminal::reset_terminal();
        std::process::exit(1);
    }

    // Create shared state
    let shared_state = Arc::new(SharedState {
        count,
        found_count: AtomicUsize::new(0),
        last_wallet_attempts: AtomicU64::new(0),
        should_stop: AtomicBool::new(false),
        total_attempts: AtomicU64::new(0),
    });

    // Create channels for results
    let (tx, rx): (Sender<VanityResult>, Receiver<VanityResult>) = bounded(thread_count * 2);

    // Spawn worker threads
    let mut handles = Vec::with_capacity(thread_count);

    for _ in 0..thread_count {
        let config = worker_config.clone();
        let state = shared_state.clone();
        let tx = tx.clone();

        let handle = thread::spawn(move || {
            worker_thread(&config, &state, &tx);
        });

        handles.push(handle);
    }

    // Drop the original sender so the channel closes when all workers are done
    drop(tx);

    // Collect results and report progress
    let mut results = Vec::with_capacity(count);
    let mut last_progress_report = Instant::now();
    let report_interval = Duration::from_secs(1);

    // Use a timeout on receive to check progress periodically
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => {
                // Only process if we haven't reached our count yet
                if results.len() < count {
                    // Call wallet callback immediately when found
                    wallet_callback(&result);
                    
                    results.push(result);

                    // Note: last_wallet_attempts is now reset atomically in worker_thread using swap(0)

                    // Check if we've found enough
                    if results.len() >= count {
                        // Signal all workers to stop
                        shared_state.should_stop.store(true, Ordering::Relaxed);
                        break; // Exit immediately when we have enough
                    }
                }
                // Ignore extra results if we already have enough
            }
            Err(_) => {
                // Check if all workers have finished
                if handles.iter().all(std::thread::JoinHandle::is_finished) {
                    break;
                }
            }
        }

        // Report progress if needed
        if last_progress_report.elapsed() >= report_interval {
            let total = shared_state.total_attempts.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed();
            let keys_per_sec = if elapsed.as_secs() > 0 {
                total / elapsed.as_secs()
            } else {
                0
            };

            // Calculate ETA and luck
            let current_wallet_attempts = shared_state.last_wallet_attempts.load(Ordering::Relaxed);
            let found_count_val = shared_state.found_count.load(Ordering::Relaxed);
            let (eta, luck) = if current_wallet_attempts > 0 && keys_per_sec > 0 {
                // Calculate remaining attempts based on expected mean
                let eta_str = if current_wallet_attempts >= expected_attempts {
                    // Past expected - show negative time (how long we've been over)
                    let over_attempts = current_wallet_attempts - expected_attempts;
                    let over_seconds = over_attempts / keys_per_sec;
                    format_eta_negative(over_seconds)
                } else {
                    // Still within expected range - show positive ETA
                    let remaining = expected_attempts - current_wallet_attempts;
                    let eta_seconds = remaining / keys_per_sec;
                    format_eta(eta_seconds)
                };

                // Calculate luck factor (only after 25% of expected time)
                let luck_val = if current_wallet_attempts > expected_attempts / 4 {
                    Some(calculate_luck_factor(
                        current_wallet_attempts,
                        expected_attempts,
                    ))
                } else {
                    None
                };

                (Some(eta_str), luck_val)
            } else {
                // First wallet, show initial ETA
                let eta_seconds = expected_attempts / keys_per_sec.max(1);
                (Some(format_eta(eta_seconds)), None)
            };

            progress_callback(ProgressInfo {
                count,
                elapsed_secs: elapsed.as_secs(),
                eta,
                found_count: found_count_val,
                keys_per_second: keys_per_sec,
                luck,
                total_attempts: total,
            });

            last_progress_report = Instant::now();
        }
    }

    // Wait for all workers to finish
    for handle in handles {
        handle.join().expect("Worker thread panicked");
    }

    // Get final stats
    let total_attempts = shared_state.total_attempts.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs();
    let elapsed_nanos = elapsed.as_nanos();
    
    // Final progress report (only if single wallet or didn't find all requested)
    if count == 1 || results.len() < count {
        let final_keys_per_sec = if elapsed_secs > 0 {
            total_attempts / elapsed_secs
        } else {
            0
        };

        progress_callback(ProgressInfo {
            count,
            elapsed_secs,
            eta: None,
            found_count: results.len(),
            keys_per_second: final_keys_per_sec,
            luck: None,
            total_attempts,
        });
    }

    (
        results,
        GenerationStats {
            total_attempts,
            elapsed_secs,
            elapsed_nanos,
        },
    )
}

fn worker_thread(config: &WorkerConfig, state: &Arc<SharedState>, tx: &Sender<VanityResult>) {
    let target_len = config.target.len();
    let mut local_attempts = 0u64;
    const HEX_MODE_REPORT_INTERVAL: u64 = 1000;
    const MNEMONIC_MODE_REPORT_INTERVAL: u64 = 100;
    let report_interval = if config.hex_mode {
        HEX_MODE_REPORT_INTERVAL
    } else {
        MNEMONIC_MODE_REPORT_INTERVAL
    };

    loop {
        // Check if we should stop
        if state.should_stop.load(Ordering::Relaxed) {
            break;
        }

        // Check if we've already found enough
        if state.found_count.load(Ordering::Relaxed) >= state.count {
            break;
        }

        // Generate address
        let (address, secret) = if config.hex_mode {
            let seed = generate_hex_seed();
            let address = crate::wallet::hex_to_address_with_prefix(&seed, config.ss58_prefix);
            let hex_string = seed_to_hex_string(&seed);
            (address, hex_string)
        } else {
            let mnemonic = generate_mnemonic();
            let address = crate::crypto::mnemonic_to_address_with_prefix(&mnemonic, config.ss58_prefix);
            (address, mnemonic.to_string())
        };

        // Perform optimized search
        let result = search_with_config(&config.search_config, &address);

        local_attempts += 1;

        // Check for match
        if result.count == target_len {
            // Get the attempts since the last wallet was found
            let attempts_since_last = state
                .last_wallet_attempts
                .swap(0, Ordering::Relaxed)
                + local_attempts;

            // We found a match!
            let vanity_result = VanityResult {
                address,
                secret,
                matches: result.count,
                offset: result.offset,
                attempts: attempts_since_last, // Individual wallet attempts
                ss58_prefix: config.ss58_prefix,
            };

            // Update total attempts before resetting local counter
            state
                .total_attempts
                .fetch_add(local_attempts, Ordering::Relaxed);
            
            // Update found count
            state.found_count.fetch_add(1, Ordering::Relaxed);

            // Send result (ignore send errors if receiver is closed)
            let _ = tx.send(vanity_result);
            
            // Reset local counter since we've found a match and counted these attempts
            local_attempts = 0;
        }

        // Periodically update global counter
        if local_attempts >= report_interval {
            state
                .total_attempts
                .fetch_add(local_attempts, Ordering::Relaxed);
            state
                .last_wallet_attempts
                .fetch_add(local_attempts, Ordering::Relaxed);
            local_attempts = 0;
        }
    }

    // Add any remaining attempts
    if local_attempts > 0 {
        state
            .total_attempts
            .fetch_add(local_attempts, Ordering::Relaxed);
        state
            .last_wallet_attempts
            .fetch_add(local_attempts, Ordering::Relaxed);
    }
}
