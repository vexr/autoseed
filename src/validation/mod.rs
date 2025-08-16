mod address;
mod search;

pub use address::{ValidationResult, validate_wallet};
pub use search::validate_search_term_with_prefix;