//! Modified implementation based on curve25519-dalek (with modifications)
//! 
//! Original source: https://github.com/dalek-cryptography/curve25519-dalek
//! Version: curve25519-dalek v5.0.0-pre.0
//! 
//! This is a 1:1 copy of the curve25519-dalek implementation
//! 
//! License: BSD-3-Clause
//! Copyright: Isis Lovecruft and Henry de Valence

#[macro_use]
pub(crate) mod macros;


// Module declarations
mod lib;
pub mod scalar;
pub mod edwards;
pub mod ristretto;
pub mod constants;
pub mod traits;
pub(crate) mod field;
pub(crate) mod backend;
pub(crate) mod window;

// Main type re-exports
pub use self::edwards::EdwardsPoint;
pub use self::scalar::Scalar;