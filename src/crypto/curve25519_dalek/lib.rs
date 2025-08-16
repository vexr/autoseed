//! Modified implementation based on curve25519-dalek (with modifications)
//!
//! Original source: https://github.com/dalek-cryptography/curve25519-dalek
//!
//! This file is part of curve25519-dalek.
//! Copyright (c) 2016-2021 isis lovecruft
//! Copyright (c) 2016-2019 Henry de Valence
//!
//! Authors:
//! - isis agora lovecruft <isis@patternsinthevoid.net>
//! - Henry de Valence <hdevalence@hdevalence.ca>

// Originally: #![no_std], #![doc(...)] etc.
//------------------------------------------------------------------------
// Linting:
//------------------------------------------------------------------------

//------------------------------------------------------------------------
// External dependencies:
//------------------------------------------------------------------------


// TODO: move std-dependent tests to `tests/`
#[cfg(test)]
#[macro_use]
extern crate std;



// Re-exports moved to mod.rs

// Build time diagnostics for validation
