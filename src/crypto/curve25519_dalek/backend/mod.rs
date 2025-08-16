//! Modified implementation based on curve25519-dalek (with modifications)
//!
//! Original source: https://github.com/dalek-cryptography/curve25519-dalek
//!
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2019 Henry de Valence
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! **INTERNALS:** Pluggable implementations for different architectures.
//!
//! The backend code is split into two parts: a serial backend,
//! and a vector backend.
//!
//! The [`serial`] backend contains 32- and 64-bit implementations of
//! field arithmetic and scalar arithmetic, as well as implementations
//! of point operations using the mixed-model strategy (passing
//! between different curve models depending on the operation).
//!
//! The [`vector`] backend contains implementations of vectorized
//! field arithmetic, used to implement point operations using a novel
//! implementation strategy derived from parallel formulas of Hisil,
//! Wong, Carter, and Dawson.
//!
//! Because the two strategies give rise to different curve models,
//! it's not possible to reuse exactly the same scalar multiplication
//! code (or to write it generically), so both serial and vector
//! backends contain matching implementations of scalar multiplication
//! algorithms.  These are intended to be selected by a `#[cfg]`-based
//! type alias.
//!
//! The [`vector`] backend is selected by the `simd_backend` cargo
//! feature; it uses the [`serial`] backend for non-vectorized operations.

use super::EdwardsPoint;
use super::Scalar;

pub mod serial;






/// Perform constant-time, variable-base scalar multiplication.
pub fn variable_base_mul(point: &EdwardsPoint, scalar: &Scalar) -> EdwardsPoint {
    serial::scalar_mul::variable_base::mul(point, scalar)
}

/// Compute \\(aA + bB\\) in variable time, where \\(B\\) is the Ed25519 basepoint.
#[allow(non_snake_case)]
pub fn vartime_double_base_mul(a: &Scalar, A: &EdwardsPoint, b: &Scalar) -> EdwardsPoint {
    serial::scalar_mul::vartime_double_base::mul(a, A, b)
}
