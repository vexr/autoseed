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

//! Module for common traits.

#![allow(non_snake_case)]

use super::scalar::Scalar;

// ------------------------------------------------------------------------
// Public Traits
// ------------------------------------------------------------------------

/// Trait for getting the identity element of a point type.
pub trait Identity {
    /// Returns the identity element of the curve.
    /// Can be used as a constructor.
    fn identity() -> Self;
}


/// A precomputed table of basepoints, for optimising scalar multiplications.
pub trait BasepointTable {
    /// The type of point contained within this table.
    type Point;

    /// Generate a new precomputed basepoint table from the given basepoint.
    fn create(basepoint: &Self::Point) -> Self;

    /// Retrieve the original basepoint from this table.
    fn basepoint(&self) -> Self::Point;

    /// Multiply a `scalar` by this precomputed basepoint table, in constant time.
    fn mul_base(&self, scalar: &Scalar) -> Self::Point;

}

// ------------------------------------------------------------------------
// Private Traits
// ------------------------------------------------------------------------

/// Trait for checking whether a point is on the curve.
///
/// This trait is only for debugging/testing, since it should be
/// impossible for a `curve25519-dalek` user to construct an invalid
/// point.
#[allow(dead_code)]
pub(crate) trait ValidityCheck {
    /// Checks whether the point is on the curve. Not CT.
    fn is_valid(&self) -> bool;
}
