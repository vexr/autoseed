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
//! Various constants, such as the Ristretto and Ed25519 basepoints.

#![allow(non_snake_case)]



#[cfg(feature = "precomputed-tables")]
use super::edwards::EdwardsBasepointTable;

// Default to u64 backend constants for simplicity
pub use super::backend::serial::u64::constants::*;


/// The Ristretto basepoint, as a `RistrettoPoint`.
///
/// This is called `_POINT` to distinguish it from `_TABLE`, which
/// provides fast scalar multiplication.

/// `BASEPOINT_ORDER` is the order of the Ristretto group and of the Ed25519 basepoint, i.e.,
/// $$
/// \ell = 2^\{252\} + 27742317777372353535851937790883648493.
/// $$

#[cfg(feature = "precomputed-tables")]
use super::ristretto::RistrettoBasepointTable;

/// The Ristretto basepoint, as a `RistrettoBasepointTable` for scalar multiplication.
#[cfg(feature = "precomputed-tables")]
pub static RISTRETTO_BASEPOINT_TABLE: &RistrettoBasepointTable = unsafe {
    // SAFETY: `RistrettoBasepointTable` is a `#[repr(transparent)]` newtype of
    // `EdwardsBasepointTable`
    &*(ED25519_BASEPOINT_TABLE as *const EdwardsBasepointTable as *const RistrettoBasepointTable)
};

#[cfg(test)]
mod test {
    use super::constants;
    use super::field::FieldElement;
    use super::traits::{IsIdentity, ValidityCheck};

    #[test]
    fn test_eight_torsion() {
        for i in 0..8 {
            let Q = constants::EIGHT_TORSION[i].mul_by_pow_2(3);
            assert!(Q.is_valid());
            assert!(Q.is_identity());
        }
    }

    #[test]
    fn test_four_torsion() {
        for i in (0..8).filter(|i| i % 2 == 0) {
            let Q = constants::EIGHT_TORSION[i].mul_by_pow_2(2);
            assert!(Q.is_valid());
            assert!(Q.is_identity());
        }
    }

    #[test]
    fn test_two_torsion() {
        for i in (0..8).filter(|i| i % 4 == 0) {
            let Q = constants::EIGHT_TORSION[i].mul_by_pow_2(1);
            assert!(Q.is_valid());
            assert!(Q.is_identity());
        }
    }

    /// Test that SQRT_M1 is the positive square root of -1
    #[test]
    fn test_sqrt_minus_one() {
        let minus_one = FieldElement::MINUS_ONE;
        let sqrt_m1_sq = &constants::SQRT_M1 * &constants::SQRT_M1;
        assert_eq!(minus_one, sqrt_m1_sq);
        assert!(bool::from(!constants::SQRT_M1.is_negative()));
    }

    #[test]
    fn test_sqrt_constants_sign() {
        let minus_one = FieldElement::MINUS_ONE;
        let (was_nonzero_square, invsqrt_m1) = minus_one.invsqrt();
        assert!(bool::from(was_nonzero_square));
        let sign_test_sqrt = &invsqrt_m1 * &constants::SQRT_M1;
        assert_eq!(sign_test_sqrt, minus_one);
    }


    /// Test that d = -121665/121666
    #[test]
    #[cfg(all(curve25519_dalek_bits = "64", not(curve25519_dalek_backend = "fiat")))]
    fn test_d_vs_ratio() {
        use super::backend::serial::u64::field::FieldElement51;
        let a = -&FieldElement51([121665, 0, 0, 0, 0]);
        let b = FieldElement51([121666, 0, 0, 0, 0]);
        let d = &a * &b.invert();
        let d2 = &d + &d;
        assert_eq!(d, constants::EDWARDS_D);
        assert_eq!(d2, constants::EDWARDS_D2);
    }

    #[test]
    fn test_sqrt_ad_minus_one() {
        let a = FieldElement::MINUS_ONE;
        let ad_minus_one = &(&a * &constants::EDWARDS_D) + &a;
        let should_be_ad_minus_one = constants::SQRT_AD_MINUS_ONE.square();
        assert_eq!(should_be_ad_minus_one, ad_minus_one);
    }

}
