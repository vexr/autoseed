//! Modified implementation based on curve25519-dalek (with modifications)
//!
//! Original source: https://github.com/dalek-cryptography/curve25519-dalek
//!
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2020 Henry de Valence
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

// We allow non snake_case names because coordinates in projective space are
// traditionally denoted by the capitalisation of their respective
// counterparts in affine space.  Yeah, you heard me, rustc, I'm gonna have my
// affine and projective cakes and eat both of them too.
#![allow(non_snake_case)]

//! An implementation of [Ristretto][ristretto_main], which provides a
//! prime-order group.
//!
//! # The Ristretto Group
//!
//! Ristretto is a modification of Mike Hamburg's Decaf scheme to work
//! with cofactor-\\(8\\) curves, such as Curve25519.
//!
//! The introduction of the Decaf paper, [_Decaf:
//! Eliminating cofactors through point
//! compression_](https://eprint.iacr.org/2015/673.pdf), notes that while
//! most cryptographic systems require a group of prime order, most
//! concrete implementations using elliptic curve groups fall short –
//! they either provide a group of prime order, but with incomplete or
//! variable-time addition formulae (for instance, most Weierstrass
//! models), or else they provide a fast and safe implementation of a
//! group whose order is not quite a prime \\(q\\), but \\(hq\\) for a
//! small cofactor \\(h\\) (for instance, Edwards curves, which have
//! cofactor at least \\(4\\)).
//!
//! This abstraction mismatch is commonly “handled” by pushing the
//! complexity upwards, adding ad-hoc protocol modifications.  But
//! these modifications require careful analysis and are a recurring
//! source of [vulnerabilities][cryptonote] and [design
//! complications][ed25519_hkd].
//!
//! Instead, Decaf (and Ristretto) use a quotient group to implement a
//! prime-order group using a non-prime-order curve.  This provides
//! the correct abstraction for cryptographic systems, while retaining
//! the speed and safety benefits of an Edwards curve.
//!
//! Decaf is named “after the procedure which divides the effect of
//! coffee by \\(4\\)”.  However, Curve25519 has a cofactor of
//! \\(8\\).  To eliminate its cofactor, Ristretto restricts further;
//! this [additional restriction][ristretto_coffee] gives the
//! _Ristretto_ encoding.
//!
//! More details on why Ristretto is necessary can be found in the
//! [Why Ristretto?][why_ristretto] section of the Ristretto website.
//!
//! Ristretto
//! points are provided in `curve25519-dalek` by the `RistrettoPoint`
//! struct.
//!
//! ## Encoding and Decoding
//!
//! Encoding is done by converting to and from a `CompressedRistretto`
//! struct, which is a typed wrapper around `[u8; 32]`.
//!
//!
//! ## Equality Testing
//!
//! Testing equality of points on an Edwards curve in projective
//! coordinates requires an expensive inversion.  By contrast, equality
//! checking in the Ristretto group can be done in projective
//! coordinates without requiring an inversion, so it is much faster.
//!
//! The `RistrettoPoint` struct implements the
//! [`subtle::ConstantTimeEq`] trait for constant-time equality
//! checking, and also uses this to ensure `Eq` equality checking
//! runs in constant time.
//!
//! ## Scalars
//!
//! Scalars are represented by the `Scalar` struct.
//!
//! ## Scalar Multiplication
//!
//! Scalar multiplication on Ristretto points is provided by:
//!
//! * the `*` operator between a `Scalar` and a `RistrettoPoint`, which
//!   performs constant-time variable-base scalar multiplication;
//!
//! * the `*` operator between a `Scalar` and a
//!   `RistrettoBasepointTable`, which performs constant-time fixed-base
//!   scalar multiplication;
//!
//! * an implementation of the
//!   [`MultiscalarMul`](../traits/trait.MultiscalarMul.html) trait for
//!   constant-time variable-base multiscalar multiplication;
//!
//! * an implementation of the
//!   [`VartimeMultiscalarMul`](../traits/trait.VartimeMultiscalarMul.html)
//!   trait for variable-time variable-base multiscalar multiplication;
//!
//!
//! ## Implementation
//!
//! The Decaf suggestion is to use a quotient group, such as \\(\mathcal
//! E / \mathcal E\[4\]\\) or \\(2 \mathcal E / \mathcal E\[2\] \\), to
//! implement a prime-order group using a non-prime-order curve.
//!
//! This requires only changing
//!
//! 1. the function for equality checking (so that two representatives
//!    of the same coset are considered equal);
//! 2. the function for encoding (so that two representatives of the
//!    same coset are encoded as identical bitstrings);
//! 3. the function for decoding (so that only the canonical encoding of
//!    a coset is accepted).
//!
//! Internally, each coset is represented by a curve point; two points
//! \\( P, Q \\) may represent the same coset in the same way that two
//! points with different \\(X,Y,Z\\) coordinates may represent the
//! same point.  The group operations are carried out with no overhead
//! using Edwards formulas.
//!
//! Notes on the details of the encoding can be found in the
//! [Details][ristretto_notes] section of the Ristretto website.
//!
//! [cryptonote]:
//! https://moderncrypto.org/mail-archive/curves/2017/000898.html
//! [ed25519_hkd]:
//! https://moderncrypto.org/mail-archive/curves/2017/000858.html
//! [ristretto_coffee]:
//! https://en.wikipedia.org/wiki/Ristretto
//! [ristretto_notes]:
//! https://ristretto.group/details/index.html
//! [why_ristretto]:
//! https://ristretto.group/why_ristretto.html
//! [ristretto_main]:
//! https://ristretto.group/


use core::array::TryFromSliceError;
use core::borrow::Borrow;
use core::iter::Sum;
use core::ops::{Add, Neg, Sub};
use core::ops::{AddAssign, SubAssign};
use core::ops::{Mul, MulAssign};


use super::constants;
use super::field::FieldElement;



use crate::crypto::subtle::Choice;
use crate::crypto::subtle::ConditionallyNegatable;
use crate::crypto::subtle::ConditionallySelectable;
use crate::crypto::subtle::ConstantTimeEq;

use super::edwards::EdwardsPoint;

use super::scalar::Scalar;

use super::traits::Identity;

#[cfg(feature = "precomputed-tables")]
use super::traits::BasepointTable;

// ------------------------------------------------------------------------
// Compressed points
// ------------------------------------------------------------------------

/// A Ristretto point, in compressed wire format.
///
/// The Ristretto encoding is canonical, so two points are equal if and
/// only if their encodings are equal.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Copy, Clone, Hash)]
pub struct CompressedRistretto(pub [u8; 32]);

impl Eq for CompressedRistretto {}
impl PartialEq for CompressedRistretto {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for CompressedRistretto {
    fn ct_eq(&self, other: &CompressedRistretto) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl CompressedRistretto {
    /// Copy the bytes of this `CompressedRistretto`.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// View this `CompressedRistretto` as an array of bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct a `CompressedRistretto` from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TryFromSliceError`] if the input `bytes` slice does not have
    /// a length of 32.
    pub fn from_slice(bytes: &[u8]) -> Result<CompressedRistretto, TryFromSliceError> {
        bytes.try_into().map(CompressedRistretto)
    }

    /// Attempt to decompress to an `RistrettoPoint`.
    ///
    /// # Return
    ///
    /// - `Some(RistrettoPoint)` if `self` was the canonical encoding of a point;
    ///
    /// - `None` if `self` was not the canonical encoding of a point.
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        let (s_encoding_is_canonical, s_is_negative, s) = decompress::step_1(self);

        if (!s_encoding_is_canonical | s_is_negative).into() {
            return None;
        }

        let (ok, t_is_negative, y_is_zero, res) = decompress::step_2(s);

        if (!ok | t_is_negative | y_is_zero).into() {
            None
        } else {
            Some(res)
        }
    }
}

mod decompress {
    use super::*;

    pub(super) fn step_1(repr: &CompressedRistretto) -> (Choice, Choice, FieldElement) {
        // Step 1. Check s for validity:
        // 1.a) s must be 32 bytes (we get this from the type system)
        // 1.b) s < p
        // 1.c) s is nonnegative
        //
        // Our decoding routine ignores the high bit, so the only
        // possible failure for 1.b) is if someone encodes s in 0..18
        // as s+p in 2^255-19..2^255-1.  We can check this by
        // converting back to bytes, and checking that we get the
        // original input, since our encoding routine is canonical.

        let s = FieldElement::from_bytes(repr.as_bytes());
        let s_bytes_check = s.to_bytes();
        let s_encoding_is_canonical = s_bytes_check[..].ct_eq(repr.as_bytes());
        let s_is_negative = s.is_negative();

        (s_encoding_is_canonical, s_is_negative, s)
    }

    pub(super) fn step_2(s: FieldElement) -> (Choice, Choice, Choice, RistrettoPoint) {
        // Step 2.  Compute (X:Y:Z:T).
        let one = FieldElement::ONE;
        let ss = s.square();
        let u1 = &one - &ss; //  1 + as²
        let u2 = &one + &ss; //  1 - as²    where a=-1
        let u2_sqr = u2.square(); // (1 - as²)²

        // v == ad(1+as²)² - (1-as²)²            where d=-121665/121666
        let v = &(&(-&constants::EDWARDS_D) * &u1.square()) - &u2_sqr;

        let (ok, I) = (&v * &u2_sqr).invsqrt(); // 1/sqrt(v*u_2²)

        let Dx = &I * &u2; // 1/sqrt(v)
        let Dy = &I * &(&Dx * &v); // 1/u2

        // x == | 2s/sqrt(v) | == + sqrt(4s²/(ad(1+as²)² - (1-as²)²))
        let mut x = &(&s + &s) * &Dx;
        let x_neg = x.is_negative();
        x.conditional_negate(x_neg);

        // y == (1-as²)/(1+as²)
        let y = &u1 * &Dy;

        // t == ((1+as²) sqrt(4s²/(ad(1+as²)² - (1-as²)²)))/(1-as²)
        let t = &x * &y;

        (
            ok,
            t.is_negative(),
            y.is_zero(),
            RistrettoPoint(EdwardsPoint {
                X: x,
                Y: y,
                Z: one,
                T: t,
            }),
        )
    }
}

impl Identity for CompressedRistretto {
    fn identity() -> CompressedRistretto {
        CompressedRistretto([0u8; 32])
    }
}

impl Default for CompressedRistretto {
    fn default() -> CompressedRistretto {
        CompressedRistretto::identity()
    }
}

impl TryFrom<&[u8]> for CompressedRistretto {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<CompressedRistretto, TryFromSliceError> {
        Self::from_slice(slice)
    }
}

// ------------------------------------------------------------------------
// Serde support
// ------------------------------------------------------------------------
// Serializes to and from `RistrettoPoint` directly, doing compression
// and decompression internally.  This means that users can create
// structs containing `RistrettoPoint`s and use Serde's derived
// serializers to serialize those structures.



// ------------------------------------------------------------------------
// Internal point representations
// ------------------------------------------------------------------------

/// A `RistrettoPoint` represents a point in the Ristretto group for
/// Curve25519.  Ristretto, a variant of Decaf, constructs a
/// prime-order group as a quotient group of a subgroup of (the
/// Edwards form of) Curve25519.
///
/// Internally, a `RistrettoPoint` is implemented as a wrapper type
/// around `EdwardsPoint`, with custom equality, compression, and
/// decompression routines to account for the quotient.  This means that
/// operations on `RistrettoPoint`s are exactly as fast as operations on
/// `EdwardsPoint`s.
///
#[derive(Copy, Clone)]
pub struct RistrettoPoint(pub(crate) EdwardsPoint);

impl RistrettoPoint {
    /// Compress this point using the Ristretto encoding.
    pub fn compress(&self) -> CompressedRistretto {
        let mut X = self.0.X;
        let mut Y = self.0.Y;
        let Z = &self.0.Z;
        let T = &self.0.T;

        let u1 = &(Z + &Y) * &(Z - &Y);
        let u2 = &X * &Y;
        // Ignore return value since this is always square
        let (_, invsqrt) = (&u1 * &u2.square()).invsqrt();
        let i1 = &invsqrt * &u1;
        let i2 = &invsqrt * &u2;
        let z_inv = &i1 * &(&i2 * T);
        let mut den_inv = i2;

        let iX = &X * &constants::SQRT_M1;
        let iY = &Y * &constants::SQRT_M1;
        let ristretto_magic = &constants::INVSQRT_A_MINUS_D;
        let enchanted_denominator = &i1 * ristretto_magic;

        let rotate = (T * &z_inv).is_negative();

        X.conditional_assign(&iY, rotate);
        Y.conditional_assign(&iX, rotate);
        den_inv.conditional_assign(&enchanted_denominator, rotate);

        Y.conditional_negate((&X * &z_inv).is_negative());

        let mut s = &den_inv * &(Z - &Y);
        let s_is_negative = s.is_negative();
        s.conditional_negate(s_is_negative);

        CompressedRistretto(s.to_bytes())
    }







}

impl Identity for RistrettoPoint {
    fn identity() -> RistrettoPoint {
        RistrettoPoint(EdwardsPoint::identity())
    }
}

impl Default for RistrettoPoint {
    fn default() -> RistrettoPoint {
        RistrettoPoint::identity()
    }
}

// ------------------------------------------------------------------------
// Equality
// ------------------------------------------------------------------------

impl PartialEq for RistrettoPoint {
    fn eq(&self, other: &RistrettoPoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for RistrettoPoint {
    /// Test equality between two `RistrettoPoint`s.
    ///
    /// # Returns
    ///
    /// * `Choice(1)` if the two `RistrettoPoint`s are equal;
    /// * `Choice(0)` otherwise.
    fn ct_eq(&self, other: &RistrettoPoint) -> Choice {
        let X1Y2 = &self.0.X * &other.0.Y;
        let Y1X2 = &self.0.Y * &other.0.X;
        let X1X2 = &self.0.X * &other.0.X;
        let Y1Y2 = &self.0.Y * &other.0.Y;

        X1Y2.ct_eq(&Y1X2) | X1X2.ct_eq(&Y1Y2)
    }
}

impl Eq for RistrettoPoint {}

// ------------------------------------------------------------------------
// Arithmetic
// ------------------------------------------------------------------------

impl<'a> Add<&'a RistrettoPoint> for &RistrettoPoint {
    type Output = RistrettoPoint;

    fn add(self, other: &'a RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(self.0 + other.0)
    }
}

define_add_variants!(
    LHS = RistrettoPoint,
    RHS = RistrettoPoint,
    Output = RistrettoPoint
);

impl AddAssign<&RistrettoPoint> for RistrettoPoint {
    fn add_assign(&mut self, _rhs: &RistrettoPoint) {
        *self = (self as &RistrettoPoint) + _rhs;
    }
}

define_add_assign_variants!(LHS = RistrettoPoint, RHS = RistrettoPoint);

impl<'a> Sub<&'a RistrettoPoint> for &RistrettoPoint {
    type Output = RistrettoPoint;

    fn sub(self, other: &'a RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(self.0 - other.0)
    }
}

define_sub_variants!(
    LHS = RistrettoPoint,
    RHS = RistrettoPoint,
    Output = RistrettoPoint
);

impl SubAssign<&RistrettoPoint> for RistrettoPoint {
    fn sub_assign(&mut self, _rhs: &RistrettoPoint) {
        *self = (self as &RistrettoPoint) - _rhs;
    }
}

define_sub_assign_variants!(LHS = RistrettoPoint, RHS = RistrettoPoint);

impl<T> Sum<T> for RistrettoPoint
where
    T: Borrow<RistrettoPoint>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(RistrettoPoint::identity(), |acc, item| acc + item.borrow())
    }
}

impl Neg for &RistrettoPoint {
    type Output = RistrettoPoint;

    fn neg(self) -> RistrettoPoint {
        RistrettoPoint(-&self.0)
    }
}

impl Neg for RistrettoPoint {
    type Output = RistrettoPoint;

    fn neg(self) -> RistrettoPoint {
        -&self
    }
}

impl<'a> MulAssign<&'a Scalar> for RistrettoPoint {
    fn mul_assign(&mut self, scalar: &'a Scalar) {
        let result = (self as &RistrettoPoint) * scalar;
        *self = result;
    }
}

impl<'a> Mul<&'a Scalar> for &RistrettoPoint {
    type Output = RistrettoPoint;
    /// Scalar multiplication: compute `scalar * self`.
    fn mul(self, scalar: &'a Scalar) -> RistrettoPoint {
        RistrettoPoint(self.0 * scalar)
    }
}

impl<'a> Mul<&'a RistrettoPoint> for &Scalar {
    type Output = RistrettoPoint;

    /// Scalar multiplication: compute `self * scalar`.
    fn mul(self, point: &'a RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(self * point.0)
    }
}


define_mul_assign_variants!(LHS = RistrettoPoint, RHS = Scalar);

define_mul_variants!(LHS = RistrettoPoint, RHS = Scalar, Output = RistrettoPoint);
define_mul_variants!(LHS = Scalar, RHS = RistrettoPoint, Output = RistrettoPoint);

// ------------------------------------------------------------------------
// Multiscalar Multiplication impls
// ------------------------------------------------------------------------

// These use iterator combinators to unwrap the underlying points and
// forward to the EdwardsPoint implementations.



/// Precomputation for variable-time multiscalar multiplication with `RistrettoPoint`s.
///
/// Note that for large numbers of `RistrettoPoint`s, this functionality may be less
/// efficient than the corresponding `VartimeMultiscalarMul` implementation.
// This wraps the inner implementation in a facade type so that we can
// decouple stability of the inner type from the stability of the
// outer type.



/// A precomputed table of multiples of a basepoint, used to accelerate
/// scalar multiplication.
///
/// A precomputed table of multiples of the Ristretto basepoint is
/// available in the `constants` module:
/// ```
/// use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
/// use curve25519_dalek::scalar::Scalar;
///
/// let a = Scalar::from(87329482u64);
/// let P = &a * RISTRETTO_BASEPOINT_TABLE;
/// ```

// ------------------------------------------------------------------------
// Constant-time conditional selection
// ------------------------------------------------------------------------

impl ConditionallySelectable for RistrettoPoint {
    /// Conditionally select between `self` and `other`.
    ///
    /// # Example
    ///
    fn conditional_select(
        a: &RistrettoPoint,
        b: &RistrettoPoint,
        choice: Choice,
    ) -> RistrettoPoint {
        RistrettoPoint(EdwardsPoint::conditional_select(&a.0, &b.0, choice))
    }
}


// Use the full trait path to avoid Group::identity overlapping Identity::identity in the
// rest of the module (e.g. tests).




// ------------------------------------------------------------------------
// Precomputed tables
// ------------------------------------------------------------------------

#[cfg(feature = "precomputed-tables")]
use super::edwards::EdwardsBasepointTable;

/// A precomputed table of basepoints for accelerating fixed-base scalar multiplication.
///
/// This is a `#[repr(transparent)]` newtype wrapper around `EdwardsBasepointTable`.
#[cfg(feature = "precomputed-tables")]
#[repr(transparent)]
pub struct RistrettoBasepointTable(pub(crate) EdwardsBasepointTable);

#[cfg(feature = "precomputed-tables")]
impl super::traits::BasepointTable for RistrettoBasepointTable {
    type Point = RistrettoPoint;
    
    fn basepoint(&self) -> RistrettoPoint {
        RistrettoPoint(self.0.basepoint())
    }
    
    fn create(basepoint: &RistrettoPoint) -> Self {
        RistrettoBasepointTable(EdwardsBasepointTable::create(&basepoint.0))
    }
    
    fn mul_base(&self, scalar: &Scalar) -> RistrettoPoint {
        RistrettoPoint(self.0.mul_base(scalar))
    }
}

#[cfg(feature = "precomputed-tables")]
impl<'a, 'b> Mul<&'b RistrettoBasepointTable> for &'a Scalar {
    type Output = RistrettoPoint;

    fn mul(self, basepoint_table: &'b RistrettoBasepointTable) -> RistrettoPoint {
        basepoint_table.mul_base(self)
    }
}

