//! Modified implementation based on curve25519-dalek (with modifications)
//!
//! Original source: https://github.com/dalek-cryptography/curve25519-dalek
//!
//! This file is part of curve25519-dalek.
//! Copyright (c) 2016-2021 isis lovecruft
//! Copyright (c) 2016-2019 Henry de Valence
//! Portions Copyright 2017 Brian Smith
//!
//! Authors:
//! - Isis Agora Lovecruft <isis@patternsinthevoid.net>
//! - Henry de Valence <hdevalence@hdevalence.ca>
//! - Brian Smith <brian@briansmith.org>

//! Arithmetic on scalars (integers mod the group order).
//!
//! Both the Ristretto group and the Ed25519 basepoint have prime order
//! \\( \ell = 2\^{252} + 27742317777372353535851937790883648493 \\).
//!
//! This code is intended to be useful with both the Ristretto group
//! (where everything is done modulo \\( \ell \\)), and the X/Ed25519
//! setting, which mandates specific bit-twiddles that are not
//! well-defined modulo \\( \ell \\).
//!
//! All arithmetic on `Scalars` is done modulo \\( \ell \\).
//!
//! # Constructing a scalar
//!
//! Scalars can be created from primitive integer types using the `From` trait:
//!
//! ```
//! use curve25519_dalek::scalar::Scalar;
//!
//! let zero = Scalar::ZERO;
//! let one = Scalar::ONE;
//! let forty_two = Scalar::from(42u64);
//! let from_u32 = Scalar::from(123u32);
//! ```

use core::borrow::Borrow;
use core::fmt::Debug;
use core::iter::{Product, Sum};
use core::ops::Index;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

use zeroize::Zeroize;


use crate::crypto::subtle::Choice;
use crate::crypto::subtle::ConditionallySelectable;
use crate::crypto::subtle::ConstantTimeEq;


use super::backend;
use super::constants;

/// An `UnpackedScalar` represents an element of the field GF(l), optimized for speed.
///
/// This is a type alias for one of the scalar types in the `backend`
/// module.
type UnpackedScalar = backend::serial::u64::scalar::Scalar52;

/// The `Scalar` struct holds an element of \\(\mathbb Z / \ell\mathbb Z \\).
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Copy, Clone, Hash)]
pub struct Scalar {
    /// `bytes` is a little-endian byte encoding of an integer representing a scalar modulo the
    /// group order.
    ///
    /// # Invariant #1
    ///
    /// The integer representing this scalar is less than \\(2\^{255}\\). That is, the most
    /// significant bit of `bytes[31]` is 0.
    ///
    /// This is required for `EdwardsPoint` variable- and fixed-base multiplication, because most
    /// integers above 2^255 are unrepresentable in our radix-16 NAF (see [`Self::as_radix_16`]).
    ///
    /// # Invariant #2 (weak)
    ///
    /// The integer representing this scalar is less than \\(2\^{255} - 19 \\), i.e., it represents
    /// a canonical representative of an element of \\( \mathbb Z / \ell\mathbb Z \\). This is
    /// stronger than invariant #1. It also sometimes has to be broken.
    ///
    /// This invariant is deliberately broken in the implementation of `EdwardsPoint::{mul_clamped,
    /// mul_base_clamped}`, and `BasepointTable::mul_base_clamped`. This is not an issue though. As mentioned above,
    /// scalar-point multiplication is defined for any choice of `bytes` that satisfies invariant
    /// #1. Since clamping guarantees invariant #1 is satisfied, these operations are well defined.
    ///
    /// Note: Scalar-point mult is the _only_ thing you can do safely with an unreduced scalar.
    /// Scalar-scalar addition and subtraction are NOT correct when using unreduced scalars.
    /// Multiplication is correct, but this is only due to a quirk of our implementation, and not
    /// guaranteed to hold in general in the future.
    ///
    /// Note: It is not possible to construct an unreduced `Scalar` from the public API unless the
    /// `legacy_compatibility` is enabled (thus making `Scalar::from_bits` public). Thus, for all
    /// public non-legacy uses, invariant #2
    /// always holds.
    ///
    pub(crate) bytes: [u8; 32],
}

impl Scalar {



    /// Construct a `Scalar` from the low 255 bits of a 256-bit integer. This breaks the invariant
    /// that scalars are always reduced. Scalar-scalar arithmetic, i.e., addition, subtraction,
    /// multiplication, **does not work** on scalars produced from this function. You may only use
    /// the output of this function for `EdwardsPoint::mul` and
    /// `EdwardsPoint::vartime_double_scalar_mul_basepoint`. **Do not use this function** unless
    /// you absolutely have to.
    #[cfg(feature = "legacy_compatibility")]
    pub const fn from_bits(bytes: [u8; 32]) -> Scalar {
        let mut s = Scalar { bytes };
        // Ensure invariant #1 holds. That is, make s < 2^255 by masking the high bit.
        s.bytes[31] &= 0b0111_1111;

        s
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Scalar{{\n\tbytes: {:?},\n}}", &self.bytes)
    }
}

impl Eq for Scalar {}
impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl Index<usize> for Scalar {
    type Output = u8;

    /// Index the bytes of the representative for this `Scalar`.  Mutation is not permitted.
    fn index(&self, _index: usize) -> &u8 {
        &(self.bytes[_index])
    }
}

impl<'a> MulAssign<&'a Scalar> for Scalar {
    fn mul_assign(&mut self, _rhs: &'a Scalar) {
        *self = UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack();
    }
}

define_mul_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a> Mul<&'a Scalar> for &Scalar {
    type Output = Scalar;
    fn mul(self, _rhs: &'a Scalar) -> Scalar {
        UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack()
    }
}

define_mul_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'a> AddAssign<&'a Scalar> for Scalar {
    fn add_assign(&mut self, _rhs: &'a Scalar) {
        *self = *self + _rhs;
    }
}

define_add_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a> Add<&'a Scalar> for &Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn add(self, _rhs: &'a Scalar) -> Scalar {
        // The UnpackedScalar::add function produces reduced outputs if the inputs are reduced. By
        // Scalar invariant #1, this is always the case.
        UnpackedScalar::add(&self.unpack(), &_rhs.unpack()).pack()
    }
}

define_add_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'a> SubAssign<&'a Scalar> for Scalar {
    fn sub_assign(&mut self, _rhs: &'a Scalar) {
        *self = *self - _rhs;
    }
}

define_sub_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a> Sub<&'a Scalar> for &Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn sub(self, rhs: &'a Scalar) -> Scalar {
        // The UnpackedScalar::sub function produces reduced outputs if the inputs are reduced. By
        // Scalar invariant #1, this is always the case.
        UnpackedScalar::sub(&self.unpack(), &rhs.unpack()).pack()
    }
}

define_sub_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl Neg for &Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn neg(self) -> Scalar {
        let self_R = UnpackedScalar::mul_internal(&self.unpack(), &constants::R);
        let self_mod_l = UnpackedScalar::montgomery_reduce(&self_R);
        UnpackedScalar::sub(&UnpackedScalar::ZERO, &self_mod_l).pack()
    }
}

impl Neg for Scalar {
    type Output = Scalar;
    fn neg(self) -> Scalar {
        -&self
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u8; 32];
        #[allow(clippy::needless_range_loop)]
        for i in 0..32 {
            bytes[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
        }
        Scalar { bytes }
    }
}


impl<T> Product<T> for Scalar
where
    T: Borrow<Scalar>,
{
    fn product<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Scalar::ONE, |acc, item| acc * item.borrow())
    }
}

impl<T> Sum<T> for Scalar
where
    T: Borrow<Scalar>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Scalar::ZERO, |acc, item| acc + item.borrow())
    }
}

impl Default for Scalar {
    fn default() -> Scalar {
        Scalar::ZERO
    }
}

impl From<u8> for Scalar {
    fn from(x: u8) -> Scalar {
        let mut s_bytes = [0u8; 32];
        s_bytes[0] = x;
        Scalar { bytes: s_bytes }
    }
}

impl From<u16> for Scalar {
    fn from(x: u16) -> Scalar {
        let mut s_bytes = [0u8; 32];
        let x_bytes = x.to_le_bytes();
        s_bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        Scalar { bytes: s_bytes }
    }
}

impl From<u32> for Scalar {
    fn from(x: u32) -> Scalar {
        let mut s_bytes = [0u8; 32];
        let x_bytes = x.to_le_bytes();
        s_bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        Scalar { bytes: s_bytes }
    }
}

impl From<u64> for Scalar {
    /// Construct a scalar from the given `u64`.
    ///
    /// # Inputs
    ///
    /// An `u64` to convert to a `Scalar`.
    ///
    /// # Returns
    ///
    /// A `Scalar` corresponding to the input `u64`.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// let fourtytwo = Scalar::from(42u64);
    /// let six = Scalar::from(6u64);
    /// let seven = Scalar::from(7u64);
    ///
    /// assert!(fourtytwo == six * seven);
    /// ```
    fn from(x: u64) -> Scalar {
        let mut s_bytes = [0u8; 32];
        let x_bytes = x.to_le_bytes();
        s_bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        Scalar { bytes: s_bytes }
    }
}

impl From<u128> for Scalar {
    fn from(x: u128) -> Scalar {
        let mut s_bytes = [0u8; 32];
        let x_bytes = x.to_le_bytes();
        s_bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        Scalar { bytes: s_bytes }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Scalar {
    /// The scalar \\( 0 \\).
    pub const ZERO: Self = Self { bytes: [0u8; 32] };

    /// The scalar \\( 1 \\).
    pub const ONE: Self = Self {
        bytes: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
    };




    /// Convert this `Scalar` to its underlying sequence of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// let s: Scalar = Scalar::ZERO;
    ///
    /// assert!(s.to_bytes() == [0u8; 32]);
    /// ```
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// View the little-endian byte encoding of the integer representing this Scalar.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// let s: Scalar = Scalar::ZERO;
    ///
    /// assert!(s.as_bytes() == &[0u8; 32]);
    /// ```
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }




    /// Compute a width-\\(w\\) "Non-Adjacent Form" of this scalar.
    ///
    /// A width-\\(w\\) NAF of a positive integer \\(k\\) is an expression
    /// $$
    /// k = \sum_{i=0}\^m n\_i 2\^i,
    /// $$
    /// where each nonzero
    /// coefficient \\(n\_i\\) is odd and bounded by \\(|n\_i| < 2\^{w-1}\\),
    /// \\(n\_{m-1}\\) is nonzero, and at most one of any \\(w\\) consecutive
    /// coefficients is nonzero.  (Hankerson, Menezes, Vanstone; def 3.32).
    ///
    /// The length of the NAF is at most one more than the length of
    /// the binary representation of \\(k\\).  This is why the
    /// `Scalar` type maintains an invariant (invariant #1) that the top bit is
    /// \\(0\\), so that the NAF of a scalar has at most 256 digits.
    ///
    /// Intuitively, this is like a binary expansion, except that we
    /// allow some coefficients to grow in magnitude up to
    /// \\(2\^{w-1}\\) so that the nonzero coefficients are as sparse
    /// as possible.
    ///
    /// When doing scalar multiplication, we can then use a lookup
    /// table of precomputed multiples of a point to add the nonzero
    /// terms \\( k_i P \\).  Using signed digits cuts the table size
    /// in half, and using odd digits cuts the table size in half
    /// again.
    ///
    /// To compute a \\(w\\)-NAF, we use a modification of Algorithm 3.35 of HMV:
    ///
    /// 1. \\( i \gets 0 \\)
    /// 2. While \\( k \ge 1 \\):
    ///     1. If \\(k\\) is odd, \\( n_i \gets k \operatorname{mods} 2^w \\), \\( k \gets k - n_i \\).
    ///     2. If \\(k\\) is even, \\( n_i \gets 0 \\).
    ///     3. \\( k \gets k / 2 \\), \\( i \gets i + 1 \\).
    /// 3. Return \\( n_0, n_1, ... , \\)
    ///
    /// Here \\( \bar x = x \operatorname{mods} 2^w \\) means the
    /// \\( \bar x \\) with \\( \bar x \equiv x \pmod{2^w} \\) and
    /// \\( -2^{w-1} \leq \bar x < 2^{w-1} \\).
    ///
    /// We implement this by scanning across the bits of \\(k\\) from
    /// least-significant bit to most-significant-bit.
    /// Write the bits of \\(k\\) as
    /// $$
    /// k = \sum\_{i=0}\^m k\_i 2^i,
    /// $$
    /// and split the sum as
    /// $$
    /// k = \sum\_{i=0}^{w-1} k\_i 2^i + 2^w \sum\_{i=0} k\_{i+w} 2^i
    /// $$
    /// where the first part is \\( k \mod 2^w \\).
    ///
    /// If \\( k \mod 2^w\\) is odd, and \\( k \mod 2^w < 2^{w-1} \\), then we emit
    /// \\( n_0 = k \mod 2^w \\).  Instead of computing
    /// \\( k - n_0 \\), we just advance \\(w\\) bits and reindex.
    ///
    /// If \\( k \mod 2^w\\) is odd, and \\( k \mod 2^w \ge 2^{w-1} \\), then
    /// \\( n_0 = k \operatorname{mods} 2^w = k \mod 2^w - 2^w \\).
    /// The quantity \\( k - n_0 \\) is
    /// $$
    /// \begin{aligned}
    /// k - n_0 &= \sum\_{i=0}^{w-1} k\_i 2^i + 2^w \sum\_{i=0} k\_{i+w} 2^i
    ///          - \sum\_{i=0}^{w-1} k\_i 2^i + 2^w \\\\
    /// &= 2^w + 2^w \sum\_{i=0} k\_{i+w} 2^i
    /// \end{aligned}
    /// $$
    /// so instead of computing the subtraction, we can set a carry
    /// bit, advance \\(w\\) bits, and reindex.
    ///
    /// If \\( k \mod 2^w\\) is even, we emit \\(0\\), advance 1 bit
    /// and reindex.  In fact, by setting all digits to \\(0\\)
    /// initially, we don't need to emit anything.
    pub(crate) fn non_adjacent_form(&self, w: usize) -> [i8; 256] {
        // required by the NAF definition
        debug_assert!(w >= 2);
        // required so that the NAF digits fit in i8
        debug_assert!(w <= 8);

        let mut naf = [0i8; 256];

        let mut x_u64 = [0u64; 5];
        read_le_u64_into(&self.bytes, &mut x_u64[0..4]);

        let width = 1 << w;
        let window_mask = width - 1;

        let mut pos = 0;
        let mut carry = 0;
        while pos < 256 {
            // Construct a buffer of bits of the scalar, starting at bit `pos`
            let u64_idx = pos / 64;
            let bit_idx = pos % 64;
            let bit_buf: u64 = if bit_idx < 64 - w {
                // This window's bits are contained in a single u64
                x_u64[u64_idx] >> bit_idx
            } else {
                // Combine the current u64's bits with the bits from the next u64
                (x_u64[u64_idx] >> bit_idx) | (x_u64[1 + u64_idx] << (64 - bit_idx))
            };

            // Add the carry into the current window
            let window = carry + (bit_buf & window_mask);

            if window & 1 == 0 {
                // If the window value is even, preserve the carry and continue.
                // Why is the carry preserved?
                // If carry == 0 and window & 1 == 0, then the next carry should be 0
                // If carry == 1 and window & 1 == 0, then bit_buf & 1 == 1 so the next carry should be 1
                pos += 1;
                continue;
            }

            if window < width / 2 {
                carry = 0;
                naf[pos] = window as i8;
            } else {
                carry = 1;
                naf[pos] = (window as i8).wrapping_sub(width as i8);
            }

            pos += w;
        }

        naf
    }

    /// Write this scalar in radix 16, with coefficients in \\([-8,8)\\),
    /// i.e., compute \\(a\_i\\) such that
    /// $$
    ///    a = a\_0 + a\_1 16\^1 + \cdots + a_{63} 16\^{63},
    /// $$
    /// with \\(-8 \leq a_i < 8\\) for \\(0 \leq i < 63\\) and \\(-8 \leq a_{63} \leq 8\\).
    ///
    /// The largest value that can be decomposed like this is just over \\(2^{255}\\). Thus, in
    /// order to not error, the top bit MUST NOT be set, i.e., `Self` MUST be less than
    /// \\(2^{255}\\).
    pub(crate) fn as_radix_16(&self) -> [i8; 64] {
        debug_assert!(self[31] <= 127);
        let mut output = [0i8; 64];

        // Step 1: change radix.
        // Convert from radix 256 (bytes) to radix 16 (nibbles)
        #[allow(clippy::identity_op)]
        #[inline(always)]
        fn bot_half(x: u8) -> u8 {
            (x >> 0) & 15
        }
        #[inline(always)]
        fn top_half(x: u8) -> u8 {
            (x >> 4) & 15
        }

        for i in 0..32 {
            output[2 * i] = bot_half(self[i]) as i8;
            output[2 * i + 1] = top_half(self[i]) as i8;
        }
        // Precondition note: since self[31] <= 127, output[63] <= 7

        // Step 2: recenter coefficients from [0,16) to [-8,8)
        for i in 0..63 {
            let carry = (output[i] + 8) >> 4;
            output[i] -= carry << 4;
            output[i + 1] += carry;
        }
        // Precondition note: output[63] is not recentered.  It
        // increases by carry <= 1.  Thus output[63] <= 8.

        output
    }

    /// Returns a size hint indicating how many entries of the return
    /// value of `to_radix_2w` are nonzero.

    /// Creates a representation of a Scalar in radix \\( 2^w \\) with \\(w = 4, 5, 6, 7, 8\\) for
    /// use with the Pippenger algorithm. Higher radixes are not supported to save cache space.
    /// Radix 256 is near-optimal even for very large inputs.
    ///
    /// Radix below 16 or above 256 is prohibited.
    /// This method returns digits in a fixed-sized array, excess digits are zeroes.
    ///
    /// For radix 16, `Self` must be less than \\(2^{255}\\). This is because most integers larger
    /// than \\(2^{255}\\) are unrepresentable in the form described below for \\(w = 4\\). This
    /// would be true for \\(w = 8\\) as well, but it is compensated for by increasing the size
    /// hint by 1.
    ///
    /// ## Scalar representation
    ///
    /// Radix \\(2\^w\\), with \\(n = ceil(256/w)\\) coefficients in \\([-(2\^w)/2,(2\^w)/2)\\),
    /// i.e., scalar is represented using digits \\(a\_i\\) such that
    /// $$
    ///    a = a\_0 + a\_1 2\^1w + \cdots + a_{n-1} 2\^{w*(n-1)},
    /// $$
    /// with \\(-2\^w/2 \leq a_i < 2\^w/2\\) for \\(0 \leq i < (n-1)\\) and \\(-2\^w/2 \leq a_{n-1} \leq 2\^w/2\\).
    ///
    #[cfg(feature = "precomputed-tables")]
    pub(crate) fn as_radix_2w(&self, w: usize) -> [i8; 64] {
        debug_assert!(w >= 4);
        debug_assert!(w <= 8);

        if w == 4 {
            return self.as_radix_16();
        }

        // Scalar formatted as four `u64`s with carry bit packed into the highest bit.
        let mut scalar64x4 = [0u64; 4];
        read_le_u64_into(&self.bytes, &mut scalar64x4[0..4]);

        let radix: u64 = 1 << w;
        let window_mask: u64 = radix - 1;

        let mut carry = 0u64;
        let mut digits = [0i8; 64];
        let digits_count = 256_usize.div_ceil(w);
        #[allow(clippy::needless_range_loop)]
        for i in 0..digits_count {
            // Construct a buffer of bits of the scalar, starting at `bit_offset`.
            let bit_offset = i * w;
            let u64_idx = bit_offset / 64;
            let bit_idx = bit_offset % 64;

            // Read the bits from the scalar
            let bit_buf: u64 = if bit_idx < 64 - w || u64_idx == 3 {
                // This window's bits are contained in a single u64,
                // or it's the last u64 anyway.
                scalar64x4[u64_idx] >> bit_idx
            } else {
                // Combine the current u64's bits with the bits from the next u64
                (scalar64x4[u64_idx] >> bit_idx) | (scalar64x4[1 + u64_idx] << (64 - bit_idx))
            };

            // Read the actual coefficient value from the window
            let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

            // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
            carry = (coef + (radix / 2)) >> w;
            digits[i] = ((coef as i64) - (carry << w) as i64) as i8;
        }

        // When 4 < w < 8, we can fold the final carry onto the last digit d,
        // because d < 2^w/2 so d + carry*2^w = d + 1*2^w < 2^(w+1) < 2^8.
        //
        // When w = 8, we can't fit carry*2^w into an i8.  This should
        // not happen anyways, because the final carry will be 0 for
        // reduced scalars, but Scalar invariant #1 allows 255-bit scalars.
        // To handle this, we expand the size_hint by 1 when w=8,
        // and accumulate the final carry onto another digit.
        match w {
            8 => digits[digits_count] += carry as i8,
            _ => digits[digits_count - 1] += (carry << w) as i8,
        }

        digits
    }

    /// Unpack this `Scalar` to an `UnpackedScalar` for faster arithmetic.
    pub(crate) fn unpack(&self) -> UnpackedScalar {
        UnpackedScalar::from_bytes(&self.bytes)
    }


}

impl UnpackedScalar {
    /// Pack the limbs of this `UnpackedScalar` into a `Scalar`.
    fn pack(&self) -> Scalar {
        Scalar {
            bytes: self.to_bytes(),
        }
    }


}





/// Read one or more u64s stored as little endian bytes.
///
/// ## Panics
/// Panics if `src.len() != 8 * dst.len()`.
fn read_le_u64_into(src: &[u8], dst: &mut [u64]) {
    assert!(
        src.len() == 8 * dst.len(),
        "src.len() = {}, dst.len() = {}",
        src.len(),
        dst.len()
    );
    for (bytes, val) in src.chunks(8).zip(dst.iter_mut()) {
        *val = u64::from_le_bytes(
            bytes
                .try_into()
                .expect("Incorrect src length, should be 8 * dst.len()"),
        );
    }
}

