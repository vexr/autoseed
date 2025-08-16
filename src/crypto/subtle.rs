//! Modified implementation based on subtle (with modifications)
//!
//! Original source: https://github.com/dalek-cryptography/subtle
//! File: src/lib.rs
//!
//! Copyright (c) 2016-2018 isis lovecruft, Henry de Valence
//!
//! Authors:
//! - isis agora lovecruft <isis@patternsinthevoid.net>
//! - Henry de Valence <hdevalence@hdevalence.ca>

//! **Pure-Rust traits and utilities for constant-time cryptographic implementations.**


use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

/// The `Choice` struct represents a choice for use in conditional assignment.
#[derive(Copy, Clone, Debug)]
pub struct Choice(u8);

impl Choice {
    /// Unwrap the `Choice` wrapper to reveal the underlying `u8`.
    #[inline]
    pub fn unwrap_u8(&self) -> u8 {
        self.0
    }
}

impl From<Choice> for bool {
    #[inline]
    fn from(source: Choice) -> bool {
        debug_assert!((source.0 == 0u8) | (source.0 == 1u8));
        source.0 != 0
    }
}

impl BitAnd for Choice {
    type Output = Choice;
    #[inline]
    fn bitand(self, rhs: Choice) -> Choice {
        (self.0 & rhs.0).into()
    }
}

impl BitAndAssign for Choice {
    #[inline]
    fn bitand_assign(&mut self, rhs: Choice) {
        *self = *self & rhs;
    }
}

impl BitOr for Choice {
    type Output = Choice;
    #[inline]
    fn bitor(self, rhs: Choice) -> Choice {
        (self.0 | rhs.0).into()
    }
}

impl BitOrAssign for Choice {
    #[inline]
    fn bitor_assign(&mut self, rhs: Choice) {
        *self = *self | rhs;
    }
}

impl BitXor for Choice {
    type Output = Choice;
    #[inline]
    fn bitxor(self, rhs: Choice) -> Choice {
        (self.0 ^ rhs.0).into()
    }
}

impl BitXorAssign for Choice {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Choice) {
        *self = *self ^ rhs;
    }
}

impl Not for Choice {
    type Output = Choice;
    #[inline]
    fn not(self) -> Choice {
        (1u8 & (!self.0)).into()
    }
}

#[inline(never)]
fn black_box<T: Copy>(input: T) -> T {
    unsafe {
        core::ptr::read_volatile(&input)
    }
}

impl From<u8> for Choice {
    #[inline]
    fn from(input: u8) -> Choice {
        debug_assert!((input == 0u8) | (input == 1u8));
        Choice(black_box(input))
    }
}

/// An `Eq`-like trait that produces a `Choice` instead of a `bool`.
pub trait ConstantTimeEq {
    fn ct_eq(&self, other: &Self) -> Choice;

}

impl<T: ConstantTimeEq> ConstantTimeEq for [T] {
    #[inline]
    fn ct_eq(&self, _rhs: &[T]) -> Choice {
        if self.len() != _rhs.len() {
            return Choice::from(0u8);
        }
        let mut x = 1u8;
        for (a, b) in self.iter().zip(_rhs.iter()) {
            x &= a.ct_eq(b).unwrap_u8();
        }
        x.into()
    }
}

/// A type which can be conditionally selected in constant time.
pub trait ConditionallySelectable: Sized {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;

    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::conditional_select(self, other, choice);
    }
    
    #[inline]
    #[allow(dead_code)]
    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let t = Self::conditional_select(a, b, choice);
        a.conditional_assign(b, choice);
        b.conditional_assign(&t, choice);
    }
}

// Direct implementations without nested macros
impl ConstantTimeEq for u8 {
    #[inline]
    fn ct_eq(&self, other: &u8) -> Choice {
        let x = self ^ other;
        let mut x = x as i8;
        x = (x | x.wrapping_neg()) >> 7;
        Choice::from((x.wrapping_add(1)) as u8)
    }
}

impl ConstantTimeEq for u16 {
    #[inline]
    fn ct_eq(&self, other: &u16) -> Choice {
        let x = self ^ other;
        let mut x = x as i16;
        x = (x | x.wrapping_neg()) >> 15;
        Choice::from((x.wrapping_add(1)) as u8)
    }
}

impl ConstantTimeEq for u32 {
    #[inline]
    fn ct_eq(&self, other: &u32) -> Choice {
        let x = self ^ other;
        let mut x = x as i32;
        x = (x | x.wrapping_neg()) >> 31;
        Choice::from((x.wrapping_add(1)) as u8)
    }
}

impl ConstantTimeEq for u64 {
    #[inline]
    fn ct_eq(&self, other: &u64) -> Choice {
        let x = self ^ other;
        let mut x = x as i64;
        x = (x | x.wrapping_neg()) >> 63;
        Choice::from((x.wrapping_add(1)) as u8)
    }
}

impl ConstantTimeEq for u128 {
    #[inline]
    fn ct_eq(&self, other: &u128) -> Choice {
        let x = self ^ other;
        let mut x = x as i128;
        x = (x | x.wrapping_neg()) >> 127;
        Choice::from((x.wrapping_add(1)) as u8)
    }
}

impl ConstantTimeEq for usize {
    #[inline]
    fn ct_eq(&self, other: &usize) -> Choice {
        let x = self ^ other;
        let mut x = x as isize;
        x = (x | x.wrapping_neg()) >> ((core::mem::size_of::<usize>() * 8) - 1);
        Choice::from((x.wrapping_add(1)) as u8)
    }
}

macro_rules! impl_conditionally_selectable {
    ($type:ty) => {
        impl ConditionallySelectable for $type {
            #[inline]
            fn conditional_select(a: &$type, b: &$type, choice: Choice) -> $type {
                let choice_1 = choice.unwrap_u8() as $type;
                let choice_0 = (choice_1 ^ 1);
                
                (choice_0 * a) | (choice_1 * b)
            }
        }
    };
}

impl_conditionally_selectable!(u8);
impl_conditionally_selectable!(u16);
impl_conditionally_selectable!(u32);
impl_conditionally_selectable!(u64);
impl_conditionally_selectable!(u128);
impl_conditionally_selectable!(usize);

/// A type which can be conditionally negated in constant time.
pub trait ConditionallyNegatable {
    fn conditional_negate(&mut self, choice: Choice);
}


impl ConditionallySelectable for [u8; 32] {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = u8::conditional_select(&a[i], &b[i], choice);
        }
        result
    }
}