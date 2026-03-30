// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of word references for generic ZKBoo backends.

use crate::{
    backend::{Backend, WordRef},
    word::{CompositeWord, Word, WordLike},
};
use core::ops::{BitAnd, BitOr, BitXor, Not};

/// A wrapper around [WordRef] that represents a boolean value,
/// i.e. a [u8] word set to either `0u8` (false) or `1u8` (true).
///
/// For constructors, see [WordRef::lsb], [WordRef::msb] and [WordRef::bit_at].
#[derive(Debug)]
#[repr(transparent)]
pub struct BooleanWordRef<B: Backend> {
    inner: WordRef<B, u8, 1>,
}

impl<B: Backend> BooleanWordRef<B> {
    /// Protected constructor, wrapping a [WordRef] that is expected to represent a boolean value.
    pub(super) fn new(inner: WordRef<B, u8, 1>) -> Self {
        return Self { inner };
    }

    /// Returns a [BooleanWordRef] representing the boolean value `true`.
    pub fn into_true(self) -> Self {
        return Self {
            inner: self
                .inner
                .into_const_same_width(CompositeWord::<u8, 1>::ONE),
        };
    }

    /// Returns a [BooleanWordRef] representing the boolean value `false`.
    pub fn into_false(self) -> Self {
        return Self {
            inner: self.inner.into_zero(),
        };
    }

    /// Unwraps the [BooleanWordRef] into the inner [WordRef].
    pub fn into(self) -> WordRef<B, u8, 1> {
        return self.inner;
    }

    /// Returns a [WordRef] where all bits are set to zero except the least significant bit,
    /// which is set to the least significant bit of this boolean value.
    pub fn into_lsb(self) -> WordRef<B, u8, 1> {
        return self.inner & 1u8;
    }

    /// Select operation: returns `then` if this boolean value is true (i.e., all bits set to 1)
    /// and `else_` if this boolean value is false (i.e., all bits set to 0).
    ///
    /// See [BooleanWordRef::select_var_const], [BooleanWordRef::select_const_var]
    /// and [BooleanWordRef::select_const_const] for variants of this method accepting constant
    /// `then` and/or `else_` arguments. Selection with constant condition is not provided,
    /// because it should be implemented using Rust's built-in `if`.
    pub fn select<W: Word, const N: usize>(
        self,
        then: WordRef<B, W, N>,
        else_: WordRef<B, W, N>,
    ) -> WordRef<B, W, N> {
        let cond = WordRef::mask(self);
        return (cond.clone() & then) ^ ((!cond) & else_);
    }

    /// Select operation with constant `else_` value.
    pub fn select_var_const<W: Word, const N: usize, C: WordLike<W, N>>(
        self,
        then: WordRef<B, W, N>,
        else_: C,
    ) -> WordRef<B, W, N> {
        let cond = WordRef::mask(self);
        return (cond.clone() & then) ^ ((!cond) & else_);
    }

    /// Select operation with constant `then` value.
    pub fn select_const_var<W: Word, const N: usize, C: WordLike<W, N>>(
        self,
        then: C,
        else_: WordRef<B, W, N>,
    ) -> WordRef<B, W, N> {
        let cond = WordRef::<B, W, N>::mask(self);
        return (cond.clone() & then) ^ ((!cond) & else_);
    }

    /// Select operation with constant `then` and `else_` values.
    pub fn select_const_const<W: Word, const N: usize, C: WordLike<W, N>>(
        self,
        then: C,
        else_: C,
    ) -> WordRef<B, W, N> {
        let cond = WordRef::<B, W, N>::mask(self);
        return (cond.clone() & then) ^ ((!cond) & else_);
    }

    /// Variant of [BooleanWordRef::select] selecting between [BooleanWordRef]s.
    pub fn boolean_select(
        self,
        then: BooleanWordRef<B>,
        else_: BooleanWordRef<B>,
    ) -> BooleanWordRef<B> {
        return Self::new(self.select(then.into(), else_.into()));
    }

    /// Variant of [BooleanWordRef::select_var_const] selecting between
    /// a [BooleanWordRef] and a constant boolean value.
    pub fn boolean_select_var_const(
        self,
        then: BooleanWordRef<B>,
        else_: bool,
    ) -> BooleanWordRef<B> {
        return Self::new(self.select_var_const(then.into(), else_ as u8));
    }

    /// Variant of [BooleanWordRef::select_const_var] selecting between
    /// a constant boolean value and a [BooleanWordRef].
    pub fn boolean_select_const_var(
        self,
        then: bool,
        else_: BooleanWordRef<B>,
    ) -> BooleanWordRef<B> {
        return Self::new(self.select_const_var(then as u8, else_.into()));
    }

    /// Variant of [BooleanWordRef::select_const_const] selecting between
    /// constant boolean values.
    pub fn boolean_select_const_const(self, then: bool, else_: bool) -> BooleanWordRef<B> {
        return Self::new(self.select_const_const(then as u8, else_ as u8));
    }
}

impl<B: Backend> Not for BooleanWordRef<B> {
    type Output = Self;

    /// Bitwise NOT operation, which negates the boolean value.
    fn not(self) -> Self::Output {
        return BooleanWordRef {
            inner: self.inner ^ 1u8,
        };
    }
}

impl<B: Backend> BitAnd<BooleanWordRef<B>> for BooleanWordRef<B> {
    type Output = Self;

    /// Bitwise AND operation, which corresponds to logical AND for boolean values.
    fn bitand(self, rhs: BooleanWordRef<B>) -> Self::Output {
        return BooleanWordRef {
            inner: self.inner & rhs.inner,
        };
    }
}

impl<B: Backend> BitAnd<bool> for BooleanWordRef<B> {
    type Output = Self;

    /// Bitwise AND operation, which corresponds to logical AND for boolean values.
    fn bitand(self, rhs: bool) -> Self::Output {
        return BooleanWordRef {
            inner: self.inner & rhs as u8,
        };
    }
}

impl<B: Backend> BitOr<BooleanWordRef<B>> for BooleanWordRef<B> {
    type Output = Self;

    /// Bitwise OR operation, which corresponds to logical OR for boolean values.
    fn bitor(self, rhs: BooleanWordRef<B>) -> Self::Output {
        return BooleanWordRef {
            inner: self.inner | rhs.inner,
        };
    }
}

impl<B: Backend> BitOr<bool> for BooleanWordRef<B> {
    type Output = Self;

    /// Bitwise OR operation, which corresponds to logical OR for boolean values.
    fn bitor(self, rhs: bool) -> Self::Output {
        return BooleanWordRef {
            inner: self.inner | rhs as u8,
        };
    }
}

impl<B: Backend> BitXor<BooleanWordRef<B>> for BooleanWordRef<B> {
    type Output = Self;

    /// Bitwise XOR operation, which corresponds to logical XOR for boolean values.
    fn bitxor(self, rhs: BooleanWordRef<B>) -> Self::Output {
        return BooleanWordRef {
            inner: self.inner ^ rhs.inner,
        };
    }
}

impl<B: Backend> BitXor<bool> for BooleanWordRef<B> {
    type Output = Self;

    /// Bitwise XOR operation, which corresponds to logical XOR for boolean values.
    fn bitxor(self, rhs: bool) -> Self::Output {
        return BooleanWordRef {
            inner: self.inner ^ rhs as u8,
        };
    }
}

impl<B: Backend> Clone for BooleanWordRef<B> {
    /// Clones the [BooleanWordRef] by cloning the inner [WordRef].
    fn clone(&self) -> Self {
        return BooleanWordRef {
            inner: self.inner.clone(),
        };
    }
}
