// SPDX-License-Identifier: LGPL-3.0-or-later

//! Trait for fixed-width words.

use crate::word::{ByWordType, Words};
use alloc::vec::Vec;
use core::{
    array,
    fmt::Debug,
    ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr},
};
use zeroize::Zeroize;

/// Seal trait to restrict external implementations of [Word].
#[doc(hidden)]
mod seal {
    pub trait Word {}
    impl Word for u8 {}
    #[cfg(feature = "u16")]
    impl Word for u16 {}
    #[cfg(feature = "u32")]
    impl Word for u32 {}
    #[cfg(feature = "u64")]
    impl Word for u64 {}
    #[cfg(feature = "u128")]
    impl Word for u128 {}
}

/// Token type to restrict external usage of certain [Word] trait methods.
#[doc(hidden)]
struct PrivateWordMethodToken;

/// Type alias for the maximum-width word, used for intermediate calculations in casts.
/// Currently set to [u128], but may change in the future if larger word types are added.
///
/// ⚠️ Stability: This type alias is unstable and may change without semver bump.
///                Do not rely on this type alias in production code.
#[doc(hidden)]
#[allow(non_camel_case_types)]
// pub type umax = u256;
pub type umax = u128;

/// Trait for word-like types, which can be converted to and from a [CompositeWord]
/// with given [Word] type and width.
///
/// Used to allow uniform treatment of [Word] and [CompositeWord] by implementations.
pub trait WordLike<W: Word, const N: usize>: Sized + Copy + Debug {
    /// Converts this value type to a [CompositeWord] of the given [Word] type and width.
    fn to_word(self) -> CompositeWord<W, N>;
    /// Converts a [CompositeWord] of the given [Word] type and width back to this value type.
    fn from_word(words: CompositeWord<W, N>) -> Self;
}

impl<W: Word, const N: usize> WordLike<W, N> for [W; N] {
    #[inline]
    fn to_word(self) -> CompositeWord<W, N> {
        return CompositeWord::from_le_words(self);
    }

    #[inline]
    fn from_word(words: CompositeWord<W, N>) -> Self {
        return words.to_le_words();
    }
}

/// Trait for fixed-width machine words.
///
/// The trait is sealed, implemented for [u8], [u16], [u32], [u64] and [u128] depending on features.
pub trait Word:
    seal::Word
    + WordLike<Self, 1>
    + Copy
    + Sync
    + Send
    + 'static
    + PartialEq
    + Eq
    + core::hash::Hash
    + core::fmt::Debug
    + core::hash::Hash
    + core::fmt::Debug
    + core::ops::Not<Output = Self>
    + core::ops::BitXor<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::BitOr<Output = Self>
    + core::ops::Shl<usize, Output = Self>
    + core::ops::Shr<usize, Output = Self>
    + Default
    + Zeroize
{
    /// Width in bits for this word type.
    const WIDTH: usize;

    /// Constant zero value for this word type.
    const ZERO: Self;

    /// Constant one value for this word type.
    const ONE: Self;

    /// Constant max value for this word type.
    const MAX: Self;

    /// Creates [Word::ZERO] or [Word::ONE] for this word type from a boolean.
    fn from_bool(bool: bool) -> Self {
        return if bool { Self::ONE } else { Self::ZERO };
    }

    /// Bitwise NOT operation.
    fn not(self) -> Self;

    /// Bitwise XOR operation.
    fn bitxor(self, rhs: Self) -> Self;

    /// Bitwise AND operation.
    fn bitand(self, rhs: Self) -> Self;

    /// Bitwise OR operation.
    fn bitor(self, rhs: Self) -> Self;

    /// Checked left shift of this word by the given amount.
    /// Returns zero if the shift amount exceeds word width.
    fn unbounded_shl(self, shift: usize) -> Self;

    /// Checked right shift of this word by the given amount.
    /// Returns zero if the shift amount exceeds word width.
    fn unbounded_shr(self, shift: usize) -> Self;

    /// Overflowing left shift.
    fn overflowing_shl(self, shift: usize) -> (Self, Self) {
        if shift >= 2 * Self::WIDTH {
            return (Self::ZERO, Self::ZERO);
        }
        if shift >= Self::WIDTH {
            return (Self::ZERO, self.unbounded_shl(shift - Self::WIDTH));
        }
        let pieces = self.rotate_left(shift);
        let mask_lo = Self::MAX.unbounded_shl(shift);
        let mask_hi = !mask_lo;
        return (pieces & mask_lo, pieces & mask_hi);
    }

    /// Left rotation of this word by given amount.
    fn rotate_left(self, rotate: usize) -> Self;

    /// Right rotation of this word by given amount.
    fn rotate_right(self, rotate: usize) -> Self;

    /// Bit-reversal of this word.
    fn reverse_bits(self) -> Self;

    /// Byte-reversal of this word.
    fn swap_bytes(self) -> Self;

    /// Number of leading zeros in this word.
    fn leading_zeros(self) -> usize;

    /// Number of leading ones in this word.
    fn leading_ones(self) -> usize;

    /// Carry generation operation.
    fn carry(self, g: Self, c: bool) -> (Self, bool) {
        let p = self;
        let mut carry = Self::ZERO;
        let mut mask = Self::ONE;
        let mut c: Self = Self::from_bool(c);
        let mut carry_out: bool = false;
        for _ in 0..Self::WIDTH {
            carry = carry ^ c;
            c = c & p;
            c = c ^ (mask & g);
            mask = mask.unbounded_shl(1);
            carry_out = c != Self::ZERO;
            c = c.unbounded_shl(1);
        }
        return (carry, carry_out);
    }

    /// Least significant bit of this word:
    fn lsb(self) -> bool {
        return self & Self::ONE != Self::ZERO;
    }

    /// Most significant bit of this word:
    fn msb(self) -> bool {
        return (self.unbounded_shr(Self::WIDTH - 1)).lsb();
    }

    /// Bit of this word at given index:
    fn bit_at(self, idx: usize) -> bool {
        return (self.unbounded_shr(idx)).lsb();
    }

    /// Applies the given function to each bit of this word,
    /// from least significant to most significant.
    fn map_bits<F: FnMut(bool)>(self, mut f: F) {
        for i in 0..Self::WIDTH {
            f(self.clone().bit_at(i));
        }
    }

    // /// Little-endian byte representation type for this word type.
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Copy + Default;

    /// Creates a word of this type from its little-endian byte representation.
    fn from_le_bytes(bytes: Self::Bytes) -> Self;

    /// Converts this word to its little-endian byte representation.
    fn to_le_bytes(self) -> Self::Bytes;

    /// Creates a word of this type from its big-endian byte representation.
    fn from_be_bytes(bytes: Self::Bytes) -> Self;

    /// Converts this word to its big-endian byte representation.
    fn to_be_bytes(self) -> Self::Bytes;

    /// Upcasts this word to [umax], always without truncation.
    ///
    /// ⚠️ Stability: This method is unstable and may change without semver bump.
    ///                Its usage is private to this module.
    #[doc(hidden)]
    #[allow(private_interfaces)]
    fn cast_to_umax(self, _token: PrivateWordMethodToken) -> umax;

    /// Creates a word of this word type from a [umax] word, truncating if necessary.
    ///
    /// ⚠️ Stability: This method is unstable and may change without semver bump.
    ///                Its usage is private to this module.
    #[doc(hidden)]
    #[allow(private_interfaces)]
    fn cast_from_umax(value: umax, _token: PrivateWordMethodToken) -> Self;

    /// Converts this word to a word of another type `U`, truncating if necessary.
    fn cast<U: Word>(self) -> U {
        return U::cast_from_umax(
            self.cast_to_umax(PrivateWordMethodToken),
            PrivateWordMethodToken,
        );
    }

    /// Creates a word of this type from a word of another type `U`, truncating if necessary.
    fn cast_from<U: Word>(other: U) -> Self {
        return Self::cast_from_umax(
            other.cast_to_umax(PrivateWordMethodToken),
            PrivateWordMethodToken,
        );
    }

    /// Reference to the value associated to this type from the given type-indexed value map.
    fn value_by_word_type<T>(value_map: &ByWordType<T>) -> &T;

    /// Mutable reference to the value associated to this type from the given type-indexed value map.
    fn value_mut_by_word_type<T>(value_map: &mut ByWordType<T>) -> &mut T;

    /// Reference to the word vector of this word type from the given word store.
    fn vec_from_words(store: &Words) -> &Vec<Self>;

    /// Mutable reference to the word vector of this word type from the given word store.
    fn vec_mut_from_words(store: &mut Words) -> &mut Vec<Self>;

    /// Creates a boolean mask from the given bool, with all bits set to the boolean value.
    fn mask(bool: bool) -> Self {
        return if bool { Self::MAX } else { Self::ZERO };
    }

    /// Tiles this word into a larger target word size.
    ///
    /// If the target word size is smaller, this behaves as a [Word::cast] instead.
    /// If the target word size is the same as this word size, the result is the same as this word.
    fn tile<U: Word, const M: usize>(self) -> U {
        // Presumes (correctly) that word sizes come in powers of two.
        let mut res: U = self.cast();
        let mut width = Self::WIDTH;
        while width < U::WIDTH {
            res = (res << width) ^ res;
            width *= 2;
        }
        return res;
    }

    /// Two's complement negation.
    fn wrapping_neg(self) -> Self;

    /// Wrapping addition.
    fn wrapping_add(self, rhs: Self) -> Self;

    /// Overflowing addition.
    fn overflowing_add(self, rhs: Self) -> (Self, bool);

    /// Wrapping subtraction.
    fn wrapping_sub(self, rhs: Self) -> Self;

    /// Overflowing subtraction.
    fn overflowing_sub(self, rhs: Self) -> (Self, bool);

    /// Wrapping multiplication.
    fn wrapping_mul(self, rhs: Self) -> Self;

    /// Wide multiplication.
    fn wide_mul(self, rhs: Self) -> (Self, Self);

    /// Less than or equal comparison.
    fn le(self, rhs: Self) -> bool;

    /// Less than comparison.
    fn lt(self, rhs: Self) -> bool;

    /// Greater than or equal comparison.
    fn ge(self, rhs: Self) -> bool;

    /// Greater than comparison.
    fn gt(self, rhs: Self) -> bool;

    /// Equality comparison.
    fn eq(self, rhs: Self) -> bool;

    /// Inequality comparison.
    fn ne(self, rhs: Self) -> bool;

    /// Returns true if this word is equal to [Word::ZERO].
    fn is_zero(self) -> bool {
        return self.eq(Self::ZERO);
    }

    /// Returns true if this word is not equal to [Word::ZERO].
    fn is_nonzero(self) -> bool {
        return self.ne(Self::ZERO);
    }
}

macro_rules! impl_Word {
    ($($t:ident), *) => {
        $(

        impl WordLike<$t, 1> for $t {
            fn to_word(self) -> CompositeWord<$t, 1> {
                return CompositeWord::from_le_words([self]);
            }
            fn from_word(words: CompositeWord<$t, 1>) -> Self {
                let [word] = words.to_le_words();
                return word;
            }
        }

        impl Word for $t {

            const WIDTH: usize = (core::mem::size_of::<Self>() * 8);
            const ZERO: Self = 0 as $t;
            const ONE: Self = 1 as $t;
            const MAX: Self = $t::MAX;

            fn not(self) -> Self {
                return !self;
            }

            fn bitxor(self, rhs: Self) -> Self {
                return self ^ rhs;
            }

            fn bitand(self, rhs: Self) -> Self {
                return self & rhs;
            }

            fn bitor(self, rhs: Self) -> Self {
                return self | rhs;
            }

            fn unbounded_shl(self, shift: usize) -> Self {
                if shift >= Self::WIDTH {
                    return Self::ZERO;
                }
                return self << shift;
            }

            fn unbounded_shr(self, shift: usize) -> Self {
                if shift >= Self::WIDTH {
                    return Self::ZERO;
                }
                return self >> shift;
            }

            fn rotate_left(self, mut shift: usize) -> Self {
                shift %= Self::WIDTH;
                return <$t>::rotate_left(self, shift as u32);
            }

            fn rotate_right(self, mut shift: usize) -> Self {
                shift %= Self::WIDTH;
                return <$t>::rotate_right(self, shift as u32);
            }

            fn reverse_bits(self) -> Self {
                return self.reverse_bits();
            }

            fn swap_bytes(self) -> Self {
                return self.swap_bytes();
            }

            fn leading_zeros(self) -> usize {
                return self.leading_zeros() as usize;
            }

            fn leading_ones(self) -> usize {
                return self.leading_ones() as usize;
            }

            fn wrapping_neg(self) -> Self {
                return self.wrapping_neg();
            }

            fn wrapping_add(self, rhs: Self) -> Self {
                return self.wrapping_add(rhs);
            }

            fn overflowing_add(self, rhs: Self) -> (Self, bool) {
                return self.overflowing_add(rhs);
            }

            fn wrapping_sub(self, rhs: Self) -> Self {
                return self.wrapping_sub(rhs);
            }

            fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
                return self.overflowing_sub(rhs);
            }

            fn wrapping_mul(self, rhs: Self) -> Self {
                return self.wrapping_mul(rhs);
            }

            fn wide_mul(self, rhs: Self) -> (Self, Self) {
                return self.carrying_mul(rhs, Self::ZERO);
            }

            fn le(self, rhs: Self) -> bool {
                return self <= rhs;
            }

            fn lt(self, rhs: Self) -> bool {
                return self < rhs;
            }

            fn ge(self, rhs: Self) -> bool {
                return self >= rhs;
            }

            fn gt(self, rhs: Self) -> bool {
                return self > rhs;
            }

            fn eq(self, rhs: Self) -> bool {
                return self == rhs;
            }

            fn ne(self, rhs: Self) -> bool {
                return self != rhs;
            }

            type Bytes = [u8; core::mem::size_of::<Self>()];

            fn from_be_bytes(bytes: Self::Bytes) -> Self {
                return <$t>::from_be_bytes(bytes);
            }

            fn to_be_bytes(self) -> Self::Bytes {
                return <$t>::to_be_bytes(self);
            }

            fn from_le_bytes(bytes: Self::Bytes) -> Self {
                return <$t>::from_le_bytes(bytes);
            }

            fn to_le_bytes(self) -> Self::Bytes {
                return <$t>::to_le_bytes(self);
            }

            #[allow(private_interfaces)]
            fn cast_to_umax(self, _token: PrivateWordMethodToken) -> umax {
                return self.into();
            }

            #[allow(private_interfaces)]
            fn cast_from_umax(value: umax, _token: PrivateWordMethodToken) -> Self {
                return value as $t;
            }

            fn value_by_word_type<T>(value_map: &ByWordType<T>) -> &T {
                return &value_map.$t;
            }

            fn value_mut_by_word_type<T>(value_map: &mut ByWordType<T>) -> &mut T {
                return &mut value_map.$t;
            }

            fn vec_from_words(store: &Words) -> &Vec<Self> {
                return &store.$t;
            }

            fn vec_mut_from_words(store: &mut Words) -> &mut Vec<Self> {
                return &mut store.$t;
            }
        }

    )*
    };
}

impl_Word!(u8);
#[cfg(feature = "u16")]
impl_Word!(u16);
#[cfg(feature = "u32")]
impl_Word!(u32);
#[cfg(feature = "u64")]
impl_Word!(u64);
#[cfg(feature = "u128")]
impl_Word!(u128);

/// Implementation of composite words, wrapping fixed-size arrays of fixed-width [Word]s.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
pub struct CompositeWord<W: Word, const N: usize> {
    le_words: [W; N],
}

impl<W: Word, const N: usize> CompositeWord<W, N> {
    const _ASSERT_NONZERO: () = assert!(N > 0, "CompositeWord must have positive cardinality");

    /// Creates a composite word of this type from its little-endian byte representation.
    pub fn from_le_bytes(bytes: [W::Bytes; N]) -> Self {
        return Self::from_le_words(bytes.map(W::from_le_bytes));
    }

    /// Converts this composite word to its little-endian byte representation.
    pub fn to_le_bytes(self) -> [W::Bytes; N] {
        return self.to_le_words().map(W::to_le_bytes);
    }

    /// Creates a composite word of this type from its big-endian byte representation.
    pub fn from_be_bytes(bytes: [W::Bytes; N]) -> Self {
        return Self::from_be_words(bytes.map(W::from_be_bytes));
    }

    /// Converts this composite word to its big-endian byte representation.
    pub fn to_be_bytes(self) -> [W::Bytes; N] {
        return self.to_be_words().map(W::to_be_bytes);
    }

    /// Creates a composite word from an array of words in little-endian order.
    #[inline]
    pub const fn from_le_words(le_words: [W; N]) -> Self {
        return Self { le_words };
    }

    /// Little-endian word array representation of this composite word.
    #[inline]
    pub const fn to_le_words(self) -> [W; N] {
        return self.le_words;
    }

    /// Creates a composite word from an array of words in big-endian order.
    pub const fn from_be_words(be_words: [W; N]) -> Self {
        let mut le_words = be_words;
        le_words.reverse();
        return Self { le_words };
    }
    /// Big-endian word array representation of this composite word.
    pub const fn to_be_words(self) -> [W; N] {
        let mut be_words = self.le_words;
        be_words.reverse();
        return be_words;
    }

    /// Creates [CompositeWord::ZERO] or [CompositeWord::ONE] for this word type from a boolean.
    pub fn from_bool(bool: bool) -> Self {
        return if bool { Self::ONE } else { Self::ZERO };
    }

    /// Width in bits of this composite word type.
    pub const WIDTH: usize = W::WIDTH * N;

    /// Constant zero value for this composite word type.
    pub const ZERO: Self = Self::from_le_words([W::ZERO; N]);

    /// Constant one value for this composite word type.
    pub const ONE: Self = {
        let mut one = [W::ZERO; N];
        one[0] = W::ONE; // little-endian
        Self::from_le_words(one)
    };

    /// Constant max value for this composite word type.
    pub const MAX: Self = Self::from_le_words([W::MAX; N]);

    /// Bitwise NOT operation.
    pub fn not(self) -> Self {
        return Self::from_le_words(self.le_words.map(|w| !w));
    }

    /// Bitwise XOR operation.
    pub fn bitxor(self, rhs: Self) -> Self {
        return Self::from_le_words(array::from_fn(|i| self.le_words[i] ^ rhs.le_words[i]));
    }

    /// Bitwise AND operation.
    pub fn bitand(self, rhs: Self) -> Self {
        return Self::from_le_words(array::from_fn(|i| self.le_words[i] & rhs.le_words[i]));
    }

    /// Bitwise OR operation.
    pub fn bitor(self, rhs: Self) -> Self {
        return Self::from_le_words(array::from_fn(|i| self.le_words[i] | rhs.le_words[i]));
    }

    /// Unbounded left shift operation.
    pub fn unbounded_shl(self, shift: usize) -> Self {
        if shift >= Self::WIDTH {
            return Self::ZERO;
        }
        let mut res = self.rotate_left(shift).to_le_words();
        let word_shift = shift / W::WIDTH;
        let bit_shift = shift % W::WIDTH;
        if word_shift > 0 {
            for i in 0..word_shift {
                res[i] = W::ZERO;
            }
        }
        if bit_shift > 0 {
            let hi_mask: W = W::MAX << bit_shift;
            res[word_shift] = res[word_shift] & hi_mask;
        }
        return Self::from_le_words(res);
    }

    /// Unbounded right shift operation.
    pub fn unbounded_shr(self, shift: usize) -> Self {
        if shift >= Self::WIDTH {
            return Self::ZERO;
        }
        let mut res = self.rotate_right(shift).to_le_words();
        let word_shift = shift / W::WIDTH;
        let bit_shift = shift % W::WIDTH;
        if word_shift > 0 {
            for i in 0..word_shift {
                res[N - 1 - i] = W::ZERO;
            }
        }
        if bit_shift > 0 {
            let lo_mask: W = W::MAX >> bit_shift;
            res[N - 1 - word_shift] = res[N - 1 - word_shift] & lo_mask;
        }
        return Self::from_le_words(res);
    }

    /// Overflowing left shift.
    pub fn overflowing_shl(self, shift: usize) -> (Self, Self) {
        if shift >= 2 * Self::WIDTH {
            return (Self::ZERO, Self::ZERO);
        }
        if shift >= Self::WIDTH {
            return (Self::ZERO, self.unbounded_shl(shift - Self::WIDTH));
        }
        let pieces = self.rotate_left(shift);
        let mask_lo = Self::MAX.unbounded_shl(shift);
        let mask_hi = !mask_lo;
        return (pieces & mask_lo, pieces & mask_hi);
    }

    /// Left rotation operation.
    pub fn rotate_left(self, shift: usize) -> Self {
        let le_words = self.le_words;
        let word_shift = shift / W::WIDTH;
        let bit_shift = shift % W::WIDTH;
        let rotated_words: [W; N] =
            array::from_fn(|i| le_words[(N - word_shift + i) % N].rotate_left(bit_shift));
        // Note word index shifts are reversed ^^^^^^^^^^^^^^^^^^^^^^^^ because of LE repr.
        if bit_shift == 0 {
            return Self::from_le_words(rotated_words);
        }
        let mut res = rotated_words;
        let hi_mask: W = W::MAX << bit_shift;
        let lo_mask: W = !hi_mask;
        for i in 0..N {
            res[i] = (res[i] & hi_mask) ^ (rotated_words[(N - 1 + i) % N] & lo_mask);
            // Note word index shifts are reversed       ^^^^^^^^^^^^^^^ because of LE repr.
        }
        return Self::from_le_words(res);
    }

    /// Right rotation operation.
    pub fn rotate_right(self, shift: usize) -> Self {
        let le_words = self.le_words;
        let word_shift = shift / W::WIDTH;
        let bit_shift = shift % W::WIDTH;
        let rotated_words: [W; N] =
            array::from_fn(|i| le_words[(i + word_shift) % N].rotate_right(bit_shift));
        // Note word index shifts are reversed ^^^^^^^^^^^^^^^^^^^^ because of LE repr.
        if bit_shift == 0 {
            return Self::from_le_words(rotated_words);
        }
        let mut res = rotated_words;
        let lo_mask: W = W::MAX >> bit_shift;
        let hi_mask: W = !lo_mask;
        for i in 0..N {
            res[i] = (res[i] & lo_mask) ^ (rotated_words[(i + 1) % N] & hi_mask);
            // Note word index shifts are reversed       ^^^^^^^^^^^ because of LE repr.
        }
        return Self::from_le_words(res);
    }

    /// Bit-reversal operation.
    pub fn reverse_bits(self) -> Self {
        let mut res = self.le_words;
        res.reverse();
        return Self::from_le_words(res.map(|w| w.reverse_bits()));
    }

    /// Byte-reversal operation.
    pub fn swap_bytes(self) -> Self {
        let mut res = self.le_words;
        res.reverse();
        return Self::from_le_words(res.map(|w| w.swap_bytes()));
    }

    /// Word-reversal of this composite word.
    pub fn swap_words(self) -> Self {
        let mut res = self.le_words;
        res.reverse();
        return Self::from_le_words(res);
    }

    /// Count leading zeros in this composite word.
    pub fn leading_zeros(self) -> usize {
        let mut count = 0;
        for i in (0..N).rev() {
            let w = self.le_words[N - 1 - i];
            //     LE representation ^^^^^^^^^
            if w == W::ZERO {
                count += W::WIDTH;
            } else {
                count += w.leading_zeros();
                break;
            }
        }
        return count;
    }

    /// Count leading ones in this composite word.
    pub fn leading_ones(self) -> usize {
        let mut count = 0;
        for i in (0..N).rev() {
            let w = self.le_words[N - 1 - i];
            //     LE representation ^^^^^^^^^
            if w == W::MAX {
                count += W::WIDTH;
            } else {
                count += w.leading_ones();
                break;
            }
        }
        return count;
    }
    /// Least significant word of this composite word.
    pub fn lsw(self) -> W {
        return self.le_words[0];
    }

    /// Most significant word of this composite word.
    pub fn msw(self) -> W {
        return self.le_words[N - 1];
    }

    /// Word at given index of this composite word, or zero if index is out of bounds.
    pub fn word_at(self, idx: usize) -> W {
        if idx >= N {
            return W::ZERO;
        }
        return self.le_words[idx];
    }

    /// Least significant bit of this word.
    pub fn lsb(self) -> bool {
        return self.lsw().lsb();
    }

    /// Most significant bit of this word.
    pub fn msb(self) -> bool {
        return self.msw().msb();
    }

    /// Bit of this word at given index, or zero if index is out of bounds.
    pub fn bit_at(self, idx: usize) -> bool {
        let word_idx = idx / W::WIDTH;
        let bit_idx = idx % W::WIDTH;
        return self.word_at(word_idx).bit_at(bit_idx);
    }

    /// Applies the given function to each bit of this word,
    /// from least significant to most significant.
    pub fn map_bits<F: FnMut(bool)>(self, mut f: F) {
        for i in 0..Self::WIDTH {
            f(self.clone().bit_at(i));
        }
    }

    /// Carry generation operation.
    pub fn carry(self, g: Self, c: bool) -> (Self, bool) {
        let mut c = c;
        let mut carry = [W::ZERO; N];
        for i in 0..N {
            let p = self.le_words[i];
            let g = g.le_words[i];
            (carry[i], c) = p.carry(g, c);
        }
        return (Self::from_le_words(carry), c);
    }

    /// Creates a boolean mask from the given bool, with all bits set to the boolean value.
    pub fn mask(bool: bool) -> Self {
        return if bool { Self::MAX } else { Self::ZERO };
    }

    /// Wrapping addition (with fixed initial carry).
    fn _wrapping_add_with_carry(self, rhs: Self, carry: bool) -> Self {
        let p = self.bitxor(rhs);
        let g = self.bitand(rhs);
        let (carry, _) = p.carry(g, carry);
        return p.bitxor(carry);
    }

    /// Two's complement negation.
    pub fn wrapping_neg(self) -> Self {
        return (!self)._wrapping_add_with_carry(Self::ZERO, true);
    }

    /// Wrapping addition.
    pub fn wrapping_add(self, rhs: Self) -> Self {
        return self._wrapping_add_with_carry(rhs, false);
    }

    /// Overflowing addition.
    pub fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let sum = self.wrapping_add(rhs.clone());
        let self_msb = self.msb();
        let rhs_msb = rhs.msb();
        let sum_msb = sum.clone().msb();
        let carry = (self_msb & rhs_msb) | ((self_msb ^ rhs_msb) & !sum_msb);
        return (sum, carry);
    }

    /// Wrapping subtraction.
    pub fn wrapping_sub(self, rhs: Self) -> Self {
        return self._wrapping_add_with_carry(rhs.not(), true);
    }

    /// Overflowing subtraction.
    pub fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let diff = self.wrapping_sub(rhs.clone());
        // Borrow: either lhs_msb == 0 and rhs_msb == 1, or lhs_msb == rhs_msb, and diff_msb == 1.
        let self_msb = self.msb();
        let rhs_msb = rhs.msb();
        let diff_msb = diff.msb();
        let borrow = (!self_msb & rhs_msb) | (!(self_msb ^ rhs_msb) & diff_msb);
        return (diff, borrow);
    }

    /// Wrapping multiplication.
    pub fn wrapping_mul(mut self, mut rhs: Self) -> Self {
        let mut acc = Self::ZERO;
        for _ in 0..W::WIDTH {
            let rhs_bit = rhs.clone().lsb();
            if rhs_bit {
                acc = acc.wrapping_add(self);
            }
            self = self << 1;
            rhs = rhs >> 1;
        }
        return acc;
    }

    /// Wide multiplication.
    pub fn wide_mul(self, mut rhs: Self) -> (Self, Self) {
        let mut acc_hi = Self::ZERO;
        let mut acc_lo = Self::ZERO;
        let mut add_hi = Self::ZERO;
        let mut add_lo = self;
        let mut add_hi_lo: Self;
        let mut carry: bool;
        for _ in 0..Self::WIDTH {
            let rhs_bit = rhs.clone().lsb();
            (acc_lo, carry) = acc_lo.overflowing_add(if rhs_bit { add_lo } else { Self::ZERO });
            acc_hi = acc_hi
                .wrapping_add(if rhs_bit { add_hi } else { Self::ZERO })
                .wrapping_add(Self::from_bool(carry));
            (add_lo, add_hi_lo) = add_lo.overflowing_shl(1);
            add_hi = (add_hi << 1).bitxor(add_hi_lo);
            rhs = rhs >> 1;
        }
        return (acc_lo, acc_hi);
    }

    /// Less than comparison.
    pub fn lt(self, rhs: Self) -> bool {
        let (_, borrow) = self.overflowing_sub(rhs);
        return borrow;
    }

    /// Greater than or equal comparison.
    pub fn ge(self, rhs: Self) -> bool {
        return !self.lt(rhs);
    }

    /// Less than or equal comparison.
    pub fn le(self, rhs: Self) -> bool {
        return !rhs.lt(self);
    }

    /// Greater than comparison.
    pub fn gt(self, rhs: Self) -> bool {
        return rhs.lt(self);
    }

    /// Equality comparison.
    pub fn eq(self, rhs: Self) -> bool {
        for i in 0..N {
            if self.le_words[i] != rhs.le_words[i] {
                return false;
            }
        }
        return true;
    }

    /// Inequality comparison.
    pub fn ne(self, rhs: Self) -> bool {
        return !self.eq(rhs);
    }

    /// Returns true if this composite word is equal to [CompositeWord::ZERO].
    pub fn is_zero(self) -> bool {
        return self.eq(Self::ZERO);
    }

    /// Returns true if this composite word is not equal to [CompositeWord::ZERO].
    pub fn is_nonzero(self) -> bool {
        return self.ne(Self::ZERO);
    }
}

impl<W: Word, const N: usize> WordLike<W, N> for CompositeWord<W, N> {
    #[inline]
    fn to_word(self) -> Self {
        return self;
    }

    #[inline]
    fn from_word(words: Self) -> Self {
        return words;
    }
}

impl<W: Word, const N: usize> Default for CompositeWord<W, N> {
    /// The default composite word is the all-zero word.
    #[inline]
    fn default() -> Self {
        return Self::ZERO;
    }
}

impl<W: Word, const N: usize> From<[W; N]> for CompositeWord<W, N> {
    /// Creates a composite word from an array of base words.
    #[inline]
    fn from(words: [W; N]) -> Self {
        return Self::from_le_words(words);
    }
}

impl<W: Word> CompositeWord<W, 1> {
    /// Unwraps a single-word composite word into the base word.
    #[inline]
    pub fn into(self) -> W {
        let [word] = self.le_words;
        return word;
    }
}

impl<W: Word> From<W> for CompositeWord<W, 1> {
    /// Creates a single-word composite word from a base word.
    #[inline]
    fn from(word: W) -> Self {
        return Self::from_le_words([word]);
    }
}

impl<W: Word, const N: usize> Not for CompositeWord<W, N> {
    type Output = Self;

    /// Bitwise NOT operation.
    #[inline]
    fn not(self) -> Self {
        return self.not();
    }
}

impl<W: Word, const N: usize> BitXor for CompositeWord<W, N> {
    type Output = Self;

    /// Bitwise XOR operation.
    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        return self.bitxor(rhs);
    }
}

impl<W: Word, const N: usize> BitAnd for CompositeWord<W, N> {
    type Output = Self;

    /// Bitwise AND operation.
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        return self.bitand(rhs);
    }
}

impl<W: Word, const N: usize> BitOr for CompositeWord<W, N> {
    type Output = Self;

    /// Bitwise OR operation.
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        return self.bitor(rhs);
    }
}

impl<W: Word, const N: usize> Shl<usize> for CompositeWord<W, N> {
    type Output = Self;

    /// Unbounded left shift operation, see [CompositeWord::unbounded_shl].
    #[inline]
    fn shl(self, rhs: usize) -> Self {
        return self.unbounded_shl(rhs);
    }
}

impl<W: Word, const N: usize> Shr<usize> for CompositeWord<W, N> {
    type Output = Self;

    /// Unbounded right shift operation, see [CompositeWord::unbounded_shr].
    #[inline]
    fn shr(self, rhs: usize) -> Self {
        return self.unbounded_shr(rhs);
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! _on_all_words {
    ($W: ident, $body: block) => {{
        {
            type $W = u8;
            $body;
        }
        #[cfg(feature = "u16")]
        {
            type $W = u16;
            $body;
        }
        #[cfg(feature = "u32")]
        {
            type $W = u32;
            $body;
        }
        #[cfg(feature = "u64")]
        {
            type $W = u64;
            $body;
        }
        #[cfg(feature = "u128")]
        {
            type $W = u128;
            $body;
        }
    }};
}

#[doc(inline)]
pub use _on_all_words as on_all_words;
