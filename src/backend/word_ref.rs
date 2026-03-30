// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of word references for generic ZKBoo backends.

use crate::{
    backend::{Backend, BooleanWordRef},
    utils::RcPtrMut,
    word::{CompositeWord, Word, WordIdx, WordLike},
};
use alloc::vec::Vec;
use core::ops::{
    AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul, MulAssign, Neg,
    Not, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use core::{array, ops::Add};

/// Reference to an allocated word in a generic backend.
#[derive(Debug)]
pub struct WordRef<B: Backend, W: Word, const N: usize = 1> {
    backend: RcPtrMut<B>,
    idx: WordIdx<W, N>,
}

impl<B: Backend, W: Word, const N: usize> WordRef<B, W, N> {
    /// Creates a new [WordRef] with the given backend and index.
    /// The reference count for the index in the backend is increased by 1.
    pub(super) fn new(backend: RcPtrMut<B>, idx: WordIdx<W, N>) -> Self {
        backend.borrow_mut().increase_refcount(idx);
        return Self { backend, idx };
    }

    /// Allocates a new input [WordRef] in the same backend as this [WordRef],
    /// initialized to the given word.
    pub(super) fn input<C: WordLike<W, N>>(backend: &RcPtrMut<B>, word: C) -> Self {
        let idx = backend.borrow_mut().input(word.to_word());
        return WordRef::new(backend.clone(), idx);
    }

    /// Allocates a new [WordRef] in the same backend as this [WordRef], without initialisation.
    pub(super) fn alloc(backend: &RcPtrMut<B>) -> Self {
        let idx = backend.borrow_mut().alloc();
        return WordRef::new(backend.clone(), idx);
    }

    /// Allocates a new [WordRef] in the same backend as this [WordRef],
    /// initialised to the given constant word.
    pub(super) fn alloc_constant<U: WordLike<W, N>>(backend: &RcPtrMut<B>, word: U) -> Self {
        let idx = backend.borrow_mut().alloc_constant(word.to_word());
        return WordRef::new(backend.clone(), idx);
    }

    /// Allocates a new [WordRef] in the same backend as this [WordRef],
    /// initialized to zero.
    fn alloc_zero(backend: &RcPtrMut<B>) -> Self {
        let idx = backend
            .borrow_mut()
            .alloc_constant(CompositeWord::<W, N>::ZERO);
        return WordRef::new(backend.clone(), idx);
    }

    /// The type-tagged index of the word in the memory manager.
    pub fn idx(&self) -> WordIdx<W, N> {
        self.idx
    }

    /// Destructures the [WordRef] into its memory manager and index.
    fn destructure(self) -> (RcPtrMut<B>, WordIdx<W, N>) {
        return (self.backend.clone(), self.idx);
    }

    /// Helper function for unary shift operations on [WordRef]s.
    fn unop_shift<F>(in_: WordRef<B, W, N>, shift: usize, op: F) -> WordRef<B, W, N>
    where
        F: Fn(&mut B, WordIdx<W, N>, usize, WordIdx<W, N>),
    {
        let (backend, in_) = in_.destructure();
        let out = Self::alloc(&backend);
        op(&mut backend.borrow_mut(), in_, shift, out.idx);
        return out;
    }

    /// Helper function for unary operations on [WordRef]s.
    fn unop<F>(in_: WordRef<B, W, N>, op: F) -> WordRef<B, W, N>
    where
        F: Fn(&mut B, WordIdx<W, N>, WordIdx<W, N>),
    {
        let (backend, in_) = in_.destructure();
        let out = Self::alloc(&backend);
        op(&mut backend.borrow_mut(), in_, out.idx);
        return out;
    }

    /// Helper function for binary operations on [WordRef]s.
    fn binop<F>(inl: WordRef<B, W, N>, inr: WordRef<B, W, N>, op: F) -> WordRef<B, W, N>
    where
        F: Fn(&mut B, WordIdx<W, N>, WordIdx<W, N>, WordIdx<W, N>),
    {
        let (backend, inl) = inl.destructure();
        let (backend_, inr) = inr.destructure();
        assert_eq!(
            backend, backend_,
            "Backends of both operands must be the same"
        );
        let out = Self::alloc(&backend);
        op(&mut backend.borrow_mut(), inl, inr, out.idx);
        return out;
    }

    /// Helper function for binary operations on [WordRef]s with a constant right-hand side.
    fn binop_const<F, RHS: WordLike<W, N>>(
        in_: WordRef<B, W, N>,
        rhs: RHS,
        op: F,
    ) -> WordRef<B, W, N>
    where
        F: Fn(&mut B, WordIdx<W, N>, CompositeWord<W, N>, WordIdx<W, N>),
    {
        let (backend, in_) = in_.destructure();
        let out = Self::alloc(&backend);
        op(&mut backend.borrow_mut(), in_, rhs.to_word(), out.idx);
        return out;
    }
}

impl<B: Backend, W: Word, const N: usize> Clone for WordRef<B, W, N> {
    /// Clones the [WordRef], increasing the reference count in the memory manager.
    fn clone(&self) -> Self {
        return WordRef::new(self.backend.clone(), self.idx);
    }
}

impl<B: Backend, W: Word, const N: usize> Drop for WordRef<B, W, N> {
    /// Drops the [WordRef], decreasing the reference count in the memory manager.
    fn drop(&mut self) {
        self.backend.borrow_mut().decrease_refcount(self.idx);
    }
}

impl<B: Backend, W: Word, const N: usize> WordRef<B, W, N> {
    const WIDTH: usize = W::WIDTH * N;
    const ZERO: CompositeWord<W, N> = CompositeWord::<W, N>::ZERO;
    const ONE: CompositeWord<W, N> = CompositeWord::<W, N>::ONE;
    const MAX: CompositeWord<W, N> = CompositeWord::<W, N>::MAX;

    /// Consumes this [WordRef] to return one set to zero, with the same word width.
    pub fn into_zero(self) -> Self {
        return self & Self::ZERO;
    }

    /// Consumes this [WordRef] to return one set to the given constant word,
    /// with the same word width.
    pub fn into_const_same_width(self, word: CompositeWord<W, N>) -> Self {
        return self.into_zero() ^ word;
    }

    /// Consumes this [WordRef] to return one set to the given machine word,
    /// possibly with different word width.
    pub fn into_const_word<V: Word>(self, word: V) -> WordRef<B, V, 1> {
        return self.lsw().into_zero().cast::<V>() ^ word;
    }

    /// Consumes this [WordRef] to return one set to the given composite word,
    /// possibly with different word width and length.
    pub fn into_const_composite_word<V: Word, const M: usize>(
        self,
        word: CompositeWord<V, M>,
    ) -> WordRef<B, V, M> {
        return self.lsw().into_zero().cast::<V>().tile() ^ word;
    }

    /// Consumes this [WordRef] to return one set to the given boolean value,
    /// with the same word width.
    pub fn into_const_bool(self, value: bool) -> BooleanWordRef<B> {
        return BooleanWordRef::new(self.into_const_word(value as u8));
    }

    /// Allocates a new [WordRef] with the same backend as this [WordRef],
    /// initialized to the given composite word.
    pub fn alloc_new_word<V: Word, const M: usize, U: WordLike<V, M>>(
        &self,
        word: U,
    ) -> WordRef<B, V, M> {
        return WordRef::alloc_constant(&self.backend, word.to_word());
    }

    /// Allocates a new [WordRef] with the same backend as this [WordRef],
    /// initialized to zero, with the given word width and length.
    pub fn alloc_new_zero<V: Word, const M: usize>(&self) -> WordRef<B, V, M> {
        return WordRef::alloc_zero(&self.backend);
    }

    /// Allocates a new [BooleanWordRef] with the same backend as this [WordRef].
    pub fn alloc_new_bool(&self, value: bool) -> BooleanWordRef<B> {
        return BooleanWordRef::new(WordRef::alloc_constant(&self.backend, value as u8));
    }

    /// Bitwise NOT operation.
    pub fn not(self) -> Self {
        return WordRef::unop(self, B::not);
    }

    /// Bitwise XOR operation.
    pub fn bitxor(self, rhs: Self) -> Self {
        return WordRef::binop(self, rhs, B::bitxor);
    }

    /// Bitwise XOR operation with a constant.
    pub fn bitxor_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> Self {
        return WordRef::binop_const(self, rhs, B::bitxor_const);
    }

    /// Bitwise AND operation.
    pub fn bitand(self, rhs: Self) -> Self {
        return WordRef::binop(self, rhs, B::bitand);
    }

    /// Bitwise AND operation with a constant.
    pub fn bitand_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> Self {
        return WordRef::binop_const(self, rhs, B::bitand_const);
    }

    /// Bitwise OR operation.
    pub fn bitor(self, rhs: Self) -> Self {
        return self.not().bitand(rhs.not()).not();
    }

    /// Bitwise OR operation with a constant.
    pub fn bitor_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> Self {
        return self.not().bitand_const(rhs.to_word().not()).not();
    }

    /// Left shift operation, where bits shifted out on the left are discarded
    /// and zero bits are shifted in on the right.
    pub fn unbounded_shl(self, shift: usize) -> Self {
        return WordRef::unop_shift(self, shift, Backend::unbounded_shl);
    }

    /// Right shift operation, where bits shifted out on the right are discarded
    /// and zero bits are shifted in on the left.
    pub fn unbounded_shr(self, shift: usize) -> Self {
        return WordRef::unop_shift(self, shift, Backend::unbounded_shr);
    }

    /// Rotate left operation.
    pub fn rotate_left(self, shift: usize) -> Self {
        return WordRef::unop_shift(self, shift, Backend::rotate_left);
    }

    /// Rotate right operation.
    pub fn rotate_right(self, shift: usize) -> Self {
        return WordRef::unop_shift(self, shift, Backend::rotate_right);
    }

    /// Overflowing left shift operation, which returns the shifted result and
    /// the bits shifted out on the left for an additional word width.
    pub fn overflowing_shl(self, shift: usize) -> (Self, Self) {
        if shift >= 2 * Self::WIDTH {
            let lo = WordRef::alloc_zero(&self.backend);
            let hi = WordRef::alloc_zero(&self.backend);
            return (lo, hi);
        }
        if shift >= Self::WIDTH {
            let lo = WordRef::alloc_zero(&self.backend);
            let hi = self << (shift - Self::WIDTH);
            return (lo, hi);
        }
        let pieces = self.rotate_left(shift);
        let mask_lo = Self::MAX << shift;
        let mask_hi = !mask_lo;
        return (pieces.clone() & mask_lo, pieces & mask_hi);
    }

    /// Reverse bits operation.
    pub fn reverse_bits(self) -> Self {
        return WordRef::unop(self, Backend::reverse_bits);
    }

    /// Swap bytes operation.
    pub fn swap_bytes(self) -> Self {
        return WordRef::unop(self, Backend::swap_bytes);
    }

    /// Returns the least significant word.
    pub fn lsw(self) -> WordRef<B, W, 1> {
        return self.into_le_words().into_iter().next().unwrap();
    }

    /// Returns the most significant word.
    pub fn msw(self) -> WordRef<B, W, 1> {
        return self.into_le_words().into_iter().last().unwrap();
    }

    /// Returns the word at the given index, where the least significant word is at index 0.
    /// If the index is out of bounds, returns a zero word.
    pub fn word_at(self, idx: usize) -> WordRef<B, W, 1> {
        let backend = self.backend.clone();
        return self
            .into_le_words()
            .into_iter()
            .nth(idx)
            .unwrap_or_else(|| WordRef::alloc_zero(&backend));
    }

    /// Returns the boolean value of the least significant bit in this word.
    pub fn lsb(self) -> BooleanWordRef<B> {
        return BooleanWordRef::new(self.lsw().cast() & 1u8);
    }

    /// Returns the boolean value of the most significant bit in this word.
    pub fn msb(self) -> BooleanWordRef<B> {
        return BooleanWordRef::new(((self.msw() >> (W::WIDTH - 1)) & W::ONE).cast());
    }

    /// Returns the boolean value of the bit at the given index in this word,
    /// where 0 is the least significant bit.
    pub fn bit_at(self, idx: usize) -> BooleanWordRef<B> {
        let word_idx = idx / W::WIDTH;
        let bit_idx = idx % W::WIDTH;
        return BooleanWordRef::new(((self.word_at(word_idx) >> bit_idx) & W::ONE).cast());
    }

    /// Consumes this [WordRef] and applies the given function to each bit in this word,
    /// from least significant to most significant.
    pub fn map_bits<F: FnMut(BooleanWordRef<B>)>(self, mut f: F) {
        for i in 0..Self::WIDTH {
            f(self.clone().bit_at(i));
        }
    }

    /// Creates a boolean mask from the given input boolean word,
    /// The mask bits are all set to the same value:
    ///
    /// - 0 if the input word is zero
    /// - 1 if the input word is non-zero
    pub fn mask(bool: BooleanWordRef<B>) -> WordRef<B, W, N> {
        let bool = bool.into();
        let mut res = bool.clone();
        // Fill one byte [8 * (SHL + XOR)]:
        for _ in 0..7 {
            res = (res << 1) ^ bool.clone();
        }
        return res.tile();
    }

    /// Creates a [WordRef] where all bits are set to zero except the least significant bit,
    /// which is set to the given boolean value.
    pub fn from_bool(bool: BooleanWordRef<B>) -> Self {
        return bool.select_const_const(Self::ONE, Self::ZERO);
    }

    /// Creates a [WordRef] from an array of [WordRef]s representing the little-endian words.
    pub fn from_le_words(refs: [WordRef<B, W, 1>; N]) -> WordRef<B, W, N> {
        assert!(N > 0, "N must be greater than 0");
        let backend = refs[0].backend.clone();
        for word_ref in refs.iter() {
            assert_eq!(
                word_ref.backend, backend,
                "All WordRefs must have the same backend"
            );
        }
        let ins = refs.map(|word_ref| word_ref.idx.into());
        let out = WordRef::alloc(&backend);
        backend.borrow_mut().from_le_words(ins, out.idx);
        return out;
    }

    /// Unpacks this [WordRef] into an array of [WordRef]s representing the little-endian words.
    pub fn into_le_words(self) -> [WordRef<B, W, 1>; N] {
        let backend = self.backend.clone();
        let in_ = self.idx;
        let outs: [_; N] = array::from_fn(|_| WordRef::<B, W, 1>::alloc(&backend));
        backend
            .borrow_mut()
            .to_le_words(in_, array::from_fn(|i| outs[i].idx));
        return outs;
    }
}

impl<B: Backend, W: Word, const N: usize> WordRef<B, W, N> {
    /// Simple carry calculation, with fixed carry-in and no carry-out.
    pub fn carry(self, g: Self, carry_in: bool) -> Self {
        let (backend, in_idx) = self.destructure();
        let out = WordRef::alloc(&backend);
        backend.borrow_mut().carry(in_idx, g.idx, carry_in, out.idx);
        return out;
    }

    /// Wrapping addition (with fixed initial carry).
    fn _wrapping_add_with_carry(self, rhs: Self, carry: bool) -> Self {
        let p = self.clone().bitxor(rhs.clone());
        let g = self.bitand(rhs);
        let carry = p.clone().carry(g, carry);
        return p.bitxor(carry);
    }

    /// Wrapping addition with a constant (with fixed initial carry).
    fn _wrapping_add_with_carry_const<RHS: WordLike<W, N>>(self, rhs: RHS, carry: bool) -> Self {
        let p = self.clone().bitxor_const(rhs);
        let g = self.bitand_const(rhs);
        let carry = p.clone().carry(g, carry);
        return p.bitxor(carry);
    }

    /// Two's complement negation.
    pub fn wrapping_neg(self) -> Self {
        return (!self)._wrapping_add_with_carry_const(Self::ZERO, true);
    }

    /// Wrapping addition.
    pub fn wrapping_add(self, rhs: Self) -> Self {
        return self._wrapping_add_with_carry(rhs, false);
    }

    /// Wrapping addition with a constant.
    pub fn wrapping_add_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> Self {
        return self._wrapping_add_with_carry_const(rhs, false);
    }

    /// Overflowing addition.
    pub fn overflowing_add(self, rhs: Self) -> (Self, BooleanWordRef<B>) {
        let sum = self.clone().wrapping_add(rhs.clone());
        let self_msb = self.msb();
        let rhs_msb = rhs.msb();
        let sum_msb = sum.clone().msb();
        let carry = (self_msb.clone() & rhs_msb.clone()) | ((self_msb ^ rhs_msb) & !sum_msb);
        return (sum, carry);
    }

    /// Overflowing addition with a constant.
    pub fn overflowing_add_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> (Self, BooleanWordRef<B>) {
        let rhs = rhs.to_word();
        let sum = self.clone().wrapping_add_const(rhs.clone());
        let self_msb = self.msb();
        let rhs_msb = rhs.msb();
        let sum_msb = sum.clone().msb();
        let carry = (self_msb.clone() & rhs_msb.clone()) | ((self_msb ^ rhs_msb) & !sum_msb);
        return (sum, carry);
    }

    /// Wrapping subtraction.
    pub fn wrapping_sub(self, rhs: Self) -> Self {
        return self._wrapping_add_with_carry(rhs.not(), true);
    }

    /// Wrapping subtraction.
    pub fn wrapping_sub_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> Self {
        let rhs = rhs.to_word();
        return self._wrapping_add_with_carry_const(!rhs, true);
    }

    /// Wrapping subtraction with borrow flag.
    pub fn overflowing_sub(self, rhs: Self) -> (Self, BooleanWordRef<B>) {
        let diff = self.clone().wrapping_sub(rhs.clone());
        // Borrow: either lhs_msb == 0 and rhs_msb == 1, or lhs_msb == rhs_msb, and diff_msb == 1.
        let self_msb = self.msb();
        let rhs_msb = rhs.msb();
        let diff_msb = diff.clone().msb();
        let borrow = (!self_msb.clone() & rhs_msb.clone()) | (!(self_msb ^ rhs_msb) & diff_msb);
        return (diff, borrow);
    }

    /// Wrapping subtraction with borrow flag and constant RHS.
    pub fn overflowing_sub_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> (Self, BooleanWordRef<B>) {
        let rhs = rhs.to_word();
        let diff = self.clone() - rhs;
        // Borrow: either lhs_msb == 0 and rhs_msb == 1, or lhs_msb == rhs_msb, and diff_msb == 1.
        let self_msb = self.msb();
        let rhs_msb = rhs.msb();
        let diff_msb = diff.clone().msb();
        let borrow = (!self_msb.clone() & rhs_msb.clone()) | (!(self_msb ^ rhs_msb) & diff_msb);
        return (diff, borrow);
    }

    /// Wrapping subtraction with borrow flag and constant LHS.
    pub fn overflowing_sub_from_const<RHS: WordLike<W, N>>(
        self,
        rhs: RHS,
    ) -> (Self, BooleanWordRef<B>) {
        let rhs = rhs.to_word();
        let diff = self.clone().wrapping_neg().wrapping_add_const(rhs);
        // Borrow: either lhs_msb == 0 and rhs_msb == 1, or lhs_msb == rhs_msb, and diff_msb == 1.
        let self_msb = self.msb();
        let rhs_msb = rhs.msb();
        let diff_msb = diff.clone().msb();
        let borrow = (self_msb.clone() & !rhs_msb.clone()) | (!(self_msb ^ rhs_msb) & diff_msb);
        return (diff, borrow);
    }

    /// Wrapping multiplication.
    pub fn wrapping_mul(mut self, mut rhs: Self) -> Self {
        let mut acc = WordRef::alloc_zero(&self.backend);
        for _ in 0..W::WIDTH {
            let rhs_bit = rhs.clone().lsb();
            acc = acc.wrapping_add(rhs_bit.select_var_const(self.clone(), Self::ZERO));
            self = self << 1;
            rhs = rhs >> 1;
        }
        return acc;
    }

    /// Wrapping multiplication with a constant.
    pub fn wrapping_mul_const<RHS: WordLike<W, N>>(mut self, rhs: RHS) -> Self {
        let mut rhs = rhs.to_word();
        let mut acc = WordRef::alloc_zero(&self.backend);
        for _ in 0..W::WIDTH {
            if rhs.lsb() {
                acc = acc.wrapping_add(self.clone());
            }
            self = self << 1;
            rhs = rhs >> 1;
        }
        return acc;
    }

    /// Wide multiplication.
    pub fn wide_mul(self, mut rhs: Self) -> (Self, Self) {
        let mut acc_hi = WordRef::alloc_zero(&self.backend);
        let mut acc_lo = WordRef::alloc_zero(&self.backend);
        let mut add_hi = WordRef::alloc_zero(&self.backend);
        let mut add_lo = self;
        let mut add_hi_lo: Self;
        let mut carry: BooleanWordRef<B>;
        for _ in 0..Self::WIDTH {
            let rhs_bit = rhs.clone().lsb();
            (acc_lo, carry) = acc_lo
                .overflowing_add(rhs_bit.clone().select_var_const(add_lo.clone(), Self::ZERO));
            acc_hi = acc_hi
                .wrapping_add(rhs_bit.select_var_const(add_hi.clone(), Self::ZERO))
                .wrapping_add(Self::from_bool(carry));
            (add_lo, add_hi_lo) = add_lo.overflowing_shl(1);
            add_hi = (add_hi << 1).bitxor(add_hi_lo);
            rhs = rhs >> 1;
        }
        return (acc_lo, acc_hi);
    }

    /// Carrying multiplication with constant rhs.
    pub fn wide_mul_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> (Self, Self) {
        let mut rhs = rhs.to_word();
        let mut acc_hi = WordRef::alloc_zero(&self.backend);
        let mut acc_lo = WordRef::alloc_zero(&self.backend);
        let mut add_hi = WordRef::alloc_zero(&self.backend);
        let mut add_lo = self;
        let mut add_hi_lo: Self;
        let mut carry: BooleanWordRef<B>;
        for _ in 0..Self::WIDTH {
            if rhs.lsb() {
                (acc_lo, carry) = acc_lo.overflowing_add(add_lo.clone());
                acc_hi = acc_hi.wrapping_add(add_hi.clone().wrapping_add(Self::from_bool(carry)));
            }
            (add_lo, add_hi_lo) = add_lo.overflowing_shl(1);
            add_hi = (add_hi << 1).bitxor(add_hi_lo);
            rhs = rhs >> 1;
        }
        return (acc_lo, acc_hi);
    }

    /// Less than comparison.
    pub fn lt(self, rhs: Self) -> BooleanWordRef<B> {
        let (_, borrow) = self.overflowing_sub(rhs);
        return borrow;
    }

    /// Greater than or equal comparison.
    pub fn ge(self, rhs: Self) -> BooleanWordRef<B> {
        return !self.lt(rhs);
    }

    /// Less than or equal comparison.
    pub fn le(self, rhs: Self) -> BooleanWordRef<B> {
        return !rhs.lt(self);
    }

    /// Greater than comparison.
    pub fn gt(self, rhs: Self) -> BooleanWordRef<B> {
        return rhs.lt(self);
    }

    /// Less than comparison with a constant.
    pub fn lt_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> BooleanWordRef<B> {
        let (_, borrow) = self.overflowing_sub_const(rhs);
        return borrow;
    }

    /// Greater than or equal comparison with a constant.
    pub fn ge_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> BooleanWordRef<B> {
        return !self.lt_const(rhs);
    }

    /// Less than or equal comparison with a constant.
    pub fn le_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> BooleanWordRef<B> {
        return !self.gt_const(rhs);
    }

    /// Greater than comparison with a constant.
    pub fn gt_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> BooleanWordRef<B> {
        let (_, borrow) = self.overflowing_sub_from_const(rhs);
        return borrow;
    }

    /// Non-zero check operation.
    pub fn is_nonzero(self) -> BooleanWordRef<B> {
        return (self.clone() | -self).msb();
    }

    /// Zero check operation.
    pub fn is_zero(self) -> BooleanWordRef<B> {
        return !self.is_nonzero();
    }

    /// Negative equality comparison.
    pub fn ne(self, rhs: Self) -> BooleanWordRef<B> {
        return (self ^ rhs).is_nonzero();
    }

    /// Equality comparison.
    pub fn eq(self, rhs: Self) -> BooleanWordRef<B> {
        return !self.ne(rhs);
    }

    /// Negative equality comparison with a constant.
    pub fn ne_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> BooleanWordRef<B> {
        return (self ^ rhs).is_nonzero();
    }

    /// Equality comparison with a constant.
    pub fn eq_const<RHS: WordLike<W, N>>(self, rhs: RHS) -> BooleanWordRef<B> {
        return !self.ne_const(rhs);
    }
}

impl<B: Backend, W: Word> WordRef<B, W, 1> {
    /// Tiles this word into a larger target word size.
    ///
    /// If the target word size is smaller, this behaves as a [WordRef::cast] instead.
    /// If the target word size is the same as this word size, the result is the same as this word.
    ///
    pub fn tile<U: Word, const M: usize>(self) -> WordRef<B, U, M> {
        // Presumes (correctly) that word sizes come in powers of two.
        let mut res: WordRef<B, U, 1> = self.cast();
        let mut width = W::WIDTH;
        while width < U::WIDTH {
            res = (res.clone() << width) ^ res;
            width *= 2;
        }
        return WordRef::from_le_words(array::from_fn(|_| res.clone()));
    }

    /// Cast to another [Word] type.
    pub fn cast<T: Word>(self) -> WordRef<B, T, 1> {
        let (backend, in_idx) = self.destructure();
        let out = WordRef::alloc(&backend);
        backend.borrow_mut().cast::<W, T>(in_idx, out.idx);
        return out;
    }

    /// Converts a word to a big-endian byte array.
    pub fn into_le_bytes(mut self) -> Vec<WordRef<B, u8, 1>> {
        let mut res = Vec::new();
        for _ in 0..(W::WIDTH / 8) {
            res.push(self.clone().cast());
            self >>= 8;
        }
        return res;
    }

    /// Converts a word to a little-endian byte array.
    pub fn into_be_bytes(self) -> Vec<WordRef<B, u8, 1>> {
        return self.into_le_bytes().into_iter().rev().collect();
    }

    /// Converts a big-endian byte array to a word of given type.
    pub fn from_be_bytes(
        bytes: Vec<WordRef<B, u8, 1>>,
    ) -> Result<WordRef<B, W, 1>, Vec<WordRef<B, u8, 1>>> {
        if bytes.len() * 8 != W::WIDTH as usize {
            return Err(bytes);
        }
        let mut it = bytes.into_iter();
        let mut res: WordRef<B, W, 1> = it.next().unwrap().cast();
        for b in it {
            res <<= 8;
            res ^= b.cast();
        }
        return Ok(res);
    }

    /// Converts a little-endian byte array to a word of given type.
    pub fn from_le_bytes(
        bytes: Vec<WordRef<B, u8, 1>>,
    ) -> Result<WordRef<B, W, 1>, Vec<WordRef<B, u8, 1>>> {
        return Self::from_be_bytes(bytes.into_iter().rev().collect());
    }
}

impl<B: Backend, W: Word, const N: usize> Not for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Bitwise NOT operation.
    fn not(self) -> Self::Output {
        return self.not();
    }
}

impl<B: Backend, W: Word, const N: usize> BitXor for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Bitwise XOR operation.
    fn bitxor(self, rhs: Self) -> Self::Output {
        return self.bitxor(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize> BitXorAssign for WordRef<B, W, N> {
    /// Bitwise XOR assignment operation.
    fn bitxor_assign(&mut self, rhs: Self) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this ^ rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> BitXor<RHS> for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Bitwise XOR operation with a constant.
    fn bitxor(self, rhs: RHS) -> Self::Output {
        return self.bitxor_const(rhs.to_word());
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> BitXorAssign<RHS>
    for WordRef<B, W, N>
{
    /// Bitwise XOR assignment operation with a constant.
    fn bitxor_assign(&mut self, rhs: RHS) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this ^ rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize> BitAnd for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Bitwise AND operation.
    fn bitand(self, rhs: Self) -> Self::Output {
        return self.bitand(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize> BitAndAssign for WordRef<B, W, N> {
    /// Bitwise AND assignment operation.
    fn bitand_assign(&mut self, rhs: Self) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this & rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> BitAnd<RHS> for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Bitwise AND operation with a constant.
    fn bitand(self, rhs: RHS) -> Self::Output {
        return self.bitand_const(rhs.to_word());
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> BitAndAssign<RHS>
    for WordRef<B, W, N>
{
    /// Bitwise AND assignment operation with a constant.
    fn bitand_assign(&mut self, rhs: RHS) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this & rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize> BitOr for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Bitwise OR operation.
    fn bitor(self, rhs: Self) -> Self::Output {
        return self.bitor(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize> BitOrAssign for WordRef<B, W, N> {
    /// Bitwise OR assignment operation.
    fn bitor_assign(&mut self, rhs: Self) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this | rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> BitOr<RHS> for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Bitwise OR operation with a constant.
    fn bitor(self, rhs: RHS) -> Self::Output {
        return self.bitor_const(rhs.to_word());
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> BitOrAssign<RHS>
    for WordRef<B, W, N>
{
    /// Bitwise OR assignment operation with a constant.
    fn bitor_assign(&mut self, rhs: RHS) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this | rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize> Shl<usize> for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Checked left shift operation.
    fn shl(self, shift: usize) -> Self::Output {
        return self.unbounded_shl(shift);
    }
}

impl<B: Backend, W: Word, const N: usize> ShlAssign<usize> for WordRef<B, W, N> {
    /// Checked left shift assignment operation.
    fn shl_assign(&mut self, shift: usize) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this.unbounded_shl(shift)) }
    }
}

impl<B: Backend, W: Word, const N: usize> Shr<usize> for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Checked right shift operation.
    fn shr(self, shift: usize) -> Self::Output {
        return self.unbounded_shr(shift);
    }
}

impl<B: Backend, W: Word, const N: usize> ShrAssign<usize> for WordRef<B, W, N> {
    /// Checked right shift assignment operation.
    fn shr_assign(&mut self, shift: usize) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this.unbounded_shr(shift)) }
    }
}

impl<B: Backend, W: Word, const N: usize> Add for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Wrapping addition.
    fn add(self, rhs: Self) -> Self::Output {
        return self.wrapping_add(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize> AddAssign for WordRef<B, W, N> {
    /// Wrapping addition assignment.
    fn add_assign(&mut self, rhs: Self) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this + rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> Add<RHS> for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Wrapping addition with a constant.
    fn add(self, rhs: RHS) -> Self::Output {
        return self.wrapping_add_const(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> AddAssign<RHS> for WordRef<B, W, N> {
    /// Wrapping addition assignment with a constant.
    fn add_assign(&mut self, rhs: RHS) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this + rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize> Neg for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Two's complement negation.
    fn neg(self) -> Self::Output {
        return self.wrapping_neg();
    }
}

impl<B: Backend, W: Word, const N: usize> Sub for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Wrapping subtraction.
    fn sub(self, rhs: Self) -> Self::Output {
        return self.wrapping_sub(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize> SubAssign for WordRef<B, W, N> {
    /// Wrapping subtraction assignment.
    fn sub_assign(&mut self, rhs: Self) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this - rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> Sub<RHS> for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Wrapping subtraction with a constant.
    fn sub(self, rhs: RHS) -> Self::Output {
        return self.wrapping_sub_const(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> SubAssign<RHS> for WordRef<B, W, N> {
    /// Wrapping subtraction assignment with a constant.
    fn sub_assign(&mut self, rhs: RHS) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this - rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize> Mul for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Wrapping multiplication.
    fn mul(self, rhs: Self) -> Self::Output {
        return self.wrapping_mul(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize> MulAssign for WordRef<B, W, N> {
    /// Wrapping multiplication assignment.
    fn mul_assign(&mut self, rhs: Self) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this * rhs) }
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> Mul<RHS> for WordRef<B, W, N> {
    type Output = WordRef<B, W, N>;
    /// Wrapping multiplication with a constant.
    fn mul(self, rhs: RHS) -> Self::Output {
        return self.wrapping_mul_const(rhs);
    }
}

impl<B: Backend, W: Word, const N: usize, RHS: WordLike<W, N>> MulAssign<RHS> for WordRef<B, W, N> {
    /// Wrapping multiplication assignment with a constant.
    fn mul_assign(&mut self, rhs: RHS) {
        let this = unsafe { core::ptr::read(self) };
        unsafe { core::ptr::write(self, this * rhs) }
    }
}
