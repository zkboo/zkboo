// SPDX-License-Identifier: LGPL-3.0-or-later

//! Trait for ZKBoo backends.

use crate::{
    backend::Frontend,
    word::{CompositeWord, Word, WordIdx},
};
use core::fmt::Debug;

/// Trait for a backend that can execute generic circuit operations.
///
/// Implementers of this trait should not be user-facing;
/// instead, [Backend]s will be wrapped into a [Frontend], via [Backend::into_frontend].
///
/// Note that all word indices used by operations this trait are type-tagged.
/// The following invariants are guaranteed if the lifecycle described above is adhered to:
///
/// - A [WordIdx] passed to the methods of a [Backend] instance has been obtained from that instance
///   via [Backend::alloc], [Backend::input], or by cloning a [WordRef](super::WordRef).
/// - A [WordIdx] passed to the methods of a [Backend] instance either has positive reference
///   count, or it has reference count zero and because the corresponding word has been dropped
///   as part of the current operation (making the index available for reuse in the same operation).
/// - The implementation of [WordRef](super::WordRef) calls [Backend::increase_refcount] on creation
///   and [Backend::decrease_refcount] on drop, ensuring that word index refcounts exactly match
///   the number of live [WordRef](super::WordRef) instances pointing to them.
///
/// Implementations of [Backend::alloc], [Backend::increase_refcount], [Backend::decrease_refcount]
/// must in turn guarantee that the internal reference counts for all wrapped indices are set to 0,
/// increased by 1 and decreased by 1 respectively, and that indices with zero reference count.
pub trait Backend: Sized + Debug {
    /// Type for data to be passed to the backend finalizer.
    type FinalizeArg;

    /// Type for the finalization result of the backend.
    type FinalizeResult;

    /// Finalizes the backend, returning a finalization result.
    fn finalize(self, arg: Self::FinalizeArg) -> Self::FinalizeResult;

    /// Wraps this backend into a [Frontend].
    fn into_frontend(self) -> Frontend<Self> {
        return Frontend::wrap(self);
    }

    /// Allocates an input word in the backend, returning the allocated index.
    ///
    /// Note: Allocation of input words is handled separately from allocation of intermediate values
    /// because the randomness from which the zero-knowledge property of ZKBoo proofs is derived
    /// is injected into the computation at the point of input allocation.
    fn input<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) -> WordIdx<W, N>;

    /// Allocates a word in the backend, returning the allocated index.
    /// ⚠️ Warning: the word value is uninitialised.
    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N>;

    /// Writes a constant word to the given index.
    fn constant<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>, out: WordIdx<W, N>);

    /// Allocates a constant work in the backend, returning the allocated index.
    fn alloc_constant<W: Word, const N: usize>(
        &mut self,
        word: CompositeWord<W, N>,
    ) -> WordIdx<W, N> {
        let idx = self.alloc();
        self.constant(word, idx);
        return idx;
    }

    /// Packs a little-endian array of machine words into a single composite word,
    /// storing the result at the given output index.
    fn from_le_words<W: Word, const N: usize>(
        &mut self,
        ins: [WordIdx<W, 1>; N],
        out: WordIdx<W, N>,
    );

    /// Unpacks a composite word into a little-endian array of machine words,
    /// storing the result at the given output indices.
    fn to_le_words<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        outs: [WordIdx<W, 1>; N],
    );

    /// Pushes the given word onto the outputs.
    fn output<W: Word, const N: usize>(&mut self, out: WordIdx<W, N>);

    /// Increases the reference count of the word at the given index.
    /// The token parameter restricts this method from external use.
    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Decreases the reference count of the word at the given index.
    /// The token parameter restricts this method from external use.
    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Performs a bitwise NOT operation on the word at the given input index,
    /// storing the result at the given output index.
    fn not<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>);

    /// Performs a bitwise XOR operation on the words at the given input indices,
    /// storing the result at the given output index.
    fn bitxor<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    );

    /// Performs a bitwise AND operation on the words at the given input indices,
    /// storing the result at the given output index.
    fn bitand<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    );

    /// Performs a bitwise XOR operation on the word at the given input index with given constant,
    /// storing the result at the given output index.
    fn bitxor_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    );

    /// Performs a bitwise AND operation on the word at the given input index with given constant,
    /// storing the result at the given output index.
    fn bitand_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    );

    /// Performs a left shift operation on the word at the given input index,
    /// storing the result at the given output index.
    fn unbounded_shl<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    );

    /// Performs a right shift operation on the word at the given input index,
    /// storing the result at the given output index.
    fn unbounded_shr<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    );

    /// Performs a left rotate operation on the word at the given input index,
    /// storing the result at the given output index.
    fn rotate_left<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    );

    /// Performs a right rotate operation on the word at the given input index,
    /// storing the result at the given output index.
    fn rotate_right<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    );

    /// Performs a bit-reversal operation on the word at the given input index,
    /// storing the result at the given output index.
    fn reverse_bits<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>);

    /// Performs a byte-reversal operation on the word at the given input index,
    /// storing the result at the given output index.
    fn swap_bytes<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>);

    /// Casts the word at the given input index to another word type,
    /// storing the result at the given output index.
    fn cast<W: Word, T: Word>(&mut self, in_: WordIdx<W, 1>, out: WordIdx<T, 1>);

    /// Computes the carry bits from the given propagate and generate words,
    /// storing the result at the given output index.
    ///
    /// The carry-in bit is provided as a boolean argument, and no carry-out bit is produced.
    ///
    /// See [Word::carry](crate::word::Word::carry) for an implementation on word values.
    fn carry<W: Word, const N: usize>(
        &mut self,
        p: WordIdx<W, N>,
        g: WordIdx<W, N>,
        carry_in: bool,
        out: WordIdx<W, N>,
    );
}
