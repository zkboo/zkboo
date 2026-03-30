// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the execution backend for ZKBoo circuits.

use crate::{
    backend::{Backend, Frontend},
    executor::word_pool::WordPool,
    word::{CompositeWord, Word, WordIdx, Words},
};

/// Execution backend for ZKBoo circuits.
#[derive(Debug)]
pub struct ExecutionBackend<WP: WordPool> {
    state: WP,
    outputs: Words,
}

impl<WP: WordPool> ExecutionBackend<WP> {
    /// Create a new execution backend using the given [WordPool].
    pub fn new() -> Self {
        return Self {
            state: WP::default(),
            outputs: Words::new(),
        };
    }

    /// Wraps this execution backend into a [Frontend].
    ///
    /// Alias of [Backend::into_frontend].
    pub fn into_executor(self) -> Frontend<Self> {
        return self.into_frontend();
    }

    /// Helper function to perform a unary operation on a word.
    fn unop<W: Word, const N: usize, F: Fn(CompositeWord<W, N>) -> CompositeWord<W, N>>(
        &mut self,
        in_: WordIdx<W, N>,
        out: WordIdx<W, N>,
        op: F,
    ) {
        self.state.write(out, op(self.state.read(in_)));
    }

    /// Helper function to perform a binary operation on two words.
    fn binop<
        W: Word,
        const N: usize,
        F: Fn(CompositeWord<W, N>, CompositeWord<W, N>) -> CompositeWord<W, N>,
    >(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
        op: F,
    ) {
        self.state
            .write(out, op(self.state.read(inl), self.state.read(inr)));
    }

    /// Helper function to perform a binary operation on a word and a constant.
    fn binop_const<
        W: Word,
        const N: usize,
        F: Fn(CompositeWord<W, N>, CompositeWord<W, N>) -> CompositeWord<W, N>,
    >(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
        op: F,
    ) {
        self.state.write(out, op(self.state.read(inl), inr));
    }
}

impl<WP: WordPool> Backend for ExecutionBackend<WP> {
    type FinalizeArg = ();
    type FinalizeResult = Words;

    fn finalize(self, _arg: Self::FinalizeArg) -> Words {
        return self.outputs;
    }

    fn input<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) -> WordIdx<W, N> {
        let idx = self.state.alloc::<W, N>();
        self.state.write(idx, word);
        return idx;
    }

    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N> {
        return self.state.alloc::<W, N>();
    }

    fn constant<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>, out: WordIdx<W, N>) {
        self.state.write(out, word);
    }

    fn output<W: Word, const N: usize>(&mut self, out: WordIdx<W, N>) {
        let word = self.state.read(out);
        self.outputs.as_vec_mut().extend(word.to_le_words());
    }

    fn from_le_words<W: Word, const N: usize>(
        &mut self,
        ins: [WordIdx<W, 1>; N],
        out: WordIdx<W, N>,
    ) {
        let ins = ins.map(|idx| self.state.read(idx).into());
        self.state.write(out, CompositeWord::from_le_words(ins));
    }

    fn to_le_words<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        outs: [WordIdx<W, 1>; N],
    ) {
        let in_ = self.state.read(in_);
        let out_words = in_.to_le_words();
        for (out, word) in outs.into_iter().zip(out_words.into_iter()) {
            self.state.write(out, word.into());
        }
    }

    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.state.increase_refcount(idx);
    }

    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.state.decrease_refcount(idx);
    }

    fn not<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.unop(in_, out, |in_| !in_);
    }

    fn bitxor<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.binop(inl, inr, out, |inl, inr| inl ^ inr);
    }

    fn bitand<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.binop(inl, inr, out, |inl, inr| inl & inr);
    }

    fn bitxor_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.binop_const(inl, inr, out, |inl, inr| inl ^ inr);
    }

    fn bitand_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.binop_const(inl, inr, out, |inl, inr| inl & inr);
    }

    fn unbounded_shl<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.unop(in_, out, |in_| in_.unbounded_shl(shift));
    }

    fn unbounded_shr<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.unop(in_, out, |in_| in_.unbounded_shr(shift));
    }

    fn rotate_left<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.unop(in_, out, |in_| in_.rotate_left(shift));
    }

    fn rotate_right<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.unop(in_, out, |in_| in_.rotate_right(shift));
    }

    fn reverse_bits<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.unop(in_, out, |in_| in_.reverse_bits());
    }

    fn swap_bytes<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.unop(in_, out, |in_| in_.swap_bytes());
    }

    fn cast<W: Word, T: Word>(&mut self, in_: WordIdx<W, 1>, out: WordIdx<T, 1>) {
        self.state
            .write(out, T::cast_from(self.state.read(in_).into()).into());
    }

    fn carry<W: Word, const N: usize>(
        &mut self,
        p: WordIdx<W, N>,
        g: WordIdx<W, N>,
        carry_in: bool,
        out: WordIdx<W, N>,
    ) {
        let p = self.state.read(p); // carry propagator
        let g = self.state.read(g); // carry generator
        let mut carry = CompositeWord::<W, N>::ZERO;
        let mut mask = CompositeWord::<W, N>::ONE;
        let mut c = CompositeWord::<W, N>::from_bool(carry_in);
        // Note: mask and c have 1 bit set
        // and are kept aligned by shifts.
        // carry     = 0........00
        // mask      = 0........01
        // c         = 0........00
        // bit pos               ^
        for _ in 0..CompositeWord::<W, N>::WIDTH {
            // carry = 0..000?..?0
            // mask  = 0..0010..00
            // c     = 0..00x0..00
            // bit pos      ^
            carry = carry ^ c;
            // carry = 0..00x?..?0
            // mask  = 0..0010..00
            // c     = 0..00x0..00
            // bit pos      ^
            c = c & p; // c & (mask & p)
            c = c ^ (mask & g);
            // carry = 0..00x?..?0
            // mask  = 0..0010..00
            // c     = 0..00y0..00
            // bit pos      ^
            c = c << 1;
            mask = mask << 1;
            // carry = 0..00x?..?0
            // mask  = 0..0100..00
            // c     = 0..0y00..00
            // bit pos     ^
        }
        self.state.write(out, carry);
    }
}
