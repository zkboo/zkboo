// SPDX-License-Identifier: LGPL-3.0-or-later

//! Composable, zero-cost per-operation hooks over a [Backend].

use crate::{
    backend::Backend,
    word::{CompositeWord, Word, WordIdx},
};
use core::fmt::{self, Debug};

/// Per-operation pre/post hooks over a [Backend].
pub trait BackendHook {
    /// Init argument from which a fresh hook is built for each backend instance.
    type InitArg: Copy + Debug;

    /// Builds a fresh hook from the given init argument.
    fn new(arg: Self::InitArg) -> Self;

    #[inline(always)]
    fn pre_input(&mut self) {}
    #[inline(always)]
    fn post_input(&mut self) {}
    #[inline(always)]
    fn pre_alloc(&mut self) {}
    #[inline(always)]
    fn post_alloc(&mut self) {}
    #[inline(always)]
    fn pre_constant(&mut self) {}
    #[inline(always)]
    fn post_constant(&mut self) {}
    #[inline(always)]
    fn pre_from_le_words(&mut self) {}
    #[inline(always)]
    fn post_from_le_words(&mut self) {}
    #[inline(always)]
    fn pre_to_le_words(&mut self) {}
    #[inline(always)]
    fn post_to_le_words(&mut self) {}
    #[inline(always)]
    fn pre_output(&mut self) {}
    #[inline(always)]
    fn post_output(&mut self) {}
    #[inline(always)]
    fn pre_increase_refcount(&mut self) {}
    #[inline(always)]
    fn post_increase_refcount(&mut self) {}
    #[inline(always)]
    fn pre_decrease_refcount(&mut self) {}
    #[inline(always)]
    fn post_decrease_refcount(&mut self) {}
    #[inline(always)]
    fn pre_not(&mut self) {}
    #[inline(always)]
    fn post_not(&mut self) {}
    #[inline(always)]
    fn pre_bitxor(&mut self) {}
    #[inline(always)]
    fn post_bitxor(&mut self) {}
    #[inline(always)]
    fn pre_bitand(&mut self) {}
    #[inline(always)]
    fn post_bitand(&mut self) {}
    #[inline(always)]
    fn pre_bitxor_const(&mut self) {}
    #[inline(always)]
    fn post_bitxor_const(&mut self) {}
    #[inline(always)]
    fn pre_bitand_const(&mut self) {}
    #[inline(always)]
    fn post_bitand_const(&mut self) {}
    #[inline(always)]
    fn pre_unbounded_shl(&mut self) {}
    #[inline(always)]
    fn post_unbounded_shl(&mut self) {}
    #[inline(always)]
    fn pre_unbounded_shr(&mut self) {}
    #[inline(always)]
    fn post_unbounded_shr(&mut self) {}
    #[inline(always)]
    fn pre_rotate_left(&mut self) {}
    #[inline(always)]
    fn post_rotate_left(&mut self) {}
    #[inline(always)]
    fn pre_rotate_right(&mut self) {}
    #[inline(always)]
    fn post_rotate_right(&mut self) {}
    #[inline(always)]
    fn pre_reverse_bits(&mut self) {}
    #[inline(always)]
    fn post_reverse_bits(&mut self) {}
    #[inline(always)]
    fn pre_swap_bytes(&mut self) {}
    #[inline(always)]
    fn post_swap_bytes(&mut self) {}
    #[inline(always)]
    fn pre_cast(&mut self) {}
    #[inline(always)]
    fn post_cast(&mut self) {}
    #[inline(always)]
    fn pre_carry(&mut self) {}
    #[inline(always)]
    fn post_carry(&mut self) {}
}

/// The default hook: overrides nothing, so every hook is the empty inlined default and the whole
/// [Hooked] layer is elided by the optimiser.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHook;

impl BackendHook for NoHook {
    type InitArg = ();

    #[inline(always)]
    fn new(_arg: ()) -> Self {
        return NoHook;
    }
}

/// Zero-cost decorator wrapping a [Backend] `B` with a [BackendHook] `H`.
#[repr(C)]
pub struct Hooked<H: BackendHook, B: Backend> {
    hook: H,
    inner: B,
}

impl<H: BackendHook, B: Backend> Hooked<H, B> {
    /// Wraps `inner` with `hook`.
    #[inline]
    pub fn new(hook: H, inner: B) -> Self {
        return Self { hook, inner };
    }

    /// A shared reference to the wrapped backend.
    #[inline]
    pub fn inner(&self) -> &B {
        return &self.inner;
    }

    /// A mutable reference to the wrapped backend.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut B {
        return &mut self.inner;
    }
}

// Hand-rolled so a hook need not be `Debug`: only the inner backend (already `Debug` via `Backend`)
// is printed. Keeps arbitrary hook state (e.g. a non-`Debug` platform context) wrappable.
impl<H: BackendHook, B: Backend> Debug for Hooked<H, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.debug_struct("Hooked").field("inner", &self.inner).finish();
    }
}

impl<H: BackendHook, B: Backend> Backend for Hooked<H, B> {
    type FinalizeArg = B::FinalizeArg;
    type FinalizeResult = B::FinalizeResult;

    #[inline]
    fn finalize(self, arg: B::FinalizeArg) -> B::FinalizeResult {
        return self.inner.finalize(arg);
    }

    #[inline]
    fn input<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) -> WordIdx<W, N> {
        self.hook.pre_input();
        let r = self.inner.input(word);
        self.hook.post_input();
        return r;
    }

    #[inline]
    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N> {
        self.hook.pre_alloc();
        let r = self.inner.alloc();
        self.hook.post_alloc();
        return r;
    }

    #[inline]
    fn constant<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>, out: WordIdx<W, N>) {
        self.hook.pre_constant();
        self.inner.constant(word, out);
        self.hook.post_constant();
    }

    #[inline]
    fn from_le_words<W: Word, const N: usize>(
        &mut self,
        ins: [WordIdx<W, 1>; N],
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_from_le_words();
        self.inner.from_le_words(ins, out);
        self.hook.post_from_le_words();
    }

    #[inline]
    fn to_le_words<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        outs: [WordIdx<W, 1>; N],
    ) {
        self.hook.pre_to_le_words();
        self.inner.to_le_words(in_, outs);
        self.hook.post_to_le_words();
    }

    #[inline]
    fn output<W: Word, const N: usize>(&mut self, out: WordIdx<W, N>) {
        self.hook.pre_output();
        self.inner.output(out);
        self.hook.post_output();
    }

    #[inline]
    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.hook.pre_increase_refcount();
        self.inner.increase_refcount(idx);
        self.hook.post_increase_refcount();
    }

    #[inline]
    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.hook.pre_decrease_refcount();
        self.inner.decrease_refcount(idx);
        self.hook.post_decrease_refcount();
    }

    #[inline]
    fn not<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.hook.pre_not();
        self.inner.not(in_, out);
        self.hook.post_not();
    }

    #[inline]
    fn bitxor<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_bitxor();
        self.inner.bitxor(inl, inr, out);
        self.hook.post_bitxor();
    }

    #[inline]
    fn bitand<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_bitand();
        self.inner.bitand(inl, inr, out);
        self.hook.post_bitand();
    }

    #[inline]
    fn bitxor_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_bitxor_const();
        self.inner.bitxor_const(inl, inr, out);
        self.hook.post_bitxor_const();
    }

    #[inline]
    fn bitand_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_bitand_const();
        self.inner.bitand_const(inl, inr, out);
        self.hook.post_bitand_const();
    }

    #[inline]
    fn unbounded_shl<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_unbounded_shl();
        self.inner.unbounded_shl(in_, shift, out);
        self.hook.post_unbounded_shl();
    }

    #[inline]
    fn unbounded_shr<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_unbounded_shr();
        self.inner.unbounded_shr(in_, shift, out);
        self.hook.post_unbounded_shr();
    }

    #[inline]
    fn rotate_left<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_rotate_left();
        self.inner.rotate_left(in_, shift, out);
        self.hook.post_rotate_left();
    }

    #[inline]
    fn rotate_right<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_rotate_right();
        self.inner.rotate_right(in_, shift, out);
        self.hook.post_rotate_right();
    }

    #[inline]
    fn reverse_bits<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.hook.pre_reverse_bits();
        self.inner.reverse_bits(in_, out);
        self.hook.post_reverse_bits();
    }

    #[inline]
    fn swap_bytes<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.hook.pre_swap_bytes();
        self.inner.swap_bytes(in_, out);
        self.hook.post_swap_bytes();
    }

    #[inline]
    fn cast<W: Word, T: Word>(&mut self, in_: WordIdx<W, 1>, out: WordIdx<T, 1>) {
        self.hook.pre_cast();
        self.inner.cast(in_, out);
        self.hook.post_cast();
    }

    #[inline]
    fn carry<W: Word, const N: usize>(
        &mut self,
        p: WordIdx<W, N>,
        g: WordIdx<W, N>,
        carry_in: bool,
        out: WordIdx<W, N>,
    ) {
        self.hook.pre_carry();
        self.inner.carry(p, g, carry_in, out);
        self.hook.post_carry();
    }
}
