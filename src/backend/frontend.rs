// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of ZKBoo [Frontend]s and [Allocator]s, exposing the intended public-facing
//! functionality of [Backend]s and encapsulating the [Backend]-sharing logic of [WordRef]s.

use crate::{
    backend::{Backend, WordRef},
    utils::RcPtrMut,
    word::{Word, WordLike},
};

/// Wrapper for a [Backend], exposing its public-facing allocation functionality.
#[derive(Debug)]
#[repr(transparent)]
pub struct Allocator<B: Backend> {
    backend: RcPtrMut<B>,
}

impl<B: Backend> Allocator<B> {
    /// Allocates a constant word in the wrapped [Backend], returning a [WordRef] to it.
    #[inline]
    pub fn alloc<W: Word, const N: usize, C: WordLike<W, N>>(&self, word: C) -> WordRef<B, W, N> {
        return WordRef::alloc_constant(&self.backend, word.to_word());
    }
}

impl<B: Backend> Clone for Allocator<B> {
    /// Clones the reference-counted pointer to the wrapped [Backend].
    fn clone(&self) -> Self {
        return Self {
            backend: self.backend.clone(),
        };
    }
}

/// Wrapper for a [Backend], exposing its full public-facing functionality.
///
/// Lifecycle for a [Frontend]:
///
/// 1. Constructor functions are used to instantiate the corresponding [Backend], which is wrapped
///    into the [Frontend] instance (e.g. via [Backend::into_frontend]).
/// 2. The user creates [WordRef]s via the [Frontend::input] and [Frontend::alloc] methods
///    on the [Frontend], manipulates them via the [WordRef] methods/operations,
///    and consumes them as outputs via the [Frontend::output] method on the [Frontend].
/// 3. The [Frontend] is finalized using [Frontend::finalize], which in turn finalizes the
///    wrapped backend and returns the finalization result.
#[derive(Debug)]
#[repr(transparent)]
pub struct Frontend<B: Backend> {
    backend: RcPtrMut<B>,
}

impl<B: Backend> Frontend<B> {
    /// Creates a new [Frontend] wrapping the given [Backend].
    #[inline]
    pub fn wrap(backend: B) -> Self {
        return Self {
            backend: RcPtrMut::new(backend),
        };
    }

    /// Returns an allocator for the wrapped [Backend].
    pub fn allocator(&self) -> Allocator<B> {
        return Allocator {
            backend: self.backend.clone(),
        };
    }

    /// Finalizes the wrapped [Backend], returning the finalization result.
    ///
    /// Panics if any [WordRef]s or [Allocator]s for the wrapped [Backend] are still live.
    #[inline]
    pub fn finalize_with_arg(self, arg: B::FinalizeArg) -> B::FinalizeResult {
        return self.backend.into_inner().finalize(arg);
    }

    /// Allocates an input word in the wrapped [Backend], returning a [WordRef] to it.
    #[inline]
    pub fn input<W: Word, const N: usize, C: WordLike<W, N>>(&self, word: C) -> WordRef<B, W, N> {
        return WordRef::input(&self.backend, word);
    }

    /// Allocates a constant word in the wrapped [Backend], returning a [WordRef] to it.
    #[inline]
    pub fn alloc<W: Word, const N: usize, C: WordLike<W, N>>(&self, word: C) -> WordRef<B, W, N> {
        return WordRef::alloc_constant(&self.backend, word.to_word());
    }

    /// Pushes an output word into the wrapped [Backend], consuming the [WordRef].
    #[inline]
    pub fn output<W: Word, const N: usize>(&self, word_ref: WordRef<B, W, N>) {
        self.backend.borrow_mut().output(word_ref.idx());
    }
}

impl<B: Backend<FinalizeArg: Default>> Frontend<B> {
    /// Finalizes the wrapped [Backend], returning the finalization result.
    ///
    /// Panics if any [WordRef]s or [Allocator]s for the wrapped [Backend] are still live.
    #[inline]
    pub fn finalize(self) -> B::FinalizeResult {
        return self.finalize_with_arg(B::FinalizeArg::default());
    }
}
