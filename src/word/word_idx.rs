// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of type-tagged storage for fixed-width words.

use crate::word::Word;
use core::marker::PhantomData;

/// Type-tagged word (multi-)index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct WordIdx<W: Word, const N: usize = 1> {
    idxs: [usize; N],
    _marker: PhantomData<W>,
}

impl<W: Word, const N: usize> WordIdx<W, N> {
    const _ASSERT_NONZERO: () = assert!(N > 0, "WordIdx must have positive cardinality");

    /// Creates a new [WordIdx] from the given indices.
    pub const fn new(idxs: [usize; N]) -> Self {
        return WordIdx {
            idxs,
            _marker: PhantomData,
        };
    }

    /// Returns the indices as an array reference.
    #[inline]
    pub fn as_array(&self) -> &[usize; N] {
        return &self.idxs;
    }

    /// Consumes the indices into the underlying [usize] array.
    #[inline]
    pub fn into_array(self) -> [usize; N] {
        return self.idxs;
    }
}

impl<W: Word, const N: usize> From<WordIdx<W, N>> for [usize; N] {
    /// Converts a [WordIdx] into its underlying [usize] array of indices.
    fn from(value: WordIdx<W, N>) -> Self {
        return value.idxs;
    }
}

impl<W: Word> From<WordIdx<W, 1>> for usize {
    /// Converts a [WordIdx] of cardinality 1 into its single underlying index.
    fn from(value: WordIdx<W, 1>) -> Self {
        let [idx] = value.idxs;
        return idx;
    }
}
