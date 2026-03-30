// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of memory management for generic ZKBoo backends.

use crate::{
    memory::AllocSet,
    word::{ByWordType, Shape, Word, WordIdx},
};
use alloc::vec::Vec;
use core::fmt::Debug;

/// Trait for reference count types to be used by [MemoryManager]s.
///
/// Implemented for [u8], [u16], [u32], [u64], [u128] and [usize] by default.
pub trait RefCount: Sized + Copy + Debug {
    const ZERO: Self;
    fn increase(&mut self);
    fn decrease(&mut self);
    fn is_zero(&self) -> bool;
}

macro_rules! impl_RefCount {
    ($ty: ty) => {
        impl RefCount for $ty {
            const ZERO: Self = 0;
            fn increase(&mut self) {
                *self += 1;
            }
            fn decrease(&mut self) {
                if *self == 0 {
                    panic!("Reference count underflow detected.");
                }
                *self -= 1;
            }
            fn is_zero(&self) -> bool {
                return *self == 0;
            }
        }
    };
}

impl_RefCount!(u8);
impl_RefCount!(u16);
impl_RefCount!(u32);
impl_RefCount!(u64);
impl_RefCount!(u128);
impl_RefCount!(usize);

/// Trait for memory managers used to track word allocations.
pub trait MemoryManager: Sized + Debug {
    /// Creates a new [MemoryManager] with no allocated words.
    fn new() -> Self;

    /// Returns a [WordIdx] pointing to `N` currently free [Word]s of type `W`,
    /// together with the new minimum vector length required for the [WordIdx] to be valid.
    ///  
    /// The reference count for the allocated words is set to 1.
    fn alloc<W: Word, const N: usize>(&mut self) -> (WordIdx<W, N>, usize);

    /// Increases the reference count for `N` [Word]s of type `W` pointed to
    /// by the given [WordIdx].
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Decreases the reference count for `N` [Word]s of type `W` pointed to
    /// by the given [WordIdx].
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Clears all allocated memory, resetting the memory manager to its initial state,
    /// but retaining any allocated capacity.
    fn clear(&mut self);
}

/// Implementation of a [MemoryManager] using [RefCount] vectors and [AllocSet]s for each word type.
/// Suitable for scenarios where the number of allocated words is not known in advance.
#[derive(Debug)]
pub struct FlexibleMemoryManager<RC: RefCount> {
    refcounts: ByWordType<Vec<RC>>,
    alloc_set: ByWordType<AllocSet>,
}

impl<RC: RefCount> FlexibleMemoryManager<RC> {
    /// Reference counts for all words in the memory manager.
    pub fn refcounts(&self) -> &ByWordType<Vec<RC>> {
        return &self.refcounts;
    }

    /// Allocation sets for all words in the memory manager.
    pub fn alloc_set(&self) -> &ByWordType<AllocSet> {
        return &self.alloc_set;
    }

    pub fn shape(&self) -> Shape {
        return self.refcounts.map(|refcounts| refcounts.len());
    }

    pub fn capacity(&self) -> Shape {
        return self.refcounts.map(|refcounts| refcounts.capacity());
    }

    /// Ensures that the internal reference count vector is large enough to accommodate the
    /// word indices contained in the given [WordIdx], extending it if necessary.
    /// Returns the new length of the reference count vector after extension.
    fn extend_recounts_vec_if_needed<W: Word, const N: usize>(
        &mut self,
        idx: WordIdx<W, N>,
    ) -> usize {
        let refcounts = self.refcounts.as_vec_mut::<W>();
        let idxs: [usize; N] = idx.into();
        let max_idx = idxs.into_iter().max();
        if let Some(max_idx) = max_idx {
            if max_idx >= refcounts.len() {
                refcounts.resize(max_idx + 1, RC::ZERO);
            }
        }
        return refcounts.len();
    }

    // pub fn reserve(&mut self, capacity: Shape) {
    //     let current_capacity = self.capacity();
    //     let additional = capacity.zip(&current_capacity, |desired, current| {
    //         if desired < current {
    //             0
    //         } else {
    //             desired - current
    //         }
    //     });
    //     use crate::word::on_all_words;
    //     on_all_words!(W, {
    //         let additional_capacity = *additional.as_value::<W>();
    //         self.alloc_set
    //             .as_value_mut::<W>()
    //             .reserve(additional_capacity);
    //         self.refcounts
    //             .as_vec_mut::<W>()
    //             .reserve_exact(additional_capacity);
    //     });
    // }

    // pub fn resize(&mut self, new_len: Shape) {
    //     use crate::word::on_all_words;
    //     on_all_words!(W, {
    //         let size = *new_len.as_value::<W>();
    //         self.alloc_set.as_value_mut::<W>().resize(size);
    //         self.refcounts.as_vec_mut::<W>().resize(size, R::ZERO);
    //     });
    // }
}

impl<RC: RefCount> MemoryManager for FlexibleMemoryManager<RC> {
    fn new() -> Self {
        return FlexibleMemoryManager {
            refcounts: ByWordType::new(),
            alloc_set: ByWordType::default(),
        };
    }

    fn alloc<W: Word, const N: usize>(&mut self) -> (WordIdx<W, N>, usize) {
        let alloc_set = self.alloc_set.as_value_mut::<W>();
        let idxs: [usize; N] = core::array::from_fn(|_| alloc_set.alloc());
        let idx = WordIdx::new(idxs);
        let vec_len = self.extend_recounts_vec_if_needed(idx);
        return (idx, vec_len);
    }

    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        let refcounts = self.refcounts.as_vec_mut::<W>();
        let idxs: [usize; _] = idx.into();
        for i in idxs {
            refcounts[i].increase();
        }
    }

    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        let refcounts = self.refcounts.as_vec_mut::<W>();
        let alloc_set = self.alloc_set.as_value_mut::<W>();
        let idxs: [usize; _] = idx.into();
        for i in idxs {
            refcounts[i].decrease();
            if refcounts[i].is_zero() {
                alloc_set.free(i);
            }
        }
    }
    fn clear(&mut self) {
        self.refcounts.map_mut(|refcounts| refcounts.clear());
        self.alloc_set.map_mut(|alloc_set| alloc_set.clear());
    }
}
