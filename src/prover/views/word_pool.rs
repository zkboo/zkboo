// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of a pool of allocated word triples for use in the view building logic.

use crate::{
    memory::{FlexibleMemoryManager, MemoryManager, RefCount},
    word::{CompositeWord, Shape, Word, WordIdx, Words, on_all_words},
};
use core::{cell::UnsafeCell, fmt::Debug};
use zeroize::Zeroizing;

/// Trait for a pool of allocated word triples.
pub trait WordTriplePool: Sized + Debug + Default {
    /// Allocates a new word triple to the pool, returning its index.
    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N>;

    /// Increases the reference count of the word triple at the given index.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Decreases the reference count of the word triple at the given index.
    /// If the reference count reaches zero after decreasing, the word triple is deallocated
    /// and the memory slot can be reused.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Reads the word triple at the given index.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn read<W: Word, const N: usize>(&self, idx: WordIdx<W, N>) -> [CompositeWord<W, N>; 3];

    /// Writes the word triple to the given index, overwriting the existing value.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn write<W: Word, const N: usize>(
        &mut self,
        idx: WordIdx<W, N>,
        words: [CompositeWord<W, N>; 3],
    );
}

/// Trait for word triple sources to be used by [WordTriplePoolWrapper]s.
pub trait WordTripleSource: Debug + Default {
    /// Returns a slice of the internal word storage for type `W`.
    fn words<W: Word>(&self) -> [&[W]; 3];

    /// Returns a mutable slice of the internal word storage for type `W`.
    fn words_mut<W: Word>(&mut self) -> [&mut [W]; 3];

    /// Ensures that the internal word vector for type `W` is large enough to accommodate the
    /// word indices contained in the given [WordIdx], extending it if necessary.
    fn resize<W: Word>(&mut self, new_len: usize);
}

/// Implementation of [WordTripleSource] wrapping a [Words] struct.
#[derive(Debug)]
pub struct WordTripleSourceWrapper {
    words: [Zeroizing<Words>; 3],
}

impl WordTripleSourceWrapper {
    /// Creates a new [WordTripleSourceWrapper] wrapping the given [Words] struct.
    pub fn new(words: [Words; 3]) -> Self {
        let [w0, w1, w2] = words;
        return Self {
            words: [Zeroizing::new(w0), Zeroizing::new(w1), Zeroizing::new(w2)],
        };
    }
}

impl WordTripleSource for WordTripleSourceWrapper {
    fn words<W: Word>(&self) -> [&[W]; 3] {
        return [
            self.words[0].as_vec::<W>(),
            self.words[1].as_vec::<W>(),
            self.words[2].as_vec::<W>(),
        ];
    }

    fn words_mut<W: Word>(&mut self) -> [&mut [W]; 3] {
        let [words0, words1, words2] = &mut self.words;
        return [
            words0.as_vec_mut::<W>(),
            words1.as_vec_mut::<W>(),
            words2.as_vec_mut::<W>(),
        ];
    }

    fn resize<W: Word>(&mut self, new_len: usize) {
        for words in self.words.iter_mut() {
            words.as_vec_mut::<W>().resize(new_len, W::ZERO);
        }
    }
}

impl Default for WordTripleSourceWrapper {
    fn default() -> Self {
        return Self::new([Words::new(), Words::new(), Words::new()]);
    }
}

/// Implementation of [WordTriplePool] wrapping together a triple of [WordTripleSource]s
/// and a [MemoryManager].
#[derive(Debug)]
pub struct WordTriplePoolWrapper<WS: WordTripleSource, M: MemoryManager> {
    word_triple_source: WS,
    memory_manager: M,
}

impl<WS: WordTripleSource, M: MemoryManager> WordTriplePoolWrapper<WS, M> {
    /// Creates a new [WordTriplePoolWrapper] with the given [WordTripleSource]s and [MemoryManager].
    pub fn new(word_triple_source: WS, memory_manager: M) -> Self {
        return Self {
            word_triple_source,
            memory_manager,
        };
    }
}

impl<WS: WordTripleSource, M: MemoryManager> WordTriplePool for WordTriplePoolWrapper<WS, M> {
    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N> {
        let (idx, vec_len) = self.memory_manager.alloc::<W, N>();
        self.word_triple_source.resize::<W>(vec_len);
        return idx;
    }

    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.memory_manager.increase_refcount::<W, N>(idx);
    }

    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.memory_manager.decrease_refcount::<W, N>(idx);
    }

    fn read<W: Word, const N: usize>(&self, idx: WordIdx<W, N>) -> [CompositeWord<W, N>; 3] {
        let word_slices = self.word_triple_source.words::<W>();
        return word_slices
            .map(|words| CompositeWord::from_le_words(idx.into_array().map(|i| words[i])));
    }

    fn write<W: Word, const N: usize>(
        &mut self,
        idx: WordIdx<W, N>,
        words: [CompositeWord<W, N>; 3],
    ) {
        let mut word_slices = self.word_triple_source.words_mut::<W>();
        for (k, word_slice) in word_slices.iter_mut().enumerate() {
            for (i, w) in idx.into_array().into_iter().zip(words[k].to_le_words()) {
                word_slice[i] = w;
            }
        }
    }
}

impl<WS: WordTripleSource, M: MemoryManager> Default for WordTriplePoolWrapper<WS, M> {
    fn default() -> Self {
        let memory_manager = M::new();
        let word_triple_source = WS::default();
        return Self::new(word_triple_source, memory_manager);
    }
}

/// A [WordTriplePool] using a triple of [WordTripleSourceWrapper]s wrapping an owned [Words] instance
/// and a [FlexibleMemoryManager] with the given [RefCount] type.
#[allow(type_alias_bounds)]
pub type OwnedFlexibleWordTriplePool<RC: RefCount> =
    WordTriplePoolWrapper<WordTripleSourceWrapper, FlexibleMemoryManager<RC>>;

struct GlobalWordTriples(UnsafeCell<[Words; 3]>);

// Manually implement Sync for GlobalWordTriples,
// as we will ensure that it is only accessed by one thread at a time.
unsafe impl Sync for GlobalWordTriples {}

static GLOBAL_WORD_TRIPLES: GlobalWordTriples =
    GlobalWordTriples(UnsafeCell::new([Words::new(), Words::new(), Words::new()]));

/// A [WordTripleSource] providing access to a static global [Words] instance.
///
/// ⚠️ This is unsafe to use in a multi-threaded context.
#[derive(Debug, Default)]
pub struct GlobalWordTripleSource;

impl WordTripleSource for GlobalWordTripleSource {
    fn words<W: Word>(&self) -> [&[W]; 3] {
        let words = unsafe { &*GLOBAL_WORD_TRIPLES.0.get() };
        [
            words[0].as_vec::<W>(),
            words[1].as_vec::<W>(),
            words[2].as_vec::<W>(),
        ]
    }

    fn words_mut<W: Word>(&mut self) -> [&mut [W]; 3] {
        let [w0, w1, w2] = unsafe { &mut *GLOBAL_WORD_TRIPLES.0.get() };
        [
            w0.as_vec_mut::<W>(),
            w1.as_vec_mut::<W>(),
            w2.as_vec_mut::<W>(),
        ]
    }

    fn resize<W: Word>(&mut self, new_len: usize) {
        let words = unsafe { &mut *GLOBAL_WORD_TRIPLES.0.get() };
        words[0].as_vec_mut::<W>().resize(new_len, W::ZERO);
        words[1].as_vec_mut::<W>().resize(new_len, W::ZERO);
        words[2].as_vec_mut::<W>().resize(new_len, W::ZERO);
    }
}

/// A [WordTriplePool] using a [GlobalWordTripleSource] and
/// a [FlexibleMemoryManager] with the given [RefCount] type.
///
/// ⚠️ This is unsafe to use in a multi-threaded context.
#[allow(type_alias_bounds)]
pub type GlobalFlexibleWordTriplePool<RC: RefCount> =
    WordTriplePoolWrapper<GlobalWordTripleSource, FlexibleMemoryManager<RC>>;

impl<RC: RefCount> GlobalFlexibleWordTriplePool<RC> {
    /// The current [Words::shape] of the underlying storage.
    pub fn shape() -> Shape {
        let shape0 = unsafe { (&mut *GLOBAL_WORD_TRIPLES.0.get())[0].shape() };
        let shape1 = unsafe { (&mut *GLOBAL_WORD_TRIPLES.0.get())[1].shape() };
        let shape2 = unsafe { (&mut *GLOBAL_WORD_TRIPLES.0.get())[2].shape() };
        assert_eq!(
            shape0, shape1,
            "Shape mismatch between word pools in global word triple pool."
        );
        assert_eq!(
            shape1, shape2,
            "Shape mismatch between word pools in global word triple pool."
        );
        return shape0;
    }

    /// The current [Words::capacity] of the underlying storage.
    pub fn capacity() -> Shape {
        let capacity0 = unsafe { (&mut *GLOBAL_WORD_TRIPLES.0.get())[0].capacity() };
        let capacity1 = unsafe { (&mut *GLOBAL_WORD_TRIPLES.0.get())[1].capacity() };
        let capacity2 = unsafe { (&mut *GLOBAL_WORD_TRIPLES.0.get())[2].capacity() };
        assert_eq!(
            capacity0, capacity1,
            "Capacity mismatch between word pools in global word triple pool."
        );
        assert_eq!(
            capacity1, capacity2,
            "Capacity mismatch between word pools in global word triple pool."
        );
        return capacity0;
    }

    /// Reserves the given capacity in the underlying storage, extending it if necessary.
    pub fn reserve(capacity: Shape) {
        let current_capacity = Self::capacity();
        let additional = capacity.zip(&current_capacity, |desired, current| {
            if desired < current {
                0
            } else {
                desired - current
            }
        });
        on_all_words!(W, {
            unsafe {
                (&mut *GLOBAL_WORD_TRIPLES.0.get())[0]
                    .as_vec_mut::<W>()
                    .reserve_exact(*additional.as_value::<W>());
                (&mut *GLOBAL_WORD_TRIPLES.0.get())[1]
                    .as_vec_mut::<W>()
                    .reserve_exact(*additional.as_value::<W>());
                (&mut *GLOBAL_WORD_TRIPLES.0.get())[2]
                    .as_vec_mut::<W>()
                    .reserve_exact(*additional.as_value::<W>());
            };
        });
    }

    /// Resizes the underlying storage to the given shape, extending or shrinking it if necessary.
    pub fn resize(new_len: Shape) {
        on_all_words!(W, {
            unsafe {
                (&mut *GLOBAL_WORD_TRIPLES.0.get())[0]
                    .as_vec_mut::<W>()
                    .resize(*new_len.as_value::<W>(), <W as Word>::ZERO);
                (&mut *GLOBAL_WORD_TRIPLES.0.get())[1]
                    .as_vec_mut::<W>()
                    .resize(*new_len.as_value::<W>(), <W as Word>::ZERO);
                (&mut *GLOBAL_WORD_TRIPLES.0.get())[2]
                    .as_vec_mut::<W>()
                    .resize(*new_len.as_value::<W>(), <W as Word>::ZERO);
            };
        });
        assert_eq!(Self::shape(), new_len);
    }
}
