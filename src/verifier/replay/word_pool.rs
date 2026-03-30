// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of a pool of allocated word pairs for use in the ZKBoo view replay.

use crate::{
    memory::{FlexibleMemoryManager, MemoryManager, RefCount},
    word::{CompositeWord, Shape, Word, WordIdx, Words, on_all_words},
};
use core::{cell::UnsafeCell, fmt::Debug};
use zeroize::Zeroizing;

/// Trait for a pool of allocated word pairs.
pub trait WordPairPool: Sized + Debug + Default {
    /// Allocates a new word pair to the pool, returning its index.
    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N>;

    /// Increases the reference count of the word pair at the given index.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Decreases the reference count of the word pair at the given index.
    /// If the reference count reaches zero after decreasing, the word pair is deallocated
    /// and the memory slot can be reused.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Reads the word pair at the given index.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn read<W: Word, const N: usize>(&self, idx: WordIdx<W, N>) -> [CompositeWord<W, N>; 2];

    /// Writes the word pair to the given index, overwriting the existing value.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn write<W: Word, const N: usize>(
        &mut self,
        idx: WordIdx<W, N>,
        words: [CompositeWord<W, N>; 2],
    );
}

/// Trait for word pair sources to be used by [WordPairPoolWrapper]s.
pub trait WordPairSource: Debug + Default {
    /// Returns a slice of the internal word storage for type `W`.
    fn words<W: Word>(&self) -> [&[W]; 2];

    /// Returns a mutable slice of the internal word storage for type `W`.
    fn words_mut<W: Word>(&mut self) -> [&mut [W]; 2];

    /// Ensures that the internal word vector for type `W` is large enough to accommodate the
    /// word indices contained in the given [WordIdx], extending it if necessary.
    fn resize<W: Word>(&mut self, new_len: usize);
}

/// Implementation of [WordPairSource] wrapping a [Words] struct.
#[derive(Debug)]
pub struct WordPairSourceWrapper {
    words: [Zeroizing<Words>; 2],
}

impl WordPairSourceWrapper {
    /// Creates a new [WordPairSourceWrapper] wrapping the given [Words] struct.
    pub fn new(words: [Words; 2]) -> Self {
        let [w0, w1] = words;
        return Self {
            words: [Zeroizing::new(w0), Zeroizing::new(w1)],
        };
    }
}

impl WordPairSource for WordPairSourceWrapper {
    fn words<W: Word>(&self) -> [&[W]; 2] {
        return [self.words[0].as_vec::<W>(), self.words[1].as_vec::<W>()];
    }

    fn words_mut<W: Word>(&mut self) -> [&mut [W]; 2] {
        let [words0, words1] = &mut self.words;
        return [words0.as_vec_mut::<W>(), words1.as_vec_mut::<W>()];
    }

    fn resize<W: Word>(&mut self, new_len: usize) {
        for words in self.words.iter_mut() {
            words.as_vec_mut::<W>().resize(new_len, W::ZERO);
        }
    }
}

impl Default for WordPairSourceWrapper {
    fn default() -> Self {
        return Self::new([Words::new(), Words::new()]);
    }
}

/// Implementation of [WordPairPool] wrapping together a pair of [WordPairSource]s
/// and a [MemoryManager].
#[derive(Debug)]
pub struct WordPairPoolWrapper<WS: WordPairSource, M: MemoryManager> {
    word_pair_source: WS,
    memory_manager: M,
}

impl<WS: WordPairSource, M: MemoryManager> WordPairPoolWrapper<WS, M> {
    /// Creates a new [WordPairPoolWrapper] with the given [WordPairSource]s and [MemoryManager].
    pub fn new(word_pair_source: WS, memory_manager: M) -> Self {
        return Self {
            word_pair_source,
            memory_manager,
        };
    }
}

impl<WS: WordPairSource, M: MemoryManager> WordPairPool for WordPairPoolWrapper<WS, M> {
    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N> {
        let (idx, vec_len) = self.memory_manager.alloc::<W, N>();
        self.word_pair_source.resize::<W>(vec_len);
        return idx;
    }

    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.memory_manager.increase_refcount::<W, N>(idx);
    }

    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.memory_manager.decrease_refcount::<W, N>(idx);
    }

    fn read<W: Word, const N: usize>(&self, idx: WordIdx<W, N>) -> [CompositeWord<W, N>; 2] {
        let word_slices = self.word_pair_source.words::<W>();
        return word_slices
            .map(|words| CompositeWord::from_le_words(idx.into_array().map(|i| words[i])));
    }

    fn write<W: Word, const N: usize>(
        &mut self,
        idx: WordIdx<W, N>,
        words: [CompositeWord<W, N>; 2],
    ) {
        let mut word_slices = self.word_pair_source.words_mut::<W>();
        for (k, word_slice) in word_slices.iter_mut().enumerate() {
            for (i, w) in idx.into_array().into_iter().zip(words[k].to_le_words()) {
                word_slice[i] = w;
            }
        }
    }
}

impl<WS: WordPairSource, M: MemoryManager> Default for WordPairPoolWrapper<WS, M> {
    fn default() -> Self {
        let memory_manager = M::new();
        let word_pair_source = WS::default();
        return Self::new(word_pair_source, memory_manager);
    }
}

/// A [WordPairPool] using a pair of [WordPairSourceWrapper]s wrapping an owned [Words] instance
/// and a [FlexibleMemoryManager] with the given [RefCount] type.
#[allow(type_alias_bounds)]
pub type OwnedFlexibleWordPairPool<RC: RefCount> =
    WordPairPoolWrapper<WordPairSourceWrapper, FlexibleMemoryManager<RC>>;

struct GlobalWordPairs(UnsafeCell<[Words; 2]>);

// Manually implement Sync for GlobalWordPairs,
// as we will ensure that it is only accessed by one thread at a time.
unsafe impl Sync for GlobalWordPairs {}

static GLOBAL_WORD_PAIRS: GlobalWordPairs =
    GlobalWordPairs(UnsafeCell::new([Words::new(), Words::new()]));

/// A [WordPairSource] providing access to a static global [Words] instance.
///
/// ⚠️ This is unsafe to use in a multi-threaded context.
#[derive(Debug, Default)]
pub struct GlobalWordPairSource;

impl WordPairSource for GlobalWordPairSource {
    fn words<W: Word>(&self) -> [&[W]; 2] {
        let words = unsafe { &*GLOBAL_WORD_PAIRS.0.get() };
        [words[0].as_vec::<W>(), words[1].as_vec::<W>()]
    }

    fn words_mut<W: Word>(&mut self) -> [&mut [W]; 2] {
        let [w0, w1] = unsafe { &mut *GLOBAL_WORD_PAIRS.0.get() };
        [w0.as_vec_mut::<W>(), w1.as_vec_mut::<W>()]
    }

    fn resize<W: Word>(&mut self, new_len: usize) {
        let words = unsafe { &mut *GLOBAL_WORD_PAIRS.0.get() };
        words[0].as_vec_mut::<W>().resize(new_len, W::ZERO);
        words[1].as_vec_mut::<W>().resize(new_len, W::ZERO);
    }
}

/// A [WordPairPool] using a [GlobalWordPairSource] and
/// a [FlexibleMemoryManager] with the given [RefCount] type.
///
/// ⚠️ This is unsafe to use in a multi-threaded context.
#[allow(type_alias_bounds)]
pub type GlobalFlexibleWordPairPool<RC: RefCount> =
    WordPairPoolWrapper<GlobalWordPairSource, FlexibleMemoryManager<RC>>;

impl<RC: RefCount> GlobalFlexibleWordPairPool<RC> {
    /// The current [Words::shape] of the underlying storage.
    pub fn shape() -> Shape {
        let shape0 = unsafe { (&mut *GLOBAL_WORD_PAIRS.0.get())[0].shape() };
        let shape1 = unsafe { (&mut *GLOBAL_WORD_PAIRS.0.get())[1].shape() };
        assert_eq!(
            shape0, shape1,
            "Shape mismatch between word pools in global word pair pool."
        );
        return shape0;
    }

    /// The current [Words::capacity] of the underlying storage.
    pub fn capacity() -> Shape {
        let capacity0 = unsafe { (&mut *GLOBAL_WORD_PAIRS.0.get())[0].capacity() };
        let capacity1 = unsafe { (&mut *GLOBAL_WORD_PAIRS.0.get())[1].capacity() };
        assert_eq!(
            capacity0, capacity1,
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
                (&mut *GLOBAL_WORD_PAIRS.0.get())[0]
                    .as_vec_mut::<W>()
                    .reserve_exact(*additional.as_value::<W>());
                (&mut *GLOBAL_WORD_PAIRS.0.get())[1]
                    .as_vec_mut::<W>()
                    .reserve_exact(*additional.as_value::<W>());
            };
        });
    }

    /// Resizes the underlying storage to the given shape, extending or shrinking it if necessary.
    pub fn resize(new_len: Shape) {
        on_all_words!(W, {
            unsafe {
                (&mut *GLOBAL_WORD_PAIRS.0.get())[0]
                    .as_vec_mut::<W>()
                    .resize(*new_len.as_value::<W>(), <W as Word>::ZERO);
                (&mut *GLOBAL_WORD_PAIRS.0.get())[1]
                    .as_vec_mut::<W>()
                    .resize(*new_len.as_value::<W>(), <W as Word>::ZERO);
            };
        });
        assert_eq!(Self::shape(), new_len);
    }
}
