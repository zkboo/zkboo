// SPDX-License-Identifier: LGPL-3.0-or-later

use core::{cell::UnsafeCell, fmt::Debug};

use zeroize::Zeroizing;

use crate::{
    memory::{FlexibleMemoryManager, MemoryManager, RefCount},
    word::{CompositeWord, Shape, Word, WordIdx, Words, on_all_words},
};

/// Trait for a pool of allocated words.
pub trait WordPool: Sized + Debug + Default {
    /// Allocates a new word to the pool, returning its index.
    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N>;

    /// Increases the reference count of the word at the given index.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Decreases the reference count of the word at the given index.
    /// If the reference count reaches zero after decreasing, the word is deallocated
    /// and the memory slot can be reused.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>);

    /// Reads the word at the given index.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn read<W: Word, const N: usize>(&self, idx: WordIdx<W, N>) -> CompositeWord<W, N>;

    /// Writes the word to the given index, overwriting the existing value.
    ///
    /// ⚠️ Safety: Calling this on an index not currently allocated is undefined behaviour.
    fn write<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>, word: CompositeWord<W, N>);
}

/// Trait for word sources to be used by [WordPoolWrapper]s.
pub trait WordSource: Debug + Default {
    /// Returns a slice of the internal word storage for type `W`.
    fn words<W: Word>(&self) -> &[W];

    /// Returns a mutable slice of the internal word storage for type `W`.
    fn words_mut<W: Word>(&mut self) -> &mut [W];

    /// Ensures that the internal word vector for type `W` is large enough to accommodate the
    /// word indices contained in the given [WordIdx], extending it if necessary.
    fn resize<W: Word>(&mut self, new_len: usize);
}

/// Implementation of [WordSource] wrapping a [Words] struct.
#[derive(Debug)]
pub struct WordSourceWrapper {
    words: Zeroizing<Words>,
}

impl WordSourceWrapper {
    /// Creates a new [WordSourceWrapper] wrapping the given [Words] struct.
    pub fn new(words: Words) -> Self {
        return Self {
            words: Zeroizing::new(words),
        };
    }
}

impl WordSource for WordSourceWrapper {
    fn words<W: Word>(&self) -> &[W] {
        return self.words.as_vec::<W>();
    }

    fn words_mut<W: Word>(&mut self) -> &mut [W] {
        return self.words.as_vec_mut::<W>();
    }

    fn resize<W: Word>(&mut self, new_len: usize) {
        self.words.as_vec_mut::<W>().resize(new_len, W::ZERO);
    }
}

impl Default for WordSourceWrapper {
    fn default() -> Self {
        return Self::new(Words::new());
    }
}

/// Implementation of [WordPool] wrapping together a [WordSource] and a [MemoryManager].
#[derive(Debug)]
pub struct WordPoolWrapper<WS: WordSource, M: MemoryManager> {
    word_source: WS,
    memory_manager: M,
}

impl<WS: WordSource, M: MemoryManager> WordPoolWrapper<WS, M> {
    /// Creates a new [WordPoolWrapper] with the given [WordSource] and [MemoryManager].
    pub fn new(word_source: WS, memory_manager: M) -> Self {
        return Self {
            word_source,
            memory_manager,
        };
    }
}

impl<WS: WordSource, M: MemoryManager> WordPool for WordPoolWrapper<WS, M> {
    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N> {
        let (idx, vec_len) = self.memory_manager.alloc::<W, N>();
        self.word_source.resize::<W>(vec_len);
        return idx;
    }

    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.memory_manager.increase_refcount::<W, N>(idx);
    }

    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.memory_manager.decrease_refcount::<W, N>(idx);
    }

    fn read<W: Word, const N: usize>(&self, idx: WordIdx<W, N>) -> CompositeWord<W, N> {
        let words = self.word_source.words::<W>();
        let res = CompositeWord::from_le_words(idx.into_array().map(|i| words[i]));
        return res;
    }

    fn write<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>, word: CompositeWord<W, N>) {
        let words = self.word_source.words_mut::<W>();
        for (i, w) in idx.into_array().into_iter().zip(word.to_le_words()) {
            words[i] = w;
        }
    }
}

impl<WS: WordSource, M: MemoryManager> Default for WordPoolWrapper<WS, M> {
    fn default() -> Self {
        return Self::new(WS::default(), M::new());
    }
}

/// A [WordPool] using a [WordSourceWrapper] wrapping an owned [Words] instance
/// and a [FlexibleMemoryManager] with the given [RefCount] type.
#[allow(type_alias_bounds)]
pub type OwnedFlexibleWordPool<RC: RefCount> =
    WordPoolWrapper<WordSourceWrapper, FlexibleMemoryManager<RC>>;

struct GlobalWords(UnsafeCell<Words>);

// Manually implement Sync for GlobalWords,
// as we will ensure that it is only accessed by one thread at a time.
unsafe impl Sync for GlobalWords {}

static GLOBAL_WORDS: GlobalWords = GlobalWords(UnsafeCell::new(Words::new()));

/// A [WordSource] providing access to a static global [Words] instance.
///
/// ⚠️ This is unsafe to use in a multi-threaded context.
#[derive(Debug, Default)]
pub struct GlobalWordSource;

impl WordSource for GlobalWordSource {
    fn words<W: Word>(&self) -> &[W] {
        unsafe { (&*GLOBAL_WORDS.0.get()).as_vec::<W>() }
    }

    fn words_mut<W: Word>(&mut self) -> &mut [W] {
        unsafe { (&mut *GLOBAL_WORDS.0.get()).as_vec_mut::<W>() }
    }

    fn resize<W: Word>(&mut self, new_len: usize) {
        unsafe { (&mut *GLOBAL_WORDS.0.get()).as_vec_mut::<W>() }.resize(new_len, W::ZERO);
    }
}

/// A [WordPool] using a [GlobalWordSource] and
/// a [FlexibleMemoryManager] with the given [RefCount] type.
///
/// ⚠️ This is unsafe to use in a multi-threaded context.
#[allow(type_alias_bounds)]
pub type GlobalFlexibleWordPool<RC: RefCount> =
    WordPoolWrapper<GlobalWordSource, FlexibleMemoryManager<RC>>;

impl<RC: RefCount> GlobalFlexibleWordPool<RC> {
    /// The current [Words::shape] of the underlying storage.
    pub fn shape() -> Shape {
        return unsafe { (&mut *GLOBAL_WORDS.0.get()).shape() };
    }

    /// The current [Words::capacity] of the underlying storage.
    pub fn capacity() -> Shape {
        return unsafe { (&mut *GLOBAL_WORDS.0.get()).capacity() };
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
            let words = unsafe { (&mut *GLOBAL_WORDS.0.get()).as_vec_mut::<W>() };
            words.reserve_exact(*additional.as_value::<W>());
        });
    }

    /// Resizes the underlying storage to the given shape, extending or shrinking it if necessary.
    pub fn resize(new_len: Shape) {
        on_all_words!(W, {
            let words = unsafe { (&mut *GLOBAL_WORDS.0.get()).as_vec_mut::<W>() };
            words.resize(*new_len.as_value::<W>(), <W as Word>::ZERO);
        });
        assert_eq!(Self::shape(), new_len);
    }
}
