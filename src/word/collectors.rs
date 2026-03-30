// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::word::{Word, WordLike, Words};
use core::fmt::Debug;

/// Trait for a collector of words.
pub trait WordCollector: Debug {
    /// The result type produced when finalizing the collector.
    type FinalizeResult;

    /// Pushes a word into the collector.
    fn push<W: Word, const N: usize, U: WordLike<W, N>>(&mut self, word: U);

    /// Finalizes the collector, consuming it and producing the collected result.
    fn finalize(self) -> Self::FinalizeResult;
}

/// A [WordCollector] where words are pushed into an owned [Words] store.
/// The collected [Words] are returned on finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct OwnedWordCollector {
    words: Words,
}

impl OwnedWordCollector {
    /// Creates a new [OwnedWordCollector] with empty underlying [Words].
    pub fn new() -> Self {
        return Self {
            words: Words::new(),
        };
    }

    /// Creates a new [OwnedWordCollector] with the given [Words] container.
    pub fn wrap(words: Words) -> Self {
        return Self { words };
    }

    /// Readonly access to the collected [Words].
    pub fn words(&self) -> &Words {
        return &self.words;
    }
}

impl WordCollector for OwnedWordCollector {
    type FinalizeResult = Words;

    /// Pushes a word into the underlying [Words] store.
    ///
    /// [CompositeWord](crate::word::CompositeWord)s are flattened into their little-endian [Word] representation
    /// using [CompositeWord::to_le_words](crate::word::CompositeWord::to_le_words).
    fn push<W: Word, const N: usize, U: WordLike<W, N>>(&mut self, word: U) {
        self.words.as_vec_mut().extend(word.to_word().to_le_words());
    }

    /// Consumes the collector and returns the collected [Words].
    fn finalize(self) -> Words {
        return self.words;
    }
}

impl Default for OwnedWordCollector {
    /// Creates a new [OwnedWordCollector] with empty underlying [Words].
    fn default() -> Self {
        return Self::new();
    }
}

/// A [WordCollector] which discards all words pushed into it.
/// Nothing is returned on finalization.
#[derive(Clone, Copy, Debug)]
pub struct WordDiscarder;

impl WordCollector for WordDiscarder {
    type FinalizeResult = ();

    /// Discards the pushed word.
    fn push<W: Word, const N: usize, U: WordLike<W, N>>(&mut self, _word: U) {}

    /// Finalization does nothing and returns nothing.
    fn finalize(self) {}
}

impl Default for WordDiscarder {
    /// Creates a new [WordDiscarder].
    fn default() -> Self {
        return Self;
    }
}
