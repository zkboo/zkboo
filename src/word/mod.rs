// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of word containers.

mod by_word_type;
pub mod collectors;
mod word;
mod word_idx;
mod words;

pub use by_word_type::{ByWordType, Shape, by_word_type, shape};
pub use word::{CompositeWord, Word, WordLike, on_all_words};
pub use word_idx::WordIdx;
pub use words::{ShapeError, Words};
