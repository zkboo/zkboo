// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the view replay backend.

mod backend;
mod word_pool;

pub use backend::{ViewReplayError, ViewReplayerBackend};
pub use word_pool::{
    GlobalFlexibleWordPairPool, GlobalWordPairSource, OwnedFlexibleWordPairPool, WordPairPool,
    WordPairPoolWrapper, WordPairSource, WordPairSourceWrapper,
};
