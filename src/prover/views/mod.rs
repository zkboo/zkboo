// SPDX-License-Identifier: LGPL-3.0-or-later

//! View building logic for the ZKBoo prover.

mod backend;
pub mod collectors;
mod functions;
mod view;
mod word_pool;

pub use backend::ViewBuilderBackend;
pub use functions::{build_view_commitments, build_views, build_views_custom};
pub use view::{ViewCommitment, Views};
pub use word_pool::{
    GlobalFlexibleWordTriplePool, GlobalWordTripleSource, OwnedFlexibleWordTriplePool,
    WordTriplePool, WordTriplePoolWrapper, WordTripleSource, WordTripleSourceWrapper,
};
