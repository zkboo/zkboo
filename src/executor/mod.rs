// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the execution logic for ZKBoo circuits.

mod backend;
// mod frontend;
pub mod functions;
mod word_pool;

pub use backend::ExecutionBackend;
// pub use frontend::Executor;
pub use functions::exec;
pub use word_pool::{
    GlobalFlexibleWordPool, GlobalWordSource, OwnedFlexibleWordPool, WordPool, WordPoolWrapper,
    WordSource, WordSourceWrapper,
};
