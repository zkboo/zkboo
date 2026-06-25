// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of generic backend functionality.

mod backend;
mod boolean_word_ref;
mod frontend;
mod hook;
mod word_ref;

pub use backend::Backend;
pub use boolean_word_ref::BooleanWordRef;
pub use frontend::{Allocator, Frontend};
pub use hook::{BackendHook, Hooked, NoHook};
pub use word_ref::WordRef;
