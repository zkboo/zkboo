// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of generic backend functionality.

mod backend;
mod boolean_word_ref;
mod frontend;
mod word_ref;

pub use backend::Backend;
pub use boolean_word_ref::BooleanWordRef;
pub use frontend::{Allocator, Frontend};
pub use word_ref::WordRef;
