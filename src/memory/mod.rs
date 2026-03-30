// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of memory management for generic ZKBoo backends.

mod allocset;
mod memory_manager;

pub use allocset::AllocSet;
pub use memory_manager::{FlexibleMemoryManager, MemoryManager, RefCount};
