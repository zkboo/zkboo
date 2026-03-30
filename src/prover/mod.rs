// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the ZKBoo proof generation logic.

pub mod challenge;
mod functions;
pub mod proof;
pub mod views;

#[cfg(feature = "parallel")]
pub use functions::par_prove;
pub use functions::{prove, prove_custom};
