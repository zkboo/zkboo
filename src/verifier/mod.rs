// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the ZKBoo proof verification logic.

mod functions;
pub mod replay;
mod verifier;

#[cfg(feature = "parallel")]
pub use functions::par_verify;
pub use functions::verify;
pub use verifier::Verifier;
