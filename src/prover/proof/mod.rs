// SPDX-License-Identifier: LGPL-3.0-or-later

//! Proof building logic for the ZKBoo prover.

mod builder;
pub mod collectors;
mod functions;
mod response;

pub use builder::ProofBuilder;
#[cfg(feature = "rayon")]
pub use functions::par_build_proof;
pub use functions::{build_proof, build_proof_custom};
pub use response::{Proof, Response};
