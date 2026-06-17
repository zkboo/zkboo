// SPDX-License-Identifier: LGPL-3.0-or-later

//! Traits and implementations for cryptographic hashers and pseudo-random generators.

mod domain;
mod hasher;
#[cfg(feature = "keccak")]
mod keccak;
mod prg;

pub use domain::{TAG_CHALLENGE, TAG_PRG, TAG_VIEW_COMMITMENT, absorb_framed};
pub use hasher::{Digest, Hasher};
#[cfg(feature = "keccak")]
pub use keccak::Keccak256Hasher;
pub use prg::{GeneratesRandom, HashPRG, PseudoRandomGenerator, RandomGenerator, Seed};
