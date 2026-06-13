// SPDX-License-Identifier: LGPL-3.0-or-later

//! Domain-separation tags and the framing that absorbs them.

use crate::crypto::Hasher;

/// The domain-separation tag of the Fiat-Shamir challenge transcript.
pub const TAG_CHALLENGE: &[u8] = b"ZKBOO-CHALLENGE";

/// The domain-separation tag of a party's view commitment.
pub const TAG_VIEW_COMMITMENT: &[u8] = b"ZKBOO-VIEW-COMMITMENT";

/// The domain-separation tag of the hash-based pseudo-random generator.
pub const TAG_PRG: &[u8] = b"ZKBOO-PRG";

/// Absorbs a domain tag and a length-prefixed byte string into the given hasher.
pub fn absorb_framed<H: Hasher>(hasher: &mut H, tag: &[u8], bytes: &[u8]) {
    hasher.update(tag);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
