// SPDX-License-Identifier: LGPL-3.0-or-later

//! Keccak-256 hasher: the original Keccak (padding byte `0x01`), not NIST SHA3-256.

use core::fmt::{self, Debug};

use tiny_keccak::{Hasher as _, Keccak};
use zeroize::Zeroize;

use crate::crypto::Hasher;

/// A [Hasher] backed by Keccak-256 (Ethereum's `keccak256`), producing 32-byte digests.
pub struct Keccak256Hasher {
    inner: Keccak,
}

impl Debug for Keccak256Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.write_str("Keccak256Hasher");
    }
}

impl Hasher for Keccak256Hasher {
    type Digest = [u8; 32];
    const DIGEST_SIZE: usize = 32;

    fn new() -> Self {
        return Self {
            inner: Keccak::v256(),
        };
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_into(&mut self, out: &mut Self::Digest) {
        // `Keccak::finalize` consumes the sponge; swap in a fresh state so the hasher stays
        // reusable after finalization (as the [Hasher] contract requires).
        let inner = core::mem::replace(&mut self.inner, Keccak::v256());
        inner.finalize(out);
    }
}

impl Zeroize for Keccak256Hasher {
    fn zeroize(&mut self) {
        // Drop the current sponge state by replacing it with a fresh one.
        self.inner = Keccak::v256();
    }
}
