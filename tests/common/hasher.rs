// SPDX-License-Identifier: LGPL-3.0-or-later

use zeroize::Zeroize;
use zkboo::crypto::Hasher;

/// A [Hasher] backed by BLAKE3, producing 32-byte digests.
#[derive(Debug)]
pub struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Hasher for Blake3Hasher {
    type Digest = [u8; 32];
    const DIGEST_SIZE: usize = 32;

    fn new() -> Self {
        return Self {
            inner: blake3::Hasher::new(),
        };
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_into(&mut self, out: &mut Self::Digest) {
        let result = self.inner.finalize();
        out.copy_from_slice(result.as_bytes());
        self.inner.reset();
    }
}

impl Zeroize for Blake3Hasher {
    fn zeroize(&mut self) {
        self.inner.reset();
    }
}
