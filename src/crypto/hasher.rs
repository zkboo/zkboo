// SPDX-License-Identifier: LGPL-3.0-or-later

//! Traits for cryptographic hashers.

use core::fmt::Debug;
use zeroize::Zeroize;

/// Trait for a hash digest.
pub trait Digest:
    AsMut<[u8]> + AsRef<[u8]> + Clone + PartialEq + Eq + Default + Zeroize + Debug + Sized
{
}
impl<T> Digest for T where
    T: AsMut<[u8]> + AsRef<[u8]> + Clone + PartialEq + Eq + Default + Zeroize + Debug + Sized
{
}

/// Trait for a hasher with fixed-size output digest.
pub trait Hasher: Zeroize + Debug {
    /// Size of the output digest in bytes.
    const DIGEST_SIZE: usize;

    /// Type of the output digest.
    type Digest: Digest;

    /// Creates a new hasher instance with empty internal state.
    fn new() -> Self;

    /// Updates the internal state by ingesting the provided data.
    fn update(&mut self, data: &[u8]);

    /// Writes the output digest into `out` and resets the internal state.
    ///
    /// Note: The hasher can be reused after finalization.
    fn finalize_into(&mut self, out: &mut Self::Digest);

    /// Retrieves the output digest and resets the internal state.
    ///
    /// Note: The hasher can be reused after finalization.
    fn finalize(&mut self) -> Self::Digest {
        let mut out = Default::default();
        self.finalize_into(&mut out);
        return out;
    }

    /// Resets the internal state of the hasher to an empty state.
    fn reset(&mut self) {
        self.finalize();
    }
}
