// SPDX-License-Identifier: LGPL-3.0-or-later

//! Trait for (pseudo-)random generators (PRGs) and implementation of a hash-based PRG.

use crate::word::Word;
use crate::{crypto::Hasher, word::CompositeWord};
use alloc::vec;
use alloc::vec::Vec;
use core::{array, fmt::Debug};
use zeroize::{Zeroize, Zeroizing};

/// Trait for a random byte generator.
///
/// Implementations must provide the [RandomGenerator::fill_bytes] method.
/// Default implementations are provided for generating arrays and vectors of random bytes.
/// Additional default implementations are provided for the [GeneratesRandom] trait.
pub trait RandomGenerator: Debug {
    /// Fill the given slice `out` with random bytes.
    fn fill_bytes(&mut self, out: &mut [u8]);

    /// Generates a single random byte.
    fn next_byte(&mut self) -> u8 {
        return self.next_bytes::<1>()[0];
    }

    /// Generates an array of `N` random bytes, where `N` is a compile-time constant.
    fn next_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill_bytes(&mut out);
        return out;
    }

    /// Generates a vector of `n` random bytes.
    fn next_bytes_vec(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        self.fill_bytes(&mut out);
        return out;
    }
}

/// Trait to specify that a [RandomGenerator] can generate a random value of the given type.
///
/// Any [RandomGenerator] has implementations generating random values for all [Word] types.
pub trait GeneratesRandom<T> {
    /// Generate the next random value of type `T`.
    fn next(&mut self) -> T;

    /// Generate a vector of `n` random values of type `T`.
    fn next_vec(&mut self, n: usize) -> Vec<T> {
        return (0..n).into_iter().map(|_| self.next()).collect();
    }
}

impl<R: RandomGenerator, W: Word> GeneratesRandom<W> for R {
    /// Generates the next random value of given [Word] type `W` from sampled little-endian bytes.
    fn next(&mut self) -> W {
        let mut b = W::Bytes::default();
        self.fill_bytes(b.as_mut());
        return W::from_le_bytes(b);
    }
}

impl<R: RandomGenerator, W: Word, const N: usize> GeneratesRandom<CompositeWord<W, N>> for R {
    /// Generates the next random value of given [CompositeWord] type `CompositeWord<W, N>`
    /// from sampled little-endian bytes.
    fn next(&mut self) -> CompositeWord<W, N> {
        let mut bs = [W::Bytes::default(); N];
        bs.iter_mut().for_each(|b| self.fill_bytes(b.as_mut()));
        return CompositeWord::<W, N>::from_le_bytes(bs);
    }
}

/// Trait for a pseudo-random generator, as a random generator seeded with initial entropy.
///
/// Generator instances with the same seed entropy must produce the same stream of random bytes.
pub trait PseudoRandomGenerator: RandomGenerator {
    /// Create a new PRG instance seeded with the given `seed`.
    fn new(seed: &[u8]) -> Self;
}

/// Hash-based implementation of a pseudo-random generator (PRG).
///
/// At PRG creation time, the `seed` bytes passed to [PseudoRandomGenerator::new] are hashed
/// to produce a fixed-size `key = h(seed)`, using the chosen hash function `h` (implemented by the
/// specified [Hasher] type `H`).
///
/// An internal buffer of random bytes if filled by `h(key||counter)`, where `counter` is a 64-bit
/// unsigned integer starting at 0 and incremented each time the buffer is refilled;
/// the little-endian byte representation of `counter` is used when concatenating to `key`.
///
/// The implementation of [RandomGenerator::fill_bytes] produces random bytes by consuming the
/// internal buffer, refilling it once empty and incrementing `counter` by 1.
///
/// As an example, the first filling of the buffer is `h(key||00 00 00 00 00 00 00 00)`,
/// the second filling of the buffer is `h(key||01 00 00 00 00 00 00 00)`, and so on.
#[derive(Debug)]
pub struct HashPRG<H: Hasher> {
    hasher: H,
    key: Zeroizing<H::Digest>,
    counter: u64,
    buf: Zeroizing<H::Digest>,
    pos: usize,
}

impl<H: Hasher> PseudoRandomGenerator for HashPRG<H> {
    /// Create a new hash-based PRG instance seeded with the given `seed`.
    fn new(seed: &[u8]) -> Self {
        assert!(
            H::DIGEST_SIZE > 0,
            "Hasher digest size must be greater than zero"
        );
        let mut hasher = H::new();
        hasher.update(seed);
        let key = hasher.finalize();
        return Self {
            hasher,
            key: Zeroizing::new(key),
            counter: 0,
            buf: Zeroizing::new(H::Digest::default()),
            pos: H::DIGEST_SIZE,
        };
    }
}

impl<H: Hasher> HashPRG<H> {
    /// Returns the number of available bytes in the internal buffer.
    pub fn available_bytes(&self) -> usize {
        return H::DIGEST_SIZE - self.pos;
    }

    /// Returns whether the internal buffer is currently empty,
    /// i.e., whether a refill will be performed on the next read.
    pub fn is_buffer_empty(&self) -> bool {
        return self.pos == H::DIGEST_SIZE;
    }

    /// Refill the internal buffer with new random bytes.
    pub fn refill_buffer(&mut self) {
        self.hasher.update(self.key.as_ref());
        self.hasher.update(&self.counter.to_le_bytes());
        self.buf = Zeroizing::new(self.hasher.finalize());
        self.counter += 1;
        self.pos = 0;
    }
}

impl<H: Hasher> RandomGenerator for HashPRG<H> {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        // Refill if empty.
        if self.is_buffer_empty() {
            self.refill_buffer();
        }
        // Fast path: enough bytes available in buffer.
        if out.len() < self.available_bytes() {
            out.copy_from_slice(&self.buf.as_ref()[self.pos..self.pos + out.len()]);
            self.pos += out.len();
            return;
        }
        // Slow path: copy in chunks, refilling buffer as needed.
        let mut written = 0;
        while written < out.len() {
            if self.is_buffer_empty() {
                self.refill_buffer();
            }
            let available = self.available_bytes();
            let needed = out.len() - written;
            let n = core::cmp::min(available, needed);
            out[written..written + n].copy_from_slice(&self.buf.as_ref()[self.pos..self.pos + n]);
            self.pos += n;
            written += n;
        }
    }

    // A more efficient implementation of next_byte().
    fn next_byte(&mut self) -> u8 {
        if self.is_buffer_empty() {
            self.refill_buffer();
        }
        let byte = self.buf.as_ref()[self.pos];
        self.pos += 1;
        return byte;
    }
}

/// Trait for seeds used to initialize [PseudoRandomGenerator]s.
///
/// The trait bounds are chosen to exactly match those of [Digest](crate::crypto::Digest),
/// since PRG seeds are typically implemented using hash digests.
pub trait Seed:
    AsMut<[u8]> + AsRef<[u8]> + Clone + PartialEq + Eq + Default + Zeroize + Debug + Sized
{
}
impl<T> Seed for T where
    T: AsMut<[u8]> + AsRef<[u8]> + Clone + PartialEq + Eq + Default + Zeroize + Debug + Sized
{
}

impl<R: RandomGenerator, S: Seed> GeneratesRandom<[S; 3]> for R {
    /// Generates the next random seed triple.
    fn next(&mut self) -> [S; 3] {
        let mut out: [S; 3] = array::from_fn(|_| S::default());
        for seed in out.iter_mut() {
            self.fill_bytes(seed.as_mut());
        }
        return out;
    }
}
