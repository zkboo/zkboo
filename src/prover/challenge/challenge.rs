// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of ZKBoo parties, bit-packed party vector, and bit-level challenge generator.

use crate::crypto::{GeneratesRandom, RandomGenerator};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zeroize::DefaultIsZeroes;

/// A party in the three-party MPC-in-the-Head protocol underlying ZKBoo.
///
/// This is a light wrapper for the integer values 0, 1, and 2, with modular [Party::next] logic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Party {
    index: u8,
}

impl DefaultIsZeroes for Party {}

impl Party {
    /// The party index, guaranteed to be 0, 1 or 2.
    pub fn index(&self) -> usize {
        return self.index as usize;
    }

    /// The next party, in round-robin fashion.
    pub fn next(self) -> Self {
        return Party {
            index: (self.index + 1) % 3,
        };
    }
}

impl From<u8> for Party {
    /// Creates a party form an unsigned 8-bit integer, with reduction modulo 3.
    fn from(index: u8) -> Self {
        return Party { index: index % 3 };
    }
}

impl From<usize> for Party {
    /// Creates a party form an unsigned integer, with reduction modulo 3.
    fn from(index: usize) -> Self {
        return Party {
            index: (index % 3) as u8,
        };
    }
}

/// Vector of parties, stored compactly using 2 bits per party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyVec {
    bytes: Vec<u8>,
    len: usize,
}

impl PartyVec {
    /// Creates a new empty party vector.
    pub fn new() -> Self {
        return Self {
            bytes: Vec::new(),
            len: 0,
        };
    }
    /// Creates a new party vector with the given capacity (in number of parties).
    pub fn with_capacity(capacity: usize) -> Self {
        return Self {
            bytes: Vec::with_capacity((capacity + 3) / 4),
            len: 0,
        };
    }

    /// Pushes a party to the end of the vector.
    pub fn push(&mut self, party: Party) {
        let vec = &mut self.bytes;
        if self.len % 4 == 0 {
            vec.push(0u8);
        }
        let (byte_idx, shift) = Self::byte_idx_and_shift(self.len);
        vec[byte_idx] |= party.index << shift;
        self.len += 1;
    }

    /// The party at the given index, or [None] if index is out of bounds.
    pub fn get(&self, index: usize) -> Option<Party> {
        if index >= self.len {
            return None;
        }
        let (byte_idx, shift) = Self::byte_idx_and_shift(index);
        let idx = (self.bytes[byte_idx] >> shift) & 0b11;
        // We are guaranteed that idx is in 0..=2.
        return Some(Party { index: idx });
    }

    /// The length of the party vector (number of parties stored).
    pub fn len(&self) -> usize {
        return self.len;
    }

    /// The byte index and bit shift for a given party index.
    pub fn byte_idx_and_shift(index: usize) -> (usize, u8) {
        let byte_idx = index / 4;
        let bitpair_idx = (index % 4) as u8;
        let shift = 2u8 * (3u8 - bitpair_idx);
        return (byte_idx, shift);
    }

    // /// Converts the party vector into a standard vector of parties.
    // pub fn as_vec(&self) -> Vec<Party> {
    //     let mut parties = Vec::with_capacity(self.len);
    //     for i in 0..self.len {
    //         parties.push(self.get(i).unwrap());
    //     }
    //     return parties;
    // }
}

/// Iterator over parties in a [PartyVec].
#[derive(Debug)]
pub struct PartyIter<'a> {
    vec: &'a PartyVec,
    pos: usize,
}

impl<'a> Iterator for PartyIter<'a> {
    type Item = Party;

    /// Returns the next party in the vector, or [None] if the end is reached.
    fn next(&mut self) -> Option<Party> {
        if self.pos >= self.vec.len {
            return None;
        }
        let (byte_idx, shift) = PartyVec::byte_idx_and_shift(self.pos);
        let idx: u8 = (self.vec.bytes[byte_idx] >> shift) & 0b11;
        self.pos += 1;
        return Some(Party { index: idx });
    }
}

impl<'a> IntoIterator for &'a PartyVec {
    type Item = Party;
    type IntoIter = PartyIter<'a>;

    /// Creates an iterator over the parties in the vector.
    fn into_iter(self) -> Self::IntoIter {
        return PartyIter { vec: self, pos: 0 };
    }
}

/// Adapter for a [RandomGenerator] to sample parties by rejection sampling over bit pairs.
/// Used for challenge generation by the ZKBoo prover.
///
/// The [ChallengeGenerator] samples one byte at a time from the underlying [RandomGenerator],
/// keeping the current byte buffered and extracting 2 bits at a time.
/// Further byte-level buffering may be performed at the level of the [RandomGenerator],
/// e.g. for hash-based PRGs, but this is not the concern of the [ChallengeGenerator].
#[derive(Debug)]
pub struct ChallengeGenerator<R: RandomGenerator> {
    generator: R,
    current_byte: u8,
    bits_used: u8,
}

impl<R: RandomGenerator> ChallengeGenerator<R> {
    /// Creates a new party generator based on the given random generator.
    pub fn new(generator: R) -> Self {
        return ChallengeGenerator {
            generator,
            current_byte: 0,
            bits_used: 8, // 8 => empty buffer, triggers refill on first use
        };
    }
}

impl<R: RandomGenerator> GeneratesRandom<Party> for ChallengeGenerator<R> {
    /// Generates the next [Party], using 2 bits at a time from the internal generator.
    ///
    /// Bit pairs are extracted until a valid party index is found (i.e. `0b11` is rejected).
    fn next(&mut self) -> Party {
        let mut party: u8 = 0b11; // Default invalid value
        while party > 2 {
            if self.bits_used == 8 {
                self.current_byte = self.generator.next_byte();
                self.bits_used = 0;
            }
            party = self.current_byte & 0b11;
            self.current_byte >>= 2;
            self.bits_used += 2;
        }
        return party.into();
    }
}
