// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of type-tagged storage for fixed-width words.

use crate::{
    crypto::Hasher,
    utils::usize_to_le_varint_bytes,
    word::{Shape, Word, on_all_words},
};
use alloc::{vec, vec::Vec};
use core::ops::{BitAnd, BitOr, BitXor, Not};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Storage of words in fixed-width word vectors, type-tagged.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, Serialize, Deserialize)]
pub struct Words {
    pub u8: Vec<u8>,
    #[cfg(feature = "u16")]
    pub u16: Vec<u16>,
    #[cfg(feature = "u32")]
    pub u32: Vec<u32>,
    #[cfg(feature = "u64")]
    pub u64: Vec<u64>,
    #[cfg(feature = "u128")]
    pub u128: Vec<u128>,
}

impl Words {
    /// Generates the flag byte for the currently enabled features.
    pub fn feature_flags(&self) -> u8 {
        let mut feature_flags = 0u8; // u8 word type is always enabled
        on_all_words!(W, {
            if self.as_vec::<W>().len() > 0 {
                feature_flags |= 1 << (W::WIDTH / 8).trailing_zeros();
            }
        });
        return feature_flags;
    }

    /// Reference to the fixed-width word vector of given word type `W`.
    pub fn as_vec<W: Word>(&self) -> &Vec<W> {
        return W::vec_from_words(self);
    }

    /// Mutable reference to the fixed-width word vector of given word type `W`.
    pub fn as_vec_mut<W: Word>(&mut self) -> &mut Vec<W> {
        return W::vec_mut_from_words(self);
    }

    /// Creates a new word store with empty word vectors.
    pub const fn new() -> Self {
        return Self {
            u8: Vec::new(),
            #[cfg(feature = "u16")]
            u16: Vec::new(),
            #[cfg(feature = "u32")]
            u32: Vec::new(),
            #[cfg(feature = "u64")]
            u64: Vec::new(),
            #[cfg(feature = "u128")]
            u128: Vec::new(),
        };
    }

    /// Creates a new word store with the given capacities for each word type.
    pub fn with_capacity(capacities: Shape) -> Self {
        return Self {
            u8: Vec::with_capacity(capacities.u8),
            #[cfg(feature = "u16")]
            u16: Vec::with_capacity(capacities.u16),
            #[cfg(feature = "u32")]
            u32: Vec::with_capacity(capacities.u32),
            #[cfg(feature = "u64")]
            u64: Vec::with_capacity(capacities.u64),
            #[cfg(feature = "u128")]
            u128: Vec::with_capacity(capacities.u128),
        };
    }

    /// Creates a new word store of given shape, with all words initialized to zero.
    pub fn zeros(shape: Shape) -> Self {
        return Self {
            u8: vec![0u8; shape.u8],
            #[cfg(feature = "u16")]
            u16: vec![0u16; shape.u16],
            #[cfg(feature = "u32")]
            u32: vec![0u32; shape.u32],
            #[cfg(feature = "u64")]
            u64: vec![0u64; shape.u64],
            #[cfg(feature = "u128")]
            u128: vec![0u128; shape.u128],
        };
    }

    /// The shape of this word store, i.e., the lengths of the word vectors for each word type.
    pub fn shape(&self) -> Shape {
        let mut shape = Shape::zero();
        on_all_words!(W, {
            *shape.as_value_mut::<W>() = self.as_vec::<W>().len();
        });
        return shape;
    }

    /// The capacity of this word store, i.e., the capacities of the word vectors for each word type.
    pub fn capacity(&self) -> Shape {
        let mut shape = Shape::zero();
        on_all_words!(W, {
            *shape.as_value_mut::<W>() = self.as_vec::<W>().capacity();
        });
        return shape;
    }

    /// Clears all word vectors in this store.
    pub fn clear(&mut self) {
        on_all_words!(W, {
            self.as_vec_mut::<W>().clear();
        });
    }

    /// Updates the given hasher with the binary data of this word store.
    pub fn update_hasher<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(&[self.feature_flags()]);
        on_all_words!(W, {
            let words = self.as_vec::<W>();
            let mut buf: Vec<u8> = Vec::with_capacity(H::DIGEST_SIZE);
            buf.append(&mut usize_to_le_varint_bytes(words.len()));
            for &w in words {
                let w_bytes = w.to_le_bytes();
                if buf.len() + w_bytes.as_ref().len() > H::DIGEST_SIZE {
                    hasher.update(&buf);
                    buf.clear();
                }
                buf.extend_from_slice(w_bytes.as_ref());
            }
            if buf.len() > 0 {
                hasher.update(&buf);
            }
        });
    }

    /// Serializes into a given byte vector.
    pub fn append_bytes(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.feature_flags());
        on_all_words!(W, {
            let word_vec = self.as_vec::<W>();
            bytes.append(&mut usize_to_le_varint_bytes(word_vec.len()));
            bytes.extend(word_vec.iter().flat_map(|&w| W::to_le_bytes(w)));
        });
    }

    /// Serializes as a byte vector.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        self.append_bytes(&mut bytes);
        return bytes;
    }
}

/// Error indicating a shape mismatch.
#[derive(Debug)]
pub struct ShapeError {
    expected: Shape,
    actual: Shape,
}

impl ShapeError {
    /// Creates a new [ShapeError] with the given expected and actual shapes.
    pub fn new(expected: Shape, actual: Shape) -> Self {
        return Self { expected, actual };
    }

    /// Returns the expected shape.
    pub fn expected(&self) -> Shape {
        return self.expected;
    }

    /// Returns the actual shape.
    pub fn actual(&self) -> Shape {
        return self.actual;
    }
}

macro_rules! impl_words_unop {
    ($opname: ident, $func: expr) => {
        fn $opname(self) -> Words {
            let mut result = Words::new();
            result.u8 = self.u8.iter().map($func).collect();
            #[cfg(feature = "u16")]
            {
                result.u16 = self.u16.iter().map($func).collect();
            }
            #[cfg(feature = "u32")]
            {
                result.u32 = self.u32.iter().map($func).collect();
            }
            #[cfg(feature = "u64")]
            {
                result.u64 = self.u64.iter().map($func).collect();
            }
            #[cfg(feature = "u128")]
            {
                result.u128 = self.u128.iter().map($func).collect();
            }
            return result;
        }
    };
}

macro_rules! impl_words_binop {
    ($opname: ident, $func: expr) => {
        fn $opname(self, rhs: Self) -> Result<Words, ShapeError> {
            if self.shape() != rhs.shape() {
                return Err(ShapeError::new(self.shape(), rhs.shape()));
            }
            let mut result = Words::new();
            result.u8 = self.u8.iter().zip(rhs.u8.iter()).map($func).collect();
            #[cfg(feature = "u16")]
            {
                result.u16 = self.u16.iter().zip(rhs.u16.iter()).map($func).collect();
            }
            #[cfg(feature = "u32")]
            {
                result.u32 = self.u32.iter().zip(rhs.u32.iter()).map($func).collect();
            }
            #[cfg(feature = "u64")]
            {
                result.u64 = self.u64.iter().zip(rhs.u64.iter()).map($func).collect();
            }
            #[cfg(feature = "u128")]
            {
                result.u128 = self.u128.iter().zip(rhs.u128.iter()).map($func).collect();
            }
            return Ok(result);
        }
    };
}

impl Not for &Words {
    type Output = Words;
    impl_words_unop!(not, |w| !w);
}

impl BitXor for &Words {
    type Output = Result<Words, ShapeError>;
    impl_words_binop!(bitxor, |(a, b)| a ^ b);
}

impl BitAnd for &Words {
    type Output = Result<Words, ShapeError>;
    impl_words_binop!(bitand, |(a, b)| a & b);
}

impl BitOr for &Words {
    type Output = Result<Words, ShapeError>;
    impl_words_binop!(bitor, |(a, b)| a | b);
}
