// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of mappings keyed by fixed-width word types.

use crate::word::Word;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Mapping of values of type `T` indexed by all possible word types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByWordType<T> {
    pub u8: T,
    #[cfg(feature = "u16")]
    pub u16: T,
    #[cfg(feature = "u32")]
    pub u32: T,
    #[cfg(feature = "u64")]
    pub u64: T,
    #[cfg(feature = "u128")]
    pub u128: T,
}

impl<T> ByWordType<T> {
    /// Creates a new [ByWordType] with the same constant value for each word type.
    pub fn constant(value: T) -> Self
    where
        T: Copy,
    {
        return Self {
            u8: value,
            #[cfg(feature = "u16")]
            u16: value,
            #[cfg(feature = "u32")]
            u32: value,
            #[cfg(feature = "u64")]
            u64: value,
            #[cfg(feature = "u128")]
            u128: value,
        };
    }

    /// Creates a new [ByWordType] by cloning the given value for each word type.
    pub fn clone_constant(value: &T) -> Self
    where
        T: Clone,
    {
        return Self {
            u8: value.clone(),
            #[cfg(feature = "u16")]
            u16: value.clone(),
            #[cfg(feature = "u32")]
            u32: value.clone(),
            #[cfg(feature = "u64")]
            u64: value.clone(),
            #[cfg(feature = "u128")]
            u128: value.clone(),
        };
    }

    /// Reference to the value associated to given word type `W`.
    pub fn as_value<W: Word>(&self) -> &T {
        return W::value_by_word_type(self);
    }

    /// Mutable reference to the value associated to given word type `W`.
    pub fn as_value_mut<W: Word>(&mut self) -> &mut T {
        return W::value_mut_by_word_type(self);
    }

    /// Sets the value associated to given word type `W`, returning the modified [ByWordType].
    pub fn with<W: Word>(mut self, value: T) -> Self {
        *self.as_value_mut::<W>() = value;
        return self;
    }

    /// Returns the [ByWordType] obtained by applying function `f` to each value of type `T`.
    pub fn map<U, F>(&self, mut f: F) -> ByWordType<U>
    where
        F: FnMut(&T) -> U,
    {
        return ByWordType {
            u8: f(&self.u8),
            #[cfg(feature = "u16")]
            u16: f(&self.u16),
            #[cfg(feature = "u32")]
            u32: f(&self.u32),
            #[cfg(feature = "u64")]
            u64: f(&self.u64),
            #[cfg(feature = "u128")]
            u128: f(&self.u128),
        };
    }

    /// Returns the [ByWordType] obtained by applying function `f` to each value of type `T`.
    pub fn map_mut<U, F>(&mut self, mut f: F) -> ByWordType<U>
    where
        F: FnMut(&mut T) -> U,
    {
        return ByWordType {
            u8: f(&mut self.u8),
            #[cfg(feature = "u16")]
            u16: f(&mut self.u16),
            #[cfg(feature = "u32")]
            u32: f(&mut self.u32),
            #[cfg(feature = "u64")]
            u64: f(&mut self.u64),
            #[cfg(feature = "u128")]
            u128: f(&mut self.u128),
        };
    }

    /// Variant of [ByWordType::map] which additionally provides word width to the function.
    pub fn map_with_width<U, F>(&self, mut f: F) -> ByWordType<U>
    where
        F: FnMut(usize, &T) -> U,
    {
        return ByWordType {
            u8: f(8, &self.u8),
            #[cfg(feature = "u16")]
            u16: f(16, &self.u16),
            #[cfg(feature = "u32")]
            u32: f(32, &self.u32),
            #[cfg(feature = "u64")]
            u64: f(64, &self.u64),
            #[cfg(feature = "u128")]
            u128: f(128, &self.u128),
        };
    }

    /// Reduces the values of type `T` using function `f(acc, val)` and initial value `init`.
    /// The function `f` is applied to the value associated to words in increasing order of width.
    pub fn reduce<U, F>(&self, mut f: F, init: U) -> U
    where
        F: FnMut(U, &T) -> U,
    {
        let acc = f(init, &self.u8);
        #[cfg(feature = "u16")]
        let acc = f(acc, &self.u16);
        #[cfg(feature = "u32")]
        let acc = f(acc, &self.u32);
        #[cfg(feature = "u64")]
        let acc = f(acc, &self.u64);
        #[cfg(feature = "u128")]
        let acc = f(acc, &self.u128);
        return acc;
    }

    /// Returns the [ByWordType] obtained by zipping `self` and `other` using function `f`.
    pub fn zip<U, F, V>(&self, other: &ByWordType<U>, mut f: F) -> ByWordType<V>
    where
        F: FnMut(&T, &U) -> V,
    {
        return ByWordType {
            u8: f(&self.u8, &other.u8),
            #[cfg(feature = "u16")]
            u16: f(&self.u16, &other.u16),
            #[cfg(feature = "u32")]
            u32: f(&self.u32, &other.u32),
            #[cfg(feature = "u64")]
            u64: f(&self.u64, &other.u64),
            #[cfg(feature = "u128")]
            u128: f(&self.u128, &other.u128),
        };
    }
}

impl<T> Copy for ByWordType<T> where T: Copy {}

impl<T> Default for ByWordType<T>
where
    T: Default,
{
    /// Creates a new [ByWordType] with default values for each word type.
    fn default() -> Self {
        return Self {
            u8: T::default(),
            #[cfg(feature = "u16")]
            u16: T::default(),
            #[cfg(feature = "u32")]
            u32: T::default(),
            #[cfg(feature = "u64")]
            u64: T::default(),
            #[cfg(feature = "u128")]
            u128: T::default(),
        };
    }
}

/// Creates a [ByWordType](crate::word::ByWordType) of given [Default] type,
/// with the given values assigned to given [Word] types.
///
/// If no value is assigned to a [Word] type, the [Default::default] value is used.
/// Repeated assignments to the same [Word] type result in overwriting.
///
/// ```rust
/// use zkboo::word::{ByWordType, Shape, by_word_type};
/// #[cfg(all(feature = "u16", feature = "u32"))]
/// {
///     let values: ByWordType<usize> = by_word_type!(usize, {
///         u8: 2,
///         u16: 2,
///         u8: 1,
///     });
///     let mut expected_values = ByWordType::default();
///     expected_values.u8 = 1;
///     expected_values.u16 = 2;
///     expected_values.u32 = usize::default();
///     assert_eq!(values, expected_values);
/// }
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! _by_word_type {
    ($ty: ty, {$($key: ident : $value: expr),* $(,)?}) => {{
        use $crate::word::ByWordType;
        let mut res = ByWordType::<$ty>::default();
        $(
            res.$key = $value;
        )*
        res
    }};
}

#[doc(inline)]
pub use _by_word_type as by_word_type;

/// Shape of a word store, i.e., the lengths of the word vectors for each word type.
pub type Shape = ByWordType<usize>;

impl Shape {
    /// Creates a new [Shape] with zero words of each type.
    pub fn zero() -> Self {
        return Shape::default();
    }

    pub fn sum(&self) -> usize {
        return self.reduce(|acc, val| acc + val, 0);
    }
}

/// Creates a [Shape](crate::word::Shape), with the given values assigned to given [Word] types.
///
/// If no value is assigned to a [Word] type, 0 is used.
/// Repeated assignments to the same [Word] type are added together.
/// Note that this behaviour differs from [by_word_type] on [usize],
/// where repeated assignments lead to overwriting.
///
/// ```rust
/// use zkboo::word::{ByWordType, Shape, shape};
/// #[cfg(all(feature = "u16", feature = "u32"))]
/// {
///     let shape: Shape = shape!({
///         u8: 2,
///         u16: 2,
///         u8: 1,
///     });
///     let mut expected_shape = Shape::zero();
///     expected_shape.u8 = 3;
///     expected_shape.u16 = 2;
///     expected_shape.u32 = 0;
///     assert_eq!(shape, expected_shape);
/// }
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! _shape {
    ({$($key: ident : $value: expr),* $(,)?}) => {{
        use $crate::word::Shape;
        let mut res = Shape::zero();
        $(
            res.$key += $value;
        )*
        res
    }};
}

#[doc(inline)]
pub use _shape as shape;

impl<T> ByWordType<Vec<T>> {
    /// Creates a new [ByWordType] with empty vectors for each word type.
    pub fn new() -> Self {
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

    /// Creates a new [ByWordType] with empty vectors for each word type and pre-allocated capacity.
    pub fn with_capacity(capacities: ByWordType<usize>) -> Self {
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

    /// Reference to the vector associated to given word type `W`.
    pub fn as_vec<W: Word>(&self) -> &Vec<T> {
        return self.as_value::<W>();
    }

    /// Mutable reference to the vector associated to given word type `W`.
    pub fn as_vec_mut<W: Word>(&mut self) -> &mut Vec<T> {
        return self.as_value_mut::<W>();
    }

    /// Returns a [ByWordType] containing the lengths of the vectors.
    pub fn shape(&self) -> Shape {
        return self.map(|v| v.len());
    }

    /// Appends the contents of `values` to the vector associated to word type `W`.
    /// The `values` vector is cleared.
    pub fn append<W: Word>(&mut self, values: &mut Vec<T>) {
        self.as_value_mut::<W>().append(values);
    }

    /// Appends the contents of `value` to the vector associated to word type `W`,
    /// returning the modified [ByWordType]. The `values` vector is cleared.
    pub fn with_appended<W: Word>(mut self, values: &mut Vec<T>) -> Self {
        self.append::<W>(values);
        return self;
    }

    /// Pushes `value` to the vector associated to word type `W`.
    pub fn push<W: Word>(&mut self, value: T) {
        self.as_value_mut::<W>().push(value);
    }

    /// Pushes `value` to the vector associated to word type `W`,
    /// returning the modified [ByWordType].
    pub fn with_pushed<W: Word>(mut self, value: T) -> Self {
        self.push::<W>(value);
        return self;
    }
}
