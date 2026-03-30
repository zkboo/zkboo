// SPDX-License-Identifier: LGPL-3.0-or-later

//! Assorted utilities for the crate.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::{
    cell::{RefCell, RefMut},
    fmt::Debug,
};
use zeroize::{Zeroize, Zeroizing};

/// Utility function to encode [usize] to little-endian varint bytes.
pub(crate) fn usize_to_le_varint_bytes(x: usize) -> Vec<u8> {
    let n = (core::mem::size_of::<usize>() * 8 - (x.leading_zeros() as usize) + 7) / 8;
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&x.to_le_bytes()[..n]);
    return bytes;
}

/// Seal traits for this module.
///
/// The following traits are sealed: [ZeroizingIntoInner].
mod seal {
    use super::{Zeroize, Zeroizing};
    pub trait ZeroizingIntoInner<T> {}
    impl<T: Zeroize> ZeroizingIntoInner<T> for Zeroizing<T> {}
}

/// Trait enabling the extraction of the inner value from a [Zeroizing] wrapper.
pub(crate) trait ZeroizingIntoInner<T>: seal::ZeroizingIntoInner<T> {
    /// Consumes the wrapper and returns the inner value, without zeroizing the wrapper's memory.
    fn into_inner(self) -> T;
}

impl<T: Zeroize> ZeroizingIntoInner<T> for Zeroizing<T> {
    fn into_inner(self) -> T {
        return unsafe { core::ptr::read(&**core::mem::ManuallyDrop::new(self)) };
    }
}

/// A reference-counted mutable pointer.
///
/// Implemented as a [RefCell] wrapped into an [Rc], with minimal API.
#[derive(Debug)]
pub(crate) struct RcPtrMut<T> {
    inner: Rc<RefCell<T>>,
}

impl<T> RcPtrMut<T> {
    /// Takes ownership of a value and wraps it into a reference-counted mutable pointer.
    pub fn new(value: T) -> Self {
        return Self {
            inner: Rc::new(RefCell::new(value)),
        };
    }

    // /// Attempts to unwrap the pointer into the inner value, returning the pointer on failure.
    // pub fn try_into_inner(self) -> Result<T, Self> {
    //     return match Rc::try_unwrap(self.inner) {
    //         Ok(ref_cell) => Ok(ref_cell.into_inner()),
    //         Err(inner) => Err(Self { inner }),
    //     };
    // }

    // /// Borrow of the inner value.
    // pub fn borrow(&self) -> Ref<'_, T> {
    //     return self.inner.borrow();
    // }

    /// Mutable borrow of the inner value.
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        return self.inner.borrow_mut();
    }
}

impl<T: Debug> RcPtrMut<T> {
    /// Unwraps the pointer into the inner value, panicking on failure.
    pub fn into_inner(self) -> T {
        return Rc::try_unwrap(self.inner)
            .expect("Failed to unwrap Backend Rc: multiple references exist")
            .into_inner();
    }
}

impl<T> Clone for RcPtrMut<T> {
    /// Clones the pointer, creating a new reference to the same inner value.
    fn clone(&self) -> Self {
        return Self {
            inner: self.inner.clone(),
        };
    }
}

impl<T> PartialEq for RcPtrMut<T> {
    /// Compares two pointers for equality by checking if they point to the same inner value.
    fn eq(&self, other: &Self) -> bool {
        return Rc::ptr_eq(&self.inner, &other.inner);
    }
}

impl<T> Eq for RcPtrMut<T> {}
