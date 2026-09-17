// SPDX-License-Identifier: LGPL-3.0-or-later

//! Checks that options values can be reused whatever the hook type.

use core::cell::Cell;
use zkboo::{
    backend::BackendHook,
    crypto::Hasher,
    executor::ExecOptions,
    prover::{challenge::ChallengeOptions, proof::ProofOptions},
    verifier::VerifyOptions,
    word::Shape,
};

#[path = "common/hasher.rs"]
mod hasher;
use hasher::Blake3Hasher;

type S = <Blake3Hasher as Hasher>::Digest;

/// A hook that is neither [Clone] nor [Copy].
#[derive(Debug)]
struct UncloneableHook<'c> {
    counter: &'c Cell<usize>,
}

impl<'c> BackendHook for UncloneableHook<'c> {
    type InitArg = &'c Cell<usize>;

    fn new(counter: Self::InitArg) -> Self {
        return Self { counter };
    }

    fn post_bitand(&mut self) {
        self.counter.set(self.counter.get() + 1);
    }
}

fn copy_twice<T: Copy>(value: T) -> (T, T) {
    return (value, value);
}

#[test]
fn execution_options_are_copy() {
    let counter = Cell::new(0);
    let options = ExecOptions::new().with_hook_arg::<UncloneableHook>(&counter);
    let (a, b) = copy_twice(options);
    assert!(core::ptr::eq(a.hook_arg(), b.hook_arg()));
}

#[test]
fn verification_options_are_copy() {
    let counter = Cell::new(0);
    let options = VerifyOptions::new().with_hook_arg::<UncloneableHook>(&counter);
    let (a, b) = copy_twice(options);
    assert!(core::ptr::eq(a.hook_arg(), b.hook_arg()));
}

#[test]
fn challenge_options_are_copy() {
    let counter = Cell::new(0);
    let options = ChallengeOptions::<S, S>::new().with_hook_arg::<UncloneableHook>(&counter);
    let (a, b) = copy_twice(options);
    assert!(core::ptr::eq(a.hook_arg(), b.hook_arg()));
}

#[test]
fn proof_options_are_clone() {
    let counter = Cell::new(0);
    let mut capacity = Shape::zero();
    capacity.u8 = 7;
    let options = ProofOptions::<S, S>::new()
        .with_hook_arg::<UncloneableHook>(&counter)
        .with_capacity(capacity);
    let copy = options.clone();
    assert!(core::ptr::eq(options.hook_arg(), copy.hook_arg()));
    assert_eq!(options.capacity(), copy.capacity());
}
