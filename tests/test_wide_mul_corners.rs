// SPDX-License-Identifier: LGPL-3.0-or-later

//! Deterministic corner-case coverage for the in-circuit [`WordRef::wide_mul`].
//!
//! The random differential in `test_wide_binops` checks the in-circuit product against the host
//! `CompositeWord::wide_mul`, but its operands are random: extreme pairs such as `MAX * MAX` are
//! hit only probabilistically. `MAX * MAX` is exactly the input that exercises the top bit of the
//! carry-save majority word, so a bug that stored the running carry shifted (`maj << 1`) rather
//! than unshifted would drop that bit and silently corrupt the high word. This test pins every such
//! corner pair deterministically, and checks the result against `num_bigint` — an oracle fully
//! independent of both the circuit backend and the host multiplier.

mod common;

use num_bigint::BigUint;
use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
    word::{CompositeWord, Word, Words},
};

use crate::common::proofs::test_proof;

type WP = OwnedFlexibleWordPool<usize>;

/// Circuit computing the wide (double-width) product `(lo, hi) = a * b` of two secret inputs.
struct WideMul<W: Word, const N: usize> {
    a: CompositeWord<W, N>,
    b: CompositeWord<W, N>,
}

impl<W: Word, const N: usize> Circuit for WideMul<W, N> {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let a = frontend.input(self.a);
        let b = frontend.input(self.b);
        let (lo, hi) = a.wide_mul(b);
        frontend.output(lo);
        frontend.output(hi);
    }
}

/// Number of bytes in a `CompositeWord<W, N>`.
fn byte_width<W: Word, const N: usize>() -> usize {
    return (W::WIDTH / 8) * N;
}

/// Reduces a [`BigUint`] modulo `2^(8 * byte_width)` and packs its little-endian bytes into a word.
fn word_from_biguint<W: Word, const N: usize>(value: &BigUint) -> CompositeWord<W, N> {
    let word_bytes = W::WIDTH / 8;
    let mut le = value.to_bytes_le();
    le.resize(byte_width::<W, N>(), 0);
    let mut buf = [W::Bytes::default(); N];
    for (i, slot) in buf.iter_mut().enumerate() {
        slot.as_mut()
            .copy_from_slice(&le[i * word_bytes..(i + 1) * word_bytes]);
    }
    return CompositeWord::<W, N>::from_le_bytes(buf);
}

/// The deterministic corner values for a given bit width, as arbitrary-precision integers.
fn corner_values(bit_width: usize) -> Vec<BigUint> {
    let byte_width = bit_width / 8;
    let one = BigUint::from(1u32);
    let max = (&one << bit_width) - &one;
    return vec![
        BigUint::ZERO,
        one.clone(),
        BigUint::from(2u32),
        max.clone(),
        &max - &one,
        &one << (bit_width - 1),
        (&one << (bit_width - 1)) + &one,
        &one << (bit_width / 2),
        (&one << (bit_width / 2)) - &one,
        (&one << (bit_width / 2)) + &one,
        BigUint::from_bytes_le(&vec![0xAAu8; byte_width]),
        BigUint::from_bytes_le(&vec![0x55u8; byte_width]),
    ];
}

/// Runs every ordered pair of corner values through the circuit and checks the low/high words
/// against the `num_bigint` product. The ordered-pair sweep also covers commutativity, since both
/// `(a, b)` and `(b, a)` are checked against the same (symmetric) oracle.
fn check_wide_mul_corners<W: Word, const N: usize>() {
    let bit_width = W::WIDTH * N;
    let modulus = BigUint::from(1u32) << bit_width;
    let corners = corner_values(bit_width);
    for a_big in corners.iter() {
        for b_big in corners.iter() {
            let a = word_from_biguint::<W, N>(a_big);
            let b = word_from_biguint::<W, N>(b_big);
            let circuit = WideMul { a, b };
            let outputs = exec::<_, WP>(&circuit);
            let product = a_big * b_big;
            let lo = word_from_biguint::<W, N>(&(&product % &modulus));
            let hi = word_from_biguint::<W, N>(&(&product >> bit_width));
            let mut expected = Words::new();
            expected.as_vec_mut::<W>().extend(lo.to_le_words());
            expected.as_vec_mut::<W>().extend(hi.to_le_words());
            assert_eq!(
                outputs, expected,
                "wide_mul mismatch for {a_big} * {b_big} at width {bit_width}"
            );
            test_proof(&circuit);
        }
    }
}

#[test]
fn test_wide_mul_corners() {
    check_wide_mul_corners::<u8, 1>();
    check_wide_mul_corners::<u8, 2>();
    check_wide_mul_corners::<u8, 3>();
    check_wide_mul_corners::<u8, 4>();
    #[cfg(feature = "u16")]
    {
        check_wide_mul_corners::<u16, 1>();
        check_wide_mul_corners::<u16, 4>();
    }
    #[cfg(feature = "u32")]
    {
        check_wide_mul_corners::<u32, 1>();
        check_wide_mul_corners::<u32, 4>();
    }
    #[cfg(feature = "u64")]
    {
        check_wide_mul_corners::<u64, 1>();
        check_wide_mul_corners::<u64, 2>();
        check_wide_mul_corners::<u64, 3>();
        check_wide_mul_corners::<u64, 4>();
    }
    #[cfg(feature = "u128")]
    {
        check_wide_mul_corners::<u128, 1>();
        check_wide_mul_corners::<u128, 4>();
    }
}
