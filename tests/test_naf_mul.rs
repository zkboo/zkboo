// SPDX-License-Identifier: LGPL-3.0-or-later

//! Structured edge-case tests for the NAF-recoded constant multiplications
//! [`WordRef::wide_mul_const`] and [`WordRef::wrapping_mul_const`].
//!
//! The random oracle tests in `test_wide_binops`/`test_binops` already check `*_const == *_var`
//! on uniform samples, but the NAF recoding has special behaviour at structured constants —
//! zero, one, all-ones (`2^width - 1`, whose NAF carries one position past the top bit), exact
//! powers of two, and pseudo-Mersenne primes (very low NAF weight). These are exactly the
//! constants that arise in Montgomery reduction, so we pin them explicitly here.

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{exec, OwnedFlexibleWordPool},
    word::{CompositeWord, Word, Words},
};

type WP = OwnedFlexibleWordPool<usize>;

/// Circuit computing `a.wide_mul_const(k)` and `a.wrapping_mul_const(k)` for a public constant `k`.
struct ConstMul<W: Word, const N: usize> {
    a: CompositeWord<W, N>,
    k: CompositeWord<W, N>,
}

impl<W: Word, const N: usize> Circuit for ConstMul<W, N> {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let a = fe.input(self.a);
        let (lo, hi) = a.clone().wide_mul_const(self.k);
        fe.output(lo);
        fe.output(hi);
        fe.output(a.wrapping_mul_const(self.k));
    }
}

/// Asserts the circuit constant-multiplications agree with the native variable-multiplications.
fn check<W: Word, const N: usize>(a: CompositeWord<W, N>, k: CompositeWord<W, N>) {
    let outputs = exec::<_, WP>(&ConstMul { a, k });

    let (lo, hi) = a.wide_mul(k);
    let low = a.wrapping_mul(k);
    let mut expected = Words::new();
    expected.as_vec_mut::<W>().extend(lo.to_le_words());
    expected.as_vec_mut::<W>().extend(hi.to_le_words());
    expected.as_vec_mut::<W>().extend(low.to_le_words());

    assert_eq!(
        outputs, expected,
        "const-mul mismatch for a={a:?}, k={k:?}",
    );
}

/// Returns a spread of structured + pseudo-random constants for a given composite width.
fn structured<W: Word, const N: usize>() -> Vec<CompositeWord<W, N>> {
    let zero = CompositeWord::<W, N>::ZERO;
    let one = CompositeWord::<W, N>::ONE;
    let max = CompositeWord::<W, N>::MAX; // 2^width - 1, the worst case for NAF carry-out
    let two = one << 1;
    let mut out = vec![zero, one, two, max, max << 1, one << (W::WIDTH * N - 1)];
    // every exact power of two
    for i in 0..(W::WIDTH * N) {
        out.push(one << i);
    }
    // a few "near power of two" values that exercise low-weight NAF (pseudo-Mersenne shape)
    out.push(max.wrapping_sub(one)); // 2^width - 2
    out.push((one << (W::WIDTH * N - 1)).wrapping_sub(one)); // 2^(width-1) - 1 (long run of ones)
    out.push(two.wrapping_add(one)); // 3 = +1·4 - 1 in NAF
    out
}

fn run_width<W: Word, const N: usize>() {
    let consts = structured::<W, N>();
    // a handful of representative multiplicands `a`
    let one = CompositeWord::<W, N>::ONE;
    let a_vals = [
        CompositeWord::<W, N>::ZERO,
        one,
        CompositeWord::<W, N>::MAX,
        (one << (W::WIDTH * N / 2)).wrapping_sub(one),
        one << (W::WIDTH * N - 1),
    ];
    for &a in a_vals.iter() {
        for &k in consts.iter() {
            check(a, k);
        }
    }
}

#[test]
fn naf_mul_u8_1() {
    run_width::<u8, 1>();
}

#[test]
fn naf_mul_u16_2() {
    run_width::<u16, 2>();
}

#[test]
fn naf_mul_u64_4() {
    // secp256k1 width: the field modulus p = 2^256 - 2^32 - 977 and the Montgomery constants.
    let p = CompositeWord::<u64, 4>::from_be_words([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xfffffffefffffc2f,
    ]);
    let n_neg_inv = CompositeWord::<u64, 4>::from_be_words([
        0xc9bd190515538399,
        0x9c46c2c295f2b761,
        0xbcb223fedc24a059,
        0xd838091dd2253531,
    ]);
    let a_vals = [
        CompositeWord::<u64, 4>::ONE,
        CompositeWord::<u64, 4>::MAX,
        p,
        n_neg_inv,
    ];
    for &a in a_vals.iter() {
        check(a, p);
        check(a, p.wrapping_add(CompositeWord::ONE));
        check(a, p.wrapping_sub(CompositeWord::ONE));
        check(a, n_neg_inv);
    }
    run_width::<u64, 4>();
}
