// SPDX-License-Identifier: LGPL-3.0-or-later

//! [`WordRef::wide_square`] against [`WordRef::wide_mul`], which it must reproduce exactly.
//!
//! The squarer exploits `a_i · a_i = a_i` to narrow each partial-product row to the limbs above
//! the bit that generated it, so its rows shrink as the square is built. That is a bit-level
//! rearrangement of the same sum, and the only convincing check is that it agrees with the
//! multiplier bit for bit — at the corners as well as at random.

use zkboo::{
    backend::{Backend, Frontend, WordRef},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
    word::{CompositeWord, Word, Words},
};

type WP = OwnedFlexibleWordPool<usize>;

/// Outputs `1` iff `wide_square(a)` equals `wide_mul(a, a)`, both halves.
struct SquareEqMul<W: Word, const N: usize> {
    a: CompositeWord<W, N>,
}

impl<W: Word, const N: usize> Circuit for SquareEqMul<W, N> {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let a: WordRef<B, W, N> = fe.input(self.a);
        let (squared_low, squared_high) = a.clone().wide_square();
        let (product_low, product_high) = a.clone().wide_mul(a);
        let matches = squared_low.eq(product_low) & squared_high.eq(product_high);
        fe.output(matches.into());
    }
}

fn ok() -> Words {
    let mut expected = Words::new();
    expected.as_vec_mut::<u8>().push(1u8);
    return expected;
}

fn check<W: Word, const N: usize>(a: CompositeWord<W, N>) {
    assert_eq!(
        exec::<_, WP>(&SquareEqMul { a }),
        ok(),
        "wide_square disagrees with wide_mul for {a:?}"
    );
}

/// A cheap deterministic spread of values, plus the corners.
fn samples<W: Word, const N: usize>() -> Vec<CompositeWord<W, N>> {
    let one = CompositeWord::<W, N>::ONE;
    let mut values = vec![
        CompositeWord::<W, N>::ZERO,
        one,
        CompositeWord::MAX,
        CompositeWord::MAX.wrapping_sub(one),
        one << (W::WIDTH * N - 1),
        (one << (W::WIDTH * N - 1)).wrapping_sub(one),
        one << W::WIDTH,
        (one << W::WIDTH).wrapping_sub(one),
    ];
    // A few structured values that exercise every limb boundary.
    let mut state = one;
    for _ in 0..6 {
        state = state
            .wrapping_mul(CompositeWord::from_le_words(core::array::from_fn(|i| {
                if i == 0 { W::MAX } else { W::ZERO }
            })))
            .wrapping_add(CompositeWord::from_le_words(core::array::from_fn(|i| {
                if i == 0 { W::ONE } else { W::ZERO }
            })));
        values.push(state);
    }
    return values;
}

#[cfg(feature = "u64")]
#[test]
fn squaring_matches_multiplication_at_u64x4() {
    for a in samples::<u64, 4>() {
        check(a);
    }
}

#[test]
fn squaring_matches_multiplication_at_other_widths() {
    for a in samples::<u8, 1>() {
        check(a);
    }
    for a in samples::<u8, 3>() {
        check(a);
    }
    #[cfg(feature = "u32")]
    for a in samples::<u32, 2>() {
        check(a);
    }
}

#[test]
fn squaring_is_exhaustively_correct_at_eight_bits() {
    for a in 0..=u8::MAX {
        check(CompositeWord::<u8, 1>::from_le_words([a]));
    }
}

#[test]
fn squaring_is_exhaustively_correct_at_the_narrowest_width_that_narrows() {
    // The point of the squarer is that its rows shrink, discarding the high limbs of the carry-save
    // accumulator as they go. At one limb nothing ever shrinks, so the exhaustive test above — and
    // every structured sample of the two above it — leaves the interesting part uncovered. Two
    // limbs is the smallest width where a row narrows, and at eight-bit limbs it is exhaustible.
    for high in 0..=u8::MAX {
        for low in 0..=u8::MAX {
            check(CompositeWord::<u8, 2>::from_le_words([low, high]));
        }
    }
}

/// A seeded xorshift, so a failure here is reproducible without a dependency's idea of a seed.
fn pseudo_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

#[test]
fn squaring_survives_repeated_narrowing() {
    // Two limbs narrow exactly once, and only ever from two limbs to one, so the exhaustive test
    // above cannot show a row shrinking while several limbs remain, nor two shrinks in a row. Four
    // eight-bit limbs shrink three times and cannot be exhausted, so sweep them instead — biased
    // towards the limb boundaries and the all-ones and power-of-two neighbourhoods where a
    // misplaced carry-save spill is likeliest to show.
    let mut state = 0x2545_f491_4f6c_dd1d;
    for _ in 0..2_000 {
        let bytes: [u8; 4] = core::array::from_fn(|_| {
            let draw = pseudo_random(&mut state);
            let shift = ((draw >> 8) % 8) as u32;
            return match draw % 5 {
                0 => 0x00,
                1 => 0xFF,
                2 => 1u8 << shift,
                3 => (1u8 << shift).wrapping_sub(1),
                _ => (draw >> 8) as u8,
            };
        });
        check(CompositeWord::<u8, 4>::from_le_words(bytes));
    }
}
