// SPDX-License-Identifier: LGPL-3.0-or-later

//! The fast carry path of [Word], against a bit-serial reference.

use zkboo::word::{CompositeWord, Word, WordLike};
/// The bit-serial recurrence, as the reference the fast path must reproduce.
fn carry_reference<W: Word>(p: W, g: W, c: bool) -> (W, bool) {
    let mut carry = W::ZERO;
    let mut mask = W::ONE;
    let mut c: W = W::from_bool(c);
    let mut carry_out: bool = false;
    for _ in 0..W::WIDTH {
        carry = carry ^ c;
        c = c & p;
        c = c ^ (mask & g);
        mask = mask.unbounded_shl(1);
        carry_out = c != W::ZERO;
        c = c.unbounded_shl(1);
    }
    return (carry, carry_out);
}

#[test]
fn the_fast_carry_path_matches_the_bit_serial_one() {
    // Exhaustive over every 8-bit (p, g) pair and both carry-ins, disjoint or not.
    for p in 0..=u8::MAX {
        for g in 0..=u8::MAX {
            for c in [false, true] {
                assert_eq!(
                    Word::carry(p, g, c),
                    carry_reference(p, g, c),
                    "p={p:#04x} g={g:#04x} c={c}"
                );
            }
        }
    }
}

#[test]
fn carries_are_the_carries_of_an_addition() {
    // For any addition the propagate and generate words are disjoint, and the sum is the
    // propagate word XOR the carries.
    for a in [0u8, 1, 0x7F, 0x80, 0xFF, 0x5A, 0xA5] {
        for b in [0u8, 1, 0x7F, 0x80, 0xFF, 0x5A, 0xA5] {
            for c in [false, true] {
                let (carry, carry_out) = Word::carry(a ^ b, a & b, c);
                let wide = a as u16 + b as u16 + c as u16;
                assert_eq!((a ^ b) ^ carry, wide as u8, "a={a} b={b} c={c}");
                assert_eq!(carry_out, wide > 0xFF, "carry out for a={a} b={b} c={c}");
            }
        }
    }
}
