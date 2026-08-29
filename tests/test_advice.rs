// SPDX-License-Identifier: LGPL-3.0-or-later

//! Prover-supplied advice, and why it is worth nothing without an assertion.
//!
//! Advice is a value the prover knows and the verifier does not, which is the definition of an
//! input — so it enters a circuit through [Frontend::input] like any other witness, computed on the
//! host where the prover has the witness to compute it from. The library has no advice gate and
//! needs none.
//!
//! What the prover may put there is *anything*. A circuit that relies on advice must pin it down
//! with in-circuit assertions, and the last test here is the one that shows why: advice without an
//! assertion constrains nothing at all, and a proof of a circuit that uses it proves less than it
//! appears to.

use zeroize::Zeroize;
use zkboo::{
    backend::{Backend, Frontend},
    circuit::{Assertions, Circuit},
    crypto::{HashPRG, Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{prove, views::OwnedFlexibleWordTriplePool},
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
    word::{CompositeWord, Words},
};

#[derive(Debug)]
struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Hasher for Blake3Hasher {
    type Digest = [u8; 32];
    const DIGEST_SIZE: usize = 32;
    fn new() -> Self {
        return Self {
            inner: blake3::Hasher::new(),
        };
    }
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    fn finalize_into(&mut self, out: &mut Self::Digest) {
        let result = self.inner.finalize();
        out.copy_from_slice(result.as_bytes());
        self.inner.reset();
    }
}

impl Zeroize for Blake3Hasher {
    fn zeroize(&mut self) {
        self.inner.reset();
    }
}

type H = Blake3Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WP = OwnedFlexibleWordPool<usize>;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

const SEED_ENTROPY: &[u8] = b"advice test seed entropy";
const BINDING: &[u8] = b"advice test binding";
const NUM_ITERS: usize = 16;

type Word4 = CompositeWord<u8, 4>;

fn flag(value: u8) -> Words {
    let mut words = Words::new();
    words.as_vec_mut::<u8>().push(value);
    return words;
}

/// The shape every real use of advice takes: the prover supplies a value it computed on the host,
/// and the circuit asserts the property it needs of it.
///
/// Here the advice is `a & b`, which is cheap either way — the point is the structure, not the
/// saving. In `zkboo-modular` it is a modular inverse, which costs one multiplication to check and
/// a full exponentiation to compute.
struct AdvisedAnd {
    a: Word4,
    b: Word4,
    /// The prover's claimed `a & b`. An ordinary input: nothing stops the prover choosing it.
    advice: Word4,
    /// When set, the circuit uses the advice and asserts nothing about it.
    unconstrained: bool,
}

impl AdvisedAnd {
    /// The prover's view: advice computed on the host, from the witness it already holds.
    fn honest(a: Word4, b: Word4) -> Self {
        return Self {
            a,
            b,
            advice: a & b,
            unconstrained: false,
        };
    }

    /// A prover that supplies something else.
    fn dishonest(a: Word4, b: Word4) -> Self {
        return Self {
            a,
            b,
            advice: (a & b) ^ Word4::ONE,
            unconstrained: false,
        };
    }

    /// The verifier's view: the same circuit, with the advice slot filled by anything at all.
    /// Input *values* are discarded on replay; only the circuit's structure has to match.
    fn without_values() -> Self {
        return Self {
            a: Word4::ZERO,
            b: Word4::ZERO,
            advice: Word4::ZERO,
            unconstrained: false,
        };
    }
}

impl Circuit for AdvisedAnd {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let mut asserts = Assertions::new();
        let a = fe.input(self.a);
        let b = fe.input(self.b);
        let advice = fe.input(self.advice);
        if !self.unconstrained {
            advice.eq(a & b).assert_into(&mut asserts);
        }
        asserts.output(fe);
    }
}

#[test]
fn honest_advice_satisfies_the_assertion() {
    assert_eq!(
        exec::<_, WP>(&AdvisedAnd::honest(Word4::MAX, Word4::ONE)),
        flag(1)
    );
}

#[test]
fn dishonest_advice_violates_the_assertion() {
    assert_eq!(
        exec::<_, WP>(&AdvisedAnd::dishonest(Word4::MAX, Word4::ONE)),
        flag(0)
    );
}

#[test]
fn a_dishonest_prover_cannot_pass_its_advice_off_as_honest() {
    let dishonest = AdvisedAnd::dishonest(Word4::MAX, Word4::ONE);
    let proof = prove::<_, H, PS, PV, S, WTP>(&dishonest, NUM_ITERS, SEED_ENTROPY, BINDING);
    // The verifier runs the circuit and expects the flag an honest statement carries.
    let is_valid = verify::<_, H, PV, S, WPP>(
        &AdvisedAnd::without_values(),
        &flag(1),
        &proof,
        BINDING,
    )
    .expect("error verifying the dishonest proof");
    assert!(!is_valid, "dishonest advice passed an assertion");
}

#[test]
fn the_verifier_needs_the_shape_of_the_advice_and_never_its_value() {
    // This is what makes advice-as-input work: the verifier constructs the same circuit with the
    // advice slot empty, because a replay discards every input value it is given.
    let honest = AdvisedAnd::honest(Word4::MAX, Word4::ONE);
    let proof = prove::<_, H, PS, PV, S, WTP>(&honest, NUM_ITERS, SEED_ENTROPY, BINDING);
    let is_valid = verify::<_, H, PV, S, WPP>(
        &AdvisedAnd::without_values(),
        &flag(1),
        &proof,
        BINDING,
    )
    .expect("error verifying the honest proof");
    assert!(
        is_valid,
        "a verifier holding no advice values failed to verify an honest proof"
    );
}

/// The hazard, made executable: **advice not covered by an assertion constrains nothing.**
///
/// The circuit below uses the advice and asserts nothing about it, so a prover that supplies
/// something other than `a & b` still produces a flag of `1` and a proof that verifies. The proof
/// is perfectly valid — it simply attests to a circuit that never checked what it was given.
/// Nothing in the library can catch this; only the discipline of asserting every advice input can.
#[test]
fn advice_without_an_assertion_constrains_nothing() {
    let mut lying = AdvisedAnd::dishonest(Word4::MAX, Word4::ONE);
    lying.unconstrained = true;
    assert_eq!(
        exec::<_, WP>(&lying),
        flag(1),
        "an unasserted circuit somehow noticed the advice was wrong"
    );
    let proof = prove::<_, H, PS, PV, S, WTP>(&lying, NUM_ITERS, SEED_ENTROPY, BINDING);
    let mut verifier_view = AdvisedAnd::without_values();
    verifier_view.unconstrained = true;
    let is_valid = verify::<_, H, PV, S, WPP>(&verifier_view, &flag(1), &proof, BINDING)
        .expect("error verifying the unconstrained proof");
    assert!(
        is_valid,
        "the point of this test is that it *does* verify: unasserted advice is free"
    );
}
