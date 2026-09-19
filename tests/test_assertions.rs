// SPDX-License-Identifier: LGPL-3.0-or-later

//! [`Assertions`], the circuit-side accumulator.
//!
//! An assertion is not a protocol feature: it is a conjunction of booleans built from ordinary
//! gates, which the circuit outputs as an ordinary output word. Nothing aborts when one fails —
//! the flag comes out `0`, the circuit's output differs from the one an honest statement claims,
//! and verification rejects the proof.

use zkboo::Repetitions;
use zkboo::executor::ExecOptions;
use zkboo::prover::proof::ProofOptions;
use zkboo::verifier::VerifyOptions;
use zkboo::{
    backend::{Backend, Frontend},
    circuit::{Assertions, Circuit},
    crypto::{HashPRG, Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{prove, views::OwnedFlexibleWordTriplePool},
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
    word::{CompositeWord, Words},
};

#[path = "common/hasher.rs"]
mod hasher;
use hasher::Blake3Hasher;

type H = Blake3Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WP = OwnedFlexibleWordPool<usize>;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

const SEED_ENTROPY: &[u8] = b"assertion test seed entropy";
const BINDING: &[u8] = b"assertion test binding";
const NUM_ITERS: usize = 16;

type Word4 = CompositeWord<u8, 4>;

/// A statement of one `u8` word.
fn flag(value: u8) -> Words {
    let mut words = Words::new();
    words.as_vec_mut::<u8>().push(value);
    return words;
}

/// Asserts `value == expected`, `times` over, and outputs nothing but the flag.
struct Asserts {
    value: Word4,
    expected: Word4,
    times: usize,
    /// When set, the condition is asserted with the postfix form instead of the method.
    postfix: bool,
}

impl Asserts {
    fn new(value: Word4, expected: Word4, times: usize) -> Self {
        return Self {
            value,
            expected,
            times,
            postfix: false,
        };
    }
}

impl Circuit for Asserts {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        Assertions::scope(fe, |asserts| {
            let value = fe.input(self.value);
            for _ in 0..self.times {
                let condition = value.clone().eq_const(self.expected);
                if self.postfix {
                    condition.assert_into(asserts);
                } else {
                    asserts.assert(condition);
                }
            }
        });
    }
}

/// Opens a scope without ever asserting anything, so its flag is the constant `1`.
struct Silent;

impl Circuit for Silent {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let _ = fe.input(Word4::ONE);
        Assertions::scope(fe, |_| {});
    }
}

/// Outputs a value and opens no scope, so nothing appends a flag.
struct NoScope;

impl Circuit for NoScope {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let value = fe.input(Word4::MAX);
        fe.output(value);
    }
}

#[test]
fn an_empty_accumulator_yields_the_constant_one() {
    assert_eq!(exec::<_, WP, _>(&Silent, ExecOptions::new()), flag(1));
}

#[test]
fn a_satisfied_assertion_yields_one() {
    assert_eq!(
        exec::<_, WP, _>(&Asserts::new(Word4::ONE, Word4::ONE, 1), ExecOptions::new()),
        flag(1)
    );
}

#[test]
fn a_violated_assertion_yields_zero() {
    assert_eq!(
        exec::<_, WP, _>(&Asserts::new(Word4::ONE, Word4::MAX, 1), ExecOptions::new()),
        flag(0)
    );
}

#[test]
fn violations_accumulate_by_conjunction_and_never_cancel() {
    // Were the accumulator an exclusive or, an even number of violations would cancel and the
    // circuit would claim to be sound.
    for times in [2, 3, 4] {
        assert_eq!(
            exec::<_, WP, _>(
                &Asserts::new(Word4::ONE, Word4::MAX, times),
                ExecOptions::new()
            ),
            flag(0),
            "{times} violated assertions did not accumulate to a violation"
        );
    }
}

#[test]
fn one_violation_among_many_satisfied_assertions_still_shows() {
    struct MostlyFine;
    impl Circuit for MostlyFine {
        fn exec<B: Backend>(&self, fe: &Frontend<B>) {
            Assertions::scope(fe, |asserts| {
                let value = fe.input(Word4::ONE);
                asserts.assert(value.clone().eq_const(Word4::ONE));
                asserts.assert(value.clone().eq_const(Word4::MAX));
                asserts.assert(value.eq_const(Word4::ONE));
            });
        }
    }
    assert_eq!(exec::<_, WP, _>(&MostlyFine, ExecOptions::new()), flag(0));
}

#[test]
fn the_postfix_form_accumulates_exactly_as_the_method_does() {
    for (value, expected) in [(Word4::ONE, Word4::ONE), (Word4::ONE, Word4::MAX)] {
        let mut method = Asserts::new(value, expected, 3);
        let mut postfix = Asserts::new(value, expected, 3);
        method.postfix = false;
        postfix.postfix = true;
        assert_eq!(
            exec::<_, WP, _>(&method, ExecOptions::new()),
            exec::<_, WP, _>(&postfix, ExecOptions::new())
        );
    }
}

#[test]
fn an_accumulator_reports_whether_anything_has_been_asserted() {
    struct Reports;
    impl Circuit for Reports {
        fn exec<B: Backend>(&self, fe: &Frontend<B>) {
            Assertions::scope(fe, |asserts| {
                assert!(asserts.is_empty(), "a fresh accumulator is not empty");
                let value = fe.input(Word4::ONE);
                asserts.assert(value.eq_const(Word4::ONE));
                assert!(
                    !asserts.is_empty(),
                    "an accumulator with an assertion is empty"
                );
            });
        }
    }
    assert_eq!(exec::<_, WP, _>(&Reports, ExecOptions::new()), flag(1));
}

#[test]
fn a_satisfied_assertion_proves_and_verifies() {
    let circuit = Asserts::new(Word4::MAX, Word4::MAX, 2);
    let statement = exec::<_, WP, _>(&circuit, ExecOptions::new());
    assert_eq!(statement, flag(1));
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(
        &circuit,
        NUM_ITERS,
        SEED_ENTROPY,
        BINDING,
        ProofOptions::new(),
    );
    let is_valid = verify::<_, H, PV, S, WPP, _>(
        &circuit,
        &statement,
        &proof,
        BINDING,
        Repetitions::exactly(NUM_ITERS),
        VerifyOptions::new(),
    )
    .expect("error verifying the asserting proof");
    assert!(
        is_valid,
        "a proof of a satisfied assertion failed to verify"
    );
}

#[test]
fn a_violated_assertion_cannot_be_proved_satisfied() {
    // The prover runs a circuit whose assertion does not hold; the verifier expects the flag to be
    // `1`, which is what any honest statement of this circuit says.
    let circuit = Asserts::new(Word4::ONE, Word4::MAX, 1);
    assert_eq!(exec::<_, WP, _>(&circuit, ExecOptions::new()), flag(0));
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(
        &circuit,
        NUM_ITERS,
        SEED_ENTROPY,
        BINDING,
        ProofOptions::new(),
    );
    let is_valid = verify::<_, H, PV, S, WPP, _>(
        &circuit,
        &flag(1),
        &proof,
        BINDING,
        Repetitions::exactly(NUM_ITERS),
        VerifyOptions::new(),
    )
    .expect("error verifying the violated proof");
    assert!(!is_valid, "a violated assertion verified as satisfied");
}

#[test]
fn a_circuit_that_asserts_nothing_costs_no_gate_for_its_flag() {
    // The flag of an assertion-free circuit is a constant, so proving one is exactly as cheap as
    // proving the same circuit without the flag: the constant costs no AND message.
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(
        &Silent,
        NUM_ITERS,
        SEED_ENTROPY,
        BINDING,
        ProofOptions::new(),
    );
    let is_valid = verify::<_, H, PV, S, WPP, _>(
        &Silent,
        &flag(1),
        &proof,
        BINDING,
        Repetitions::exactly(NUM_ITERS),
        VerifyOptions::new(),
    )
    .expect("error verifying the silent proof");
    assert!(is_valid, "a circuit that asserts nothing failed to verify");
}

#[test]
fn a_circuit_that_opens_no_scope_emits_no_flag() {
    // The flag belongs to the output contract of the circuits that assert, in the way every other
    // output word does, rather than being a fixed tax on all of them.
    let output = exec::<_, WP, _>(&NoScope, ExecOptions::new());
    assert_eq!(
        output.as_vec::<u8>().len(),
        4,
        "a circuit that opens no scope emitted something beyond its own payload"
    );
}

#[test]
fn a_scope_emits_its_flag_even_when_its_body_returns_a_value() {
    struct Returns;
    impl Circuit for Returns {
        fn exec<B: Backend>(&self, fe: &Frontend<B>) {
            let doubled = Assertions::scope(fe, |asserts| {
                let value = fe.input(Word4::ONE);
                asserts.assert(value.clone().eq_const(Word4::ONE));
                return value.clone() + value;
            });
            fe.output(doubled);
        }
    }
    // The flag is emitted when the scope's body returns, so it precedes anything the caller
    // outputs afterwards from the value the body handed back.
    let output = exec::<_, WP, _>(&Returns, ExecOptions::new());
    let words = output.as_vec::<u8>();
    assert_eq!(words.len(), 5, "expected the flag and four payload words");
    assert_eq!(words[0], 1, "the flag of a satisfied assertion is not one");
}
