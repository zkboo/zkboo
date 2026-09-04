// SPDX-License-Identifier: LGPL-3.0-or-later

//! Ranged response generation: a prover may emit any half-open sub-range `[start, end)` of a
//! proof's response sequence, skipping the rest, so that a long proof is resumable, retriable, and
//! splittable across several provers sharing the witness. The responses of any partition of
//! `0..num_iters`, concatenated in order, must be byte-identical to the unranged proof over the
//! same entropy — and must verify as that proof.

#![cfg(feature = "keccak")]

use zeroize::Zeroizing;
use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher, Keccak256Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{
        challenge::build_challenge_entropy,
        proof::{Proof, ProofBuilder, collectors::OwnedResponseDataCollector},
        prove,
        views::OwnedFlexibleWordTriplePool,
    },
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
    word::Words,
};
use zkboo::executor::ExecOptions;
use zkboo::prover::proof::ProofOptions;
use zkboo::verifier::VerifyOptions;
use zkboo::prover::challenge::ChallengeOptions;

type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WP = OwnedFlexibleWordPool<usize>;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;
type RDC = OwnedResponseDataCollector<S, S>;

const SEED_ENTROPY: &[u8] = b"ranged prover seed entropy";
const BINDING: &[u8] = b"ranged proving";
const NUM_ITERS: usize = 9;

/// A circuit with both nonlinear gate kinds: `out = (a & b) + c`.
struct AndCarry {
    a: u8,
    b: u8,
    c: u8,
}

impl Circuit for AndCarry {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let a = fe.input(self.a);
        let b = fe.input(self.b);
        let c = fe.input(self.c);
        fe.output((a & b) + c);
    }
}

fn circuit() -> AndCarry {
    return AndCarry {
        a: 0x6E,
        b: 0xD1,
        c: 0x24,
    };
}

/// The challenge entropy of the full `NUM_ITERS`-response proof. Every range of one proof must be
/// built from it: the Fiat-Shamir challenge is global over all iterations, so the challenge phase
/// is run in full regardless of which responses are emitted.
fn challenge_entropy() -> Zeroizing<Vec<u8>> {
    return build_challenge_entropy::<_, H, PS, PV, S, _, WTP, _>(
        &circuit(),
        SEED_ENTROPY,
        BINDING,
        NUM_ITERS,
        ChallengeOptions::new(),
    );
}

/// Builds the responses `[start, end)` of the full proof, skipping the iterations outside the range.
fn ranged(start: usize, end: usize) -> Proof<S, S> {
    let circuit = circuit();
    let mut builder =
        ProofBuilder::<H, PS, PV, S, RDC, WTP>::new(
            SEED_ENTROPY,
            challenge_entropy(),
            NUM_ITERS,
            ProofOptions::new(),
        );
    builder.skip_iters(start);
    let mut responses = Proof::new();
    for _ in start..end {
        let iteration = builder.next_iter().expect("iteration available in range");
        circuit.exec(iteration.view_builder());
        responses.push(iteration.finalize());
    }
    builder.skip_remaining_iters();
    builder.finalize();
    return responses;
}

/// The serialized bytes of each response, the form in which a proof travels.
fn response_bytes(proof: &Proof<S, S>) -> Vec<Vec<u8>> {
    return proof.iter().map(|response| response.as_bytes()).collect();
}

fn expected_output() -> Words {
    return exec::<_, WP, _>(&circuit(), ExecOptions::new());
}

/// Every partition of `0..NUM_ITERS` reassembles the unranged proof exactly, and the reassembled
/// proof verifies.
#[test]
fn ranges_reassemble_the_full_proof() {
    let full = prove::<_, H, PS, PV, S, _, WTP, _>(&circuit(), NUM_ITERS, SEED_ENTROPY, BINDING, ProofOptions::new());
    let full_bytes = response_bytes(&full);
    let singletons: Vec<(usize, usize)> = (0..NUM_ITERS).map(|k| (k, k + 1)).collect();
    let partitions: Vec<Vec<(usize, usize)>> = partitions(singletons);
    for partition in partitions {
        let mut assembled = Proof::new();
        for &(start, end) in &partition {
            assembled.extend(ranged(start, end));
        }
        assert_eq!(
            response_bytes(&assembled),
            full_bytes,
            "partition {partition:?} does not reassemble the full proof"
        );
        assert!(
            verify::<_, H, PV, S, WPP, _>(&circuit(), &expected_output(), &assembled, BINDING, VerifyOptions::new())
                .expect("verification runs"),
            "partition {partition:?} reassembles into a proof that does not verify"
        );
    }
}

/// The partitions of `0..NUM_ITERS` exercised above: the whole range, several splits (including
/// ranges of length one at either end), and the fully singleton partition.
fn partitions(singletons: Vec<(usize, usize)>) -> Vec<Vec<(usize, usize)>> {
    return vec![
        vec![(0, NUM_ITERS)],
        vec![(0, 1), (1, NUM_ITERS)],
        vec![(0, NUM_ITERS - 1), (NUM_ITERS - 1, NUM_ITERS)],
        vec![(0, 4), (4, NUM_ITERS)],
        vec![(0, 3), (3, 6), (6, NUM_ITERS)],
        singletons,
    ];
}

/// All three 2-of-3 openings occur in the pinned proof, so the equality above covers every response
/// layout, not just one.
#[test]
fn every_challenge_is_exercised() {
    let full = prove::<_, H, PS, PV, S, _, WTP, _>(&circuit(), NUM_ITERS, SEED_ENTROPY, BINDING, ProofOptions::new());
    let mut seen = [false; 3];
    for response in &full {
        seen[response.challenge().index()] = true;
    }
    assert_eq!(seen, [true; 3], "not every challenge occurs in the proof");
}

/// Skipping is what aligns a range with the full sequence: the same iterations built without
/// skipping the ones before them draw different seeds and different challenges, and so produce
/// different responses.
#[test]
fn skipping_advances_the_streams() {
    let tail = ranged(4, NUM_ITERS);
    let circuit = circuit();
    let mut builder =
        ProofBuilder::<H, PS, PV, S, RDC, WTP>::new(
            SEED_ENTROPY,
            challenge_entropy(),
            NUM_ITERS,
            ProofOptions::new(),
        );
    let mut unskipped = Proof::new();
    for _ in 4..NUM_ITERS {
        let iteration = builder.next_iter().expect("iteration available");
        circuit.exec(iteration.view_builder());
        unskipped.push(iteration.finalize());
    }
    builder.skip_remaining_iters();
    builder.finalize();
    assert_ne!(
        response_bytes(&tail),
        response_bytes(&unskipped),
        "responses built without skipping match the range, so skipping advanced nothing"
    );
}

/// Skipped iterations count towards finalization, and no iteration is yielded beyond the total.
#[test]
fn skipped_iterations_are_accounted_for() {
    let mut builder =
        ProofBuilder::<H, PS, PV, S, RDC, WTP>::new(
            SEED_ENTROPY,
            challenge_entropy(),
            NUM_ITERS,
            ProofOptions::new(),
        );
    assert_eq!(builder.num_iters_remaining(), NUM_ITERS);
    builder.skip_iters(2);
    assert_eq!(builder.num_iters_skipped(), 2);
    assert_eq!(builder.num_iters_yielded(), 0);
    assert_eq!(builder.num_iters_remaining(), NUM_ITERS - 2);
    let iteration = builder.next_iter().expect("iteration available");
    circuit().exec(iteration.view_builder());
    iteration.finalize();
    assert_eq!(builder.num_iters_yielded(), 1);
    assert_eq!(builder.iter().len(), NUM_ITERS - 3);
    builder = builder
        .try_finalize()
        .expect_err("finalization must fail while iterations remain");
    builder.skip_remaining_iters();
    assert_eq!(builder.num_iters_remaining(), 0);
    assert!(
        builder.next_iter().is_none(),
        "an exhausted builder must yield no further iterations"
    );
    builder.try_finalize().expect("finalization succeeds");
}

/// Skipping past the end of the sequence is a programming error, not a silently truncated proof.
#[test]
#[should_panic(expected = "Cannot skip")]
fn skipping_past_the_end_panics() {
    let mut builder =
        ProofBuilder::<H, PS, PV, S, RDC, WTP>::new(
            SEED_ENTROPY,
            challenge_entropy(),
            NUM_ITERS,
            ProofOptions::new(),
        );
    builder.skip_iters(NUM_ITERS + 1);
}
