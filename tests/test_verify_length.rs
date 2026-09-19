// SPDX-License-Identifier: LGPL-3.0-or-later

//! Verification requires the number of repetitions it is given.
//!
//! Each response constrains a cheating prover independently, so a proof of fewer responses than a
//! soundness level demands proves proportionally less, and an empty one proves nothing at all.
//! Neither is rejected by replaying responses, only by counting them.

use zkboo::{
    Repetitions,
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher},
    executor::{ExecOptions, OwnedFlexibleWordPool, exec},
    prover::{
        proof::{Proof, ProofOptions},
        prove,
        views::OwnedFlexibleWordTriplePool,
    },
    verifier::{Verifier, VerifyOptions, replay::OwnedFlexibleWordPairPool, verify},
    word::Words,
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

const NUM_ITERS: usize = 8;
const BINDING: &[u8] = b"length binding";

struct XorNot {
    a: u8,
    b: u8,
}

impl Circuit for XorNot {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let a = frontend.input(self.a);
        let b = frontend.input(self.b);
        frontend.output(!(a ^ b));
    }
}

fn circuit() -> XorNot {
    return XorNot { a: 0x5a, b: 0x33 };
}

fn proof_of(num_iters: usize) -> (Words, Proof<S, S>) {
    let c = circuit();
    let output = exec::<_, WP, _>(&c, ExecOptions::new());
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(
        &c,
        num_iters,
        b"seed entropy",
        BINDING,
        ProofOptions::new(),
    );
    return (output, proof);
}

fn verifies(output: &Words, proof: &Proof<S, S>, repetitions: Repetitions) -> bool {
    return verify::<_, H, PV, S, WPP, _>(
        &circuit(),
        output,
        proof,
        BINDING,
        repetitions,
        VerifyOptions::new(),
    )
    .expect("verify error");
}

#[test]
fn a_proof_of_the_required_length_verifies() {
    let (output, proof) = proof_of(NUM_ITERS);
    assert!(verifies(&output, &proof, Repetitions::exactly(NUM_ITERS)));
}

#[test]
fn an_empty_proof_is_rejected() {
    let (output, _) = proof_of(NUM_ITERS);
    let empty: Proof<S, S> = Vec::new();
    assert!(!verifies(&output, &empty, Repetitions::exactly(NUM_ITERS)));
}

#[test]
fn a_truncated_proof_is_rejected() {
    let (output, proof) = proof_of(NUM_ITERS);
    // Every response in the prefix is honest: only the count is wrong.
    let truncated: Proof<S, S> = proof[..NUM_ITERS - 1].to_vec();
    assert!(!verifies(
        &output,
        &truncated,
        Repetitions::exactly(NUM_ITERS)
    ));
}

#[test]
fn a_verifier_that_ingested_too_few_iterations_rejects() {
    let (output, proof) = proof_of(NUM_ITERS);
    let mut verifier =
        Verifier::<H, PV, S, WPP>::new(&output, BINDING, Repetitions::exactly(NUM_ITERS));
    for response in proof.iter().take(NUM_ITERS - 1) {
        let iter = verifier.next_iter(response);
        circuit().exec(iter.view_replayer());
        iter.finalize().expect("replay error");
    }
    assert_eq!(verifier.num_iters_ingested(), NUM_ITERS - 1);
    assert!(!verifier.finalize());
}

#[test]
fn the_pq_soundness_level_names_its_own_count() {
    assert_eq!(Repetitions::for_pq_security_bits(128).count(), 438);
    assert_eq!(Repetitions::for_pq_security_bits(64).count(), 219);
}
