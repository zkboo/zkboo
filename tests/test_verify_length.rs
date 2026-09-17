// SPDX-License-Identifier: LGPL-3.0-or-later

//! Pins that verification leaves the number of responses to the caller.
//!
//! An empty proof has no challenge to mismatch, so it verifies against any output. A caller that
//! does not require its own number of responses accepts it.

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher},
    prover::proof::Proof,
    verifier::{Verifier, VerifyOptions, replay::OwnedFlexibleWordPairPool, verify},
    word::Words,
};

#[path = "common/hasher.rs"]
mod hasher;
use hasher::Blake3Hasher;

type H = Blake3Hasher;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WPP = OwnedFlexibleWordPairPool<usize>;

struct Identity;

impl Circuit for Identity {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        frontend.output(frontend.input(0u8));
    }
}

fn arbitrary_output() -> Words {
    let mut output = Words::new();
    output.as_vec_mut::<u8>().push(0x5a);
    return output;
}

#[test]
fn an_empty_proof_verifies_against_any_output() {
    let proof: Proof<S, S> = Vec::new();
    let valid = verify::<_, H, PV, S, WPP, _>(
        &Identity,
        &arbitrary_output(),
        &proof,
        b"",
        VerifyOptions::new(),
    )
    .expect("no response to replay");
    assert!(valid);
}

#[test]
fn a_verifier_that_ingested_nothing_accepts() {
    let output = arbitrary_output();
    let verifier = Verifier::<H, PV, S, WPP>::new(&output, b"");
    assert_eq!(verifier.num_iters_ingested(), 0);
    assert!(verifier.finalize());
}
