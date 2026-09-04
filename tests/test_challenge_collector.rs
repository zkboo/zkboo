// SPDX-License-Identifier: LGPL-3.0-or-later

//! Locks in the transcript-neutrality of a custom challenge-phase [ViewsDataCollector].
//!
//! The challenge builder is generic over its collector (mirroring how the proof phase is generic
//! over its [ResponseDataCollector]). A collector that merely *observes* the relayed `push_*` calls
//! — e.g. to service a platform watchdog during a long circuit pass — must not perturb the view
//! commitments, the challenge entropy, or the resulting proof. This test exercises exactly such a
//! collector and asserts byte-identical challenge entropy and an identical, verifying proof.

use core::cell::Cell;
use zeroize::Zeroize;
use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{Digest, HashPRG, Hasher, Seed},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{
        challenge::{ChallengeOptions, build_challenge_entropy},
        proof::{ProofOptions, build_proof},
        views::{
            OwnedFlexibleWordTriplePool, ViewCommitment,
            collectors::{ViewCommitmentsRelayer, ViewsDataCollector},
        },
    },
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
    word::{CompositeWord, Word},
};
use zkboo::executor::ExecOptions;
use zkboo::verifier::VerifyOptions;

// --- A minimal Blake3-backed hasher (mirrors tests/common/proofs.rs). ---------------------------

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

// --- An observing collector: counts relayed calls, hashes nothing, relays the commitments. -------

/// Wraps [ViewCommitmentsRelayer], bumping a shared counter on every relayed `push_*` call while
/// delegating `finalize` to the inner relayer unchanged. It feeds no hasher, so it is purely a
/// transport-side observer of the per-operation seam.
#[derive(Debug)]
struct CountingRelayer<'c, D: Digest, S: Seed> {
    inner: ViewCommitmentsRelayer<D, S>,
    counter: &'c Cell<usize>,
}

impl<'c, D: Digest, S: Seed> ViewsDataCollector<D, S> for CountingRelayer<'c, D, S> {
    type InitArg = &'c Cell<usize>;
    type FinalizeRes = [ViewCommitment<D>; 3];

    fn new(seeds: &[S; 3], counter: Self::InitArg) -> Self {
        return Self {
            inner: ViewCommitmentsRelayer::new(seeds, ()),
            counter,
        };
    }

    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
        self.counter.set(self.counter.get() + 1);
        self.inner.push_input_share2(word);
    }

    fn push_and_msgs<W: Word, const N: usize>(&mut self, and_msgs: [CompositeWord<W, N>; 3]) {
        self.counter.set(self.counter.get() + 1);
        self.inner.push_and_msgs(and_msgs);
    }

    fn finalize(self, commitments: [ViewCommitment<D>; 3]) -> Self::FinalizeRes {
        return self.inner.finalize(commitments);
    }
}

// --- A tiny AND-gate circuit so `push_and_msgs` actually fires during the challenge pass. ---------

#[derive(Default)]
struct AndCircuit {
    a: u8,
    b: u8,
}

impl Circuit for AndCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let a = frontend.input(self.a);
        let b = frontend.input(self.b);
        let c = a.bitand(b);
        frontend.output(c);
    }
}

type H = Blake3Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WP = OwnedFlexibleWordPool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

const SEED_ENTROPY: &[u8] = b"challenge collector seed entropy";
const BINDING: &[u8] = b"challenge collector binding";
const NUM_ITERS: usize = 8;

#[test]
fn custom_challenge_collector_is_transcript_neutral() {
    let circuit = AndCircuit { a: 0b1100, b: 0b1010 };

    // 1. Default relayer path (today's behaviour).
    let entropy_relayer = build_challenge_entropy::<AndCircuit, H, PS, PV, S, _, WTP, _>(
        &circuit,
        SEED_ENTROPY,
        BINDING,
        NUM_ITERS,
        ChallengeOptions::new(),
    );

    // 2. Custom observing-collector path.
    let counter = Cell::new(0usize);
    let entropy_custom = build_challenge_entropy::<AndCircuit, H, PS, PV, S, _, WTP, _>(
        &circuit,
        SEED_ENTROPY,
        BINDING,
        NUM_ITERS,
        ChallengeOptions::new().with_collector_arg::<CountingRelayer<S, S>>(&counter),
    );

    // The collector observed the per-gate seam (otherwise the equality below would be vacuous)...
    assert!(
        counter.get() > 0,
        "the observing collector's push_* seam never fired"
    );
    // ...yet the challenge entropy is byte-identical to the relayer path.
    assert_eq!(
        &*entropy_relayer, &*entropy_custom,
        "custom challenge collector changed the challenge entropy"
    );

    // 3. The downstream proof is therefore identical and still verifies.
    let proof_relayer =
        build_proof::<AndCircuit, H, PS, PV, S, _, WTP, _>(
            &circuit,
            SEED_ENTROPY,
            entropy_relayer,
            NUM_ITERS,
            ProofOptions::new(),
        );
    let proof_custom =
        build_proof::<AndCircuit, H, PS, PV, S, _, WTP, _>(
            &circuit,
            SEED_ENTROPY,
            entropy_custom,
            NUM_ITERS,
            ProofOptions::new(),
        );
    assert_eq!(
        proof_relayer, proof_custom,
        "custom challenge collector changed the emitted proof"
    );

    let expected_output = exec::<AndCircuit, WP, _>(&circuit, ExecOptions::new());
    let is_valid = verify::<AndCircuit, H, PV, S, WPP, _>(&circuit, &expected_output, &proof_custom, BINDING, VerifyOptions::new())
        .expect("verification errored");
    assert!(is_valid, "proof from the custom challenge path did not verify");
}
