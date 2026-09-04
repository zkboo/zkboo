// SPDX-License-Identifier: LGPL-3.0-or-later

//! Locks in the zero-effect guarantee of the [BackendHook] / [Hooked] decorator on the prover.
//!
//! A `Hooked<H, B>` wraps each iteration's view builder backend and fires a `pre_*`/`post_*` pair
//! around every backend operation. The contract is that this is transcript-neutral: the hook only
//! observes, it must not perturb the emitted proof. Two things are checked:
//!
//! 1. With the default [NoHook], a hooked prove is byte-identical to an unhooked prove — the
//!    acceptance criterion for the decorator landing behaviour-neutral by default.
//! 2. With a real hook that ticks on both an AND gate (`post_bitand`) and the linear ops
//!    (`post_rotate_left`, `post_not`) — the very ops a watchdog needs to ride through the
//!    AND-silent stretches of a circuit pass — the hook demonstrably fires, yet the proof is still
//!    byte-identical to the unhooked one.

use core::cell::Cell;
use zeroize::Zeroize;
use zkboo::{
    backend::{Backend, BackendHook, Frontend, NoHook},
    circuit::Circuit,
    crypto::{HashPRG, Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{
        challenge::{ChallengeOptions, build_challenge_entropy},
        proof::{ProofOptions, build_proof},
    },
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
};
use zkboo::executor::ExecOptions;
use zkboo::verifier::VerifyOptions;

// --- A minimal Blake3-backed hasher (mirrors tests/test_challenge_collector.rs). -----------------

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

// --- A hook that ticks on one AND gate and on the linear ops, recording into a shared counter. ----

/// Overrides only the `post_*` of operations the circuit below performs: an AND gate and two linear
/// ops. Each tick bumps a shared counter so the test can prove the hook actually ran. Touches only
/// its own state — never the backend — as a hook must.
#[derive(Debug)]
struct CountingHook<'c> {
    counter: &'c Cell<usize>,
}

impl<'c> BackendHook for CountingHook<'c> {
    type InitArg = &'c Cell<usize>;

    fn new(counter: Self::InitArg) -> Self {
        return Self { counter };
    }

    fn post_bitand(&mut self) {
        self.counter.set(self.counter.get() + 1);
    }

    fn post_rotate_left(&mut self) {
        self.counter.set(self.counter.get() + 1);
    }

    fn post_not(&mut self) {
        self.counter.set(self.counter.get() + 1);
    }
}

// --- A circuit mixing an AND gate (emits AND-messages) with linear ops (emit none). --------------

#[derive(Default)]
struct MixedCircuit {
    a: u8,
    b: u8,
}

impl Circuit for MixedCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let a = frontend.input(self.a);
        let b = frontend.input(self.b);
        let c = a.bitand(b).rotate_left(3).not();
        frontend.output(c);
    }
}

type H = Blake3Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WTP = zkboo::prover::views::OwnedFlexibleWordTriplePool<usize>;
type WP = OwnedFlexibleWordPool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

const SEED_ENTROPY: &[u8] = b"backend hook seed entropy";
const BINDING: &[u8] = b"backend hook binding";
const NUM_ITERS: usize = 8;

/// `build_challenge_entropy` is deterministic in its inputs, so each call reproduces the exact
/// entropy a prove needs (the returned value is consumed by `build_proof*`).
fn challenge_entropy(circuit: &MixedCircuit) -> zeroize::Zeroizing<std::vec::Vec<u8>> {
    return build_challenge_entropy::<MixedCircuit, H, PS, PV, S, _, WTP, _>(
        circuit,
        SEED_ENTROPY,
        BINDING,
        NUM_ITERS,
        ChallengeOptions::new(),
    );
}

#[test]
fn nohook_wrapped_prove_is_byte_identical() {
    let circuit = MixedCircuit { a: 0b1100, b: 0b1010 };

    let proof_plain = build_proof::<MixedCircuit, H, PS, PV, S, _, WTP, _>(
        &circuit,
        SEED_ENTROPY,
        challenge_entropy(&circuit),
        NUM_ITERS,
        ProofOptions::new(),
    );

    let proof_nohook = build_proof::<MixedCircuit, H, PS, PV, S, _, WTP, _>(
        &circuit,
        SEED_ENTROPY,
        challenge_entropy(&circuit),
        NUM_ITERS,
        ProofOptions::new().with_hook_arg::<NoHook>((),
    ),
    );

    assert_eq!(
        proof_plain, proof_nohook,
        "NoHook-wrapped prove diverged from the unhooked prove"
    );

    // And it still verifies, so the equality is not equality-of-two-broken-things.
    let expected_output = exec::<MixedCircuit, WP, _>(&circuit, ExecOptions::new());
    let is_valid = verify::<MixedCircuit, H, PV, S, WPP, _>(&circuit,
        &expected_output,
        &proof_nohook,
        BINDING, VerifyOptions::new())
    .expect("verification errored");
    assert!(is_valid, "NoHook-wrapped proof did not verify");
}

#[test]
fn observing_hook_fires_yet_is_transcript_neutral() {
    let circuit = MixedCircuit { a: 0b1100, b: 0b1010 };

    let proof_plain = build_proof::<MixedCircuit, H, PS, PV, S, _, WTP, _>(
        &circuit,
        SEED_ENTROPY,
        challenge_entropy(&circuit),
        NUM_ITERS,
        ProofOptions::new(),
    );

    let counter = Cell::new(0usize);
    let proof_hooked = build_proof::<MixedCircuit, H, PS, PV, S, _, WTP, _>(
        &circuit,
        SEED_ENTROPY,
        challenge_entropy(&circuit),
        NUM_ITERS,
        ProofOptions::new().with_hook_arg::<CountingHook>(&counter),
    );

    // The hook ticked on the AND gate and the linear ops, across all iterations...
    assert!(
        counter.get() >= NUM_ITERS * 3,
        "the hook's post_* seam did not fire as expected (counter = {})",
        counter.get()
    );
    // ...yet the emitted proof is byte-identical to the unhooked one.
    assert_eq!(
        proof_plain, proof_hooked,
        "an observing hook perturbed the emitted proof"
    );

    let expected_output = exec::<MixedCircuit, WP, _>(&circuit, ExecOptions::new());
    let is_valid = verify::<MixedCircuit, H, PV, S, WPP, _>(&circuit,
        &expected_output,
        &proof_hooked,
        BINDING, VerifyOptions::new())
    .expect("verification errored");
    assert!(is_valid, "hooked proof did not verify");
}

#[test]
fn nohook_verify_matches_plain_verify() {
    let circuit = MixedCircuit { a: 0b1100, b: 0b1010 };
    let proof = build_proof::<MixedCircuit, H, PS, PV, S, _, WTP, _>(
        &circuit,
        SEED_ENTROPY,
        challenge_entropy(&circuit),
        NUM_ITERS,
        ProofOptions::new(),
    );
    let expected_output = exec::<MixedCircuit, WP, _>(&circuit, ExecOptions::new());

    let plain = verify::<MixedCircuit, H, PV, S, WPP, _>(&circuit, &expected_output, &proof, BINDING, VerifyOptions::new())
        .expect("verify errored");
    let nohook = verify::<MixedCircuit, H, PV, S, WPP, _>(
        &circuit,
        &expected_output,
        &proof,
        BINDING,
        VerifyOptions::new().with_hook_arg::<NoHook>((),
    ),
    )
    .expect("verify errored");

    assert!(plain, "plain verify rejected a valid proof");
    assert_eq!(plain, nohook, "NoHook-wrapped verify diverged from plain verify");
}

#[test]
fn observing_hook_on_verify_fires_yet_verifies() {
    let circuit = MixedCircuit { a: 0b1100, b: 0b1010 };
    let proof = build_proof::<MixedCircuit, H, PS, PV, S, _, WTP, _>(
        &circuit,
        SEED_ENTROPY,
        challenge_entropy(&circuit),
        NUM_ITERS,
        ProofOptions::new(),
    );
    let expected_output = exec::<MixedCircuit, WP, _>(&circuit, ExecOptions::new());

    let counter = Cell::new(0usize);
    let ok = verify::<MixedCircuit, H, PV, S, WPP, _>(
        &circuit,
        &expected_output,
        &proof,
        BINDING,
        VerifyOptions::new().with_hook_arg::<CountingHook>(&counter),
    )
    .expect("verify errored");

    // A correct verification result already implies the hooked replay reproduced the exact
    // transcript (otherwise the challenge sequence would mismatch and verify would return false)...
    assert!(ok, "hooked verify rejected a valid proof");
    // ...and the hook demonstrably fired on the AND gate and the linear ops, per replayed response.
    assert!(
        counter.get() >= NUM_ITERS * 3,
        "the verify hook's post_* seam did not fire as expected (counter = {})",
        counter.get()
    );
}

#[test]
fn nohook_exec_is_byte_identical() {
    let circuit = MixedCircuit { a: 0b1100, b: 0b1010 };

    let out_plain = exec::<MixedCircuit, WP, _>(&circuit, ExecOptions::new());
    let out_nohook = exec::<MixedCircuit, WP, NoHook>(&circuit, ExecOptions::new().with_hook_arg::<NoHook>(()));

    assert_eq!(
        out_plain, out_nohook,
        "NoHook-wrapped exec diverged from plain exec"
    );
}

#[test]
fn observing_hook_on_exec_fires_yet_is_output_neutral() {
    let circuit = MixedCircuit { a: 0b1100, b: 0b1010 };

    let out_plain = exec::<MixedCircuit, WP, _>(&circuit, ExecOptions::new());

    let counter = Cell::new(0usize);
    let out_hooked = exec::<MixedCircuit, WP, CountingHook>(&circuit, ExecOptions::new().with_hook_arg::<CountingHook>(&counter));

    // The hook fired on the AND gate and the linear ops (one clear-text pass: at least 3 ticks)...
    assert!(
        counter.get() >= 3,
        "the exec hook's post_* seam did not fire as expected (counter = {})",
        counter.get()
    );
    // ...yet the computed output is byte-identical to the unhooked execution.
    assert_eq!(
        out_plain, out_hooked,
        "an observing hook changed the executed output"
    );
}
