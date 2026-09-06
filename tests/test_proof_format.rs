// SPDX-License-Identifier: LGPL-3.0-or-later

//! Tripwire for [PROOF_FORMAT_ID]. The emitted response bytes of a canonical proof over a fixed
//! circuit and fixed entropy are pinned, so any change to the response layout or to the
//! view-commitment preimages — a change no circuit fingerprint can observe — breaks this test.
//! The only repair is to update [PROOF_FORMAT_ID] itself, which is the value consumers absorb, so
//! proofs and deterministically derived prover entropy cannot cross formats silently.

#![cfg(feature = "u32")]

use zeroize::Zeroize;
use zkboo::{
    PROOF_FORMAT_ID,
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher},
    prover::{
        proof::{Proof, ProofOptions},
        prove,
        views::OwnedFlexibleWordTriplePool,
    },
};

/// The hash the pin is taken under.
///
/// Frozen for the life of this test, and deliberately not the shared test hasher: a pin whose hash
/// can move for a reason unrelated to the proof format cannot distinguish "the format changed"
/// from "the test changed", and that ambiguity has consumed the signal before. Changing this
/// invalidates [PROOF_FORMAT_ID] for a reason that has nothing to do with the format.
#[derive(Debug)]
struct PinHasher {
    inner: blake3::Hasher,
}

impl Hasher for PinHasher {
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

impl Zeroize for PinHasher {
    fn zeroize(&mut self) {
        self.inner.reset();
    }
}

type H = PinHasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WTP = OwnedFlexibleWordTriplePool<usize>;

const SEED_ENTROPY: &[u8] = b"proof format pin seed entropy";
const BINDING: &[u8] = b"proof format pin";
const NUM_ITERS: usize = 9;

/// Byte length of each response of the canonical proof.
///
/// Gates nothing the digest does not; it exists so that a break reports what moved.
const PINNED_RESPONSE_LENGTHS: [usize; NUM_ITERS] = [127, 115, 127, 115, 115, 115, 127, 127, 115];

/// Mixes both nonlinear gate kinds and two word widths, so the pinned bytes cover the response
/// layout of AND messages, carries, and input shares across word types.
struct Mixed {
    a: u32,
    b: u32,
    c: u8,
}

impl Circuit for Mixed {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let a = fe.input(self.a);
        let b = fe.input(self.b);
        let c = fe.input(self.c);
        let x = (a.clone() & b) + a.rotate_left(7);
        fe.output(x);
        fe.output(c.clone() + (c.clone() & c));
    }
}

fn hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

fn canonical_proof() -> Proof<S, S> {
    let circuit = Mixed {
        a: 0x1234_5678,
        b: 0x9ABC_DEF0,
        c: 0x5A,
    };
    return prove::<_, H, PS, PV, S, _, WTP, _>(
        &circuit,
        NUM_ITERS,
        SEED_ENTROPY,
        BINDING,
        ProofOptions::new(),
    );
}

fn format_id(proof: &Proof<S, S>) -> [u8; 32] {
    let mut hasher = H::new();
    for response in proof {
        hasher.update(&response.as_bytes());
    }
    return hasher.finalize();
}

#[test]
fn proof_bytes_match_the_pinned_format() {
    let proof = canonical_proof();
    let id = format_id(&proof);
    let lengths: Vec<usize> = proof.into_iter().map(|r| r.as_bytes().len()).collect();
    let repair = format!(
        "the emitted proof bytes changed. If this is intended, set PROOF_FORMAT_ID to {} and the \
         pinned lengths to {:?} — and note that consumers absorb the id, so every \
         deterministically derived prover entropy moves with it, which is the point.",
        hex(&id),
        lengths
    );
    assert_eq!(lengths, PINNED_RESPONSE_LENGTHS.to_vec(), "{repair}");
    assert_eq!(id, PROOF_FORMAT_ID, "{repair}");
}
