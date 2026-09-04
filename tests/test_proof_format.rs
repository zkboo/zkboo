// SPDX-License-Identifier: LGPL-3.0-or-later

//! Tripwire for [PROOF_FORMAT_VERSION]. The emitted response bytes of a fixed proof over a fixed
//! circuit and fixed entropy are pinned by their digest, so any change to the response layout or to
//! the view-commitment preimages — a change no circuit fingerprint can observe — breaks this test.
//! The fix is deliberate: re-pin the digest here *and* bump [PROOF_FORMAT_VERSION], so that proofs
//! and deterministically derived prover entropy never cross format versions silently.

#![cfg(all(feature = "keccak", feature = "u32"))]

use zkboo::{
    PROOF_FORMAT_VERSION,
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher, Keccak256Hasher},
    prover::{proof::Proof, prove, views::OwnedFlexibleWordTriplePool},
};
use zkboo::prover::proof::ProofOptions;

type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WTP = OwnedFlexibleWordTriplePool<usize>;

const SEED_ENTROPY: &[u8] = b"proof format pin seed entropy";
const BINDING: &[u8] = b"proof format pin";
const NUM_ITERS: usize = 9;

/// The proof format this pin was taken under.
const PINNED_VERSION: u32 = 3;

/// Keccak-256 of the concatenated response bytes of the pinned proof.
const PINNED_DIGEST: &str = "51b10fb29979c774e547feaa60212d2efabc02f4b4c1e37388e5022e4d7a8b43";

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

fn proof_digest(proof: &Proof<S, S>) -> String {
    let mut hasher = H::new();
    for response in proof {
        hasher.update(&response.as_bytes());
    }
    return hex(hasher.finalize().as_ref());
}

#[test]
fn proof_bytes_match_the_pinned_format() {
    let circuit = Mixed {
        a: 0x1234_5678,
        b: 0x9ABC_DEF0,
        c: 0x5A,
    };
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(&circuit, NUM_ITERS, SEED_ENTROPY, BINDING, ProofOptions::new());
    assert_eq!(
        proof_digest(&proof),
        PINNED_DIGEST,
        "the emitted proof bytes changed: if this is intended, re-pin the digest here and bump \
         PROOF_FORMAT_VERSION (currently {PROOF_FORMAT_VERSION})"
    );
    assert_eq!(
        PROOF_FORMAT_VERSION, PINNED_VERSION,
        "PROOF_FORMAT_VERSION was bumped without re-pinning the proof bytes it identifies"
    );
}
