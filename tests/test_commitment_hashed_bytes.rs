// SPDX-License-Identifier: LGPL-3.0-or-later

//! Pins the size of the ZKB++ view-commitment preimage, guarding the perf win of not hashing linear
//! wires. For a rotate/xor-heavy "hash-like" circuit (256 rounds, one AND every 16), the two opened
//! parties' preimages total 158 bytes — two domain-framed blocks over the two seeds (32 each), the
//! input shares, and only the AND outputs — versus 2080 bytes under the previous all-wires ZKBoo
//! commitment (a 13.2x reduction).
//! A jump back up means a linear gate started hashing again.

#[path = "common/hasher.rs"]
mod hasher;
use hasher::Blake3Hasher;

use core::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroize;
use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher},
    prover::{prove, views::OwnedFlexibleWordTriplePool},
    verifier::replay::{OwnedFlexibleWordPairPool, ViewReplayerBackend},
};
use zkboo::prover::proof::ProofOptions;

/// Total bytes absorbed by every [CountingHasher] since the last reset.
static HASHED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// A [Blake3Hasher] that additionally counts the bytes it absorbs.
#[derive(Debug, Zeroize)]
struct CountingHasher(Blake3Hasher);

impl Hasher for CountingHasher {
    const DIGEST_SIZE: usize = Blake3Hasher::DIGEST_SIZE;
    type Digest = <Blake3Hasher as Hasher>::Digest;

    fn new() -> Self {
        return CountingHasher(Blake3Hasher::new());
    }

    fn update(&mut self, data: &[u8]) {
        HASHED_BYTES.fetch_add(data.len(), Ordering::Relaxed);
        self.0.update(data);
    }

    fn finalize_into(&mut self, out: &mut Self::Digest) {
        self.0.finalize_into(out);
    }
}

type H = Blake3Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

/// Linear-heavy circuit (like a hash round function): many rotate/xor gates, a few ANDs.
struct HashLike {
    a: u8,
    b: u8,
}

impl Circuit for HashLike {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let a = fe.input(self.a);
        let b = fe.input(self.b);
        let mut x = a.clone();
        for r in 0..256 {
            x = x.clone().rotate_left(3) ^ x.rotate_right(5) ^ b.clone(); // linear
            if r % 16 == 0 {
                x = x & a.clone(); // nonlinear (AND) every 16 rounds
            }
        }
        fe.output(x);
    }
}

#[test]
fn commitment_preimage_excludes_linear_wires() {
    let circuit = HashLike { a: 0xA5, b: 0x3C };
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(&circuit, 1, b"seed", b"", ProofOptions::new());
    let response = &proof[0];
    HASHED_BYTES.store(0, Ordering::Relaxed);
    let frontend =
        ViewReplayerBackend::<CountingHasher, PV, S, WPP>::new(response).into_view_replayer();
    circuit.exec(&frontend);
    let hashed = HASHED_BYTES.load(Ordering::Relaxed);
    // Per party: the framed domain tag (21 + 8), the seed (32), the input shares and the AND-gate
    // outputs. No linear-wire bytes.
    assert_eq!(
        hashed, 158,
        "commitment preimage size changed (was 2080 under all-wires hashing)"
    );
}
