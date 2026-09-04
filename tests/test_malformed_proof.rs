// SPDX-License-Identifier: LGPL-3.0-or-later

//! Robustness regression tests: an untrusted, malformed proof must be rejected (deserialize error
//! or `Ok(false)`), never crash the verifier. Two aborts are covered: an out-of-range
//! challenge index (drove an `unreachable!()`), and a challenge that claims to open party 2 but
//! omits the party-2 input share (drove an `.expect()`), each amplified to an uncatchable abort by
//! the iteration's panic-on-drop guard.

#[path = "common/hasher.rs"]
mod hasher;
use hasher::Blake3Hasher;

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{challenge::Party, proof::Proof, prove, views::OwnedFlexibleWordTriplePool},
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
};
use zkboo::executor::ExecOptions;
use zkboo::prover::proof::ProofOptions;
use zkboo::verifier::VerifyOptions;

type H = Blake3Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WP = OwnedFlexibleWordPool<usize>;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

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

const BINDING: &[u8] = b"regression binding";

#[test]
fn party_deserialize_rejects_out_of_range_index() {
    // The wire form of a `Party` is its index byte; 0..=2 accepted, everything else rejected.
    for index in 0u8..=2 {
        let bytes = postcard::to_allocvec(&Party::from(index)).expect("serialize");
        let party: Party = postcard::from_bytes(&bytes).expect("valid index deserializes");
        assert_eq!(party.index(), index as usize);
    }
    for index in [3u8, 4, 100, 200, 255] {
        assert!(
            postcard::from_bytes::<Party>(&[index]).is_err(),
            "index {index} must be rejected on deserialize"
        );
    }
}

#[test]
fn valid_proof_survives_postcard_roundtrip() {
    // Guards the custom `Party` serde against a wire-format regression.
    let circuit = XorNot { a: 0x5A, b: 0x3C };
    let expected = exec::<_, WP, _>(&circuit, ExecOptions::new());
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(&circuit, 16, b"seed", BINDING, ProofOptions::new());
    let bytes = postcard::to_allocvec(&proof).expect("serialize proof");
    let decoded: Proof<S, S> = postcard::from_bytes(&bytes).expect("deserialize proof");
    assert!(verify::<_, H, PV, S, WPP, _>(&circuit, &expected, &decoded, BINDING, VerifyOptions::new()).expect("verify ok"));
}

#[test]
fn corrupted_challenge_byte_never_aborts_the_verifier() {
    // The first byte after the (single-byte) vector-length prefix is the first response's
    // challenge index. Overwriting it with every possible byte value must leave the verifier
    // returning a deserialize error or `Ok(false)` — never a panic/abort. A regression of either
    // A crash would abort this test process instead of failing gracefully.
    let circuit = XorNot { a: 0x11, b: 0x22 };
    let expected = exec::<_, WP, _>(&circuit, ExecOptions::new());
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(&circuit, 16, b"seed", BINDING, ProofOptions::new());
    let bytes = postcard::to_allocvec(&proof).expect("serialize proof");
    let orig = bytes[1];
    for corrupt in 0u8..=255 {
        let mut corrupted = bytes.clone();
        corrupted[1] = corrupt;
        match postcard::from_bytes::<Proof<S, S>>(&corrupted) {
            Err(_) => {} // malformed bytes rejected at parse — fine.
            Ok(decoded) => {
                let result = verify::<_, H, PV, S, WPP, _>(&circuit, &expected, &decoded, BINDING, VerifyOptions::new());
                if corrupt == orig {
                    assert_eq!(
                        result.expect("verify ok"),
                        true,
                        "unchanged proof must verify"
                    );
                } else {
                    // Any altered challenge either mismatches Fiat-Shamir or is structurally
                    // inconsistent; either way the answer is a graceful non-acceptance.
                    assert_ne!(
                        result.unwrap_or(false),
                        true,
                        "corrupted challenge {corrupt} must not verify as valid"
                    );
                }
            }
        }
    }
}
