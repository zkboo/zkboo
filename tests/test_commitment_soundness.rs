// SPDX-License-Identifier: LGPL-3.0-or-later

//! Soundness coverage for the ZKB++-style view commitment (seed + input shares + nonlinear
//! traffic; linear wires excluded). A valid proof over a circuit with both AND and carry gates must
//! verify; tampering with the committed nonlinear traffic (`and_msg`) or the committed party-2 input
//! share must be rejected. The all-challenges test asserts every 2-of-3 opening pattern is exercised,
//! since each lays out the input-share and nonlinear-traffic hashing over a different slot mapping.

#![cfg(feature = "keccak")]

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher, Keccak256Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{proof::Proof, proof::Response, prove, views::OwnedFlexibleWordTriplePool},
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
    word::Words,
};

type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WP = OwnedFlexibleWordPool<usize>;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

const BINDING: &[u8] = b"zkbpp commitment soundness";

/// A circuit with both nonlinear gate kinds: `out = (a & b) + c` (one AND, one carry).
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
        a: 0xB5,
        b: 0x3C,
        c: 0x9A,
    };
}

fn prove_it(iters: usize) -> (Words, Proof<S, S>) {
    let c = circuit();
    let expected = exec::<_, WP>(&c);
    let proof = prove::<_, H, PS, PV, S, WTP>(&c, iters, b"seed entropy", BINDING);
    return (expected, proof);
}

fn is_valid(expected: &Words, proof: &Proof<S, S>) -> bool {
    return verify::<_, H, PV, S, WPP>(&circuit(), expected, proof, BINDING).expect("verify ok");
}

/// Flips the least significant bit of the first byte-word of `words` (its first `u8` slot).
fn flip_first_bit(words: &Words) -> Words {
    let mut w = words.clone();
    let v = w.as_vec_mut::<u8>();
    assert!(
        !v.is_empty(),
        "expected a non-empty u8 word vector to tamper"
    );
    v[0] ^= 1;
    return w;
}

/// Rebuilds a response, substituting a (possibly tampered) AND message and party-2 input share.
fn rebuild(resp: &Response<S, S>, and_msg: Words, input_share_2: Option<Words>) -> Response<S, S> {
    let seeds = resp.seeds();
    let dig = *resp.commitment_digest_unopened();
    return match resp.challenge().index() {
        0 => Response::new_0(*seeds[0], *seeds[1], dig, and_msg),
        1 => Response::new_1(
            dig,
            *seeds[0],
            *seeds[1],
            and_msg,
            input_share_2.expect("share"),
        ),
        2 => Response::new_2(
            *seeds[1],
            dig,
            *seeds[0],
            and_msg,
            input_share_2.expect("share"),
        ),
        _ => unreachable!(),
    };
}

#[test]
fn valid_proof_with_nonlinear_gates_verifies() {
    let (expected, proof) = prove_it(16);
    assert!(
        is_valid(&expected, &proof),
        "a valid proof over a circuit with AND and carry gates must verify"
    );
}

#[test]
fn all_three_challenges_are_exercised() {
    // Each 2-of-3 opening lays out the input-share and nonlinear-traffic hashing over a different
    // slot mapping; with enough iterations the Fiat-Shamir challenge hits all three.
    let (_, proof) = prove_it(64);
    let mut seen = [false; 3];
    for resp in &proof {
        seen[resp.challenge().index()] = true;
    }
    assert!(
        seen.iter().all(|&s| s),
        "not all three challenges were exercised: {seen:?}"
    );
}

#[test]
fn tampering_with_nonlinear_traffic_is_rejected() {
    // The AND messages are committed (nonlinear traffic). Flipping one bit must invalidate the proof.
    let (expected, mut proof) = prove_it(16);
    let tampered = rebuild(
        &proof[0],
        flip_first_bit(proof[0].and_msg_next_party()),
        proof[0].input_share_2().cloned(),
    );
    proof[0] = tampered;
    assert!(
        !is_valid(&expected, &proof),
        "a flipped AND message must be rejected"
    );
}

#[test]
fn tampering_with_the_input_share_is_rejected() {
    // The party-2 input share is bound into the view digest (the ZKB++ commitment condition that a
    // pure ZKBoo all-wires digest also gave, but which the reduced digest must restore explicitly).
    let (expected, mut proof) = prove_it(64);
    let idx = proof
        .iter()
        .position(|r| r.input_share_2().is_some())
        .expect("some challenge opens party 2");
    let tampered = rebuild(
        &proof[idx],
        proof[idx].and_msg_next_party().clone(),
        Some(flip_first_bit(proof[idx].input_share_2().unwrap())),
    );
    proof[idx] = tampered;
    assert!(
        !is_valid(&expected, &proof),
        "a flipped party-2 input share must be rejected"
    );
}
