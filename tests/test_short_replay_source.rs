// SPDX-License-Identifier: LGPL-3.0-or-later

//! A response whose AND-message or party-2 input-share vector is shorter than the circuit consumes
//! fails replay with a shape mismatch.
//! Validated by deletion: with the replay cursors advanced only by the words actually supplied, both
//! shape tests finalise `Ok`.

#[path = "common/hasher.rs"]
mod hasher;
use hasher::Blake3Hasher;

use zkboo::{
    Repetitions,
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Hasher},
    executor::{ExecOptions, OwnedFlexibleWordPool, exec},
    prover::{
        proof::{Proof, ProofOptions, Response},
        prove,
        views::OwnedFlexibleWordTriplePool,
    },
    verifier::{
        VerifyOptions,
        replay::{OwnedFlexibleWordPairPool, ViewReplayError, ViewReplayerBackend},
        verify,
    },
    word::Words,
};

type H = Blake3Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;
type WP = OwnedFlexibleWordPool<usize>;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

const BINDING: &[u8] = b"short replay source";
const ITERS: usize = 16;

/// Computes `((a & b) ^ c) & d`, with two AND gates and four inputs.
struct TwoAnds {
    inputs: [u8; 4],
}

impl Circuit for TwoAnds {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let [a, b, c, d] = self.inputs.map(|x| fe.input(x));
        fe.output(((a & b) ^ c) & d);
    }
}

fn circuit() -> TwoAnds {
    return TwoAnds {
        inputs: [0xB5, 0x3C, 0x9A, 0x6E],
    };
}

fn prove_it() -> (Words, Proof<S, S>) {
    let c = circuit();
    let expected = exec::<_, WP, _>(&c, ExecOptions::new());
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(
        &c,
        ITERS,
        b"seed entropy",
        BINDING,
        ProofOptions::new(),
    );
    return (expected, proof);
}

fn without_last_word(words: &Words) -> Words {
    let mut w = words.clone();
    w.as_vec_mut::<u8>().pop().expect("a non-empty u8 vector");
    return w;
}

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

fn replay(resp: &Response<S, S>, expected: &Words) -> Result<(), ViewReplayError> {
    let replayer = ViewReplayerBackend::<H, PV, S, WPP>::new(resp).into_view_replayer();
    circuit().exec(&replayer);
    return replayer.finalize_with_arg(expected).map(|_| ());
}

fn party_2_response(proof: &Proof<S, S>) -> &Response<S, S> {
    return proof
        .iter()
        .find(|r| r.input_share_2().is_some())
        .expect("some challenge opens party 2");
}

#[test]
fn honest_responses_replay() {
    let (expected, proof) = prove_it();
    for resp in &proof {
        assert!(replay(resp, &expected).is_ok());
    }
}

#[test]
fn short_and_message_vector_fails_replay() {
    let (expected, proof) = prove_it();
    let resp = &proof[0];
    let short = rebuild(
        resp,
        without_last_word(resp.and_msg_next_party()),
        resp.input_share_2().cloned(),
    );
    assert!(matches!(
        replay(&short, &expected),
        Err(ViewReplayError::AndMsgShapeMismatch(_))
    ));
}

#[test]
fn short_input_share_vector_fails_replay() {
    let (expected, proof) = prove_it();
    let resp = party_2_response(&proof);
    let short = rebuild(
        resp,
        resp.and_msg_next_party().clone(),
        Some(without_last_word(resp.input_share_2().unwrap())),
    );
    assert!(matches!(
        replay(&short, &expected),
        Err(ViewReplayError::InputShare2ShapeMismatch(_))
    ));
}

/// Checks robustness only: a truncated proof is already refused by the Fiat-Shamir match, so this
/// test passes with or without the shape check.
#[test]
fn short_proof_never_verifies() {
    let (expected, mut proof) = prove_it();
    let idx = proof
        .iter()
        .position(|r| r.input_share_2().is_some())
        .expect("some challenge opens party 2");
    let resp = &proof[idx];
    proof[idx] = rebuild(
        resp,
        without_last_word(resp.and_msg_next_party()),
        Some(without_last_word(resp.input_share_2().unwrap())),
    );
    let verdict = verify::<_, H, PV, S, WPP, _>(
        &circuit(),
        &expected,
        &proof,
        BINDING,
        Repetitions::exactly(ITERS),
        VerifyOptions::new(),
    );
    assert!(!matches!(verdict, Ok(true)));
}
