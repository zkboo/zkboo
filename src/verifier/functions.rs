// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions for verifying ZKBoo proofs.

use crate::{
    backend::BackendHook,
    circuit::Circuit,
    crypto::{Hasher, PseudoRandomGenerator, Seed},
    prover::proof::Proof,
    verifier::{
        Verifier, VerifyOptions,
        replay::{ViewReplayError, WordPairPool},
    },
    word::Words,
};
#[cfg(feature = "rayon")]
use crate::crypto::{TAG_CHALLENGE, absorb_framed};

/// Verifies a ZKBoo [Proof] against the given circuit and expected output.
pub fn verify<
    C: Circuit,
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    WPP: WordPairPool,
    BH: BackendHook,
>(
    circuit: &C,
    expected_output: &Words,
    proof: &Proof<H::Digest, S>,
    binding: &[u8],
    options: VerifyOptions<BH>,
) -> Result<bool, ViewReplayError> {
    let mut verifier: Verifier<H, PV, S, WPP> = Verifier::new(expected_output, binding);
    for response in proof {
        // Reject a structurally malformed (untrusted) response before replaying it.
        if !response.is_well_formed() {
            return Ok(false);
        }
        let iter = verifier.next_iter_hooked::<BH>(response, options.hook_arg());
        circuit.exec(iter.view_replayer());
        iter.finalize()?;
    }
    return Ok(verifier.finalize());
}

/// Variant of [verify] which replays views in parallel.
///
/// Returns [ViewReplayError] if the shape of the expected output does not match the shape
/// of the outputs produced during a replay, or if the AND messages have not all been consumed.
#[cfg(feature = "rayon")]
pub fn par_verify<C: Circuit, H: Hasher, PV: PseudoRandomGenerator, S: Seed, WPP: WordPairPool>(
    circuit: &C,
    expected_output: &Words,
    proof: &Proof<H::Digest, S>,
    binding: &[u8],
) -> Result<bool, ViewReplayError>
where
    C: Sync,
    H::Digest: Send + Sync,
    S: Send + Sync,
{
    use crate::{
        crypto::{GeneratesRandom, HashPRG},
        prover::challenge::{ChallengeGenerator, PartyVec},
    };
    use alloc::vec::Vec;
    use rayon::prelude::*;
    // 1. Extract the vector of challenges from the proof, in sequence, rejecting any
    //    structurally malformed (untrusted) response before it reaches the parallel replay:
    let mut challenges = PartyVec::with_capacity(proof.len());
    for response in proof {
        if !response.is_well_formed() {
            return Ok(false);
        }
        challenges.push(response.challenge());
    }
    // 2. Replay all responses in the proof, in parallel:
    let replay_results: Vec<_> = proof
        .into_par_iter()
        .map(|response| {
            use crate::verifier::replay::ViewReplayerBackend;

            let view_replayer =
                ViewReplayerBackend::<H, PV, S, WPP>::new(response).into_view_replayer();
            circuit.exec(&view_replayer);
            view_replayer.finalize_with_arg(expected_output)
        })
        .collect();
    // 3. Ingest all replayed view commitments, in sequence:
    let mut challenge_hasher = H::new();
    absorb_framed(&mut challenge_hasher, TAG_CHALLENGE, binding);
    for res in replay_results {
        let view_commitments = res?;
        for commitment in view_commitments {
            challenge_hasher.update(commitment.digest().as_ref());
            commitment
                .output_share()
                .update_hasher(&mut challenge_hasher);
        }
    }
    // 4. Generate challenges from the entropy gathered by replayed view commitment,
    //    and check whether replay challenge sequence matches challenge sequence from the proof:
    let challenge_entropy = challenge_hasher.finalize();
    let mut challenge_generator =
        ChallengeGenerator::new(HashPRG::<H>::new(challenge_entropy.as_ref()));
    for challenge in &challenges {
        if challenge_generator.next() != challenge {
            return Ok(false);
        }
    }
    return Ok(true);
}
