// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions to build ZKBoo challenge entropy.

use crate::{
    circuit::Circuit,
    crypto::{TAG_CHALLENGE, absorb_framed, Hasher, PseudoRandomGenerator, Seed},
    prover::{
        challenge::builder::ChallengeBuilder,
        views::{
            ViewCommitment, WordTriplePool,
            collectors::{ViewCommitmentsRelayer, ViewsDataCollector},
        },
    },
};
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Builds the challenge entropy for ZKBoo with a caller-chosen [ViewsDataCollector] for the
/// challenge phase, mirroring how [build_proof_custom](crate::prover::proof::build_proof_custom)
/// lets callers pick a collector for the proof phase.
///
/// The collector observes the per-operation `push_*` calls relayed during circuit execution but
/// does not feed the view-commitment hashers, so it is transcript-neutral: its `finalize` must
/// relay the unchanged `[ViewCommitment; 3]`. This is the seam a downstream consumer uses to, e.g.,
/// service a platform watchdog during an otherwise uninterrupted circuit pass, without altering the
/// challenge entropy or the resulting proof.
pub fn build_challenge_entropy_custom<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    VDC: ViewsDataCollector<H::Digest, S, FinalizeRes = [ViewCommitment<H::Digest>; 3]>,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seed_entropy: &[u8],
    binding: &[u8],
    num_iters: usize,
    collector_init_arg: VDC::InitArg,
) -> Zeroizing<Vec<u8>> {
    // 1. Initialise the challenge builder:
    let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(seed_entropy, binding);
    // 2. Ingest iterations into the builder sequentially:
    for _ in 0..num_iters {
        let iter = builder.next_iter_custom::<VDC>(collector_init_arg);
        circuit.exec(&mut iter.view_builder());
        iter.finalize();
    }
    // 3. Finalize the builder to produce the challenge entropy:
    return builder.finalize();
}

/// Builds the challenge entropy for ZKBoo by executing the given circuit for a specified number
/// of iterations, using the provided seed entropy to generate pseudo-random iteration seeds.
///
/// Uses the default [ViewCommitmentsRelayer] collector; this is the convenience wrapper over
/// [build_challenge_entropy_custom] preserving the historical behaviour.
pub fn build_challenge_entropy<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seed_entropy: &[u8],
    binding: &[u8],
    num_iters: usize,
) -> Zeroizing<Vec<u8>> {
    return build_challenge_entropy_custom::<
        C,
        H,
        PS,
        PV,
        S,
        ViewCommitmentsRelayer<H::Digest, S>,
        WTP,
    >(circuit, seed_entropy, binding, num_iters, ());
}

/// Variant of [build_challenge_entropy] that computes view commitments in parallel.
#[cfg(feature = "rayon")]
pub fn par_build_challenge_entropy<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seed_entropy: &[u8],
    binding: &[u8],
    num_iters: usize,
) -> Zeroizing<Vec<u8>>
where
    C: Sync,
    H::Digest: Send,
    S: Send,
{
    use crate::{crypto::GeneratesRandom, prover::views::ViewCommitment};
    use rayon::prelude::*;
    // 1. Generate seeds for all iterations sequentially:
    let mut seed_prg = PS::new(seed_entropy);
    let seed_vec: Vec<[S; 3]> = (0..num_iters).map(|_| seed_prg.next()).collect();
    // 2. Compute view commitments for all iterations in parallel:
    let view_commitments_vec = seed_vec
        .into_par_iter()
        .map(|seeds| {
            use crate::prover::views::build_view_commitments;

            build_view_commitments::<C, H, PV, S, WTP>(circuit, Zeroizing::new(seeds))
        })
        .collect::<Vec<[ViewCommitment<H::Digest>; 3]>>();
    // 3. Ingest view commitments into the challenge hasher sequentially:
    let mut challenge_hasher = H::new();
    absorb_framed(&mut challenge_hasher, TAG_CHALLENGE, binding);
    for view_commitments in view_commitments_vec {
        for commitment in view_commitments {
            challenge_hasher.update(commitment.digest().as_ref());
            commitment
                .output_share()
                .update_hasher(&mut challenge_hasher);
        }
    }
    // 4. Finalize the challenge hasher to produce the challenge entropy:
    return Zeroizing::new(challenge_hasher.finalize().as_ref().to_vec());
}
