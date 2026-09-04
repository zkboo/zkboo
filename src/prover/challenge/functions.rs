// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions to build ZKBoo challenge entropy.

use crate::{
    backend::BackendHook,
    circuit::Circuit,
    crypto::{Hasher, PseudoRandomGenerator, Seed},
    prover::{
        challenge::{ChallengeOptions, builder::ChallengeBuilder},
        views::{
            ViewCommitment, WordTriplePool,
            collectors::ViewsDataCollector,
        },
    },
};
#[cfg(feature = "rayon")]
use crate::crypto::{TAG_CHALLENGE, absorb_framed};
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Builds the challenge entropy by executing the circuit for the given number of iterations.
pub fn build_challenge_entropy<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    VDC: ViewsDataCollector<H::Digest, S, FinalizeRes = [ViewCommitment<H::Digest>; 3]>,
    WTP: WordTriplePool,
    BH: BackendHook,
>(
    circuit: &C,
    seed_entropy: &[u8],
    binding: &[u8],
    num_iters: usize,
    options: ChallengeOptions<H::Digest, S, VDC, BH>,
) -> Zeroizing<Vec<u8>> {
    let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(seed_entropy, binding);
    for _ in 0..num_iters {
        let iter = builder.next_iter_hooked::<VDC, BH>(options.collector_arg(), options.hook_arg());
        circuit.exec(&mut iter.view_builder());
        iter.finalize();
    }
    return builder.finalize();
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
