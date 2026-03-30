// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions for building ZKBoo proofs.

use crate::{
    circuit::Circuit,
    crypto::{Hasher, PseudoRandomGenerator, Seed},
    prover::{
        proof::{
            Proof, ProofBuilder,
            collectors::{OwnedResponseDataCollector, ResponseDataCollector},
        },
        views::WordTriplePool,
    },
};
#[cfg(feature = "rayon")]
use crate::{
    crypto::HashPRG,
    prover::{challenge::ChallengeGenerator, views::ViewBuilderBackend},
};
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Function building a ZKBoo proof for a custom [ResponseDataCollector] implementation.
/// The finalization results for all iterations are returned as a vector.
pub fn build_proof_custom<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seed_entropy: &[u8],
    challenge_entropy: Zeroizing<Vec<u8>>,
    num_iters: usize,
    collector_init_arg: RDC::InitArg,
) -> Vec<RDC::FinalizeRes> {
    let mut proof_builder = ProofBuilder::<H, PS, PV, S, RDC, WTP>::new_with_arg(
        seed_entropy,
        challenge_entropy,
        num_iters,
        collector_init_arg,
    );
    let mut res_vec = Vec::new();
    for iter in proof_builder.iter() {
        circuit.exec(iter.view_builder());
        res_vec.push(iter.finalize());
    }
    return res_vec;
}

/// Function building a ZKBoo proof using the default [OwnedResponseDataCollector] implementation.
/// The proof is progressively constructed in memory and returned as the result.
pub fn build_proof<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seed_entropy: &[u8],
    challenge_entropy: Zeroizing<Vec<u8>>,
    num_iters: usize,
) -> Proof<H::Digest, S> {
    return build_proof_custom::<C, H, PS, PV, S, OwnedResponseDataCollector<H::Digest, S>, WTP>(
        circuit,
        seed_entropy,
        challenge_entropy,
        num_iters,
        (),
    );
}

/// Variant of [build_proof] that builds individual proof responses in parallel.
#[cfg(feature = "rayon")]
pub fn par_build_proof<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seed_entropy: &[u8],
    challenge_entropy: Zeroizing<Vec<u8>>,
    num_iters: usize,
) -> Proof<H::Digest, S>
where
    C: Sync,
    H::Digest: Send,
    S: Sync + Send,
{
    use rayon::prelude::*;
    let mut seed_prg = PS::new(seed_entropy);
    let mut challenge_generator = ChallengeGenerator::new(HashPRG::<H>::new(&challenge_entropy));
    // 1. Generate seeds and challenges for all iterations sequentially:
    let seed_challenge_vec: Vec<([S; 3], Party)> = (0..num_iters)
        .map(|_| (seed_prg.next(), challenge_generator.next()))
        .collect();
    // 2. Build the proof in parallel:
    let proof = seed_challenge_vec
        .into_par_iter()
        .map(|(seeds, challenge)| {
            let view_builder = ViewBuilderBackend::<
                H,
                PV,
                S,
                ResponseDataSelector<H::Digest, S, OwnedResponseDataCollector<H::Digest, S>>,
                WTP,
            >::new_with_arg(Zeroizing::new(seeds), (challenge, ()))
            .into_view_builder();
            circuit.exec(&view_builder);
            view_builder.finalize()
        })
        .collect();
    return proof;
}
