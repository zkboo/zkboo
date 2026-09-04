// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions for building ZKBoo proofs.

use crate::{
    backend::BackendHook,
    circuit::Circuit,
    crypto::{Hasher, PseudoRandomGenerator, Seed},
    prover::{
        proof::{
            ProofBuilder, ProofOptions,
            collectors::ResponseDataCollector,
        },
        views::WordTriplePool,
    },
};
#[cfg(feature = "rayon")]
use crate::{
    crypto::{GeneratesRandom, HashPRG},
    prover::proof::{Proof, collectors::OwnedResponseDataCollector},
    prover::{
        challenge::{ChallengeGenerator, Party},
        views::{ViewBuilderBackend, collectors::ResponseDataSelector},
    },
};
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Builds a ZKBoo proof, returning the finalisation result of every iteration.
pub fn build_proof<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
    BH: BackendHook,
>(
    circuit: &C,
    seed_entropy: &[u8],
    challenge_entropy: Zeroizing<Vec<u8>>,
    num_iters: usize,
    options: ProofOptions<H::Digest, S, RDC, BH>,
) -> Vec<RDC::FinalizeRes> {
    let mut proof_builder = ProofBuilder::<H, PS, PV, S, RDC, WTP, BH>::new(
        seed_entropy,
        challenge_entropy,
        num_iters,
        options,
    );
    let mut res_vec = Vec::new();
    for iter in proof_builder.iter() {
        circuit.exec(iter.view_builder());
        res_vec.push(iter.finalize());
    }
    return res_vec;
}

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
