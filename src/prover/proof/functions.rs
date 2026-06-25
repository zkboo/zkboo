// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions for building ZKBoo proofs.

use crate::{
    backend::BackendHook,
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
    crypto::{GeneratesRandom, HashPRG},
    prover::{
        challenge::{ChallengeGenerator, Party},
        views::{ViewBuilderBackend, collectors::ResponseDataSelector},
    },
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

/// Variant of [build_proof_custom] that additionally wraps each iteration's view builder backend
/// with a per-operation [BackendHook], built fresh per iteration from `hook_init_arg`.
///
/// The hook fires around every backend operation — the linear ops (XOR, shifts, rotates) included —
/// so it can service a platform watchdog at per-operation granularity through the AND-silent
/// stretches of a circuit pass. With `BH = NoHook` this is byte-identical to [build_proof_custom].
pub fn build_proof_custom_hooked<
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
    collector_init_arg: RDC::InitArg,
    hook_init_arg: BH::InitArg,
) -> Vec<RDC::FinalizeRes> {
    let mut proof_builder = ProofBuilder::<H, PS, PV, S, RDC, WTP, BH>::new_with_arg_hooked(
        seed_entropy,
        challenge_entropy,
        num_iters,
        collector_init_arg,
        hook_init_arg,
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

/// Variant of [build_proof] that wraps each iteration's view builder backend with a per-operation
/// [BackendHook], built fresh per iteration from `hook_init_arg`. With `BH = NoHook` this is
/// byte-identical to [build_proof].
pub fn build_proof_hooked<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
    BH: BackendHook,
>(
    circuit: &C,
    seed_entropy: &[u8],
    challenge_entropy: Zeroizing<Vec<u8>>,
    num_iters: usize,
    hook_init_arg: BH::InitArg,
) -> Proof<H::Digest, S> {
    return build_proof_custom_hooked::<
        C,
        H,
        PS,
        PV,
        S,
        OwnedResponseDataCollector<H::Digest, S>,
        WTP,
        BH,
    >(
        circuit,
        seed_entropy,
        challenge_entropy,
        num_iters,
        (),
        hook_init_arg,
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
