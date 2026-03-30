// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions for generating ZKBoo proofs.

#[cfg(feature = "rayon")]
use crate::prover::{challenge::par_build_challenge_entropy, proof::par_build_proof};
use crate::{
    circuit::Circuit,
    crypto::{Hasher, PseudoRandomGenerator, Seed},
    prover::{
        challenge::build_challenge_entropy,
        proof::{Proof, build_proof, build_proof_custom, collectors::ResponseDataCollector},
        views::WordTriplePool,
    },
};
use alloc::vec::Vec;

/// Build a proof for the given circuit, using the given number of iterations and seed entropy,
/// using a custom [ResponseDataCollector] implementation.
/// Returns the finalized responses from the collector.
pub fn prove_custom<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
>(
    circuit: &C,
    num_iters: usize,
    seed_entropy: &[u8],
    collector_init_arg: RDC::InitArg,
) -> Vec<RDC::FinalizeRes> {
    let challenge_entropy =
        build_challenge_entropy::<C, H, PS, PV, S, WTP>(circuit, seed_entropy, num_iters);
    return build_proof_custom::<C, H, PS, PV, S, RDC, WTP>(
        circuit,
        seed_entropy,
        challenge_entropy,
        num_iters,
        collector_init_arg,
    );
}

/// Build a proof for the given circuit, using the given number of iterations and seed entropy.
pub fn prove<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
>(
    circuit: &C,
    num_iters: usize,
    seed_entropy: &[u8],
) -> Proof<H::Digest, S> {
    let challenge_entropy =
        build_challenge_entropy::<C, H, PS, PV, S, WTP>(circuit, seed_entropy, num_iters);
    return build_proof::<C, H, PS, PV, S, WTP>(
        circuit,
        seed_entropy,
        challenge_entropy,
        num_iters,
    );
}

/// Variant of [prove] where responses are generated in parallel.
#[cfg(feature = "rayon")]
pub fn par_prove<
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
>(
    circuit: &C,
    num_iters: usize,
    seed_entropy: &[u8],
) -> Proof<H::Digest, S>
where
    C: Sync,
    H::Digest: Send,
    S: Sync + Send,
{
    let challenge_entropy =
        par_build_challenge_entropy::<C, H, PS, PV, S, WTP>(circuit, seed_entropy, num_iters);
    return par_build_proof::<C, H, PS, PV, S, WTP>(
        circuit,
        seed_entropy,
        challenge_entropy,
        num_iters,
    );
}
