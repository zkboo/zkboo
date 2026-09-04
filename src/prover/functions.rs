// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions for generating ZKBoo proofs.

#[cfg(feature = "rayon")]
use crate::prover::{
    challenge::par_build_challenge_entropy,
    proof::{Proof, par_build_proof},
};
use crate::{
    backend::BackendHook,
    circuit::Circuit,
    crypto::{Hasher, PseudoRandomGenerator, Seed},
    prover::{
        challenge::{ChallengeOptions, build_challenge_entropy},
        proof::{ProofOptions, build_proof, collectors::ResponseDataCollector},
        views::{WordTriplePool, collectors::ViewCommitmentsRelayer},
    },
};
use alloc::vec::Vec;

/// Builds a proof of the given circuit, returning the finalisation result of every iteration.
pub fn prove<
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
    num_iters: usize,
    seed_entropy: &[u8],
    binding: &[u8],
    options: ProofOptions<H::Digest, S, RDC, BH>,
) -> Vec<RDC::FinalizeRes> {
    let challenge_options =
        ChallengeOptions::<H::Digest, S>::new().with_hook_arg::<BH>(options.hook_arg());
    let challenge_entropy = build_challenge_entropy::<
        C,
        H,
        PS,
        PV,
        S,
        ViewCommitmentsRelayer<H::Digest, S>,
        WTP,
        BH,
    >(circuit, seed_entropy, binding, num_iters, challenge_options);
    return build_proof::<C, H, PS, PV, S, RDC, WTP, BH>(
        circuit,
        seed_entropy,
        challenge_entropy,
        num_iters,
        options,
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
    binding: &[u8],
) -> Proof<H::Digest, S>
where
    C: Sync,
    H::Digest: Send,
    S: Sync + Send,
{
    let challenge_entropy =
        par_build_challenge_entropy::<C, H, PS, PV, S, WTP>(circuit, seed_entropy, binding, num_iters);
    return par_build_proof::<C, H, PS, PV, S, WTP>(
        circuit,
        seed_entropy,
        challenge_entropy,
        num_iters,
    );
}
