// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of builder and frontend for ZKBoo challenge generation.

use crate::{
    backend::Frontend,
    crypto::{GeneratesRandom, Hasher, PseudoRandomGenerator, Seed},
    prover::views::{
        ViewBuilderBackend, ViewCommitment, WordTriplePool, collectors::ViewCommitmentsRelayer,
    },
};
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Builder structure to iteratively accumulate entropy for ZKBoo challenge generation.
#[derive(Debug)]
pub struct ChallengeBuilder<
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
> {
    num_iters_ingested: usize,
    seed_prg: PS,
    challenge_hasher: H,
    _marker: core::marker::PhantomData<(PV, S, WTP)>,
}

impl<H: Hasher, PS: PseudoRandomGenerator, PV: PseudoRandomGenerator, S: Seed, WTP: WordTriplePool>
    ChallengeBuilder<H, PS, PV, S, WTP>
{
    /// Creates a new challenge builder with the given seed entropy.
    pub fn new(seed_entropy: &[u8]) -> Self {
        return ChallengeBuilder {
            seed_prg: PS::new(seed_entropy),
            challenge_hasher: H::new(),
            num_iters_ingested: 0,
            _marker: core::marker::PhantomData,
        };
    }

    /// Number of iterations ingested so far.
    pub fn num_iters_ingested(&self) -> usize {
        return self.num_iters_ingested;
    }

    /// Starts a new challenge building iteration.
    pub fn next_iter(&'_ mut self) -> ChallengeBuildingIteration<'_, H, PS, PV, S, WTP> {
        let seeds: Zeroizing<[S; 3]> = Zeroizing::new(self.seed_prg.next());
        return ChallengeBuildingIteration {
            challenge_builder: self,
            view_builder: ViewBuilderBackend::new(seeds).into_view_builder(),
        };
    }

    /// Finalizes the builder, extracting the challenge entropy and number of iterations ingested.
    pub fn finalize(mut self) -> Zeroizing<Vec<u8>> {
        let challenge_entropy = Zeroizing::new(self.challenge_hasher.finalize().as_ref().to_vec());
        return challenge_entropy;
    }

    /// Updates the challenge hasher with the given view commitments.
    fn ingest_commitments(&mut self, commitments: &[ViewCommitment<H::Digest>; 3]) {
        let challenge_hasher = &mut self.challenge_hasher;
        for commitment in commitments {
            challenge_hasher.update(commitment.digest().as_ref());
            commitment.output_share().update_hasher(challenge_hasher);
        }
        self.num_iters_ingested += 1;
    }
}

/// Wrapper structure exposing a [Frontend] which can be used to build view commitments for
/// a single challenge building iteration.
#[derive(Debug)]
pub struct ChallengeBuildingIteration<
    'a,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
> {
    challenge_builder: &'a mut ChallengeBuilder<H, PS, PV, S, WTP>,
    view_builder: Frontend<ViewBuilderBackend<H, PV, S, ViewCommitmentsRelayer<H::Digest, S>, WTP>>,
}

impl<
    'a,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
> ChallengeBuildingIteration<'a, H, PS, PV, S, WTP>
{
    /// The view builder [Frontend] for this challenge building iteration.
    pub fn view_builder(
        &self,
    ) -> &Frontend<ViewBuilderBackend<H, PV, S, ViewCommitmentsRelayer<H::Digest, S>, WTP>> {
        return &self.view_builder;
    }

    /// Finalizes the challenge building iteration,
    /// ingesting the view commitments into the hasher state for the parent [ChallengeBuilder].
    pub fn finalize(self) {
        let this = core::mem::ManuallyDrop::new(self);
        let challenge_builder = unsafe { core::ptr::read(&this.challenge_builder) };
        let view_builder = unsafe { core::ptr::read(&this.view_builder) };
        let view_commitments = view_builder.finalize();
        challenge_builder.ingest_commitments(&view_commitments);
    }
}

impl<
    'a,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
> Drop for ChallengeBuildingIteration<'a, H, PS, PV, S, WTP>
{
    /// Panics if the iteration is dropped before being finalized.
    fn drop(&mut self) {
        panic!("Challenge building iteration was dropped before being finalized.")
    }
}
