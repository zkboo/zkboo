// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of builder and frontend for ZKBoo challenge generation.

use crate::{
    backend::{Backend, BackendHook, Frontend, Hooked, NoHook},
    crypto::{TAG_CHALLENGE, absorb_framed, GeneratesRandom, Hasher, PseudoRandomGenerator, Seed},
    prover::views::{
        ViewBuilderBackend, ViewCommitment, WordTriplePool,
        collectors::{ViewCommitmentsRelayer, ViewsDataCollector},
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
    /// Creates a new challenge builder with the given seed entropy and binding message.
    pub fn new(seed_entropy: &[u8], binding: &[u8]) -> Self {
        let mut challenge_hasher = H::new();
        absorb_framed(&mut challenge_hasher, TAG_CHALLENGE, binding);
        return ChallengeBuilder {
            seed_prg: PS::new(seed_entropy),
            challenge_hasher,
            num_iters_ingested: 0,
            _marker: core::marker::PhantomData,
        };
    }

    /// Number of iterations ingested so far.
    pub fn num_iters_ingested(&self) -> usize {
        return self.num_iters_ingested;
    }

    /// Starts a new challenge building iteration using the default [ViewCommitmentsRelayer]
    /// collector, which simply relays the view commitments for ingestion into the challenge hasher.
    pub fn next_iter(
        &'_ mut self,
    ) -> ChallengeBuildingIteration<'_, H, PS, PV, S, ViewCommitmentsRelayer<H::Digest, S>, WTP>
    {
        return self.next_iter_custom(());
    }

    /// Starts a new challenge building iteration with a caller-chosen [ViewsDataCollector].
    pub fn next_iter_custom<VDC>(
        &'_ mut self,
        collector_init_arg: VDC::InitArg,
    ) -> ChallengeBuildingIteration<'_, H, PS, PV, S, VDC, WTP>
    where
        VDC: ViewsDataCollector<H::Digest, S, FinalizeRes = [ViewCommitment<H::Digest>; 3]>,
    {
        return self.next_iter_hooked::<VDC, NoHook>(collector_init_arg, ());
    }

    /// Starts a new challenge building iteration with both a caller-chosen [ViewsDataCollector] and
    /// a per-operation [BackendHook] wrapping the view builder backend.
    pub fn next_iter_hooked<VDC, BH>(
        &'_ mut self,
        collector_init_arg: VDC::InitArg,
        hook_init_arg: BH::InitArg,
    ) -> ChallengeBuildingIteration<'_, H, PS, PV, S, VDC, WTP, BH>
    where
        VDC: ViewsDataCollector<H::Digest, S, FinalizeRes = [ViewCommitment<H::Digest>; 3]>,
        BH: BackendHook,
    {
        let seeds: Zeroizing<[S; 3]> = Zeroizing::new(self.seed_prg.next());
        return ChallengeBuildingIteration {
            challenge_builder: self,
            view_builder: Hooked::new(
                BH::new(hook_init_arg),
                ViewBuilderBackend::new_with_arg(seeds, collector_init_arg),
            )
            .into_frontend(),
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
    VDC: ViewsDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
    BH: BackendHook = NoHook,
> {
    challenge_builder: &'a mut ChallengeBuilder<H, PS, PV, S, WTP>,
    view_builder: Frontend<Hooked<BH, ViewBuilderBackend<H, PV, S, VDC, WTP>>>,
}

impl<
    'a,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    VDC: ViewsDataCollector<H::Digest, S, FinalizeRes = [ViewCommitment<H::Digest>; 3]>,
    WTP: WordTriplePool,
    BH: BackendHook,
> ChallengeBuildingIteration<'a, H, PS, PV, S, VDC, WTP, BH>
{
    /// The view builder [Frontend] for this challenge building iteration.
    pub fn view_builder(&self) -> &Frontend<Hooked<BH, ViewBuilderBackend<H, PV, S, VDC, WTP>>> {
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
    VDC: ViewsDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
    BH: BackendHook,
> Drop for ChallengeBuildingIteration<'a, H, PS, PV, S, VDC, WTP, BH>
{
    /// Panics if the iteration is dropped before being finalized.
    fn drop(&mut self) {
        panic!("Challenge building iteration was dropped before being finalized.")
    }
}
