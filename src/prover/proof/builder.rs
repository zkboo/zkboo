// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the ZKBoo proof builder.

use crate::{
    backend::Frontend,
    crypto::{GeneratesRandom, HashPRG, Hasher, PseudoRandomGenerator, Seed},
    prover::{
        challenge::{ChallengeGenerator, Party},
        proof::collectors::ResponseDataCollector,
        views::{ViewBuilderBackend, WordTriplePool, collectors::ResponseDataSelector},
    },
};
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Builder structure for ZKBoo proofs.
/// Encapsulates the process of iterative response generation based on given:
///
/// - seed entropy, to generate pseudo-random iteration seed triples;
/// - challenge entropy, to generate the sequence of challenges;
/// - number of iterations, i.e. number of responses in the proof.
///
#[derive(Debug)]
pub struct ProofBuilder<
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> {
    seed_prg: PS,
    challenge_generator: ChallengeGenerator<HashPRG<H>>,
    collector_init_arg: RDC::InitArg,
    num_iters: usize,
    num_iters_yielded: usize,
    _marker: core::marker::PhantomData<(PV, S, WTP)>,
}

impl<
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S, InitArg: Default>,
    WTP: WordTriplePool,
> ProofBuilder<H, PS, PV, S, RDC, WTP>
{
    /// Creates a new proof builder with the given seed entropy, challenge entropy,
    /// and number of iterations (i.e. number of responses in the proof).
    ///
    /// The [ResponseDataCollector] is initialized with its default argument.
    pub fn new(
        seed_entropy: &[u8],
        challenge_entropy: Zeroizing<Vec<u8>>,
        num_iters: usize,
    ) -> Self {
        return ProofBuilder {
            seed_prg: PS::new(seed_entropy),
            challenge_generator: ChallengeGenerator::new(HashPRG::<H>::new(&challenge_entropy)),
            num_iters,
            num_iters_yielded: 0,
            collector_init_arg: Default::default(),
            _marker: core::marker::PhantomData,
        };
    }
}

impl<
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> ProofBuilder<H, PS, PV, S, RDC, WTP>
{
    /// Variant of [ProofBuilder::new] accepting a custom initialization argument for the
    /// [ResponseDataCollector].
    pub fn new_with_arg(
        seed_entropy: &[u8],
        challenge_entropy: Zeroizing<Vec<u8>>,
        num_iters: usize,
        collector_init_arg: RDC::InitArg,
    ) -> Self {
        return ProofBuilder {
            seed_prg: PS::new(seed_entropy),
            challenge_generator: ChallengeGenerator::new(HashPRG::<H>::new(&challenge_entropy)),
            num_iters,
            num_iters_yielded: 0,
            collector_init_arg,
            _marker: core::marker::PhantomData,
        };
    }

    /// Returns the number of iterations (i.e. number of responses in the proof).
    pub fn num_iters(&self) -> usize {
        return self.num_iters;
    }

    /// Returns the number of iterations that have been yielded so far.
    pub fn num_iters_yielded(&self) -> usize {
        return self.num_iters_yielded;
    }

    /// Yields the next iteration of the proof building process, if any.
    pub fn next_iter(&mut self) -> Option<ProofBuildingIteration<H, PV, S, RDC, WTP>> {
        if self.num_iters_yielded == self.num_iters {
            return None;
        }
        let seeds: Zeroizing<[S; 3]> = Zeroizing::new(self.seed_prg.next());
        let challenge: Party = self.challenge_generator.next();
        let collector_init_arg = self.collector_init_arg;
        self.num_iters_yielded += 1;
        return Some(ProofBuildingIteration {
            view_builder: ViewBuilderBackend::new_with_arg(seeds, (challenge, collector_init_arg))
                .into_view_builder(),
        });
    }

    /// Returns an iterator over the iterations of the proof building process.
    pub fn iter(&'_ mut self) -> ProofBuildingIterator<'_, H, PS, PV, S, RDC, WTP> {
        return ProofBuildingIterator {
            proof_builder: self,
        };
    }

    /// Finalizes the builder.
    ///
    /// Returns an error if not all iterations have been yielded and finalized (necessarily in order).
    pub fn try_finalize(self) -> Result<(), Self> {
        if self.num_iters_yielded != self.num_iters {
            return Err(self);
        }
        Ok(())
    }

    /// Finalizes the builder.
    ///
    /// Panics if not all iterations have been yielded and finalized (necessarily in order).
    pub fn finalize(self) {
        assert_eq!(
            self.num_iters_yielded, self.num_iters,
            "Proof builder finalized before all iterations were yielded: num_iters_yielded = {}, num_iters = {}",
            self.num_iters_yielded, self.num_iters
        );
    }
}

/// Iterator over the iterations of the proof building process.
#[derive(Debug)]
pub struct ProofBuildingIterator<
    'a,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> {
    proof_builder: &'a mut ProofBuilder<H, PS, PV, S, RDC, WTP>,
}

impl<
    'a,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> Iterator for ProofBuildingIterator<'a, H, PS, PV, S, RDC, WTP>
{
    type Item = ProofBuildingIteration<H, PV, S, RDC, WTP>;

    /// Yields the next iteration of the proof building process, if any.
    fn next(&mut self) -> Option<Self::Item> {
        return self.proof_builder.next_iter();
    }

    /// Returns the number of iterations remaining to be yielded.
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.proof_builder.num_iters() - self.proof_builder.num_iters_yielded();
        return (remaining, Some(remaining));
    }
}

impl<
    'a,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> ExactSizeIterator for ProofBuildingIterator<'a, H, PS, PV, S, RDC, WTP>
{
    /// Returns the number of iterations remaining to be yielded.
    fn len(&self) -> usize {
        let remaining = self.proof_builder.num_iters() - self.proof_builder.num_iters_yielded();
        return remaining;
    }
}

/// Structure representing a single iteration of the proof building process,
/// exposing a [Frontend] that can be used to build an individual response.
#[derive(Debug)]
pub struct ProofBuildingIteration<
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> {
    view_builder:
        Frontend<ViewBuilderBackend<H, PV, S, ResponseDataSelector<H::Digest, S, RDC>, WTP>>,
}

impl<
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> ProofBuildingIteration<H, PV, S, RDC, WTP>
{
    /// Returns a reference to a [Frontend] used to build the response for this iteration.
    pub fn view_builder(
        &self,
    ) -> &Frontend<ViewBuilderBackend<H, PV, S, ResponseDataSelector<H::Digest, S, RDC>, WTP>> {
        return &self.view_builder;
    }

    /// Finalizes this iteration, returning the data collected by the [ResponseDataCollector].
    pub fn finalize(self) -> RDC::FinalizeRes {
        return self.view_builder.finalize();
    }
}
