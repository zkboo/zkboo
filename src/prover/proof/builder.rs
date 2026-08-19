// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the ZKBoo proof builder.

use crate::{
    backend::{Backend, BackendHook, Frontend, Hooked, NoHook},
    crypto::{GeneratesRandom, HashPRG, Hasher, PseudoRandomGenerator, Seed},
    prover::{
        challenge::{ChallengeGenerator, Party},
        proof::collectors::ResponseDataCollector,
        views::{ViewBuilderBackend, WordTriplePool, collectors::ResponseDataSelector},
    },
    word::Shape,
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
    BH: BackendHook = NoHook,
> {
    seed_prg: PS,
    challenge_generator: ChallengeGenerator<HashPRG<H>>,
    collector_init_arg: RDC::InitArg,
    hook_init_arg: BH::InitArg,
    capacity_hint: Shape,
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
> ProofBuilder<H, PS, PV, S, RDC, WTP, NoHook>
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
            hook_init_arg: (),
            capacity_hint: Shape::zero(),
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
> ProofBuilder<H, PS, PV, S, RDC, WTP, NoHook>
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
            hook_init_arg: (),
            capacity_hint: Shape::zero(),
            _marker: core::marker::PhantomData,
        };
    }

    /// Variant of [ProofBuilder::new_with_arg] that additionally reserves internal state-pool
    /// capacity for the given peak state shape (e.g. obtained from a profiling pre-pass over the
    /// circuit).
    ///
    /// Each iteration's view builder pool is reserved exactly to `capacity` before execution, so
    /// its heap sits at the true high-water mark instead of the next power of two above it. This
    /// changes only the pools' allocated capacity, never the produced responses: with an accurate
    /// (or larger) `capacity` the proof is byte-identical to [ProofBuilder::new_with_arg]. Passing
    /// [Shape::zero] recovers the unreserved behaviour exactly.
    pub fn new_with_arg_reserved(
        seed_entropy: &[u8],
        challenge_entropy: Zeroizing<Vec<u8>>,
        num_iters: usize,
        collector_init_arg: RDC::InitArg,
        capacity: Shape,
    ) -> Self {
        return ProofBuilder {
            seed_prg: PS::new(seed_entropy),
            challenge_generator: ChallengeGenerator::new(HashPRG::<H>::new(&challenge_entropy)),
            num_iters,
            num_iters_yielded: 0,
            collector_init_arg,
            hook_init_arg: (),
            capacity_hint: capacity,
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
    BH: BackendHook,
> ProofBuilder<H, PS, PV, S, RDC, WTP, BH>
{
    /// Variant of [ProofBuilder::new_with_arg] additionally accepting an init argument for a
    /// per-operation [BackendHook] that wraps each iteration's view builder backend.
    ///
    /// A fresh hook is built per iteration via [BackendHook::new] from `hook_init_arg`, firing
    /// around every backend operation — the linear ops (XOR, shifts, rotates) included — so it can
    /// service a platform watchdog at per-operation granularity during the proof pass, not just on
    /// the AND-message seam. With the default [NoHook] this is byte-identical to the unhooked path.
    ///
    /// ⚠️ The hook must not re-enter the backend (operations run inside the [Frontend]'s borrow); it
    /// should touch only its own state.
    pub fn new_with_arg_hooked(
        seed_entropy: &[u8],
        challenge_entropy: Zeroizing<Vec<u8>>,
        num_iters: usize,
        collector_init_arg: RDC::InitArg,
        hook_init_arg: BH::InitArg,
    ) -> Self {
        return ProofBuilder {
            seed_prg: PS::new(seed_entropy),
            challenge_generator: ChallengeGenerator::new(HashPRG::<H>::new(&challenge_entropy)),
            num_iters,
            num_iters_yielded: 0,
            collector_init_arg,
            hook_init_arg,
            capacity_hint: Shape::zero(),
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
    pub fn next_iter(&mut self) -> Option<ProofBuildingIteration<H, PV, S, RDC, WTP, BH>> {
        if self.num_iters_yielded == self.num_iters {
            return None;
        }
        let seeds: Zeroizing<[S; 3]> = Zeroizing::new(self.seed_prg.next());
        let challenge: Party = self.challenge_generator.next();
        let collector_init_arg = self.collector_init_arg;
        let hook_init_arg = self.hook_init_arg;
        self.num_iters_yielded += 1;
        let mut backend =
            ViewBuilderBackend::new_with_arg(seeds, (challenge, collector_init_arg));
        backend.reserve(self.capacity_hint);
        return Some(ProofBuildingIteration {
            view_builder: Hooked::new(BH::new(hook_init_arg), backend).into_frontend(),
        });
    }

    /// Returns an iterator over the iterations of the proof building process.
    pub fn iter(&'_ mut self) -> ProofBuildingIterator<'_, H, PS, PV, S, RDC, WTP, BH> {
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
    BH: BackendHook = NoHook,
> {
    proof_builder: &'a mut ProofBuilder<H, PS, PV, S, RDC, WTP, BH>,
}

impl<
    'a,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
    BH: BackendHook,
> Iterator for ProofBuildingIterator<'a, H, PS, PV, S, RDC, WTP, BH>
{
    type Item = ProofBuildingIteration<H, PV, S, RDC, WTP, BH>;

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
    BH: BackendHook,
> ExactSizeIterator for ProofBuildingIterator<'a, H, PS, PV, S, RDC, WTP, BH>
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
    BH: BackendHook = NoHook,
> {
    view_builder: Frontend<
        Hooked<BH, ViewBuilderBackend<H, PV, S, ResponseDataSelector<H::Digest, S, RDC>, WTP>>,
    >,
}

impl<
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
    BH: BackendHook,
> ProofBuildingIteration<H, PV, S, RDC, WTP, BH>
{
    /// Returns a reference to a [Frontend] used to build the response for this iteration.
    pub fn view_builder(
        &self,
    ) -> &Frontend<
        Hooked<BH, ViewBuilderBackend<H, PV, S, ResponseDataSelector<H::Digest, S, RDC>, WTP>>,
    > {
        return &self.view_builder;
    }

    /// Finalizes this iteration, returning the data collected by the [ResponseDataCollector].
    pub fn finalize(self) -> RDC::FinalizeRes {
        return self.view_builder.finalize();
    }
}
