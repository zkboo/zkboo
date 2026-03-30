// SPDX-License-Identifier: LGPL-3.0-or-later

//! Trait and implementations for collectors of [Views] data used by the view building logic.

use crate::{
    crypto::{Digest, Seed},
    prover::{
        challenge::Party,
        proof::collectors::ResponseDataCollector,
        views::{ViewCommitment, Views},
    },
    word::{
        CompositeWord, Word,
        collectors::{OwnedWordCollector, WordCollector, WordDiscarder},
    },
};
use core::{fmt::Debug, marker::PhantomData};

/// Trait for collectors of [Views] data used by the view building logic.
pub trait ViewsDataCollector<D: Digest, S: Seed>: Debug {
    /// The type for the additional initialisation argument passed to the constructor.
    type InitArg: Sized + Copy + Debug;

    /// The result of collector finalisation.
    type FinalizeRes;

    /// Instantiates a collector with the initial seeds for the three parties.
    fn new(seeds: &[S; 3], arg: Self::InitArg) -> Self;

    /// Pushes an input share word for party 2 into the collector.
    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>);

    /// Pushes an AND message triple into the collector.
    fn push_and_msgs<W: Word, const N: usize>(&mut self, and_msgs: [CompositeWord<W, N>; 3]);

    /// Finalizes the collector with the view commitments,
    /// consuming it and producing the collected result.
    fn finalize(self, commitments: [ViewCommitment<D>; 3]) -> Self::FinalizeRes;
}

/// [ViewsDataCollector] implementation generic on implementations of the [WordCollector] trait for
/// the input share for party 2 and the AND messages for each of the three parties.
///
/// The implementations must additionally implement [Default], and the [Default::default]
/// constructor is used to instantiate the collector for the input share of party 2 and the triple
/// of collectors for the AND messages of the parties.
#[derive(Debug, Clone)]
pub struct ViewsDataCollectorAdapter<
    D: Digest,
    S: Seed,
    WCI: WordCollector + Default,
    WCM: WordCollector + Default,
> {
    seeds: [S; 3],
    input_share_2: WCI,
    and_msgs: [WCM; 3],
    _marker: core::marker::PhantomData<D>,
}

impl<D: Digest, S: Seed, WCI: WordCollector + Default, WCM: WordCollector + Default>
    ViewsDataCollector<D, S> for ViewsDataCollectorAdapter<D, S, WCI, WCM>
{
    type InitArg = ();

    type FinalizeRes = (
        [S; 3],
        WCI::FinalizeResult,
        [WCM::FinalizeResult; 3],
        [ViewCommitment<D>; 3],
    );

    fn new(seeds: &[S; 3], _arg: Self::InitArg) -> Self {
        return Self {
            seeds: seeds.clone(),
            input_share_2: WCI::default(),
            and_msgs: [WCM::default(), WCM::default(), WCM::default()],
            _marker: core::marker::PhantomData,
        };
    }

    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
        self.input_share_2.push(word);
    }

    fn push_and_msgs<W: Word, const N: usize>(&mut self, and_msgs: [CompositeWord<W, N>; 3]) {
        for (collector, and_msg) in self.and_msgs.iter_mut().zip(and_msgs.into_iter()) {
            collector.push(and_msg);
        }
    }

    fn finalize(self, commitments: [ViewCommitment<D>; 3]) -> Self::FinalizeRes {
        return (
            self.seeds,
            self.input_share_2.finalize(),
            self.and_msgs.map(|collector| collector.finalize()),
            commitments,
        );
    }
}

/// [ViewsDataCollector] implementation based on internal [OwnedWordCollector]s
/// and returning [Views] upon finalization.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct OwnedViewsDataCollector<D: Digest, S: Seed> {
    inner: ViewsDataCollectorAdapter<D, S, OwnedWordCollector, OwnedWordCollector>,
}

impl<D: Digest, S: Seed> ViewsDataCollector<D, S> for OwnedViewsDataCollector<D, S> {
    type InitArg = ();
    type FinalizeRes = Views<D, S>;

    fn new(seeds: &[S; 3], arg: Self::InitArg) -> Self {
        return Self {
            inner: ViewsDataCollectorAdapter::new(seeds, arg),
        };
    }

    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
        self.inner.push_input_share2(word);
    }

    fn push_and_msgs<W: Word, const N: usize>(&mut self, and_msgs: [CompositeWord<W, N>; 3]) {
        self.inner.push_and_msgs(and_msgs);
    }

    fn finalize(self, commitments: [ViewCommitment<D>; 3]) -> Self::FinalizeRes {
        let (seeds, input_share_2, and_msgs, commitments) = self.inner.finalize(commitments);
        return Views::new(seeds, input_share_2, and_msgs, commitments);
    }
}

/// [ViewsDataCollector] implementation which returns the commitments on finalization,
/// without storing input shares or and messages.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct ViewCommitmentsRelayer<D: Digest, S: Seed> {
    inner: ViewsDataCollectorAdapter<D, S, WordDiscarder, WordDiscarder>,
}

impl<D: Digest, S: Seed> ViewsDataCollector<D, S> for ViewCommitmentsRelayer<D, S> {
    type InitArg = ();
    type FinalizeRes = [ViewCommitment<D>; 3];

    fn new(seeds: &[S; 3], arg: Self::InitArg) -> Self {
        return Self {
            inner: ViewsDataCollectorAdapter::new(seeds, arg),
        };
    }

    fn push_input_share2<W: Word, const N: usize>(&mut self, _word: CompositeWord<W, N>) {}

    fn push_and_msgs<W: Word, const N: usize>(&mut self, _and_msgs: [CompositeWord<W, N>; 3]) {}

    fn finalize(self, commitments: [ViewCommitment<D>; 3]) -> Self::FinalizeRes {
        return commitments;
    }
}

/// Adapter structure relaying views data to a [ResponseDataCollector] implementation
/// for a set challenge party.
#[derive(Debug)]
pub struct ResponseDataSelector<D: Digest, S: Seed, RDC: ResponseDataCollector<D, S>> {
    next_party: Party,
    inner: RDC,
    _marker: PhantomData<(D, S)>,
}

impl<D: Digest, S: Seed, RDC: ResponseDataCollector<D, S>> ViewsDataCollector<D, S>
    for ResponseDataSelector<D, S, RDC>
{
    type InitArg = (Party, RDC::InitArg);
    type FinalizeRes = RDC::FinalizeRes;

    fn new(seeds: &[S; 3], collector_init_arg: Self::InitArg) -> Self {
        let (challenge_party, collector_init_arg) = collector_init_arg;
        return Self {
            next_party: challenge_party.next(),
            inner: RDC::new(
                challenge_party,
                seeds[challenge_party.index()].clone(),
                seeds[challenge_party.next().index()].clone(),
                collector_init_arg,
            ),
            _marker: PhantomData,
        };
    }

    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
        self.inner.push_input_share2(word);
    }

    fn push_and_msgs<W: Word, const N: usize>(&mut self, _and_msgs: [CompositeWord<W, N>; 3]) {
        self.inner.push_and_msg(_and_msgs[self.next_party.index()]);
    }

    fn finalize(self, commitments: [ViewCommitment<D>; 3]) -> Self::FinalizeRes {
        let commitment_unopened = commitments
            .into_iter()
            .nth(self.next_party.next().index())
            .unwrap();
        return self.inner.finalize(commitment_unopened.into_digest());
    }
}
