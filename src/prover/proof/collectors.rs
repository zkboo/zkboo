// SPDX-License-Identifier: LGPL-3.0-or-later

//! Trait and implementations for collectors of [Response] data used by the response building logic.

use crate::{
    crypto::{Digest, Seed},
    prover::{challenge::Party, proof::Response},
    word::{
        CompositeWord, Word,
        collectors::{OwnedWordCollector, WordCollector},
    },
};
use core::fmt::Debug;

/// Trait for collectors of [Response] data used by the response building logic.
pub trait ResponseDataCollector<D: Digest, S: Seed>: Debug {
    /// The type for the additional initialisation argument passed to the constructor.
    type InitArg: Sized + Copy + Debug;

    /// The result of collector finalisation.
    type FinalizeRes;

    /// Instantiates a collector with the challenge party
    /// as well as the initial seeds for the challenge party and for the next party.
    fn new(
        challenge: Party,
        seed_challenge_party: S,
        seed_next_party: S,
        arg: Self::InitArg,
    ) -> Self;

    /// Pushes an input share word for party 2 into the collector.
    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>);

    /// Pushes an AND message for the next party into the collector.
    fn push_and_msg<W: Word, const N: usize>(&mut self, and_msg_next_party: CompositeWord<W, N>);

    /// Finalizes the collector with the commitment digest for the unopened party,
    /// consuming it and producing the collected result.
    fn finalize(self, commitment_digest_unopened: D) -> Self::FinalizeRes;
}

/// [ResponseDataCollector] implementation generic on implementations of the [WordCollector] trait
/// for the input share for party 2 and the AND messages for the next party.
///
/// The implementations must additionally implement [Default], and the [Default::default]
/// constructor is used to instantiate the collector for the input share of party 2
/// and the AND messages for the next party.
#[derive(Debug, Clone)]
pub struct ResponseDataCollectorAdapter<
    D: Digest,
    S: Seed,
    WCI: WordCollector + Default,
    WCM: WordCollector + Default,
> {
    challenge: Party,
    seed_challenge_party: S,
    seed_next_party: S,
    input_share_2: WCI,
    and_msgs_next_party: WCM,
    _marker: core::marker::PhantomData<D>,
}

impl<D: Digest, S: Seed, WCI: WordCollector + Default, WCM: WordCollector + Default>
    ResponseDataCollector<D, S> for ResponseDataCollectorAdapter<D, S, WCI, WCM>
{
    type InitArg = ();
    type FinalizeRes = (Party, S, S, WCI::FinalizeResult, WCM::FinalizeResult, D);

    fn new(
        challenge: Party,
        seed_challenge_party: S,
        seed_next_party: S,
        _arg: Self::InitArg,
    ) -> Self {
        return Self {
            challenge,
            seed_challenge_party,
            seed_next_party,
            input_share_2: WCI::default(),
            and_msgs_next_party: WCM::default(),
            _marker: core::marker::PhantomData,
        };
    }

    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
        self.input_share_2.push(word);
    }

    fn push_and_msg<W: Word, const N: usize>(&mut self, and_msg_next_party: CompositeWord<W, N>) {
        self.and_msgs_next_party.push(and_msg_next_party);
    }

    fn finalize(self, commitment_digest_unopened: D) -> Self::FinalizeRes {
        return (
            self.challenge,
            self.seed_challenge_party,
            self.seed_next_party,
            self.input_share_2.finalize(),
            self.and_msgs_next_party.finalize(),
            commitment_digest_unopened,
        );
    }
}

/// [ResponseDataCollector] implementation based on internal [OwnedWordCollector]s
/// and returning a [Response] upon finalization.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct OwnedResponseDataCollector<D: Digest, S: Seed> {
    inner: ResponseDataCollectorAdapter<D, S, OwnedWordCollector, OwnedWordCollector>,
}

impl<D: Digest, S: Seed> ResponseDataCollector<D, S> for OwnedResponseDataCollector<D, S> {
    type InitArg = ();
    type FinalizeRes = Response<D, S>;

    fn new(
        challenge: Party,
        seed_challenge_party: S,
        seed_next_party: S,
        arg: Self::InitArg,
    ) -> Self {
        return Self {
            inner: ResponseDataCollectorAdapter::new(
                challenge,
                seed_challenge_party,
                seed_next_party,
                arg,
            ),
        };
    }

    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
        self.inner.push_input_share2(word);
    }

    fn push_and_msg<W: Word, const N: usize>(&mut self, and_msg_next_party: CompositeWord<W, N>) {
        self.inner.push_and_msg(and_msg_next_party);
    }

    fn finalize(self, commitment_digest_unopened: D) -> Self::FinalizeRes {
        let (
            challenge,
            seed_challenge_party,
            seed_next_party,
            input_share_2,
            and_msg_next_party,
            commitment_digest_unopened,
        ) = self.inner.finalize(commitment_digest_unopened);
        return match challenge.index() {
            0 => Response::new_0(
                seed_challenge_party,
                seed_next_party,
                commitment_digest_unopened,
                and_msg_next_party,
            ),
            1 => Response::new_1(
                commitment_digest_unopened,
                seed_challenge_party,
                seed_next_party,
                and_msg_next_party,
                input_share_2,
            ),
            2 => Response::new_2(
                seed_next_party,
                commitment_digest_unopened,
                seed_challenge_party,
                and_msg_next_party,
                input_share_2,
            ),
            _ => unreachable!(),
        };
    }
}
