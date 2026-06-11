// SPDX-License-Identifier: LGPL-3.0-or-later

//! Sources of per-response streamed data for the [ViewReplayerBackend](super::ViewReplayerBackend).

use crate::{
    crypto::{Digest, Seed},
    prover::proof::Response,
    verifier::replay::ViewReplayError,
    word::{ByWordType, CompositeWord, ShapeError, Word},
};
use core::array;

/// Source of the bulky, streamed per-response data: the AND messages received by the second opened
/// party from the unopened party, and the input share for party 2.
pub trait ReplaySource<D: Digest>: core::fmt::Debug {
    /// Yields the next AND message word for the second opened party.
    fn next_and_msg<W: Word, const N: usize>(&mut self) -> CompositeWord<W, N>;

    /// Yields the next input-share word for party 2.
    fn next_input_share2<W: Word, const N: usize>(&mut self) -> CompositeWord<W, N>;

    /// Yields the commitment digest for the unopened party.
    fn commitment_digest_unopened(&mut self) -> D;

    /// Checks, at finalisation, that the source was consumed exactly — no missing words and no
    /// leftover data.
    fn check_consumed(&self) -> Result<(), ViewReplayError>;
}

/// [ReplaySource] backed by a fully-materialised [Response].
#[derive(Debug)]
pub struct ResponseReplaySource<'a, D: Digest, S: Seed> {
    response: &'a Response<D, S>,
    and_msg_idx: ByWordType<usize>,
    input_share2_idx: ByWordType<usize>,
}

impl<'a, D: Digest, S: Seed> ResponseReplaySource<'a, D, S> {
    /// Wraps a response as a replay source, with both read cursors at the start.
    pub fn new(response: &'a Response<D, S>) -> Self {
        return Self {
            response,
            and_msg_idx: ByWordType::default(),
            input_share2_idx: ByWordType::default(),
        };
    }
}

impl<'a, D: Digest, S: Seed> ReplaySource<D> for ResponseReplaySource<'a, D, S> {
    /// Extracts the next AND message for the next party from the response.
    fn next_and_msg<W: Word, const N: usize>(&mut self) -> CompositeWord<W, N> {
        let and_msg_vec = self.response.and_msg_next_party().as_vec::<W>();
        let and_msg_idx = self.and_msg_idx.as_value_mut::<W>();
        if *and_msg_idx + N > and_msg_vec.len() {
            return CompositeWord::<W, N>::ZERO;
        }
        let and_msg =
            CompositeWord::<W, N>::from_le_words(array::from_fn(|i| and_msg_vec[*and_msg_idx + i]));
        *and_msg_idx += N;
        return and_msg;
    }

    fn next_input_share2<W: Word, const N: usize>(&mut self) -> CompositeWord<W, N> {
        let input_share2_vec = self
            .response
            .input_share_2()
            .expect("Failed to get input share 2")
            .as_vec::<W>();
        let input_share2_idx = self.input_share2_idx.as_value_mut::<W>();
        if *input_share2_idx + N > input_share2_vec.len() {
            return CompositeWord::<W, N>::ZERO;
        }
        let input_share2 = CompositeWord::<W, N>::from_le_words(array::from_fn(|i| {
            input_share2_vec[*input_share2_idx + i]
        }));
        *input_share2_idx += N;
        return input_share2;
    }

    fn commitment_digest_unopened(&mut self) -> D {
        return self.response.commitment_digest_unopened().clone();
    }

    fn check_consumed(&self) -> Result<(), ViewReplayError> {
        if self.and_msg_idx != self.response.and_msg_next_party().shape() {
            return Err(ViewReplayError::AndMsgShapeMismatch(ShapeError::new(
                self.response.and_msg_next_party().shape(),
                self.and_msg_idx,
            )));
        }
        if let Some(input_share_2) = self.response.input_share_2() {
            if self.input_share2_idx != input_share_2.shape() {
                return Err(ViewReplayError::InputShare2ShapeMismatch(ShapeError::new(
                    input_share_2.shape(),
                    self.input_share2_idx,
                )));
            }
        }
        return Ok(());
    }
}
