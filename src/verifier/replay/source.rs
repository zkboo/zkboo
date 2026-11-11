// SPDX-License-Identifier: LGPL-3.0-or-later

//! Sources of per-response streamed data for the [ViewReplayerBackend](super::ViewReplayerBackend).

use crate::{
    crypto::{Digest, Seed},
    prover::proof::Response,
    verifier::replay::ViewReplayError,
    word::{ByWordType, CompositeWord, Shape, ShapeError, Word},
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
        let start = *and_msg_idx;
        *and_msg_idx += N;
        if start + N > and_msg_vec.len() {
            return CompositeWord::<W, N>::ZERO;
        }
        return CompositeWord::<W, N>::from_le_words(array::from_fn(|i| and_msg_vec[start + i]));
    }

    fn next_input_share2<W: Word, const N: usize>(&mut self) -> CompositeWord<W, N> {
        let input_share2_idx = self.input_share2_idx.as_value_mut::<W>();
        let start = *input_share2_idx;
        *input_share2_idx += N;
        let input_share2_vec = match self.response.input_share_2() {
            Some(share) => share.as_vec::<W>(),
            None => return CompositeWord::<W, N>::ZERO,
        };
        if start + N > input_share2_vec.len() {
            return CompositeWord::<W, N>::ZERO;
        }
        return CompositeWord::<W, N>::from_le_words(array::from_fn(|i| {
            input_share2_vec[start + i]
        }));
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
        let input_share2_shape = match self.response.input_share_2() {
            Some(share) => share.shape(),
            None => Shape::default(),
        };
        if self.input_share2_idx != input_share2_shape {
            return Err(ViewReplayError::InputShare2ShapeMismatch(ShapeError::new(
                input_share2_shape,
                self.input_share2_idx,
            )));
        }
        return Ok(());
    }
}
