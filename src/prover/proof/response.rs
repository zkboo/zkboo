// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of ZKBoo responses.

use crate::{
    crypto::{Digest, Seed},
    prover::{challenge::Party, views::Views},
    word::Words,
};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// ZKBoo response to a challenge, containing the necessary data to open two views.
/// The challenge is stored implicitly into the variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "D: Serialize, S: Serialize",
    deserialize = "D: DeserializeOwned, S: DeserializeOwned"
))]
pub struct Response<D: Digest, S: Seed> {
    challenge: Party,
    seed_challenge_party: S,
    seed_next_party: S,
    input_share_party_2: Option<Words>,
    and_msg_next_party: Words,
    commitment_digest_unopened: D,
}

impl<D: Digest, S: Seed> Response<D, S> {
    /// Creates a new response for challenge party 0.
    pub fn new_0(seed_0: S, seed_1: S, commitment_digest_2: D, and_msg_1: Words) -> Self {
        return Self {
            challenge: 0usize.into(),
            seed_challenge_party: seed_0,
            seed_next_party: seed_1,
            commitment_digest_unopened: commitment_digest_2,
            and_msg_next_party: and_msg_1,
            input_share_party_2: None,
        };
    }

    /// Creates a new response for challenge party 1.
    pub fn new_1(
        commitment_digest_0: D,
        seed_1: S,
        seed_2: S,
        and_msg_2: Words,
        input_share_2: Words,
    ) -> Self {
        return Self {
            challenge: 1usize.into(),
            commitment_digest_unopened: commitment_digest_0,
            seed_challenge_party: seed_1,
            seed_next_party: seed_2,
            and_msg_next_party: and_msg_2,
            input_share_party_2: Some(input_share_2),
        };
    }

    /// Creates a new response for challenge party 2.
    pub fn new_2(
        seed_0: S,
        commitment_digest_1: D,
        seed_2: S,
        and_msg_3: Words,
        input_share_2: Words,
    ) -> Self {
        return Self {
            challenge: 2usize.into(),
            seed_next_party: seed_0,
            commitment_digest_unopened: commitment_digest_1,
            seed_challenge_party: seed_2,
            and_msg_next_party: and_msg_3,
            input_share_party_2: Some(input_share_2),
        };
    }

    /// The challenge to which this response corresponds.
    ///
    /// For challenge party `j`, the response opens the views for parties `j` and `(j+1)%3`.
    #[inline]
    pub fn challenge(&self) -> Party {
        return self.challenge;
    }

    /// The PRG seeds for the opened views in this response.
    ///
    /// For challenge party `j`, the seeds are for parties `j` and `(j+1)%3`.
    pub fn seeds(&self) -> [&S; 2] {
        return [&self.seed_challenge_party, &self.seed_next_party];
    }

    /// The input share for party 2, if included in this response.
    pub fn input_share_2(&self) -> Option<&Words> {
        return self.input_share_party_2.as_ref();
    }

    /// The commitment digest for the unopened view in this response.
    ///
    /// For challenge party `j`, the unopened view is for party `(j+2)%3`.
    pub fn commitment_digest_unopened(&self) -> &D {
        return &self.commitment_digest_unopened;
    }

    /// The AND message vector received by the second party opened in the response
    /// from the unopened party.
    ///
    /// For challenge party `j`, the AND messages are received by party `(j+1)%3`
    /// from party `(j+2)%3`.
    pub fn and_msg_next_party(&self) -> &Words {
        return &self.and_msg_next_party;
    }

    /// Constructs a response from the given view data and challenge, consuming the view data.
    ///
    /// A convenience alias of [Views::into_response].
    pub fn from_views(view_data: Views<D, S>, challenge: Party) -> Self {
        return view_data.into_response(challenge);
    }

    /// Serializes into a given byte vector.
    pub fn append_bytes(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.challenge.index() as u8);
        bytes.extend_from_slice(self.seed_challenge_party.as_ref());
        bytes.extend_from_slice(self.seed_next_party.as_ref());
        if let Some(input_share_2) = &self.input_share_party_2 {
            input_share_2.append_bytes(bytes);
        }
        bytes.extend_from_slice(self.commitment_digest_unopened.as_ref());
        self.and_msg_next_party.append_bytes(bytes);
    }

    /// Serializes into a byte vector.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        self.append_bytes(&mut bytes);
        return bytes;
    }
}

/// Type alias for a ZKBoo proof, as a [Vec] of [Response]s.
#[allow(type_alias_bounds)]
pub type Proof<D: Digest, S: Seed> = Vec<Response<D, S>>;
