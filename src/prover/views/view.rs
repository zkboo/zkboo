// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of view data for the ZKBoo MPC-in-the-Head protocol.

use crate::{
    crypto::{Digest, Seed},
    prover::{challenge::Party, proof::Response},
    utils::ZeroizingIntoInner,
    word::Words,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

/// Commitment to a single view, consisting of the hash digest and output share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "D: Serialize", deserialize = "D: DeserializeOwned"))]
pub struct ViewCommitment<D: Digest> {
    digest: D,
    output_share: Words,
}

impl<D: Digest> ViewCommitment<D> {
    /// Creates a new view commitment with the given digest and output share.
    pub fn new(digest: D, output_share: Words) -> Self {
        return Self {
            digest,
            output_share,
        };
    }

    /// The hash digest of the view to which this commitment refers.
    pub fn digest(&self) -> &D {
        return &self.digest;
    }

    /// Consumes this view commitment and returns the hash digest.
    pub fn into_digest(self) -> D {
        return self.digest;
    }

    /// The output share of the view to which this commitment refers.
    pub fn output_share(&self) -> &Words {
        return &self.output_share;
    }
}

/// Data for a view triple in the MPC-in-the-Head protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Views<D: Digest, S: Seed> {
    seeds: Zeroizing<[S; 3]>,
    input_share_2: Words,
    and_msgs: [Words; 3],
    commitments: [ViewCommitment<D>; 3],
}

impl<D: Digest, S: Seed> Views<D, S> {
    /// Assembles a view triple from its components.
    pub fn new(
        seeds: [S; 3],
        input_share_2: Words,
        and_msgs: [Words; 3],
        commitments: [ViewCommitment<D>; 3],
    ) -> Self {
        for p in 0usize..2 {
            assert_eq!(
                commitments[p].output_share().shape(),
                commitments[p + 1].output_share().shape(),
                "All view output shares must have the same shape",
            );
            assert_eq!(
                and_msgs[p].shape(),
                and_msgs[p + 1].shape(),
                "All AND message vectors must have the same shape",
            );
        }
        return Self {
            seeds: Zeroizing::new(seeds),
            input_share_2,
            and_msgs,
            commitments,
        };
    }

    /// Seeds to the three view [PseudoRandomGenerator](crate::crypto::PseudoRandomGenerator)s.
    pub fn seeds(&self) -> &[S; 3] {
        return &self.seeds;
    }

    /// The input share for party 2.
    pub fn input_share_2(&self) -> &Words {
        return &self.input_share_2;
    }

    /// The AND message vectors produced by the three views.
    pub fn and_msgs(&self) -> &[Words; 3] {
        return &self.and_msgs;
    }

    /// The hash commitments computed for the three views.
    pub fn commitments(&self) -> &[ViewCommitment<D>; 3] {
        return &self.commitments;
    }

    /// Produces a response for the given challenge.
    pub fn as_response(&self, challenge: Party) -> Response<D, S> {
        // Construct and return the response:
        return match challenge.index() {
            0 => Response::new_0(
                self.seeds()[0].clone(),
                self.seeds()[1].clone(),
                self.commitments[2].digest().clone(),
                self.and_msgs()[1].clone(),
            ),
            1 => Response::new_1(
                self.commitments[0].digest().clone(),
                self.seeds()[1].clone(),
                self.seeds()[2].clone(),
                self.and_msgs()[2].clone(),
                self.input_share_2().clone(),
            ),
            2 => Response::new_2(
                self.seeds()[0].clone(),
                self.commitments[1].digest().clone(),
                self.seeds()[2].clone(),
                self.and_msgs()[0].clone(),
                self.input_share_2().clone(),
            ),
            _ => unreachable!(),
        };
    }

    /// Consumes this view data into a response for the given challenge.
    pub fn into_response(self, challenge: Party) -> Response<D, S> {
        // let init = self.init;
        // let ([seed_0, seed_1, seed_2], input_share_2) = init.destructure();
        let [seed_0, seed_1, seed_2] = self.seeds.into_inner();
        let input_share_2 = self.input_share_2;
        let [commitment_0, commitment_1, commitment_2] = self.commitments;
        let commitment_digest_0 = commitment_0.digest;
        let commitment_digest_1 = commitment_1.digest;
        let commitment_digest_2 = commitment_2.digest;
        let [and_msg_vec_0, and_msg_vec_1, and_msg_vec_2] = self.and_msgs;
        // Construct and return the response:
        return match challenge.index() {
            0 => Response::new_0(seed_0, seed_1, commitment_digest_2, and_msg_vec_1),
            1 => Response::new_1(
                commitment_digest_0,
                seed_1,
                seed_2,
                and_msg_vec_2,
                input_share_2,
            ),
            2 => Response::new_2(
                seed_0,
                commitment_digest_1,
                seed_2,
                and_msg_vec_0,
                input_share_2,
            ),
            _ => unreachable!(),
        };
    }
}
