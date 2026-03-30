// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the ZKBoo verifier.

use crate::{
    backend::Frontend,
    crypto::{GeneratesRandom, HashPRG, Hasher, PseudoRandomGenerator, Seed},
    prover::{
        challenge::{ChallengeGenerator, PartyVec},
        proof::Response,
        views::ViewCommitment,
    },
    verifier::replay::{ViewReplayError, ViewReplayerBackend, WordPairPool},
    word::Words,
};
use zeroize::Zeroizing;

/// Struct for iterative ZKBoo proof verification.
#[derive(Debug)]
pub struct Verifier<'a, H: Hasher, PV: PseudoRandomGenerator, S: Seed, WPP: WordPairPool> {
    expected_output: &'a Words,
    challenge_hasher: H,
    challenges: PartyVec,
    num_iters_ingested: usize,
    _marker: core::marker::PhantomData<(PV, S, WPP)>,
}

impl<'a, H: Hasher, PV: PseudoRandomGenerator, S: Seed, WPP: WordPairPool>
    Verifier<'a, H, PV, S, WPP>
{
    /// Creates a new [Verifier] for the given expected output.
    pub fn new(expected_output: &'a Words) -> Self {
        return Self {
            expected_output,
            challenge_hasher: H::new(),
            challenges: PartyVec::new(),
            num_iters_ingested: 0,
            _marker: core::marker::PhantomData,
        };
    }

    /// Returns the number of iterations that have been ingested by this verifier so far.
    pub fn num_iters_ingested(&self) -> usize {
        return self.num_iters_ingested;
    }

    /// Yields the next iteration for the verification process.
    pub fn next_iter<'b, 'c>(
        &'c mut self,
        response: &'b Response<H::Digest, S>,
    ) -> VerifyingIteration<'a, 'b, 'c, H, PV, S, WPP> {
        self.challenges.push(response.challenge());
        let view_replayer =
            ViewReplayerBackend::<H, PV, S, WPP>::new(response).into_view_replayer();
        return VerifyingIteration {
            verifier: self,
            view_replayer,
        };
    }

    /// Finalizes the verifier, returning the validity of the proof.
    pub fn finalize(mut self) -> bool {
        let challenge_entropy = Zeroizing::new(self.challenge_hasher.finalize().as_ref().to_vec());
        let mut challenge_generator =
            ChallengeGenerator::new(HashPRG::<H>::new(&challenge_entropy));
        for challenge in &self.challenges {
            if challenge_generator.next() != challenge {
                return false;
            }
        }
        return true;
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

/// A single iteration of the ZKBoo proof verification process, which can be used to replay a single
/// view of the proof and ingest its view commitment into the parent [Verifier].
#[derive(Debug)]
pub struct VerifyingIteration<
    'a: 'b,
    'b,
    'c,
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    WPP: WordPairPool,
> {
    verifier: &'c mut Verifier<'a, H, PV, S, WPP>,
    view_replayer: Frontend<ViewReplayerBackend<'b, H, PV, S, WPP>>,
}

impl<'a, 'b, 'c, H: Hasher, PV: PseudoRandomGenerator, S: Seed, WPP: WordPairPool>
    VerifyingIteration<'a, 'b, 'c, H, PV, S, WPP>
{
    /// Returns a [Frontend] which can be used to replay the view corresponding to this iteration.
    pub fn view_replayer(&self) -> &Frontend<ViewReplayerBackend<'b, H, PV, S, WPP>> {
        return &self.view_replayer;
    }

    /// Finalizes this iteration, ingesting the view commitments produced by the view replayer
    /// into the parent [Verifier] (as well as returning the commitments themselves).
    pub fn finalize(self) -> Result<[ViewCommitment<H::Digest>; 3], ViewReplayError> {
        let this = core::mem::ManuallyDrop::new(self);
        let verifier = unsafe { core::ptr::read(&this.verifier) };
        let view_replayer = unsafe { core::ptr::read(&this.view_replayer) };
        let view_commitments = view_replayer.finalize_with_arg(verifier.expected_output)?;
        verifier.ingest_commitments(&view_commitments);
        return Ok(view_commitments);
    }
}

impl<'a, 'b, 'c, H: Hasher, PV: PseudoRandomGenerator, S: Seed, WPP: WordPairPool> Drop
    for VerifyingIteration<'a, 'b, 'c, H, PV, S, WPP>
{
    /// Panics if this iteration is dropped before being finalized.
    fn drop(&mut self) {
        panic!("Verifying iteration was dropped before being finalized.")
    }
}
