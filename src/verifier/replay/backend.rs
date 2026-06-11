// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the view replay backend for ZKBoo circuits.

use crate::{
    backend::{Backend, Frontend},
    crypto::{GeneratesRandom, Hasher, PseudoRandomGenerator, Seed},
    prover::{challenge::Party, proof::Response, views::ViewCommitment},
    verifier::replay::{
        WordPairPool,
        source::{ReplaySource, ResponseReplaySource},
    },
    word::{
        CompositeWord, ShapeError, Word, WordIdx, Words,
        collectors::{OwnedWordCollector, WordCollector},
    },
};
use core::{array, marker::PhantomData};

/// [Backend] to replay the opened views for two parties in the MPC-in-the-Head protocol.
///
/// The bulky per-response data (AND messages and the party-2 input share) is supplied by a
/// [ReplaySource]. By default this is a [ResponseReplaySource] reading from a materialised
/// [Response], but any source — e.g. one streaming words from a live prover — can be used.
#[derive(Debug)]
pub struct ViewReplayerBackend<
    'a,
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    WPP: WordPairPool,
    RS: ReplaySource<<H as Hasher>::Digest> = ResponseReplaySource<'a, <H as Hasher>::Digest, S>,
> {
    challenge: Party,
    source: RS,
    prgs: [PV; 2],
    states: WPP,
    hashers: [H; 2],
    outputs: [OwnedWordCollector; 2],
    _marker: PhantomData<(&'a Words, fn() -> S)>,
}

impl<
    'a,
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    WPP: WordPairPool,
    RS: ReplaySource<H::Digest>,
> ViewReplayerBackend<'a, H, PV, S, WPP, RS>
{
    /// Creates a new view replayer backend from a challenge, the two opened seeds, and a
    /// [ReplaySource] supplying the streamed AND messages, input shares and unopened digest.
    pub fn with_source(challenge: Party, opened_seeds: [&S; 2], source: RS) -> Self {
        return Self {
            challenge,
            source,
            prgs: array::from_fn(|p| PV::new(opened_seeds[p].as_ref())),
            hashers: array::from_fn(|_| H::new()),
            states: WPP::default(),
            outputs: array::from_fn(|_| OwnedWordCollector::new()),
            _marker: PhantomData,
        };
    }

    /// Wraps this view replayer backend into a [Frontend].
    ///
    /// Alias of [Backend::into_frontend].
    pub fn into_view_replayer(self) -> Frontend<Self> {
        return self.into_frontend();
    }

    /// Helper method to update internal state state of the two party hashers with the
    /// little-endian bytes from the corresponding words in the given word pair.
    fn update_hashers<W: Word, const N: usize>(&mut self, word_pair: [CompositeWord<W, N>; 2]) {
        word_pair
            .iter()
            .zip(self.hashers.iter_mut())
            .for_each(|(w, hasher)| {
                w.to_le_bytes().iter().for_each(|bs| {
                    hasher.update(bs.as_ref());
                });
            });
    }

    /// Helper method applying the given unary operation to the state of each party.
    fn unop<W: Word, const N: usize, F: Fn(CompositeWord<W, N>, Party) -> CompositeWord<W, N>>(
        &mut self,
        in_: WordIdx<W, N>,
        out: WordIdx<W, N>,
        op: F,
    ) {
        let ins = self.states.read(in_);

        let outs: [_; 2] = array::from_fn(|p| op(ins[p], p.into()));

        self.update_hashers(outs);
        self.states.write(out, outs);
    }

    /// Helper method applying the given binary operation to the state of each party.
    fn binop<
        W: Word,
        const N: usize,
        F: Fn(CompositeWord<W, N>, CompositeWord<W, N>, Party) -> CompositeWord<W, N>,
    >(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
        op: F,
    ) {
        let inls = self.states.read(inl);
        let inrs = self.states.read(inr);

        let outs: [_; 2] = array::from_fn(|p| op(inls[p], inrs[p], p.into()));

        self.update_hashers(outs);
        self.states.write(out, outs);
    }

    /// Helper method applying the given binary operation (const rhs) to the state of each party.
    fn binop_const<
        W: Word,
        const N: usize,
        F: Fn(CompositeWord<W, N>, CompositeWord<W, N>, Party) -> CompositeWord<W, N>,
    >(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
        op: F,
    ) {
        let inls = self.states.read(inl);
        let inrs = [inr, inr];

        let outs: [_; 2] = array::from_fn(|p| op(inls[p], inrs[p], p.into()));

        self.update_hashers(outs);
        self.states.write(out, outs);
    }

    /// Generates and returns the next random words for the two parties using the view PRGs.
    fn next_rand_words<W: Word, const N: usize>(&mut self) -> [CompositeWord<W, N>; 2] {
        return [self.prgs[0].next(), self.prgs[1].next()];
    }
}

impl<'a, H: Hasher, PV: PseudoRandomGenerator, S: Seed, WPP: WordPairPool>
    ViewReplayerBackend<'a, H, PV, S, WPP, ResponseReplaySource<'a, H::Digest, S>>
{
    /// Creates a new view replayer backend reading from a materialised [Response].
    pub fn new(response: &'a Response<H::Digest, S>) -> Self {
        return Self::with_source(
            response.challenge(),
            response.seeds(),
            ResponseReplaySource::new(response),
        );
    }
}

/// Errors that can occur during view replay.
#[derive(Debug)]
pub enum ViewReplayError {
    /// The shape of the expected output does not match the shape of the output shares
    /// generated by the view replay process.
    OutputShapeMismatch(ShapeError),
    /// The shape of the AND message for the next party does not match the shape of AND messages
    /// generated by the view replay process.
    AndMsgShapeMismatch(ShapeError),
    /// The shape of input share for party 2 does not match the shape of input share for party 2
    /// generated by the view replay process.
    InputShare2ShapeMismatch(ShapeError),
}

impl<
    'a,
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    WPP: WordPairPool,
    RS: ReplaySource<H::Digest>,
> Backend for ViewReplayerBackend<'a, H, PV, S, WPP, RS>
{
    type FinalizeArg = &'a Words;
    type FinalizeResult = Result<[ViewCommitment<H::Digest>; 3], ViewReplayError>;

    fn finalize(mut self, expected_output: Self::FinalizeArg) -> Self::FinalizeResult {
        if expected_output.shape() != self.outputs[0].words().shape() {
            return Err(ViewReplayError::OutputShapeMismatch(ShapeError::new(
                self.outputs[0].words().shape(),
                expected_output.shape(),
            )));
        }
        self.source.check_consumed()?;
        // The unopened commitment digest arrives last, after all AND messages and input shares.
        let digest_p2 = self.source.commitment_digest_unopened();
        unsafe {
            // Set to manually drop (because of zeroization):
            let mut self_ = core::mem::ManuallyDrop::new(self);
            // Manually read all fields:
            let _source = core::ptr::read(&mut self_.source);
            let _prgs = core::ptr::read(&mut self_.prgs);
            let _states = core::ptr::read(&mut self_.states);
            let hashers = core::ptr::read(&mut self_.hashers);
            let outputs = core::ptr::read(&mut self_.outputs);
            let challenge = self_.challenge;
            // Perform the necessary computations:
            let [output_p0, output_p1] = outputs.map(|collector| collector.finalize());
            let output_p2 = (&(expected_output ^ &output_p0).unwrap() ^ &output_p1).unwrap();
            let [digest_p0, digest_p1] = hashers.map(|mut hasher| hasher.finalize());
            let commitments = [
                ViewCommitment::new(digest_p0, output_p0),
                ViewCommitment::new(digest_p1, output_p1),
                ViewCommitment::new(digest_p2, output_p2),
            ];
            let mut commitments = core::mem::ManuallyDrop::new(commitments);
            let challenge = challenge.index();
            let idxs = [
                (3 - challenge) % 3,
                (4 - challenge) % 3,
                (5 - challenge) % 3,
            ];
            let res = [
                core::ptr::read(&mut commitments[idxs[0]]),
                core::ptr::read(&mut commitments[idxs[1]]),
                core::ptr::read(&mut commitments[idxs[2]]),
            ];
            return Ok(res);
        }
    }

    fn input<W: Word, const N: usize>(&mut self, _word: CompositeWord<W, N>) -> WordIdx<W, N> {
        return match self.challenge.index() {
            0 => {
                let input_share_0 = self.prgs[0].next();
                let input_share_1 = self.prgs[1].next();

                let idx = self.states.alloc();
                self.states.write(idx, [input_share_0, input_share_1]);
                idx
            }
            1 => {
                let input_share1 = self.prgs[0].next();
                let input_share2 = self.source.next_input_share2();

                let idx = self.states.alloc();
                self.states.write(idx, [input_share1, input_share2]);
                idx
            }
            2 => {
                let input_share2 = self.source.next_input_share2();
                let input_share0 = self.prgs[1].next();

                let idx = self.states.alloc();
                self.states.write(idx, [input_share2, input_share0]);
                idx
            }
            _ => unreachable!(),
        };
    }

    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N> {
        return self.states.alloc();
    }

    fn constant<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>, out: WordIdx<W, N>) {
        self.states.write(out, [word, word]);
    }

    fn from_le_words<W: Word, const N: usize>(
        &mut self,
        ins: [WordIdx<W, 1>; N],
        out: WordIdx<W, N>,
    ) {
        let ins = ins.map(|idx| self.states.read(idx));
        let ins_shares: [_; 2] = array::from_fn(|p| ins.map(|word| word[p].into()));
        let out_shares = ins_shares.map(|shares| CompositeWord::from_le_words(shares));
        self.states.write(out, out_shares);
    }

    fn to_le_words<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        outs: [WordIdx<W, 1>; N],
    ) {
        let in_shares = self.states.read(in_);
        let in_shares = in_shares.map(|word| word.to_le_words());
        let in_word_shares: [_; N] = array::from_fn(|n| in_shares.map(|share| share[n].into()));
        for (out, word_shares) in outs.into_iter().zip(in_word_shares.into_iter()) {
            self.states.write(out, word_shares);
        }
    }

    fn output<W: Word, const N: usize>(&mut self, out: WordIdx<W, N>) {
        let output_shares = self.states.read(out);

        for (output_share, collector) in output_shares.into_iter().zip(self.outputs.iter_mut()) {
            collector.push(output_share);
        }
    }

    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.states.decrease_refcount(idx);
    }

    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.states.increase_refcount(idx);
    }

    fn not<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        let challenge = self.challenge;
        self.unop(in_, out, |w, p| {
            if (p.index() + challenge.index()) % 3 == 0 {
                !w
            } else {
                w
            }
        });
    }

    fn bitxor_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        let challenge = self.challenge;
        self.binop_const(inl, inr, out, |wl, wr, p| {
            if (p.index() + challenge.index()) % 3 == 0 {
                wl ^ wr
            } else {
                wl
            }
        });
    }

    fn bitxor<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.binop(inl, inr, out, |wl, wr, _| wl ^ wr);
    }

    fn bitand_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.binop_const(inl, inr, out, |wl, wr, _| wl & wr);
    }

    fn unbounded_shl<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.unop(in_, out, |w, _| w.unbounded_shl(shift));
    }

    fn unbounded_shr<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.unop(in_, out, |w, _| w.unbounded_shr(shift));
    }

    fn rotate_left<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.unop(in_, out, |w, _| w.rotate_left(shift));
    }

    fn rotate_right<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.unop(in_, out, |w, _| w.rotate_right(shift));
    }

    fn reverse_bits<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.unop(in_, out, |w, _| w.reverse_bits());
    }

    fn swap_bytes<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.unop(in_, out, |w, _| w.swap_bytes());
    }

    fn cast<W: Word, T: Word>(&mut self, in_: WordIdx<W>, out: WordIdx<T>) {
        let ins = self.states.read(in_);

        let outs: [CompositeWord<T, 1>; 2] = ins.map(|w| w.into().cast::<T>()).map(|w| w.into());

        self.update_hashers(outs);
        self.states.write(out, outs);
    }

    fn bitand<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    ) {
        let rand_words = self.next_rand_words::<W, N>();
        let inls = self.states.read(inl);
        let inrs = self.states.read(inr);

        let and_msg_0 = (inls[0] & inrs[1]) ^ (inls[1] & inrs[0]) ^ rand_words[0] ^ rand_words[1];
        let and_msg_1 = self.source.next_and_msg();

        let outs = [
            (inls[0] & inrs[0]) ^ and_msg_0,
            (inls[1] & inrs[1]) ^ and_msg_1,
        ];

        self.update_hashers(outs);
        self.states.write(out, outs);
    }

    fn carry<W: Word, const N: usize>(
        &mut self,
        p: WordIdx<W, N>,
        g: WordIdx<W, N>,
        carry_in: bool,
        out: WordIdx<W, N>,
    ) {
        let rand_words = self.next_rand_words::<W, N>();
        let ps = self.states.read(p);
        let gs = self.states.read(g);

        let mut and_msgs = [CompositeWord::<W, N>::ZERO, self.source.next_and_msg()];
        let mut carries = [CompositeWord::<W, N>::ZERO; 2];
        let mut mask = CompositeWord::<W, N>::ONE;
        let mut cs = [CompositeWord::<W, N>::from_bool(carry_in); 2];
        for _ in 0..CompositeWord::<W, N>::WIDTH {
            for i in 0..2usize {
                carries[i] = carries[i] ^ cs[i];
                if i == 0 {
                    let next_i = 1;
                    and_msgs[i] = and_msgs[i]
                        ^ (cs[i] & ps[next_i])
                        ^ (cs[next_i] & ps[i])
                        ^ (rand_words[i] & mask)
                        ^ (rand_words[next_i] & mask);
                }
            }
            for i in 0usize..2 {
                cs[i] = ((cs[i] & ps[i]) ^ (and_msgs[i] & mask) ^ (gs[i] & mask)) << 1;
            }
            mask = mask << 1;
        }

        self.update_hashers(carries);
        self.states.write(out, carries);
    }
}
