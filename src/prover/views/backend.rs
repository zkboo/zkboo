// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the view building backend for ZKBoo circuits.

use crate::{
    backend::{Backend, Frontend},
    crypto::{GeneratesRandom, Hasher, PseudoRandomGenerator, Seed},
    prover::{
        challenge::Party,
        views::{ViewCommitment, WordTriplePool, collectors::ViewsDataCollector},
    },
    word::{
        CompositeWord, Word, WordIdx,
        collectors::{OwnedWordCollector, WordCollector},
    },
};
use core::{array, marker::PhantomData};
use zeroize::Zeroizing;

/// [Backend] to build the views for the three parties in the MPC-in-the-Head protocol.
#[derive(Debug)]
pub struct ViewBuilderBackend<
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    VDC: ViewsDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> {
    prgs: [PV; 3],
    hashers: [H; 3],
    states: WTP,
    collector: VDC,
    outputs: [OwnedWordCollector; 3],
    _marker: PhantomData<S>,
}

impl<
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    VDC: ViewsDataCollector<H::Digest, S, InitArg: Default>,
    WTP: WordTriplePool,
> ViewBuilderBackend<H, PV, S, VDC, WTP>
{
    /// Creates a new view builder backend using the given [Seed]s for the three parties
    /// and the given [WordTriplePool] for internal state storage.
    /// The [Default::default] value is used for the additional initialisation argument
    /// of the [ViewsDataCollector].
    ///
    /// Internally:
    ///
    /// - [PseudoRandomGenerator]s are instantiated for the three parties using the given seeds.
    /// - A [ViewsDataCollector] is created using the given seeds.
    /// - [Hasher]s are instantiated for the three parties with empty internal state.
    /// - A [OwnedWordCollector] is used to collect output shares for the three parties.
    pub fn new(seeds: Zeroizing<[S; 3]>) -> Self {
        let collector = VDC::new(&seeds, VDC::InitArg::default());
        // println!();
        // println!("-- BEGIN --");
        // println!();
        return Self {
            prgs: array::from_fn(|p| PV::new(seeds[p].as_ref())),
            hashers: array::from_fn(|_| H::new()),
            states: WTP::default(),
            collector,
            outputs: array::from_fn(|_| OwnedWordCollector::new()),
            _marker: PhantomData,
        };
    }
}

impl<
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    VDC: ViewsDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> ViewBuilderBackend<H, PV, S, VDC, WTP>
{
    /// Creates a new view builder backend using the given [Seed]s for the three parties
    /// and the given [WordTriplePool] for internal state storage.
    /// An additional initialisation argument is passed for the [ViewsDataCollector].
    ///
    /// Internally:
    ///
    /// - [PseudoRandomGenerator]s are instantiated for the three parties using the given seeds.
    /// - A [ViewsDataCollector] is created using the given seeds.
    /// - [Hasher]s are instantiated for the three parties with empty internal state.
    /// - A [OwnedWordCollector] is used to collect output shares for the three parties.
    pub fn new_with_arg(seeds: Zeroizing<[S; 3]>, collector_init_arg: VDC::InitArg) -> Self {
        let collector = VDC::new(&seeds, collector_init_arg);
        // println!();
        // println!("-- BEGIN --");
        // println!();
        return Self {
            prgs: array::from_fn(|p| PV::new(seeds[p].as_ref())),
            hashers: array::from_fn(|_| H::new()),
            states: WTP::default(),
            collector,
            outputs: array::from_fn(|_| OwnedWordCollector::new()),
            _marker: PhantomData,
        };
    }

    /// Wraps this view builder backend into a [Frontend].
    ///
    /// Alias of [Backend::into_frontend].
    pub fn into_view_builder(self) -> Frontend<Self> {
        return self.into_frontend();
    }

    /// Helper method to update internal state state of the three party hashers with the
    /// little-endian bytes from the corresponding words in the given word triple.
    fn update_hashers<W: Word, const N: usize>(&mut self, word_triple: [CompositeWord<W, N>; 3]) {
        word_triple
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
        // print_shares("in_", &ins);
        let outs: [_; 3] = array::from_fn(|p| op(ins[p], p.into()));
        // print_shares("out", &outs);
        // println!();
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
        // print_shares("inl", &inls);
        // print_shares("inr", &inrs);
        let outs: [_; 3] = array::from_fn(|p| op(inls[p], inrs[p], p.into()));
        // print_shares("out", &outs);
        // println!();
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
        let inrs = [inr, inr, inr];
        // print_shares("inl", &inls);
        // print_item("inr", &inr);
        let outs: [_; 3] = array::from_fn(|p| op(inls[p], inrs[p], p.into()));
        // print_shares("out", &outs);
        // println!();
        self.update_hashers(outs);
        self.states.write(out, outs);
    }

    /// Generates and returns the next random words for the three parties using the view PRGs.
    fn next_rand_words<W: Word, const N: usize>(&mut self) -> [CompositeWord<W, N>; 3] {
        return [
            self.prgs[0].next(),
            self.prgs[1].next(),
            self.prgs[2].next(),
        ];
    }
}

impl<
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    VDC: ViewsDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
> Backend for ViewBuilderBackend<H, PV, S, VDC, WTP>
{
    type FinalizeArg = ();
    type FinalizeResult = VDC::FinalizeRes;

    fn finalize(self, _arg: Self::FinalizeArg) -> VDC::FinalizeRes {
        let [digest_0, digest_1, digest_2] = self.hashers.map(|mut hasher| hasher.finalize());
        let [output0, output1, output2] = self.outputs.map(|collector| collector.finalize());
        let commitments = [
            ViewCommitment::new(digest_0, output0),
            ViewCommitment::new(digest_1, output1),
            ViewCommitment::new(digest_2, output2),
        ];
        return self.collector.finalize(commitments);
    }

    fn input<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) -> WordIdx<W, N> {
        let input_share0: CompositeWord<W, N> = self.prgs[0].next();
        let input_share1: CompositeWord<W, N> = self.prgs[1].next();
        let input_share2 = word ^ input_share0 ^ input_share1;
        assert_eq!(input_share0 ^ input_share1 ^ input_share2, word);
        self.collector.push_input_share2(input_share2);
        let idx = self.states.alloc();
        self.states
            .write(idx, [input_share0, input_share1, input_share2]);
        return idx;
    }

    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N> {
        return self.states.alloc();
    }

    fn constant<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>, out: WordIdx<W, N>) {
        return self.states.write(out, [word, word, word]);
    }

    fn from_le_words<W: Word, const N: usize>(
        &mut self,
        ins: [WordIdx<W, 1>; N],
        out: WordIdx<W, N>,
    ) {
        let ins = ins.map(|idx| self.states.read(idx));
        let ins_shares: [_; 3] = array::from_fn(|p| ins.map(|word| word[p].into()));
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
        self.unop(in_, out, |w, p| if p.index() == 0 { !w } else { w });
    }

    fn bitxor_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.binop_const(
            inl,
            inr,
            out,
            |wl, wr, p| {
                if p.index() == 0 { wl ^ wr } else { wl }
            },
        );
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
        let outs: [CompositeWord<T, 1>; 3] = ins.map(|w| w.into().cast::<T>()).map(|w| w.into());
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
        let mut and_msgs = [CompositeWord::<W, N>::ZERO; 3];
        let mut outs = [CompositeWord::<W, N>::ZERO; 3];
        for p in 0..3usize {
            let next_p = (p + 1) % 3;
            let and_msg = (inls[p] & inrs[next_p])
                ^ (inls[next_p] & inrs[p])
                ^ rand_words[p]
                ^ rand_words[next_p];
            and_msgs[p] = and_msg;
            outs[p] = (inls[p] & inrs[p]) ^ and_msg;
        }
        self.collector.push_and_msgs(and_msgs);
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
        let mut and_msgs = [CompositeWord::<W, N>::ZERO; 3];
        let mut carries = [CompositeWord::<W, N>::ZERO; 3];
        let mut mask = CompositeWord::<W, N>::ONE;
        let mut cs = [CompositeWord::<W, N>::from_bool(carry_in); 3];
        for _ in 0..CompositeWord::<W, N>::WIDTH {
            for i in 0..3usize {
                carries[i] = carries[i] ^ cs[i];
                let next_i = (i + 1) % 3;
                and_msgs[i] = and_msgs[i]
                    ^ (cs[i] & ps[next_i])
                    ^ (cs[next_i] & ps[i])
                    ^ (rand_words[i] & mask)
                    ^ (rand_words[next_i] & mask);
            }
            for i in 0usize..3 {
                cs[i] = ((cs[i] & ps[i]) ^ (and_msgs[i] & mask) ^ (gs[i] & mask)) << 1;
            }
            mask = mask << 1;
        }
        self.collector.push_and_msgs(and_msgs);
        self.update_hashers(carries);
        self.states.write(out, carries);
    }
}
