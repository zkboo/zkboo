// SPDX-License-Identifier: LGPL-3.0-or-later

//! Optional arguments for proof building.

use crate::{
    backend::{BackendHook, NoHook},
    crypto::{Digest, Seed},
    prover::proof::collectors::{OwnedResponseDataCollector, ResponseDataCollector},
    word::Shape,
};
use core::marker::PhantomData;

/// The optional arguments of a proof build.
#[derive(Debug, Clone)]
pub struct ProofOptions<
    D: Digest,
    S: Seed,
    RDC: ResponseDataCollector<D, S> = OwnedResponseDataCollector<D, S>,
    BH: BackendHook = NoHook,
> {
    collector_init_arg: RDC::InitArg,
    hook_init_arg: BH::InitArg,
    capacity: Shape,
    _marker: PhantomData<fn() -> (D, S)>,
}

impl<D: Digest, S: Seed> ProofOptions<D, S> {
    /// Creates the default options.
    pub fn new() -> Self {
        return ProofOptions {
            collector_init_arg: (),
            hook_init_arg: (),
            capacity: Shape::zero(),
            _marker: PhantomData,
        };
    }
}

impl<D: Digest, S: Seed> Default for ProofOptions<D, S> {
    fn default() -> Self {
        return ProofOptions::new();
    }
}

impl<D: Digest, S: Seed, RDC: ResponseDataCollector<D, S>, BH: BackendHook>
    ProofOptions<D, S, RDC, BH>
{
    /// Sets the response data collector and its initialisation argument.
    pub fn with_collector_arg<RDC2: ResponseDataCollector<D, S>>(
        self,
        arg: RDC2::InitArg,
    ) -> ProofOptions<D, S, RDC2, BH> {
        return ProofOptions {
            collector_init_arg: arg,
            hook_init_arg: self.hook_init_arg,
            capacity: self.capacity,
            _marker: PhantomData,
        };
    }

    /// Sets the backend hook and its initialisation argument.
    pub fn with_hook_arg<BH2: BackendHook>(
        self,
        arg: BH2::InitArg,
    ) -> ProofOptions<D, S, RDC, BH2> {
        return ProofOptions {
            collector_init_arg: self.collector_init_arg,
            hook_init_arg: arg,
            capacity: self.capacity,
            _marker: PhantomData,
        };
    }

    /// Sets the state pool shape reserved for each iteration.
    pub fn with_capacity(mut self, capacity: Shape) -> Self {
        self.capacity = capacity;
        return self;
    }

    /// The initialisation argument of the response data collector.
    pub fn collector_arg(&self) -> RDC::InitArg {
        return self.collector_init_arg;
    }

    /// The initialisation argument of the backend hook.
    pub fn hook_arg(&self) -> BH::InitArg {
        return self.hook_init_arg;
    }

    /// The state pool shape reserved for each iteration.
    pub fn capacity(&self) -> &Shape {
        return &self.capacity;
    }
}
