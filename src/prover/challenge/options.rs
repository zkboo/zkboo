// SPDX-License-Identifier: LGPL-3.0-or-later

//! Optional arguments for challenge entropy generation.

use crate::{
    backend::{BackendHook, NoHook},
    crypto::{Digest, Seed},
    prover::views::collectors::{ViewCommitmentsRelayer, ViewsDataCollector},
};
use core::marker::PhantomData;

/// The optional arguments of a challenge entropy build.
#[derive(Debug, Clone)]
pub struct ChallengeOptions<
    D: Digest,
    S: Seed,
    VDC: ViewsDataCollector<D, S> = ViewCommitmentsRelayer<D, S>,
    BH: BackendHook = NoHook,
> {
    collector_init_arg: VDC::InitArg,
    hook_init_arg: BH::InitArg,
    _marker: PhantomData<fn() -> (D, S)>,
}

impl<D: Digest, S: Seed> ChallengeOptions<D, S> {
    /// Creates the default options.
    pub fn new() -> Self {
        return ChallengeOptions {
            collector_init_arg: (),
            hook_init_arg: (),
            _marker: PhantomData,
        };
    }
}

impl<D: Digest, S: Seed> Default for ChallengeOptions<D, S> {
    fn default() -> Self {
        return ChallengeOptions::new();
    }
}

impl<D: Digest, S: Seed, VDC: ViewsDataCollector<D, S>, BH: BackendHook>
    ChallengeOptions<D, S, VDC, BH>
{
    /// Sets the views data collector and its initialisation argument.
    pub fn with_collector_arg<VDC2: ViewsDataCollector<D, S>>(
        self,
        arg: VDC2::InitArg,
    ) -> ChallengeOptions<D, S, VDC2, BH> {
        return ChallengeOptions {
            collector_init_arg: arg,
            hook_init_arg: self.hook_init_arg,
            _marker: PhantomData,
        };
    }

    /// Sets the backend hook and its initialisation argument.
    pub fn with_hook_arg<BH2: BackendHook>(
        self,
        arg: BH2::InitArg,
    ) -> ChallengeOptions<D, S, VDC, BH2> {
        return ChallengeOptions {
            collector_init_arg: self.collector_init_arg,
            hook_init_arg: arg,
            _marker: PhantomData,
        };
    }

    /// The initialisation argument of the views data collector.
    pub fn collector_arg(&self) -> VDC::InitArg {
        return self.collector_init_arg;
    }

    /// The initialisation argument of the backend hook.
    pub fn hook_arg(&self) -> BH::InitArg {
        return self.hook_init_arg;
    }
}
