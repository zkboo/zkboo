// SPDX-License-Identifier: LGPL-3.0-or-later

//! Functions for generating MPC-in-the-Head views.

use zeroize::Zeroizing;

use crate::{
    circuit::Circuit,
    crypto::{Hasher, PseudoRandomGenerator, Seed},
    prover::views::{
        ViewBuilderBackend, ViewCommitment, Views, WordTriplePool,
        collectors::{OwnedViewsDataCollector, ViewCommitmentsRelayer, ViewsDataCollector},
    },
};

/// Builds the views for a given circuit and seeds, using a custom [ViewsDataCollector].
/// Returns the result of finalising the collector.
pub fn build_views_custom<
    C: Circuit,
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    VDC: ViewsDataCollector<H::Digest, S>,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seeds: Zeroizing<[S; 3]>,
    collector_init_arg: VDC::InitArg,
) -> VDC::FinalizeRes {
    let view_builder =
        ViewBuilderBackend::<H, PV, S, VDC, WTP>::new_with_arg(seeds, collector_init_arg)
            .into_view_builder();
    circuit.exec(&view_builder);
    return view_builder.finalize();
}

/// Builds the views for a given circuit and seeds, using an [OwnedViewsDataCollector]
/// to collect the full [Views] data in memory.
pub fn build_views<
    C: Circuit,
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seeds: Zeroizing<[S; 3]>,
) -> Views<H::Digest, S> {
    return build_views_custom::<C, H, PV, S, OwnedViewsDataCollector<H::Digest, S>, WTP>(
        circuit,
        seeds,
        (),
    );
}

/// Builds the view commitments for a given circuit and seeds, using an [ViewCommitmentsRelayer]
/// to collect the view commitments only from the view builder.
pub fn build_view_commitments<
    C: Circuit,
    H: Hasher,
    PV: PseudoRandomGenerator,
    S: Seed,
    WTP: WordTriplePool,
>(
    circuit: &C,
    seeds: Zeroizing<[S; 3]>,
) -> [ViewCommitment<H::Digest>; 3] {
    return build_views_custom::<C, H, PV, S, ViewCommitmentsRelayer<H::Digest, S>, WTP>(
        circuit,
        seeds,
        (),
    );
}
