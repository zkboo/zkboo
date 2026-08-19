// SPDX-License-Identifier: LGPL-3.0-or-later

//! Utility function to execute a circuit on an [ExecutionBackend], returning the output [Words].

use crate::{
    backend::{Backend, BackendHook, Hooked},
    circuit::Circuit,
    executor::{ExecutionBackend, WordPool},
    word::Words,
};

/// Executes the given circuit on an [ExecutionBackend] instantiated using the given [WordPool].
/// Returns the output [Words].
pub fn exec<C: Circuit, WP: WordPool>(circuit: &C) -> Words {
    let executor = ExecutionBackend::<WP>::new().into_frontend();
    circuit.exec(&executor);
    return executor.finalize();
}

/// Variant of [exec] that wraps the execution backend with a per-operation [BackendHook], built
/// from `hook_init_arg`. With `BH = NoHook` the output is byte-identical to [exec]; a non-trivial
/// hook can count operations or service a platform watchdog during the (non-secret) clear-text pass.
///
/// ⚠️ The hook must not re-enter the backend (operations run inside the
/// [Frontend](crate::backend::Frontend)'s borrow); it should touch only its own state.
pub fn exec_hooked<C: Circuit, WP: WordPool, BH: BackendHook>(
    circuit: &C,
    hook_init_arg: BH::InitArg,
) -> Words {
    let executor = Hooked::new(BH::new(hook_init_arg), ExecutionBackend::<WP>::new()).into_frontend();
    circuit.exec(&executor);
    return executor.finalize();
}
