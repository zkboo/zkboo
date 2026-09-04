// SPDX-License-Identifier: LGPL-3.0-or-later

//! Utility function to execute a circuit on an [ExecutionBackend], returning the output [Words].

use crate::{
    backend::{Backend, BackendHook, Hooked},
    circuit::Circuit,
    executor::{ExecOptions, ExecutionBackend, WordPool},
    word::Words,
};

/// Executes the circuit on an [ExecutionBackend], returning the output [Words].
pub fn exec<C: Circuit, WP: WordPool, BH: BackendHook>(
    circuit: &C,
    options: ExecOptions<BH>,
) -> Words {
    let executor =
        Hooked::new(BH::new(options.hook_arg()), ExecutionBackend::<WP>::new()).into_frontend();
    circuit.exec(&executor);
    return executor.finalize();
}
