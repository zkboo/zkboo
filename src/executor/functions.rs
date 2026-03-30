// SPDX-License-Identifier: LGPL-3.0-or-later

//! Utility function to execute a circuit on an [ExecutionBackend], returning the output [Words].

use crate::{
    backend::Backend,
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
