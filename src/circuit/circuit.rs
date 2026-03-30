// SPDX-License-Identifier: LGPL-3.0-or-later

//! Trait for ZKBoo circuits.

use crate::backend::{Backend, Frontend};

/// Trait to define ZKBoo circuits generic in the [Backend] choice.
///
/// The [Circuit::exec] method encapsulates the full circuit execution lifecycle, featuring:
///
/// - Input allocation via [Frontend::input].
/// - Constant allocation via [Frontend::alloc].
/// - Execution via [WordRef](crate::backend::WordRef) methods/operations.
/// - Output production via [Frontend::output].
///
pub trait Circuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>);
}
