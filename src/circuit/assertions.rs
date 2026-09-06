// SPDX-License-Identifier: LGPL-3.0-or-later

//! In-circuit assertions: a circuit-side accumulator built from ordinary gates.

use crate::backend::{Backend, BooleanWordRef, Frontend, WordRef};

/// Accumulator for a circuit's in-circuit assertions.
#[derive(Debug)]
pub struct Assertions<B: Backend> {
    /// The running conjunction, or `None` until the first assertion.
    acc: Option<WordRef<B, u8, 1>>,
}

impl<B: Backend> Assertions<B> {
    /// Runs the given body with an assertion accumulator, emitting its flag as the next output
    /// word: `1` if every assertion held, `0` if any did not, and the constant `1` if nothing was
    /// asserted at all.
    pub fn scope<R>(frontend: &Frontend<B>, body: impl FnOnce(&mut Assertions<B>) -> R) -> R {
        let mut assertions = Assertions { acc: None };
        let result = body(&mut assertions);
        let flag = match assertions.acc.take() {
            Some(acc) => acc,
            None => frontend.alloc(1u8),
        };
        frontend.output(flag);
        return result;
    }

    /// Whether nothing has been asserted yet.
    pub fn is_empty(&self) -> bool {
        return self.acc.is_none();
    }

    /// Conjoins a boolean into the accumulator.
    pub fn assert(&mut self, condition: BooleanWordRef<B>) {
        let condition = BooleanWordRef::into(condition);
        self.acc = Some(match self.acc.take() {
            None => condition,
            Some(previous) => previous & condition,
        });
    }
}

impl<B: Backend> BooleanWordRef<B> {
    /// Conjoins this boolean into an assertion accumulator, consuming it.
    pub fn assert_into(self, assertions: &mut Assertions<B>) {
        assertions.assert(self);
    }
}
