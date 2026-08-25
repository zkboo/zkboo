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
    /// A fresh accumulator, with nothing asserted.
    pub fn new() -> Self {
        return Self { acc: None };
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

    /// The assertion flag: `1` if every assertion held, `0` if any did not, and the constant `1` if
    /// nothing was asserted at all.
    pub fn finish(self, frontend: &Frontend<B>) -> WordRef<B, u8, 1> {
        return match self.acc {
            Some(acc) => acc,
            None => frontend.alloc(1u8),
        };
    }

    /// Emits the assertion flag as the circuit's next output word.
    pub fn output(self, frontend: &Frontend<B>) {
        let flag = self.finish(frontend);
        frontend.output(flag);
    }
}

impl<B: Backend> Default for Assertions<B> {
    fn default() -> Self {
        return Assertions::new();
    }
}

impl<B: Backend> BooleanWordRef<B> {
    /// Conjoins this boolean into an assertion accumulator, consuming it.
    pub fn assert_into(self, assertions: &mut Assertions<B>) {
        assertions.assert(self);
    }
}
