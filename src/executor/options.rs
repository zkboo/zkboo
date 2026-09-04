// SPDX-License-Identifier: LGPL-3.0-or-later

//! Optional arguments for circuit execution.

use crate::backend::{BackendHook, NoHook};

/// The optional arguments of a circuit execution.
#[derive(Debug, Clone)]
pub struct ExecOptions<BH: BackendHook = NoHook> {
    hook_init_arg: BH::InitArg,
}

impl ExecOptions<NoHook> {
    /// Creates the default options.
    pub fn new() -> Self {
        return ExecOptions { hook_init_arg: () };
    }
}

impl Default for ExecOptions<NoHook> {
    fn default() -> Self {
        return ExecOptions::new();
    }
}

impl<BH: BackendHook> ExecOptions<BH> {
    /// Sets the backend hook and its initialisation argument.
    pub fn with_hook_arg<BH2: BackendHook>(self, arg: BH2::InitArg) -> ExecOptions<BH2> {
        return ExecOptions {
            hook_init_arg: arg,
        };
    }

    /// The initialisation argument of the backend hook.
    pub fn hook_arg(&self) -> BH::InitArg {
        return self.hook_init_arg;
    }
}
