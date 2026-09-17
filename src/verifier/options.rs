// SPDX-License-Identifier: LGPL-3.0-or-later

//! Optional arguments for verification.

use crate::backend::{BackendHook, NoHook};

/// The optional arguments of a verification.
#[derive(Debug)]
pub struct VerifyOptions<BH: BackendHook = NoHook> {
    hook_init_arg: BH::InitArg,
}

// Hand-rolled: a derive would require the hook itself to be [Clone]/[Copy], when the only thing
// held is its init argument, which [BackendHook] already requires to be [Copy].
impl<BH: BackendHook> Clone for VerifyOptions<BH> {
    fn clone(&self) -> Self {
        return *self;
    }
}

impl<BH: BackendHook> Copy for VerifyOptions<BH> {}

impl VerifyOptions<NoHook> {
    /// Creates the default options.
    pub fn new() -> Self {
        return VerifyOptions { hook_init_arg: () };
    }
}

impl Default for VerifyOptions<NoHook> {
    fn default() -> Self {
        return VerifyOptions::new();
    }
}

impl<BH: BackendHook> VerifyOptions<BH> {
    /// Sets the backend hook and its initialisation argument.
    pub fn with_hook_arg<BH2: BackendHook>(self, arg: BH2::InitArg) -> VerifyOptions<BH2> {
        return VerifyOptions {
            hook_init_arg: arg,
        };
    }

    /// The initialisation argument of the backend hook.
    pub fn hook_arg(&self) -> BH::InitArg {
        return self.hook_init_arg;
    }
}
