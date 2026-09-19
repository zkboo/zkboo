// SPDX-License-Identifier: LGPL-3.0-or-later

//! The number of repetitions a proof carries.

/// The number of MPC-in-the-Head repetitions a proof is required to carry.
///
/// Verification checks each response it is given and nothing about how many there are, so the
/// count is what ties a proof to a soundness level: a verifier that does not require one accepts a
/// proof of a single response, or of none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Repetitions(usize);

impl Repetitions {
    /// The number of repetitions required for the given level of post-quantum security, in bits.
    ///
    /// Each repetition leaves a cheating prover a `2/3` chance of going undetected, so reaching
    /// `2^-b` against a Grover-style search over `2^(2b)` work takes `ceil(2b / log2(3/2))`
    /// repetitions: 438 at 128 bits.
    pub const fn for_pq_security_bits(bits: usize) -> Self {
        // 1 / log2(3/2) ≈ NUM / DEN.
        const NUM: u128 = 1_709_511_291_351_455;
        const DEN: u128 = 1_000_000_000_000_000;
        assert!(bits > 0, "a soundness level of zero bits admits any proof");
        let two_b = (2 * bits) as u128;
        return Self(((two_b * NUM + (DEN - 1)) / DEN) as usize);
    }

    /// Exactly the given number of repetitions.
    pub const fn exactly(count: usize) -> Self {
        assert!(count > 0, "a proof of no repetitions constrains nothing");
        return Self(count);
    }

    /// The number of repetitions.
    pub const fn count(self) -> usize {
        return self.0;
    }
}
