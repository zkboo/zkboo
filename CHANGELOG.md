# Changelog

All notable changes to this crate are documented in this file, starting at 1.2.0.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `ChallengeOptions` and `VerifyOptions` are `Copy` and `Clone`, and `ProofOptions` is `Clone`, whatever the digest, seed, collector and hook types.
  They had the derived implementations that 1.2.1 replaced for `ExecOptions`, which asked every type parameter to be cloneable when only initialisation arguments and a shape are held.

### Documentation

- `verify`, `par_verify` and `Verifier::finalize` state that the number of responses is not checked, and that an empty proof verifies against any output.
- The crate documentation no longer names the removed `prove_custom`, no longer claims that `u32` and `u64` are enabled by default, and marks the `u256` feature as reserved.
- `HashPRG` documents the domain tag and length prefix it absorbs.

## [1.2.1] — 2026-09-09

### Changed

- An assertion accumulator is obtained only from `Assertions::scope`, which emits its flag when the body returns.
  A circuit that asserts can no longer fail to emit what its assertions amount to, which was a silent failure: prover and verifier both built from the same circuit definition, agreed on an output carrying no flag, and the proof verified while constraining nothing.
  `Assertions::new`, `Assertions::finish` and `Assertions::output` are gone, along with the `Default` implementation.
  A circuit that asserts nothing opens no scope and emits no flag, so the flag remains part of the output contract of the circuits that have one rather than a fixed cost on every circuit.

- The proof format is identified by `PROOF_FORMAT_ID`, the digest of a canonical reference proof, in place of the hand-maintained `PROOF_FORMAT_VERSION` counter.
  A counter and a digest are two records of one fact that nothing keeps in agreement, and their disagreement is exactly how a format change once went unannounced.
  The tripwire that pins the format can now only be repaired by editing the constant that consumers absorb, so re-pinning the bytes and announcing the change are the same edit.
- The pin is taken under a hasher private to its test and frozen there.
  Sharing a hasher with the rest of the suite let the pinned digest move for a reason unrelated to the format, which supplied a ready explanation for a change that had a second cause.

### Fixed

- `ExecOptions` is `Copy` and `Clone` whatever the hook type.
  A derived implementation asked the hook itself to be cloneable, when the only thing held is its initialisation argument, which a hook already has to make `Copy`.

### Removed

- `PROOF_FORMAT_VERSION`, superseded by `PROOF_FORMAT_ID`.

## [1.2.0] — 2026-09-04

### Changed

- Building a proof, verifying one and executing a circuit each take their optional arguments in an options value, so each has a single entry point instead of a family of functions naming the arguments supplied.
  Every combination is now reachable, including a hook together with a reserved pool shape, which no previous entry point offered.
- The Fiat-Shamir transcript, the view commitments and the pseudo-random generator are domain-separated, each absorbing its own tag and length prefix.
  Previously only the transcript was separated, and its tag was written out at each of six call sites rather than defined once.
  **This changes the proof format**: `PROOF_FORMAT_VERSION` is `3` and proofs made under earlier versions do not verify.

### Fixed

- `par_prove` and `par_verify` were defined under the `rayon` feature but re-exported under `parallel`, so a build enabling `rayon` alone could not reach either.
  Both are now re-exported under `rayon`; enabling `parallel` still works, since it implies it.

### Removed

- The recording facilities on the view replayer, and the two recording methods on `WordPairPool`.
  They were assembled one request at a time for a single consumer and never had a stated requirement.
  Measuring what a replay hashes needs no library support: supply a hasher that counts the bytes it absorbs.
- `n_eps`, which now lives in `zkboo-harness`.
  The core crate never called it.
- `Keccak256Hasher`, the `keccak` feature and the `tiny-keccak` dependency.
  The crate now defines the `Hasher` trait and no implementation of it, leaving the choice of hash to the caller as it does for every other hash function in the ecosystem.
  The implementation is unchanged in `zkboo-harness`.
