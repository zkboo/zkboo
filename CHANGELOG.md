# Changelog

All notable changes to this crate are documented in this file, starting at 1.2.0.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
