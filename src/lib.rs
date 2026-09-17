// SPDX-License-Identifier: LGPL-3.0-or-later

//! A `no_std` implementation of the [ZKBoo protocol](https://eprint.iacr.org/2016/163),
//! using [ZKB++ optimisations](https://eprint.iacr.org/2017/279).
//!
//! ⚠️ Warning: This crate has not undergone an external security review. ⚠️
//!
//! # Generic Parameters
//!
//! The protocol logic is generic over implementations of the following primitives:
//!
//! - An implementation [C: Circuit](crate::circuit::Circuit) of the desired circuit logic.
//!   Used by execution, proof generation and proof verification.
//! - An implementation [H: Hasher](crate::crypto::Hasher) of the cryptographic hash function
//!   used to compute view commitments and to generate the stream of pseudo-random challenges.
//!   Used by proof generation and proof verification.
//! - An implementation [PS: PseudoRandomGenerator](crate::crypto::PseudoRandomGenerator) of the
//!   pseudo-random generator used to generate view seeds. Used by proof generation only.
//! - An implementation [PV: PseudoRandomGenerator](crate::crypto::PseudoRandomGenerator) of the
//!   pseudo-random generator used to generate entropy for AND messages in the view execution
//!   and reconstruction logic. Used by proof generation and proof verification.
//! - An implementation [S: Seed](crate::crypto::Seed) of the type used for view seeds.
//!
//! The pseudo-random generators can be built from the same cryptographic hasher
//! [H: Hasher](crate::crypto::Hasher) used for view commitment and challenge generation,
//! using the [`HashPRG<H>`](crate::crypto::HashPRG) wrapper for `PS`/`PV`
//! and the digest type [`<H as Hasher>::Digest`](crate::crypto::Hasher::Digest) for `S`.
//!
//! # Circuit Implementation
//!
//! ZKBoo circuits are defined by implementing the [Circuit](crate::circuit::Circuit) trait.
//! The [Circuit::exec](crate::circuit::Circuit::exec) method must encapsulate the full circuit
//! execution lifecycle, featuring:
//!
//! - Input allocation via [Frontend::input](crate::backend::Frontend::input).
//! - Constant allocation via [Frontend::alloc](crate::backend::Frontend::alloc).
//! - Execution via [WordRef](crate::backend::WordRef) methods/operations.
//! - Output production via [Frontend::output](crate::backend::Frontend::output).
//!
//! A circuit implementation will typically feature two constructors:
//!
//! - A `new` constructor for execution and proof generation, taking secret input information.
//! - A `dummy` constructor for proof verification, using dummy values for input information.
//!
//! The proof verification logic does not use the value of input words, but their type/width
//! remains relevant for the purpose of internal memory management.
//!
//! ## Advice and assertions
//!
//! A value the prover knows and the verifier does not is an input, so **prover-supplied advice
//! needs no mechanism of its own**: the prover computes it on the host, where it holds the witness
//! to compute it from, and passes it through [Frontend::input](crate::backend::Frontend::input)
//! like any other secret. The `dummy` constructor above fills the slot with anything at all,
//! precisely because verification never reads an input's value.
//!
//! Advice constrains nothing by itself — a prover may put whatever it likes in the slot — so a
//! circuit that relies on it must pin it down with in-circuit assertions.
//! [Assertions](crate::circuit::Assertions) accumulates those by conjunction into a single flag,
//! emitted as an ordinary output word; a verifier's expected output carries `1` there because the
//! circuit says it outputs it there. The whole mechanism is ordinary gates, and neither the
//! [Backend](crate::backend::Backend) nor the proof format knows what an assertion is.
//!
//! An accumulator can only be obtained from
//! [Assertions::scope](crate::circuit::Assertions::scope), which emits the flag when its body
//! returns. A circuit that asserts therefore cannot fail to emit what its assertions amount to:
//! the two are one construct. A circuit that asserts nothing opens no scope and emits no flag, so
//! the flag is part of the output contract of the circuits that have one, like every other output
//! word, rather than a fixed tax on all of them.
//!
//! ⚠️ **Advice not covered by an assertion is unconstrained**, and nothing in this crate can detect
//! that: a circuit using unasserted advice produces perfectly valid proofs of a statement weaker
//! than it appears to make. The scope guarantees that assertions made are assertions emitted; it
//! guarantees nothing about assertions not made.
//!
//! The [WordRef](crate::backend::WordRef) struct provides an abstraction for words in the
//! circuit state, allowing the circuit to define its logic independently on the underlying choice
//! of [Backend](crate::backend::Backend). This allows the same circuit implementation to be used
//! for plain execution, proof generation, proof verification, and much more.
//!
//! [WordRef](crate::backend::WordRef)s mirror Rust's ownership model, requiring explicit clone
//! for multiple use and allowing automatic memory management for circuits via RAII.
//! A [Frontend](crate::backend::Frontend) wrapper is used to manage the
//! [Backend](crate::backend::Backend) lifecycle, enforce its invariants, and provide convenient
//! access to for word allocation methods and finalization.
//!
//! # Proof Generation
//!
//! The [prover] module implements proof generation logic:
//!
//! - The [prove](crate::prover::prove) function can be used to build a ZKBoo proof in memory.
//! - The [ProofOptions](crate::prover::proof::ProofOptions) passed to
//!   [prove](crate::prover::prove) select the
//!   [ResponseDataCollector](crate::prover::proof::collectors::ResponseDataCollector) that receives
//!   the responses, the [BackendHook](crate::backend::BackendHook) and the state pool reservation.
//! - The [par_prove](crate::prover::par_prove) function variant of [prove](crate::prover::prove)
//!   using [rayon] to generate responses in parallel.
//! - The [ProofBuilder](crate::prover::proof::ProofBuilder) struct drives response generation one
//!   iteration at a time, and can skip iterations
//!   ([ProofBuilder::skip_iters](crate::prover::proof::ProofBuilder::skip_iters)) to emit only a
//!   sub-range of a proof's responses, making long proofs resumable and splittable across provers.
//!
//! The format of the responses, together with the view-commitment scheme they are checked against,
//! is identified by [PROOF_FORMAT_ID].
//!
//! # Proof Verification
//!
//! The [verifier] module implements proof verification logic:
//!
//! - The [verify](crate::verifier::verify) function can be used to verify a ZKBoo proof in memory.
//!   It accepts a proof of any length, including an empty one, so the caller must check that the
//!   proof has the number of responses its soundness level requires.
//! - The [par_verify](crate::verifier::par_verify) function variant of
//!   [verify](crate::verifier::verify) using [rayon] to verify responses in parallel.
//!
//! # Word Containers
//!
//! The implementation provides support for native [Word](crate::word::Word) types corresponding to
//! Rust's primitive unsigned integer types: [u8], [u16], [u32], [u64] and [u128].
//! All logic is monomorphised over word type, with no dynamic dispatch or boxing, and support for
//! all desired word types must be enabled via Cargo [features](#features).
//!
//! The [Words](crate::word::Words) structure defines a container for vectors of words,
//! with vector indexing explicitly tagged by word type for the purpose of monomorphisation.
//! The [Shape](crate::word::Shape) struct is used to specify the number of words for each type,
//! and [ShapeError](crate::word::ShapeError) is used to report shape mismatches.
//!
//! It is important to understand that indexing of words within these containers is not absolute,
//! but rather relative to the position of words of the same type. This is different from common
//! conventions in circuit frameworks, where indexing is absolute and a sequence of word types
//! is specified as part of signatures.
//!
//! # Features
//!
//! - `u16` enables support for 16-bit words
//! - `u32` enables support for 32-bit words
//! - `u64` enables support for 64-bit words
//! - `u128` enables support for 128-bit words
//! - `u256` is reserved, and currently enables nothing
//! - `parallel` enables parallel proving/verifying using the `rayon` crate
//!
//! No feature is enabled by default. Support for `u8` words is always present.
//!

#![no_std]
extern crate alloc;
pub mod backend;
pub mod circuit;
pub mod crypto;
pub mod executor;
pub mod memory;
pub mod prover;
pub mod utils;
pub mod verifier;
pub mod word;

pub use crate::prover::proof::PROOF_FORMAT_ID;
