// SPDX-License-Identifier: LGPL-3.0-or-later

//! A `no_std` implementation of the [ZKBoo protocol](https://eprint.iacr.org/2016/163),
//! using [ZKB++ optimisations](https://eprint.iacr.org/2017/279).
//!
//! 🚧 Warning: This crate is work in progress, not yet suitable for use in production. 🚧
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
//! - The [prove_custom](crate::prover::prove_custom) function allows for complete customisation
//!   of the proof building process via a user-provided implementation of a
//!   [ResponseDataCollector](crate::prover::proof::collectors::ResponseDataCollector).
//! - The [par_prove](crate::prover::par_prove) function variant of [prove](crate::prover::prove)
//!   using [rayon] to generate responses in parallel.
//!
//! # Proof Verification
//!
//! The [verifier] module implements proof verification logic:
//!
//! - The [verify](crate::verifier::verify) function can be used to verify a ZKBoo proof in memory.
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
//! - `u32` enables support for 32-bit words (enabled by default)
//! - `u64` enables support for 64-bit words (enabled by default)
//! - `u128` enables support for 128-bit words
//! - `parallel` enables parallel proving/verifying using the `rayon` crate
//!
//! Support for `u8` words is enabled by default.
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
