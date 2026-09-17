// SPDX-License-Identifier: LGPL-3.0-or-later

//! Pins the domain-separation tag bytes and the construction of the hash-based PRG over them.

use zkboo::crypto::{
    HashPRG, Hasher, PseudoRandomGenerator, RandomGenerator, TAG_CHALLENGE, TAG_PRG,
    TAG_VIEW_COMMITMENT,
};

#[path = "common/hasher.rs"]
mod hasher;
use hasher::Blake3Hasher;

fn blake3(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    return hasher.finalize();
}

#[test]
fn the_domain_tags_have_their_published_bytes() {
    assert_eq!(TAG_CHALLENGE, b"ZKBOO-CHALLENGE");
    assert_eq!(TAG_VIEW_COMMITMENT, b"ZKBOO-VIEW-COMMITMENT");
    assert_eq!(TAG_PRG, b"ZKBOO-PRG");
}

#[test]
fn the_prg_keys_and_fills_under_its_tag() {
    let seed = b"a seed of some length";
    let key = blake3(&[b"ZKBOO-PRG", &(seed.len() as u64).to_le_bytes(), seed]);
    let block0 = blake3(&[b"ZKBOO-PRG", &key, &0u64.to_le_bytes()]);
    let block1 = blake3(&[b"ZKBOO-PRG", &key, &1u64.to_le_bytes()]);
    let mut prg = HashPRG::<Blake3Hasher>::new(seed);
    let mut out = [0u8; 64];
    prg.fill_bytes(&mut out);
    assert_eq!(out[..32], block0);
    assert_eq!(out[32..], block1);
}
