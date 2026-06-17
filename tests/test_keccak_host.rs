// SPDX-License-Identifier: LGPL-3.0-or-later

//! The host Keccak-256 hasher and the hash-based generator built on it.

#![cfg(feature = "keccak")]

use zkboo::crypto::{HashPRG, Hasher, Keccak256Hasher, PseudoRandomGenerator, RandomGenerator};
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256Hasher::new();
    h.update(data);
    return h.finalize();
}

#[test]
fn test_keccak256_vectors() {
    // Ethereum keccak256 (original Keccak, 0x01 padding) — not NIST SHA3-256.
    assert_eq!(
        keccak256(b""),
        hex32(b"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    );
    assert_eq!(
        keccak256(b"abc"),
        hex32(b"4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    );
}

#[test]
fn test_update_is_streaming() {
    let mut h = Keccak256Hasher::new();
    h.update(b"ab");
    h.update(b"c");
    assert_eq!(h.finalize(), keccak256(b"abc"));
}

#[test]
fn test_reusable_after_finalize() {
    let mut h = Keccak256Hasher::new();
    h.update(b"abc");
    let _ = h.finalize();
    // After finalization the hasher must be reset and reusable.
    h.update(b"");
    assert_eq!(h.finalize(), keccak256(b""));
}

#[test]
fn test_hashprg_deterministic() {
    let mut a = HashPRG::<Keccak256Hasher>::new(b"seed bytes");
    let mut b = HashPRG::<Keccak256Hasher>::new(b"seed bytes");
    let mut c = HashPRG::<Keccak256Hasher>::new(b"different seed");
    let (mut xa, mut xb, mut xc) = ([0u8; 96], [0u8; 96], [0u8; 96]);
    a.fill_bytes(&mut xa);
    b.fill_bytes(&mut xb);
    c.fill_bytes(&mut xc);
    assert_eq!(xa, xb); // same seed => same stream
    assert_ne!(xa, xc); // different seed => different stream
}

/// Decode a 64-char hex byte-string literal into 32 bytes (avoids a hex dev-dependency).
fn hex32(s: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
        i += 1;
    }
    return out;
}
fn nibble(c: u8) -> u8 {
    return match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex digit"),
    };
}
