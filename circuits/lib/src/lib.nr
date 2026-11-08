// MurkFun circuit library: hashes, the holder tree and the EIP-712 digests the wallet signs.
// Specified in docs/SIGNED_ORDERS.md of the murkfun-mcp repository; the holder tree is the same as murkfun-holders'
// src/tree.mjs (checked by the tests below and the vectors).
use keccak256::keccak256;
use poseidon::poseidon2::Poseidon2;

pub mod constants;
pub use constants::{
    BATCH_LOG, BATCH_SIZE, DEPTH, DOMAIN_SEPARATOR, GLOBAL_LOG, ORDER_AUTH_TYPEHASH, SEED_DIGEST,
    TAG_NULLIFIER, TAG_ORDER, TAG_PSEUDONYM, TAG_SECRET, ZEROS,
};

/// secp256k1 order / 2, as (high, low) 128-bit halves.
global HALF_N_HI: u128 = 0x7fffffffffffffffffffffffffffffff;
global HALF_N_LO: u128 = 0x5d576e7357a4501ddfe92f46681b20a0;

pub fn node(l: Field, r: Field) -> Field {
    Poseidon2::hash([l, r], 2)
}

/// leaf(A) = H(A). Never 0 for a real address, so the zero padding of a batch can not be proven as a member.
pub fn leaf(addr: Field) -> Field {
    Poseidon2::hash([addr], 1)
}

/// Root reached from `leaf_value` at `index` (bit i = side at level i, LSB first) with `siblings` bottom-up.
/// `index` must fit in D bits (to_le_bits asserts it).
pub fn root_from_path<let D: u32>(leaf_value: Field, index: Field, siblings: [Field; D]) -> Field {
    let bits: [bool; D] = index.to_le_bits();
    let mut cur = leaf_value;
    for i in 0..D {
        let s = siblings[i];
        let (l, r) = if bits[i] { (s, cur) } else { (cur, s) };
        cur = node(l, r);
    }
    cur
}

/// Big-endian 16 bytes from `b[offset..offset + 16]` as u128.
fn u128_be<let N: u32>(b: [u8; N], offset: u32) -> u128 {
    let mut x: u128 = 0;
    for i in 0..16 {
        x = x * 256 + (b[offset + i] as u128);
    }
    x
}

/// (high, low) 128-bit halves of the 32 bytes at `b[offset..]` as field elements.
pub fn limbs<let N: u32>(b: [u8; N], offset: u32) -> (Field, Field) {
    (u128_be(b, offset) as Field, u128_be(b, offset + 16) as Field)
}

/// s of an r||s signature is at most n / 2 (low s). The ECDSA black box checks it too; this keeps the rule explicit.
pub fn assert_low_s(sig: [u8; 64]) {
    let hi = u128_be(sig, 32);
    let lo = u128_be(sig, 48);
    assert((hi < HALF_N_HI) | ((hi == HALF_N_HI) & (lo <= HALF_N_LO)), "high-s signature");
}

/// The Ethereum address of an uncompressed secp256k1 public key: the last 20 bytes of keccak256(x || y).
pub fn address_of(x: [u8; 32], y: [u8; 32]) -> Field {
    let mut buf = [0u8; 64];
    for i in 0..32 {
        buf[i] = x[i];
        buf[32 + i] = y[i];
    }
    let h = keccak256(buf, 64);
    let mut a: Field = 0;
    for i in 12..32 {
        a = a * 256 + (h[i] as Field);
    }
    a
}

/// EIP-712 digest of OrderAuth{orderHash} under DOMAIN_SEPARATOR.
pub fn order_auth_digest(order_hash: Field) -> [u8; 32] {
    let oh: [u8; 32] = order_hash.to_be_bytes();
    let mut s = [0u8; 64];
    for i in 0..32 {
        s[i] = ORDER_AUTH_TYPEHASH[i];
        s[32 + i] = oh[i];
    }
    let struct_hash = keccak256(s, 64);
    let mut d = [0u8; 66];
    d[0] = 0x19;
    d[1] = 0x01;
    for i in 0..32 {
        d[2 + i] = DOMAIN_SEPARATOR[i];
        d[34 + i] = struct_hash[i];
    }
    keccak256(d, 66)
}

/// secret = H(TAG_SECRET, S1.r, S1.s) with r, s split into 128-bit halves (each may exceed the field).
pub fn secret_of(seed_sig: [u8; 64]) -> Field {
    let (r_hi, r_lo) = limbs(seed_sig, 0);
    let (s_hi, s_lo) = limbs(seed_sig, 32);
    Poseidon2::hash([TAG_SECRET, r_hi, r_lo, s_hi, s_lo], 5)
}

pub fn pseudonym_of(secret: Field, token: Field) -> Field {
    Poseidon2::hash([TAG_PSEUDONYM, secret, token], 3)
}

pub fn nullifier_of(secret: Field, token: Field, nonce: Field) -> Field {
    Poseidon2::hash([TAG_NULLIFIER, secret, token, nonce], 4)
}

/// orderHash = H(TAG_ORDER, chainId, market, action, token, amount, minOut, to, nonce, relayer, fee, deadline, salt).
pub fn order_hash_of(fields: [Field; 11], salt: Field) -> Field {
    let mut x = [0; 13];
    x[0] = TAG_ORDER;
    for i in 0..11 {
        x[1 + i] = fields[i];
    }
    x[12] = salt;
    Poseidon2::hash(x, 13)
}

#[test]
fn test_zeros_match_js() {
    // ZEROS is generated from the holder tree code (src/tree.mjs): recompute it here.
    let mut z = 0;
    for i in 0..DEPTH {
        assert(ZEROS[i] == z);
        z = node(z, z);
    }
    assert(ZEROS[DEPTH] == z);
}

#[test]
fn test_poseidon2_matches_js() {
    // @zkpassport/poseidon2 poseidon2Hash([1n, 2n])
    assert(node(1, 2) == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383);
}

#[test]
fn test_low_s_boundary() {
    let mut sig = [0u8; 64];
    // s = n / 2 exactly is accepted
    let half: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    for i in 0..32 {
        sig[32 + i] = half[i];
    }
    assert_low_s(sig);
}

#[test(should_fail_with = "high-s signature")]
fn test_low_s_rejects_half_plus_one() {
    let mut sig = [0u8; 64];
    let half_plus_one: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa1,
    ];
    for i in 0..32 {
        sig[32 + i] = half_plus_one[i];
    }
    assert_low_s(sig);
}

/// Property: the path computed for any leaf / index / siblings reproduces itself, and flipping the index's lowest
/// bit changes the root unless both children are equal.
#[test]
fn fuzz_root_from_path(leaf_value: Field, index: u32, s0: Field, s1: Field) {
    let idx = (index % (1 << 2)) as Field;
    let r = root_from_path(leaf_value, idx, [s0, s1]);
    assert(r == root_from_path(leaf_value, idx, [s0, s1]));
    if leaf_value != s0 {
        let flipped = if (index % 2) == 0 { idx + 1 } else { idx - 1 };
        assert(r != root_from_path(leaf_value, flipped, [s0, s1]));
    }
}
