// Batch circuit tests (vectors.nr: generated from the holder tree code, murkfun-holders src/tree.mjs).
use crate::main;
use crate::vectors::{
    B0, B0_SIBLINGS, B0_SUB, B1, B1_SIBLINGS, B1_SUB, EMPTY_ROOT, FULL_SIBLINGS, FULL_SUB, ROOT_1,
    ROOT_2, ROOT_3,
};
use murk::{BATCH_SIZE, ZEROS};

fn pad<let N: u32>(xs: [Field; N]) -> [Field; BATCH_SIZE] {
    let mut out = [0; BATCH_SIZE];
    for i in 0..N {
        out[i] = xs[i];
    }
    out
}

fn full() -> [Field; BATCH_SIZE] {
    let mut out = [0; BATCH_SIZE];
    for i in 0..BATCH_SIZE {
        out[i] = 0x1000 + (i as Field);
    }
    out
}

#[test]
fn test_empty_root_is_zeros() {
    assert(EMPTY_ROOT == ZEROS[26]);
}

#[test]
fn test_first_batch_into_empty_tree() {
    main(EMPTY_ROOT, ROOT_1, 0, 3, B0_SUB, pad(B0), B0_SIBLINGS);
}

#[test]
fn test_second_batch() {
    main(ROOT_1, ROOT_2, 1, 2, B1_SUB, pad(B1), B1_SIBLINGS);
}

#[test]
fn test_full_batch() {
    main(
        ROOT_2,
        ROOT_3,
        2,
        BATCH_SIZE,
        FULL_SUB,
        full(),
        FULL_SIBLINGS,
    );
}

#[test(should_fail_with = "wrong new root")]
fn test_wrong_new_root() {
    main(ROOT_1, ROOT_2 + 1, 1, 2, B1_SUB, pad(B1), B1_SIBLINGS);
}

#[test(should_fail_with = "slot not empty under old root")]
fn test_wrong_old_root() {
    main(ROOT_1 + 1, ROOT_2, 1, 2, B1_SUB, pad(B1), B1_SIBLINGS);
}

#[test(should_fail_with = "slot not empty under old root")]
fn test_overwrite_filled_slot() {
    // Batch 1's list written into slot 0 (already holding B0) under ROOT_1: slot 0 is not empty.
    main(ROOT_1, ROOT_2, 0, 2, B1_SUB, pad(B1), B1_SIBLINGS);
}

#[test(should_fail_with = "wrong subtree root")]
fn test_extra_hidden_address() {
    // A third address that the published count does not cover: the published count makes it padding.
    let mut a = pad(B1);
    a[2] = B0[0];
    main(ROOT_1, ROOT_2, 1, 3, B1_SUB, a, B1_SIBLINGS);
}

#[test(should_fail_with = "padding must be zero")]
fn test_nonzero_padding() {
    let mut a = pad(B1);
    a[5] = 1;
    main(ROOT_1, ROOT_2, 1, 2, B1_SUB, a, B1_SIBLINGS);
}

#[test(should_fail_with = "bad count")]
fn test_zero_count() {
    main(
        ROOT_1,
        ROOT_1,
        1,
        0,
        ZEROS[10],
        [0; BATCH_SIZE],
        B1_SIBLINGS,
    );
}

#[test(should_fail_with = "bad count")]
fn test_count_above_batch_size() {
    main(
        ROOT_2,
        ROOT_3,
        2,
        BATCH_SIZE + 1,
        FULL_SUB,
        full(),
        FULL_SIBLINGS,
    );
}

#[test(should_fail)]
fn test_address_above_160_bits() {
    let mut a = pad(B1);
    a[0] = B1[0] + 0x10000000000000000000000000000000000000000;
    main(ROOT_1, ROOT_2, 1, 2, B1_SUB, a, B1_SIBLINGS);
}

#[test(should_fail)]
fn test_batch_index_out_of_range() {
    main(ROOT_1, ROOT_2, 1 + 0x10000, 2, B1_SUB, pad(B1), B1_SIBLINGS);
}

#[test(should_fail)]
fn fuzz_any_changed_address_fails(pos: u8, delta: Field) {
    // Same roots, one listed address changed: the subtree (and so new_root) no longer matches.
    let mut a = pad(B1);
    let d = if delta == 0 { 1 } else { delta };
    a[(pos as u32) % 2] += d;
    main(ROOT_1, ROOT_2, 1, 2, B1_SUB, a, B1_SIBLINGS);
}

#[test(should_fail)]
fn fuzz_any_sibling_change_fails(level: u8, delta: Field) {
    let mut s = B1_SIBLINGS;
    let d = if delta == 0 { 1 } else { delta };
    s[(level as u32) % 16] += d;
    main(ROOT_1, ROOT_2, 1, 2, B1_SUB, pad(B1), s);
}
