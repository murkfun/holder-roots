// MurkFun holder batch circuit: the proof of MurkFunHolderRoots.postBatch (the holder set).
//
// Proves new_root = append(old_root, addrs): slot `batch_index` of the global tree is empty under old_root, and
// new_root is old_root with that slot replaced by the 1024-leaf subtree of leaf(addrs[0..count]) (zero-padded).
// Every address is a public input, so MurkFunHolderRoots binds the root to exactly the list it publishes; the
// siblings are the only private input and are fixed by old_root (collision resistance).
// Public inputs, in this order: old_root, new_root, batch_index, count, subtree_root, addrs[1024].
use murk::{BATCH_LOG, BATCH_SIZE, GLOBAL_LOG, leaf, node, root_from_path, ZEROS};

mod tests;
mod vectors;

fn main(
    old_root: pub Field,
    new_root: pub Field,
    batch_index: pub Field,
    count: pub u32,
    subtree_root: pub Field,
    addrs: pub [Field; BATCH_SIZE],
    siblings: [Field; GLOBAL_LOG],
) {
    assert((count > 0) & (count <= BATCH_SIZE), "bad count");

    // leaves: H(addr) for the listed addresses (each a 160-bit value), 0 for the padding (which must be 0)
    let mut layer = [0; BATCH_SIZE];
    for i in 0..BATCH_SIZE {
        let a = addrs[i];
        if i < count {
            a.assert_max_bit_size::<160>();
            layer[i] = leaf(a);
        } else {
            assert(a == 0, "padding must be zero");
        }
    }
    // the batch's own subtree
    for level in 0..BATCH_LOG {
        let width = BATCH_SIZE >> (level + 1);
        for i in 0..width {
            layer[i] = node(layer[2 * i], layer[2 * i + 1]);
        }
    }
    assert(layer[0] == subtree_root, "wrong subtree root");

    // the slot was empty, and now holds the subtree (to_le_bits bounds batch_index to GLOBAL_LOG bits)
    assert(
        root_from_path(ZEROS[BATCH_LOG], batch_index, siblings) == old_root,
        "slot not empty under old root",
    );
    assert(root_from_path(subtree_root, batch_index, siblings) == new_root, "wrong new root");
}
