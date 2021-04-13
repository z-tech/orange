use crypto_hash::{Algorithm, digest};

use crate::merkle_hash_tree::mem_store::Storer;

pub mod mem_store;

const MHT_LEAF_PREFIX: u8 = 0;
const MHT_NODE_PREFIX: u8 = 1;

fn depth(store: &impl Storer) -> isize {
    let mut width: isize = store.width();
    if width == 0 {
        return -1;
    }
    width -= 1;
    let total_bits: u32 = width.count_ones() + width.count_zeros(); // not ideal, but see isize::BITS
    return (total_bits - width.leading_zeros()) as isize;
}

fn root(store: &impl Storer) -> Vec<u8> {
    let depth: isize = depth(store);
    if depth == -1 {
        return digest(Algorithm::SHA256, b""); // TODO: this is hash of nil?
    }
    return store.get(depth, 0).unwrap();
}

fn hash_leaf(data: Vec<u8>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.push(MHT_LEAF_PREFIX);
    buf.extend(data.iter().cloned());
    return digest(Algorithm::SHA256, &buf);
}

fn append(store: &mut impl Storer, data: Vec<u8>) {
    append_hash(store, hash_leaf(data));
}

fn append_hash(store: &mut impl Storer, leaf_hash: Vec<u8>) {
    // append the leaf
    let mut width: isize = store.width();
    store.set(0, width, leaf_hash.to_vec());
    width += 1;

    // rebuild the root
    let mut i: isize = 0;
    let mut c: Vec<u8> = leaf_hash.to_vec();
    let mut t: Vec<u8> = Vec::new();
    while width > 1 {
        if width % 2 == 0 {
            t.resize(1, MHT_NODE_PREFIX);
            t.extend(store.get(i, width-2).unwrap());
            t.extend(c.to_vec());
            c.resize(0, 0);
            c.extend(digest(Algorithm::SHA256, &t));
            i += 1;
            width >>= 1;
            store.set(i, width-1, c.to_vec());
        } else {
            width += 1;
            i += 1;
            width >>= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_hash_tree::mem_store::MemStore;

    #[test]
    fn test_root_of_empty_tree() {
        let mem_store: MemStore = Storer::new();
        let expected_1: Vec<u8> = digest(Algorithm::SHA256, b"");
        let computed_1: Vec<u8> = root(&mem_store);
        assert_eq!(expected_1, computed_1);
    }
    #[test]
    fn test_root_of_tree_with_one_node() {
        let mut mem_store: MemStore = Storer::new();
        let value: Vec<u8> = vec![104, 101, 108, 108, 109];
        append(&mut mem_store, value.to_vec());
        let expected_2: Vec<u8> = hash_leaf(value.to_vec());
        let computed_2: Vec<u8> = root(&mem_store);
        assert_eq!(expected_2, computed_2);
    }
}
