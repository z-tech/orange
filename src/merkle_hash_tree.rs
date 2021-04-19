use crypto_hash::{Algorithm, digest};

use crate::merkle_hash_tree::mem_store::Storer;

pub mod mem_store;
pub mod test_data;

const MHT_LEAF_PREFIX: u8 = 0;
const MHT_NODE_PREFIX: u8 = 1;

fn depth(store: &impl Storer) -> isize {
    let mut width: isize = store.width();
    if width == 0 {
        return -1;
    }
    width -= 1;
    /*
        there's an isize::BITS function that does this, but it is only a "nightly" build,
        so just working around that for now with count_ones() and count_zeros()
    */
    let total_bits: u32 = width.count_ones() + width.count_zeros();
    return (total_bits - width.leading_zeros()) as isize;
}

fn root(store: &impl Storer) -> Vec<u8> {
    let depth: isize = depth(store);
    if depth == -1 {
        return digest(Algorithm::SHA256, b"");
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
    use crate::merkle_hash_tree::test_data;

    #[test]
    fn test_append() {
        let mut ms: MemStore = Storer::new();
        assert_eq!(-1, depth(&ms));
        for index in 0..64 {
            let b: Vec<u8> = index.to_string().as_bytes().to_vec();
            append(&mut ms, b);

            assert_eq!(index as isize, ms.width()-1);
            let d: f64 = ((index + 1) as f64).log2().ceil();
            assert_eq!(d as isize, depth(&ms));

            assert_eq!(test_data::get_test_roots()[index as usize], root(&ms));
        }
    }
    #[test]
    fn test_root() {
        let mut ms: MemStore = Storer::new();
        assert_eq!(digest(Algorithm::SHA256, b""), root(&ms));
        let value: Vec<u8> = "my value".as_bytes().to_vec();
        append(&mut ms, value.to_vec());
        assert_eq!(hash_leaf(value), root(&ms));
    }
}
