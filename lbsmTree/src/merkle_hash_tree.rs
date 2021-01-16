use crypto_hash::{Algorithm, digest};
use std::convert::TryInto;

use crate::merkle_hash_tree::mem_store::Storer;

pub mod mem_store;

fn depth(store: &impl Storer) -> usize {
    let s: usize = store.size() - 1;
    let bits: u32 = s.count_ones() + s.count_zeros();
    return (bits - s.leading_zeros()).try_into().unwrap();
}

fn root(store: &impl Storer) -> Vec<u8> {
    let h_opt: Option<&Vec<u8>> = store.get(depth(store), 0);
    if h_opt == None {
        return digest(Algorithm::SHA256, &[]);
    }
    return h_opt.unwrap().to_vec();
}

fn leaf_hash(data: Vec<u8>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mht_leaf_prefix: u8 = 0;
    buf.push(mht_leaf_prefix);
    buf.extend(data.iter().cloned());
    return digest(Algorithm::SHA256, &buf);
}

fn append(store: &mut impl Storer, data: Vec<u8>) {
    let h: Vec<u8> = leaf_hash(data);
    append_hash(store, h);
}

fn append_hash(store: &mut impl Storer, h: Vec<u8>) {
    let s: usize = store.size();
    store.set(0, s, h);
    // s += 1;
    let d: usize = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_hash_tree::mem_store::MemStore;
    use std::str::from_utf8;

    #[test]
    fn test_root() {
        let mem_store: MemStore = Storer::new();
        let expected: Vec<u8> = digest(Algorithm::SHA256, &[]);
        let computed: Vec<u8> = root(&mem_store);
        assert_eq!(expected, computed);
    }
}
