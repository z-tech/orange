use std::convert::TryFrom;
use crypto_hash::{Algorithm, digest};

use crate::merkle_hash_tree::mem_store::Storer;

pub mod mem_store;
pub mod test_data;

const MHT_LEAF_PREFIX: u8 = 0;
const MHT_NODE_PREFIX: u8 = 1;

fn min_num_bits(x: isize) -> isize {
    /*
        there's an isize::BITS function that does this, but it is only a "nightly" build,
        so just working around that for now with count_ones() and count_zeros()
    */
    let total_bits: u32 = x.count_ones() + x.count_zeros();
    return (total_bits - x.leading_zeros()) as isize;
}

fn depth(store: &impl Storer) -> isize {
    let mut width: isize = store.width();
    if width == 0 {
        return -1;
    }
    return min_num_bits(width - 1);
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

fn is_frozen(layer: isize, index: isize, at: isize) -> bool {
    let a: isize = 1 << layer; // 6 -> 64, 7 -> 128 etc
    return at >= index * a + a - 1;
}

fn hash_at(store: &mut impl Storer, l: isize, r: isize, at: isize) -> Vec<u8> {
    if r == l {
        return store.get(0, r).unwrap();
    }

    let layer: isize = min_num_bits(r-l); // height of subtree
    let a: isize = 1 << layer; // width of subtree

    if at >= l+a-1 || at == store.width()-1 {
        return store.get(layer, l/a).unwrap();
    }

    let k: isize = a / 2;
    let mut c: Vec<u8> = Vec::new();
    c.push(MHT_NODE_PREFIX);
    c.extend(hash_at(store, l, l+k-1, at).iter().cloned());
    c.extend(hash_at(store, l+k, r, at).iter().cloned());
    return digest(Algorithm::SHA256, &c);
}

// Reference implementation as per https://tools.ietf.org/html/rfc6962#section-2.1
fn MTH(D: Vec<Vec<u8>>) -> Vec<u8> {
    let n: isize = isize::try_from(D.len()).unwrap();
    if n == 0 {
        return digest(Algorithm::SHA256, b"");
    }
    if n == 1 {
        let mut c: Vec<u8> = Vec::new();
        c.push(MHT_LEAF_PREFIX);
        c.extend(D[0].to_vec());
        return digest(Algorithm::SHA256, &c);
    }

    let k: usize = 1 << (min_num_bits(n - 1) - 1);
    let mut c: Vec<u8> = Vec::new();
    c.push(MHT_NODE_PREFIX);
    c.extend(MTH(D[0..k].to_vec()));
    c.extend(MTH(D[k..(n as usize)].to_vec()));
    return digest(Algorithm::SHA256, &c);
}

fn MPath(m: isize, D: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let n: isize = isize::try_from(D.len()).unwrap();
    if 0 > m || m >= n {
        return None;
    }
    if n == 1 && m == 0 {
        return None;
    }

    let mut path: Vec<Vec<u8>> = Vec::new();
    let k: isize = 1 << (min_num_bits(n - 1) - 1);

    if m < k {
        path.extend(MPath(m, D[0..k as usize].to_vec()).unwrap());
        path.push(MTH(D[k as usize .. n as usize].to_vec()));
    } else {
        path.extend(MPath(m-k, D[k as usize..n as usize].to_vec()).unwrap());
        path.push(MTH(D[0..k as usize].to_vec()));
    }
    return Some(path);
}

fn inclusion_proof(store: &mut impl Storer, at: isize, i: isize) -> Option<Vec<Vec<u8>>> {
    let w: isize = store.width();
    if i > at || at >= w || at < 1 {
        return None;
    }

    let mut p: Vec<Vec<u8>> = Vec::new();

    let mut m: isize = i;
    let mut n: isize = at + 1;

    let mut offset: isize = 0;
    let mut l: isize;
    let mut r: isize;
    loop {
        let d: isize = min_num_bits(n - 1);
        let k: isize = 1 << (d - 1);
        if m < k {
            l = offset + k;
            r = offset+n-1;
            n = k;
        } else {
            l = offset;
            r = offset+k-1;
            m = m - k;
            n = n - k;
            offset += k;
        }

        p.push(hash_at(store, l, r, at));

        if n < 1 || (n == 1 && m == 0) {
            return Some(p);
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
    #[test]
    fn test_is_frozen() {
        // layer, index, width
        assert_eq!(is_frozen(0, 0, 0), true);
        assert_eq!(is_frozen(0, 7, 6), false);
        assert_eq!(is_frozen(0, 7, 7), true);
        assert_eq!(is_frozen(3, 0, 6), false);
        assert_eq!(is_frozen(2, 0, 6), true);
        assert_eq!(is_frozen(2, 1, 6), false);
        assert_eq!(is_frozen(1, 0, 6), true);
        assert_eq!(is_frozen(1, 1, 6), true);
        assert_eq!(is_frozen(1, 2, 6), true);
    }
    #[test]
    fn test_MTH() {
        let mut D: Vec<Vec<u8>> = Vec::new();
        assert_eq!(digest(Algorithm::SHA256, b""), MTH(D.to_vec()));
        for index in 0..=64 {
            let b: Vec<u8> = index.to_string().as_bytes().to_vec();
            D.push(b);
            assert_eq!(test_data::get_test_roots()[index as usize], MTH(D.to_vec()));
        }
    }
    fn test_MPath() {
        let mut D: Vec<Vec<u8>> = Vec::new();
        assert_eq!(None, MPath(0, D.to_vec()));
        for index in 0..=8 {
            let b: Vec<u8> = index.to_string().as_bytes().to_vec();
            D.push(b);
            assert_eq!(None, MPath(index + 1, D.to_vec())); // undefined path
            for i in 0..=index {
                let path: Vec<Vec<u8>> = MPath(i, D.to_vec()).unwrap();
                assert_eq!(test_data::get_test_paths()[index as usize][i as usize], path);
            }
        }
    }
    // #[test]
    // fn test_inclusion_proof() {
    //     let mut ms: MemStore = Storer::new();
    //     let mut D: Vec<Vec<u8>> = Vec::new();
    //     for index in 0..=64 {
    //         let v: Vec<u8> = index.to_string().as_bytes().to_vec();
    //         D.push(v.to_vec());
    //         append(&mut ms, v);
    //
    //         // test out of range
    //         assert_eq!(inclusion_proof(&mut ms, index + 1, index), None);
    //         assert_eq!(inclusion_proof(&mut ms, index, index + 1), None);
    //
    //         for at in 0..=index {
    //             for i in 0..=at {
    //                 println!("{},{},{}", index, at, i);
    //                 let expected_option: Option<Vec<Vec<u8>>> = MPath(i, D[0..(at as usize+1)].to_vec());
    //                 let path_option: Option<Vec<Vec<u8>>> = inclusion_proof(&mut ms, at, i);
    //                 if path_option == None {
    //                     assert_eq!(path_option, expected_option);
    //                 } else {
    //                     let path: Vec<Vec<u8>> = path_option.unwrap();
    //                     let expected: Vec<Vec<u8>> = expected_option.unwrap();
    //                     assert_eq!(path.len(), expected.len());
    //
    //                     for j in 0..path.len() {
    //                         assert_eq!(expected[j], path[j]);
    //                     }
    //                 }
    //             }
    //         }
    //     }
    // }
}
