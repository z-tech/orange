mod store;

use crypto_hash::{digest, Algorithm};

use store::Storer;

const MHT_LEAF_PREFIX: u8 = 0;
const MHT_NODE_PREFIX: u8 = 1;

pub struct MerkleHashTree<T: Storer> {
    pub store: T,
}

fn min_num_bits(x: isize) -> isize {
    /*
        there's an isize::BITS function that does this, but it is only a "nightly" build,
        so just working around that for now
    */
    const ISIZE_BITS: u32 = std::mem::size_of::<isize>() as u32 * 8;
    (ISIZE_BITS - x.leading_zeros()) as isize
}

fn hash_leaf(data: &[u8]) -> Vec<u8> {
    let mut buf = vec![MHT_LEAF_PREFIX];
    buf.extend(data);
    digest(Algorithm::SHA256, &buf)
}

fn hash_node(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut buf = vec![MHT_NODE_PREFIX];
    buf.extend(left);
    buf.extend(right);
    digest(Algorithm::SHA256, &buf)
}

impl<T: Storer> MerkleHashTree<T> {
    pub fn new(s: T) -> MerkleHashTree<T> {
        MerkleHashTree { store: s }
    }
    pub fn depth(&self) -> isize {
        /*
            canonically, a tree of size zero has depth of negative one
        */
        match self.store.width() {
            0 => -1,
            // note that width is num leaves in tree, min_num_bits(width) is essentially log2 operation
            n => min_num_bits(n - 1),
        }
    }
    pub fn root(&self) -> Vec<u8> {
        /*
            per RFC the root hash of an empty tree is hash of empty string
        */
        match self.depth() {
            -1 => digest(Algorithm::SHA256, b""),
            n => self.store.get(n, 0).unwrap(),
        }
    }
    pub fn append(&mut self, data: &[u8]) {
        // append the leaf
        let leaf_hash = hash_leaf(data);
        let mut width = self.store.width();
        self.store.set(0, width, &leaf_hash);
        width += 1;

        // rebuild the root
        let mut i = 0;
        let mut hash = leaf_hash;
        while width > 1 {
            if width % 2 == 0 {
                hash = hash_node(&self.store.get(i, width - 2).unwrap(), &hash);
                self.store.set(i + 1, (width >> 1) - 1, &hash);
            } else {
                width += 1;
            }
            i += 1;
            width >>= 1;
        }
    }
    pub fn is_frozen(layer: isize, index: isize, at: isize) -> bool {
        /*
            when a left subtree becomes perfect 2^i, it becomes "frozen"
        */
        let a = 1 << layer; // 6 -> 64, 7 -> 128 etc
        at >= index * a + a - 1
    }
    fn hash_at(&self, l: isize, r: isize, at: isize) -> Vec<u8> {
        if r == l {
            return self.store.get(0, r).unwrap();
        }

        let layer = min_num_bits(r - l); // height of subtree
        let width = 1 << layer; // width of subtree

        if at >= l + width - 1 || at == self.store.width() - 1 {
            return self.store.get(layer, l / width).unwrap();
        }

        let mid_point = width / 2;
        hash_node(
            &self.hash_at(l, l + mid_point - 1, at),
            &self.hash_at(l + mid_point, r, at),
        )
    }
    pub fn inclusion_proof(&self, at: isize, i: isize) -> Option<Vec<Vec<u8>>> {
        if at == 0 && i == 0 {
            return Some(vec![]);
        }
        if i > at || at >= self.store.width() || at < 1 {
            return None;
        }

        let mut i1 = i;
        let mut at1 = at + 1;
        let mut offset = 0;
        let mut result: Vec<Vec<u8>> = Vec::new();
        loop {
            let k: isize = 1 << (min_num_bits(at1 - 1) - 1);
            if i1 < k {
                result.insert(0, self.hash_at(offset + k, offset + at1 - 1, at));
                at1 = k;
            } else {
                result.insert(0, self.hash_at(offset, offset + k - 1, at));
                i1 -= k;
                at1 -= k;
                offset += k;
            }
            if at1 < 1 || (at1 == 1 && i1 == 0) {
                return Some(result);
            }
        }
    }
    pub fn verify_inclusion(
        path: &[Vec<u8>],
        root: &[u8],
        leaf: &[u8],
        mut at: isize,
        mut i: isize,
    ) -> bool {
        if i > at || (at > 0 && path.is_empty()) {
            return false;
        }

        let mut h = leaf.to_vec();
        for p in path.iter() {
            if i % 2 == 0 && i != at {
                h = hash_node(&h, p);
            } else {
                h = hash_node(p, &h);
            }
            i /= 2;
            at /= 2;
        }

        at == i && h == root
    }
}

#[cfg(test)]
mod tests {
    mod test_data;
    use super::*;
    use crate::store::mem_store::MemStore;
    use std::convert::TryFrom;
    use std::time::Instant;
    use test_data::{get_test_paths, get_test_roots};

    #[test]
    fn test_append() {
        let mut mht: MerkleHashTree<MemStore> = MerkleHashTree::new(MemStore::new());
        assert_eq!(-1, mht.depth());
        for index in 0..64 {
            let b = index.to_string().as_bytes().to_vec();
            mht.append(&b);

            assert_eq!(index as isize, mht.store.width() - 1);
            let d: f64 = ((index + 1) as f64).log2().ceil();
            assert_eq!(d as isize, mht.depth());

            assert_eq!(get_test_roots()[index as usize], mht.root());
        }
    }
    #[test]
    fn test_root() {
        let mut mht: MerkleHashTree<MemStore> = MerkleHashTree::new(MemStore::new());
        assert_eq!(digest(Algorithm::SHA256, b""), mht.root());
        let value = "my value".as_bytes().to_vec();
        mht.append(&value);
        assert_eq!(hash_leaf(&value), mht.root());
    }
    #[test]
    fn test_is_frozen() {
        // layer, index, width
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 0, 0), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 7, 6), false);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 7, 7), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(3, 0, 6), false);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(2, 0, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(2, 1, 6), false);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(1, 0, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(1, 1, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(1, 2, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(1, 3, 6), false);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 0, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 1, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 2, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 3, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 4, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 5, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 6, 6), true);
        assert_eq!(MerkleHashTree::<MemStore>::is_frozen(0, 7, 6), false);
    }
    fn mth(d: &[Vec<u8>]) -> Vec<u8> {
        /*
            note this is to test against the reference implementation as per
                https://tools.ietf.org/html/rfc6962#section-2.1
        */
        let n: isize = isize::try_from(d.len()).unwrap();
        if n == 0 {
            return digest(Algorithm::SHA256, b"");
        }
        if n == 1 {
            return hash_leaf(&d[0]);
        }

        let k: usize = 1 << (min_num_bits(n - 1) - 1);
        hash_node(&mth(&d[0..k]), &mth(&d[k..(n as usize)]))
    }
    #[test]
    fn test_mth() {
        let mut d: Vec<Vec<u8>> = Vec::new();
        assert_eq!(digest(Algorithm::SHA256, b""), mth(&d));
        for index in 0..=64 {
            let b: Vec<u8> = index.to_string().as_bytes().to_vec();
            d.push(b);
            assert_eq!(get_test_roots()[index as usize], mth(&d));
        }
    }
    fn mpath(m: isize, d: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        /*
            note this is also a reference to test against
        */
        let n: isize = isize::try_from(d.len()).unwrap();
        if 0 > m || m >= n {
            return None;
        }
        if n == 1 && m == 0 {
            return Some(vec![]);
        }

        let k: isize = 1 << (min_num_bits(n - 1) - 1);
        let mut path: Vec<Vec<u8>> = Vec::new();
        let sub_path_option: Option<Vec<Vec<u8>>>;
        if m < k {
            sub_path_option = mpath(m, &d[0..k as usize]);
            if sub_path_option != None {
                path.extend(sub_path_option.unwrap());
            }
            path.push(mth(&d[k as usize..n as usize]));
        } else {
            sub_path_option = mpath(m - k, &d[k as usize..n as usize]);
            if sub_path_option != None {
                path.extend(sub_path_option.unwrap());
            }
            path.push(mth(&d[0..k as usize]));
        }
        Some(path)
    }
    #[test]
    fn test_mpath() {
        let mut d: Vec<Vec<u8>> = Vec::new();
        assert_eq!(None, mpath(0, &d));
        for index in 0..=8 {
            let b: Vec<u8> = index.to_string().as_bytes().to_vec();
            d.push(b);
            assert_eq!(None, mpath(index + 1, &d)); // undefined path
            for i in 0..=index {
                let path: Vec<Vec<u8>> = mpath(i, &d).unwrap();
                assert_eq!(get_test_paths()[index as usize][i as usize], path);
            }
        }
    }
    #[test]
    fn test_inclusion_proof() {
        let mut mht: MerkleHashTree<MemStore> = MerkleHashTree::new(MemStore::new());
        let mut d: Vec<Vec<u8>> = Vec::new();
        for index in 0..=64 {
            let v: Vec<u8> = index.to_string().as_bytes().to_vec();
            d.push(v.to_vec());
            mht.append(&v);

            // test out of range
            assert_eq!(mht.inclusion_proof(index + 1, index), None);
            assert_eq!(mht.inclusion_proof(index, index + 1), None);

            for at in 0..=index {
                for i in 0..=at {
                    let path_option: Option<Vec<Vec<u8>>> = mht.inclusion_proof(at, i);
                    let expected_option: Option<Vec<Vec<u8>>> = mpath(i, &d[0..(at + 1) as usize]);
                    assert_eq!(path_option, expected_option);
                }
            }
        }
    }
    #[test]
    fn test_verify_inclusion() {
        let mut path: Vec<Vec<u8>> = Vec::new();
        assert_eq!(
            true,
            MerkleHashTree::<MemStore>::verify_inclusion(&path, &Vec::new(), &Vec::new(), 0, 0)
        );
        assert_eq!(
            false,
            MerkleHashTree::<MemStore>::verify_inclusion(&path, &Vec::new(), &Vec::new(), 0, 1)
        );
        assert_eq!(
            false,
            MerkleHashTree::<MemStore>::verify_inclusion(&path, &Vec::new(), &Vec::new(), 1, 0)
        );
        assert_eq!(
            false,
            MerkleHashTree::<MemStore>::verify_inclusion(&path, &Vec::new(), &Vec::new(), 1, 1)
        );

        let mut mht: MerkleHashTree<MemStore> = MerkleHashTree::new(MemStore::new());
        let mut d: Vec<Vec<u8>> = Vec::new();
        for index in 0..=64 {
            let v: Vec<u8> = index.to_string().as_bytes().to_vec();
            d.push(v.to_vec());
            mht.append(&v);
            for at in 0..=index {
                for i in 0..=at {
                    path = mpath(i, &d[0..(at + 1) as usize]).unwrap();
                    let is_verified: bool = MerkleHashTree::<MemStore>::verify_inclusion(
                        &path,
                        &get_test_roots()[at as usize],
                        &mht.store.get(0, i).unwrap(),
                        at,
                        i,
                    );
                    assert_eq!(is_verified, true);
                }
            }
        }
    }
    #[test]
    #[ignore]
    fn time_commit_and_verify() {
        let mut mht: MerkleHashTree<MemStore> = MerkleHashTree::new(MemStore::new());
        let roughly_one_billion: isize = 2isize.pow(30);
        for index in 0..=roughly_one_billion {
            let v: Vec<u8> = index.to_string().as_bytes().to_vec();
            // time perfect trees
            let log_base_2: f64 = (index as f64).log2();
            if log_base_2.fract() == 0.0 {
                // time commit
                let n1 = Instant::now();
                mht.append(&v);
                println!("a, {}, {:?}", log_base_2, n1.elapsed());
                // time retrieve path
                let n2 = Instant::now();
                let path: Vec<Vec<u8>> = mht.inclusion_proof(index, index).unwrap();
                println!("b, {}, {:?}", log_base_2, n2.elapsed());
                // time verify path
                let n3 = Instant::now();
                let is_verified: bool = MerkleHashTree::<MemStore>::verify_inclusion(
                    &path,
                    &mht.root(),
                    &mht.store.get(0, index).unwrap(),
                    index,
                    index,
                );
                println!("c, {}, {:?}", log_base_2, n3.elapsed());
                assert_eq!(is_verified, true);
            } else {
                mht.append(&v);
            }
        }
    }
}
