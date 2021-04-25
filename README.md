# orange

A modular Merkle tree with respect to RFC6963 written for an applied cryptography graduate course.

Special thanks to @codenotary, [one of whose implementations](https://github.com/codenotary/merkletree) this project is (heavily) based on. Program correctness hinges on the test suites found there.

Still, this repo is *not* recommended for production use at this time.

Test suite:
```
cargo test
```

Usage:
```
let ms: MemStore = MemStore::new();
let mut mht: MerkleHashTree<MemStore> = MerkleHashTree::new(ms);

let v: Vec<u8> = "Hello World.".to_string().as_bytes().to_vec();
mht.append(v.to_vec()); // commit new entry

let proof: Vec<Vec<u8>> = mht.inclusion_proof(0, 0).unwrap(); // get inclusion proof
let is_verified: bool = MerkleHashTree::<MemStore>::verify_inclusion(
    proof.to_vec(),
    mht.root(),
    v,
    0,
    0
); // verify proof
```
