use base64::{encode, decode};
use crypto_hash::{Algorithm, digest};

fn hash_mht_subtree_hashes(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mht_hash_prefix: u8 = 1;
    buf.push(mht_hash_prefix);
    buf.extend(a.iter().cloned());
    buf.extend(b.iter().cloned());
    return digest(Algorithm::SHA256, &buf);
}

fn chain_proof(seed: &Vec<u8>, proof: &Vec<Vec<u8>>, index:u64) -> Vec<u8> {
    let mut chained: Vec<u8> = seed.to_vec();
    for (i, hash) in proof.iter().enumerate() {
        let chain_goes_first: bool = ((index >> i) & 1) == 0;
        if chain_goes_first {
            chained = hash_mht_subtree_hashes(&chained, hash);
        } else {
            chained = hash_mht_subtree_hashes(hash, &chained);
        }
    }
    return chained;
}

fn main() {
    let b64_seed = String::from("HRD7QHvXXYSEcEfshyQMWIEnavYo0gKghOGmPsur2Zk=");
    let b64_proof = String::from("uEyLjXl8SvjVS657SIjyi4bVubaE8b8Gc0n0sm5hnfw=");
    let b64_expect = String::from("Sct8aVnZORh9cQYyXsNoJ9fQPnkFuaXNYLVZeYkYwpE=");
    let seed: Vec<u8> = decode(&b64_seed).unwrap();
    let proof: Vec<u8> = decode(&b64_proof).unwrap();
    let computed: Vec<u8> = hash_mht_subtree_hashes(&seed, &proof);
    let b64_computed = encode(computed);
    assert_eq!(b64_computed, b64_expect);
}
