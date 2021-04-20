use std::convert::TryFrom;

pub trait Storer {
    fn new() -> Self;
    fn width(&self) -> isize;
    fn set(&mut self, layer: isize, index: isize, value: Vec<u8>);
    fn get(&self, layer: isize, index: isize) -> Option<Vec<u8>>;
    fn print(&self);
}

pub struct MemStore {
    data: Vec<Vec<Vec<u8>>>
}

impl Storer for MemStore {
    fn new() -> MemStore {
        return MemStore {
            data: vec![vec![]],
        };
    }
    /*
        Note: width of the tree tells us how many values are in the ledger
        e.g.
         root h        <-- n-1th layer containg the root
         \      \
         h       h     <-- layer 1, containing internal nodes
        \   \   \   \
        v0  v1  v2  v3 <-- layer 0, containing all ledger values
    */
    fn width(&self) -> isize {
        /*
            Note: .len() returns usize, but canonically a tree with 0 nodes has
            depth of -1. A little bit annoying to decide where to make this conversion.

            On the one hand, width is never -1 so it would make sense to do outside this function.
            On the other hand, we'd have to do it A LOT if we didn't do it here this one time.
        */
        return isize::try_from(self.data[0].len()).unwrap();
    }
    fn set(&mut self, layer: isize, index: isize, value: Vec<u8>) {
        /*
            as n items in tree grows, need log(n) layers
        */
        while self.data.len() <= layer as usize {
            self.data.push(Vec::new());
        }
        /*
            each of those layers has either a list of values (layer 0) or a list of internal hashes
        */
        if self.data[layer as usize].len() == index as usize {
            self.data[layer as usize].push(value);
        } else {
            self.data[layer as usize][index as usize] = value;
        }
    }
    fn get(&self, layer: isize, index: isize) -> Option<Vec<u8>> {
        if layer as usize >= self.data.len() || index as usize >= self.data[layer as usize].len() {
            return None;
        }
        return Some(self.data[layer as usize][index as usize].to_vec());
    }
    fn print(&self) {
        let mut tab: String;
        let mut i: isize = isize::try_from(self.data.len()).unwrap() - 1;
        while i >= 0 {
            print!("{}", String::from("  ").repeat((1<<i)-1));
            tab = String::from("  ").repeat((1<<(i+1))-1);
            for layer in self.data[i as usize].iter() {
                print!("{:?}{}", layer[0], tab);
            }
            println!();
            i -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_width_is_0() {
        let mem_store: MemStore = Storer::new();
        assert_eq!(mem_store.width(), 0);
    }
    #[test]
    fn tree_width_is_correct() {
        let mut mem_store: MemStore = Storer::new();
        let value: Vec<u8> = vec![104, 101, 108, 108, 109];
        mem_store.set(0, 0, value.to_vec());
        assert_eq!(mem_store.width(), 1);
        mem_store.set(0, 1, value.to_vec());
        assert_eq!(mem_store.width(), 2);
        mem_store.set(0, 1, value.to_vec()); // update. no change in width
        assert_eq!(mem_store.width(), 2);
    }
    #[test]
    fn get_and_retrieve_from_non_zeroeth_layer() {
        let mut mem_store: MemStore = Storer::new();
        let value: Vec<u8> = vec![104, 101, 108, 108, 109];
        mem_store.set(1, 0, value.to_vec());
        assert_eq!(mem_store.get(1, 0).unwrap().to_vec(), value);
    }
    #[test]
    fn get_from_non_existent_layer_index() {
        let mut mem_store: MemStore = Storer::new();
        let value: Vec<u8> = vec![104, 101, 108, 108, 109];
        mem_store.set(1, 0, value.to_vec());
        assert_eq!(mem_store.get(1, 1).is_none(), true);
    }
    #[test]
    fn print_tree() {
        let mut mem_store: MemStore = Storer::new();
        let mut value: Vec<u8> = vec![6];
        mem_store.set(0, 0, value.to_vec());
        value[0] = 5;
        mem_store.set(0, 1, value.to_vec());
        value[0] = 4;
        mem_store.set(0, 2, value.to_vec());
        value[0] = 3;
        mem_store.set(0, 3, value.to_vec());
        value[0] = 2;
        mem_store.set(1, 0, value.to_vec());
        value[0] = 1;
        mem_store.set(1, 1, value.to_vec());
        value[0] = 0;
        mem_store.set(2, 0, value.to_vec());
        mem_store.print();
    }
}
