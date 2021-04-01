use std::convert::TryFrom;

pub trait Storer {
    fn new() -> Self;
    fn width(&self) -> isize;
    fn set(&mut self, layer: isize, index: isize, value: Vec<u8>);
    fn get(&self, layer: isize, index: isize) -> Option<&Vec<u8>>;
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
    fn width(&self) -> isize {
        // the first layer has the values, all other layers just internal node hashes
        let w: isize = isize::try_from(self.data[0].len()).unwrap();
        return w;
    }
    fn set(&mut self, layer: isize, index: isize, value: Vec<u8>) {
        while self.data.len() <= layer as usize {
            self.data.push(Vec::new());
        }
        if self.data[layer as usize].len() == index as usize {
            self.data[layer as usize].push(value);
        } else {
            self.data[layer as usize][index as usize] = value;
        }
    }
    fn get(&self, layer: isize, index: isize) -> Option<&Vec<u8>> {
        if layer as usize >= self.data.len() || index as usize >= self.data[layer as usize].len() {
            return None;
        }
        return Some(&self.data[layer as usize][index as usize]);
    }
    fn print(&self) {
        let mut w: isize = self.width() - 1;
        let mut tab: String = "".to_string();
        let i = w - 1;
        while w >= 0 {
            print!("{}", String::from("  ").repeat((1<<w)-1));
            tab = String::from("  ").repeat((1<<(w+1))-1);
            for layer in self.data[w as usize].iter() {
                print!("{:?}{}", layer, tab);
            }
            println!();
            w -= 1;
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
    fn get_and_retrieve_from_non_zeroth_layer() {
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


    // fn test_root_of_tree_with_one_node() {
    //     let mut mem_store: MemStore = Storer::new();
    //     let value: Vec<u8> = vec![104, 101, 108, 108, 109];
    //     append(&mut mem_store, value.to_vec());
    //     let expected_2: Vec<u8> = leaf_hash(value.to_vec());
    //     let computed_2: Vec<u8> = root(&mem_store);
    //     assert_eq!(expected_2, computed_2);
    // }
}
