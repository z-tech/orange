pub trait Storer {
    fn new() -> Self;
    fn size(&self) -> usize;
    fn set(&mut self, layer: usize, index: usize, value: Vec<u8>);
    fn get(&self, layer: usize, index: usize) -> Option<&Vec<u8>>;
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
    fn size(&self) -> usize {
        return self.data[0].len();
    }
    fn set(&mut self, layer: usize, index: usize, value: Vec<u8>) {
        while self.data.len() <= layer {
            self.data.push(Vec::new());
        }
        while self.data[layer].len() <= index {
            self.data[layer].push(Vec::new());
        }
        self.data[layer][index].extend(value.iter().cloned());
    }
    fn get(&self, layer: usize, index: usize) -> Option<&Vec<u8>> {
        if layer >= self.data.len() || index >= self.data[layer].len() {
            return None;
        }
        if self.data[layer][index].len() == 0 {
            return None;
        }
        return Some(&self.data[layer][index]);
    }
    fn print(&self) {
        let mut s: usize = self.size();
        let mut tab: String;
        while s > 0 {
            s -= 1;
            print!("{}", String::from("  ").repeat((1<<s)-1));
            tab = String::from("  ").repeat((1<<(s+1))-1);
            for layer in self.data[s].iter() {
                print!("{:?}{}", layer, tab);
            }
            println!();
        }
    }
}
