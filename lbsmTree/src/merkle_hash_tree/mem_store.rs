pub trait Storer {
    fn new() -> Self;
    fn size(&self) -> usize;
    fn set(&mut self, layer: usize, index: usize, value: Vec<u8>);
    fn get(&self, layer: usize, index: usize) -> Option<&Vec<u8>>;
}

pub struct MemStore {
    data: Vec<Vec<Vec<u8>>>
}

impl Storer for MemStore {
    fn new() -> MemStore {
        return MemStore {
            data: vec![vec![vec![]]],
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
}
