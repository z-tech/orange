pub mod mem_store;

pub trait Storer {
    fn width(&self) -> isize;
    fn set(&mut self, layer: isize, index: isize, value: &[u8]);
    fn get(&self, layer: isize, index: isize) -> Option<Vec<u8>>;
}
