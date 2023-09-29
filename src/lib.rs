mod tests;
pub mod sha256;

pub trait Hasher<T> {
    fn push(&mut self, data: u8);
    fn push_all(&mut self, data: &[u8]) {
        for &i in data {
            self.push(i);
        }
    }
    fn finish(self) -> T;
}
