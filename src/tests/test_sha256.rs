use crate::{sha256::Sha256, Hasher};

#[test]
fn test_empty_string() {
    let mut hasher = Sha256::new();
    hasher.push_all(b"");
    assert_eq!(format!("{}", hasher.finish()), String::from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

#[test]
fn test_abc() {
    let mut hasher = Sha256::new();
    hasher.push_all(b"abc");
    assert_eq!(format!("{}", hasher.finish()), String::from("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

#[test]
fn test_long_txt1() {
    let mut hasher = Sha256::new();
    hasher.push_all(b"fn main() {\r\n    println!(\"Hello World!\");\r\n}\r\n");
    assert_eq!(format!("{}", hasher.finish()), String::from("2b86cb2b0275bf3311a47d55dfcd4d6a5685ba5113686370ddf5074806c4668f"));
}
