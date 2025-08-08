use std::fs;
use std::path::Path;
use std::process;

// Convert file contents to buffer of bytes
pub fn file_to_buf(filename: &String) -> Vec<u8> {
    let path = Path::new(filename);
    if let Ok(buf) = fs::read(path) {
        buf
    } else {
        println!("reading of provided file path ({}) failed, test suite is misconfigured", filename);
        process::exit(1)
    }
}
