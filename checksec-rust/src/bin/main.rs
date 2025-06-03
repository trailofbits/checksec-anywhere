use std::path::Path;
use std::env;
use std::fs;

fn main () -> Result<(), Box<dyn std::error::Error>>{
    let mut buffer = Vec::new();
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            buffer = fs::read(path)?;
        }
    }

    if buffer.is_empty() {
        return Err("Buffer is empty — no file or empty file given.".into());
    }
    
    checksec_anywhere::checksec(&buffer);
    Ok(())
}