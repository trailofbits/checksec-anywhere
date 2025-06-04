use std::path::Path;
use std::env;
use std::fs;
use checksec_anywhere::{CheckSecResults};

fn main () -> Result<(), Box<dyn std::error::Error>> {
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

    match checksec_anywhere::checksec(&buffer)?{
        CheckSecResults::Elf(elf_result) =>{
            println!("Parsed elf file:\n{}", elf_result)
        }
        CheckSecResults::Pe(pe_result) =>{
            println!("Parsed pe file:\n{}", pe_result)
        }
        CheckSecResults::Macho(macho_result) =>{
            println!("Parsed Mach-O file:\n{}", macho_result)
        }
    }
    Ok(())
}