use std::process;
use std::path::Path;
use std::fs;

use checksec_anywhere::{checksec, CheckSecResults};
use checksec::{elf};

fn file_to_buf(filename: String) -> Vec<u8>{
    let path = Path::new(&filename);
    if let Ok(buf) = fs::read(path){
        return buf;
    }
    else{
        println!("reading of provided failed, test suite is misconfigured");
        process::exit(1)
    }
}


// Elf-related tests
#[test]
fn test_is_elf(){
    let buf = file_to_buf("./tests/binaries/elf/fszero".into());
    if let Ok(CheckSecResults::Elf(_elf_result)) = checksec(&buf) {
    }
    else{
        panic!("Expected Binary to be classified as Elf");
    }
}

#[test]
fn test_w_canary(){
    let buf = file_to_buf("./tests/binaries/elf/all_cl".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.canary, true);
    }
}

#[test]
fn test_w_no_canary(){
    let buf = file_to_buf("./tests/binaries/elf/cfi".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.canary, false);
    }
}

#[test]
fn test_partial_relro(){
    let buf = file_to_buf("./tests/binaries/elf/cfi".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.relro, elf::Relro::Partial);
    }
}

#[test]
fn test_no_relro(){
    let buf = file_to_buf("./tests/binaries/elf/nolibc_cl".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.relro, elf::Relro::None);
    }
}

#[test]
fn test_full_relro(){
    let buf = file_to_buf("./tests/binaries/elf/rpath".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.relro, elf::Relro::Full);
    }
}

#[test]
fn test_PIE_enabled(){
    let buf = file_to_buf("./tests/binaries/elf/partial".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.pie, elf::PIE::PIE);
    }
}

#[test]
fn test_PIE_DSO(){
    let buf = file_to_buf("./tests/binaries/elf/dso.so".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.pie, elf::PIE::DSO);
    }
}

#[test]
fn test_PIE_none(){
    let buf = file_to_buf("./tests/binaries/elf/nolibc".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.pie, elf::PIE::None);
    }
}

#[test]
fn test_fortify_na(){
    let buf = file_to_buf("./tests/binaries/elf/nolibc".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.fortify, elf::Fortify::Undecidable);
        assert_eq!(elf_result.fortified, 0);
        assert_eq!(elf_result.fortifiable, 0);
    }
}

#[test]
fn test_fortify_no(){
    let buf = file_to_buf("./tests/binaries/elf/sstack".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.fortify, elf::Fortify::None);
        assert_eq!(elf_result.fortified, 0);
        assert_eq!(elf_result.fortifiable, 3);
    }
}

#[test]
fn test_fortify_partial(){
    // difference in fortifiable functions
    let buf = file_to_buf("./tests/binaries/elf/partial".into());
    if let Ok(CheckSecResults::Elf(elf_result)) = checksec(&buf){
        assert_eq!(elf_result.fortify, elf::Fortify::Partial);
        assert_eq!(elf_result.fortified, 1);
        assert_eq!(elf_result.fortifiable, 2);
    }
}




