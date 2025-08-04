use checksec::{elf, checksec, shared, binary::BinSpecificProperties};
mod utils;
use utils::file_to_buf;

// Elf-related tests
#[test]
fn test_is_elf(){
    let filename = "./tests/binaries/elf/fszero".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(_) => {},
        _ => {panic!("Expected Binary to be classified as Elf");}
    }
}

#[test]
fn test_w_canary(){
    let filename = "./tests/binaries/elf/all_cl".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.canary, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_w_no_canary(){
    let filename = "./tests/binaries/elf/cfi".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.canary, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_partial_relro(){
    let filename = "./tests/binaries/elf/cfi".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.relro, elf::Relro::Partial)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_relro(){
    let filename = "./tests/binaries/elf/nolibc_cl".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.relro, elf::Relro::None)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_full_relro(){
    let filename = "./tests/binaries/elf/rpath".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.relro, elf::Relro::Full)},
        _ => {panic!("Checksec failed")},
    }
}

#[allow(non_snake_case)]
#[test]
fn test_PIE_enabled(){
    let filename = "./tests/binaries/elf/partial".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.pie, elf::PIE::PIE)},
        _ => {panic!("Checksec failed")},
    }
}

#[allow(non_snake_case)]
#[test]
fn test_PIE_DSO(){
    let filename = "./tests/binaries/elf/dso.so".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.pie, elf::PIE::DSO)},
        _ => {panic!("Checksec failed")},
    }
}

#[allow(non_snake_case)]
#[test]
fn test_PIE_REL(){
    let filename = "./tests/binaries/elf/rel.o".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.pie, elf::PIE::REL)},
        _ => {panic!("Checksec failed")},
    }
}

#[allow(non_snake_case)]
#[test]
fn test_PIE_none(){
    let filename = "./tests/binaries/elf/nolibc".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.pie, elf::PIE::None)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_nx_enabled(){
    let filename = "./tests/binaries/elf/fszero".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.nx, elf::Nx::Enabled)},
        _ => {panic!("Checksec failed")},
    }
}

#[allow(non_snake_case)]
#[test]
fn test_nx_Na(){
    let filename = "./tests/binaries/elf/rel.o".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.nx, elf::Nx::Na)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_nx_disabled(){
    let filename = "./tests/binaries/elf/none".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.nx, elf::Nx::Disabled)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_symbols(){
    let filename = "./tests/binaries/elf/all".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.symbol_count, 0)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_symbol_count(){
    let filename = "./tests/binaries/elf/sstack".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.symbol_count, 87)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_clang_cfi_exists(){
    let filename = "./tests/binaries/elf/cfi".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.clang_cfi, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_clang_cfi(){
    let filename = "./tests/binaries/elf/dso.so".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.clang_cfi, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_clang_safestack_exists(){
    let filename = "./tests/binaries/elf/sstack".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.clang_safestack, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_clang_safestack(){
    let filename = "./tests/binaries/elf/partial".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.clang_safestack, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_fortify_na(){
    let filename = "./tests/binaries/elf/nolibc".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {
            assert_eq!(elf_result.fortify, elf::Fortify::Undecidable);
            assert_eq!(elf_result.fortified, 0);
            assert_eq!(elf_result.fortifiable, 0);
        },
        _ => panic!("Checksec failed"),
    }
}

#[test]
fn test_fortify_no(){
    let filename = "./tests/binaries/elf/sstack".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {
        assert_eq!(elf_result.fortify, elf::Fortify::None);
        assert_eq!(elf_result.fortified, 0);
        assert_eq!(elf_result.fortifiable, 3);
        },
        _ => panic!("Checksec failed"),
    }
}

#[test]
fn test_fortify_partial(){
    let filename = "./tests/binaries/elf/partial".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties{
        BinSpecificProperties::Elf(elf_result) => {
        assert_eq!(elf_result.fortify, elf::Fortify::Partial);
        assert_eq!(elf_result.fortified, 1);
        assert_eq!(elf_result.fortifiable, 2);
        },
     _ => panic!("Checksec failed"),
    }
}

#[test]
fn test_fortify_full(){
    let filename = "./tests/binaries/elf/rpath".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties{
        BinSpecificProperties::Elf(elf_result) => {
        assert_eq!(elf_result.fortify, elf::Fortify::Full);
        assert_eq!(elf_result.fortified, 2);
        assert_eq!(elf_result.fortifiable, 2);
        },
        _ => panic!("Checksec failed"),
    }
}

#[test]
fn test_rpath_exists(){
    let filename = "./tests/binaries/elf/rpath".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties{
        BinSpecificProperties::Elf(elf_result) => {
            let rpath_val = shared::Rpath::Yes("./".into());
            let rpath_vec = shared::VecRpath::new(vec![rpath_val.clone()]);
            assert_eq!(elf_result.rpath.len(), rpath_vec.len());
            assert_eq!(elf_result.rpath[0], rpath_val);
        },
        _ => panic!("Checksec failed"),
    }
}

#[test]
fn test_rpath_none(){
    let filename = "./tests/binaries/elf/fszero".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties{
        BinSpecificProperties::Elf(elf_result) => {
            let rpath_val = shared::Rpath::None;
            let rpath_vec = shared::VecRpath::new(vec![rpath_val.clone()]);
            assert_eq!(elf_result.rpath.len(), rpath_vec.len());
            assert_eq!(elf_result.rpath[0], rpath_val);
        },
        _ =>  {panic!("Checksec failed")},
    }
}

#[test]
fn test_runpath_exists(){
    let filename = "./tests/binaries/elf/runpath".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties{
        BinSpecificProperties::Elf(elf_result) => {
            let runpath_val = shared::Rpath::Yes("./".into());
            let runpath_vec = shared::VecRpath::new(vec![runpath_val.clone()]);
            assert_eq!(elf_result.rpath.len(), runpath_vec.len());
            assert_eq!(elf_result.runpath[0], runpath_val);
        },
        _ =>  {panic!("Checksec failed")},
    }
}

#[test]
fn test_runpath_none(){
    let filename = "./tests/binaries/elf/sstack".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties{
        BinSpecificProperties::Elf(elf_result) => {
            let runpath_val = shared::Rpath::None;
            let runpath_vec = shared::VecRpath::new(vec![runpath_val.clone()]);
            assert_eq!(elf_result.rpath.len(), runpath_vec.len());
            assert_eq!(elf_result.runpath[0], runpath_val);
        },
        _ =>  {panic!("Checksec failed")},
    }
}

#[test]
fn test_asan_exists(){
    let filename = "./tests/binaries/elf/asan_enabled".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.asan, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_asan_absent(){
    let filename = "./tests/binaries/elf/all".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.asan, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_get_architecture(){
    let filename = "./tests/binaries/elf/all".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.architecture, "X86_64".to_string())},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_dynamically_linked(){
    let filename = "./tests/binaries/elf/all".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.dyn_linking, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_statically_linked(){
    let filename = "./tests/binaries/elf/static_linking".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.dyn_linking, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_interpreter_path(){
    let filename = "./tests/binaries/elf/all".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::Elf(elf_result) => {assert_eq!(elf_result.interpreter, "/lib64/ld-linux-x86-64.so.2".to_string())},
        _ => {panic!("Checksec failed")},
    }
}