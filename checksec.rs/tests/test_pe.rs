use checksec::{pe, checksec, binary::{BinSpecificProperties}};
mod utils;
use utils::file_to_buf;

// pe32+-related tests
#[test]
fn test_is_pe(){
    let filename = "./tests/binaries/pe/debug_directories-clang_lld.exe.bin".into();
    let buf = file_to_buf(&filename);
     match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(_) => {assert_eq!(1, 1)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_aslr_high_entropy(){
    let filename = "./tests/binaries/pe/pegoat-no-cetcompat.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.aslr, pe::ASLR::HighEntropyVa)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_aslr_wo_high_entropy(){
    let filename = "./tests/binaries/pe/pegoat-no-highentropyva.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.aslr, pe::ASLR::DynamicBase)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_aslr(){
    let filename = "./tests/binaries/pe/pegoat-ineffective-cfg-no-dynamicbase.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.aslr, pe::ASLR::None)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_force_integrity(){
    let filename = "./tests/binaries/pe/pegoat-no-gs.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.force_integrity, false)},
        _ => {panic!("Checksec failed")},
    }
}

// TODO: Find a PE that does force integrity
#[test]
fn test_has_isolation(){
    let filename = "./tests/binaries/pe/pegoat-no-gs.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.isolation, true)},
        _ => {panic!("Checksec failed")},
    }
}

// TODO: Find a PE that does not have isolation

#[test]
fn test_nx_present(){
    let filename = "./tests/binaries/pe/well_formed_import.exe.bin".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.nx, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_nx(){
    let filename = "./tests/binaries/pe/pegoat-no-nxcompat.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.nx, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_seh_present(){
    let filename = "./tests/binaries/pe/pegoat-no-cetcompat.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.seh, true)},
        _ => {panic!("Checksec failed")},
    }
}

// TODO: Find a PE that does not have SEH

#[test]
fn test_cfg_present(){
    let filename = "./tests/binaries/pe/pegoat-yes-cfg.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.cfg, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_cfg(){
    let filename = "./tests/binaries/pe/pegoat.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.cfg, false)},
        _ => {panic!("Checksec failed")},
    }
}

// TODO: Find a PE that has rfg

#[test]
fn test_no_rfg(){
    let filename = "./tests/binaries/pe/pegoat.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.rfg, false)},
        _ => {panic!("Checksec failed")},
    }
}

// TODO: Find a PE that has safeseh

#[test]
fn test_no_safeseh(){
    let filename = "./tests/binaries/pe/pegoat.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.safeseh, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_gs_present(){
    let filename = "./tests/binaries/pe/pegoat-yes-cfg.exe".into();
    let buf = file_to_buf(&filename);
        match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.gs, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_gs(){
    let filename = "./tests/binaries/pe/debug_directories-clang_lld.exe.bin".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.gs, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_authenticode_present(){
    let filename = "./tests/binaries/pe/pegoat-authenticode.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.authenticode, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_authenticode(){
    let filename = "./tests/binaries/pe/pegoat-no-highentropyva.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.authenticode, false)},
        _ => {panic!("Checksec failed")},
    }
}

// TODO: Find a PE that has .NET

#[test]
fn test_no_dotnet(){
    let filename = "./tests/binaries/pe/pegoat.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.dotnet, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_is_cet_compat(){
    let filename = "./tests/binaries/pe/pegoat-cetcompat.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.cet, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_not_cet_compat(){
    let filename = "./tests/binaries/pe/pegoat-ineffective-cfg-no-dynamicbase.exe".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(pe_result) => {assert_eq!(pe_result.cet, false)},
        _ => {panic!("Checksec failed")},
    }
}

// TODO: Find .exe with asan instrumentation