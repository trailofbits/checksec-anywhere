use checksec::{checksec, shared, binary::BinSpecificProperties};
mod utils;
use utils::file_to_buf;

#[test]
fn test_is_macho(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(_) => {},
        _ => {panic!("Expected Binary to be classified as Mach-O");}
    }
}

#[allow(non_snake_case)]
#[test]
fn test_has_PIE(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.pie, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[allow(non_snake_case)]
#[test]
fn test_no_PIE(){
    let filename = "./tests/binaries/Mach-O/rel_cl.o".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.pie, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_has_arc(){
    let filename = "./tests/binaries/Mach-O/arc_enabled".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.arc, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_arc(){
    let filename = "./tests/binaries/Mach-O/no_canary".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.arc, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_has_canary(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.canary, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_canary(){
    let filename = "./tests/binaries/Mach-O/no_canary".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.canary, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_has_codesig(){
    let filename = "./tests/binaries/Mach-O/arc_enabled".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.code_signature, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_codesig(){
    let filename = "./tests/binaries/Mach-O/nosig".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.code_signature, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_has_fortify(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.fortify, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_fortified_count(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.fortified, 1)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_not_fortified(){
    let filename = "./tests/binaries/Mach-O/no_fortify".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.fortify, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_nx_stack(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.nx_stack, true)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_nx_heap(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.nx_heap, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_restrict(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.restrict, false)},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_not_encrypted(){
    let filename = "./tests/binaries/Mach-O/basic".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.encrypted, false)},
        _ => {panic!("Checksec failed")}
    }
}

#[test]
fn test_restricted(){
    let filename = "./tests/binaries/Mach-O/restrict".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => assert_eq!(macho_result.restrict, true),
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_no_rpath(){
    let filename = "./tests/binaries/Mach-O/restrict".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {
        let runpath_vec = shared::VecRpath::new(vec![shared::Rpath::None]);
        assert_eq!(macho_result.rpath.len(), runpath_vec.len());
        assert_eq!(macho_result.rpath[0], shared::Rpath::None);
        },
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_rpath(){
    let filename = "./tests/binaries/Mach-O/runpaths".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {
        let runpath_vec = shared::VecRpath::new(vec![shared::Rpath::Yes("@executable_path/lib".into()), shared::Rpath::Yes("./src".into())]);
        assert_eq!(macho_result.rpath.len(), runpath_vec.len());
        assert_eq!(macho_result.rpath[0], shared::Rpath::Yes("@executable_path/lib".into()));
        assert_eq!(macho_result.rpath[1], shared::Rpath::Yes("./src".into()));
        },
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_architecture_id(){
    let filename = "./tests/binaries/Mach-O/rel_cl.o".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.architecture, "x86_64".to_string())},
        _ => {panic!("Checksec failed")},
    }

    let filename = "./tests/binaries/Mach-O/runpaths".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::MachO(macho_result) => {assert_eq!(macho_result.architecture, "arm64".to_string())},
        _ => {panic!("Checksec failed")},
    }
}

#[test]
fn test_multiarch_extract(){
    let filename = "./tests/binaries/Mach-O/multiarch".into();
    let buf = file_to_buf(&filename);
    let blobs = &checksec(&buf, filename).blobs;
    assert_eq!(blobs.len(), 2);
}