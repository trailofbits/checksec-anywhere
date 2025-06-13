use checksec::{macho, shared, checksec_core, BinResults};
mod utils;
use utils::file_to_buf;

// Mach-O related tests
#[test]
fn test_is_macho(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(_)) = checksec_core(&buf) {
    }
    else{
        panic!("Expected Binary to be classified as PE32+");
    }
}

#[test]
fn test_has_PIE(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.pie, true);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_no_PIE(){
    let buf = file_to_buf("./tests/binaries/Mach-O/rel_cl.o".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.pie, false);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_has_arc(){
    let buf = file_to_buf("./tests/binaries/Mach-O/arc_enabled".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.arc, true);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_no_arc(){
    let buf = file_to_buf("./tests/binaries/Mach-O/no_canary".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.arc, false);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_has_canary(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.canary, true);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_no_canary(){
    let buf = file_to_buf("./tests/binaries/Mach-O/no_canary".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.canary, false);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_has_codesig(){
    let buf = file_to_buf("./tests/binaries/Mach-O/arc_enabled".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.code_signature, true);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_no_codesig(){
    let buf = file_to_buf("./tests/binaries/Mach-O/nosig".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.code_signature, false);
    }
    else {
        panic!("Checksec failed");
    }
}

// TODO: Find a binary that has encryption

#[test]
fn test_not_encrypted(){
    let buf = file_to_buf("./tests/binaries/Mach-O/nosig".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.code_signature, false);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_has_fortify(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.fortify, true);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_fortified_count(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.fortified, 1);
    }
    else {
        panic!("Checksec failed");
    }
}


#[test]
fn test_not_fortified(){
    let buf = file_to_buf("./tests/binaries/Mach-O/no_fortify".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.fortify, false);
    }
    else {
        panic!("Checksec failed");
    }
}


#[test]
fn test_NX_stack(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.nx_stack, true);
    }
    else {
        panic!("Checksec failed");
    }
}

// TODO: Find a binary with executable stack

#[test]
fn test_X_heap(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.nx_heap, false);
    }
    else {
        panic!("Checksec failed");
    }
}

// TODO: Find a binary with non-executable heap

#[test]
fn test_no_restrict(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.restrict, false);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_restricted(){
    let buf = file_to_buf("./tests/binaries/Mach-O/restrict".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.restrict, true);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_no_rpath(){
    let buf = file_to_buf("./tests/binaries/Mach-O/restrict".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        let runpath_vec = shared::VecRpath::new(vec![shared::Rpath::None]);
        assert_eq!(macho_result.rpath.len(), runpath_vec.len());
        assert_eq!(macho_result.rpath[0], shared::Rpath::None);
    }
    else {
        panic!("Checksec failed");
    }
}

#[test]
fn test_rpath(){
    let buf = file_to_buf("./tests/binaries/Mach-O/runpaths".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        let runpath_vec = shared::VecRpath::new(vec![shared::Rpath::Yes("@executable_path/lib".into()), shared::Rpath::Yes("./src".into())]);
        assert_eq!(macho_result.rpath.len(), runpath_vec.len());
        assert_eq!(macho_result.rpath[0], shared::Rpath::Yes("@executable_path/lib".into()));
        assert_eq!(macho_result.rpath[1], shared::Rpath::Yes("./src".into()));
    }
    else {
        panic!("Checksec failed");
    }
}













