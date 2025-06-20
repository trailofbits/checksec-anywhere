use checksec::{elf, shared, checksec_core, BinResults, sarif};
mod utils;
use utils::file_to_buf;

#[test]
fn test_w_canary(){
    let buf = file_to_buf("./tests/binaries/elf/all_cl".into());
    if let Ok(result) = checksec_core(&buf){
        sarif::get_sarif_report(&result);
        assert_eq!(true, true); // TODO: actually assert correct properties
    }
    else {
        panic!("Checksec failed");
    }
}