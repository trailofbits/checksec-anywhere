use checksec::{elf, shared, checksec_core, BinResults, sarif};
mod utils;
use utils::file_to_buf;

#[test]
fn test_dump_sarif(){
    let buf = file_to_buf("./tests/binaries/elf/all_cl".into());
    if let Ok(result) = checksec_core(&buf){
        let sarif = sarif::get_sarif_report(&result);
        let json = serde_json::to_string_pretty(&sarif)
        .expect("Failed to serialize SARIF report");
        println!("{}", json);
    }
    else {
        panic!("sarif conversion failed");
    }
}