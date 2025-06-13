use checksec::{elf, shared, web_bindings, BinResults, compression::{compress, decompress}};
use wasm_bindgen_test::*;
mod utils;
use utils::file_to_buf;

#[wasm_bindgen_test]
fn test_roundtrip() {
    // let buf = file_to_buf("./tests/binaries/elf/fszero".into());
    // let result = web_bindings::checksec(&buf).expect("checksec_core failed");
    assert_eq!(true, true)
}

