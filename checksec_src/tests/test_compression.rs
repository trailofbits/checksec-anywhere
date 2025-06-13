use checksec::{elf, shared, checksec_core, BinResults, compression::{compress, decompress}};
mod utils;
use utils::file_to_buf;

#[test]
fn test_roundtrip() {
    let buf = file_to_buf("./tests/binaries/pe/debug_directories-clang_lld.exe.bin".into());

    let result = checksec_core(&buf).expect("checksec_core failed");
    let compressed = compress(&result).expect("compress_results failed");
    let decompress_result = decompress(compressed.as_bytes()).expect("decompress_results failed");

    match (result, decompress_result) {
        (BinResults::Pe(pe_result), BinResults::Pe(pe_decode_result)) => {
            assert_eq!(pe_result, pe_decode_result);
            assert_eq!(pe_result.aslr, pe_decode_result.aslr);
        }
        _ => panic!("Roundtrip failed"),
    }
}

