use checksec::{checksec_core, BinResults, compression::{compress, decompress, get_sha256_hash}};
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

#[test]
fn test_sha() {
    let hash = "19245b35a3eea8282c425146223b6f3d0ba578a017213dd142f04bc5a39f9014".to_string();
    let buf = file_to_buf("./tests/binaries/pe/no_debug_directories.exe.bin".into());
    assert_eq!(hash, hex::encode(get_sha256_hash(&buf)));
}