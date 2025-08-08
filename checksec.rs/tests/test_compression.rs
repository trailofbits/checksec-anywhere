use checksec::{
    binary::BinSpecificProperties,
    checksec,
    compression::{compress, decompress},
    pe,
};
mod utils;
use utils::file_to_buf;

#[test]
fn test_roundtrip() {
    let filename =
        "./tests/binaries/pe/debug_directories-clang_lld.exe.bin".into();
    let buf = file_to_buf(&filename);
    match &checksec(&buf, filename).blobs[0].properties {
        BinSpecificProperties::PE(result) => {
            let compressed =
                compress(&result).expect("compress_results failed");
            let decompress_result: pe::CheckSecResults =
                decompress(compressed.as_bytes())
                    .expect("decompress_results failed");
            assert_eq!(result, &decompress_result);
            assert_eq!(result.aslr, decompress_result.aslr);
        }
        _ => {
            panic!("Checksec failed")
        }
    }
}
