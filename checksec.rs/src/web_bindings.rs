use wasm_bindgen::prelude::*;
use serde_derive::{Deserialize, Serialize};
use crate::{BinResults, VERSION, checksec_core, sarif, compression::{compress, decompress}};

// Hold actual checksec results along with other relevant metadata. 
// Future-proofing this means we need to be able to modify this struct and BinResults
#[derive(Serialize, Deserialize)]
pub struct CheckSecJs{
    version: String,
    filename: String,
    data: BinResults,
   // sha256_hash: Vec<u8> -- Adds significant length to the url generated for the user
}

/// Performs the core checksec functionality on the given binary data.
///
/// # Arguments
///
/// * `buffer` - Raw bytes of the file to analyze (e.g., uploaded file content).
/// * `filename` - The name of the file being analyzed.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(JsValue)` wrapping a `CheckSecJs` struct with:
///   - version info
///   - filename
///   - checksec analysis data
/// - `Err(JsValue)` wrapping error information if the analysis fails.
///
/// # Errors
///
/// Returns an error if the underlying `checksec_core` function fails to process the file.
/// The error is serialized to a `JsValue` suitable for consumption in the WebAssembly context.
#[wasm_bindgen]
pub fn checksec (buffer: &[u8], filename: String) -> Result<JsValue, JsValue> {
    match checksec_core(buffer) {
        Ok(data) => {
            Ok(serde_wasm_bindgen::to_value(&CheckSecJs{version: VERSION.into(), filename, data})?)
        },
        Err(data) => Err(serde_wasm_bindgen::to_value(&data)?),
    }
} 

/// Compresses and encodes a serialized `CheckSecJs` structure.
///
/// # Arguments
///
/// * `js_representation` - A `JsValue` containing the JavaScript-serialized `CheckSecJs` struct.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(JsValue)` with the compressed and encoded string representation of the `CheckSecJs`.
/// - `Err(JsValue)` with an error message describing what went wrong.
///
/// # Errors
///
/// This function returns an error if:
/// - The input `JsValue` cannot be deserialized into a `CheckSecJs` struct.
/// - Compression of the parsed struct fails.
/// - Serialization of the compressed string back into a `JsValue` fails.
#[wasm_bindgen]
pub fn checksec_compress(js_representation: JsValue) -> Result<JsValue, JsValue> {
    let parsed: CheckSecJs = serde_wasm_bindgen::from_value(js_representation)
        .map_err(|_| JsValue::from_str("Error converting JS value to Rust struct"))?;
    
    let encoded_str = compress(&parsed)
        .map_err(|err_msg| JsValue::from_str(&err_msg))?;
    
    serde_wasm_bindgen::to_value(&encoded_str)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}


/// Unpacks a compressed checksec result from raw bytes.
///
/// # Arguments
///
/// * `buffer` - A byte slice representing the compressed checksec information,
///   typically retrieved from a URL or other binary source.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(JsValue)` with the decoded and decompressed `CheckSecJs` structure.
/// - `Err(JsValue)` containing an error message describing the failure.
///
/// # Errors
///
/// This function returns an error if:
/// - Decompression of the provided byte slice fails.
/// - Serialization of the decompressed `CheckSecJs` struct into a `JsValue` fails.
#[wasm_bindgen]
pub fn checksec_decompress(buffer: &[u8]) -> Result<JsValue, JsValue> {
    let decompressed: Result<CheckSecJs, String> = decompress(buffer);
    match decompressed {
        Ok(value) => Ok(serde_wasm_bindgen::to_value(&value)?),
        Err(err) => Err(serde_wasm_bindgen::to_value(&err)?),
    }
}

/// Converts a checksec report into the SARIF (Static Analysis Results Interchange Format) format.
///
/// # Arguments
///
/// * `js_representation` - A `JsValue` representing a serialized `CheckSecJs` structure from JavaScript.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(JsValue)` with the SARIF report as a serialized string.
/// - `Err(JsValue)` with an error message describing the failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The input `JsValue` cannot be deserialized into a `CheckSecJs` struct.
/// - The SARIF report generation fails.
/// - Serialization of the SARIF report string into a `JsValue` fails.
#[wasm_bindgen]
pub fn generate_sarif_report(js_representation: JsValue) -> Result<JsValue, JsValue> {
    let report: CheckSecJs = serde_wasm_bindgen::from_value(js_representation)
        .map_err(|_| JsValue::from_str("Error converting JS value to Rust struct"))?;
    match sarif::get_sarif_report(&report.data) {
        Ok(report_string) => Ok(serde_wasm_bindgen::to_value(&report_string)?),
        Err(err) => Err(serde_wasm_bindgen::to_value(&err.to_string())?),
    }
}
    
