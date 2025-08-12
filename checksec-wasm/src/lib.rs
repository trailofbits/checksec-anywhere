//! WASM bindings for the checksec library

use checksec::{binary::Binary, checksec, compression::{compress, decompress}, sarif, VERSION};
use serde_derive::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Hold checksec results along with other web-related metadata.
#[derive(Serialize, Deserialize)]
pub struct CheckSecJs {
    version: String,
    report: Binary,
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
///   - checksec analysis data
/// - `Err(JsValue)` wrapping error information if the analysis fails.
///
/// # Errors
///
/// Returns an error if the underlying `checksec` function fails to process the file.
/// The error is serialized to a `JsValue` suitable for consumption in the WebAssembly context.
#[wasm_bindgen]
pub fn checksec_web(
    buffer: &[u8],
    filename: String,
) -> Result<JsValue, JsValue> {
    let report = CheckSecJs {
        version: VERSION.into(),
        report: checksec(buffer, filename),
    };
    Ok(serde_wasm_bindgen::to_value(&report)?)
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
pub fn checksec_compress(
    js_representation: JsValue,
) -> Result<JsValue, JsValue> {
    let parsed: CheckSecJs = serde_wasm_bindgen::from_value(js_representation)
        .map_err(|_| {
            JsValue::from_str("Error converting JS value to Rust struct")
        })?;

    let encoded_str =
        compress(&parsed).map_err(|err_msg| JsValue::from_str(&err_msg))?;

    serde_wasm_bindgen::to_value(&encoded_str)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

/// Unpacks a compressed checksec result from raw bytes.
///
/// # Arguments
///
/// * `buffer` - A byte slice representing compressed checksec information.
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
/// * `js_representation` - A `JsValue` representing a serialized `Vec<Binary>` structure from JavaScript.
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
pub fn generate_sarif_report(
    js_representation: JsValue,
) -> Result<JsValue, JsValue> {
    let reports: Vec<Binary> =
        serde_wasm_bindgen::from_value(js_representation).map_err(|_| {
            JsValue::from_str("Error converting JS value to Rust struct")
        })?;
    match sarif::get_sarif_report(&reports) {
        Ok(report_string) => Ok(serde_wasm_bindgen::to_value(&report_string)?),
        Err(err) => Err(serde_wasm_bindgen::to_value(&err.to_string())?),
    }
}