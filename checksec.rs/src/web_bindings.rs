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

// API entrypoint for performing the core checksec functionality
// Consume raw bytes provided by file upload
// Return a wrapper around checksec results along with other metadata like version info
#[wasm_bindgen]
pub fn checksec (buffer: &[u8], filename: String) -> Result<JsValue, JsValue> {
    match checksec_core(buffer) {
        Ok(result) => {
            Ok(serde_wasm_bindgen::to_value(&CheckSecJs{version: VERSION.into(), filename: filename, data: result})?)
        },
        Err(result) => Err(serde_wasm_bindgen::to_value(&result)?),
    }
} 

// API entrypoint for compressing and encoding a checksec result
// consume a javascript-serialized version of CheckSecJs
// return a compressed, encoded version of this structure
#[wasm_bindgen]
pub fn checksec_compress(js_representation: JsValue) -> Result<JsValue, JsValue> {
    let parsed: CheckSecJs = serde_wasm_bindgen::from_value(js_representation)
        .map_err(|_| JsValue::from_str("Error converting JS value to Rust struct"))?;
    
    let encoded_str = compress(&parsed)
        .map_err(|err_msg| JsValue::from_str(&err_msg))?;
    
    serde_wasm_bindgen::to_value(&encoded_str)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}


// API entrypoint for unpacking a compressed checksec result
// Consume raw bytes from url (representing checksec info)
// Return a decoded + decompressed version of checksec info
#[wasm_bindgen]
pub fn checksec_decompress(buffer: &[u8]) -> Result<JsValue, JsValue> {
    let decompressed: Result<CheckSecJs, String> = decompress(buffer);
    match decompressed {
        Ok(value) => Ok(serde_wasm_bindgen::to_value(&value)?),
        Err(err) => Err(serde_wasm_bindgen::to_value(&err)?),
    }
}

// Convert a checksec report to the sarif format
#[wasm_bindgen]
pub fn generate_sarif_report(js_representation: JsValue) -> Result<JsValue, JsValue> {
    let report: CheckSecJs = serde_wasm_bindgen::from_value(js_representation)
        .map_err(|_| JsValue::from_str("Error converting JS value to Rust struct"))?;
    match sarif::get_sarif_report(&report.data) {
        Ok(report_string) => Ok(serde_wasm_bindgen::to_value(&report_string)?),
        Err(err) => Err(serde_wasm_bindgen::to_value(&err.to_string())?),
    }
}
    
