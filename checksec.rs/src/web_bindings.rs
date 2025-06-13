use wasm_bindgen::prelude::*;
use serde_derive::{Deserialize, Serialize};
use crate::{checksec_core, BinResults, VERSION, compression::{compress, decompress}};

// Hold actual checksec results along with other relevant metadata. 
// Future-proofing this means we need to be able to modify this struct and BinResults
#[derive(Serialize, Deserialize)]
pub struct CheckSec_JS{
    version: String,
    data: BinResults,
}

// API entrypoint for performing the core checksec functionality
// Consume raw bytes provided by file upload
// Return a wrapper around checksec results along with other metadata like version info
#[wasm_bindgen]
pub fn checksec (buffer: &[u8]) -> Result<JsValue, JsValue> {
    match checksec_core(buffer) {
        Ok(result) => {
            Ok(serde_wasm_bindgen::to_value(&CheckSec_JS{version: VERSION.into(), data: result})?)
        },
        Err(result) => Err(serde_wasm_bindgen::to_value(&result)?),
    }
} 

// API entrypoint for compressing and encoding a checksec result
// consume a javascript-serialized version of CheckSec_JS
// return a compressed, encoded version of this structure
pub fn checksec_compress (js_representation: JsValue) -> Result<JsValue, JsValue> {
    let parsed: Result<CheckSec_JS, _> = serde_wasm_bindgen::from_value(js_representation); 
    match parsed {
        Ok(p) => {
            match compress(&p) {
                Ok(encoded_str) => serde_wasm_bindgen::to_value(&encoded_str).map_err(|e| JsValue::from_str(&format!("Serialization error: {e}"))),
                Err(err_msg) => Err(JsValue::from_str(&err_msg)),
            }
        },
        Err(p) => Err(JsValue::from_str("Error occurred during conversion from javascript to rust".into())),
    }
}

// API entrypoint for unpacking a compressed checksec result
// Consume raw bytes from url (representing checksec info)
// Return a decoded + decompressed version of checksec info
#[wasm_bindgen]
pub fn checksec_decompress(buffer: &[u8]) -> Result<JsValue, JsValue> {
    let decompressed: Result<CheckSec_JS, String> = decompress(buffer);
    if decompressed.is_ok(){
        return Ok(serde_wasm_bindgen::to_value(&decompressed)?)
    }
    else {
        return Err(serde_wasm_bindgen::to_value(&decompressed)?)
    }
}
