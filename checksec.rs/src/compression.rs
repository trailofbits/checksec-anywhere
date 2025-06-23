//! Utilities for compression and encoding of checksec reports
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Cursor, Write};
use flate2::{write::ZlibEncoder, read::ZlibDecoder, Compression};
use sha2::{Sha256, Digest};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bincode; 


pub fn compress<T: Serialize>(results: &T) -> Result<String, String> {
    let serialized = bincode::serialize(&results)
        .map_err(|_| "Result serialization to binary failed".to_string())?;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&serialized)
        .map_err(|_| "Compression failed".to_string())?;
    
    let compressed = encoder
        .finish()
        .map_err(|_| "IO error occurred during flush".to_string())?;

    let encoded = BASE64_STANDARD.encode(compressed);
    Ok(encoded) // original type -> serialized -> compressed -> B64
}

pub fn decompress<T: DeserializeOwned>(encoded_bytes: &[u8]) -> Result<T, String> {

    let encoded = std::str::from_utf8(encoded_bytes)
    .map_err(|_| "Error converting bytes to utf".to_string())?.to_string();

    let compressed = BASE64_STANDARD.decode(encoded)
    .map_err(|_| "Decoding failed".to_string())?;

    let cursor = Cursor::new(compressed);
    let mut decoder = ZlibDecoder::new(cursor);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)
    .map_err(|_| "Error occurred during decompression".to_string())?;


    let deserialized = bincode::deserialize(&decompressed)
    .map_err(|_| "Deserialization failed".to_string())?;

    Ok(deserialized) // input bytes -> B64 -> bytes -> decompress -> deserialize
}

// Given a string of bytes (file contents), get the sha-256 hash
pub fn get_sha256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}