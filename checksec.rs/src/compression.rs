//! Utilities for compression and encoding of checksec reports
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bincode;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Write};

/// Compresses and base64-encodes a serializable data structure.
///
/// This function serializes the given data using `bincode`, compresses the serialized bytes
/// with zlib compression, and then encodes the compressed data into a base64 string.
///
/// # Type Parameters
///
/// * `T` - The type of the data to be compressed, which must implement `Serialize`.
///
/// # Arguments
///
/// * `results` - A reference to the data structure to be compressed and encoded.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(String)` with the base64-encoded compressed representation of the input data.
/// - `Err(String)` describing the failure reason.
///
/// # Errors
///
/// This function will return an error if:
/// - Serialization to binary using `bincode` fails.
/// - Compression using zlib fails during writing.
/// - Finishing the compression (flushing) encounters an IO error.
///
/// # Bincode Limitations
///
/// Due to bincode's format limitations, the following serde attributes are not supported
/// and will cause data loss or corruption:
/// - `#[serde(flatten)]`
/// - `#[serde(skip)]`, `#[serde(skip_deserializing)]`, `#[serde(skip_serializing)]`
/// - `#[serde(skip_serializing_if = "path")]`
/// - `#[serde(tag = "...")]`
/// - `#[serde(untagged)]`
///
/// See: <https://docs.rs/bincode/latest/bincode/serde/index.html#known-issues>
pub fn compress<T: Serialize>(results: &T) -> Result<String, String> {
    let serialized = bincode::serde::encode_to_vec(results, bincode::config::standard())
        .map_err(|_| "Result serialization to binary failed".to_string())?;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&serialized)
        .map_err(|_| "Compression failed".to_string())?;

    let compressed = encoder
        .finish()
        .map_err(|_| "IO error occurred during flush".to_string())?;

    let encoded_compressed = BASE64_STANDARD.encode(compressed);
    Ok(encoded_compressed) // original type -> serialized -> compressed -> B64
}

/// Decompress and deserialize base64-encoded compressed data.
///
/// Takes a UTF-8 byte slice containing base64-encoded zlib-compressed serialized data
/// and returns the deserialized result.
///
/// # Type Parameters
///
/// * `T` - The type to deserialize into, implementing `DeserializeOwned`.
///
/// # Arguments
///
/// * `encoded_bytes` - Base64-encoded compressed input bytes.
///
/// # Returns
///
/// `Ok(T)` if successful, or `Err(String)` describing the failure.
///
/// # Errors
///
/// Returns an error if decoding, decompression, or deserialization fails.
///
/// # Bincode Limitations
///
/// Due to bincode's format limitations, data serialized with the following serde attributes
/// cannot be properly deserialized and will cause data loss or corruption:
/// - `#[serde(flatten)]`
/// - `#[serde(skip)]`, `#[serde(skip_deserializing)]`, `#[serde(skip_serializing)]`
/// - `#[serde(skip_serializing_if = "path")]`
/// - `#[serde(tag = "...")]`
/// - `#[serde(untagged)]`
///
/// See: <https://docs.rs/bincode/latest/bincode/serde/index.html#known-issues>
pub fn decompress<T: DeserializeOwned>(
    encoded_bytes: &[u8],
) -> Result<T, String> {
    let encoded_compressed = std::str::from_utf8(encoded_bytes)
        .map_err(|_| "Error converting bytes to utf".to_string())?
        .to_string();

    let compressed = BASE64_STANDARD
        .decode(encoded_compressed)
        .map_err(|_| "Decoding failed".to_string())?;

    let cursor = Cursor::new(compressed);
    let mut decoder = ZlibDecoder::new(cursor);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|_| "Error occurred during decompression".to_string())?;

    let (deserialized, _): (T, usize) = bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())
        .map_err(|_| "Deserialization failed".to_string())?;

    Ok(deserialized) // input bytes -> B64 -> bytes -> decompress -> deserialize
}

/// Computes the SHA-256 hash of the given byte slice.
///
/// # Arguments
///
/// * `bytes` - A slice of bytes representing the input data to hash.
///
/// # Returns
///
/// A `Vec<u8>` containing the 32-byte SHA-256 hash of the input data.
#[allow(clippy::must_use_candidate)]
pub fn get_sha256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}
