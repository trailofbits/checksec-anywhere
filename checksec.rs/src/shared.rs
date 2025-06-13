//! Implements shared functionalities between elf/macho modules
#[cfg(feature = "color")]
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;
use std::io::{Read, Cursor, Write};
use flate2::{write::ZlibEncoder, read::ZlibDecoder, Compression};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bincode; 

use crate::{macho, elf, pe};


/// Split contents of `DT_RPATH`/`DT_RUNPATH` or @rpath entries
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Rpath {
    None,
    Yes(String),
    YesRW(String),
}
/// wrapper for Vec<Rpath> to allow easy color output per path entry
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct VecRpath {
    paths: Vec<Rpath>,
}
impl VecRpath {
    #[must_use]
    pub fn new(v: Vec<Rpath>) -> Self {
        Self { paths: v }
    }
}
impl Deref for VecRpath {
    type Target = Vec<Rpath>;
    fn deref(&self) -> &Self::Target {
        &self.paths
    }
}
#[cfg(not(feature = "color"))]
impl fmt::Display for VecRpath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s: Vec<String> = Vec::<String>::new();
        for v in &self.paths {
            match v {
                Rpath::Yes(p) | Rpath::YesRW(p) => s.push(p.to_string()),
                Rpath::None => s.push("None".to_string()),
            }
        }
        write!(f, "{}", s.join(":"))
    }
}
#[cfg(feature = "color")]
impl fmt::Display for VecRpath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s: Vec<String> = Vec::<String>::new();
        for v in &self.paths {
            match v {
                Rpath::Yes(p) | Rpath::YesRW(p) => s.push(p.red().to_string()),
                Rpath::None => s.push("None".green().to_string()),
            }
        }
        write!(f, "{}", s.join(":"))
    }
}

#[derive(Serialize, Deserialize)]
pub enum BinResults {
    Elf(elf::CheckSecResults),
    Pe(pe::CheckSecResults),
    Macho(macho::CheckSecResults),
}

pub fn compress_results(results: &BinResults) -> Result<String, String> {
    // Serialize
    let serialized = bincode::serialize(&results)
        .map_err(|_| "Result serialization to binary failed".to_string())?;

    // Compress
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&serialized)
        .map_err(|_| "Compression failed".to_string())?;
    
    let compressed = encoder
        .finish()
        .map_err(|_| "IO error occurred during flush".to_string())?;

    // Encode
    let encoded = BASE64_STANDARD.encode(compressed);
    Ok(encoded)
}

pub fn decompress_results(encoded_bytes: &[u8]) -> Result<BinResults, String> {
    let encoded = std::str::from_utf8(encoded_bytes).map_err(|_| "Error converting bytes to utf".to_string())?.to_string();
    let compressed = BASE64_STANDARD.decode(encoded).map_err(|_| "Decoding failed".to_string())?;

    let cursor = Cursor::new(compressed);
    let mut decoder = ZlibDecoder::new(cursor);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|_| "Error occurred during decompression".to_string())?;


    let result = bincode::deserialize(&decompressed).map_err(|_| "Deserialization failed".to_string())?;

    Ok(result)
}