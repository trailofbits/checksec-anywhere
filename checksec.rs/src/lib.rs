#![warn(clippy::pedantic)]
use goblin::mach::{Mach, MultiArch, SingleArch::Archive, SingleArch::MachO};
use goblin::Object;
use std::path::PathBuf;

#[cfg(feature = "disassembly")]
pub mod disassembly;
#[cfg(feature = "elf")]
pub mod elf;
#[cfg(target_os = "linux")]
pub mod ldso;
#[cfg(feature = "macho")]
pub mod macho;
pub mod macros;
pub mod output;
#[cfg(feature = "pe")]
pub mod pe;
#[cfg(feature = "shared")]
#[macro_use]
pub mod shared;
pub mod binary;
pub mod compression;
pub mod sarif;
use binary::{BinSpecificProperties, BinType, Binary, Blob};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Analyze a binary file buffer and extract security-related results.
///
/// Parses the input buffer to detect its binary format (ELF, PE, or Mach-O)
/// and runs the appropriate security checks for that format.
/// For multi-architecture Mach-O binaries, multiple security reports are returned.
///
/// # Arguments
///
/// * `buffer` - A byte slice representing the raw contents of a binary file.
///
/// * `filename` - A string representing the name of the file under analysis.
///
/// # Returns
///
/// * `Binary` containing the parsed security check results for the
///   detected binary format. Upion failure, corresponding blob binary types of are of type 'error'.
///
/// # Supported formats
///
/// - ELF binaries
/// - PE (Portable Executable) binaries
/// - Mach-O binaries (single-architecture and multi-architecture)
///
/// # Examples
///
/// ```
/// use std::fs;
/// use checksec::checksec;
///
/// // Read the binary file into a byte buffer
/// let filename = "tests/binaries/elf/all".into();
/// let buffer = fs::read(&filename).expect("Failed to read binary");
///
/// // Run the security checks
/// let binary_info = checksec(&buffer, filename);
/// println!("Binary Info:/n{:?}", binary_info);
/// ```
#[must_use]
pub fn checksec(bytes: &[u8], filename: String) -> Binary {
    Binary::new(PathBuf::from(filename), get_blob_from_buf(bytes))
}

/// Parses a binary buffer and performs security analysis based on the detected format.
///
/// Supports ELF, PE, and Mach-O binaries (both 32-bit and 64-bit). Returns multiple
/// `Blob` objects for fat Mach-O binaries, single `Blob` for other formats.
/// Errors are returned as `Blob` objects with `BinType::Error`.
///
/// # Arguments
/// * `buffer` - Raw binary data to analyze
///
/// # Returns
/// `Vec<Blob>` containing security analysis results or error information
///
/// # Example
/// ```rust
/// use std::fs;
/// use checksec::get_blob_from_buf;
///
/// let buffer = fs::read("tests/binaries/elf/all").expect("Failed to read binary");
/// let blobs = get_blob_from_buf(&buffer);
/// println!("Binary Info:/n{:?}", blobs[0]);
/// ```
#[must_use]
pub fn get_blob_from_buf(buffer: &[u8]) -> Vec<Blob> {
    match Object::parse(buffer) {
        Ok(Object::Elf(elf)) => {
            let result = elf::CheckSecResults::parse(&elf, buffer);
            let bin_type =
                if elf.is_64 { BinType::Elf64 } else { BinType::Elf32 };
            vec![Blob::new(bin_type, BinSpecificProperties::Elf(result))]
        }
        Ok(Object::PE(pe)) => {
            let result = pe::CheckSecResults::parse(&pe, buffer);
            let bin_type =
                if pe.is_64 { BinType::PE64 } else { BinType::PE32 };
            vec![Blob::new(bin_type, BinSpecificProperties::PE(result))]
        }
        Ok(Object::Mach(mach)) => match mach {
            Mach::Binary(mach) => {
                let result = macho::CheckSecResults::parse(&mach);
                let bin_type = if mach.is_64 {
                    BinType::MachO64
                } else {
                    BinType::MachO32
                };
                vec![Blob::new(bin_type, BinSpecificProperties::MachO(result))]
            }
            Mach::Fat(mach) => process_fat_mach(&mach, buffer),
        },
        Ok(Object::Unknown(_)) => {
            vec![Blob::new(
                BinType::Error,
                BinSpecificProperties::Error(format!(
                    "Unsupported File Format (File Type: {})",
                    get_file_type(buffer)
                )),
            )]
        }
        Err(res) => vec![Blob::new(
            BinType::Error,
            BinSpecificProperties::Error(res.to_string()),
        )],
        _ => vec![Blob::new(
            BinType::Error,
            BinSpecificProperties::Error("unsupported file type".to_string()),
        )],
    }
}

// Parse out the individual binaries/artifacts contained in a multi-architectural binary.
fn process_fat_mach(fatmach: &MultiArch, bytes: &[u8]) -> Vec<Blob> {
    let mut blob_vec: Vec<Blob> = Vec::new();
    for (idx, fatarch) in fatmach.iter_arches().enumerate() {
        if let Ok(container) = fatmach.get(idx) {
            match container {
                MachO(mach) => {
                    let result = macho::CheckSecResults::parse(&mach);
                    let bin_type = if mach.is_64 {
                        BinType::MachO64
                    } else {
                        BinType::MachO32
                    };
                    blob_vec.push(Blob::new(
                        bin_type,
                        BinSpecificProperties::MachO(result),
                    ));
                }
                Archive(archive) => match fatarch {
                    Ok(fatarch) => {
                        if let Some(archive_bytes) = bytes.get(
                            fatarch.offset as usize
                                ..(fatarch.offset + fatarch.size) as usize,
                        ) {
                            blob_vec.extend(parse_archive(
                                &archive,
                                archive_bytes,
                            ));
                        } else {
                            blob_vec.push(Blob::new(
                                BinType::Error,
                                BinSpecificProperties::Error(
                                    "Archive refers to invalid position"
                                        .to_string(),
                                ),
                            ));
                        }
                    }
                    _ => blob_vec.push(Blob::new(
                        BinType::Error,
                        BinSpecificProperties::Error(
                            "fatarch enumeration failed".to_string(),
                        ),
                    )),
                },
            }
        }
    }
    blob_vec
}

// Parse out binaries contained in an archive/static library.
fn parse_archive(
    archive: &goblin::archive::Archive,
    bytes: &[u8],
) -> Vec<Blob> {
    archive
        .members()
        .iter()
        .filter_map(|member_name| match archive.extract(member_name, bytes) {
            Ok(ext_bytes) => Some(get_blob_from_buf(ext_bytes)),
            Err(_) => None,
        })
        .flatten()
        .collect()
}

fn get_file_type(buffer: &[u8]) -> &str {
    match infer::get(buffer) {
        Some(file_kind) => file_kind.extension(),
        _ => "Unknown",
    }
}
