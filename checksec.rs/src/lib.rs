#![warn(clippy::pedantic)]
//! ![checksec](https://raw.githubusercontent.com/etke/checksec.rs/master/resources/checksec.svg?sanitize=true)
//!
//! Checksec is a standalone command line utility and library that provides
//! binary executable security-oriented property checks for `ELF`, `PE`, and
//! `MachO`executables.
//!
//! **Structures**
//!
//! The full checksec results can be retrieved from the implemented
//! `*CheckSecResult` structures for a given binary by passing a
//! [`goblin::Object`](https://docs.rs/goblin/latest/goblin/enum.Object.html)
//! object to the parse method.
//!
//! * [`checksec::elf::CheckSecResults`](crate::elf::CheckSecResults)
//! * [`checksec::macho::CheckSecResults`](crate::macho::CheckSecResults)
//! * [`checksec::pe::CheckSecResults`](crate::pe::CheckSecResults)
//!
//! ```rust
//! use checksec::elf::CheckSecResults as ElfCheckSecResults;
//! use checksec::macho::CheckSecResults as MachOCheckSecResults;
//! use checksec::pe::CheckSecResults as PECheckSecResults;
//! ```
//!
//! **Traits**
//!
//! Add the associated `*Properties` trait to the imports as shown below to
//! have direct access to the security property check functions for a given
//! binary executable format.
//!
//! * [`checksec::elf::Properties`](crate::elf::Properties)
//! * [`checksec::macho::Properties`](crate::macho::Properties)
//! * [`checksec::pe::Properties`](crate::pe::Properties)
//!
//! ```rust
//! use checksec::elf::Properties as ElfProperties;
//! use checksec::macho::Properties as MachOProperties;
//! use checksec::pe::Properties as PEProperties;
//! ```
//!
//! Refer to the generated docs or the examples directory
//! [examples/](https://github.com/etke/checksec.rs/tree/master/examples)
//! for examples of working with both `*Properties` traits and
//! `*CheckSecResults` structs.
//!

use goblin::{Object};
use goblin::mach::Mach;
use serde_derive::{Deserialize, Serialize};

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
pub mod web_bindings;
pub mod compression;
pub mod sarif;

const VERSION: &str = "0.1.0";

#[derive(Serialize, Deserialize)]
pub enum BinResults {
    Elf(elf::CheckSecResults),
    Pe(pe::CheckSecResults),
    Macho(macho::CheckSecResults),
}

/// Analyze a binary file buffer and extract security-related results.
///
/// Parses the input buffer to detect its binary format (ELF, PE, or Mach-O)
/// and runs the appropriate security checks for that format.
///
/// # Arguments
///
/// * `buffer` - A byte slice representing the raw contents of a binary file.
///
/// # Returns
///
/// * `Ok(BinResults)` containing the parsed security check results for the
///   detected binary format.
///
/// * `Err(String)` if parsing or analysis fails.
///
/// # Errors
///
/// This function returns an error in the following cases:
/// - If the binary format is not recognized or supported (e.g., fat Mach-O binaries).
/// - If parsing the binary buffer fails due to invalid or corrupted data.
/// - If the binary type is unsupported by the analysis logic.
///
/// # Supported formats
///
/// - ELF binaries
/// - PE (Portable Executable) binaries
/// - Mach-O binaries (single-architecture only)
///
/// # Examples
///
/// ```
/// use std::fs;
/// use checksec::{checksec_core, BinResults};
///
/// // Read the binary file into a byte buffer
/// let buffer = fs::read("tests/binaries/elf/all").expect("Failed to read binary");
///
/// // Run the security checks
/// if let Ok(BinResults::Elf(elf_results)) = checksec_core(&buffer) {
///     println!("Analysis Results: {}", elf_results);
/// } else {
///     println!("Not an ELF binary or error occurred.");
/// }
/// ```
pub fn checksec_core (buffer: &[u8]) -> Result<BinResults, String> {
    match Object::parse(buffer){
        Ok(Object::Elf(elf)) => {
            let result = elf::CheckSecResults::parse(&elf, buffer);
            Ok(BinResults::Elf(result))
        },
        Ok(Object::PE(pe)) => {
            let result = pe::CheckSecResults::parse(&pe, buffer);
            Ok(BinResults::Pe(result))
        },
        Ok(Object::Mach(mach)) => match mach {
            Mach::Binary(mach) => {
                let result = macho::CheckSecResults::parse(&mach); 
                Ok(BinResults::Macho(result))
            }
            Mach::Fat(_) => { Err("fat binaries currently not supported".into()) }
        },
        Err(res) => {Err(res.to_string())},
        _ => {  Err("unsupported file type".into()) }
    }
}
