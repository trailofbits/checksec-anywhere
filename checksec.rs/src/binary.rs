#[cfg(feature = "color")]
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{fmt};

#[cfg(feature = "elf")]
use crate::elf;
#[cfg(feature = "macho")]
use crate::macho;
#[cfg(feature = "pe")]
use crate::pe;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BinType {
    #[cfg(feature = "elf")]
    Elf32,
    #[cfg(feature = "elf")]
    Elf64,
    #[cfg(feature = "pe")]
    PE32,
    #[cfg(feature = "pe")]
    PE64,
    #[cfg(feature = "macho")]
    MachO32,
    #[cfg(feature = "macho")]
    MachO64,
    Error,
}
#[cfg(not(feature = "color"))]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "elf")]
            Self::Elf32 => write!(f, "ELF32"),
            #[cfg(feature = "elf")]
            Self::Elf64 => write!(f, "ELF64"),
            #[cfg(feature = "pe")]
            Self::PE32 => write!(f, "PE32"),
            #[cfg(feature = "pe")]
            Self::PE64 => write!(f, "PE64"),
            #[cfg(feature = "macho")]
            Self::MachO32 => write!(f, "MachO32"),
            #[cfg(feature = "macho")]
            Self::MachO64 => write!(f, "MachO64"),
            Self::Error => write!(f, "Error")
        }
    }
}
#[cfg(feature = "color")]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "elf")]
            Self::Elf32 => write!(f, "{}", "ELF32".bold().underline()),
            #[cfg(feature = "elf")]
            Self::Elf64 => write!(f, "{}", "ELF64".bold().underline()),
            #[cfg(feature = "pe")]
            Self::PE32 => write!(f, "{}", "PE32".bold().underline()),
            #[cfg(feature = "pe")]
            Self::PE64 => write!(f, "{}", "PE64".bold().underline()),
            #[cfg(feature = "macho")]
            Self::MachO32 => write!(f, "{}", "MachO32".bold().underline()),
            #[cfg(feature = "macho")]
            Self::MachO64 => write!(f, "{}", "MachO64".bold().underline()),
            Self::Error => write!(f, "{}", "Error".bold().underline()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BinSpecificProperties {
    #[cfg(feature = "elf")]
    Elf(elf::CheckSecResults),
    #[cfg(feature = "pe")]
    PE(pe::CheckSecResults),
    #[cfg(feature = "macho")]
    MachO(macho::CheckSecResults),
    Error(String),
}
impl fmt::Display for BinSpecificProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "elf")]
            Self::Elf(b) => write!(f, "{b}"),
            #[cfg(feature = "pe")]
            Self::PE(b) => write!(f, "{b}"),
            #[cfg(feature = "macho")]
            Self::MachO(b) => write!(f, "{b}"),
            Self::Error(b) => write!(f, "{b}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Blob {
    pub binarytype: BinType,
    pub properties: BinSpecificProperties,
}

impl Blob {
    pub fn new(
        binarytype: BinType,
        properties: BinSpecificProperties,
    ) -> Self {
        Self { binarytype, properties }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Binary {
    pub file: PathBuf,
    pub blobs: Vec<Blob>,
    pub libraries: Vec<Binary>,
}

impl Binary {
    pub fn new(file: PathBuf, blobs: Vec<Blob>) -> Self {
        Self { file, blobs, libraries: vec![] }
    }
}
