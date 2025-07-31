//! Implements checksec for `MachO` binaries
#[cfg(feature = "color")]
use colored::Colorize;
use goblin::mach::load_command::CommandVariant;
use goblin::mach::constants::cputype::get_arch_name_from_types;
use goblin::mach::MachO;
use serde::{Deserialize, Serialize};
use crate::shared::{Rpath, VecRpath};
use std::fmt;

#[cfg(feature = "color")]
use crate::colorize_bool;
//use crate::shared::{Rpath, VecRpath};

const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

/// Checksec result struct for `MachO32/64` binaries
///
/// **Example**
///
/// ```rust
/// use checksec::macho::CheckSecResults;
/// use goblin::mach::MachO;
/// use std::fs;
///
/// pub fn print_results(binary: &String) {
///     if let Ok(buf) = fs::read(binary) {
///         if let Ok(macho) = MachO::parse(&buf, 0) {
///             println!("{:#?}", CheckSecResults::parse(&macho));
///         }
///     }
/// }
/// ```
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct CheckSecResults {
    /// Automatic Reference Counting
    pub arc: bool,
    /// Target architecture for the binary
    pub architecture: String,
    /// Stack Canary
    pub canary: bool,
    /// Code Signature (codesign)
    pub code_signature: bool,
    /// Encrypted (`LC_ENCRYPTION_INFO`/`LC_ENCRYPTION_INFO_64`)
    pub encrypted: bool,
    /// Fortify (*CFLAGS=*`-D_FORTIFY_SOURCE`)
    pub fortify: bool,
    /// Fortified functions
    pub fortified: u32,
    /// Non-Executable Heap (`MH_NO_HEAP_EXECUTION`)
    pub nx_heap: bool,
    /// Non-Executable Stack (`MH_ALLOW_STACK_EXECUTION`)
    pub nx_stack: bool,
    /// Position Independent Executable (`MH_PIE`)
    pub pie: bool,
    /// Restrict segment
    pub restrict: bool,
    /// Load Command @rpath
    //rpath: VecRpath,
    pub rpath: VecRpath,
    // bitness info
    pub bitness: u64,
    //Symbol count
    pub symbol_count: usize,
    // Has asan instrumentation
    pub asan: bool,
}
impl CheckSecResults {
    #[must_use]
    pub fn parse(macho: &MachO) -> Self {
        Self {
            arc: macho.has_arc(),
            architecture: macho.get_architecture(),
            canary: macho.has_canary(),
            code_signature: macho.has_code_signature(),
            encrypted: macho.has_encrypted(),
            fortify: macho.has_fortify(),
            fortified: macho.has_fortified(),
            nx_heap: macho.has_nx_heap(),
            nx_stack: macho.has_nx_stack(),
            pie: macho.has_pie(),
            restrict: macho.has_restrict(),
            rpath: macho.has_rpath(),
            bitness: if macho.is_64 { 64 } else { 32 },
            symbol_count: macho.symbol_count(),
            asan: macho.has_asan(),
        }
    }
}

impl fmt::Display for CheckSecResults {
    #[cfg(not(feature = "color"))]
    /// Colorized human readable format output
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ARC: {} Architecture: {} Canary: {} Code Signature: {} Encryption: {} \
            Fortify: {} Fortified {:2} NX Heap: {} \
            NX Stack: {} PIE: {} Restrict: {} RPath: {} Symbols: {} Asan: {}",
            self.arc,
            self.architecture,
            self.canary,
            self.code_signature,
            self.encrypted,
            self.fortify,
            self.fortified,
            self.nx_heap,
            self.nx_stack,
            self.pie,
            self.restrict,
            self.rpath,
            self.symbol_count,
            self.asan
        )
    }
    #[cfg(feature = "color")]
    /// Colorized human readable format output
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} \
            {} {} {} {} {} {} {} {} {} {}",
            "ARC:".bold(),
            colorize_bool!(self.arc),
            "Architecture:".bold(),
            self.architecture,
            "Canary:".bold(),
            colorize_bool!(self.canary),
            "Code Signature:".bold(),
            colorize_bool!(self.code_signature),
            "Encrypted:".bold(),
            colorize_bool!(self.encrypted),
            "Fortify:".bold(),
            colorize_bool!(self.fortify),
            "Fortified:".bold(),
            self.fortified,
            "NX Heap:".bold(),
            colorize_bool!(self.nx_heap),
            "NX Stack:".bold(),
            colorize_bool!(self.nx_stack),
            "PIE:".bold(),
            colorize_bool!(self.pie),
            "Restrict:".bold(),
            colorize_bool!(self.restrict),
            "RPath:".bold(),
            self.rpath,
            "Symbols".bold(),
            self.symbol_count,
            "Asan".bold(),
            colorize_bool!(!self.asan),
        )
    }
}

/// checksec Trait implementation for
/// [`goblin::mach::MachO`](https://docs.rs/goblin/latest/goblin/mach/struct.MachO.html)
///
/// **Example**
///
/// ```rust
/// use checksec::macho::Properties;
/// use goblin::mach::MachO;
/// use std::fs;
///
/// pub fn print_results(binary: &String) {
///     if let Ok(buf) = fs::read(binary) {
///         if let Ok(macho) = MachO::parse(&buf, 0) {
///             println!("arc: {}", macho.has_arc());
///         }
///     }
/// }
/// ```
pub trait Properties {
    /// check import names for `_objc_release`
    fn has_arc(&self) -> bool;
    /// Get target architecture for the binary, helpful when analyzing multi-architecture Mach-O files.
    fn get_architecture(&self) -> String;
    /// check import names for `___stack_chk_fail` or `___stack_chk_guard`
    fn has_canary(&self) -> bool;
    /// check data size of code signature in load commands
    fn has_code_signature(&self) -> bool;
    /// check if `cryptid` has a value set for EncryptionInfo32/64 in load
    /// commands
    fn has_encrypted(&self) -> bool;
    /// check for symbols ending in `_chk` from symbols
    fn has_fortify(&self) -> bool;
    /// count symbols ending in `_chk` from symbols
    fn has_fortified(&self) -> u32;
    /// check `MH_NO_HEAP_EXECUTION` *(0x01000000)* in `MachO` header flags
    fn has_nx_heap(&self) -> bool;
    /// check `MH_ALLOW_STACK_EXECUTION` *(0x00020000)* in `MachO` header flags
    fn has_nx_stack(&self) -> bool;
    /// check `MH_PIE` *(0x00200000)* in `MachO` header flags
    fn has_pie(&self) -> bool;
    /// check for `___restrict` segment name
    fn has_restrict(&self) -> bool;
    //fn has_rpath(&self) -> VecRpath;
    /// check for `RPath` in load commands
    fn has_rpath(&self) -> VecRpath;
    // return the total number of symbols in the binary
    fn symbol_count(&self) -> usize;
    // return if the binary has asan instrumentation
    fn has_asan(&self) -> bool;
}
impl Properties for MachO<'_> {
    fn has_arc(&self) -> bool {
        self.symbols()
        .flatten()
        .any(|(name, _)| name == "_objc_release" || name == "_objc_alloc")
    }
    fn get_architecture(&self) -> String {
        match get_arch_name_from_types(self.header.cputype(), self.header.cpusubtype()) {
            Some(arch) => arch.to_string(),
            None => "Unknown".to_string()
        }
    }
    fn has_canary(&self) -> bool {
        self.symbols()
        .flatten()
        .any(|(name, _)| name == "___stack_chk_fail" || name == "___stack_chk_guard")
    }
    fn has_code_signature(&self) -> bool {
        for loadcmd in &self.load_commands {
            if let CommandVariant::CodeSignature(cmd) = loadcmd.command {
                // just check for existence, todo full validation
                if cmd.datasize > 0 {
                    return true;
                }
            }
        }
        false
    }
    fn has_encrypted(&self) -> bool {
        for loadcmd in &self.load_commands {
            match loadcmd.command {
                CommandVariant::EncryptionInfo32(cmd) => {
                    if cmd.cryptid != 0 {
                        return true;
                    }
                }
                CommandVariant::EncryptionInfo64(cmd) => {
                    if cmd.cryptid != 0 {
                        return true;
                    }
                }
                _ => (),
            }
        }
        false
    }
    fn has_fortify(&self) -> bool {
        for sym in self.symbols().flatten() {
            if sym.0.ends_with("_chk") {
                return true;
            }
        }
        false
    }
    fn has_fortified(&self) -> u32 {
        let mut fortified_count: u32 = 0;
        for sym in self.symbols().flatten() {
            if sym.0.ends_with("_chk") {
                fortified_count += 1;
            }
        }
        fortified_count
    }
    fn has_nx_heap(&self) -> bool {
        matches!(self.header.flags & MH_NO_HEAP_EXECUTION, x if x != 0)
    }
    fn has_nx_stack(&self) -> bool {
        !matches!(self.header.flags & MH_ALLOW_STACK_EXECUTION, x if x != 0)
    }
    fn has_pie(&self) -> bool {
        matches!(self.header.flags & MH_PIE, x if x != 0)
    }
    fn has_restrict(&self) -> bool {
        for segment in &self.segments {
            if let Ok(name) = segment.name() {
                if name.to_string().to_lowercase() == "__restrict" {
                    return true;
                }
            }
        }
        false
    }
    fn has_rpath(&self) -> VecRpath {
        let mut paths = Vec::new();
        for &rpath in &self.rpaths {
            paths.push(Rpath::Yes(rpath.into()));
        }
        if paths.is_empty(){
            return VecRpath::new(vec![Rpath::None]);
        }
        VecRpath::new(paths)
    }
    fn symbol_count(&self) -> usize {
        self.symbols().flatten().count()
    }
    fn has_asan(&self) -> bool{
        // check for asan initialization prologue. Apple adds an additional underscore in front of C symbols to differentiate from asm symbols.
        self.symbols()
            .flatten()
            .any(|(name, _)| {
                name == "___asan_init"
        })
    }
}
