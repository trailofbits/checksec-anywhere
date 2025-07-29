//! Convert checksec report to sarif
use crate::{macho, elf, pe, shared::{Rpath, VecRpath}, binary::{Binary, BinSpecificProperties}};
use serde_sarif::sarif;
use std::path::PathBuf;
use serde_json;
const SARIF_VERSION: &str = "2.1.0";

/// Converts a binary analysis result into a SARIF JSON report.
///
/// # Arguments
///
/// * `results` - A reference to a vector of `Binary` structs. Each containing filename, blob information (individual reports), and libraries.
///
/// # Returns
///
/// Returns a `serde_json::Result<String>` containing the formatted SARIF JSON string on success.
pub fn get_sarif_report(results: &Vec<Binary>) -> serde_json::Result<String> {
    let tool = get_tool_spec();
    let sarif_runs: Vec<sarif::Run> = results
        .iter()
        .map(|result| {
            let results: Vec<sarif::Result> = result
                .blobs
                .iter()
                .map(|blob| match &blob.properties {
                    BinSpecificProperties::Elf(elf) => create_elf_results(elf),
                    BinSpecificProperties::PE(pe) => create_pe_results(pe),
                    BinSpecificProperties::MachO(macho) => create_macho_results(macho),
                    _ => unreachable!(
                        "Sarif reports should only be generated for non-error reports."
                    ),
                })
                .flatten()
                .collect();
            sarif::Run::builder()
                .tool(tool.clone())
                .artifacts(vec![get_file_artifact(&result.file)])
                .results(results)
                .build()
        })
        .collect();
    build_sarif_for_checksec(sarif_runs)
}

// create a sarif Artifact with the name of the file included
fn get_file_artifact(filename: &PathBuf) -> sarif::Artifact{
    sarif::Artifact::builder()
    .location(
        sarif::ArtifactLocation::builder().uri(
            filename.to_string_lossy().to_string()
        ).build()
    ).build()
}

// Perform initial setup of the sarif Tool type
fn get_tool_spec() -> sarif::Tool {
    sarif::Tool::builder()
    .driver(sarif::ToolComponent::builder()
        .name("checksec-anywhere")
        .build())
    .build()
}

// Wrap a vector of runs into a full sarif report and convert it to json
fn build_sarif_for_checksec(runs: Vec<sarif::Run>) -> serde_json::Result<String> {
    let sarif = sarif::Sarif::builder()
        .schema(sarif::SCHEMA_URL)
        .runs(runs)
        .version(SARIF_VERSION.to_string())
        .build();
    let json = serde_json::to_string_pretty(&sarif)?;
    Ok(json)
}

// Convert checksec results for an elf file into a vector of results
#[allow(clippy::too_many_lines)]
fn create_elf_results(elf_result: &elf::CheckSecResults) -> Vec<sarif::Result> {
    vec![
        sarif::Result::builder()
            .rule_id("canary".to_string())
            .message(sarif::Message::builder()
                .text(format!("Stack Canary enabled: {}", elf_result.canary))
                .build())
            .level(if elf_result.canary {
                sarif::ResultLevel::None
            } else {
                sarif::ResultLevel::Warning
            })
            .build(),
            sarif::Result::builder()
            .rule_id("Clang CFI".to_string())
            .message(sarif::Message::builder()
                .text(format!("Clang CFI enabled: {}", elf_result.clang_cfi))
                .build())
            .level(if elf_result.clang_cfi {
                sarif::ResultLevel::None
            } else {
                sarif::ResultLevel::Warning
            })
            .build(),
            sarif::Result::builder()
            .rule_id("Clang SafeStack".to_string())
            .message(sarif::Message::builder()
                .text(format!("Clang SafeStack enabled: {}", elf_result.clang_safestack))
                .build())
            .level(if elf_result.clang_safestack {
                sarif::ResultLevel::None
            } else {
                sarif::ResultLevel::Warning
            })
            .build(),
            sarif::Result::builder()
            .rule_id("Stack Clash Protection".to_string())
            .message(sarif::Message::builder()
                .text(format!("Stack Clash Protection enabled: {}", elf_result.stack_clash_protection))
                .build())
            .level(if elf_result.stack_clash_protection {
                sarif::ResultLevel::None
            } else {
                sarif::ResultLevel::Warning
            })
            .build(),
            sarif::Result::builder()
            .rule_id("Fortify".to_string())
            .message(sarif::Message::builder()
                .text(format!("Fortify: {}", elf_result.fortify.to_string().trim_end()))
                .build())
            .level(match elf_result.fortify{
                elf::Fortify::Full => sarif::ResultLevel::None,
                elf::Fortify::Undecidable => sarif::ResultLevel::Note,
                elf::Fortify::Partial | elf::Fortify::None => sarif::ResultLevel::Warning,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("fortified functions".to_string())
            .message(sarif::Message::builder()
                .text(format!("Number of fortified functions: {}", elf_result.fortified.to_string().trim_end()))
                .build())
            .level(match elf_result.fortify{
                elf::Fortify::Full => sarif::ResultLevel::None,
                elf::Fortify::Undecidable => sarif::ResultLevel::Note,
                elf::Fortify::Partial | elf::Fortify::None => sarif::ResultLevel::Warning,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("fortifiable functions".to_string())
            .message(sarif::Message::builder()
                .text(format!("Number of fortifiable functions: {}", elf_result.fortifiable.to_string().trim_end()))
                .build())
            .level(match elf_result.fortify{
                elf::Fortify::Full => sarif::ResultLevel::None,
                elf::Fortify::Undecidable => sarif::ResultLevel::Note,
                elf::Fortify::Partial | elf::Fortify::None => sarif::ResultLevel::Warning,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("NX".to_string())
            .message(sarif::Message::builder()
                .text(format!("Non-executable memory segments: {}", elf_result.nx.to_string().trim_end()))
                .build())
            .level(match elf_result.nx{
                elf::Nx::Na => sarif::ResultLevel::Note,
                elf::Nx::Enabled => sarif::ResultLevel::None,
                elf::Nx::Disabled => sarif::ResultLevel::Warning,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("PIE".to_string())
            .message(sarif::Message::builder()
                .text(format!("Position-independent executable: {}", elf_result.pie.to_string().trim_end()))
                .build())
            .level(match elf_result.pie{
                elf::PIE::None => sarif::ResultLevel::Warning,
                elf::PIE::DSO | elf::PIE::REL => sarif::ResultLevel::Note,
                elf::PIE::PIE => sarif::ResultLevel::None,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("relro".to_string())
            .message(sarif::Message::builder()
                .text(format!("Relocation Read-Only: {}", elf_result.relro.to_string().trim_end()))
                .build())
            .level(match elf_result.relro{
                elf::Relro::Partial | elf::Relro::None => sarif::ResultLevel::Warning,
                elf::Relro::Full => sarif::ResultLevel::None,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("rpath".to_string())
            .message(sarif::Message::builder()
                .text(format!("Runtime search path: {}", elf_result.rpath))
                .build())
            .level(check_rpath(&elf_result.rpath))
            .build(),
            sarif::Result::builder()
            .rule_id("runpath".to_string())
            .message(sarif::Message::builder()
                .text(format!("Runtime search path (overrrides rpath): {}", elf_result.runpath))
                .build())
            .level(check_rpath(&elf_result.runpath))
            .build(),
            sarif::Result::builder()
            .rule_id("dynlibs".to_string())
            .message(sarif::Message::builder()
                .text(format!("Linked dynamic libraries: {}", elf_result.dynlibs.join(", ")))
                .build())
            .level(sarif::ResultLevel::Note)
            .build(),
            sarif::Result::builder()
            .rule_id("symbols".to_string())
            .message(sarif::Message::builder()
                .text(format!("Symbol count: {}", elf_result.symbol_count.to_string().trim_end()))
                .build())
            .level(if *elf_result.symbol_count == 0 {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("bitness".to_string())
            .message(sarif::Message::builder()
                .text(format!("Bitness: {}", elf_result.bitness))
                .build())
            .level(sarif::ResultLevel::Note)
            .build(),
    ]
}

// Convert checksec results for a PE file into a vector of results
#[allow(clippy::too_many_lines)]
fn create_pe_results(pe_result: &pe::CheckSecResults) -> Vec<sarif::Result> {
    vec![
            sarif::Result::builder()
            .rule_id("aslr".to_string())
            .message(sarif::Message::builder()
                .text(format!("Address Space Layout Randomization: {}", pe_result.aslr))
                .build())
            .level(match pe_result.aslr {
                pe::ASLR::DynamicBase | pe::ASLR::None => sarif::ResultLevel::Warning,
                pe::ASLR::HighEntropyVa => sarif::ResultLevel::None,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("authenticode".to_string())
            .message(sarif::Message::builder()
                .text(format!("Authenticode: {}", pe_result.authenticode))
                .build())
            .level(if pe_result.authenticode {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("cfg".to_string())
            .message(sarif::Message::builder()
                .text(format!("Control flow guard: {}", pe_result.cfg))
                .build())
            .level(if pe_result.cfg {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("dotnet".to_string())
            .message(sarif::Message::builder()
                .text(format!("Common Language Runtime *(.NET Framework)*: {}", pe_result.dotnet))
                .build())
            .level(if pe_result.dotnet {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("nx".to_string())
            .message(sarif::Message::builder()
                .text(format!("Non-executable memory segments: {}", pe_result.nx))
                .build())
            .level(if pe_result.nx {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("force integrity".to_string())
            .message(sarif::Message::builder()
                .text(format!("Force integrity: {}", pe_result.force_integrity))
                .build())
            .level(if pe_result.force_integrity {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("GS".to_string())
            .message(sarif::Message::builder()
                .text(format!("Security Cookie/Stack Canary: {}", pe_result.gs))
                .build())
            .level(if pe_result.gs {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("GS".to_string())
            .message(sarif::Message::builder()
                .text(format!("Security Cookie/Stack Canary: {}", pe_result.gs))
                .build())
            .level(if pe_result.gs {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("isolation".to_string())
            .message(sarif::Message::builder()
                .text(format!("Allow isolation: {}", pe_result.gs))
                .build())
            .level(if pe_result.gs {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("rfg".to_string())
            .message(sarif::Message::builder()
                .text(format!("Return flow guard: {}", pe_result.rfg))
                .build())
            .level(if pe_result.rfg {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("safeseh".to_string())
            .message(sarif::Message::builder()
                .text(format!("Safe Structured Exception Handler: {}", pe_result.safeseh))
                .build())
            .level(if pe_result.safeseh {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("seh".to_string())
            .message(sarif::Message::builder()
                .text(format!("Structured Exception Handler: {}", pe_result.seh))
                .build())
            .level(if pe_result.seh {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("cet".to_string())
            .message(sarif::Message::builder()
                .text(format!("Control-flow enforcement technology compatible: {}", pe_result.cet))
                .build())
            .level(if pe_result.cet {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("bitness".to_string())
            .message(sarif::Message::builder()
            .text(format!("Bitness: {}", pe_result.bitness))
            .build())
            .level(sarif::ResultLevel::Note)
            .build(),
    ]
}

// Convert checksec results for a mach-o file into a vector of results
#[allow(clippy::too_many_lines)]
fn create_macho_results(macho_result: &macho::CheckSecResults) -> Vec<sarif::Result> {
    vec![
            sarif::Result::builder()
            .rule_id("arc".to_string())
            .message(sarif::Message::builder()
                .text(format!("Automatic Reference Counting: {}", macho_result.arc))
                .build())
            .level(if macho_result.arc {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("architecture".to_string())
            .message(sarif::Message::builder()
                .text(format!("Target Architecture: {}", macho_result.architecture))
                .build())
            .level(sarif::ResultLevel::Note)
            .build(),
            sarif::Result::builder()
            .rule_id("canary".to_string())
            .message(sarif::Message::builder()
                .text(format!("Stack canary: {}", macho_result.canary))
                .build())
            .level(if macho_result.canary {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("encrypted".to_string())
            .message(sarif::Message::builder()
                .text(format!("encrypted: {}", macho_result.encrypted))
                .build())
            .level(if macho_result.encrypted {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("fortify".to_string())
            .message(sarif::Message::builder()
                .text(format!("fortify: {}", macho_result.fortify))
                .build())
            .level(if macho_result.fortify {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("fortifed".to_string())
            .message(sarif::Message::builder()
                .text(format!("Number of fortified functions: {}", macho_result.fortified))
                .build())
            .level(sarif::ResultLevel::Note)
            .build(),
            sarif::Result::builder()
            .rule_id("nx heap".to_string())
            .message(sarif::Message::builder()
                .text(format!("Non-executable heap: {}", macho_result.nx_heap))
                .build())
            .level(if macho_result.nx_heap {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("nx stack".to_string())
            .message(sarif::Message::builder()
                .text(format!("Non-executable stack: {}", macho_result.nx_stack))
                .build())
            .level(if macho_result.nx_stack {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("pie".to_string())
            .message(sarif::Message::builder()
                .text(format!("Position independent executable: {}", macho_result.pie))
                .build())
            .level(if macho_result.pie {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("restrict".to_string())
            .message(sarif::Message::builder()
                .text(format!("Restrict segment: {}", macho_result.restrict))
                .build())
            .level(if macho_result.restrict {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("rpath".to_string())
            .message(sarif::Message::builder()
                .text(format!("Runtime path: {}", macho_result.rpath))
                .build())
            .level(check_rpath(&macho_result.rpath))
            .build(),
            sarif::Result::builder()
            .rule_id("bitness".to_string())
            .message(sarif::Message::builder()
                .text(format!("Bitness: {}", macho_result.bitness))
                .build())
            .level(sarif::ResultLevel::Note)
            .build(),
    ]
}

// Check if the elements in an rpath/runpath are nontrivial and should be given warning.
fn check_rpath(paths: &VecRpath) -> sarif::ResultLevel {
    if paths.is_empty(){
        return sarif::ResultLevel::None;
    }
    if paths.len() != 1 {
       return sarif::ResultLevel::Warning;
    }
    match &paths[0] {
        Rpath::Yes(path) | Rpath::YesRW(path) => {
            if path == "None" {
                sarif::ResultLevel::None
            }
            else{
                sarif::ResultLevel::Warning
            }
        },
        Rpath::None => sarif::ResultLevel::None
    }
}