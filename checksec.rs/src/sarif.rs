//! Convert checksec report to sarif
use crate::{BinResults, macho, elf, pe};
use serde_sarif::sarif;
use serde_json;

const SARIF_VERSION: &str = "2.1.0";

pub fn get_sarif_report(result: &BinResults) -> serde_json::Result<String> {
    match result {
        BinResults::Elf(elf) => build_sarif_for_checksec(create_elf_results(elf)),
        BinResults::Pe(pe) => build_sarif_for_checksec(create_pe_results(pe)),
        BinResults::Macho(macho) => build_sarif_for_checksec(create_macho_results(macho)),
    }
}

// setting properties common to all results
fn build_sarif_for_checksec(results: Vec<sarif::Result>) -> serde_json::Result<String> {
    let tool = sarif::Tool::builder()
        .driver(sarif::ToolComponent::builder()
            .name(format!("checksec-anywhere"))
            .build())
        .build();

    let runs = vec![
        sarif::Run::builder()
            .tool(tool)
            .results(results)
            .build()
    ];

    let sarif = sarif::Sarif::builder()
        .schema(sarif::SCHEMA_URL)
        .runs(runs)
        .version(SARIF_VERSION.to_string())
        .build();
    let json = serde_json::to_string_pretty(&sarif)?;
    return Ok(json);
    
}


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
                elf::Fortify::Partial => sarif::ResultLevel::Warning,
                elf::Fortify::None => sarif::ResultLevel::Warning,
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
                elf::Fortify::Partial => sarif::ResultLevel::Warning,
                elf::Fortify::None => sarif::ResultLevel::Warning,
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
                elf::Fortify::Partial => sarif::ResultLevel::Warning,
                elf::Fortify::None => sarif::ResultLevel::Warning,
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
                elf::PIE::DSO => sarif::ResultLevel::Note,
                elf::PIE::REL => sarif::ResultLevel::Note,
                elf::PIE::PIE => sarif::ResultLevel::None,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("relro".to_string())
            .message(sarif::Message::builder()
                .text(format!("Relocation Read-Only: {}", elf_result.relro.to_string().trim_end()))
                .build())
            .level(match elf_result.relro{
                elf::Relro::None => sarif::ResultLevel::Warning,
                elf::Relro::Partial => sarif::ResultLevel::Warning,
                elf::Relro::Full => sarif::ResultLevel::None,
            })
            .build(),
            sarif::Result::builder()
            .rule_id("rpath".to_string())
            .message(sarif::Message::builder()
                .text(format!("Runtime search path: {}", elf_result.rpath))
                .build())
            .level(if elf_result.rpath.is_empty() {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
            sarif::Result::builder()
            .rule_id("runpath".to_string())
            .message(sarif::Message::builder()
                .text(format!("Runtime search path (overrrides rpath): {}", elf_result.runpath))
                .build())
            .level(if elf_result.runpath.is_empty() {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
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
    ]
}

fn create_pe_results(pe_result: &pe::CheckSecResults) -> Vec<sarif::Result> {
    vec![
            sarif::Result::builder()
            .rule_id("aslr".to_string())
            .message(sarif::Message::builder()
                .text(format!("Address Space Layout Randomization: {}", pe_result.aslr))
                .build())
            .level(match pe_result.aslr {
                pe::ASLR::None => sarif::ResultLevel::Warning,
                pe::ASLR::DynamicBase => sarif::ResultLevel::Warning,
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
    ]
}

// TODO
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
            .level(if macho_result.rpath.is_empty() {
                    sarif::ResultLevel::None
                }
                else{
                    sarif::ResultLevel::Warning
                })
            .build(),
    ]
}