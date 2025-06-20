use crate::{BinResults, macho, elf, pe};
use serde_sarif::sarif;
use serde_json::json;

const SARIF_VERSION: &str = "2.1.0";

pub fn get_sarif_report(result: &BinResults) -> bool {
    match result {
        BinResults::Elf(elf) => build_sarif_for_checksec(create_elf_results(elf)),
        BinResults::Pe(pe) => build_sarif_for_checksec(create_pe_results(pe)),
        BinResults::Macho(macho) => build_sarif_for_checksec(create_macho_results(macho)),
    }
}

// setting properties common to all results
fn build_sarif_for_checksec(results: Vec<sarif::Result>) -> bool {
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

    let sarify = sarif::Sarif::builder()
        .runs(runs)
        .version(SARIF_VERSION.to_string())
        .build();

    println!("{:#?}", sarify);
    true
}

// TODO: implement for all elf properties
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
            .build()
    ]
}

// TODO
fn create_pe_results(_pe_result: &pe::CheckSecResults) -> Vec<sarif::Result> {
    vec![]
}

// TODO
fn create_macho_results(_macho_result: &macho::CheckSecResults) -> Vec<sarif::Result> {
    vec![]
}