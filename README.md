# 🛡️ Checksec Anywhere: Building Checksec Without Boundaries

Checksec Anywhere enables quick, seamless binary security analysis for your ELF, PE, and MACH-O files.
Accessible from the browser, it cuts out unnecessary dependencies and maintenance from your checksec toolkit! 

Check it out at [https://trailofbits.github.io/checksec-anywhere](https://trailofbits.github.io/checksec-anywhere).

## Features
### Multiple Formats
  ELF, PE, and single or multi-architecture Mach-O binaries from a single interface.
### Privacy
  Critical for proprietary software, security-sensitive applications, and compliance-restricted code, Checksec Anywhere ensures your binaries never leave your machine by processing everything locally in the browser.
### Comprehensive Reports
  All of the properties you're used to seeing and more.
### Speed
Analysis performance for 699 files in `/usr/bin`:
  | Tool | Processing Time |
|----------|----------|
| checksec (bash) | 14.355s |
| checksec (go) | 0.804s |
| Checksec Anywhere (browser) | 2.777s |

### Accessibility
- Shareable Results: Generate static URLs for any report view
- SARIF Export: Download reports in SARIF format
- Batch Processing: Drag and drop entire directories for bulk analysis
- Tabbed Interface: Manage multiple analyses simultaneously with an intuitive UI

## Technical Details
The core of Checksec Anywhere is built on [checksec.rs](https://crates.io/crates/checksec). Key additions include:
- `lib.rs`: A unified library interface for checksec functionality
- `web_bindings.rs`: WebAssembly bindings to expose checksec functionality to the browser
- `sarif.rs`: Convert checksec reports to the SARIF outputs
- `compression.rs`: Compress and encode reports to generate static URLs
- Bug fixes and tests: Extensive unit tests and test files in `/tests`
- Additional functionality and checks
  - Fine-grained disassembly for GS detection in PE binaries.
  - Checks for mixing of data and code in ELF program headers.
  - Address Sanitizer detection
  - and more!
