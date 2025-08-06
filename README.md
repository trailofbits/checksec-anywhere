# 🛡️ Checksec Anywhere: Building Checksec Without Boundaries

Analyze binary security features instantly in your browser. No downloads, no uploads, no accounts.

**[Try it now](https://trailofbits.github.io/checksec-anywhere)**

> **Your files never leave your browser** - Critical for proprietary software, security-sensitive applications, and compliance-restricted code

## Get Started in 30 seconds

1. Open [https://trailofbits.github.io/checksec-anywhere](https://trailofbits.github.io/checksec-anywhere) in your browser
2. Drag and drop your binary file
3. Get comprehensive security analysis instantly

<!-- TODO: Add animated GIF showing drag-and-drop functionality -->

## Features

✅ **Multiple Formats** - ELF, PE, and Mach-O from a single interface 
✅ **No installation required** - Runs locally in your browser using WASM 
✅ **Comprehensive Reports** - All of the properties you're used to seeing and more 
✅ **Batch processing** - Drag and drop entire directories  
✅ **Shareable results** - Generate static URLs for any report 
✅ **Tabbed interface** - Manage multiple analyses simultaneously with an intuitive UI 
✅ **SARIF export** - Download reports in industry-standard format

## Performance

Analysis performance for 699 files in `/usr/bin`:
  | Tool | Processing Time |
|----------|----------|
| checksec (bash) | 14.355s |
| checksec (go) | 0.804s |
| Checksec Anywhere (browser) | 2.777s |

## Technical Details
The core of Checksec Anywhere is built on [checksec.rs](https://crates.io/crates/checksec). 

Key additions include:
- A unified library interface for checksec functionality
- WebAssembly bindings to expose checksec functionality to the browser
- SARIF output
- Compress and encode reports into static shareable URLs
- Additional functionality and checks
  - Fine-grained disassembly for GS detection in PE binaries.
  - Checks for mixing of data and code in ELF program headers.
  - Address Sanitizer detection
  - and more!
