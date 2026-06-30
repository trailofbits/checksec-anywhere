# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Checksec Anywhere analyzes binary security features (ELF / PE / Mach-O) entirely
client-side in the browser via WebAssembly — files never leave the user's machine.
The same Rust core also ships as a native CLI (`checksec`). It is a fork of
[checksec.rs](https://crates.io/crates/checksec) with extra checks, SARIF export, and
shareable-URL compression.

## Workspace layout

Cargo workspace (`resolver = "3"`) with two crates plus a static frontend:

- **`checksec.rs/`** — the core `checksec` crate: a library (`src/lib.rs`) **and** the
  native CLI binary (`src/main.rs`). Both targets live in one crate.
- **`checksec-wasm/`** — thin `wasm-bindgen` bindings (`cdylib`) that re-export library
  functions to JavaScript. Adds no analysis logic of its own.
- **`frontend/`** — vanilla-JS static site (no framework, no bundler). Loads the WASM
  module and renders results.

## Build & test

```bash
make cli            # native CLI -> target/release/checksec
make wasm           # wasm-pack build -> frontend/pkg/ (gitignored, generated)
make all            # both
make local_instance # builds wasm, then `python3 -m http.server` in frontend/ (port 8000)
make test           # cargo test -p checksec
make clean          # cargo clean + rm -rf frontend/pkg
```

Run a single test file or test by name:
```bash
cargo test -p checksec --test test_elf
cargo test -p checksec <substring_of_test_name>
```

CI (`.github/workflows/ci.yml`) enforces three gates — match them before pushing:
```bash
cargo fmt --all -- --check                                          # see rustfmt note below
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features -- --nocapture
```
`make wasm` runs `cargo install wasm-pack` first; install the `wasm32-unknown-unknown`
target if building WASM locally. Pushes to `main` auto-deploy `frontend/` to GitHub Pages
(`deploy.yml`).

## Architecture notes

**Data model (`src/binary.rs`) is the contract across every boundary.**
`Binary { file, blobs: Vec<Blob>, libraries: Vec<Binary> }` where each `Blob` pairs a
`BinType` (Elf32/64, PE32/64, MachO32/64, Error) with `BinSpecificProperties` (the
per-format `CheckSecResults`). This struct is `serde`-serialized and is what crosses the
Rust↔JS WASM boundary and gets compressed into shareable URLs. Changing its shape means
updating `frontend/display.js` (which reads these fields by name) and the SARIF mapping
in `src/sarif.rs` in lockstep — there is no generated schema keeping them in sync.

**`binary.rs` is shared by file path between the lib and the CLI** (`pub mod binary` in
`lib.rs`, `mod binary` in `main.rs` point at the same file). `proc.rs` (live-process
scanning) is CLI-only.

**Analysis entry point:** `checksec::checksec(bytes, filename)` → `get_blob_from_buf`
(`src/lib.rs`) dispatches on the format goblin detects and calls the matching
`CheckSecResults::parse` in `elf.rs` / `pe.rs` / `macho.rs`. Fat Mach-O and archives
(`.a`/static libs) expand into multiple blobs. Parse failures become `BinType::Error`
blobs rather than hard errors.

**WASM surface (`checksec-wasm/src/lib.rs`)** — only four exported functions:
`checksec_web`, `checksec_compress`, `checksec_decompress`, `generate_sarif_report`.
Results are wrapped in `CheckSecJs { version, report }`. The CLI never touches this crate.

**Format modules** (`elf.rs`, `pe.rs`, `macho.rs`) each own their `CheckSecResults`
struct, its checks, and its `Display` impl. ELF/Mach-O/PE share helpers via the `shared`
feature (`src/shared.rs`, `src/macros.rs`).

## Feature flags & platform gating

Default features: `elf, macho, pe, color, maps, disassembly`.
- `disassembly` (iced-x86) powers fine-grained PE GS detection — `src/disassembly.rs`.
- `color` pulls in `colored`/`colored_json` and (Linux only) `xattr` for setuid/filecaps
  highlighting.
- `maps` + live-process inspection (`proc.rs`, `ldso.rs`) are Linux-only and heavily
  `#[cfg]`-gated; Windows uses the `windows` crate. Code that touches processes, ld.so, or
  xattrs must stay behind the right `cfg`/feature gates or it breaks the WASM and non-Linux
  builds.

## Conventions

- **rustfmt: `max_width = 79`** (`checksec.rs/rustfmt.toml`) — lines are narrow; let
  rustfmt wrap rather than hand-formatting.
- Both `lib.rs` and `main.rs` enable `#![warn(clippy::pedantic)]`, and CI treats clippy
  warnings as errors, so pedantic lints must be satisfied or explicitly `#[allow]`-ed.
