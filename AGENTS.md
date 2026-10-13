# AGENTS.md - Repository Guidelines for AI & Contributors

## 1. Project Overview
`fritzdecode` is a Rust CLI tool and library for reading, verifying, decrypting, and manipulating configuration backups (`.export`) from AVM FRITZ!Box routers and modems.

## 2. Core Architecture
- **Language**: Rust (Edition 2021).
- **Compatibility**: Must compile and pass tests on standard **Rust Stable** (>= 1.80) and Nightly. Do **NOT** introduce unstable `#![feature(...)]` flags.
- **Safety**: `#![forbid(unsafe_code)]` is enforced throughout the codebase. No `unsafe` blocks are allowed.
- **Linter**: `#![warn(clippy::pedantic)]` is active. Code should remain clean of clippy warnings where feasible.
- **Main Modules**:
  - `src/main.rs`: Command line parsing using `clap` (derive mode).
  - `src/lib.rs`: Typestate-pattern backup parser and serializer (`ConfigBackup<Unverified>` / `ConfigBackup<Verified>`).
  - `src/crypto.rs`: AVM-specific key derivation (MD5), AES-256-CBC secret decoding/encoding, and random IV handling.
  - `src/fritz_base32.rs`: Custom AVM Base32 encoding (using digits `1-6` instead of `2-7`).
  - `src/parser.rs` / `src/avm_cfg.rs`: Parser for AVM's C-like configuration syntax into AST / JSON / YAML.
  - `src/passwords.rs`: Extractor for credentials (ISP PPPoE, VoIP SIP, Wi-Fi WPA, Admin GUI, TR-069, VPN).
  - `src/charset.rs`: Encoding detection and conversion (UTF-8 / ISO-8859-1 / Windows-1252).
  - `src/errors.rs`: Structured errors using `thiserror`.

## 3. Coding Guidelines
- **Standard Library & Idioms**: Use standard Rust library methods (e.g. `split_first_chunk`, `matches!`, `and_then`) instead of unstable compiler features.
- **Interactive Prompts vs. Output Streams**:
  - All interactive prompts (passwords, progress, logs) must be written to `stderr` (`eprint!`, `eprintln!`, `rpassword::prompt_password_stderr`).
  - `stdout` is reserved strictly for program data output (so that pipe redirection `fritzdecode decrypt file > out.export` remains uncorrupted).
- **Security & Privacy**:
  - **NEVER** commit real `.export`, `.json`, or decrypted configuration files containing user credentials, IPsec/WireGuard keys, Wi-Fi passphrases, or ISP passwords to Git.
  - Verify `.gitignore` before making any commits.

## 4. Building and Testing
```bash
cargo check
cargo test
cargo clippy
cargo build --release
```

## 5. Licensing
The project is licensed under the **GNU AGPL-3.0-or-later**. Any additions and redistributions must preserve this license and author credits.
