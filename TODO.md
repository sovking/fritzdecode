# TODO & Roadmap

This document outlines upcoming improvements, features, and infrastructure enhancements for `fritzdecode`.

---

## 1. Automated Testing & Integration Suite
- [x] **End-to-End Synthetic Backup Test**:
  - Implemented in `tests/integration_tests.rs`: full lifecycle test validating `generate -> encrypt -> serialize -> load -> verify_crc -> decrypt -> unpack -> pack -> verify_crc` and credential verification.
- [x] **Fuzz Testing (`cargo-fuzz`)**:
  - Set up fuzzing targets in `fuzz/` for `avm_cfg::parse_avm_cfg` and `crypto::decode_secret` to ensure resilience against corrupted or maliciously crafted backup files.
- [x] **Legacy Encoding Test Matrix**:
  - Added integration test `test_legacy_charset_matrix` verifying handling of legacy Fritz!OS 6.x/7.0 backups with ISO-8859-1 and Windows-1252 accented characters in Wi-Fi and user passwords.

---

## 2. CI/CD on GitHub Actions
- [x] **Continuous Integration Workflow (`.github/workflows/ci.yml`)**:
  - Matrix across:
    - Linux (`ubuntu-latest`)
    - macOS (`macos-latest`)
    - Windows (`windows-latest`)
  - Automated steps:
    - `cargo fmt --check`
    - `cargo clippy --all-targets -- -D warnings`
    - `cargo test --all-targets`
- [x] **Automated Release Pipeline (`.github/workflows/release.yml`)**:
  - Triggers on Git tags (`v*`).
  - Precompiled binary assets for:
    - `x86_64-unknown-linux-gnu` / `x86_64-unknown-linux-musl`
    - `aarch64-unknown-linux-gnu` (Raspberry Pi / ARM64)
    - `x86_64-apple-darwin` / `aarch64-apple-darwin` (Apple Silicon)
    - `x86_64-pc-windows-msvc` (`.exe`)
  - Automated tarball / zip archive creation and SHA256 checksum publishing.

---

## 3. Cryptography & CLI Enhancements
- [x] **Symmetric `encrypt` Subcommand**:
  - Implemented: encrypts cleartext sensitive values in `.export` files or encrypts individual standalone secret strings with password.
- [x] **Offline Password Recovery / Auditing Mode**:
  - Implemented high-performance multi-threaded dictionary/wordlist recovery (`fritzdecode crack -w wordlist.txt <backup.export>`) with pre-parsed key decoding, zero-heap-allocation candidate checking, and dynamic rate reporting.
- [x] **Direct Diff Command**:
  - Implemented `fritzdecode diff file1.export file2.export` to compare two backups (with optional password decryption and section filtering), generating unified diffs for text configurations and property/binary comparison.

---

## 4. Documentation & Packaging
- [ ] Publish crate to [crates.io](https://crates.io) once stabilized.
- [x] Provide a Homebrew formula (`packaging/fritzdecode.rb`) and Arch Linux AUR package (`packaging/PKGBUILD`).
