# fritzdecode

A powerful, high-performance CLI tool and Rust library for inspecting, verifying, decrypting, and manipulating **AVM FRITZ!Box** configuration backup files (`.export`).

---

## Features

- **Decryption (`decrypt`)**: Decrypts all passwords and sensitive data stored within FRITZ!Box backup files.
- **Credential Extraction (`passwords`)**: Instantly dumps Internet/PPPoE, VoIP/SIP accounts, Wi-Fi keys, router users, TR-069 management credentials, and VPN configurations in human-readable tables, JSON, or YAML.
- **Unpack & Pack (`unpack`, `pack`)**: Extracts all contained `.cfg` text files and decoded raw binaries from the archive with a `manifest.json`, allowing easy editing and rebuilding into a valid `.export` file with recalculated CRC32.
- **JSON & YAML Conversion (`convert`)**: Parses AVM's proprietary C-like configuration language into structured JSON or YAML for easy consumption with tools like `jq` or Ansible.
- **Direct Diff (`diff`)**: Compares two FRITZ!Box configuration exports line-by-line, showing unified diffs for text configurations and detecting property and binary file changes.
- **Offline Password Recovery (`crack`)**: High-speed multi-threaded dictionary/wordlist recovery for forgotten backup export passwords.
- **Integrity Verification & Recalculation (`verify`, `gencrc`)**: Verifies and recalculates ISO-HDLC CRC32 checksums so modified backups can be restored without router rejection.
- **Seamless Charset Handling**: Transparently decodes both UTF-8 and legacy ISO-8859-1 / Windows-1252 backups.
- **Secure Password Prompting**: Non-echoing password input on `stderr` via `rpassword`, with support for the `--password` flag and the `FRITZ_PASSWORD` environment variable.

---

## Supported Platforms

`fritzdecode` is cross-platform and compiles natively on:
- **Linux** (`x86_64`, `aarch64` / ARM, including Raspberry Pi)
- **macOS** (`Apple Silicon` / `M1/M2/M3`, and `Intel x86_64`)
- **Windows** (`x86_64`)

---

## Prerequisites & Rust Installation

`fritzdecode` requires a standard **Rust Stable** toolchain (version 1.80 or higher).

If you do not have Rust installed on your system, install it using the official installer from the [Official Rust Website](https://www.rust-lang.org/tools/install):

### On Linux & macOS:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### On Windows:
Download and run the installer from [rustup.rs](https://rustup.rs/) or [rust-lang.org](https://www.rust-lang.org/tools/install).

---

## Installation

From within the cloned/downloaded repository directory:

```bash
cargo install --path .
```

This will build the release binary and install `fritzdecode` into your Cargo bin path (`~/.cargo/bin`).

Alternatively, compile without installing:
```bash
cargo build --release
# The executable is located at ./target/release/fritzdecode
```

---

## Usage

### 1. Extract and Dump Credentials (`passwords`)
Extracts all ISP, VoIP, Wi-Fi, TR-069, and VPN credentials without having to search through thousands of configuration lines:

```bash
# Human-readable table
fritzdecode passwords backup.export

# JSON format
fritzdecode passwords backup.export --format json

# YAML format
fritzdecode passwords backup.export --format yaml -o credentials.yaml
```

*Note: If the file is already decrypted, use `--skip-decrypt`.*

---

### 2. Decrypt a Backup (`decrypt`)
Decrypts all secrets within the backup and outputs a decrypted `.export` file:

```bash
# Interactive prompt (securely entered without echoing on stderr):
fritzdecode decrypt backup.export -o decrypted.export

# Or supply password via CLI argument or environment variable:
fritzdecode decrypt backup.export -p "MySecretPassword" -o decrypted.export
# or:
FRITZ_PASSWORD="MySecretPassword" fritzdecode decrypt backup.export -o decrypted.export
```

---

### 3. Encrypt a Backup or Value (`encrypt`)
Re-encrypts cleartext sensitive values in a configuration file or encrypts a standalone string value:

```bash
# Encrypt an entire configuration backup:
fritzdecode encrypt decrypted.export -p "MySecretPassword" -o reencrypted.export

# Encrypt a single secret string:
fritzdecode encrypt --value "ClearTextPassword" -p "MySecretPassword"
```

---

### 4. Unpack and Re-pack Backups (`unpack` / `pack`)
Extracts individual configuration files (`ar7.cfg`, `wlan.cfg`, `voip.cfg`, etc.) and binary files (`fx_cg`, phonebook, certificates) to a folder, making manual edits simple:

```bash
# Unpack:
fritzdecode unpack backup.export -o ./extracted_config/ --decrypt -p "MySecretPassword"

# Edit any file inside ./extracted_config/, then re-pack:
fritzdecode pack ./extracted_config/ -o modified_backup.export
```
The `pack` command automatically recalculates the CRC32 checksum, making the file ready for import into the FRITZ!Box.

---

### 5. Convert to JSON / YAML (`convert`)
Converts AVM configuration sections into JSON or YAML:

```bash
# Convert specific section:
fritzdecode convert backup.export -s wlan.cfg --format json
fritzdecode convert backup.export -s ar7.cfg --format yaml

# Convert entire backup:
fritzdecode convert backup.export --format json -o full_backup.json
```

---

### 6. Compare Configuration Backups (`diff`)
Compares two `.export` files and outputs standard unified diffs for text configurations, highlighting changes between firmware versions or backup snapshots:

```bash
# Compare two exports:
fritzdecode diff backup1.export backup2.export

# Decrypt both files before comparing:
fritzdecode diff backup1.export backup2.export -p "MySecretPassword"

# Compare only a specific section (e.g. wlan.cfg):
fritzdecode diff backup1.export backup2.export -s wlan.cfg
```

---

### 7. Recover Forgotten Passwords (`crack`)
Performs a high-performance multi-threaded dictionary attack against the export's encrypted key:

```bash
# Wordlist attack:
fritzdecode crack backup.export -w /path/to/wordlist.txt

# Pipe candidates from stdin:
cat passwords.txt | fritzdecode crack backup.export -w -

# Specify thread count:
fritzdecode crack backup.export -w wordlist.txt --threads 8
```

---

### 8. Verify and Generate Checksums (`verify` / `gencrc`)

```bash
# Verify CRC32 checksum:
fritzdecode verify backup.export

# Print calculated CRC32 in hexadecimal:
fritzdecode gencrc backup.export
```

---

### 9. Shell Completions (`completions`)
Generates shell autocompletion scripts:

```bash
# Bash:
fritzdecode completions bash > ~/.local/share/bash-completion/completions/fritzdecode

# Zsh:
fritzdecode completions zsh > ~/.zfunc/_fritzdecode

# Fish:
fritzdecode completions fish > ~/.config/fish/completions/fritzdecode.fish

# Or source directly:
source <(fritzdecode completions bash)
```

---

## Authors & Attribution

- **Original Author**: [xiretza](https://gitlab.com/xiretza/fritzdecode)
- **Maintainer & Enhancements**: [sovking](https://github.com/sovking) <sovking@gmail.com>

This project is a fork and extension of the original `fritzdecode` utility created by xiretza. In compliance with the **GNU Affero General Public License v3.0 or later** ([AGPL-3.0-or-later](LICENSE)), all original notices, license terms, and derivative modifications remain fully open source under the same license terms.

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 or later** ([AGPL-3.0-or-later](LICENSE)).
