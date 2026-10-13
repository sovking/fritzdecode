use std::{
    fs::{File, OpenOptions},
    io::{stderr, stdin, stdout, BufReader, Write},
    path::Path,
};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use fritzdecode::{
    avm_cfg::{parse_avm_cfg, to_json_string, to_yaml_string},
    crack::crack_wordlist,
    crypto::PasswordTester,
    diff::diff_backups,
    markers::Unverified,
    pack::{pack_backup, unpack_backup},
    passwords::ExtractedCredentials,
    ConfigBackup, FileContent,
};
use serde_json::{Map, Value};

#[derive(Parser)]
#[command(
    name = "fritzdecode",
    version,
    about = "Tools for working with AVM FritzBox config file exports"
)]
struct Args {
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum PasswordsFormat {
    Text,
    Json,
    Yaml,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum DataFormat {
    Json,
    Yaml,
}

#[derive(Subcommand)]
enum Operation {
    /// Decrypts data in a given config file.
    Decrypt {
        file: String,
        /// Ignore an invalid CRC32 checksum in the input
        #[arg(long)]
        ignore_invalid_crc: bool,
        /// Password to decrypt secrets. If omitted, prompts interactively on stderr or checks FRITZ_PASSWORD env var.
        #[arg(short, long)]
        password: Option<String>,
        /// File to write the decrypted config to. Uses standard output if not specified.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Encrypts plain-text secrets in a given config file or encrypts a standalone string.
    Encrypt {
        /// Config file to encrypt.
        #[arg(conflicts_with = "value")]
        file: Option<String>,
        /// Encrypt a single standalone string value instead of an entire file.
        #[arg(short, long, conflicts_with = "file")]
        value: Option<String>,
        /// Password to derive the encryption key. If omitted, prompts interactively on stderr or checks FRITZ_PASSWORD.
        #[arg(short, long)]
        password: Option<String>,
        /// File to write the encrypted config to. Uses standard output if not specified.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Verifies the integrity (CRC32) of the given config file.
    Verify { file: Option<String> },
    /// Generates the correct CRC32 checksum for a given config file.
    #[command(name = "gencrc")]
    GenCrc { file: Option<String> },
    /// Extracts and dumps all credentials (Internet/PPPoE, VoIP, Wi-Fi, Users, TR-069, VPN).
    #[command(name = "passwords", alias = "dump-passwords")]
    Passwords {
        file: String,
        /// Password to decrypt secrets. If omitted, prompts interactively on stderr or checks FRITZ_PASSWORD env var.
        #[arg(short, long)]
        password: Option<String>,
        /// Output format (text, json, yaml).
        #[arg(short, long, default_value = "text")]
        format: PasswordsFormat,
        /// Skip decryption step (useful if file is already decrypted or only plain secrets are needed).
        #[arg(long)]
        skip_decrypt: bool,
        /// File to write the extracted credentials to. Uses standard output if not specified.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Unpacks all configuration and binary files from a backup export into a directory.
    Unpack {
        file: String,
        /// Target directory to extract files into. Defaults to `<file>_unpacked`.
        #[arg(short, long)]
        output: Option<String>,
        /// Decrypt secrets before extracting files.
        #[arg(short, long)]
        decrypt: bool,
        /// Password to decrypt secrets if --decrypt is specified.
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Re-packs an unpacked directory (with manifest.json) back into a valid .export file with updated CRC32.
    Pack {
        /// Directory containing the unpacked files and manifest.json.
        dir: String,
        /// File to write the packed backup to. Uses standard output if not specified.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Converts AVM .cfg files inside the export to standard JSON or YAML.
    #[command(name = "convert", alias = "to-json", alias = "to-yaml")]
    Convert {
        file: String,
        /// Specific file section to convert (e.g. `ar7.cfg`, `wlan.cfg`). If omitted, converts all configuration files.
        #[arg(short, long)]
        section: Option<String>,
        /// Output format (json, yaml).
        #[arg(short, long, default_value = "json")]
        format: DataFormat,
        /// Decrypt secrets before conversion.
        #[arg(short, long)]
        decrypt: bool,
        /// Password to decrypt secrets if --decrypt is specified.
        #[arg(short, long)]
        password: Option<String>,
        /// File to write the converted data to. Uses standard output if not specified.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Compares two configuration backups and displays differences.
    Diff {
        /// First backup file to compare.
        file1: String,
        /// Second backup file to compare.
        file2: String,
        /// Specific configuration section to compare (e.g. `ar7.cfg`, `wlan.cfg`). If omitted, compares all sections.
        #[arg(short, long)]
        section: Option<String>,
        /// Decrypt secrets before comparing.
        #[arg(short, long)]
        decrypt: bool,
        /// Password to decrypt backups. Used for both files unless --password2 is specified.
        #[arg(short, long)]
        password: Option<String>,
        /// Password to decrypt the second backup file if different from the first.
        #[arg(long)]
        password2: Option<String>,
        /// File to write the diff output to. Uses standard output if not specified.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Recovers forgotten export passwords using an offline dictionary/wordlist attack.
    Crack {
        /// Config backup file to crack.
        file: String,
        /// Path to dictionary / wordlist file (or '-' for stdin).
        #[arg(short, long)]
        wordlist: String,
        /// Number of worker threads (defaults to number of CPU cores).
        #[arg(short, long)]
        threads: Option<usize>,
    },
    /// Generates shell completion scripts for Bash, Zsh, Fish, PowerShell, or Elvish.
    Completions {
        /// Shell to generate completions for.
        shell: Shell,
    },
}

fn load_file(file: Option<&str>) -> color_eyre::Result<ConfigBackup<Unverified>> {
    match file {
        None | Some("-") => {
            let config = ConfigBackup::load(BufReader::new(stdin()))?;
            Ok(config)
        }
        Some(file) => {
            let config = ConfigBackup::load(BufReader::new(File::open(file)?))?;
            Ok(config)
        }
    }
}

/// Retrieves the password safely:
/// 1. From CLI flag (--password).
/// 2. From FRITZ_PASSWORD environment variable.
/// 3. Prompts securely on stderr without echoing characters to terminal.
fn get_password(cli_pwd: Option<&str>) -> color_eyre::Result<String> {
    if let Some(p) = cli_pwd {
        return Ok(p.to_string());
    }
    if let Ok(p) = std::env::var("FRITZ_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }

    eprint!("Password: ");
    stderr().flush()?;
    let password = rpassword::read_password()?;
    Ok(password)
}

fn write_output(content: &[u8], output: Option<&str>) -> color_eyre::Result<()> {
    if let Some(path) = output {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(content)?;
    } else {
        stdout().write_all(content)?;
    }
    Ok(())
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    match args.operation {
        Operation::Decrypt {
            file,
            ignore_invalid_crc,
            password,
            output,
        } => {
            let config = load_file(Some(&file))?;
            let password = get_password(password.as_deref())?;

            let decrypted = match config.verify_crc() {
                Ok(c) => c.decrypt(&password)?,
                Err((unverified, _e)) if ignore_invalid_crc => unverified.decrypt(&password)?,
                Err((_unverified, e)) => return Err(e.into()),
            };

            let decrypted = decrypted.update_crc();
            if let Some(output) = output {
                decrypted.serialize(
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(output)?,
                )?;
            } else {
                decrypted.serialize(stdout())?;
            }
        }
        Operation::Encrypt {
            file,
            value,
            password,
            output,
        } => {
            let password = get_password(password.as_deref())?;

            if let Some(val) = value {
                let bootstrap_key = fritzdecode::crypto::generate_boostrap_key(&password);
                let encrypted = fritzdecode::crypto::encode_secret(
                    val.as_bytes().to_vec(),
                    bootstrap_key,
                    fritzdecode::crypto::IsStringValue::Yes,
                )?;
                write_output(format!("{encrypted}\n").as_bytes(), output.as_deref())?;
            } else if let Some(file_path) = file {
                let config = load_file(Some(&file_path))?;
                let encrypted = config.encrypt(&password)?.update_crc();
                if let Some(out_path) = output {
                    encrypted.serialize(
                        OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .open(out_path)?,
                    )?;
                } else {
                    encrypted.serialize(stdout())?;
                }
            } else {
                return Err(color_eyre::eyre::eyre!(
                    "Either a file or --value must be provided to encrypt"
                ));
            }
        }
        Operation::Verify { file } => {
            let config = load_file(file.as_deref())?;
            config.verify_crc().map_err(|(_unverified, e)| e)?;
            eprintln!("CRC32 is valid.");
        }
        Operation::GenCrc { file } => {
            let config = load_file(file.as_deref())?.update_crc();
            println!("{:08X}", config.crc());
        }
        Operation::Passwords {
            file,
            password,
            format,
            skip_decrypt,
            output,
        } => {
            let config = load_file(Some(&file))?;
            let has_encrypted_password = config
                .properties()
                .iter()
                .any(|(k, v)| k == "Password" && v.starts_with("$$$$"));

            let config = if !skip_decrypt && has_encrypted_password {
                let password = get_password(password.as_deref())?;
                config.update_crc().decrypt(&password)?
            } else {
                config
            };

            let creds = ExtractedCredentials::extract(&config);

            let out_str = match format {
                PasswordsFormat::Text => creds.format_text(),
                PasswordsFormat::Json => serde_json::to_string_pretty(&creds)?,
                PasswordsFormat::Yaml => serde_yaml::to_string(&creds)?,
            };

            write_output(out_str.as_bytes(), output.as_deref())?;
        }
        Operation::Unpack {
            file,
            output,
            decrypt,
            password,
        } => {
            let config = load_file(Some(&file))?;
            let target_dir = output.unwrap_or_else(|| {
                let p = Path::new(&file);
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("export");
                format!("{stem}_unpacked")
            });

            if decrypt {
                let password = get_password(password.as_deref())?;
                let decrypted = config.update_crc().decrypt(&password)?;
                unpack_backup(&decrypted, &target_dir)?;
            } else {
                unpack_backup(&config, &target_dir)?;
            }

            eprintln!("Successfully unpacked backup to '{target_dir}'.");
        }
        Operation::Pack { dir, output } => {
            let packed = pack_backup(&dir)?;
            if let Some(out_path) = output {
                packed.serialize(
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&out_path)?,
                )?;
                eprintln!("Successfully created backup archive '{out_path}'.");
            } else {
                packed.serialize(stdout())?;
            }
        }
        Operation::Convert {
            file,
            section,
            format,
            decrypt,
            password,
            output,
        } => {
            let config = load_file(Some(&file))?;
            let config = if decrypt {
                let password = get_password(password.as_deref())?;
                config.update_crc().decrypt(&password)?
            } else {
                config
            };

            let value = if let Some(sec_name) = section {
                let found = config
                    .files()
                    .iter()
                    .find(|f| f.name.eq_ignore_ascii_case(&sec_name));
                match found {
                    Some(f) => match &f.content {
                        FileContent::Plain(text) => parse_avm_cfg(text),
                        FileContent::Binary(_) => {
                            Value::String("[Binary data - cannot convert to JSON/YAML]".to_string())
                        }
                    },
                    None => {
                        return Err(color_eyre::eyre::eyre!(
                            "Section '{sec_name}' not found in backup files"
                        ));
                    }
                }
            } else {
                let mut root = Map::new();
                root.insert(
                    "model".to_string(),
                    Value::String(config.model().to_string()),
                );

                let mut props = Map::new();
                for (k, v) in config.properties() {
                    props.insert(k.clone(), Value::String(v.clone()));
                }
                root.insert("properties".to_string(), Value::Object(props));

                let mut files_map = Map::new();
                for f in config.files() {
                    match &f.content {
                        FileContent::Plain(text) => {
                            files_map.insert(f.name.clone(), parse_avm_cfg(text));
                        }
                        FileContent::Binary(bytes) => {
                            let mut bin_info = Map::new();
                            bin_info
                                .insert("_type".to_string(), Value::String("binary".to_string()));
                            bin_info.insert(
                                "_size".to_string(),
                                Value::Number(serde_json::Number::from(bytes.len())),
                            );
                            files_map.insert(f.name.clone(), Value::Object(bin_info));
                        }
                    }
                }
                root.insert("files".to_string(), Value::Object(files_map));

                Value::Object(root)
            };

            let out_str = match format {
                DataFormat::Json => to_json_string(&value)?,
                DataFormat::Yaml => to_yaml_string(&value)?,
            };

            write_output(out_str.as_bytes(), output.as_deref())?;
        }
        Operation::Diff {
            file1,
            file2,
            section,
            decrypt,
            password,
            password2,
            output,
        } => {
            let config1 = load_file(Some(&file1))?;
            let config2 = load_file(Some(&file2))?;

            let config1 = if decrypt || password.is_some() {
                let p1 = get_password(password.as_deref())?;
                config1.update_crc().decrypt(&p1)?
            } else {
                config1
            };

            let config2 = if decrypt || password.is_some() || password2.is_some() {
                let p2 = if let Some(p) = password2 {
                    p
                } else if let Some(p) = password {
                    p
                } else {
                    get_password(None)?
                };
                config2.update_crc().decrypt(&p2)?
            } else {
                config2
            };

            let diff_text = diff_backups(&config1, &config2, section.as_deref());
            write_output(diff_text.as_bytes(), output.as_deref())?;
        }
        Operation::Crack {
            file,
            wordlist,
            threads,
        } => {
            let config = load_file(Some(&file))?;
            let encrypted_key = config.encrypted_password().ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "Backup file does not contain an encrypted 'Password' header property"
                )
            })?;

            if !encrypted_key.starts_with("$$$$") {
                eprintln!("Backup is not password-protected or already decrypted.");
                return Ok(());
            }

            let tester = PasswordTester::new(encrypted_key)?;

            eprintln!("Starting offline dictionary attack on '{file}'...");

            let stats = if wordlist == "-" {
                crack_wordlist(
                    &tester,
                    BufReader::new(stdin()),
                    threads,
                    Some(&mut |tested, elapsed| {
                        let secs = elapsed.as_secs_f64();
                        let rate = if secs > 0.0 {
                            #[allow(clippy::cast_precision_loss)]
                            let rate = (tested as f64) / secs / 1000.0;
                            rate
                        } else {
                            0.0
                        };
                        eprint!("\rTested {tested} passwords ({rate:.1} kP/s)...");
                        let _ = stderr().flush();
                    }),
                )
            } else {
                let wordlist_file = File::open(&wordlist).map_err(|e| {
                    color_eyre::eyre::eyre!("Failed to open wordlist '{wordlist}': {e}")
                })?;
                crack_wordlist(
                    &tester,
                    BufReader::new(wordlist_file),
                    threads,
                    Some(&mut |tested, elapsed| {
                        let secs = elapsed.as_secs_f64();
                        let rate = if secs > 0.0 {
                            #[allow(clippy::cast_precision_loss)]
                            let rate = (tested as f64) / secs / 1000.0;
                            rate
                        } else {
                            0.0
                        };
                        eprint!("\rTested {tested} passwords ({rate:.1} kP/s)...");
                        let _ = stderr().flush();
                    }),
                )
            };

            eprint!("\r\x1b[K");
            let _ = stderr().flush();

            if let Some(pwd) = stats.found {
                println!("{pwd}");
                eprintln!(
                    "Password recovered: '{pwd}' (tested {} candidates in {:.2?})",
                    stats.candidates_tested, stats.elapsed
                );
            } else {
                eprintln!(
                    "Password not found in wordlist (tested {} candidates in {:.2?})",
                    stats.candidates_tested, stats.elapsed
                );
                return Err(color_eyre::eyre::eyre!("Password not found in wordlist"));
            }
        }
        Operation::Completions { shell } => {
            let mut cmd = Args::command();
            let bin_name = cmd.get_name().to_string();
            generate(shell, &mut cmd, bin_name, &mut stdout());
        }
    }

    Ok(())
}
