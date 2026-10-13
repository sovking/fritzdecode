//! Unpack and pack functionality for FRITZ!Box configuration export files.
//! Allows extracting all files into a directory and rebuilding the `.export` archive.

use std::{
    fs::{self, File as StdFile},
    io::{self, BufReader, Read, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{
    charset,
    markers::{CrcState, Verified},
    ConfigBackup, File, FileContent,
};

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub model: String,
    pub properties: Vec<(String, String)>,
    pub files: Vec<ManifestFile>,
}

#[derive(Serialize, Deserialize)]
pub struct ManifestFile {
    pub name: String,
    pub is_binary: bool,
}

/// Unpacks a `ConfigBackup` into a target directory.
/// Text files are extracted as plain text, binary files are extracted as raw bytes.
/// A `manifest.json` file is generated containing header metadata and file listings.
///
/// # Errors
/// Returns an error if filesystem operations fail.
pub fn unpack_backup<S: CrcState, P: AsRef<Path>>(
    config: &ConfigBackup<S>,
    out_dir: P,
) -> io::Result<()> {
    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)?;

    let mut manifest_files = Vec::new();

    for file in config.files() {
        let dest_path = out_dir.join(&file.name);
        match &file.content {
            FileContent::Plain(text) => {
                let mut f = StdFile::create(&dest_path)?;
                f.write_all(text.as_bytes())?;
                manifest_files.push(ManifestFile {
                    name: file.name.clone(),
                    is_binary: false,
                });
            }
            FileContent::Binary(bytes) => {
                let mut f = StdFile::create(&dest_path)?;
                f.write_all(bytes)?;
                manifest_files.push(ManifestFile {
                    name: file.name.clone(),
                    is_binary: true,
                });
            }
        }
    }

    let manifest = Manifest {
        model: config.model().to_string(),
        properties: config.properties().to_vec(),
        files: manifest_files,
    };

    let manifest_path = out_dir.join("manifest.json");
    let manifest_file = StdFile::create(manifest_path)?;
    serde_json::to_writer_pretty(manifest_file, &manifest)?;

    Ok(())
}

/// Packs a previously unpacked directory containing `manifest.json` back into a `ConfigBackup<Verified>`.
/// Automatically computes the updated CRC32 checksum.
///
/// # Errors
/// Returns an error if `manifest.json` is missing or files cannot be read.
pub fn pack_backup<P: AsRef<Path>>(in_dir: P) -> io::Result<ConfigBackup<Verified>> {
    let in_dir = in_dir.as_ref();
    let manifest_path = in_dir.join("manifest.json");
    let manifest_file = StdFile::open(manifest_path)?;
    let manifest: Manifest = serde_json::from_reader(BufReader::new(manifest_file))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut files = Vec::new();

    for entry in manifest.files {
        let file_path = in_dir.join(&entry.name);
        let content = if entry.is_binary {
            let mut f = StdFile::open(file_path)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            FileContent::Binary(buf)
        } else {
            let mut f = StdFile::open(file_path)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            FileContent::Plain(charset::decode_bytes(&buf))
        };

        files.push(File {
            name: entry.name,
            content,
        });
    }

    let unverified = ConfigBackup::from_parts(manifest.model, manifest.properties, files, 0);
    Ok(unverified.update_crc())
}
