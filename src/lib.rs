//! Utilities for working with (encrypted) config backups from AVM FritzBox
//! devices. This library is mostly designed as a backing for the `fritzdecode`
//! binary, but might be useful on its own as well.
//!
//! The main type is [`ConfigBackup`], it allows reading, verifying, decrypting
//! and writing backup files.
//!
//! # Examples
//!
//! ```no_run
//! # use std::{fs::File, io::{BufReader, stdout}};
//! # use fritzdecode::ConfigBackup;
//! let file = BufReader::new(File::open("config.export").unwrap());
//!
//! // Load the config backup
//! let config = ConfigBackup::load(file).unwrap();
//!
//! // Decrypt any contained values using the password specified during export, update CRC
//! let config = config.decrypt("1234").unwrap().update_crc();
//!
//! // Write the decrypted backup to standard output
//! config.serialize(stdout()).unwrap();
//! ```

// lints
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use core::fmt;
use std::{
    fmt::Write as _,
    io::{self, BufRead},
    marker::PhantomData,
    str::FromStr,
};

use crc::{Digest, CRC_32_ISO_HDLC};
use crypto::{decode_secrets_in_text, decrypt_encryption_key, generate_boostrap_key};
use data_encoding::BASE64;

pub mod avm_cfg;
pub mod charset;
pub mod crack;
pub mod crypto;
pub mod diff;
pub mod errors;
pub mod fritz_base32;
pub mod pack;
pub mod passwords;

use errors::{Error, FormatError, SpecialLineError, EOF};

/// A file inside the config backup. It has a name and content; the content is
/// either text or (base64-encoded) binary data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub content: FileContent,
}

impl File {
    fn update_crc(&self, crc: &mut Digest<u32>) {
        crc.update(self.name.as_bytes());
        crc.update(b"\0");

        match &self.content {
            FileContent::Plain(s) => {
                // last line does not count toward CRC
                if let Some((text, _last_line)) = s.rsplit_once('\n') {
                    crc.update(text.as_bytes());
                }
            }
            FileContent::Binary(data) => crc.update(data),
        }
    }

    fn parse_file_entry(
        mut lines: impl Iterator<Item = Result<String, std::io::Error>>,
    ) -> Result<File, Error> {
        let line = lines
            .next()
            .ok_or(FormatError::ExpectedStartOfFileSection { got: EOF })??;

        let SpecialLine::StartOfFile { kind, name } = line.parse()? else {
            return Err(FormatError::ExpectedStartOfFileSection { got: line.into() }.into());
        };

        let mut content = match kind {
            ContentKind::Plain => FileContent::Plain(String::new()),
            ContentKind::Binary => FileContent::Binary(Vec::new()),
        };

        for line in lines {
            let line = line?;

            if let Ok(special) = line.parse() {
                let SpecialLine::EndOfFile = special else {
                    return Err(FormatError::ExpectedEndOfFileSection { got: special }.into());
                };
                break;
            }

            content.extend_with_line(&line)?;
        }

        Ok(File { name, content })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentKind {
    Plain,
    Binary,
}

impl From<&FileContent> for ContentKind {
    fn from(content: &FileContent) -> Self {
        match content {
            FileContent::Plain(_) => ContentKind::Plain,
            FileContent::Binary(_) => ContentKind::Binary,
        }
    }
}

/// The contents of a [`File`] entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileContent {
    Plain(String),
    Binary(Vec<u8>),
}

impl FileContent {
    /// Extends the file content using a line read from the config file
    /// (excluding newline).
    ///
    /// # Errors
    ///
    /// Returns an error if the line does not have a valid format for this
    /// content type.
    fn extend_with_line(&mut self, line: &str) -> Result<(), Error> {
        match self {
            FileContent::Plain(s) => {
                // backslashes are doubled up for some reason
                let line = line.replace(r"\\", r"\");
                writeln!(s, "{line}").unwrap();
            }
            FileContent::Binary(v) => {
                let data = BASE64
                    .decode(line.as_bytes())
                    .map_err(FormatError::InvalidBinaryData)?;

                v.extend_from_slice(&data);
            }
        }

        Ok(())
    }

    /// Decrypts the file's contents, if any of it is encrypted. Returns
    /// `Ok(None)` if no decryption was required.
    ///
    /// # Errors
    ///
    /// Returns an error if the decryption fails, e.g. due to wrong key or
    /// malformed secrets.
    pub fn decrypt(&self, encryption_key: [u8; 32]) -> Result<Option<Self>, Error> {
        match self {
            FileContent::Plain(s) => {
                Ok(decode_secrets_in_text(s, encryption_key)?.map(FileContent::Plain))
            }
            FileContent::Binary(_) => Ok(None),
        }
    }
}

/// A metadata line inside the backup. Used to separate file entries, as well as
/// for framing the entire backup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecialLine {
    StartOfExport { model: String },
    EndOfExport { crc: u32 },

    StartOfFile { name: String, kind: ContentKind },
    EndOfFile,
}

impl SpecialLine {
    fn parse_inner(line: &str) -> Result<Self, SpecialLineError> {
        if let Some(model) = line.strip_suffix(" CONFIGURATION EXPORT") {
            Ok(Self::StartOfExport {
                model: model.to_string(),
            })
        } else if let Some(name) = line.strip_prefix("CFGFILE:") {
            Ok(Self::StartOfFile {
                name: name.to_string(),
                kind: ContentKind::Plain,
            })
        } else if let Some(name) = line.strip_prefix("B64FILE:") {
            Ok(Self::StartOfFile {
                name: name.to_string(),
                kind: ContentKind::Binary,
            })
        } else if let Some(line) = line.strip_suffix(" ****") {
            if line == "END OF FILE" {
                Ok(Self::EndOfFile)
            } else if let Some(crc_str) = line.strip_prefix("END OF EXPORT ") {
                let crc: [u8; 4] = hex::decode(crc_str)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| SpecialLineError::MalformedCrc {
                        crc: crc_str.to_string(),
                    })?;
                let crc = u32::from_be_bytes(crc);

                Ok(Self::EndOfExport { crc })
            } else {
                Err(SpecialLineError::UnknownFormat)
            }
        } else {
            Err(SpecialLineError::UnknownFormat)
        }
    }

    #[must_use]
    pub fn check(line: &str) -> bool {
        line.starts_with("**** ")
    }
}

impl FromStr for SpecialLine {
    type Err = Error;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let line = line
            .strip_prefix("**** ")
            .ok_or(Error::FormatError(FormatError::ExpectedSpecialLine))?;

        Self::parse_inner(line).map_err(|kind| {
            FormatError::InvalidSpecialLine {
                line: line.to_string(),
                kind,
            }
            .into()
        })
    }
}

impl fmt::Display for SpecialLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "**** ")?;

        match self {
            SpecialLine::StartOfExport { model } => writeln!(f, "{model} CONFIGURATION EXPORT"),
            SpecialLine::EndOfExport { crc } => writeln!(f, "END OF EXPORT {crc:08X} ****"),
            SpecialLine::StartOfFile { name, kind } => match kind {
                ContentKind::Plain => writeln!(f, "CFGFILE:{name}"),
                ContentKind::Binary => writeln!(f, "B64FILE:{name}"),
            },
            SpecialLine::EndOfFile => writeln!(f, "END OF FILE ****"),
        }
    }
}

pub mod markers {
    mod private {
        pub trait Sealed {}
    }

    /// Marker trait for [`Verified`] and [`Unverified`].
    pub trait CrcState: private::Sealed {}

    /// Marker type to indicate a [`ConfigBackup`] whose CRC checksum has been
    /// verified to match.
    ///
    /// [`ConfigBackup`]: crate::ConfigBackup
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Verified;
    impl private::Sealed for Verified {}
    impl CrcState for Verified {}

    /// Marker type to indicate a [`ConfigBackup`] whose CRC checksum has not
    /// been verified.
    ///
    /// [`ConfigBackup`]: crate::ConfigBackup
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Unverified;
    impl private::Sealed for Unverified {}
    impl CrcState for Unverified {}
}

use markers::{CrcState, Unverified, Verified};

/// A parsed config backup. Created using [`ConfigBackup::load()`].
///
/// The backup consists of a header containing some key-value pairs, followed by
/// a set of [`File`]s. The header contains an encryption key that is used to
/// encrypt values inside the files; such encrypted values are signified by four
/// dollar signs `$$$$` followed by the base32-encoded secret, see [the `crypto`
/// module](`crypto`) for more details.
///
/// The type parameter `S` indicates whether or not the CRC checksum has been
/// verified to match the contents. [`ConfigBackup::load()`] initially returns
/// `Unverified` data, which can then either be verified using
/// [`ConfigBackup::verify_crc()`] or have its CRC adjusted to match the
/// contents using [`ConfigBackup::update_crc()`]. Both return `Verified` data,
/// which can then be written back out using [`ConfigBackup::serialize()`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigBackup<S: CrcState> {
    model: String,
    properties: Vec<(String, String)>,
    files: Vec<File>,
    crc: u32,

    state: PhantomData<S>,
}

impl ConfigBackup<Unverified> {
    /// Loads an exported configuration. It is neither decrypted, nor is the CRC
    /// checksum verified.
    ///
    /// # Errors
    #[must_use]
    pub fn from_parts(
        model: String,
        properties: Vec<(String, String)>,
        files: Vec<File>,
        crc: u32,
    ) -> Self {
        Self {
            model,
            properties,
            files,
            crc,
            state: PhantomData,
        }
    }

    /// Loads an exported configuration. It is neither decrypted, nor is the CRC
    /// checksum verified. Supports both UTF-8 and ISO-8859-1 encoded files.
    ///
    /// # Errors
    ///
    /// This function will return an error if the `input` can not be read or if
    /// its format is invalid.
    pub fn load<R: BufRead>(input: R) -> Result<Self, Error> {
        struct LosslessLines<R> {
            reader: R,
        }

        impl<R: BufRead> Iterator for LosslessLines<R> {
            type Item = io::Result<String>;

            fn next(&mut self) -> Option<Self::Item> {
                match charset::read_line_lossless(&mut self.reader) {
                    Ok(Some(s)) => Some(Ok(s)),
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                }
            }
        }

        let mut lines = LosslessLines { reader: input }.peekable();

        // Parse the header and properties (handling potential leaked 'Password: ' prompt from older tools)
        let header = loop {
            let line = lines
                .next()
                .ok_or(FormatError::ExpectedHeader { got: EOF })??;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("Password:") {
                let rest_trimmed = rest.trim_start();
                if rest_trimmed.starts_with("****") {
                    break rest_trimmed.to_string();
                }
            }
            break line;
        };

        let SpecialLine::StartOfExport { model } = header.parse()? else {
            return Err(FormatError::ExpectedHeader { got: header.into() }.into());
        };

        let mut properties = Vec::new();

        while !lines
            .peek()
            .is_some_and(|line| line.as_ref().is_ok_and(|s| SpecialLine::check(s)))
        {
            let line = lines
                .next()
                .ok_or(FormatError::ExpectedProperty { got: EOF })??;

            let Some((key, value)) = line.split_once('=') else {
                return Err(FormatError::ExpectedProperty { got: line.into() }.into());
            };

            properties.push((key.to_string(), value.to_string()));
        }

        // Parse the contained files
        let mut files = Vec::new();
        let encountered_crc = loop {
            if let Some(Ok(line)) = lines.peek() {
                if let SpecialLine::EndOfExport {
                    crc: encountered_crc,
                } = line.parse()?
                {
                    lines.next();

                    break encountered_crc;
                }
            }

            let file = File::parse_file_entry(&mut lines)?;

            files.push(file);
        };

        Ok(Self {
            model,
            properties,
            files,
            crc: encountered_crc,

            state: PhantomData,
        })
    }

    /// Checks that the CRC in the file matches the CRC of the data. If they
    /// match, a [`ConfigBackup<Verified>`] is returned, otherwise the
    /// unverified config is returned unchanged along with the calculcated
    /// CRC.
    #[allow(clippy::missing_errors_doc, clippy::result_large_err)]
    pub fn verify_crc(self) -> Result<ConfigBackup<Verified>, (Self, Error)> {
        let calculated_crc = self.calculate_crc();
        if calculated_crc == self.crc {
            Ok(ConfigBackup::<Verified> {
                model: self.model,
                properties: self.properties,
                files: self.files,
                crc: self.crc,
                state: PhantomData,
            })
        } else {
            let e = FormatError::InvalidCrc {
                expected: self.crc,
                calculated: calculated_crc,
            }
            .into();

            Err((self, e))
        }
    }

    /// Updates the internal CRC to match the content of the config and returns
    /// a [`ConfigBackup<Verified>`].
    #[must_use]
    pub fn update_crc(self) -> ConfigBackup<Verified> {
        let crc = self.calculate_crc();
        ConfigBackup::<Verified> {
            model: self.model,
            properties: self.properties,
            files: self.files,
            crc,
            state: PhantomData,
        }
    }
}

impl ConfigBackup<Verified> {
    /// Serializes the config backup to its textual representation.
    ///
    /// # Errors
    ///
    /// This function will return an error if the passed `Write` instance
    /// encounters an error.
    pub fn serialize<W: io::Write>(self, mut w: W) -> Result<(), io::Error> {
        debug_assert_eq!(self.crc, self.calculate_crc());

        write!(w, "{}", SpecialLine::StartOfExport { model: self.model })?;

        for (key, value) in self.properties {
            writeln!(w, "{key}={value}")?;
        }

        for file in self.files {
            write!(
                w,
                "{}",
                SpecialLine::StartOfFile {
                    name: file.name,
                    kind: ContentKind::from(&file.content),
                }
            )?;

            match file.content {
                FileContent::Plain(s) => write!(w, "{}", s.replace('\\', r"\\"))?,
                FileContent::Binary(data) => {
                    if data.is_empty() {
                        writeln!(w)?;
                    } else {
                        for chunk in data.chunks(80 * 6 / 8) {
                            writeln!(w, "{}", BASE64.encode(chunk))?;
                        }
                    }
                }
            }

            write!(w, "{}", SpecialLine::EndOfFile)?;
        }

        write!(w, "{}", SpecialLine::EndOfExport { crc: self.crc })?;

        Ok(())
    }
}

impl<S: CrcState> ConfigBackup<S> {
    #[must_use]
    fn calculate_crc(&self) -> u32 {
        let crc = crc::Crc::<u32>::new(&CRC_32_ISO_HDLC);
        let mut crc = crc.digest();

        for (key, value) in &self.properties {
            crc.update(key.as_bytes());
            crc.update(value.as_bytes());
            crc.update(b"\0");
        }

        for file in &self.files {
            file.update_crc(&mut crc);
        }

        crc.finalize()
    }

    #[must_use]
    pub fn files(&self) -> &[File] {
        self.files.as_ref()
    }

    #[must_use]
    pub fn properties(&self) -> &[(String, String)] {
        self.properties.as_ref()
    }

    #[must_use]
    pub fn model(&self) -> &str {
        self.model.as_ref()
    }

    #[must_use]
    pub fn crc(&self) -> u32 {
        self.crc
    }

    /// Returns the encrypted password string (e.g. `$$$$...`) from the header properties, if present.
    #[must_use]
    pub fn encrypted_password(&self) -> Option<&str> {
        self.properties
            .iter()
            .find_map(|(name, val)| (name == "Password").then_some(val.as_str()))
    }

    /// Decrypts any encrypted values in the config.
    ///
    /// # Errors
    ///
    /// Returns an error if the decryption fails, e.g. due to wrong key or
    /// malformed secrets.
    pub fn decrypt(mut self, password: &str) -> Result<ConfigBackup<Unverified>, Error> {
        let bootstrap_key = generate_boostrap_key(password);
        let encryption_key = self
            .properties
            .iter()
            .find_map(|(name, val)| (name == "Password").then_some(val))
            .ok_or(FormatError::MissingPasswordProperty)?;
        let encryption_key = decrypt_encryption_key(encryption_key, bootstrap_key)?;

        for file in &mut self.files {
            if let Some(content) = file.content.decrypt(encryption_key)? {
                file.content = content;
            }
        }

        Ok(ConfigBackup::<Unverified> {
            model: self.model,
            properties: self.properties,
            files: self.files,
            crc: self.crc,
            state: PhantomData,
        })
    }

    /// Encrypts sensitive plain-text values in the config and updates the Password header property.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt(mut self, password: &str) -> Result<ConfigBackup<Unverified>, Error> {
        let encryption_key = crypto::generate_random_encryption_key();
        let bootstrap_key = crypto::generate_boostrap_key(password);
        let encrypted_key_str = crypto::encrypt_encryption_key(encryption_key, bootstrap_key)?;

        let mut found_pass = false;
        for (name, val) in &mut self.properties {
            if name == "Password" {
                val.clone_from(&encrypted_key_str);
                found_pass = true;
                break;
            }
        }
        if !found_pass {
            self.properties
                .push(("Password".to_string(), encrypted_key_str));
        }

        for file in &mut self.files {
            if let FileContent::Plain(content) = &file.content {
                file.content =
                    FileContent::Plain(crypto::encode_secrets_in_text(content, encryption_key)?);
            }
        }

        Ok(ConfigBackup::<Unverified> {
            model: self.model,
            properties: self.properties,
            files: self.files,
            crc: self.crc,
            state: PhantomData,
        })
    }
}
