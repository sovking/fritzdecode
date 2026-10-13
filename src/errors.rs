use std::fmt;

use thiserror::Error;

use crate::SpecialLine;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StringOrEof {
    String(String),
    Eof,
}

pub(crate) const EOF: StringOrEof = StringOrEof::Eof;

impl fmt::Display for StringOrEof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringOrEof::String(s) => write!(f, "{s:?}"),
            StringOrEof::Eof => write!(f, "end of file"),
        }
    }
}

impl From<String> for StringOrEof {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    #[error("Expected header line, got {got:?}")]
    ExpectedHeader { got: StringOrEof },
    #[error("Expected \"end of export\" line, got {got:?}")]
    ExpectedEndOfExport { got: StringOrEof },
    #[error("Expected property, got {got:?}")]
    ExpectedProperty { got: StringOrEof },
    #[error("Invalid special line")]
    InvalidSpecialLine {
        line: String,
        kind: SpecialLineError,
    },
    #[error("Expected special line")]
    ExpectedSpecialLine,
    #[error("Expected end of input")]
    ExpectedEndOfInput,
    #[error("Invalid secret prefix, expected `$$$$`: {secret}")]
    InvalidSecretPrefix { secret: String },
    #[error("Missing `Password` property")]
    MissingPasswordProperty,
    #[error("Invalid length of encryption key: expected 32 bytes, got {length}")]
    InvalidEncryptionKeyLength { length: usize },
    #[error("Invalid CRC: expected `{expected:08X}`, calculated `{calculated:08X}`")]
    InvalidCrc { expected: u32, calculated: u32 },
    #[error("Expected start of file, got {got:?}")]
    ExpectedStartOfFileSection { got: StringOrEof },
    #[error("Expected end of file section, got {got:?}")]
    ExpectedEndOfFileSection { got: SpecialLine },
    #[error("Invalid binary data")]
    InvalidBinaryData(data_encoding::DecodeError),
    #[error("Decrypted secret is not valid UTF-8")]
    SecretNotUtf8(#[source] std::str::Utf8Error),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecialLineError {
    #[error("Not a special line (must start with `**** `)")]
    NotASpecialLine,
    #[error("Malformed CRC: {crc:?}")]
    MalformedCrc { crc: String },
    #[error("Unknown format")]
    UnknownFormat,
}

#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum DecryptionError {
    #[error(
        "Bad ciphertext length: expected up to 4 excess bytes from base32 decoding, got {excess}"
    )]
    BadCiphertextLength { excess: usize },
    #[error(
        "Hash mismatch: should be `{expected}...`, got `{found}`",
        expected = hex::encode(.expected),
        found = hex::encode(.found),
    )]
    HashMismatch { expected: [u8; 4], found: [u8; 16] },
    #[error(
        "Missing null terminator in decrypted string value: {} ({})",
        hex::encode(data),
        String::from_utf8_lossy(data)
    )]
    MissingNullTerminator { data: Vec<u8> },
}

#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum EncryptionError {
    #[error("Data too large: {length}")]
    DataTooLarge { length: usize },
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Encoding error")]
    EncodingError(#[from] data_encoding::DecodeError),
    #[error("Format error")]
    FormatError(#[from] FormatError),
    #[error("Decryption error")]
    Decryption(#[from] DecryptionError),
    #[error("Encryption error")]
    Encryption(#[from] EncryptionError),
    #[error("IO error")]
    Io(#[from] std::io::Error),
}
