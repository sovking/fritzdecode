//! Charset utilities to seamlessly handle both UTF-8 and ISO-8859-1 / Windows-1252 encodings
//! commonly found in FRITZ!OS backups.

use std::io::BufRead;

/// Decodes bytes to a `String`.
/// If the byte sequence is valid UTF-8, it will be decoded as UTF-8.
/// Otherwise, it falls back to Windows-1252 (which is a backward-compatible superset of ISO-8859-1/Latin1).
#[must_use]
pub fn decode_bytes(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        s.to_string()
    } else {
        let (cow, _malformed, _has_replacements) = encoding_rs::WINDOWS_1252.decode(bytes);
        cow.into_owned()
    }
}

/// Reads a line from a `BufRead` source, safely decoding bytes using UTF-8 or Windows-1252/ISO-8859-1.
/// Returns `Ok(None)` on EOF.
///
/// # Errors
///
/// Returns an `io::Error` if the underlying read fails.
pub fn read_line_lossless<R: BufRead>(reader: &mut R) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let num_bytes = reader.read_until(b'\n', &mut buf)?;
    if num_bytes == 0 {
        return Ok(None);
    }
    while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(Some(decode_bytes(&buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_decoding() {
        let text = "Città di Pisa";
        assert_eq!(decode_bytes(text.as_bytes()), text);
    }

    #[test]
    fn test_iso_8859_1_fallback() {
        // "Città" in ISO-8859-1: 'à' is byte 0xE0 (not valid standalone UTF-8)
        let latin1_bytes = [b'C', b'i', b't', b't', 0xE0];
        assert_eq!(decode_bytes(&latin1_bytes), "Città");
    }
}
