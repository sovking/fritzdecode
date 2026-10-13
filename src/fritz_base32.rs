//! Fritz!OS base32 encoding. Similar to [RFC4648], but uses digits 1 through 6
//! instead of 2 through 7.
//!
//! [RFC4648]: https://www.rfc-editor.org/rfc/rfc4648.html
///
/// # Example
///
/// ```rust
/// use fritzdecode::fritz_base32;
///
/// let decoded = fritz_base32::ENCODING.decode(b"KRSXG4BAMRQXIYJB");
/// assert_eq!(decoded.unwrap(), "Test data!".as_bytes());
///
/// let decoded = fritz_base32::ENCODING.decode(b"K4ZG62THEBWGK2THORUA====");
/// assert!(matches!(
///     decoded,
///     Err(data_encoding::DecodeError {
///         position: 20,
///         kind: data_encoding::DecodeKind::Symbol
///     })
/// ));
/// ```
use std::sync::LazyLock;

use data_encoding::{Encoding, Specification};

pub static ENCODING: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
    spec.encoding().expect("encoding is invalid")
});
