//! Utilities to handle encrypted values in config backup files.
//!
//! Every encrypted value is represented in the file using four dollar signs
//! `$$$$` followed by a [custom bas32 encoding](crate::fritz_base32) of a
//! random IV concatenated with the AES-encrypted data.
//!
//! The encryption key for values inside of file entries is stored in the config
//! backup's header; it is itself encrypted using a "bootstrap key" derived from
//! the password specified during export of the backup.
//! The bootstrap key can be obtained using [`generate_boostrap_key()`] and
//! subsequently used to decrypt the main encryption key using
//! [`decrypt_encryption_key()`].

use std::{array, sync::LazyLock};

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::{Digest, Md5};
use rand::random;
use regex::Regex;

use crate::{
    errors::{DecryptionError, EncryptionError, Error, FormatError},
    fritz_base32,
};

/// Generates the bootstrap encryption key (used to decrypt the real, random
/// encryption key).
///
/// If a password was set during export of the backup, the bootstrap key is
/// simply the MD5 sum of the password.
#[must_use]
pub fn generate_boostrap_key(password: &str) -> [u8; 32] {
    let hash = Md5::digest(password.as_bytes());

    array::from_fn(|i| hash.get(i).copied().unwrap_or(0))
}

/// Decrypts the random encryption key stored in the `Password=` property of the
/// config export, using the bootstrap key derived from the user password (see
/// [`generate_boostrap_key()`]).
///
/// # Errors
///
/// Returns an error if the  bootstrap key is incorrect, or if the decrypted
/// encryption key is malformed.
pub fn decrypt_encryption_key(
    encrypted_key: &str,
    bootstrap_key: [u8; 32],
) -> Result<[u8; 32], Error> {
    let key = decode_secret(encrypted_key, bootstrap_key, IsStringValue::No)?;
    let mut key: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| FormatError::InvalidEncryptionKeyLength { length: key.len() })?;
    key[16..].fill(0);

    Ok(key)
}

/// Generates a random 32-byte encryption key for encrypting secrets in backup files.
/// The first 16 bytes are randomly generated, and the last 16 bytes are set to 0, matching AVM convention.
#[must_use]
pub fn generate_random_encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let random_bytes: [u8; 16] = rand::random();
    key[..16].copy_from_slice(&random_bytes);
    key
}

/// Encrypts the random encryption key using the bootstrap key derived from the user password.
///
/// # Errors
/// Returns an error if encryption fails.
pub fn encrypt_encryption_key(
    encryption_key: [u8; 32],
    bootstrap_key: [u8; 32],
) -> Result<String, Error> {
    encode_secret(encryption_key.to_vec(), bootstrap_key, IsStringValue::No)
}

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

/// Whether or not the plaintext has an implicit trailing null byte. This
/// should be set to `Yes` for secrets inside files, and to `No` for the
/// decryption key.
#[derive(Clone, Copy, Debug)]
pub enum IsStringValue {
    No,
    Yes,
}

/// Decrypts a secret, encoded as fritz-base32 with a `$$$$` prefix, using a
/// key.
///
/// # Errors
///
/// Returns an error if the data is malformed or could not be decoded using the
/// specified key.
#[allow(clippy::missing_panics_doc)]
pub fn decode_secret(
    secret: &str,
    key: [u8; 32],
    is_string_value: IsStringValue,
) -> Result<Vec<u8>, Error> {
    let secret = secret
        .strip_prefix("$$$$")
        .ok_or(FormatError::InvalidSecretPrefix {
            secret: secret.to_string(),
        })?;

    let secret = fritz_base32::ENCODING.decode(secret.as_bytes())?;

    // remove excess bytes that may have been added through base32 encoding
    let extra_len = secret.len() % 16;
    if extra_len > 4 {
        return Err(DecryptionError::BadCiphertextLength { excess: extra_len }.into());
    }
    let (secret, _extra) = secret.split_at(secret.len() - extra_len);

    // secret consists of 16 bytes IV concatenated with the ciphertext
    let (iv, ciphertext) = secret
        .split_first_chunk::<16>()
        .ok_or(DecryptionError::BadCiphertextLength { excess: extra_len })?;

    // decrypt ciphertext
    let decrypted = Aes256CbcDec::new(&key.into(), iv.into())
        .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .expect("unpadding should not fail with NoPadding");

    // first 4 bytes of plaintext: hash of everything thereafter
    let (hash, decrypted) = decrypted
        .split_first_chunk::<4>()
        .ok_or(DecryptionError::BadCiphertextLength { excess: 0 })?;
    let calculated_hash: [u8; 16] = Md5::digest(decrypted).into();
    if *hash != calculated_hash[..4] {
        return Err(DecryptionError::HashMismatch {
            expected: *hash,
            found: calculated_hash,
        }
        .into());
    }

    // next 4 bytes of plaintext: length of data
    let (length, data) = decrypted
        .split_first_chunk::<4>()
        .ok_or(DecryptionError::BadCiphertextLength { excess: 0 })?;
    let length: usize = u32::from_be_bytes(*length)
        .try_into()
        .expect("u32 should fit in usize");

    let mut data = data
        .get(..length)
        .ok_or(DecryptionError::BadCiphertextLength { excess: 0 })?;
    if let IsStringValue::Yes = is_string_value {
        data = data
            .strip_suffix(b"\0")
            .ok_or(DecryptionError::MissingNullTerminator {
                data: data.to_vec(),
            })?;
    }

    Ok(data.to_vec())
}

pub(crate) fn decode_secrets_in_text(
    line: &str,
    encryption_key: [u8; 32],
) -> Result<Option<String>, Error> {
    static SECRET_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\${4}[A-Z1-6]+").unwrap());

    let mut it = SECRET_REGEX.captures_iter(line).peekable();
    if it.peek().is_none() {
        return Ok(None);
    }
    let mut new = String::with_capacity(line.len());
    let mut last_match = 0;
    for cap in it {
        // unwrap on 0 is OK because captures only reports matches
        let m = cap.get(0).unwrap();
        new.push_str(&line[last_match..m.start()]);

        let decoded = decode_secret(m.into(), encryption_key, IsStringValue::Yes)?;
        new.push_str(&crate::charset::decode_bytes(&decoded));

        last_match = m.end();
    }
    new.push_str(&line[last_match..]);

    Ok(Some(new))
}

/// Pre-parsed encrypted encryption key optimized for high-speed offline password auditing.
#[derive(Clone, Debug)]
pub struct PasswordTester {
    iv: [u8; 16],
    ciphertext: Vec<u8>,
}

impl PasswordTester {
    /// Pre-parses an encrypted key string (e.g. from `Password=$$$$...` header).
    ///
    /// # Errors
    /// Returns an error if the encrypted key format or base32 encoding is invalid.
    pub fn new(encrypted_key: &str) -> Result<Self, Error> {
        let secret =
            encrypted_key
                .strip_prefix("$$$$")
                .ok_or_else(|| FormatError::InvalidSecretPrefix {
                    secret: encrypted_key.to_string(),
                })?;

        let secret = fritz_base32::ENCODING.decode(secret.as_bytes())?;

        let extra_len = secret.len() % 16;
        if extra_len > 4 {
            return Err(DecryptionError::BadCiphertextLength { excess: extra_len }.into());
        }
        let (secret, _extra) = secret.split_at(secret.len() - extra_len);

        let (iv, ciphertext) = secret
            .split_first_chunk::<16>()
            .ok_or(DecryptionError::BadCiphertextLength { excess: extra_len })?;

        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(DecryptionError::BadCiphertextLength { excess: 0 }.into());
        }

        Ok(Self {
            iv: *iv,
            ciphertext: ciphertext.to_vec(),
        })
    }

    /// Fast test if candidate password decrypts the encryption key.
    /// Zero heap allocations during testing for standard key ciphertexts.
    #[must_use]
    pub fn test(&self, candidate: &str) -> bool {
        let bootstrap_key = generate_boostrap_key(candidate);
        let mut buf = [0u8; 128];
        if self.ciphertext.len() > buf.len() {
            return false;
        }
        buf[..self.ciphertext.len()].copy_from_slice(&self.ciphertext);
        let Ok(decrypted) = Aes256CbcDec::new(&bootstrap_key.into(), (&self.iv).into())
            .decrypt_padded_mut::<NoPadding>(&mut buf[..self.ciphertext.len()])
        else {
            return false;
        };

        let Some((hash, rest)) = decrypted.split_first_chunk::<4>() else {
            return false;
        };
        let calculated_hash: [u8; 16] = Md5::digest(rest).into();
        if *hash != calculated_hash[..4] {
            return false;
        }

        let Some((length_bytes, data)) = rest.split_first_chunk::<4>() else {
            return false;
        };
        let length = u32::from_be_bytes(*length_bytes) as usize;
        length == 32 && data.len() >= 32
    }
}

/// Tests whether a candidate password correctly decrypts the encrypted encryption key.
///
/// Returns `true` if the candidate password successfully decrypts the key with a matching checksum.
#[must_use]
pub fn test_password(encrypted_key: &str, candidate: &str) -> bool {
    PasswordTester::new(encrypted_key).is_ok_and(|tester| tester.test(candidate))
}

/// Encrypts known sensitive plain-text values in a configuration file text, replacing them with `$$$$...`.
/// Values that are empty or already encrypted are left untouched.
///
/// # Errors
/// Returns an error if encryption fails.
#[allow(clippy::missing_panics_doc)]
pub fn encode_secrets_in_text(text: &str, encryption_key: [u8; 32]) -> Result<String, Error> {
    static SENSITIVE_KV_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?im)^(\s*(?:passwd|password|pskvalue|pskvalue_scnd|pskvalue_thrd|guest_pskvalue|ConnectionRequestPassword|presharedkey|authname_passwd|key)\s*=\s*)"([^"]*)""#).unwrap()
    });

    let mut result = String::with_capacity(text.len());
    let mut last_idx = 0;

    for cap in SENSITIVE_KV_REGEX.captures_iter(text) {
        let full_match = cap.get(0).unwrap();
        let prefix = cap.get(1).unwrap().as_str();
        let val = cap.get(2).unwrap().as_str();

        result.push_str(&text[last_idx..full_match.start()]);

        if val.is_empty() || val.starts_with("$$$$") {
            result.push_str(full_match.as_str());
        } else {
            let enc = encode_secret(val.as_bytes().to_vec(), encryption_key, IsStringValue::Yes)?;
            result.push_str(prefix);
            result.push('"');
            result.push_str(&enc);
            result.push('"');
        }

        last_idx = full_match.end();
    }
    result.push_str(&text[last_idx..]);

    Ok(result)
}

/// Encrypts a secret using the key, outputting it as a fritz-base32-encoded
/// value prefixed with `$$$$`.
///
/// # Errors
///
/// Returns an error if the length of the supplied data is too large to be
/// represented using a 32-bit integer.
pub fn encode_secret(
    mut data: Vec<u8>,
    key: [u8; 32],
    is_string_value: IsStringValue,
) -> Result<String, Error> {
    if let IsStringValue::Yes = is_string_value {
        data.push(b'\0');
    }

    let length = data.len();
    let length = u32::try_from(length)
        .map_err(|_| EncryptionError::DataTooLarge { length })?
        .to_be_bytes();

    let total_len = data.len() + 4 + 4;
    let pad_len = 16 - total_len % 16;
    data.resize(data.len() + pad_len, 0);

    let mut hash = Md5::new();
    hash.update(length);
    hash.update(&data);
    let hash: [u8; 16] = hash.finalize().into();

    let iv: [u8; 16] = random();
    let plaintext = [&hash[..4], &length, &data].concat();
    let encrypted =
        Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<NoPadding>(&plaintext);

    let mut result = "$$$$".to_string();
    fritz_base32::ENCODING
        .encode_append(&[iv.as_slice(), encrypted.as_slice()].concat(), &mut result);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_known() {
        let cases: &[(&[u8], &str, &str)] = &[
            (b"test", "$$$$5AEWFTDNEIXGOGVTKJYBXJ2JK1B1LDDUXDLOAQPSQTPGI6LCQRLP1E5DEPNJIF45F4ADNFTXZF31541T", "7695206a0422786fc612643ed2f337d900000000000000000000000000000000"),
            (b"testus", "$$$$4ZNKDABPVOF32CDHBPIGXRGUOPWFS3KYOUXXZK61GQ6TT1E4JYYUDOE6YMLBML6ZOJSO53NGG3HOS4ZY", "3cfb14830234eb5abf8de7570d47d79600000000000000000000000000000000"),
            (b"testuse", "$$$$UEUST1NGXTC1Y52R2CSML4TNJPT2HV54MGFUXRCYHH3ROBT3OMBLV66ZQ2XOGZURJTRTP3123QQB34Y5", "4b50c9683664a466c117d89986ef5c9300000000000000000000000000000000"),
            (b"testuser",             "$$$$XLSJ6KVR2KNNBUVJHBA1NPMDEZCHZI4GAMY3BMNUJ5CN4PAGLKWD5K5M5GJYBXKBF1BJE5JX5GEFA4W5", "19d1c0f994c4a7157a99363d8d60097500000000000000000000000000000000"),
        ];

        for &(plain, secret, key) in cases {
            let key = hex::decode(key).unwrap().try_into().unwrap();
            assert_eq!(
                decode_secret(secret, key, IsStringValue::Yes,).unwrap(),
                plain
            );
        }
    }

    #[test]
    fn encrypt() {
        let key = random();

        let encrypted = encode_secret(b"testuse".to_vec(), key, IsStringValue::Yes).unwrap();

        assert_eq!(
            decode_secret(&encrypted, key, IsStringValue::Yes,).unwrap(),
            b"testuse"
        );
    }

    #[test]
    fn test_password_candidate_check() {
        let random_key = generate_random_encryption_key();
        let correct_pwd = "SuperSecretPassword123!";
        let wrong_pwd = "WrongPassword!";

        let bootstrap_key = generate_boostrap_key(correct_pwd);
        let encrypted_key = encrypt_encryption_key(random_key, bootstrap_key).unwrap();

        assert!(test_password(&encrypted_key, correct_pwd));
        assert!(!test_password(&encrypted_key, wrong_pwd));
    }

    #[test]
    fn test_password_tester_wordlist() {
        let random_key = generate_random_encryption_key();
        let correct_pwd = "fritzbox_secret";
        let bootstrap_key = generate_boostrap_key(correct_pwd);
        let encrypted_key = encrypt_encryption_key(random_key, bootstrap_key).unwrap();

        let tester = PasswordTester::new(&encrypted_key).unwrap();
        let candidates = ["admin", "123456", "password", "fritzbox_secret", "root"];

        let found = candidates.into_iter().find(|&c| tester.test(c));
        assert_eq!(found, Some("fritzbox_secret"));
    }
}
