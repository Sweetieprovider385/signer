//! Library to encrypt and decrypt BLS12-381 Keystores.
//! The keystore is in JSON format as defined by [EIP-2335][1].
//!
//![1]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md

mod keystore;
mod password_util;

#[cfg(test)]
mod tests;

use crate::{password_util::normalize_password, password_util::validate_decryption_key};
use anyhow::{bail, Result};

/// Decrypt BLS12-381 keystore with provided password. Returns decrypted key
/// as Vec<u8>
pub fn decrypt(keystore_json: &str, password: &str) -> Result<Vec<u8>> {
    let normalized_password = normalize_password(password);
    let keystore = keystore::parse_keystore(keystore_json)?;
    let decryption_key = keystore
        .crypto
        .kdf
        .decryption_key(normalized_password.as_str())?;

    if !validate_decryption_key(
        &decryption_key,
        &keystore.crypto.cipher.message,
        &keystore.crypto.checksum.message,
    ) {
        bail!("Password verification failed");
    }

    keystore.crypto.cipher.decrypt_secret(&decryption_key)
}
