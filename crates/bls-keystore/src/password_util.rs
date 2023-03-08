//! password utility methods to normalize and validate passwords as described in
//! https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub fn normalize_password(password: &str) -> String {
    password
        .nfkd()
        .collect::<String>()
        .chars()
        .filter(|c| !is_control(c))
        .collect::<String>()
}

pub fn validate_decryption_key(
    decryption_key: &[u8],
    cipher_message: &[u8],
    checksum_message: &[u8],
) -> bool {
    let dk_slice = &decryption_key[16..32];
    let pre_image = [dk_slice, cipher_message].concat();
    let mut hasher = Sha256::new();
    hasher.update(pre_image);
    let checksum = hasher.finalize();

    checksum.eq(checksum_message.into())
}

fn is_c0(c: &char) -> bool {
    *c >= '\u{0000}' && *c <= '\u{001F}'
}

fn is_c1(c: &char) -> bool {
    *c >= '\u{0080}' && *c <= '\u{009F}'
}

fn is_control(c: &char) -> bool {
    is_c0(c) || is_c1(c) || *c == '\u{007F}'
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalize_works_with_space() {
        let input = "test test";
        let result = normalize_password(input);
        assert_eq!(result, String::from("test test"));
    }

    #[test]
    fn normalize_strips_c0_control_chars() {
        let input = "test\u{001F}test";
        let result = normalize_password(input);
        assert_eq!(result, String::from("testtest"));
    }

    #[test]
    fn normalize_strips_c1_control_chars() {
        let input = "test\u{0080}\u{0081}\u{009F}test";
        let result = normalize_password(input);
        assert_eq!(result, "testtest".to_string());
    }

    #[test]
    fn normalize_strips_delete_control_chars() {
        let input = "test\u{007F}test";
        let result = normalize_password(input);
        assert_eq!(result, "testtest".to_string());
    }

    #[test]
    fn normalize_works_with_non_control_char() {
        let input = "test\u{0020}test";
        let result = normalize_password(input);
        assert_eq!(result, String::from("test\u{0020}test"));
    }
}
