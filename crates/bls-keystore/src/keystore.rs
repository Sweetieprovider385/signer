//! Keystore JSON definition

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{anyhow, bail, Result};
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt, Params};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;

type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;

#[derive(Serialize, Deserialize, Debug)]
pub struct ChecksumModule {
    pub function: String,
    pub params: HashMap<String, String>,
    #[serde(with = "hex")]
    pub message: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CipherParams {
    #[serde(with = "hex")]
    pub iv: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CipherModule {
    pub function: String,
    pub params: CipherParams,
    #[serde(with = "hex")]
    pub message: Vec<u8>,
}

impl CipherModule {
    pub fn decrypt_secret(&self, decryption_key: &[u8]) -> Result<Vec<u8>> {
        if !self.function.eq_ignore_ascii_case("aes-128-ctr") {
            bail!("Unsupported cipher function {}", self.function);
        }

        // for aes-128, the decryption key size must be >= 16
        if decryption_key.len() < 16 {
            bail!("Invalid decryption key length");
        }

        let dk_slice = &decryption_key[0..16];
        let iv = &self.params.iv[..];
        let message = &self.message;

        let mut buf = vec![0; message.len()];
        let cipher_result = Aes128Ctr128BE::new_from_slices(dk_slice, iv);
        let mut cipher = match cipher_result {
            Ok(cipher) => cipher,
            Err(err) => bail!("Error creating cipher: {}", err),
        };

        let decrypt_result = cipher.apply_keystream_b2b(message, &mut buf);
        match decrypt_result {
            Ok(()) => Ok(buf),
            Err(err) => bail!("Error applying cipher: {}", err),
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
#[serde(tag = "function")]
pub enum KdfParams {
    #[serde(rename = "scrypt")]
    SCrypt {
        params: SCryptParams,
        message: String,
    },

    #[serde(rename = "pbkdf2")]
    PbKdf2 {
        params: Pbkdf2Params,
        message: String,
    },
}

impl KdfParams {
    pub fn decryption_key(&self, normalized_password: &str) -> Result<Vec<u8>> {
        match self {
            KdfParams::SCrypt { params, message: _ } => params.decryption_key(normalized_password),
            KdfParams::PbKdf2 { params, message: _ } => params.decryption_key(normalized_password),
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct SCryptParams {
    pub dklen: usize,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    #[serde(with = "hex")]
    pub salt: Vec<u8>,
}

impl SCryptParams {
    pub fn decryption_key(&self, password: &str) -> Result<Vec<u8>> {
        let log_n = f64::log2(self.n as f64).round() as u8;
        let param_result = Params::new(log_n, self.r, self.p, self.dklen);
        let params = match param_result {
            Ok(params) => params,
            Err(err) => bail!("Error constructing Params {}", err.to_string()),
        };
        let mut result = vec![0u8; self.dklen];
        let scrypt_result = scrypt(password.as_bytes(), &self.salt, &params, &mut result);
        if let Err(err) = scrypt_result {
            bail!("Error in scrypt method {}", err)
        }
        Ok(result)
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Pbkdf2Params {
    pub dklen: usize,
    pub c: u32,
    pub prf: String,
    #[serde(with = "hex")]
    pub salt: Vec<u8>,
}

impl Pbkdf2Params {
    pub fn decryption_key(&self, password: &str) -> Result<Vec<u8>> {
        let mut result = vec![0u8; self.dklen];
        match self.prf.as_str() {
            "hmac-sha256" => {
                pbkdf2_hmac::<Sha256>(password.as_bytes(), &self.salt, self.c, &mut result)
            }
            "hmac-sha512" => {
                pbkdf2_hmac::<Sha512>(password.as_bytes(), &self.salt, self.c, &mut result)
            }
            _ => bail!("Unsupported prf for pbkdf2: {}", &self.prf),
        }
        Ok(result.to_vec())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Crypto {
    pub kdf: KdfParams,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    pub crypto: Crypto,
    pub description: Option<String>,
    pub pubkey: Option<String>,
    pub path: String,
    pub uuid: String,
    pub version: u8,
}

pub fn parse_keystore(json: &str) -> Result<Keystore> {
    let keystore: Keystore = serde_json::from_str(json)?;
    if keystore.version != 4 {
        Err(anyhow!(
            "Keystore version {} is not supported",
            keystore.version
        ))
    } else {
        Ok(keystore)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keystore_json_scrypt_parsed() {
        let keystore_json = r#"{
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
            },
            "description": "This is a test keystore that uses scrypt to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
            }"#;

        let keystore = parse_keystore(keystore_json).unwrap();
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.pubkey, Some("9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string()));
        let expected_kdf = KdfParams::SCrypt {
            params: SCryptParams {
                dklen: 32,
                n: 262144,
                p: 1,
                r: 8,
                salt: hex::decode(
                    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                )
                .unwrap(),
            },
            message: "".to_string(),
        };
        assert_eq!(keystore.crypto.kdf, expected_kdf);
    }

    #[test]
    fn keystore_json_parsed_wo_desc_pubkey() {
        let keystore_json = r#"{
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
            },
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
            }"#;

        let keystore = parse_keystore(keystore_json).unwrap();
        assert_eq!(keystore.version, 4);
        assert!(keystore.pubkey.is_none());
    }

    #[test]
    fn keystore_json_pbkdf2_parsed() {
        let keystore_json = r#"
            {
                "crypto": {
                    "kdf": {
                        "function": "pbkdf2",
                        "params": {
                            "dklen": 32,
                            "c": 262144,
                            "prf": "hmac-sha256",
                            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                        },
                        "message": ""
                    },
                    "checksum": {
                        "function": "sha256",
                        "params": {},
                        "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                    },
                    "cipher": {
                        "function": "aes-128-ctr",
                        "params": {
                            "iv": "264daa3f303d7259501c93d997d84fe6"
                        },
                        "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                    }
                },
                "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
                "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "path": "m/12381/60/0/0",
                "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
                "version": 4
          }"#;
        let keystore = parse_keystore(keystore_json).unwrap();
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.pubkey, Some("9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string()));
        let expected_kdf = KdfParams::PbKdf2 {
            params: Pbkdf2Params {
                dklen: 32,
                c: 262144,
                prf: "hmac-sha256".to_string(),
                salt: hex::decode(
                    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                )
                .unwrap(),
            },
            message: "".to_string(),
        };
        assert_eq!(keystore.crypto.kdf, expected_kdf);
    }

    #[test]
    fn scrypt_decryption_key() {
        let password = "testpassword";
        let params = SCryptParams {
            dklen: 32,
            n: 512,
            p: 1,
            r: 8,
            salt: hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap(),
        };

        let result = params.decryption_key(password).unwrap();
        let encoded = hex::encode(result);
        assert_eq!(
            encoded,
            "7674a6e092e0b3132921c0cceb3a40c84f0333b8e11220a734470bb572b5da24"
        );
    }

    #[test]
    fn pbkdf2_decryption_key() {
        let password = "testpassword";
        let params = Pbkdf2Params {
            dklen: 32,
            prf: "hmac-sha256".to_string(),
            c: 512,
            salt: hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap(),
        };

        let result = params.decryption_key(password).unwrap();
        assert_eq!(result.len(), 32);
        let encoded = hex::encode(result);
        assert_eq!(
            encoded,
            "9fae37a71c78f05c4d43b7215766c4ee9339db2e59632b2058cf17a9fadb589f"
        );
    }
}
