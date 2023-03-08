use super::*;

const SCRYPT_TEST_VECTOR: &str = r#"
        {
          "crypto" : {
            "kdf" : {
              "function" : "scrypt",
              "params" : {
                "dklen" : 32,
                "n" : 512,
                "p" : 1,
                "r" : 8,
                "salt" : "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
              },
              "message" : ""
            },
            "checksum" : {
              "function" : "sha256",
              "params" : { },
              "message" : "28aea7510466a76c848c2f48649b94bd0170f90badf05480948304838d43acfc"
            },
            "cipher" : {
              "function" : "aes-128-ctr",
              "params" : {
                "iv" : "264daa3f303d7259501c93d997d84fe6"
              },
              "message" : "5f4cbeea80336bd076e8f648d4c6c0f6954ae40babdbab70079fc1cd8bec4a11"
            }
          },
          "pubkey" : "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
          "version" : 4,
          "path" : "m/12381/60/3141592653/589793238",
          "uuid" : "eb329e94-6d98-4999-a773-6162fa0dd13a"
        }"#;

const PBKDF2_TEST_VECTOR: &str = r#"
        {
          "crypto" : {
            "kdf" : {
              "function" : "pbkdf2",
              "params" : {
                "dklen" : 32,
                "c" : 512,
                "prf" : "hmac-sha256",
                "salt" : "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
              },
              "message" : ""
            },
            "checksum" : {
              "function" : "sha256",
              "params" : { },
              "message" : "6751983f3370494fd68b3efb3031a576985fb011c624b139ca810bd9f96577c2"
            },
            "cipher" : {
              "function" : "aes-128-ctr",
              "params" : {
                "iv" : "264daa3f303d7259501c93d997d84fe6"
              },
              "message" : "8d17c26276921a72923f62c6f25ec70b980bb3a39d26aa54744fa784bd08be6d"
            }
          },
          "pubkey" : "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
          "version" : 4,
          "path" : "",
          "uuid" : "3c4fe576-fffb-4263-a52c-444dc38b99a5"
      }"#;

const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
const SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

#[test]
fn decrypt_secret() {
    let expected_key_vec = hex::decode(SECRET).unwrap();

    let decrypted_key = decrypt(SCRYPT_TEST_VECTOR, PASSWORD).unwrap();
    assert_eq!(decrypted_key, expected_key_vec);
    let decrypted_key = decrypt(PBKDF2_TEST_VECTOR, PASSWORD).unwrap();
    assert_eq!(decrypted_key, expected_key_vec);
}

#[test]
fn invalid_keystore() {
    let decrypted_result = decrypt("{}", PASSWORD);
    assert!(&decrypted_result.is_err());
}

#[test]
fn decrypt_keystore_with_invalid_password() {
    let decrypted_result = decrypt(SCRYPT_TEST_VECTOR, "test");
    let err = decrypted_result.err().unwrap();
    assert_eq!(err.to_string(), "Password verification failed");
}
