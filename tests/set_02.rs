use std::collections::HashSet;

use cryptopals::{aes, pad::pkcs7};

use data_encoding::BASE64;
use insta::{assert_debug_snapshot, assert_snapshot};

#[test]
fn challenge_09() {
    let input_text = b"YELLOW SUBMARINE";

    let mut text = Vec::from(input_text);
    pkcs7(&mut text, 20);

    assert_eq!(20, text.len());
    assert_debug_snapshot!(text);
}

#[test]
fn challenge_10() {
    let ciphertext_base64 = include_str!("challenge-data/10.txt");
    let ciphertext = ciphertext_base64
        .lines()
        .flat_map(|line| {
            BASE64
                .decode(line.as_bytes())
                .expect("input should be valid base64")
        })
        .collect::<Vec<u8>>();

    let key = b"YELLOW SUBMARINE";

    let plaintext = aes::cbc_decrypt(key.into(), &ciphertext, &[0; 16]);

    assert_snapshot!(String::from_utf8_lossy(&plaintext));
}

#[test]
fn challenge_11() {
    let encryption_oracle_1 = |plaintext| {
        let key = b"YELLOW SUBMARINE".into();
        let iv = b"RANDOM IV WOWOWW";

        // Random padding len, chosen by fair dice roll
        // https://xkcd.com/221/
        let padding_len = 4;

        let mut padded_plaintext = vec![0xa5u8; padding_len];
        padded_plaintext.extend_from_slice(plaintext);
        padded_plaintext.resize(padded_plaintext.len() + padding_len, 0x5a);

        aes::cbc_encrypt(key, padded_plaintext.as_slice(), iv)
    };

    let encryption_oracle_2 = |plaintext| {
        let key = b"YELLOW SUBMARINE".into();

        // Random padding len, chosen by fair dice roll
        // https://xkcd.com/221/
        let padding_len = 4;

        let mut padded_plaintext = vec![0xa5u8; padding_len];
        padded_plaintext.extend_from_slice(plaintext);
        padded_plaintext.resize(padded_plaintext.len() + padding_len, 0x5a);

        aes::ecb_encrypt(key, padded_plaintext.as_slice())
    };

    fn detect_cbc<'a>(encryption_oracle: impl Fn(&'a [u8]) -> Vec<u8>) -> bool {
        let plaintext = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE";
        let mut chunks = HashSet::new();
        for chunk in encryption_oracle(plaintext).chunks_exact(16) {
            if !chunks.insert(chunk) {
                return false;
            }
        }
        true
    }

    assert!(detect_cbc(encryption_oracle_1));
    assert!(!detect_cbc(encryption_oracle_2));
}
