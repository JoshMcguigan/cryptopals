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
