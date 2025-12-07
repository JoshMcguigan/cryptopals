use cryptopals::aes::{cbc_decrypt_check_padding, cbc_encrypt};

use data_encoding::BASE64;
use rand::{Rng, RngCore};

struct Oracle17 {
    plaintext_index: usize,
    key: [u8; 16],
}

impl Default for Oracle17 {
    fn default() -> Self {
        let mut key = [0; 16];
        rand::rng().fill_bytes(&mut key);

        Self {
            plaintext_index: rand::rng().random_range(0..10),
            key,
        }
    }
}

impl Oracle17 {
    /// Returns the encrypted data prefixed with the IV.
    fn encrypt(&self) -> Vec<u8> {
        let mut iv = [0; 16];
        rand::rng().fill_bytes(&mut iv);

        let plaintext_strings_base64 = include_str!("challenge-data/17.txt");
        let plaintext_strings = plaintext_strings_base64
            .lines()
            .map(|line| {
                BASE64
                    .decode(line.as_bytes())
                    .expect("input should be valid base64")
            })
            .collect::<Vec<Vec<u8>>>();
        assert_eq!(
            10,
            plaintext_strings.len(),
            "should be 10 options, failed to parse"
        );
        let plaintext = &plaintext_strings[self.plaintext_index];

        let mut out = Vec::from(iv);
        let ciphertext = cbc_encrypt(&self.key.into(), plaintext, &iv);
        out.extend_from_slice(&ciphertext);

        out
    }

    /// `ciphertext` arg is prefixed with IV.
    fn padding_is_valid(&self, ciphertext: &[u8]) -> bool {
        cbc_decrypt_check_padding(&self.key.into(), &ciphertext[16..], &ciphertext[0..16]).0
    }
}

#[test]
fn challenge_17() {
    let oracle = Oracle17::default();
    let ciphertext = oracle.encrypt();

    assert!(
        oracle.padding_is_valid(&ciphertext),
        "padding should be valid before the ciphertext is modified"
    );
}
