use cryptopals::aes::{cbc_decrypt_check_padding, cbc_encrypt};

use data_encoding::BASE64;
use rand::{Rng, RngCore};

struct Oracle17 {
    key: [u8; 16],
    plaintext: Vec<u8>,
}

impl Default for Oracle17 {
    fn default() -> Self {
        let plaintext_strings_base64 = include_str!("challenge-data/17.txt");
        let plaintext_index = rand::rng().random_range(0..10);
        let selected_plaintext = plaintext_strings_base64
            .lines()
            .nth(plaintext_index)
            .map(|line| {
                BASE64
                    .decode(line.as_bytes())
                    .expect("input should be valid base64")
            })
            .expect("should have 10 input strings");

        Self::with_plaintext(selected_plaintext)
    }
}

impl Oracle17 {
    /// The challenge doesn't describe the oracle as having this function, but its
    /// useful for testing.
    fn with_plaintext(plaintext: Vec<u8>) -> Self {
        let mut key = [0; 16];
        rand::rng().fill_bytes(&mut key);

        Self { key, plaintext }
    }

    /// Returns the encrypted data prefixed with the IV.
    fn encrypt(&self) -> Vec<u8> {
        let mut iv = [0; 16];
        rand::rng().fill_bytes(&mut iv);

        let mut out = Vec::from(iv);
        let ciphertext = cbc_encrypt(&self.key.into(), &self.plaintext, &iv);
        out.extend_from_slice(&ciphertext);

        out
    }

    /// `ciphertext` arg is prefixed with IV.
    fn padding_is_valid(&self, ciphertext: &[u8]) -> bool {
        cbc_decrypt_check_padding(&self.key.into(), &ciphertext[16..], &ciphertext[0..16]).0
    }

    /// The challenge doesn't describe the oracle as having this function, but its
    /// useful for testing.
    fn decryption_is_correct(&self, plaintext_guess: &[u8]) -> bool {
        plaintext_guess == self.plaintext
    }
}

/// Simplified version of challenge 17, where we select a single
/// short plaintext.
#[test]
fn challenge_17_warmup() {
    let plaintext = Vec::from(b"A");
    let oracle = Oracle17::with_plaintext(plaintext.clone());

    let mut ciphertext = oracle.encrypt();

    // Check that the oracle is working as expected.
    assert!(oracle.padding_is_valid(&ciphertext));
    assert!(oracle.decryption_is_correct(&plaintext));

    let c1_original_last_byte = ciphertext[15];
    let mut c1_prime_valid_last_bytes = vec![];
    for i in u8::MIN..=u8::MAX {
        ciphertext[15] = i;
        if oracle.padding_is_valid(&ciphertext) {
            c1_prime_valid_last_bytes.push(i);
        }
    }

    // There can be at most two valid last bytes:
    // * The value which makes the padding byte 1, which is always valid
    // * The value which makes the padding byte equal some other value
    //   which happens to match previous bytes which can be interpreted
    //   as padding
    //   * One common reason for this - although it isn't always the case,
    //     is when matching the real padding (although the real padding
    //     can always be one)

    assert_eq!(2, c1_prime_valid_last_bytes.len());
    assert!(c1_prime_valid_last_bytes.contains(&c1_original_last_byte));

    // In the case where the real padding is 1, and previous bytes happen
    // not to play along, its possible to only have one valid value here, which
    // would be the original value of the ciphertext.
    {
        let oracle_b = Oracle17::with_plaintext(Vec::from(b"BBBBBBBBBBBBBBB"));

        let mut ciphertext = oracle_b.encrypt();

        let original_c15 = ciphertext[15];
        for i in (u8::MIN..=u8::MAX).filter(|i| *i != original_c15) {
            ciphertext[15] = i;
            assert!(!oracle_b.padding_is_valid(&ciphertext));
        }
    }

    // If we get one solution, we know that byte of plaintext was already 1.
    //
    // If we get multiple solutions, we need to narrow them down. We can do
    // this by modifying the previous byte of ciphertext to see which still
    // works. The one that still works is the one that led to the plaintext
    // value of 1.
    let c1_prime_byte_that_causes_plaintext_to_be_one = {
        ciphertext[15] = c1_prime_valid_last_bytes[0];
        ciphertext[14] = ciphertext[14].wrapping_add(1);

        if oracle.padding_is_valid(&ciphertext) {
            c1_prime_valid_last_bytes[0]
        } else {
            c1_prime_valid_last_bytes[1]
        }
    };

    // Now we know the decrypted byte xor c1_prime_byte_that_causes_plaintext_to_be_one == 1, so
    // we can 1 xor c1_prime_byte_that_causes_plaintext_to_be_one to get the decrypted byte then
    // decrypted_byte xor original_c1_byte to get the real plaintext.

    let decrypted_byte = c1_prime_byte_that_causes_plaintext_to_be_one ^ 1;
    let plaintext_byte = decrypted_byte ^ c1_original_last_byte;

    // Given for this excercise we created the plaintext, we know to expect this padding byte.
    assert_eq!(15, plaintext_byte);
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
