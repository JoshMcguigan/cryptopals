use cryptopals::{
    aes::{cbc_decrypt_check_padding, cbc_encrypt, ctr},
    analysis::plaintext_scorer_english_prose,
    break_xor,
    pad::pkcs7_remove,
};

use data_encoding::BASE64;
use insta::{assert_debug_snapshot, assert_snapshot};
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

    // Decrypted, but not yet XOR'd text.
    let mut decrypted_blocks = vec![];

    // Skip 1 because the first block is the IV.
    for ciphertext_block in ciphertext.chunks_exact(16).skip(1) {
        let mut prev_ciphertext_block_to_try = [0u8; 16];
        let mut decrypted_block = [0u8; 16];

        for byte_index in (0..16).rev() {
            let num_padding_bytes = 16 - byte_index;
            for i in byte_index..16 {
                prev_ciphertext_block_to_try[i] = decrypted_block[i] ^ num_padding_bytes as u8;
            }

            let mut valid_bytes = vec![];
            for i in u8::MIN..=u8::MAX {
                prev_ciphertext_block_to_try[byte_index] = i;

                let ciphertext_to_try = {
                    let mut v = vec![];
                    v.extend_from_slice(&prev_ciphertext_block_to_try);
                    v.extend_from_slice(ciphertext_block);
                    v
                };

                if oracle.padding_is_valid(&ciphertext_to_try) {
                    valid_bytes.push(i);
                }
            }

            let c_prime_byte = {
                if valid_bytes.len() == 1 {
                    valid_bytes.pop().unwrap()
                } else {
                    assert_eq!(2, valid_bytes.len());

                    let prev_byte_index = byte_index - 1;
                    prev_ciphertext_block_to_try[prev_byte_index] =
                        prev_ciphertext_block_to_try[prev_byte_index].wrapping_add(1);
                    prev_ciphertext_block_to_try[byte_index] = valid_bytes[0];

                    let ciphertext_to_try = {
                        let mut v = vec![];
                        v.extend_from_slice(&prev_ciphertext_block_to_try);
                        v.extend_from_slice(ciphertext_block);
                        v
                    };

                    if oracle.padding_is_valid(&ciphertext_to_try) {
                        valid_bytes[0]
                    } else {
                        valid_bytes[1]
                    }
                }
            };
            decrypted_block[byte_index] = c_prime_byte ^ num_padding_bytes as u8;
        }

        decrypted_blocks.extend_from_slice(&decrypted_block);
    }

    let mut plaintext = ciphertext
        .iter()
        .zip(decrypted_blocks)
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();
    pkcs7_remove(&mut plaintext);

    assert!(oracle.decryption_is_correct(&plaintext));
}

#[test]
fn challenge_18() {
    let base64_ciphertext =
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let ciphertext = BASE64
        .decode(base64_ciphertext)
        .expect("input should be valid base64");

    let plaintext = ctr(b"YELLOW SUBMARINE".into(), &ciphertext, 0);

    assert_snapshot!(String::from_utf8_lossy(&plaintext));
}

#[test]
fn challenge_19() {
    let plaintext_base64 = include_str!("challenge-data/19.txt");
    let plaintexts = plaintext_base64
        .lines()
        .map(|line| {
            BASE64
                .decode(line.as_bytes())
                .expect("input should be valid base64")
        })
        .collect::<Vec<Vec<u8>>>();

    let ciphertexts = plaintexts
        .iter()
        .map(|plaintext| {
            // Re-using the same nonce! This is what allows
            // us to break this encryption.
            ctr(b"YELLOW SUBMARINE".into(), plaintext, 0)
        })
        .collect::<Vec<Vec<u8>>>();

    // Combine all first blocks to break them as repeated key XOR.
    let ciphertext_first_blocks = ciphertexts
        .iter()
        .flat_map(|c| Vec::from(&c[0..16]))
        .collect::<Vec<u8>>();

    let possible_plaintext_first_blocks =
        break_xor(&ciphertext_first_blocks, 16, plaintext_scorer_english_prose).possible_plaintext;

    assert_debug_snapshot!(
        possible_plaintext_first_blocks
            .chunks_exact(16)
            .map(|plaintext| String::from_utf8_lossy(plaintext).into_owned())
            .collect::<Vec<String>>()
    );

    // This could be repeated for remaining blocks, although you'd have to deal with the
    // strings haven't different lengths.
}
