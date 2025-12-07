use std::collections::{HashMap, HashSet};

use cryptopals::{
    aes,
    pad::{pkcs7, pkcs7_remove, pkcs7_valid},
};

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
    fn encryption_oracle_1(plaintext: &[u8]) -> Vec<u8> {
        let key = b"YELLOW SUBMARINE".into();
        let iv = b"RANDOM IV WOWOWW";

        // Random padding len, chosen by fair dice roll
        // https://xkcd.com/221/
        let padding_len = 4;

        let mut padded_plaintext = vec![0xa5u8; padding_len];
        padded_plaintext.extend_from_slice(plaintext);
        padded_plaintext.resize(padded_plaintext.len() + padding_len, 0x5a);

        aes::cbc_encrypt(key, padded_plaintext.as_slice(), iv)
    }

    fn encryption_oracle_2(plaintext: &[u8]) -> Vec<u8> {
        let key = b"YELLOW SUBMARINE".into();

        // Random padding len, chosen by fair dice roll
        // https://xkcd.com/221/
        let padding_len = 4;

        let mut padded_plaintext = vec![0xa5u8; padding_len];
        padded_plaintext.extend_from_slice(plaintext);
        padded_plaintext.resize(padded_plaintext.len() + padding_len, 0x5a);

        aes::ecb_encrypt(key, padded_plaintext.as_slice())
    }

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

#[test]
fn challenge_12() {
    fn encryption_oracle(plaintext: &[u8]) -> Vec<u8> {
        let secret_text_base64 = include_str!("challenge-data/12.txt");
        let secret_text = secret_text_base64
            .lines()
            .flat_map(|line| {
                BASE64
                    .decode(line.as_bytes())
                    .expect("input should be valid base64")
            })
            .collect::<Vec<u8>>();
        let key = b"YELLOW SUBMARINE".into();

        let mut plaintext_plus_secret = Vec::from(plaintext);
        plaintext_plus_secret.extend_from_slice(&secret_text);

        aes::ecb_encrypt(key, &plaintext_plus_secret)
    }

    // Step 1
    let initial_ciphertext_len = encryption_oracle(&[]).len();
    let mut i = 1;
    let (block_size, secret_len) = loop {
        let len = encryption_oracle(&vec![0; i]).len();
        if len != initial_ciphertext_len {
            break (len - initial_ciphertext_len, len - 16 - i);
        }
        i += 1;
    };
    assert_eq!(16, block_size);

    // Step 2
    fn detect_ecb<'a>(encryption_oracle: impl Fn(&'a [u8]) -> Vec<u8>) -> bool {
        let plaintext = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE";
        let mut chunks = HashSet::new();
        for chunk in encryption_oracle(plaintext).chunks_exact(16) {
            if !chunks.insert(chunk) {
                return true;
            }
        }
        false
    }
    assert!(detect_ecb(encryption_oracle));

    // Step 3
    let mut plaintext = Vec::from(b"YELLOW SUBMARIN");
    let first_ciphertext_block_with_one_secret_byte = &encryption_oracle(&plaintext)[..16];

    // Step 4 + 5
    for i in u8::MIN..=u8::MAX {
        plaintext.push(i);
        if &encryption_oracle(&plaintext)[..16] == first_ciphertext_block_with_one_secret_byte {
            break;
        }
        plaintext.pop();
    }
    let first_secret_byte = plaintext[15];
    assert_eq!(b'R', first_secret_byte);

    // Step 6
    //
    // For this step I'm going to take a different approach. Rather than shortening my
    // input to the oracle, I'm going to extend it. This way I can find secrets longer
    // than a block size without changing techniques part way through, as the proposed
    // approach would require.
    //
    // Assume:
    // * secret: "SECRET"
    // * block_len: 5
    //
    // The encryption oracle leaks the secret_len as calculated above.
    //
    // We know if we ask the oracle to encrypt (block_len - (secret_len % block_len))
    // bytes then all blocks will be full and PKCS#7 will add a block of
    // [5, 5, 5, 5, 5]. This isn't very helpful, but if we instead ask the oracle to
    // encrypt one byte fewer than that then the final block plaintext will be
    // ["T", 4, 4, 4, 4]. The value of the "T" would be unknown to us, but could be
    // determined in no more than 256 guesses.
    //
    // We can then repeat that process (looking at blocks from the back):
    //
    // ["T", 4, 4, 4, 4]
    // ["E", "T", 3, 3, 3]
    // ["R", "E", "T", 2, 2]
    // ["C", "R", "E", "T", 1]
    // ["E", "C", "R", "E", "T"] [5, 5, 5, 5, 5]
    let mut plaintext_of_secret = vec![];
    'outer: for byte_index_to_break in (0..secret_len).rev() {
        // We always want to make byte_index_to_break the first
        // byte of a block.
        let target_byte_position = byte_index_to_break.next_multiple_of(16);
        let padding_required = target_byte_position - byte_index_to_break;
        let block_index = target_byte_position / 16;
        let cipher_block_to_match: Vec<u8> = encryption_oracle(&vec![0; padding_required])
            .chunks_exact(16)
            .nth(block_index)
            .expect("ciphertext should be long enough")
            .into();

        // Insert arbitrary data for now, the value will be updated in
        // the loop below.
        plaintext_of_secret.insert(0, 0);
        pkcs7(&mut plaintext_of_secret, 16);
        for i in u8::MIN..=u8::MAX {
            plaintext_of_secret[0] = i;
            let cipher_block_to_check: Vec<u8> = encryption_oracle(&plaintext_of_secret)
                .chunks_exact(16)
                .next()
                .expect("ciphertext should be long enough")
                .into();
            if cipher_block_to_check == cipher_block_to_match {
                pkcs7_remove(&mut plaintext_of_secret);
                continue 'outer;
            }
        }
        panic!("should always find a valid solution after checking all bytes")
    }
    assert_snapshot!(String::from_utf8_lossy(&plaintext_of_secret));
}

#[test]
fn challenge_13() {
    fn profile_for(email: &str) -> String {
        let email = email.replace('&', ".");
        let email = email.replace('=', ".");

        format!("email={email}&uid=10&role=user")
    }

    fn parse_kv(input: &str) -> HashMap<String, String> {
        input
            .split('&')
            .filter_map(|s| {
                s.split_once('=')
                    .map(|(s1, s2)| (s1.to_string(), s2.to_string()))
            })
            .collect()
    }

    fn is_admin(input: &str) -> bool {
        let kv = parse_kv(input);

        kv.get("role").map(|v| v == "admin").unwrap_or(false)
    }

    assert!(!is_admin(&profile_for("notadmin@foo.bar")));

    let key = b"YELLOW SUBMARINE";

    let encrypt_user =
        |email: &str| -> Vec<u8> { aes::ecb_encrypt(key.into(), profile_for(email).as_bytes()) };

    let decrypt_user_is_admin = |ciphertext: Vec<u8>| -> bool {
        is_admin(&String::from_utf8_lossy(&aes::ecb_decrypt(
            key.into(),
            &ciphertext,
        )))
    };

    assert!(!decrypt_user_is_admin(encrypt_user("notadmin@foo.bar")));

    // Need to encrypt "&role=admin". Since it can't be done in the email
    // address due to filtering, it will need to be done in a couple
    // blocks.
    //
    //  0123456789ABCDEF
    // "admin" (padded to a block length with 11 bytes of value 11)
    // "com&uid=10&role="
    //
    // This can be done with a single account:
    //
    //  0123456789ABCDEF   0123456789ABCDEF   0123456789ABCDEF   0123456789ABCDEF   0123456789ABCDEF
    // "email=0123456789" "admin(pad      )" "placeholder@foo." "com&uid=10&role=" "user(pad       )"

    let malicious_email = {
        let mut bytes = Vec::from(b"0123456789admin");
        bytes.extend_from_slice(&[11; 11]);
        bytes.extend_from_slice(b"placeholder@foo.com");
        unsafe { String::from_utf8_unchecked(bytes) }
    };
    let malicious_ciphertext = encrypt_user(&malicious_email);

    // Then we make an account of appropriate length to append to:
    //
    //  0123456789ABCDEF   0123456789ABCDEF
    // "testacc@foo.com&" "uid=10&role=user"

    let email = "testacc@foo.com";
    let mut ciphertext = encrypt_user(email);
    ciphertext.extend_from_slice(&malicious_ciphertext[48..64]);
    ciphertext.extend_from_slice(&malicious_ciphertext[16..32]);

    assert!(decrypt_user_is_admin(ciphertext));
}

#[test]
fn challenge_14() {
    fn encryption_oracle(plaintext: &[u8]) -> Vec<u8> {
        // Challenge 14 suggests re-using the same bytes as challenge 12.
        let secret_text_base64 = include_str!("challenge-data/12.txt");
        let secret_text = secret_text_base64
            .lines()
            .flat_map(|line| {
                BASE64
                    .decode(line.as_bytes())
                    .expect("input should be valid base64")
            })
            .collect::<Vec<u8>>();
        let key = b"YELLOW SUBMARINE".into();

        let mut prefix_plus_plaintext_plus_secret = Vec::from(b"12345");
        prefix_plus_plaintext_plus_secret.extend_from_slice(plaintext);
        prefix_plus_plaintext_plus_secret.extend_from_slice(&secret_text);

        aes::ecb_encrypt(key, &prefix_plus_plaintext_plus_secret)
    }

    // Detect block size
    let initial_ciphertext_len = encryption_oracle(&[]).len();
    let mut i = 0;
    let block_size = loop {
        i += 1;
        let len = encryption_oracle(&vec![0; i]).len();
        if len != initial_ciphertext_len {
            break len - initial_ciphertext_len;
        }
    };
    let bytes_needed_to_pad_to_next_block = i;
    assert_eq!(16, block_size);

    // Detect ECB mode
    fn detect_ecb<'a>(encryption_oracle: impl Fn(&'a [u8]) -> Vec<u8>) -> bool {
        let plaintext = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE";
        let mut chunks = HashSet::new();
        for chunk in encryption_oracle(plaintext).chunks_exact(16) {
            if !chunks.insert(chunk) {
                return true;
            }
        }
        false
    }
    assert!(detect_ecb(encryption_oracle));

    // Detect prefix and suffix length
    let plaintext = vec![0; 48];
    let ciphertext = encryption_oracle(&plaintext);

    let mut all_zero_block_ciphertext: Option<Vec<u8>> = None;
    for i in (0..ciphertext.len()).step_by(16) {
        if let (Some(block_1), Some(block_2)) = (
            ciphertext.get(i..(i + 16)),
            ciphertext.get(i + 16..(i + 32)),
        ) {
            if block_1 == block_2 {
                all_zero_block_ciphertext = Some(block_1.to_vec());
            }
        } else {
            break;
        }
    }
    // This will always find a duplicate block. However, there are cases where it could find the wrong
    // block, for example if the prefix includes duplicate blocks. We could filter for this by checking
    // the ciphertext when passing empty byte string as input.
    let all_zero_block_ciphertext =
        all_zero_block_ciphertext.expect("must have found duplicate block");

    let (duplicate_block_index, i, total_num_blocks) = (0..16)
        .into_iter()
        .find_map(|i| {
            // Prefix with anything other than zero, so it stands out
            // against our all zero block.
            let mut plaintext = vec![1; i];
            plaintext.extend_from_slice(&[0; 16]);

            let ciphertext = encryption_oracle(&plaintext);
            ciphertext
                .chunks_exact(16)
                .enumerate()
                .find_map(|(duplicate_block_index, block)| {
                    if block == all_zero_block_ciphertext {
                        Some((duplicate_block_index, i, ciphertext.len() / 16))
                    } else {
                        None
                    }
                })
        })
        .expect("must find block");
    let prefix_len = duplicate_block_index * 16 - i;
    assert_eq!(5, prefix_len);

    // Subtracting two blocks:
    // * All zero block
    // * Full block of PKCS#7 padding
    let suffix_len = (total_num_blocks - duplicate_block_index - 2) * 16 + 16
        - prefix_len
        - bytes_needed_to_pad_to_next_block;
    assert_eq!(138, suffix_len);

    let mut plaintext_of_secret = vec![];
    'outer: for byte_index_to_break in (prefix_len..(prefix_len + suffix_len)).rev() {
        // We always want to make byte_index_to_break the first
        // byte of a block.
        let target_byte_position = byte_index_to_break.next_multiple_of(16);
        let padding_required = target_byte_position - byte_index_to_break;
        let block_index = target_byte_position / 16;
        let cipher_block_to_match: Vec<u8> = encryption_oracle(&vec![0; padding_required])
            .chunks_exact(16)
            .nth(block_index)
            .expect("ciphertext should be long enough")
            .into();

        // Insert arbitrary data for now, the value will be updated in
        // the loop below.
        plaintext_of_secret.insert(0, 0);
        pkcs7(&mut plaintext_of_secret, 16);
        for i in u8::MIN..=u8::MAX {
            plaintext_of_secret[0] = i;
            // This only handles prefixes of less than a block size.
            let mut text_to_encrypt = vec![0; 16 - prefix_len];
            text_to_encrypt.extend_from_slice(&plaintext_of_secret);
            let cipher_block_to_check: Vec<u8> = encryption_oracle(&text_to_encrypt)
                .chunks_exact(16)
                // This only handles prefixes of less than a block size.
                .nth(1)
                .expect("ciphertext should be long enough")
                .into();
            if cipher_block_to_check == cipher_block_to_match {
                pkcs7_remove(&mut plaintext_of_secret);
                continue 'outer;
            }
        }
        panic!("should always find a valid solution after checking all bytes")
    }
    assert_snapshot!(String::from_utf8_lossy(&plaintext_of_secret));
}

#[test]
fn challenge_15() {
    assert!(!pkcs7_valid(&[]));
    assert!(!pkcs7_valid(&[1]));
    assert!(!pkcs7_valid(&[32; 32]));
    assert!(!pkcs7_valid(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ]));
    assert!(!pkcs7_valid(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 2
    ]));
    assert!(!pkcs7_valid(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0
    ]));
    assert!(pkcs7_valid(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1
    ]));
}

/// Simplified version of challenge 16, where the attacker modifies
/// the IV to change the plaintext in the first block.
#[test]
fn challenge_16_warmup() {
    let (encrypt_user_data, decrypt) = {
        let key = b"YELLOW SUBMARINE";
        // Using the same IV is exploitable, but we'll pretend like this function
        // is using a unique IV each time.
        let iv = b"yellow submarine";

        let encrypt_user_data = |plaintext: &[u8]| -> Vec<u8> {
            let ciphertext = aes::cbc_encrypt(key.into(), plaintext, iv);

            // Return the ciphertext pre-pended with the IV.
            let mut ret = vec![];
            ret.extend_from_slice(iv);
            ret.extend_from_slice(&ciphertext);

            ret
        };

        let decrypt = |ciphertext: &[u8]| -> Vec<u8> {
            aes::cbc_decrypt(key.into(), &ciphertext[16..], &ciphertext[0..16])
        };

        (encrypt_user_data, decrypt)
    };

    let mut plaintext = vec![0; 16];
    plaintext[0] = 1;
    let mut ciphertext = encrypt_user_data(&plaintext);

    // Show that we can round-trip the data with no modifications.
    let decrypted_plaintext = decrypt(&ciphertext);
    assert_eq!(1, decrypted_plaintext[0]);

    // Now flip a bit.
    //
    // By flipping the bit at index 1 in the IV, we can flip that
    // same bit in the output.
    ciphertext[0] ^= 0b10;
    let decrypted_plaintext = decrypt(&ciphertext);
    assert_eq!(3, decrypted_plaintext[0]);
}

#[test]
fn challenge_16() {
    let (encrypt_user_data, decrypt_is_admin) = {
        let key = b"YELLOW SUBMARINE";
        // Using the same IV is exploitable, but we'll pretend like this function
        // is using a unique IV each time.
        let iv = b"yellow submarine";

        let encrypt_user_data = |user_data: &[u8]| -> Vec<u8> {
            // This function should validate user input, but we'll skip that.

            let prefix = b"comment1=cooking%20MCs;userdata=";
            let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
            let mut plaintext = Vec::from(prefix);
            plaintext.extend_from_slice(user_data);
            plaintext.extend_from_slice(suffix);

            let ciphertext = aes::cbc_encrypt(key.into(), &plaintext, iv);

            // Return the ciphertext pre-pended with the IV.
            let mut ret = vec![];
            ret.extend_from_slice(iv);
            ret.extend_from_slice(&ciphertext);

            ret
        };

        let decrypt_is_admin = |ciphertext: &[u8]| -> bool {
            let plaintext = aes::cbc_decrypt(key.into(), &ciphertext[16..], &ciphertext[0..16]);
            let target_bytes = b";admin=true;";
            plaintext
                .windows(target_bytes.len())
                .any(|w| w == target_bytes)
        };

        (encrypt_user_data, decrypt_is_admin)
    };

    // Block which is close to the value we want.
    let close = b"9admin9true9abcd";

    let mut ciphertext = encrypt_user_data(close);

    // Without modification, we are not admin
    assert!(!decrypt_is_admin(&ciphertext));

    // Blocks of ciphertext:
    // * 0 - iv
    // * 1 & 2 - prefix
    // * 3 - our block
    let prev_block_index = 2;

    let ciphertext_block_to_modify = ciphertext
        .chunks_exact_mut(16)
        .nth(prev_block_index)
        .expect("ciphertext should be long enough");
    // First ;
    ciphertext_block_to_modify[0] ^= 0b10;
    // =
    ciphertext_block_to_modify[6] ^= 0b100;
    // Second ;
    ciphertext_block_to_modify[11] ^= 0b10;

    assert!(decrypt_is_admin(&ciphertext));
}
