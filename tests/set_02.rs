use std::collections::{HashMap, HashSet};

use cryptopals::{
    aes,
    pad::{pkcs7, pkcs7_remove},
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
