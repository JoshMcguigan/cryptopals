use std::collections::HashSet;

use cryptopals::{aes, find_xor_keysize};

use data_encoding::{BASE64, HEXLOWER};
use insta::{assert_debug_snapshot, assert_snapshot};

/// No code is implemented for this challenge - but it confirms that the `data_encoding`
/// crate behaves as expected.
#[test]
fn challenge_01() {
    let input_hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(
        expected_base64,
        BASE64.encode(
            &HEXLOWER
                .decode(input_hex_str.as_bytes())
                .expect("input is valid hex")
        )
    );
}

#[test]
fn challenge_02() {
    let input_hex_str_1 = "1c0111001f010100061a024b53535009181c";
    let input_hex_str_2 = "686974207468652062756c6c277320657965";
    let expected_xor_output_as_hex = "746865206b696420646f6e277420706c6179";

    assert_eq!(
        expected_xor_output_as_hex,
        &HEXLOWER.encode(&cryptopals::xor(
            &HEXLOWER
                .decode(input_hex_str_1.as_bytes())
                .expect("intput is valid hex"),
            &HEXLOWER
                .decode(input_hex_str_2.as_bytes())
                .expect("intput is valid hex"),
        ))
    );
}

#[test]
fn challenge_03() {
    let ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let expected_key = vec![88];
    let expected_plaintext = "Cooking MC's like a pound of bacon";

    let cryptopals::PossibleBreak {
        possible_key: key,
        possible_plaintext: plaintext,
        ..
    } = cryptopals::break_single_byte_xor(
        &HEXLOWER
            .decode(ciphertext_hex.as_bytes())
            .expect("input is valid hex"),
        cryptopals::analysis::plaintext_scorer_english_prose,
    );
    assert_eq!(expected_key, key);
    assert_eq!(expected_plaintext, String::from_utf8_lossy(&plaintext));
}

#[test]
fn challenge_04() {
    let ciphertext_hex_lines = include_str!("challenge-data/4.txt");
    let expected_plaintext = "Now that the party is jumping\n";

    let plaintext = ciphertext_hex_lines
        .lines()
        .map(|ciphertext_hex_line| {
            let cryptopals::PossibleBreak {
                score,
                possible_plaintext,
                ..
            } = cryptopals::break_single_byte_xor(
                &HEXLOWER
                    .decode(ciphertext_hex_line.as_bytes())
                    .expect("input is valid hex"),
                cryptopals::analysis::plaintext_scorer_english_prose,
            );

            (score, possible_plaintext)
        })
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .map(|(_, plaintext)| plaintext)
        .expect("must have max because we are comparing non-zero number of things");

    assert_eq!(expected_plaintext, String::from_utf8_lossy(&plaintext));
}

#[test]
fn challenge_05() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\n\
                     I go crazy when I hear a cymbal";
    let expected_ciphertext_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                                   a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    assert_eq!(
        expected_ciphertext_hex,
        HEXLOWER.encode(&cryptopals::xor(plaintext.as_bytes(), b"ICE"))
    )
}

#[test]
fn challenge_06() {
    let ciphertext_base64 = include_str!("challenge-data/6.txt");
    let ciphertext = ciphertext_base64
        .lines()
        .flat_map(|line| {
            BASE64
                .decode(line.as_bytes())
                .expect("input should be valid base64")
        })
        .collect::<Vec<u8>>();

    let keysize = find_xor_keysize(&ciphertext, 60.try_into().expect("value is non-zero"));
    let cryptopals::PossibleBreak {
        possible_key: key,
        possible_plaintext: plaintext,
        ..
    } = cryptopals::break_xor(
        &ciphertext,
        keysize.into(),
        cryptopals::analysis::plaintext_scorer_english_prose,
    );

    assert_debug_snapshot!(key);
    assert_snapshot!(String::from_utf8_lossy(&plaintext));
}

#[test]
fn challenge_07() {
    let ciphertext_base64 = include_str!("challenge-data/7.txt");
    let ciphertext = ciphertext_base64
        .lines()
        .flat_map(|line| {
            BASE64
                .decode(line.as_bytes())
                .expect("input should be valid base64")
        })
        .collect::<Vec<u8>>();

    let key = b"YELLOW SUBMARINE";

    let plaintext = aes::ecb_decrypt(key.into(), &ciphertext);

    assert_snapshot!(String::from_utf8_lossy(&plaintext));
}

#[test]
fn challenge_08() {
    let ciphertext_hex_lines = include_str!("challenge-data/8.txt");

    let index_of_ecb_ciphertext =
        ciphertext_hex_lines
            .lines()
            .enumerate()
            .find_map(|(index, ciphertext_hex_line)| {
                let ciphertext = HEXLOWER
                    .decode(ciphertext_hex_line.as_bytes())
                    .expect("input is valid hex");

                let mut set = HashSet::new();
                for block in ciphertext.chunks_exact(16) {
                    if !set.insert(block) {
                        // Duplicate block detected, this is likely ECB
                        return Some(index);
                    }
                }

                // No duplicate was detected, this is likely not ECB
                None
            });

    assert_eq!(Some(132), index_of_ecb_ciphertext);
}
