mod utils;
use utils::*;

use std::io::{BufReader,BufRead};
use std::fs::File;

#[cfg(test)]
mod set_1 {
    use super::*;

    #[test]
    fn challenge_1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(expected_base64, hex_to_base64(hex));
    }

    #[test]
    fn challenge_2() {
        let in1 = "1c0111001f010100061a024b53535009181c";
        let in2 = "686974207468652062756c6c277320657965";
        let expected_result = "746865206b696420646f6e277420706c6179";

        assert_eq!(expected_result, hex_fixed_xor(in1, in2));
    }

    #[test]
    fn challenge_3() {
        let hex_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let result = get_most_likely_single_char_xor_result(hex_input);

        let expected_message = String::from("Cooking MC\'s like a pound of bacon");
        assert_eq!(expected_message, result.decoded_message);
    }

    #[test]
    fn challenge_4() {

        let mut decoded_message = SingleCharXorDecryptedMessage {
            decoded_message: String::from(""),
            key: 0,
            score: -9999f32,
        };

        let file = File::open("resources/set_1_challenge_4.txt").unwrap();
        for line in BufReader::new(file).lines() {
            let line_string = line.unwrap();
            let hex_input : &str = line_string.as_ref();
            let result = get_most_likely_single_char_xor_result(hex_input);
            if result.score > decoded_message.score {
                decoded_message = result;
            }
        }

        let expected_message = String::from("Now that the party is jumping\n");
        assert_eq!(expected_message, decoded_message.decoded_message)
    }
}