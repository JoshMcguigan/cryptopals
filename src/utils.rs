extern crate base64;

use std::u8;
use self::base64::{encode};

fn char_to_score(char: char) -> f32 {
    //https://en.wikipedia.org/wiki/Letter_frequency
    match char {
        'a' => 8.167,
        'b' => 1.492,
        'c' => 2.782,
        'd' => 4.253,
        'e' => 12.702,
        'f' => 2.228,
        'g' => 2.015,
        'h' => 6.094,
        'i' => 6.966,
        'j' => 0.153,
        'k' => 0.772,
        'l' => 4.025,
        'm' => 2.406,
        'n' => 6.749,
        'o' => 7.507,
        'p' => 1.929,
        'q' => 0.095,
        'r' => 5.987,
        's' => 6.327,
        't' => 9.056,
        'u' => 2.758,
        'v' => 0.978,
        'w' => 2.360,
        'x' => 0.150,
        'y' => 1.974,
        'z' => 0.074,
        ' ' => 0.000,
        '.' => 0.000,
        ',' => 0.000,
        ';' => 0.000,
        ':' => 0.000,
        '\'' => 0.000,
        _   => -10.000
    }
}

pub struct SingleCharXorDecryptedMessage {
    pub decoded_message: String,
    pub key: u8,
    pub score: f32
}

pub fn get_most_likely_single_char_xor_result(hex_input: &str) -> SingleCharXorDecryptedMessage {

    let mut result = SingleCharXorDecryptedMessage {
        score: 0f32,
        key: 0u8,
        decoded_message: String::from("")
    };

    for char_input in 0u8..127u8 {

        let result_string = hex_single_char_xor_to_ascii(hex_input,&char_input);

        let score = get_score_for_string(&result_string);

        if score > result.score {
            result.score = score;
            result.key = char_input;
            result.decoded_message = result_string;
        }
    }

    result
}

pub fn get_score_for_string(string: &str) -> f32 {
    let lower_case_string = string.to_lowercase();
    let mut score : f32 = 0f32;
    for char in lower_case_string.chars() {
        score += char_to_score(char);
    }
    score / (string.len() as f32)
}


pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(hex.len()/2) {
        let result = u8::from_str_radix(&hex[2*i .. 2*i+2], 16);
        bytes.push(result.unwrap());
    };
    bytes
}

pub fn hex_to_base64(hex: &str) -> String {
    encode(&hex_to_bytes(hex))
}

pub fn hex_fixed_xor(in1: &str, in2: &str) -> String {

    let bytes1 = hex_to_bytes(in1);
    let bytes2 = hex_to_bytes(in2);

    let mut result_bytes : Vec<u8> = Vec::new();

    for (index, byte) in bytes1.iter().enumerate() {
        let byte2 : &u8 = bytes2.get(index).unwrap();
        result_bytes.push(byte ^ byte2);
    }

    bytes_to_hex_string(result_bytes)
}

pub fn bytes_to_hex_string(bytes: Vec<u8>) -> String {
    let strings: Vec<String> = bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    strings.join("").to_lowercase()
}

pub fn bytes_to_ascii_string(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Err(_) => String::from(""),
        Ok(string) => string
    }
}

pub fn hex_single_char_xor_to_ascii(hex_string: &str, char: &u8) -> String {
    let bytes = hex_to_bytes(hex_string);

    let mut result_bytes : Vec<u8> = Vec::new();

    for byte in bytes {
        result_bytes.push(byte ^ char);
    }

    bytes_to_ascii_string(result_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_base64() {
        let hex = "49276d206b696c6c696";
        let expected_base64 = "SSdtIGtpbGxp";

        assert_eq!(expected_base64, hex_to_base64(hex));
    }

    #[test]
    fn test_hex_fixed_xor() {
        let in1 = "1c0111001f";
        let in2 = "6869742074";
        let expected_result = "746865206b";

        assert_eq!(expected_result, hex_fixed_xor(in1, in2));
    }

    #[test]
    fn test_hex_single_char_xor_to_ascii() {

        let hex_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let char = 88u8;

        let expected_string = "Cooking MC's like a pound of bacon";

        assert_eq!(expected_string, hex_single_char_xor_to_ascii(hex_input, &char));

    }

    #[test]
    fn test_char_to_score() {
        let char_a = 'a';
        let char_z = 'z';

        assert!(char_to_score(char_a) > char_to_score(char_z));
    }

    #[test]
    fn test_get_score_for_string() {
        let test_string = "josh";
        let expected_score : f32 = 5.02025;

        assert_eq!(expected_score, get_score_for_string(test_string));
    }

    #[test]
    fn test_get_most_likely_single_char_xor_result() {

        let hex_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let result = get_most_likely_single_char_xor_result(hex_input);

        let expected_max_score_char :u8 = 88;
        assert_eq!(expected_max_score_char, result.key);
    }
}