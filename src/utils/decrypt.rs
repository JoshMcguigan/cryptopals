extern crate itertools;

use super::*;
use self::itertools::Itertools;

pub struct DecryptedMessage {
    pub decrypted_message: String,
    pub decrypted_bytes: Vec<u8>,
    pub key: Vec<u8>,
    pub score: f32
}

impl DecryptedMessage {
    pub fn new() -> DecryptedMessage {
        DecryptedMessage {
            score: -9999f32,
            key: Vec::new(),
            decrypted_message: String::new(),
            decrypted_bytes: Vec::new()
        }
    }
}

pub fn single_byte_xor(input: Vec<u8>) -> DecryptedMessage {

    let mut result = DecryptedMessage::new();

    for key in 0u8..127u8 {
        let decrypted_bytes = encrypt::repeating_key_xor(input.clone(), vec![key]);
        let decrypted_string = from_bytes::into_utf8(decrypted_bytes.clone());

        match decrypted_string {
            Err(_err) => {},
            Ok(decrypted_string) => {
                let score = plain_text_analysis::get_score(decrypted_string.as_ref());

                if score > result.score {
                    result.score = score;
                    result.key = vec![key];
                    result.decrypted_message = decrypted_string;
                    result.decrypted_bytes = decrypted_bytes;
                }
            }
        }

    }

    result
}

fn multi_byte_xor_for_key_size(input: Vec<u8>, key_size: usize) -> DecryptedMessage {

    let mut decrypted_messages = Vec::new();

    for i in 0..key_size {
        let mut bytes = Vec::new();
        for j in (i..input.len()).step(key_size) {
            let byte : u8 = input.get(j).unwrap().clone();
            bytes.push(byte);
        }
        let result_for_ith_byte = single_byte_xor(bytes);
        decrypted_messages.push(result_for_ith_byte);
    }

    combine_decrypted_messages_from_multi_byte_xor(decrypted_messages)
}

fn combine_decrypted_messages_from_multi_byte_xor(decrypted_messages: Vec<DecryptedMessage>) -> DecryptedMessage {
    let mut result = DecryptedMessage::new();

    // Interleave the bytes from each partial decrypted message
    let decrypted_bytes_part_length = decrypted_messages.get(0).unwrap().decrypted_bytes.len();
    for i in 0..decrypted_bytes_part_length {
        for j in 0..decrypted_messages.len(){
            let byte_option = decrypted_messages.get(j).unwrap().decrypted_bytes.get(i);
            // Assume if the byte doesn't exist that indicates the end of the message
            match byte_option {
                Some(byte) => result.decrypted_bytes.push(byte.clone()),
                None => break
            }
        }
    }

    // Create UTF-8 message from bytes
    result.decrypted_message = from_bytes::into_utf8(result.decrypted_bytes.clone()).unwrap();

    // Calculate average score
    let mut score_sum = 0f32;
    for i in 0..decrypted_messages.len(){
        score_sum += decrypted_messages.get(i).unwrap().score;
    }
    result.score = score_sum / (decrypted_messages.len() as f32);


    // Combine key
    for i in 0..decrypted_messages.len(){
        result.key.append(&mut decrypted_messages.get(i).unwrap().key.clone());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_byte_xor(){

        let hex_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let input_bytes = into_bytes::from_hex(hex_input);

        let expected_message = "Cooking MC\'s like a pound of bacon";

        assert_eq!(expected_message, single_byte_xor(input_bytes).decrypted_message);
    }

    #[test]
    fn test_multi_byte_xor_for_key_size(){
        let encrypted_message_as_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let encrypted_message_bytes = into_bytes::from_hex(encrypted_message_as_hex);
        let key_size = 3usize;

        let expected_decrypted_message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        multi_byte_xor_for_key_size(encrypted_message_bytes.clone(), key_size);
        assert_eq!(expected_decrypted_message, multi_byte_xor_for_key_size(encrypted_message_bytes, key_size).decrypted_message);
    }

    #[test]
    fn test_combine_decrypted_messages_from_multi_byte_xor(){
        let decrypted_message_1 = DecryptedMessage{
            decrypted_message: String::from("Jh"),
            decrypted_bytes: vec![74u8, 104],
            key: vec![1],
            score: 10f32,
        };
        let decrypted_message_2 = DecryptedMessage{
            decrypted_message: String::from("ou"),
            decrypted_bytes: vec![111u8, 117],
            key: vec![2],
            score: 20f32,
        };
        let decrypted_message_3 = DecryptedMessage{
            decrypted_message: String::from("sa"),
            decrypted_bytes: vec![115u8, 97],
            key: vec![3],
            score: 30f32,
        };
        let decrypted_messages = vec![decrypted_message_1, decrypted_message_2, decrypted_message_3];
        let result = combine_decrypted_messages_from_multi_byte_xor(decrypted_messages);

        let expected_message = "Joshua";
        let expected_key = vec![1u8, 2, 3];
        let expected_score = 20f32;

        assert_eq!(expected_message, result.decrypted_message);
        assert_eq!(expected_score, result.score);
        assert_eq!(expected_key, result.key);
    }

}