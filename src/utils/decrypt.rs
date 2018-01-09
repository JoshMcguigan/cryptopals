extern crate itertools;

use super::*;
use self::itertools::Itertools;

extern crate openssl;
use self::openssl::symm::{Cipher, Crypter, Mode};

use std::collections::HashSet;

pub struct DecryptedMessage {
    pub decrypted_bytes: Vec<u8>,
    pub key: Vec<u8>,
    pub score: f32
}

impl DecryptedMessage {
    pub fn new() -> DecryptedMessage {
        DecryptedMessage {
            score: -9999f32,
            key: Vec::new(),
            decrypted_bytes: Vec::new()
        }
    }
}

pub fn single_byte_xor(input: Vec<u8>) -> DecryptedMessage {

    let mut result = DecryptedMessage::new();

    for key in 0u8..127u8 {
        let decrypted_bytes = encrypt::repeating_key_xor(input.clone(), vec![key]);

        let score = analysis::get_score(&decrypted_bytes);

        if score > result.score {
            result.score = score;
            result.key = vec![key];
            result.decrypted_bytes = decrypted_bytes;
        }

    }

    result
}

pub fn multi_byte_xor_for_key_size(input: Vec<u8>, key_size: usize) -> DecryptedMessage {

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

pub fn aes_ecb(input: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key.as_ref(), None);
    let mut decrypted = vec![0u8; input.len()+key.len()];
    decrypter.unwrap().update(&input[..input.len()], decrypted.as_mut_slice()).unwrap();

    let mut result = vec![0u8; input.len()];
    result.copy_from_slice(&decrypted[0..input.len()]);

    result
}

pub fn is_aes_ecb(input: &Vec<u8>) -> bool {
    // detects if data has been AES ECB encrypted by looking for repeated 16 byte blocks of data
    // returns true if possible AES ECB encrypted data has been detected, otherwise returns false
    let zero_value = 0u8;
    const BLOCK_SIZE_IN_BYTES : usize = 16usize;
    let mut blocks: HashSet<[&u8; BLOCK_SIZE_IN_BYTES]> = HashSet::new();

    for byte_index in 0..input.len() {
        let mut block = [&zero_value; BLOCK_SIZE_IN_BYTES];
        for block_index in 0usize..BLOCK_SIZE_IN_BYTES {
            let byte = input.get(byte_index+block_index);
            match byte {
                None => {block[block_index] = &zero_value;},
                Some(byte) => {block[block_index] = byte;},
            }
        }

        if blocks.contains(&block){
            return true
        } else {
            blocks.insert(block);
        }
    }

    false
}

//pub fn aes_cbc(input: Vec<u8>, key: Vec<u8>, init_vector: Vec<u8>) -> Vec<u8> {
//    // Initialization vector size must be equal to one block (4 bytes)
//    assert_eq!(4usize, init_vector.len());
//}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_byte_xor(){

        let hex_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let input_bytes = into_bytes::from_hex(hex_input);

        let expected_message = String::from("Cooking MC\'s like a pound of bacon");

        assert_eq!(expected_message, from_bytes::into_utf8(single_byte_xor(input_bytes).decrypted_bytes).unwrap());
    }

    #[test]
    fn test_multi_byte_xor_for_key_size(){
        let encrypted_message_as_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let encrypted_message_bytes = into_bytes::from_hex(encrypted_message_as_hex);
        let key_size = 3usize;

        let expected_decrypted_message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        multi_byte_xor_for_key_size(encrypted_message_bytes.clone(), key_size);
        assert_eq!(expected_decrypted_message, from_bytes::into_utf8(multi_byte_xor_for_key_size(encrypted_message_bytes, key_size).decrypted_bytes).unwrap());
    }

    #[test]
    fn test_combine_decrypted_messages_from_multi_byte_xor(){
        let decrypted_message_1 = DecryptedMessage{
            decrypted_bytes: vec![74u8, 104],
            key: vec![1],
            score: 10f32,
        };
        let decrypted_message_2 = DecryptedMessage{
            decrypted_bytes: vec![111u8, 117],
            key: vec![2],
            score: 20f32,
        };
        let decrypted_message_3 = DecryptedMessage{
            decrypted_bytes: vec![115u8, 97],
            key: vec![3],
            score: 30f32,
        };
        let decrypted_messages = vec![decrypted_message_1, decrypted_message_2, decrypted_message_3];
        let result = combine_decrypted_messages_from_multi_byte_xor(decrypted_messages);

        let expected_message = "Joshua";
        let expected_key = vec![1u8, 2, 3];
        let expected_score = 20f32;

        assert_eq!(expected_message, from_bytes::into_utf8(result.decrypted_bytes).unwrap());
        assert_eq!(expected_score, result.score);
        assert_eq!(expected_key, result.key);
    }

    #[test]
    fn test_aes_ecb(){
        let input = into_bytes::from_hex("15fd5f4f8b135545424e4925009210f6");
        let key = into_bytes::from_utf8("YELLOW SUBMARINE");

        let expected_result = vec![72, 101, 108, 108, 111, 32, 71, 111, 111, 100, 98, 121, 101, 0, 0, 0];

        assert_eq!(expected_result, aes_ecb(input, key));
    }

    #[test]
    fn test_is_aes_ecb_returns_true(){
        let aes_ecb_encrypted_bytes = into_bytes::from_hex("AA26D13908D945F088A6806AB3EAC449AA26D13908D945F088A6806AB3EAC449AA26D13908D945F088A6806AB3EAC449AA26D13908D945F088A6806AB3EAC449B9DFFE9EBF7CF3C4BBD340B17D841BB9");
        assert_eq!(true, is_aes_ecb(&aes_ecb_encrypted_bytes));
    }

    #[test]
    fn test_is_aes_ecb_returns_false(){
        let aes_cbc_encrypted_bytes = into_bytes::from_hex("AA26D13908D945F088A6806AB3EAC4490918537A264CF5B033AA8F1FEB0C9BFAE572A9461437C87C479143AA659CC1D27618E7A356CF19BEF9F9F4DF7AAE37C1102457436CA826297C3AFA7011097C44");
        assert_eq!(false, is_aes_ecb(&aes_cbc_encrypted_bytes));
    }

//    #[test]
//    fn test_aes_cbc(){
//
//    }
}