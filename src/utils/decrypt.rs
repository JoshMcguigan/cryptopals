extern crate itertools;

use super::*;
use self::itertools::Itertools;

extern crate openssl;
use self::openssl::symm::{Cipher, Crypter, Mode};

use std::collections::HashSet;

use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

const AES_BLOCK_SIZE_IN_BYTES : usize = 16usize;

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
    let mut blocks: HashSet<[&u8; AES_BLOCK_SIZE_IN_BYTES]> = HashSet::new();

    for byte_index in 0..input.len() {
        let mut block = [&zero_value; AES_BLOCK_SIZE_IN_BYTES];
        for block_index in 0usize..AES_BLOCK_SIZE_IN_BYTES {
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

pub fn aes_cbc(input: Vec<u8>, key: Vec<u8>, init_vector: Vec<u8>) -> Vec<u8> {
    // Initialization vector size must be equal to one block (16 bytes)
    assert_eq!(AES_BLOCK_SIZE_IN_BYTES, init_vector.len());

    let input = into_bytes::with_padding(input, AES_BLOCK_SIZE_IN_BYTES);

    let mut result = Vec::new();

    for byte_index in (0..input.len()).step(AES_BLOCK_SIZE_IN_BYTES) {
        let input_block = input[byte_index..(byte_index + AES_BLOCK_SIZE_IN_BYTES)].to_vec();
        let mut decrypted_block = aes_ecb(input_block, key.clone());

        let xor_with = match byte_index {
            0 => init_vector.clone(),
            _ => {
                let previous_block_of_encrypted_data = input[(byte_index-AES_BLOCK_SIZE_IN_BYTES)..byte_index].to_vec();
                previous_block_of_encrypted_data
            }
        };

        let mut decrypted_and_xored_block = encrypt::repeating_key_xor(decrypted_block, xor_with);

        result.append(&mut decrypted_and_xored_block);
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

        let expected_message = String::from("Cooking MC\'s like a pound of bacon");

        assert_eq!(expected_message, from_bytes::into_utf8(single_byte_xor(input_bytes).decrypted_bytes));
    }

    #[test]
    fn test_multi_byte_xor_for_key_size(){
        let encrypted_message_as_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let encrypted_message_bytes = into_bytes::from_hex(encrypted_message_as_hex);
        let key_size = 3usize;

        let expected_decrypted_message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        multi_byte_xor_for_key_size(encrypted_message_bytes.clone(), key_size);
        assert_eq!(expected_decrypted_message, from_bytes::into_utf8(multi_byte_xor_for_key_size(encrypted_message_bytes, key_size).decrypted_bytes));
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

        assert_eq!(expected_message, from_bytes::into_utf8(result.decrypted_bytes));
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

    #[test]
    fn test_aes_cbc() {
        let mut file = File::open("resources/set_2/challenge_10.txt").unwrap();
        let mut contents = String::new();
        let _file_read_result = file.read_to_string(&mut contents);
        let input_bytes = into_bytes::from_base64(&contents);
        let key = into_bytes::from_utf8("YELLOW SUBMARINE");
        let iv = vec![0u8; 16];

        let decrypted_bytes = decrypt::aes_cbc(input_bytes, key, iv);

        let expected_result = String::from("I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}");

        assert_eq!(expected_result, from_bytes::into_utf8(decrypted_bytes));
    }
}