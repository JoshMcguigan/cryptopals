use super::*;

extern crate openssl;
use self::openssl::symm::{Cipher, Crypter, Mode};

pub fn repeating_key_xor(input: Vec<u8>, key: Vec<u8>) -> Vec<u8> {

    let mut encrypted_bytes : Vec<u8> = Vec::new();

    for (index, input_byte) in input.iter().enumerate() {
        let key_index = index % key.len();
        let key_byte : &u8 = key.get(key_index).unwrap();
        encrypted_bytes.push(input_byte ^ key_byte);
    }

    encrypted_bytes
}

pub fn aes_ecb(input: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key.as_ref(), None);
    let mut encrypted = vec![0u8; input.len()+key.len()];
    let _result_length = encrypter.unwrap().update(input.as_ref(), encrypted.as_mut_slice()).unwrap();

    let mut result = vec![0u8; input.len()];
    result.copy_from_slice(&encrypted[0..input.len()]);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repeating_key_xor(){
        let input : Vec<u8> = vec![0, 1, 2];
        let key : Vec<u8> = vec![128];

        let expected : Vec<u8> = vec![128, 129, 130];

        assert_eq!(expected, repeating_key_xor(input, key));
    }

    #[test]
    fn test_repeating_key_xor_with_key_length_equal_to_input_length(){

        let input : Vec<u8> = vec![0, 10];
        let key : Vec<u8> = vec![255, 11];

        let expected : Vec<u8> = vec![255, 1];

        assert_eq!(expected, repeating_key_xor(input, key));
    }

    #[test]
    fn test_aes_ecb(){
        let input_bytes = vec![72, 101, 108, 108, 111, 32, 71, 111, 111, 100, 98, 121, 101, 0, 0, 0];
        let key = into_bytes::from_utf8("YELLOW SUBMARINE");

        let expected_result = into_bytes::from_hex("15fd5f4f8b135545424e4925009210f6");

        assert_eq!(expected_result, aes_ecb(input_bytes, key));
    }
}