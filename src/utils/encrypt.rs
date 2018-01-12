use super::*;
use self::constants::*;

extern crate itertools;
use self::itertools::Itertools;

extern crate openssl;
use self::openssl::symm::{Cipher, Crypter, Mode};

pub fn repeating_key_xor(input: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    // TODO: move this functionality as it is used more generally than just encryption
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

pub fn aes_cbc(input: Vec<u8>, key: Vec<u8>, init_vector: Vec<u8>) -> Vec<u8> {
    // Initialization vector size must be equal to one block (16 bytes)
    assert_eq!(AES_BLOCK_SIZE_IN_BYTES, init_vector.len());

    let input = into_bytes::with_padding(input, AES_BLOCK_SIZE_IN_BYTES);

    let mut result = Vec::new();

    for byte_index in (0..input.len()).step(AES_BLOCK_SIZE_IN_BYTES) {
        let input_block = input[byte_index..(byte_index + AES_BLOCK_SIZE_IN_BYTES)].to_vec();

        let xor_with = match byte_index {
            0 => init_vector.clone(),
            _ => {
                let previous_block_of_encrypted_data = result[(byte_index-AES_BLOCK_SIZE_IN_BYTES)..byte_index].to_vec();
                previous_block_of_encrypted_data
            }
        };

        let xored_block = encrypt::repeating_key_xor(input_block, xor_with);

        let mut encrypted_block = aes_ecb(xored_block, key.clone());

        result.append(&mut encrypted_block);
    }

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

    #[test]
    fn test_aes_cbc(){
        let input_bytes = into_bytes::from_utf8("CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.\r\n\r\nIn CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.\r\n\r\nThe first plaintext block, which has no associated previous ciphertext block, is added to a \"fake 0th ciphertext block\" called the initialization vector, or IV.\r\n\r\nImplement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.");
        let key = into_bytes::from_hex("0123456789ABCDEF0123456789ABCDEF");
        let iv = vec![0u8; 16];

        let encrypted_data = from_bytes::into_hex(aes_cbc(input_bytes, key, iv));

        let expected_result = String::from("0B1ED2DF0D717A2CC0B1514AE264215A8C73C251B97BB83448C4D985ECD7F179491D2541EB85BF422C8877573B4A0CE06B4C0F030F6B9C8E4FE222CBCBA27405137B1F1B4F290D72C1E980F8253A695E19B18AB880C3CC0107D4B461FDE0996108BF18C792A4C18EEAACD0FC3282E36FFE9BF834DF27FC9FFA99E8EFC8583401D35A7BEE51F00EBD30FE088F1E153DBD02A0D038D4D05FF8594A8CAB9EC326A7FAF0D89581CB02417546579496D502E0484C9AAB8C4797F8AA241BA8CA14A36F2BF944F93BB4348C2C36E4C6B9972874EF06B5430EA5CC330B707B47504C2356F1E151AD8311DCD42D714E45CE5433E1870B26520876409A2B5E0A9D83A0F576E72F4D5AD950F490F21EC0A5181543B2B5DD8C422775DE77A99CA635DB7B767FA3386ABD47186398D3279635E14B7FA15A9F903C5899FADD41C9CF8687A75CD8C39B34E448E3BB8553361056E0E3797FE0F021C3D8728F86CDFF44B8495182F4D24711578BCE963C506AEC5AC3FD26B2F049DDCDAC25DEE15363C43578C0C584A40FAA30E8FE9EE38494A03744AF512B099CF39A16DFE949E8D3364DEFC571B45C39408EDF2E9BBEF811B70CAD6CA77D5D946A5C3412EDE030209FE0D99D97C1E2036EA22778FCD075FC9D484ED8FBCC07D198E8DA94DB20B05943C67B01A42432CE549C3B3F39BE69D7D7A935C277A437F3EFF14A8FAC39294F5B6612EE1E0B999D3D6B7D7D45CA6AAEB18031B17B248C9A34727C1344D3DE7601930CE1CAD1CD0CD19521D128F771DD4C3F8320D3529384367D778770CE89BB9C8808D4C0314BCFF0505CCDA0E816AD99CA36CA214002DCFE286E6EFD0D8E04815665A1321578F31C553AA6395B6162CCFF6B773202DCB5BA7501762B91E46DAF7588CB3888B709975A57B91BF06349EC7559E5048C477C2D9D404A03FE714600821B3F9D7D88C96EE17E774EBC93730E863490987087B5690BFF264673A6B46CB3B5CC75C9");

        assert_eq!(expected_result, encrypted_data);
    }
}