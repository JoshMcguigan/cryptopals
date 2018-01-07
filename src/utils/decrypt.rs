use super::*;

pub struct DecryptedMessage {
    pub decrypted_message: String,
    pub key: Vec<u8>,
    pub score: f32
}

impl DecryptedMessage {
    pub fn new() -> DecryptedMessage {
        DecryptedMessage {
            score: -9999f32,
            key: Vec::new(),
            decrypted_message: String::new()
        }
    }
}

pub fn single_byte_xor(input: Vec<u8>) -> DecryptedMessage {

    let mut result = DecryptedMessage::new();

    for key in 0u8..127u8 {
        let decrypted_bytes = encrypt::repeating_key_xor(input.clone(), vec![key]);
        let decrypted_string = from_bytes::into_utf8(decrypted_bytes);

        match decrypted_string {
            Err(_err) => {},
            Ok(decrypted_string) => {
                let score = plain_text_analysis::get_score(decrypted_string.as_ref());

                if score > result.score {
                    result.score = score;
                    result.key = vec![key];
                    result.decrypted_message = decrypted_string;
                }
            }
        }

    }

    result
}

fn multi_byte_xor_for_key_size(input: Vec<u8>, key_size: usize) -> DecryptedMessage {
    DecryptedMessage::new()
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

//        assert_eq!(expected_decrypted_message, multi_byte_xor_for_key_size(encrypted_message_bytes, key_size).decrypted_message);
    }

}