use super::*;

pub struct DecryptedMessage {
    pub decrypted_message: String,
    pub key: Vec<u8>,
    pub score: f32
}

pub fn single_byte_xor(input: Vec<u8>) -> DecryptedMessage {

    let mut result = DecryptedMessage {
        score: -9999f32,
        key: Vec::new(),
        decrypted_message: String::new()
    };

    for key in 0u8..127u8 {
        let decrypted_bytes = xor::repeating_key_xor(input.clone(), vec![key]);
        let decrypted_string = from_bytes::into_utf8(decrypted_bytes);

        let score = plain_text_analysis::get_score(decrypted_string.as_ref());

        if score > result.score {
            result.score = score;
            result.key = vec![key];
            result.decrypted_message = decrypted_string;
        }
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

}