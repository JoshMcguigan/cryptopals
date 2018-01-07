mod utils;

#[cfg(test)]
mod set_1 {
    use utils::*;
    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufRead;

    #[test]
    fn challenge_1() {
        let hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let actual_base64 = from_bytes::into_base64(into_bytes::from_hex(hex_input));

        assert_eq!(expected_base64, actual_base64);
    }

    #[test]
    fn challenge_2() {
        let in1 = "1c0111001f010100061a024b53535009181c";
        let in2 = "686974207468652062756c6c277320657965";
        let expected_hex = String::from("746865206b696420646f6e277420706c6179");

        let xor_result = xor::repeating_key_xor(into_bytes::from_hex(in1),
                                               into_bytes::from_hex(in2));
        let actual_hex = from_bytes::into_hex(xor_result);

        assert_eq!(expected_hex, actual_hex.to_lowercase());
    }

    #[test]
    fn challenge_3() {
        let hex_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let input_bytes = into_bytes::from_hex(hex_input);

        let expected_message = "Cooking MC\'s like a pound of bacon";

        assert_eq!(expected_message, decrypt::single_byte_xor(input_bytes).decrypted_message);
    }

    #[test]
    fn challenge_4() {
        let mut decrypted_message = decrypt::DecryptedMessage {
            decrypted_message: String::new(),
            key: Vec::new(),
            score: -9999f32,
        };

        let file = File::open("resources/set_1/challenge_4.txt").unwrap();
        for line in BufReader::new(file).lines() {
            let line_string = line.unwrap();
            let line_hex = line_string.as_ref();
            let line_bytes = into_bytes::from_hex(line_hex);
            let result = decrypt::single_byte_xor(line_bytes);
            if result.score > decrypted_message.score {
                decrypted_message = result;
            }
        }

        let expected_message = String::from("Now that the party is jumping\n");
        assert_eq!(expected_message, decrypted_message.decrypted_message)
    }
//
//    #[test]
//    fn challenge_5() {
//        let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
//        let key = "ICE";
//
//        let expected_encrypted_message = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
//
//        assert_eq!(expected_encrypted_message, repeating_key_xor_encrypt(message, key));
//    }
}