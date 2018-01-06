pub fn repeating_key_xor(input: Vec<u8>, key: Vec<u8>) -> Vec<u8> {

    let mut result_bytes : Vec<u8> = Vec::new();

    for (index, input_byte) in input.iter().enumerate() {
        let key_index = index % key.len();
        let key_byte : &u8 = key.get(key_index).unwrap();
        result_bytes.push(input_byte ^ key_byte);
    }

    result_bytes
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
}