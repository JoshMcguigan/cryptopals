extern crate base64;

pub fn from_hex(input: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(input.len()/2) {
        let result = u8::from_str_radix(&input[2*i .. 2*i+2], 16);
        bytes.push(result.unwrap());
    };
    bytes
}

pub fn from_utf8(input: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for byte in input.as_bytes() {
        bytes.push(byte.clone());
    };
    bytes
}

pub fn from_base64(input: &str) -> Vec<u8> {
    base64::decode_config(input, base64::MIME).unwrap()
}

pub fn with_padding(mut input: Vec<u8>, block_size: usize) -> Vec<u8> {
    // Returns a vector whose number of bytes is an even multiple of the block size

    let padding_byte = 4u8;

    let padding_bytes_needed = block_size - (input.len() % block_size);

    for _i in 0..padding_bytes_needed {
        input.push(padding_byte);
    }

    input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_hex(){
        let expected : Vec<u8> = vec![15];

        assert_eq!(expected, from_hex("0F"));
    }

    #[test]
    fn test_from_utf8(){
        let expected : Vec<u8> = vec![65];

        assert_eq!(expected, from_utf8("A"));
    }

    #[test]
    fn test_from_base64() {
        let expected: Vec<u8> = vec![65, 66, 67];

        assert_eq!(expected, from_base64("QUJD"));
    }

    #[test]
    fn test_from_base64_and_ignores_whitespace() {
        let expected: Vec<u8> = vec![65, 66, 67];

        assert_eq!(expected, from_base64("QU\nJD"));
    }

    #[test]
    fn test_with_padding() {
        let input = "JOSH";
        let block_size = 8usize;

        let expected_bytes = vec![74u8, 79, 83, 72, 4, 4, 4, 4];
        assert_eq!(expected_bytes, with_padding(from_utf8(input), block_size));
    }

}