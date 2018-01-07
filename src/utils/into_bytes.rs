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
}