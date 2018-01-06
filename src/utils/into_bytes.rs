pub fn from_hex(input_string: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(input_string.len()/2) {
        let result = u8::from_str_radix(&input_string[2*i .. 2*i+2], 16);
        bytes.push(result.unwrap());
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
}