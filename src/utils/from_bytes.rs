extern crate base64;
use std::string::FromUtf8Error;

pub fn into_base64(bytes: Vec<u8>) -> String {
    base64::encode(bytes.as_slice())
}

pub fn into_hex(bytes: Vec<u8>) -> String {
    let strings: Vec<String> = bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    strings.join("")
}

pub fn into_utf8(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_base64(){
        let bytes : Vec<u8> = vec![15];

        let expected = String::from("Dw==");

        assert_eq!(expected, into_base64(bytes));
    }

    #[test]
    fn test_into_hex(){
        let bytes : Vec<u8> = vec![15];

        let expected = String::from("0F");

        assert_eq!(expected, into_hex(bytes));
    }

    #[test]
    fn test_into_utf8(){
        let bytes : Vec<u8> = vec![65];

        let expected = String::from("A");

        assert_eq!(expected, into_utf8(bytes));
    }
}