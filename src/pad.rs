pub fn pkcs7(text: &mut Vec<u8>, block_size: u8) {
    // In pkcs7 this value is both the number of padding bytes and the value of
    // the padding bytes.
    let padding_bytes = block_size - (text.len() % (block_size as usize)) as u8;

    text.resize(text.len() + padding_bytes as usize, padding_bytes);
}

pub fn pkcs7_remove(text: &mut Vec<u8>) {
    // We could validate that each of the padding bytes has the same
    // value as the last byte, and that but we don't do that here.
    if let Some(last_byte) = text.last().copied() {
        text.truncate(text.len() - last_byte as usize);
    }
}

#[cfg(test)]
mod tests {
    use crate::pad::pkcs7;

    #[test]
    fn pad_empty() {
        let mut text = vec![];
        pkcs7(&mut text, 4);
        assert_eq!(vec![4, 4, 4, 4], text);
    }

    #[test]
    fn pad_partial() {
        let mut text = vec![1, 1];
        pkcs7(&mut text, 4);
        assert_eq!(vec![1, 1, 2, 2], text);
    }

    #[test]
    fn pad_full() {
        let mut text = vec![2, 2, 2, 2];
        pkcs7(&mut text, 4);
        assert_eq!(vec![2, 2, 2, 2, 4, 4, 4, 4], text);
    }
}
