pub fn pkcs7(text: &mut Vec<u8>, block_size: u8) {
    // In pkcs7 this value is both the number of padding bytes and the value of
    // the padding bytes.
    let padding_bytes = block_size - (text.len() % (block_size as usize)) as u8;

    text.resize(text.len() + padding_bytes as usize, padding_bytes);
}

pub fn pkcs7_remove(text: &mut Vec<u8>) {
    // We could validate that each of the padding bytes has the same
    // value as the last byte, and that the value is <= block size,
    // but we don't do that here.
    if let Some(last_byte) = text.last().copied() {
        text.truncate(text.len() - last_byte as usize);
    }
}

pub fn pkcs7_valid(text: &[u8]) -> bool {
    if !text.len().is_multiple_of(16) {
        return false;
    }

    if let Some(last_byte) = text.last().copied() {
        if last_byte as usize > 16 {
            return false;
        }

        text.iter()
            .rev()
            .copied()
            .take(last_byte as usize)
            .all(|b| b == last_byte)
    } else {
        // If there is no last byte, the padding is not valid.
        false
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
