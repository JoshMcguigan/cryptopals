use aes::{
    Aes128,
    cipher::{BlockDecrypt as _, BlockEncryptMut as _, Key, KeyInit as _},
};

use crate::pad::{pkcs7, pkcs7_remove};

const AES_BLOCK_SIZE: u8 = 16;

/// Encrypts with AES ECB.
///
/// Padding bytes is added per PKCS#7.
pub fn ecb_encrypt(key: &Key<Aes128>, plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = Aes128::new(key);

    let mut ciphertext = Vec::from(plaintext);
    pkcs7(&mut ciphertext, AES_BLOCK_SIZE);

    for ciphertext_block in ciphertext.chunks_exact_mut(AES_BLOCK_SIZE as usize) {
        cipher.encrypt_block_mut(ciphertext_block.into());
    }

    ciphertext
}

/// Decrypts AES ECB. Ciphertext length should be a multiple of the block
/// size, trailing bytes which don't fill a block are ignored.
///
/// Padding bytes are removed per PKCS#7.
pub fn ecb_decrypt(key: &Key<Aes128>, ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key);
    let mut plaintext = vec![0; ciphertext.len()];
    for (i, cipher_block) in ciphertext.chunks_exact(AES_BLOCK_SIZE as usize).enumerate() {
        cipher.decrypt_block_b2b(
            cipher_block.into(),
            (&mut plaintext[(AES_BLOCK_SIZE as usize * i)..(AES_BLOCK_SIZE as usize * (i + 1))])
                .into(),
        );
    }

    pkcs7_remove(&mut plaintext);

    plaintext
}

/// Encrypts with AES CBC.
///
/// `iv` length must equal the block size.
///
/// Padding bytes are added per PKCS#7.
pub fn cbc_encrypt(key: &Key<Aes128>, plaintext: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut cipher = Aes128::new(key);
    let mut ciphertext = Vec::from(plaintext);
    pkcs7(&mut ciphertext, AES_BLOCK_SIZE);

    let mut previous_cipher_block = iv;

    for cipher_block in ciphertext.chunks_exact_mut(AES_BLOCK_SIZE as usize) {
        for i in 0..(AES_BLOCK_SIZE as usize) {
            cipher_block[i] ^= previous_cipher_block[i];
        }
        cipher.encrypt_block_mut(cipher_block.into());

        previous_cipher_block = cipher_block;
    }

    ciphertext
}

/// Decrypts AES CBC. Ciphertext length should be a multiple of the block
/// size, trailing bytes which don't fill a block are ignored.
///
/// `iv` length must equal the block size.
///
/// Padding bytes are removed per PKCS#7.
pub fn cbc_decrypt(key: &Key<Aes128>, ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key);
    let mut plaintext = vec![0; ciphertext.len()];
    let mut previous_cipher_block = iv;

    for (cipher_block, plaintext_block) in ciphertext
        .chunks_exact(AES_BLOCK_SIZE as usize)
        .zip(plaintext.chunks_exact_mut(AES_BLOCK_SIZE as usize))
    {
        cipher.decrypt_block_b2b(cipher_block.into(), plaintext_block.into());

        for i in 0..(AES_BLOCK_SIZE as usize) {
            plaintext_block[i] ^= previous_cipher_block[i];
        }
        previous_cipher_block = cipher_block;
    }

    pkcs7_remove(&mut plaintext);

    plaintext
}

#[cfg(test)]
mod tests {
    use super::{cbc_decrypt, cbc_encrypt, ecb_decrypt, ecb_encrypt};

    #[test]
    fn ecb_round_trip() {
        let key = b"YELLOW SUBMARINE".into();
        let plaintext = b"what time is it game time, what time is it game time";

        assert_eq!(
            plaintext[..],
            ecb_decrypt(key, &ecb_encrypt(key, plaintext))[..]
        );
    }

    #[test]
    fn cbc_round_trip() {
        let key = b"YELLOW SUBMARINE".into();
        let iv = b"RANDOM IV WOWOWW";
        let plaintext = b"what time is it game time, what time is it game time";

        assert_eq!(
            plaintext[..],
            cbc_decrypt(key, &cbc_encrypt(key, plaintext, iv), iv)[..]
        );
    }
}
