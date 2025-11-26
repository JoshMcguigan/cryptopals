use aes::{
    Aes128,
    cipher::{BlockDecrypt as _, Key, KeyInit as _},
};

use crate::pad::pkcs7_remove;

/// Decrypts AES ECB. Ciphertext length should be a multiple of the block
/// size, trailing bytes which don't fill a block are ignored.
///
/// Padding bytes are removed per PKCS#7.
pub fn ecb_decrypt(key: &Key<Aes128>, ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key);
    let mut plaintext = vec![0; ciphertext.len()];
    for (i, cipher_block) in ciphertext.chunks_exact(16).enumerate() {
        cipher.decrypt_block_b2b(
            cipher_block.into(),
            (&mut plaintext[(16 * i)..(16 * (i + 1))]).into(),
        );
    }

    pkcs7_remove(&mut plaintext);

    plaintext
}
