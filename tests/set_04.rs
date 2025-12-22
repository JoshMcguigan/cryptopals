use cryptopals::aes;

#[test]
fn challenge_25() {
    let encrypt = {
        let key = b"YELLOW SUBMARINE";
        let nonce = 5;

        move |plaintext| aes::ctr(key.into(), plaintext, nonce)
    };
    let secret_plaintext = b"123456789012345612345678901234561234567890123456";

    let ciphertext = encrypt(secret_plaintext);

    // Now recover the plaintext, given the ability to re-encrypt. I've modified
    // the challenge to simplify the setup. Rather than being able to re-encrypt
    // at any particular offset, you must re-encrypt the whole plaintext.

    let recovered_plaintext = encrypt(&ciphertext);

    assert_eq!(secret_plaintext, recovered_plaintext.as_slice());
}

#[test]
fn challenge_26() {
    let encrypt_decrypt = {
        let key = b"YELLOW SUBMARINE";
        let nonce = 5;

        move |plaintext| aes::ctr(key.into(), plaintext, nonce)
    };
    let secret_plaintext = b";admin=0;";

    let mut ciphertext = encrypt_decrypt(secret_plaintext);
    // Convert ascii 0 to ascii 1
    ciphertext[7] |= 0b1;

    let modified_plaintext = encrypt_decrypt(&ciphertext);

    assert!(
        String::from_utf8(modified_plaintext)
            .expect("must be valid ascii")
            .contains("admin=1")
    );
}
