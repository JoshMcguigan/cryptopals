use cryptopals::pad::pkcs7;

use insta::assert_debug_snapshot;

#[test]
fn challenge_09() {
    let input_text = b"YELLOW SUBMARINE";

    let mut text = Vec::from(input_text);
    pkcs7(&mut text, 20);

    assert_eq!(20, text.len());
    assert_debug_snapshot!(text);
}
