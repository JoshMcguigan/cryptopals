use utils::*;

#[test]
fn challenge_9() {
    let input_bytes = into_bytes::from_utf8("YELLOW SUBMARINE");
    let block_size = 20usize;

    let expected_bytes = vec![89u8, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4];
    assert_eq!(expected_bytes, into_bytes::with_padding(input_bytes, block_size));
}
