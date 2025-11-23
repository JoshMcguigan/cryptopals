pub mod analysis;

/// Performs repeating key XOR.
///
/// Can also perform fixed key XOR if `b` is the same length as `a`, or
/// single-byte XOR if `b` is a single byte.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter().cycle()).map(|(a, b)| a ^ b).collect()
}

pub struct PossibleBreak {
    /// Score is only comparable across results from the same scorer function.
    pub score: f64,
    pub possible_key: Vec<u8>,
    pub possible_plaintext: Vec<u8>,
}

/// Attempts to break repeating key XOR.
///
/// Returns the most likely plaintext.
pub fn break_xor(
    ciphertext: &[u8],
    #[expect(unused, reason = "not yet implemented")] possible_key_len: impl std::ops::RangeBounds<
        usize,
    >,
    plaintext_scorer: fn(&[u8]) -> f64,
) -> PossibleBreak {
    (u8::MIN..=u8::MAX)
        .map(|possible_key| {
            let possible_plaintext = xor(ciphertext, &[possible_key]);
            let score = plaintext_scorer(&possible_plaintext);
            (score, possible_key, possible_plaintext)
        })
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .map(|(score, key, plaintext)| PossibleBreak {
            score,
            possible_key: vec![key],
            possible_plaintext: plaintext,
        })
        .expect("there must be some max because we iterated over all possible keys")
}
