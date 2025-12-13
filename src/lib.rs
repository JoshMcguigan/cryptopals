use std::num::NonZero;

pub mod aes;
pub mod analysis;
pub mod pad;
pub mod rand;

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
    keysize: usize,
    plaintext_scorer: fn(&[u8]) -> f64,
) -> PossibleBreak {
    let mut ret = (0..keysize)
        .map(|i| {
            let chunk = ciphertext
                .iter()
                .copied()
                .skip(i)
                .step_by(keysize)
                .collect::<Vec<u8>>();
            (i, break_single_byte_xor(&chunk, plaintext_scorer))
        })
        .fold(
            PossibleBreak {
                score: 0.,
                possible_key: vec![],
                possible_plaintext: vec![0; ciphertext.len()],
            },
            |mut acc, (i, e)| {
                acc.score += e.score;
                acc.possible_key.push(e.possible_key[0]);

                e.possible_plaintext
                    .iter()
                    .copied()
                    .enumerate()
                    .for_each(|(j, b)| {
                        acc.possible_plaintext[i + j * keysize] = b;
                    });

                acc
            },
        );

    ret.score /= keysize as f64;

    ret
}

pub fn break_single_byte_xor(
    ciphertext: &[u8],
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

/// Find likely XOR keysize assuming ASCII-ish plaintext.
pub fn find_xor_keysize(ciphertext: &[u8], max_key_len: NonZero<usize>) -> NonZero<usize> {
    (1..=max_key_len.into())
        .map(|keysize| {
            let first_chunk = &ciphertext[0..keysize];

            let bits_diff_per_byte = ciphertext
                .chunks_exact(keysize)
                .skip(1)
                .map(|n_th_chunk| {
                    first_chunk
                        .iter()
                        .copied()
                        .zip(n_th_chunk)
                        .map(|(b1, b2)| (b1 ^ b2).count_ones() as usize)
                        .sum::<usize>() as f64
                        / keysize as f64
                })
                .sum::<f64>()
                / (ciphertext.len() / keysize) as f64;

            (keysize, bits_diff_per_byte)
        })
        .find(|(_keysize, bits_diff_per_byte)| *bits_diff_per_byte < 2.9)
        // TODO
        // This function should return option here.
        .expect("must find key size")
        .0
        .try_into()
        .expect("key size known to be non-zero")
}
