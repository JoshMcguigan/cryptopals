pub fn get_score(input: &Vec<u8>) -> f32 {
    // Scores plain text input, higher scores indicate greater likelihood that the input is english plain text
    let mut score = 0f32;
    for byte in input {
        let char = (byte.clone() as char).to_ascii_lowercase();
        score += char_to_score(char);
    }
    score / (input.len() as f32)
}

fn char_to_score(char: char) -> f32 {
    //https://en.wikipedia.org/wiki/Letter_frequency
    match char {
        'a' => 8.167,
        'b' => 1.492,
        'c' => 2.782,
        'd' => 4.253,
        'e' => 12.702,
        'f' => 2.228,
        'g' => 2.015,
        'h' => 6.094,
        'i' => 6.966,
        'j' => 0.153,
        'k' => 0.772,
        'l' => 4.025,
        'm' => 2.406,
        'n' => 6.749,
        'o' => 7.507,
        'p' => 1.929,
        'q' => 0.095,
        'r' => 5.987,
        's' => 6.327,
        't' => 9.056,
        'u' => 2.758,
        'v' => 0.978,
        'w' => 2.360,
        'x' => 0.150,
        'y' => 1.974,
        'z' => 0.074,
        ' ' => 0.000,
        '.' => 0.000,
        ',' => 0.000,
        ';' => 0.000,
        ':' => 0.000,
        '\'' => 0.000,
        '\n' => 0.000,
        _   => -10.000
    }
}

pub fn detect_repeating_blocks(input: &Vec<u8>, repeat_length: usize) -> bool {
    for i in 0..(input.len()-repeat_length) {
        let byte_block = &input[i..i+repeat_length];
        for j in i+repeat_length..(input.len()-repeat_length) {
            if byte_block == &input[j..j+repeat_length]{
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_score() {
        let input = vec![74u8, 111, 115, 104];
        let expected_score : f32 = 5.02025;

        assert_eq!(expected_score, get_score(&input));
    }

    #[test]
    fn test_get_score_should_return_low_score_for_non_ascii() {
        let input = vec![29u8, 31];
        let expected_score = -10f32;

        assert_eq!(expected_score, get_score(&input));
    }

    #[test]
    fn test_detect_repeating_blocks_for_non_repeating_sequence() {
        let input = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        assert!(!detect_repeating_blocks(&input, 2));
    }

    #[test]
    fn test_detect_repeating_blocks_for_repeating_sequence() {
        let input = vec![1u8, 2, 3, 2, 3, 6, 7, 8];
        assert!(detect_repeating_blocks(&input, 2));
    }

}
