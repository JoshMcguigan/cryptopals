pub fn plaintext_scorer_english_prose(plaintext: &[u8]) -> f64 {
    // https://en.wikipedia.org/wiki/Letter_frequency
    fn char_to_score(char: char) -> f64 {
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
            _ => -10.000,
        }
    }

    let mut score = 0f64;
    for byte in plaintext.iter().copied() {
        let char = (byte as char).to_ascii_lowercase();
        score += char_to_score(char);
    }

    score / (plaintext.len() as f64)
}
