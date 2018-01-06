pub fn get_score(input: &str) -> f32 {
    // Scores plain text input, higher scores indicate greater likelihood that the input is english plain text

    let lower_case_input = input.to_lowercase();
    let mut score : f32 = 0f32;
    for char in lower_case_input.chars() {
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
        _   => -10.000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_score() {
        let input = "Josh";
        let expected_score : f32 = 5.02025;

        assert_eq!(expected_score, get_score(input));
    }

}
