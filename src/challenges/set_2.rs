use utils::*;
use std::io::prelude::*;
use std::fs::File;

extern crate rand;
use self::rand::Rng;

fn random_aes_key() -> Vec<u8> {
    get_random_bytes(constants::AES_BLOCK_SIZE_IN_BYTES)
}

fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut output = Vec::new();

    for _i in 0..size {
        let random_byte: u8 = rand::thread_rng().gen();
        output.push(random_byte);
    }

    output
}

fn encryption_oracle(input: Vec<u8>) -> Vec<u8> {
    let length_of_random_bytes_to_prepend = rand::thread_rng().gen_range(5,10);
    let length_of_random_bytes_to_append = rand::thread_rng().gen_range(5,10);

    let mut mutated_input = get_random_bytes(length_of_random_bytes_to_prepend);
    mutated_input.append(&mut input.clone());
    mutated_input.append(&mut get_random_bytes(length_of_random_bytes_to_append));

    let random_boolean: bool = rand::thread_rng().gen();

    if random_boolean {
        encrypt::aes_ecb(mutated_input, random_aes_key())
    } else {
        encrypt::aes_cbc(mutated_input, random_aes_key(), random_aes_key())
    }
}

#[test]
fn challenge_9() {
    let input_bytes = into_bytes::from_utf8("YELLOW SUBMARINE");
    let block_size = 20usize;

    let expected_bytes = vec![89u8, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4];
    assert_eq!(expected_bytes, into_bytes::with_padding(input_bytes, block_size));
}

#[test]
fn challenge_10() {
    let mut file = File::open("resources/set_2/challenge_10.txt").unwrap();
    let mut contents = String::new();
    let _file_read_result = file.read_to_string(&mut contents);
    let input_bytes = into_bytes::from_base64(&contents);
    let key = into_bytes::from_utf8("YELLOW SUBMARINE");
    let iv = vec![0u8; 16];

    let decrypted_bytes = decrypt::aes_cbc(input_bytes, key, iv);

    let expected_result = String::from("I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}\u{14}\u{17}}`A�ױ�3o5f\u{e}�~");

    assert_eq!(expected_result, from_bytes::into_utf8(decrypted_bytes));
}

#[test]
fn challenge_11() {
    let input = into_bytes::from_utf8("Now that you have ECB and CBC working: Write a function to generate a random AES key; that's just 16 random bytes. Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.");

    println!("Encrypted output, hex encoded: {:?}", from_bytes::into_hex(encryption_oracle(input)));


    // TODO need to write analysis tool to detect CBC vs ECB from encryption oracle
}
