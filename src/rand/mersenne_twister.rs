//! Implementation of Mersenne Twister, per <https://en.wikipedia.org/wiki/Mersenne_Twister>
//! and <https://create.stephan-brumme.com/mersenne-twister/>.

/// Degree of recurrence
const N: u32 = 624;
/// Middle word
const M: u32 = 397;

/// Coefficients of the rational normal form twist matrix
const A: u32 = 0x9908b0df;

/// TGFSR(R) tempering bitmask
const B: u32 = 0x9d2c5680;
/// TGFSR(R) tempering bitmask
const C: u32 = 0xefc60000;

/// TGFSR(R) tempering bit shift
const S: u32 = 7;
/// TGFSR(R) tempering bit shift
const T: u32 = 15;

/// Additional Mersenne Twister tempering bit shift/mask
const U: u32 = 11;
const L: u32 = 18;

/// Multiplier used for state initialization
const F: u32 = 1812433253;

pub struct Mt19937 {
    state_array: [u32; N as usize],
    state_index: usize,
}

impl Mt19937 {
    pub fn new(seed: u32) -> Self {
        let mut state_array = [0; N as usize];

        state_array[0] = seed;

        for i in 1..(N as usize) {
            state_array[i] = F
                .wrapping_mul(state_array[i - 1] ^ (state_array[i - 1] >> 30))
                .wrapping_add(i as u32);
        }

        let mut s = Self {
            state_array,
            state_index: 0,
        };

        s.twist();

        s
    }

    pub fn from_samples(samples: [u32; N as usize]) -> Self {
        let mut state_array = [0; N as usize];

        for (sample, state) in samples.iter().copied().zip(state_array.iter_mut()) {
            *state = reverse(sample);
        }

        Self {
            state_array,
            state_index: N as usize,
        }
    }

    fn twist(&mut self) {
        let first_part = (N - M) as usize;

        for i in 0..first_part {
            let bits = (self.state_array[i] & 0x80000000) | (self.state_array[i + 1] & 0x7fffffff);
            self.state_array[i] = self.state_array[i + M as usize] ^ (bits >> 1) ^ ((bits & 1) * A);
        }

        for i in first_part..(N as usize - 1) {
            let bits = (self.state_array[i] & 0x80000000) | (self.state_array[i + 1] & 0x7fffffff);
            self.state_array[i] = self.state_array[i - first_part] ^ (bits >> 1) ^ ((bits & 1) * A);
        }

        let i = N as usize - 1;
        let bits = (self.state_array[i] & 0x80000000) | (self.state_array[0] & 0x7fffffff);
        self.state_array[i] = self.state_array[M as usize - 1] ^ (bits >> 1) ^ ((bits & 1) * A);

        self.state_index = 0;
    }

    pub fn random_u32(&mut self) -> u32 {
        if self.state_index >= N as usize {
            self.twist();
        }

        let x = self.state_array[self.state_index];
        self.state_index += 1;

        let mut y = x;
        y = y ^ (y >> U);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);

        y ^ (y >> L)
    }
}

/// Implementation from <https://docs.rs/mersenne_twister/1.1.1/src/mersenne_twister/mt19937.rs.html#173-192>.
fn reverse(mut x: u32) -> u32 {
    // reverse "x ^=  x>>18;"
    x ^= x >> 18;

    // reverse "x ^= (x<<15) & 0xefc60000;"
    x ^= (x << 15) & 0x2fc60000;
    x ^= (x << 15) & 0xc0000000;

    // reverse "x ^= (x<< 7) & 0x9d2c5680;"
    x ^= (x << 7) & 0x00001680;
    x ^= (x << 7) & 0x000c4000;
    x ^= (x << 7) & 0x0d200000;
    x ^= (x << 7) & 0x90000000;

    // reverse "x ^=  x>>11;"
    x ^= x >> 11;
    x ^= x >> 22;

    x
}

#[cfg(test)]
mod tests {
    use super::{Mt19937, reverse};

    #[test]
    fn matches_vectors() {
        let mut rand_source = Mt19937::new(1131464071);
        let vectors = include_str!("mt19937_vectors.txt")
            .lines()
            .skip(3)
            .map(|s| s.parse::<u32>().expect("input should be valid u32"))
            .collect::<Vec<u32>>();
        for vector in vectors {
            assert_eq!(vector, rand_source.random_u32());
        }
    }

    #[test]
    fn reverse_single_val() {
        let mut rand_source = Mt19937::new(1131464071);
        let rand_val = rand_source.random_u32();

        assert_eq!(rand_source.state_array[0], reverse(rand_val));
    }
}
