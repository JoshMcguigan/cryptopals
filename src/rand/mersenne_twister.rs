//! Implementation of Mersenne Twister, per <https://en.wikipedia.org/wiki/Mersenne_Twister>.

/// Word size in bits
const W: u32 = 32;
/// Degree of recurrence
const N: u32 = 624;
/// Middle word
const M: u32 = 397;
/// Separation point of one word
const R: u32 = 31;

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

const UMASK: u32 = 0xffffffff << R;
const LMASK: u32 = 0xffffffff >> (W - R);

pub struct Mt19937 {
    state_array: [u32; N as usize],
    state_index: usize,
}

impl Mt19937 {
    pub fn new(mut seed: u32) -> Self {
        let mut state_array = [0; N as usize];

        state_array[0] = seed;

        state_array
            .iter_mut()
            .enumerate()
            .skip(1)
            .for_each(|(i, state_array_item)| {
                seed = F.wrapping_mul(seed ^ (seed >> (W - 2))) + (i as u32);
                *state_array_item = seed;
            });

        Self {
            state_array,
            state_index: 0,
        }
    }

    pub fn random_u32(&mut self) -> u32 {
        let mut k = self.state_index as i32;

        let mut j = k - (N as i32 - 1);
        if j < 0 {
            j += N as i32;
        }

        let mut x = (self.state_array[k as usize] & UMASK) | (self.state_array[j as usize] & LMASK);

        let mut x_a = x >> 1;
        if x & 0x00000001 == 0x1 {
            x_a ^= A;
        }

        j = k - (N as i32 - M as i32);
        if j < 0 {
            j += N as i32;
        }

        x = self.state_array[j as usize] ^ x_a;
        self.state_array[k as usize] = x;
        k += 1;

        if k >= N as i32 {
            k = 0;
        }
        self.state_index = k as usize;

        let mut y = x ^ (x >> U);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);

        y ^ (y >> L)
    }
}
