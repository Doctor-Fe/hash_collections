use std::fmt::Display;

use crate::Hasher;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug, Clone)]
pub struct Sha256 {
    buffer: [u8; 64],
    length: usize,
    result: [u32; 8],
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            buffer: [0; 64],
            length: 0,
            result: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
        }
    }

    fn proceed(&mut self) {
        let mut tmp = [0u32; 16];
        for i in 0..16 {
            tmp[i] = u32::from_be_bytes([self.buffer[i << 2], self.buffer[(i << 2) + 1], self.buffer[(i << 2) + 2], self.buffer[(i << 2) + 3]])
        }
        let mut w = [0; 64];
        for t in 0..64 {
            if t < 16 {
                w[t] = tmp[t];
            } else {
                w[t] = sigma_s_1(w[t - 2]).wrapping_add(w[t - 7])
                    .wrapping_add(sigma_s_0(w[t - 15]))
                    .wrapping_add(w[t - 16])
                ;
            }
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.result;
        for t in 0..64 {
            let t1 = h.wrapping_add(sigma_l_1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = sigma_l_0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.result[0] = self.result[0].wrapping_add(a);
        self.result[1] = self.result[1].wrapping_add(b);
        self.result[2] = self.result[2].wrapping_add(c);
        self.result[3] = self.result[3].wrapping_add(d);
        self.result[4] = self.result[4].wrapping_add(e);
        self.result[5] = self.result[5].wrapping_add(f);
        self.result[6] = self.result[6].wrapping_add(g);
        self.result[7] = self.result[7].wrapping_add(h);
    }
}

impl Hasher<Sha256Result> for Sha256 {
    fn push(&mut self, data: u8) {
        self.buffer[self.length & 63] = data;
        self.length += 1;
        if self.length & 63 == 0 {
            self.proceed();
        }
    }

    fn finish(mut self) -> Sha256Result {
        let len = self.length * 8;
        // Padding
        self.push(0b10000000);
        while self.length % 64 != 56 {
            self.push(0);
        }
        let t = len.to_be_bytes();
        self.push_all(&t);

        Sha256Result::new(self.result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256Result {
    data: [u32; 8],
}

impl Sha256Result {
    fn new(data: [u32; 8]) -> Self {
        Self { data }
    }

    pub fn get(&self, index: usize) -> Option<&u32> {
        self.data.get(index)
    }
}

impl Display for Sha256Result {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for &i in &self.data {
            write!(f, "{i:08x}")?;
        }
        return Ok(());
    }
}

#[inline(always)]
const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
const fn sigma_l_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
const fn sigma_l_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
const fn sigma_s_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
const fn sigma_s_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
