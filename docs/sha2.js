'use strict';

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

// 2.2.2 Symbols and Operations

// ROTL
function ROTL(x, n, w) {
    return (x << n) | (x >>> (w - n));
}

// ROTR
function ROTR(x, n, w) {
    return (x >>> n) | (x << (w - n));
}

// SHR
function SHR(x, n) {
    return x >>> n;
}

// 4. FUNCTIONS AND CONSTANTS
// 4.1.1 SHA-1 Functions

// (4.1)
function Parity(x, y, z) {
    return x ^ y ^ z;
}

// (4.1)(4.2)(4.8)
function Ch(x, y, z) {
    return (x & y) ^ (~x & z);
}

// (4.1)(4.3)(4.9)
function Maj(x, y, z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// (4.4)
function SIGMA0_256(x, w) {
    return ROTR(x, 2, w) ^ ROTR(x, 13, w) ^ ROTR(x, 22, w);
}

// (4.5)
function SIGMA1_256(x, w) {
    return ROTR(x, 6, w) ^ ROTR(x, 11, w) ^ ROTR(x, 25, w);
}

// (4.6)
function sigma0_256(x, w) {
    return ROTR(x, 7, w) ^ ROTR(x, 18, w) ^ SHR(x, 3);
}

// (4.7)
function sigma1_256(x, w) {
    return ROTR(x, 17, w) ^ ROTR(x, 19, w) ^ SHR(x, 10);
}

// (4.10)
function SIGMA0_512(x, w) {
    return ROTR(x, 28, w) ^ ROTR(x, 34, w) ^ ROTR(x, 39, w);
}

// (4.11)
function SIGMA1_512(x, w) {
    return ROTR(x, 14, w) ^ ROTR(x, 18, w) ^ ROTR(x, 41, w);
}

// (4.12)
function sigma0_512(x, w) {
    return ROTR(x, 1, w) ^ ROTR(x, 8, w) ^ SHR(x, 7);
}

// (4.13)
function sigma1_512(v, w) {
    return ROTR(x, 19, w) ^ ROTR(x, 61, w) ^ SHR(x, 6);
}

// 4.2 Constants
// 4.2.1 SHA-1 Constants
const SHA1_K = [
    0x5a827999,
    0x6ed9eba1,
    0x8f1bbcdc,
    0xca62c1d6,
];

// 4.2.2 SHA-224 and SHA-256 Constants

const SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// 5.1 Padding the Message

// 5.1.1 SHA-1, SHA-224 and SHA-256
function padding_256(M) {
    let len = M.length;
    let tmp = null;
    if (len % 64 < 56) {
        tmp = new Array(56 - len % 64);
    } else {
        tmp = new Array(64 + 56 - len % 64);
    }
    tmp.fill(0);
    tmp[0] = 0x80;
    let bs = M.concat(tmp);
    let bits = len * 8;
    let size = Array(8);
    size.fill(0);
    size[4] = (bits & 0xff000000) >> 24;
    size[5] = (bits & 0x00ff0000) >> 16;
    size[6] = (bits & 0x0000ff00) >> 8;
    size[7] = (bits & 0x000000ff);
    bs = bs.concat(size);
    return bs;
}

// 5.1.2 SHA-384, SHA-512, SHA-512/224 and SHA-512/256
function padding_512(M) {
    let len = M.length;
    let tmp = null;
    if (len % 128 < 112) {
        tmp = new Array(112 - len % 128);
    } else {
        tmp = new Array(128 + 112 - len % 128);
    }
    tmp.fill(0);
    tmp[0] = 0x80;
    let bs = M.concat(tmp);
    let bits = len * 8;
    let size = Array(16);
    size.fill(0);
    size[12] = (bits & 0xff000000) >> 24;
    size[13] = (bits & 0x00ff0000) >> 16;
    size[14] = (bits & 0x0000ff00) >> 8;
    size[15] = (bits & 0x000000ff);
    bs = bs.concat(size);
    return bs;
}

// 5.3 Setting the Initial Hash Value (H(0))
// 5.3.1 SHA-1
const SHA1_H0 = [
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0,
];

// 5.3.2 SHA-224
const SHA224_H0 = [
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4,
];

// 5.3.3 SHA-256
const SHA256_H0 = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

// 6.1.1 SHA-1 Preprocessing
// 6.1.2 SHA-1 Hash Computation

function computeSHA1(msg) {
    // For i=1 to N:
    // {
    let N = msg.length / 64;
    let W = new Array(80);
    let H = SHA1_H0.concat();
    let K = SHA1_K;
    let w = 32;
    let MASK = 0xffffffff;
    for (let i = 1; i <= N; i++) {
        // 1. Prepare the message schedule, {Wt}:
        for (let t = 0; t < 80; t++) {
            if (t < 16) {
                let p = (i - 1) * 64 + t * 4;
                W[t] = (msg[p] << 24) + (msg[p + 1] << 16) + (msg[p + 2] << 8) + msg[p + 3];
            } else {
                W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1, w);
            }
        }
        // 2. Initialize the five working variables, a, b, c, d, and e, with the (i-1)st hash value:
        let a = H[0];
        let b = H[1];
        let c = H[2];
        let d = H[3];
        let e = H[4];
        // 3. For t=0 to 79:
        for (let t = 0; t < 80; t++) {
            let T = (ROTL(a, 5, w) + e + W[t]) & MASK;
            if (t < 20) {
                T = (T + K[0] + Ch(b, c, d)) & MASK;
            } else if (t < 40) {
                T = (T + K[1] + Parity(b, c, d)) & MASK;
            } else if (t < 60) {
                T = (T + K[2] + Maj(b, c, d)) & MASK;
            } else {
                T = (T + K[3] + Parity(b, c, d)) & MASK;
            }
            e = d;
            d = c;
            c = ROTL(b, 30, w) & MASK;
            b = a;
            a = T;
        }
        // 4. Compute the i-th intermediate hash value H(i)
        H[0] = (a + H[0]) & MASK;
        H[1] = (b + H[1]) & MASK;
        H[2] = (c + H[2]) & MASK;
        H[3] = (d + H[3]) & MASK;
        H[4] = (e + H[4]) & MASK;
    }
    // }
    return H;
}

// 6.2.1 SHA-256 Preprocessing
// 6.2.2 SHA-256 Hash Computation

function computeSHA256(msg, H0) {
    // For i=1 to N:
    // {
    let N = msg.length / 64;
    let W = new Array(64);
    let H = H0.concat();
    let K = SHA256_K;
    let w = 32;
    let MASK = 0xffffffff;
    for (let i = 1; i <= N; i++) {
        // 1. Prepare the message schedule, {Wt}:
        for (let t = 0; t < 64; t++) {
            if (t < 16) {
                let p = (i - 1) * 64 + t * 4;
                W[t] = (msg[p] << 24) + (msg[p + 1] << 16) + (msg[p + 2] << 8) + msg[p + 3];
            } else {
                W[t] = (sigma1_256(W[t - 2], w) + W[t - 7] + sigma0_256(W[t - 15], w) + W[t - 16]) & MASK;
            }
        }
        // 2. Initialize the eight working variables, a, b, c, d, e, f, g, and h, with the (i-1)st hash value:
        let a = H[0];
        let b = H[1];
        let c = H[2];
        let d = H[3];
        let e = H[4];
        let f = H[5];
        let g = H[6];
        let h = H[7];
        // 3. For t=0 to 63:
        // {
        for (let t = 0; t < 64; t++) {
            let T1 = (h + SIGMA1_256(e, w) + Ch(e, f, g) + K[t] + W[t]) & MASK;
            let T2 = (SIGMA0_256(a, w) + Maj(a, b, c)) & MASK;
            h = g;
            g = f;
            f = e;
            e = (d + T1) & MASK;
            d = c;
            c = b;
            b = a;
            a = (T1 + T2) & MASK;
        }
        // }
        // 4. Compute the i-th intermediate hash value H(i):
        H[0] = (a + H[0]) & MASK;
        H[1] = (b + H[1]) & MASK;
        H[2] = (c + H[2]) & MASK;
        H[3] = (d + H[3]) & MASK;
        H[4] = (e + H[4]) & MASK;
        H[5] = (f + H[5]) & MASK;
        H[6] = (g + H[6]) & MASK;
        H[7] = (h + H[7]) & MASK;
    }
    // }
    return H;
}

function SHA1(bs) {
    let msg = padding_256(bs);
    let H = computeSHA1(msg);
    return hash2str(H);
}

function SHA224(bs) {
    let msg = padding_256(bs);
    let H = computeSHA256(msg, SHA224_H0);
    H = H.slice(0, H.length - 1);
    return hash2str(H);
}

function SHA256(bs) {
    let msg = padding_256(bs);
    let H = computeSHA256(msg, SHA256_H0);
    return hash2str(H);
}


function hash2str(H) {
    let hash = '';
    for (let h of H) {
        for (let i = 32 - 8; i >= 0; i -= 8) {
            hash += ((h >>> i) & 0xff).toString(16).padStart(2, '0');
        }
    }
    return hash;
}

export { SHA1, SHA224, SHA256 }