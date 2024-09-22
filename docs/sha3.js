'use strict';

// lane lengths
const w = 64;

// This gives 24 rounds for Keccak-f[1600]
const ROUND = 24;

// rot(W,r) is the usual bitwise cyclic shift operation,
// moving bit at position i into position i+r (modulo the lane size).
function rot(W, r) {
    return ((W << r) & 0xffffffffffffffffn) + (W >> (64n - r));
}

// Table 1: The round constants RC[i]
const RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An, 0x8000000080008000n,
    0x000000000000808Bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008An, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An,
    0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800An, 0x800000008000000An,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Table 2: the rotation offsets
const r = [
    [0n, 36n, 3n, 41n, 18n],
    [1n, 44n, 10n, 45n, 2n],
    [62n, 6n, 43n, 15n, 61n],
    [28n, 55n, 25n, 21n, 56n],
    [27n, 20n, 39n, 8n, 14n],
];
// Keccak-f[b](A) {
function Keccak_f1600(A) {
    // for i in 0…n-1
    for (let i = 0; i < ROUND; i++) {
        // A = Round[b](A, RC[i])
        A = Round1600(A, RC[i]);
    }
    // return A
    return A;
    // }
}

// Round[b](A,RC) {
function Round1600(A, RC) {
    let C = [0n, 0n, 0n, 0n, 0n];
    let D = [0n, 0n, 0n, 0n, 0n];

    // # θ step
    // C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
    for (let x = 0; x < 5; x++) {
        C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
    }
    // D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
    for (let x = 0; x < 5; x++) {
        D[x] = C[(5 + x - 1) % 5] ^ rot(C[(x + 1) % 5], 1n);
    }
    // A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
    for (let y = 0; y < 5; y++) {
        for (let x = 0; x < 5; x++) {
            A[x][y] = A[x][y] ^ D[x];
        }
    }

    let B = [
        [0n, 0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n],
    ];

    // # ρ and π steps
    // B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
    for (let y = 0; y < 5; y++) {
        for (let x = 0; x < 5; x++) {
            B[y][(2 * x + 3 * y) % 5] = rot(A[x][y], r[x][y]);
        }
    }

    // # χ step
    // A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
    for (let y = 0; y < 5; y++) {
        for (let x = 0; x < 5; x++) {
            A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);
        }
    }

    // # ι step
    // A[0,0] = A[0,0] xor RC
    A[0][0] = A[0][0] ^ RC;

    // return A
    return A;
    // }
}

// Keccak[r, c](Mbytes || Mbits) {
function Keccak(r, OutputLength, Mbytes, d) {
    // # Padding
    // d = 2 ^| Mbits | + sum for i = 0..| Mbits | -1 of 2 ^ i * Mbits[i]
    // P = Mbytes || d || 0x00 || … || 0x00
    let P = [];
    for (let i = 0; i < Mbytes.length; i++) {
        P.push(Mbytes[i] & 0xff);
    }
    P.push(d);
    while (P.length % (r / 8) != 0) {
        P.push(0);
    }
    // P = P xor(0x00 || … || 0x00 || 0x80)
    for (let i = 0; i < P.length - 1; i++) {
        P[i] = P[i] ^ 0x00;
    }
    P[P.length - 1] = P[P.length - 1] ^ 0x80;

    // # Initialization
    // S[x, y] = 0,                               for (x, y) in (0…4, 0…4)
    let S = [
        [0n, 0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n],
        [0n, 0n, 0n, 0n, 0n],
    ];

    // # Absorbing phase
    // for each block Pi in P
    for (let i = 0; i < P.length; i += (r / 8)) {
        let Pi = [];
        for (let j = 0; j < (r / 8); j += 8) {
            let bi = 0n;
            for (let k = 0; k < 8; k++) {
                bi = bi << 8n;
                bi = bi + BigInt(P[i + j + (7 - k)]);
            }
            Pi.push(bi);
        }
        //   S[x, y] = S[x, y] xor Pi[x + 5 * y],          for (x, y) such that x + 5 * y < r / w
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                if (x + 5 * y < r / w) {
                    S[x][y] = S[x][y] ^ Pi[x + 5 * y];
                }
            }
        }
        // S = Keccak - f[r + c](S)
        S = Keccak_f1600(S);
    }

    // # Squeezing phase
    // Z = empty string
    let Z = "";
    // while output is requested
    let blakeFlg = false;
    while (!blakeFlg) {
        // Z = Z || S[x, y],                        for (x, y) such that x + 5 * y < r / w
        outlen: for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                if (x + 5 * y < r / w) {
                    for (let i = 0n; i < 8n; i++) {
                        Z = Z + ((S[x][y] >> (i * 8n)) & 0xffn).toString(16).padStart(2, "0");
                        if (Z.length == (OutputLength / 8) * 2) {
                            blakeFlg = true;
                            break outlen;
                        }
                    }
                }
            }
        }
        if (!blakeFlg) {
            // S = Keccak - f[r + c](S)
            S = Keccak_f1600(S);
        }
    }

    // return Z
    return Z;
    // }
}

function SHAKE128(Mbytes, OutputLength) {
    if (OutputLength % 8 != 0) {
        throw new Error("Illegal OutputLength");
    }
    return Keccak(1344, OutputLength, Mbytes, 0x1F);
}

function SHAKE256(Mbytes, OutputLength) {
    if (OutputLength % 8 != 0) {
        throw new Error("Illegal OutputLength");
    }
    return Keccak(1088, OutputLength, Mbytes, 0x1F);
}

function SHA3_224(Mbytes) {
    return Keccak(1152, 224, Mbytes, 0x06);
}

function SHA3_256(Mbytes) {
    return Keccak(1088, 256, Mbytes, 0x06);
}

function SHA3_384(Mbytes) {
    return Keccak(832, 384, Mbytes, 0x06);
}

function SHA3_512(Mbytes) {
    return Keccak(576, 512, Mbytes, 0x06);
}

export { SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256 };