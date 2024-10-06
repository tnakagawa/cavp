# cavp

https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

```javascript
function monte(SHAKE, initialMsg, minoutlen, maxoutlen) {
    // INPUT: The initial Msg of 128 bits long
    // Initial Outputlen = (floor(maxoutlen/8) )*8
    let Outputlen = (Math.floor(maxoutlen / 8));
    // //makes maxoutlen a multiple of 8 and remains within the range specified.
    const minoutbytes = (Math.floor(minoutlen / 8));
    const maxoutbytes = (Math.floor(maxoutlen / 8));
    // {
    let Output = new Array(1001);
    let Outputlenj = null;
    let Outputj = null;
    let Msg = new Array(1001);
    // Output0 = Msg;
    Output[0] = hex2bs(initialMsg);
    // for (j=0; j<100; j++) {
    for (let j = 0; j < 100; j++) {
        // for (i=1; i<1001; i++) {
        for (let i = 1; i < 1001; i++) {
            // Msgi = 128 leftmost bits of Outputi-1;
            Msg[i] = Output[i - 1].slice(0, 128 / 8);
            while (Msg[i].length < 128 / 8) {
                Msg[i].push(0);
            }
            // Outputi = SHAKE(Msgi,Outputlen);
            Output[i] = hex2bs(SHAKE(Msg[i], Outputlen * 8));
            // If (i == 1000){
            if (i == 1000) {
                // Outputlenj = Outputlen;
                Outputlenj = Outputlen;
            }
            // }
            // Rightmost_Output_bits = rightmost 16 bits of Outputi;
            let Rightmost_Output_bits = Output[i][Output[i].length - 2] * 256 + Output[i][Output[i].length - 1];
            // Range = (maxoutbytes – minoutbytes + 1);
            let Range = (maxoutbytes - minoutbytes + 1);
            // Outputlen = minoutbytes + (Rightmost_Output_bits mod Range);
            Outputlen = minoutbytes + (Rightmost_Output_bits % Range);
        }
        // }
        // Outputj = Output1000;
        Outputj = Output[1000];
        // OUTPUT: Outputlenj, Outputj
        console.log(j, Outputlenj * 8, bs2hex(Outputj));
        Output[0] = Output[1000];
    }
    // }
    // }
}
```

