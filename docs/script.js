'use strict';

import { SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256 } from './sha3.js';
import { SHA1, SHA224, SHA256, SHA512, SHA384, SHA512_224, SHA512_256 } from './sha2.js';

async function init() {
    console.log('>>>', 'init');
    const app = Vue.createApp(MainApp).mount('#main');
    console.log('<<<', 'init');
}

const MainApp = {
    data() {
        return {
            loading: true,
            testname: '',
            tests: [],
            total: 0,
            ok: 0,
            ng: 0,
            time: '',
            url: '',
            SHAKE: null,
            SHA3: null,
            SHA: null,
        };
    },
    mounted() {
        console.log('>>>', 'mounted');
        this.init();
        console.log('<<<', 'mounted');
    },
    methods: {
        async init() {
            console.log('>>>', 'init');
            this.loading = false;
            this.tests = [
                'SHA3_224LongMsg',
                'SHA3_224Monte',
                'SHA3_224ShortMsg',
                'SHA3_256LongMsg',
                'SHA3_256Monte',
                'SHA3_256ShortMsg',
                'SHA3_384LongMsg',
                'SHA3_384Monte',
                'SHA3_384ShortMsg',
                'SHA3_512LongMsg',
                'SHA3_512Monte',
                'SHA3_512ShortMsg',
                'SHAKE128LongMsg',
                'SHAKE128Monte',
                'SHAKE128ShortMsg',
                'SHAKE128VariableOut',
                'SHAKE256LongMsg',
                'SHAKE256Monte',
                'SHAKE256ShortMsg',
                'SHAKE256VariableOut',
                'SHA1LongMsg',
                'SHA1Monte',
                'SHA1ShortMsg',
                'SHA224LongMsg',
                'SHA224Monte',
                'SHA224ShortMsg',
                'SHA256LongMsg',
                'SHA256Monte',
                'SHA256ShortMsg',
                'SHA384LongMsg',
                'SHA384Monte',
                'SHA384ShortMsg',
                'SHA512LongMsg',
                'SHA512Monte',
                'SHA512ShortMsg',
                'SHA512_224LongMsg',
                'SHA512_224Monte',
                'SHA512_224ShortMsg',
                'SHA512_256LongMsg',
                'SHA512_256Monte',
                'SHA512_256ShortMsg',
            ]
            console.log('<<<', 'init');
        },
        clear() {
            this.total = 0;
            this.ok = 0;
            this.ng = 0;
            this.time = '';
        },
        async test() {
            console.log(this.testname);
            if (this.testname) {
                this.clear();
                const start = Date.now();
                this.loading = true;
                if (this.testname == 'SHA3_224LongMsg') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_224;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA3_224Monte') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_224;
                    await this.testSHA3Monte();
                } else if (this.testname == 'SHA3_224ShortMsg') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_224;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA3_256LongMsg') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_256;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA3_256Monte') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_256;
                    await this.testSHA3Monte();
                } else if (this.testname == 'SHA3_256ShortMsg') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_256;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA3_384LongMsg') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_384;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA3_384Monte') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_384;
                    await this.testSHA3Monte();
                } else if (this.testname == 'SHA3_384ShortMsg') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_384;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA3_512LongMsg') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_512;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA3_512Monte') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_512;
                    await this.testSHA3Monte();
                } else if (this.testname == 'SHA3_512ShortMsg') {
                    this.url = './sha-3bytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA3_512;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHAKE128LongMsg') {
                    this.url = './shakebytetestvectors/' + this.testname + '.rsp';
                    this.SHAKE = SHAKE128;
                    await this.testSHAKEMsg();
                } else if (this.testname == 'SHAKE128Monte') {
                    this.url = './shakebytetestvectors/' + this.testname + '.rsp';
                    this.SHAKE = SHAKE128;
                    await this.testSHAKEMonte();
                } else if (this.testname == 'SHAKE128ShortMsg') {
                    this.url = './shakebytetestvectors/' + this.testname + '.rsp';
                    this.SHAKE = SHAKE128;
                    await this.testSHAKEMsg();
                } else if (this.testname == 'SHAKE128VariableOut') {
                    this.url = './shakebytetestvectors/' + this.testname + '.rsp';
                    this.SHAKE = SHAKE128;
                    await this.testSHAKEVariableOut();
                } else if (this.testname == 'SHAKE256LongMsg') {
                    this.url = './shakebytetestvectors/' + this.testname + '.rsp';
                    this.SHAKE = SHAKE256;
                    await this.testSHAKEMsg();
                } else if (this.testname == 'SHAKE256Monte') {
                    this.url = './shakebytetestvectors/' + this.testname + '.rsp';
                    this.SHAKE = SHAKE256;
                    await this.testSHAKEMonte();
                } else if (this.testname == 'SHAKE256ShortMsg') {
                    this.url = './shakebytetestvectors/' + this.testname + '.rsp';
                    this.SHAKE = SHAKE256;
                    await this.testSHAKEMsg();
                } else if (this.testname == 'SHAKE256VariableOut') {
                    this.url = './shakebytetestvectors/' + this.testname + '.rsp';
                    this.SHAKE = SHAKE256;
                    await this.testSHAKEVariableOut();
                } else if (this.testname == 'SHA1LongMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA1;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA1Monte') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA = SHA1;
                    await this.testSHAMonte();
                } else if (this.testname == 'SHA1ShortMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA1;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA224LongMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA224;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA224Monte') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA = SHA224;
                    await this.testSHAMonte();
                } else if (this.testname == 'SHA224ShortMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA224;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA256LongMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA256;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA256Monte') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA = SHA256;
                    await this.testSHAMonte();
                } else if (this.testname == 'SHA256ShortMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA256;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA512LongMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA512;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA512Monte') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA = SHA512;
                    await this.testSHAMonte();
                } else if (this.testname == 'SHA512ShortMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA512;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA384LongMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA384;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA384Monte') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA = SHA384;
                    await this.testSHAMonte();
                } else if (this.testname == 'SHA384ShortMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA384;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA512_224LongMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA512_224;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA512_224Monte') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA = SHA512_224;
                    await this.testSHAMonte();
                } else if (this.testname == 'SHA512_224ShortMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA512_224;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA512_256LongMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA512_256;
                    await this.testSHA3Msg();
                } else if (this.testname == 'SHA512_256Monte') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA = SHA512_256;
                    await this.testSHAMonte();
                } else if (this.testname == 'SHA512_256ShortMsg') {
                    this.url = './shabytetestvectors/' + this.testname + '.rsp';
                    this.SHA3 = SHA512_256;
                    await this.testSHA3Msg();
                }
                const end = Date.now();
                this.time = (end - start) + ' ms';
                this.loading = false;
            }
        },
        sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },
        async testSHA3Msg() {
            try {
                const text = await getRes(this.url);
                const data = parseSHA3Msg(text);
                this.total = data.list.length;
                for (let item of data.list) {
                    let Mbytes = hex2bs(item.Msg);
                    if (item.Len == 0) {
                        Mbytes = [];
                    }
                    let hash = this.SHA3(Mbytes);
                    console.log(hash, item.MD, hash == item.MD);
                    if (hash == item.MD) {
                        this.ok++;
                    } else {
                        this.ng++;
                    }
                    await this.sleep(1);
                }
            } catch (e) {
                console.error(e);
            }
        },
        async testSHAMonte() {
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf
            try {
                const text = await getRes(this.url);
                const data = parseSHA3Monte(text);
                console.dir(data);
                this.total = data.list.length;

                // INPUT: Seed - A random seed n bits long
                // {
                let M = new Array(1003);
                let MD = new Array(1003);
                let Seed = hex2bs(data.Seed);
                // for (j=0; j<100; j++) {
                for (let j = 0; j < 100; j++) {
                    // MD0 = MD1 = MD2 = Seed;
                    MD[0] = Seed;
                    MD[1] = MD[0];
                    MD[2] = MD[1];
                    // for (i=3; i<1003; i++) {
                    for (let i = 3; i < 1003; i++) {
                        // Mi = MDi-3 || MDi-2 || MDi-1;
                        M[i] = MD[i - 3].concat(MD[i - 2]).concat(MD[i - 1]);
                        // MDi = SHA(Mi);
                        MD[i] = hex2bs(this.SHA(M[i]));
                    }
                    // }
                    // MDj = Seed = MD1002;
                    let MDj = MD[1002];
                    Seed = MD[1002];
                    // OUTPUT: MDj
                    console.log(j, bs2hex(MDj), bs2hex(MDj) == data.list[j].MD);
                    if (bs2hex(MDj) == data.list[j].MD) {
                        this.ok++;
                    } else {
                        this.ng++;
                    }
                    await this.sleep(1);
                }
                // }
                // }
            } catch (e) {
                console.error(e);
            }
        },
        async testSHA3Monte() {
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
            try {
                const text = await getRes(this.url);
                const data = parseSHA3Monte(text);
                console.dir(data);
                this.total = data.list.length;
                // INPUT: A random Seed n bits long
                // {
                let MD = new Array(1001);
                let Msg = new Array(1001);
                // MD0 = Seed;
                MD[0] = hex2bs(data.Seed);
                // for (j=0; j<100; j++) {
                for (let j = 0; j < 100; j++) {
                    // for (i=1; i<1001; i++) {
                    for (let i = 1; i < 1001; i++) {
                        // Msgi = MDi-1;
                        Msg[i] = MD[i - 1];
                        // MDi = SHA3(Msgi);
                        MD[i] = hex2bs(this.SHA3(Msg[i]));
                        // }
                    }
                    // MD0 = MD1000;
                    MD[0] = MD[1000];
                    // OUTPUT: MD0
                    console.log(j, bs2hex(MD[0]), bs2hex(MD[0]) == data.list[j].MD);
                    // }
                    if (bs2hex(MD[0]) == data.list[j].MD) {
                        this.ok++;
                    } else {
                        this.ng++;
                    }
                    await this.sleep(1);
                }
                // }
            } catch (e) {
                console.error(e);
            }
        },
        async testSHAKEMsg() {
            try {
                const text = await getRes(this.url);
                const data = parseSHAKEMsg(text);
                this.total = data.list.length;
                const OutputLength = data.Outputlen;
                for (let item of data.list) {
                    let Mbytes = hex2bs(item.Msg);
                    if (item.Len == 0) {
                        Mbytes = [];
                    }
                    let hash = this.SHAKE(Mbytes, OutputLength);
                    console.log(hash, item.Output, hash == item.Output);
                    if (hash == item.Output) {
                        this.ok++;
                    } else {
                        this.ng++;
                    }
                    await this.sleep(1);
                }
            } catch (e) {
                console.error(e);
            }
        },
        async testSHAKEMonte() {
            try {
                const text = await getRes(this.url);
                const data = parseSHAKEMonte(text);
                this.total = data.list.length;
                // INPUT: The initial Msg of 128 bits long
                let initialMsg = data.Msg;
                const minoutlen = data.minoutlen;
                const maxoutlen = data.maxoutlen;
                const minoutbytes = (Math.floor(minoutlen / 8));
                const maxoutbytes = (Math.floor(maxoutlen / 8));
                // Initial Outputlen = (floor(maxoutlen/8) )*8 
                let Outputlen = (Math.floor(maxoutlen / 8));
                // //makes maxoutlen a multiple of 8 and remains within the 
                // range specified.
                // {
                let Output = new Array(1001);
                let Outputj = null;
                let Outputlenj = null;
                // Output0 = Msg;
                Output[0] = hex2bs(initialMsg);
                let Msg = new Array(1001);
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
                        Output[i] = hex2bs(this.SHAKE(Msg[i], Outputlen * 8));
                        // If (i == 1000){
                        if (i == 1000) {
                            // Outputlenj = Outputlen;
                            Outputlenj = Outputlen;
                        }
                        // }
                        // Rightmost_Output_bits = rightmost 16 bits of Outputi;
                        // let Rightmost_Output_bits = Output[i][Output[i].length - 2] * 16 + Output[i][Output[i].length - 1];
                        let Rightmost_Output_bits = Output[i][Output[i].length - 2] * 256 + Output[i][Output[i].length - 1];
                        // Range = (maxoutbytes – minoutbytes + 1);
                        let Range = (maxoutbytes - minoutbytes + 1);
                        // Outputlen = minoutbytes + (Rightmost_Output_bits
                        // mod Range);
                        Outputlen = minoutbytes + (Rightmost_Output_bits % Range);
                        // }
                    }
                    // Outputj = Output1000;
                    Outputj = Output[1000];
                    // OUTPUT: Outputlenj, Outputj
                    console.log(j, Outputlenj * 8, bs2hex(Outputj), data.list[j].Outputlen == Outputlenj * 8, data.list[j].Output == bs2hex(Outputj));
                    // }
                    Output[0] = Output[1000];
                    if (data.list[j].Outputlen == Outputlenj * 8 && data.list[j].Output == bs2hex(Outputj)) {
                        this.ok++;
                    } else {
                        this.ng++;
                    }
                    await this.sleep(1);
                }
                // }
            } catch (e) {
                console.error(e);
            }
        },
        async testSHAKEVariableOut() {
            try {
                const text = await getRes(this.url);
                const data = parseVariableOut(text);
                console.log(data);
                this.total = data.list.length;
                for (let item of data.list) {
                    let Mbytes = hex2bs(item.Msg);
                    let hash = this.SHAKE(Mbytes, item.Outputlen);
                    console.log(hash, item.Output, hash == item.Output);
                    if (hash == item.Output) {
                        this.ok++;
                    } else {
                        this.ng++;
                    }
                    await this.sleep(1);
                }
            } catch (e) {
                console.error(e);
            }
        }
    },
}

async function getRes(url) {
    const data = await fetch(url);
    const text = await data.text();
    return text;
}

function parseSHA3Msg(text) {
    const data = {
        list: [],
    };
    let lines = text.split("\n");
    let item = {
        Len: null,
        Msg: null,
        MD: null,
    };
    for (let line of lines) {
        line = line.trim();
        if (line.indexOf('Len = ') == 0) {
            let len = parseInt(line.substring("Len = ".length));
            item.Len = len;
        } else if (line.indexOf('Msg = ') == 0) {
            let msg = line.substring("Msg = ".length);
            item.Msg = msg;
        } else if (line.indexOf('MD = ') == 0) {
            let md = line.substring("MD = ".length);
            item.MD = md;
            data.list.push(item);
            item = {
                Len: null,
                Msg: null,
                MD: null,
            };
        }
    }
    return data;
}

function parseSHA3Monte(text) {
    const data = {
        Seed: null,
        list: [],
    };
    let lines = text.split("\n");
    let item = {
        COUNT: null,
        MD: null,
    };
    for (let line of lines) {
        line = line.trim();
        if (line.indexOf('Seed = ') == 0) {
            let seed = line.substring("Seed = ".length);
            data.Seed = seed;
        } else if (line.indexOf('COUNT = ') == 0) {
            let cnt = parseInt(line.substring("COUNT = ".length));
            item.COUNT = cnt;
        } else if (line.indexOf('MD = ') == 0) {
            let md = line.substring("MD = ".length);
            item.MD = md;
            data.list.push(item);
            item = {
                COUNT: null,
                MD: null,
            };
        }
    }
    return data;
}

function parseSHAKEMsg(text) {
    const data = {
        Outputlen: null,
        list: [],
    };
    let lines = text.split("\n");
    let item = {
        Len: null,
        Msg: null,
        Output: null,
    };
    for (let line of lines) {
        line = line.trim();
        if (line.indexOf('[Outputlen = ') == 0) {
            let num = parseInt(line.match(/\d+/g)[0]);
            data.Outputlen = num;
        } else if (line.indexOf('Len = ') == 0) {
            let len = parseInt(line.substring("Len = ".length));
            item.Len = len;
        } else if (line.indexOf('Msg = ') == 0) {
            let msg = line.substring("Msg = ".length);
            item.Msg = msg;
        } else if (line.indexOf('Output = ') == 0) {
            let output = line.substring("Output = ".length);
            item.Output = output;
            data.list.push(item);
            item = {
                Len: null,
                Msg: null,
                Output: null,
            };
        }
    }
    return data;
}

function parseSHAKEMonte(text) {
    const data = {
        Msg: null,
        minoutlen: null,
        maxoutlen: null,
        list: [],
    };
    let lines = text.split("\n");
    let item = {
        COUNT: null,
        Outputlen: null,
        Output: null,
    };
    for (let line of lines) {
        line = line.trim();
        if (line.indexOf('[Minimum Output Length (bits) = ') == 0) {
            let num = parseInt(line.match(/\d+/g)[0]);
            data.minoutlen = num;
        } else if (line.indexOf('[Maximum Output Length (bits) = ') == 0) {
            let num = parseInt(line.match(/\d+/g)[0]);
            data.maxoutlen = num;
        } else if (line.indexOf('Msg = ') == 0) {
            let msg = line.substring("Msg = ".length);
            data.Msg = msg;
        } else if (line.indexOf('COUNT = ') == 0) {
            let cnt = parseInt(line.match(/\d+/g)[0]);
            item.COUNT = cnt;
        } else if (line.indexOf('Outputlen = ') == 0) {
            let len = parseInt(line.match(/\d+/g)[0]);
            item.Outputlen = len;
        } else if (line.indexOf('Output = ') == 0) {
            let output = line.substring("Output = ".length);
            item.Output = output;
            data.list.push(item);
            item = {
                COUNT: null,
                Outputlen: null,
                Output: null,
            };
        }
    }
    return data;
}

function parseVariableOut(text) {
    const data = {
        list: [],
    };
    let lines = text.split("\n");
    let item = {
        COUNT: null,
        Outputlen: null,
        Msg: null,
        Output: null,
    };
    for (let line of lines) {
        line = line.trim();
        if (line.indexOf('Msg = ') == 0) {
            let msg = line.substring("Msg = ".length);
            item.Msg = msg;
        } else if (line.indexOf('COUNT = ') == 0) {
            let cnt = parseInt(line.match(/\d+/g)[0]);
            item.COUNT = cnt;
        } else if (line.indexOf('Outputlen = ') == 0) {
            let len = parseInt(line.match(/\d+/g)[0]);
            item.Outputlen = len;
        } else if (line.indexOf('Output = ') == 0) {
            let output = line.substring("Output = ".length);
            item.Output = output;
            data.list.push(item);
            item = {
                COUNT: null,
                Outputlen: null,
                Msg: null,
                Output: null,
            };
        }
    }
    return data;
}

function hex2bs(hex) {
    let bs = [];
    for (let i = 0; i < hex.length; i += 2) {
        bs.push(parseInt(hex.substring(i, i + 2), 16));
    }
    return bs;
}

function bs2hex(bs) {
    let hex = "";
    for (let b of bs) {
        if (b < 16) {
            hex += '0' + b.toString(16);
        } else {
            hex += b.toString(16);
        }
    }
    return hex;
}

window.addEventListener('load', init);