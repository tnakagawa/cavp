'use strict';

import { SHAKE128 } from './sha3.js';

async function init() {
    console.log('>>>', 'init');
    try {
        let url = "./shakebytetestvectors/SHAKE128ShortMsg.rsp"
        const data = await fetch(url);
        const blob = await data.blob();
        console.log(blob);
        const reader = new FileReader();
        reader.readAsText(blob);
        reader.addEventListener('load', function () {
            let result = reader.result;
            let lines = result.split("\n");
            console.log(lines.length);
            for (let line of lines) {
                console.log(line);
            }
        });
    } catch (e) {
        console.error(e);
    }
    console.log('<<<', 'init');
}

window.addEventListener('load', init);