/**
 * Node.js test script to verify WojakCoin address generation.
 * Tests: RIPEMD-160, Base58, Base58Check, Address generation, WIF generation.
 */

// We need crypto for SubtleCrypto in Node.js
const { webcrypto } = require('crypto');
if (!globalThis.crypto) {
    globalThis.crypto = webcrypto;
}

// Load elliptic
const ellipticLib = require('elliptic');
const EC = ellipticLib.ec;

// ---- Inline the crypto-utils functions ----

async function sha256(data) {
    if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
}

async function doubleSha256(data) {
    return sha256(await sha256(data));
}

const RIPEMD160 = (function () {
    const zl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
    const zr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
    const sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
    const sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];

    function f(j, x, y, z) {
        if (j <= 15) return x ^ y ^ z;
        if (j <= 31) return (x & y) | (~x & z);
        if (j <= 47) return (x | ~y) ^ z;
        if (j <= 63) return (x & z) | (y & ~z);
        return x ^ (y | ~z);
    }
    function K_left(j) {
        if (j <= 15) return 0x00000000;
        if (j <= 31) return 0x5A827999;
        if (j <= 47) return 0x6ED9EBA1;
        if (j <= 63) return 0x8F1BBCDC;
        return 0xA953FD4E;
    }
    function K_right(j) {
        if (j <= 15) return 0x50A28BE6;
        if (j <= 31) return 0x5C4DD124;
        if (j <= 47) return 0x6D703EF3;
        if (j <= 63) return 0x7A6D76E9;
        return 0x00000000;
    }
    function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

    return function ripemd160(message) {
        if (!(message instanceof Uint8Array)) message = new Uint8Array(message);
        const msgLen = message.length;
        const bitLenLo = (msgLen * 8) >>> 0;
        const bitLenHi = (msgLen / 0x20000000) >>> 0;
        let padLen = 64 - ((msgLen + 9) % 64);
        if (padLen === 64) padLen = 0;
        const padded = new Uint8Array(msgLen + 1 + padLen + 8);
        padded.set(message);
        padded[msgLen] = 0x80;
        padded[padded.length - 8] = bitLenLo & 0xff;
        padded[padded.length - 7] = (bitLenLo >>> 8) & 0xff;
        padded[padded.length - 6] = (bitLenLo >>> 16) & 0xff;
        padded[padded.length - 5] = (bitLenLo >>> 24) & 0xff;
        padded[padded.length - 4] = bitLenHi & 0xff;
        padded[padded.length - 3] = (bitLenHi >>> 8) & 0xff;
        padded[padded.length - 2] = (bitLenHi >>> 16) & 0xff;
        padded[padded.length - 1] = (bitLenHi >>> 24) & 0xff;
        let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
        for (let offset = 0; offset < padded.length; offset += 64) {
            const x = new Array(16);
            for (let i = 0; i < 16; i++) {
                const o = offset + i * 4;
                x[i] = ((padded[o]) | (padded[o+1] << 8) | (padded[o+2] << 16) | (padded[o+3] << 24)) >>> 0;
            }
            let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
            let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
            for (let j = 0; j < 80; j++) {
                let tl = (al + f(j, bl, cl, dl)) >>> 0;
                tl = (tl + x[zl[j]]) >>> 0;
                tl = (tl + K_left(j)) >>> 0;
                tl = (rotl(tl, sl[j]) + el) >>> 0;
                al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;
                let tr = (ar + f(79 - j, br, cr, dr)) >>> 0;
                tr = (tr + x[zr[j]]) >>> 0;
                tr = (tr + K_right(j)) >>> 0;
                tr = (rotl(tr, sr[j]) + er) >>> 0;
                ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
            }
            const t = (h1 + cl + dr) >>> 0;
            h1 = (h2 + dl + er) >>> 0;
            h2 = (h3 + el + ar) >>> 0;
            h3 = (h4 + al + br) >>> 0;
            h4 = (h0 + bl + cr) >>> 0;
            h0 = t;
        }
        const result = new Uint8Array(20);
        for (let i = 0; i < 4; i++) {
            result[i] = (h0 >>> (i*8)) & 0xff;
            result[i+4] = (h1 >>> (i*8)) & 0xff;
            result[i+8] = (h2 >>> (i*8)) & 0xff;
            result[i+12] = (h3 >>> (i*8)) & 0xff;
            result[i+16] = (h4 >>> (i*8)) & 0xff;
        }
        return result;
    };
})();

async function hash160(data) {
    const sha = await sha256(data);
    return RIPEMD160(sha);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buffer) {
    if (!(buffer instanceof Uint8Array)) buffer = new Uint8Array(buffer);
    if (buffer.length === 0) return '';
    let leadingZeros = 0;
    while (leadingZeros < buffer.length && buffer[leadingZeros] === 0) {
        leadingZeros++;
    }
    const digits = [0];
    for (let i = leadingZeros; i < buffer.length; i++) {
        let carry = buffer[i];
        for (let j = 0; j < digits.length; j++) {
            carry += digits[j] << 8;
            digits[j] = carry % 58;
            carry = (carry / 58) | 0;
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = (carry / 58) | 0;
        }
    }
    let result = BASE58_ALPHABET[0].repeat(leadingZeros);
    if (leadingZeros < buffer.length) {
        let i = digits.length - 1;
        while (i > 0 && digits[i] === 0) i--;
        for (; i >= 0; i--) {
            result += BASE58_ALPHABET[digits[i]];
        }
    }
    return result;
}

async function base58CheckEncode(version, payload) {
    const data = new Uint8Array(1 + payload.length);
    data[0] = version;
    data.set(payload, 1);
    const checksum = (await doubleSha256(data)).slice(0, 4);
    const result = new Uint8Array(data.length + 4);
    result.set(data);
    result.set(checksum, data.length);
    return base58Encode(result);
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// ---- Tests ----

async function runTests() {
    console.log('=== WojakCoin Paper Wallet Tests ===\n');
    let passed = 0;
    let failed = 0;

    function assert(condition, message) {
        if (condition) {
            console.log(`  PASS: ${message}`);
            passed++;
        } else {
            console.log(`  FAIL: ${message}`);
            failed++;
        }
    }

    // Test 1: RIPEMD-160 known test vector
    // ripemd160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
    console.log('\n--- RIPEMD-160 Tests ---');
    const abcBytes = new TextEncoder().encode('abc');
    const rmd = RIPEMD160(abcBytes);
    const rmdHex = bytesToHex(rmd);
    assert(rmdHex === '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc', `RIPEMD-160("abc") = ${rmdHex}`);

    // ripemd160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
    const emptyRmd = RIPEMD160(new Uint8Array(0));
    const emptyRmdHex = bytesToHex(emptyRmd);
    assert(emptyRmdHex === '9c1185a5c5e9fc54612808977ee8f548b2258d31', `RIPEMD-160("") = ${emptyRmdHex}`);

    // Test 2: SHA-256 known test vector
    console.log('\n--- SHA-256 Tests ---');
    const shaResult = await sha256(new TextEncoder().encode('abc'));
    const shaHex = bytesToHex(shaResult);
    assert(shaHex === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', `SHA-256("abc") correct`);

    // Test 3: Base58 encoding
    console.log('\n--- Base58 Tests ---');
    const b58test = base58Encode(hexToBytes('0000000000'));
    assert(b58test === '11111', `Base58(0x0000000000) = ${b58test}`);

    // Test 4: Generate a WojakCoin wallet and verify format
    console.log('\n--- Wallet Generation Tests ---');
    const ec = new EC('secp256k1');

    // Use a known private key for deterministic testing
    const testPrivKeyHex = '0000000000000000000000000000000000000000000000000000000000000001';
    const testPrivKey = hexToBytes(testPrivKeyHex);

    const keyPair = ec.keyFromPrivate(Array.from(testPrivKey));
    const publicKey = new Uint8Array(keyPair.getPublic(true, 'array'));
    console.log(`  Public key (compressed): ${bytesToHex(publicKey)}`);

    const pubKeyHash = await hash160(publicKey);
    console.log(`  PubKeyHash: ${bytesToHex(pubKeyHash)}`);

    // WojakCoin address with version byte 73 (0x49)
    const address = await base58CheckEncode(73, pubKeyHash);
    console.log(`  Address: ${address}`);
    assert(address.startsWith('W'), `Address starts with 'W': ${address}`);

    // WIF with version byte 201 (0xC9), compressed
    const wifPayload = new Uint8Array(33);
    wifPayload.set(testPrivKey);
    wifPayload[32] = 0x01;
    const wif = await base58CheckEncode(201, wifPayload);
    console.log(`  WIF: ${wif}`);
    assert(wif.length > 40, `WIF has reasonable length: ${wif.length}`);

    // Test 5: Generate multiple random wallets
    console.log('\n--- Random Wallet Generation ---');
    for (let i = 0; i < 5; i++) {
        const privKey = new Uint8Array(32);
        crypto.getRandomValues(privKey);

        const kp = ec.keyFromPrivate(Array.from(privKey));
        const pk = new Uint8Array(kp.getPublic(true, 'array'));
        const pkh = await hash160(pk);
        const addr = await base58CheckEncode(73, pkh);

        const wp = new Uint8Array(33);
        wp.set(privKey);
        wp[32] = 0x01;
        const w = await base58CheckEncode(201, wp);

        console.log(`  Wallet ${i + 1}: ${addr} | WIF: ${w.substring(0, 12)}...`);
        assert(addr.startsWith('W'), `Wallet ${i + 1} address starts with W`);
    }

    // Summary
    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
    process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
    console.error('Test error:', err);
    process.exit(1);
});
