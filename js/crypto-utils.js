/**
 * Pure JavaScript cryptographic utilities for WojakCoin paper wallet generation.
 * Includes: RIPEMD-160, Base58, Base58Check, SHA-256 (via SubtleCrypto).
 * No external dependencies for core crypto - auditable and offline-safe.
 */

// ============================================================
// SHA-256 (uses native Web Crypto API for security)
// ============================================================

async function sha256(data) {
    if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
}

async function doubleSha256(data) {
    return sha256(await sha256(data));
}

// ============================================================
// RIPEMD-160 (pure JS implementation per the specification)
// ============================================================

const RIPEMD160 = (function () {
    const zl = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
    ];

    const zr = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
    ];

    const sl = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
    ];

    const sr = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
    ];

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

    function rotl(x, n) {
        return ((x << n) | (x >>> (32 - n))) >>> 0;
    }

    return function ripemd160(message) {
        if (!(message instanceof Uint8Array)) {
            message = new Uint8Array(message);
        }

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

        let h0 = 0x67452301;
        let h1 = 0xEFCDAB89;
        let h2 = 0x98BADCFE;
        let h3 = 0x10325476;
        let h4 = 0xC3D2E1F0;

        for (let offset = 0; offset < padded.length; offset += 64) {
            const x = new Array(16);
            for (let i = 0; i < 16; i++) {
                const o = offset + i * 4;
                x[i] = (padded[o]) |
                    (padded[o + 1] << 8) |
                    (padded[o + 2] << 16) |
                    (padded[o + 3] << 24);
                x[i] = x[i] >>> 0;
            }

            let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
            let ar = h0, br = h1, cr = h2, dr = h3, er = h4;

            for (let j = 0; j < 80; j++) {
                let tl = (al + f(j, bl, cl, dl)) >>> 0;
                tl = (tl + x[zl[j]]) >>> 0;
                tl = (tl + K_left(j)) >>> 0;
                tl = (rotl(tl, sl[j]) + el) >>> 0;

                al = el;
                el = dl;
                dl = rotl(cl, 10);
                cl = bl;
                bl = tl;

                let tr = (ar + f(79 - j, br, cr, dr)) >>> 0;
                tr = (tr + x[zr[j]]) >>> 0;
                tr = (tr + K_right(j)) >>> 0;
                tr = (rotl(tr, sr[j]) + er) >>> 0;

                ar = er;
                er = dr;
                dr = rotl(cr, 10);
                cr = br;
                br = tr;
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
            result[i] = (h0 >>> (i * 8)) & 0xff;
            result[i + 4] = (h1 >>> (i * 8)) & 0xff;
            result[i + 8] = (h2 >>> (i * 8)) & 0xff;
            result[i + 12] = (h3 >>> (i * 8)) & 0xff;
            result[i + 16] = (h4 >>> (i * 8)) & 0xff;
        }

        return result;
    };
})();

// ============================================================
// HASH-160: RIPEMD160(SHA256(data))
// ============================================================

async function hash160(data) {
    const sha = await sha256(data);
    return RIPEMD160(sha);
}

// ============================================================
// Base58 Encoding
// ============================================================

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

// ============================================================
// Base58Check Encoding: version(1 byte) + payload + checksum(4 bytes)
// ============================================================

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

// ============================================================
// Hex Utilities
// ============================================================

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
