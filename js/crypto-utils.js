/**
 * Pure JavaScript cryptographic utilities for WojakCoin paper wallet generation.
 * Includes: RIPEMD-160, Base58, Base58Check, SHA-256 (via SubtleCrypto).
 * No external dependencies for core crypto - auditable and offline-safe.
 */

// ============================================================
// SHA-256 (native Web Crypto with pure-JS fallback)
// ============================================================

// Pure-JS SHA-256 for environments where crypto.subtle is unavailable
// (non-secure contexts: HTTP on mobile Safari, older browsers, etc.)
const _jsSha256 = (function() {
    const K = new Uint32Array([
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);

    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

    return function sha256js(data) {
        if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
        const len = data.length;
        const bitLen = len * 8;

        const padLen = 64 - ((len + 9) % 64);
        const totalLen = len + 1 + (padLen === 64 ? 0 : padLen) + 8;
        const msg = new Uint8Array(totalLen);
        msg.set(data);
        msg[len] = 0x80;
        const dv = new DataView(msg.buffer);
        dv.setUint32(totalLen - 4, bitLen, false);

        let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

        const w = new Uint32Array(64);

        for (let off = 0; off < totalLen; off += 64) {
            for (let i = 0; i < 16; i++) {
                w[i] = dv.getUint32(off + i * 4, false);
            }
            for (let i = 16; i < 64; i++) {
                const s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
                const s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
                w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
            }

            let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

            for (let i = 0; i < 64; i++) {
                const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                const ch = (e & f) ^ (~e & g);
                const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
                const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const t2 = (S0 + maj) >>> 0;

                h = g; g = f; f = e; e = (d + t1) >>> 0;
                d = c; c = b; b = a; a = (t1 + t2) >>> 0;
            }

            h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0;
            h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
            h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0;
            h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
        }

        const result = new Uint8Array(32);
        const rv = new DataView(result.buffer);
        rv.setUint32(0, h0, false); rv.setUint32(4, h1, false);
        rv.setUint32(8, h2, false); rv.setUint32(12, h3, false);
        rv.setUint32(16, h4, false); rv.setUint32(20, h5, false);
        rv.setUint32(24, h6, false); rv.setUint32(28, h7, false);
        return result;
    };
})();

const _hasSubtleCrypto = typeof crypto !== 'undefined'
    && typeof crypto.subtle !== 'undefined'
    && typeof crypto.subtle.digest === 'function';

async function sha256(data) {
    if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
    if (_hasSubtleCrypto) {
        const hash = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(hash);
    }
    return _jsSha256(data);
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
