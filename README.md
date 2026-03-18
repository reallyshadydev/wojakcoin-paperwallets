# WojakCoin Paper Wallet Generator

A secure, client-side paper wallet generator for **WojakCoin (WJK)**. Generate P2PKH addresses and WIF private keys entirely in your browser — no data ever leaves your device.

![License](https://img.shields.io/badge/license-MIT-blue)
![Client-Side](https://img.shields.io/badge/crypto-100%25%20client--side-green)
![Addresses](https://img.shields.io/badge/prefix-W-gold)

---

## Features

- **Client-side key generation** — all cryptographic operations run in your browser using `crypto.getRandomValues()` and mouse entropy
- **WojakCoin mainnet parameters** — addresses start with `W` (version byte 73), WIF keys use version byte 201
- **QR codes** — scannable QR codes for both public address and private key
- **Printable paper wallets** — fold-and-seal design with dedicated print stylesheet
- **Bulk generation** — create up to 50 wallets at once with CSV export
- **Offline-ready** — all crypto libraries bundled locally; works without an internet connection
- **Responsive design** — dark theme with gold accents, looks great on desktop and mobile

## Quick Start

Open `index.html` in any modern browser. That's it — no build step, no server, no dependencies to install.

```bash
# Option 1: open directly
open index.html

# Option 2: serve locally
npx http-server -p 8080
# then visit http://localhost:8080
```

For maximum security, **disconnect from the internet** before generating wallets. The site will show a green "offline mode" banner confirming no network activity is possible.

## How It Works

1. **Generate** — click the button to create a new wallet using cryptographically secure randomness
2. **Print** — print the paper wallet with the fold-and-seal layout (public address on one side, private key on the other)
3. **Fund** — send WJK to the public address (the `W...` address)
4. **Redeem** — import the private key (WIF) into a WojakCoin wallet application to spend your coins

## Network Parameters

These values come from WojakCoin's `src/chainparams.cpp`:

| Parameter | Value |
|---|---|
| **P2PKH version** | 73 (0x49) — addresses start with `W` |
| **WIF version** | 201 (0xC9) |
| **P2SH version** | 5 (0x05) |
| **BIP32 xpub** | 0x0488B21E |
| **BIP32 xprv** | 0x0488ADE4 |
| **Curve** | secp256k1 |

## Project Structure

```
index.html              Main page
css/style.css           Styles + print stylesheet
js/
  crypto-utils.js       RIPEMD-160, Base58Check, SHA-256 helpers
  wallet.js             Wallet generation logic + UI controller
  vendor/
    elliptic.min.js     secp256k1 library (bundled for offline use)
    qrcode.min.js       QR code library (bundled for offline use)
img/
  logo.svg              SVG logo fallback
  logo.png              Place your WojakCoin logo here (optional)
test-wallet.js          Node.js test suite
```

## Customizing the Logo

Drop your WojakCoin PNG logo at `img/logo.png`. The site automatically falls back to the included `img/logo.svg` if the PNG is missing.

## Running Tests

The test suite verifies RIPEMD-160, SHA-256, Base58, address generation, and WIF encoding against known vectors.

```bash
npm install elliptic   # one-time dev dependency
node test-wallet.js
```

Expected output:

```
=== WojakCoin Paper Wallet Tests ===

--- RIPEMD-160 Tests ---
  PASS: RIPEMD-160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
  PASS: RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31

--- SHA-256 Tests ---
  PASS: SHA-256("abc") correct

--- Base58 Tests ---
  PASS: Base58(0x0000000000) = 11111

--- Wallet Generation Tests ---
  PASS: Address starts with 'W': WZMJS5eeCEgiqxNK1QRbE1HR4wFQwmCjJV
  PASS: WIF has reasonable length: 52

--- Random Wallet Generation ---
  PASS: Wallet 1 address starts with W
  PASS: Wallet 2 address starts with W
  PASS: Wallet 3 address starts with W
  PASS: Wallet 4 address starts with W
  PASS: Wallet 5 address starts with W

=== Results: 11 passed, 0 failed ===
```

## Security Notes

- **Go offline** before generating wallets for maximum security
- **Never share** your private key (WIF) — anyone with it can spend your coins
- **Use a local printer** — avoid network-connected or wireless printers
- **Laminate** your paper wallet to protect against water and fading
- **Store securely** — treat paper wallets like cash; consider multiple copies in separate locations
- **Verify the source** — this project is open source; review the code to confirm no data is transmitted

## Cryptographic Details

| Component | Implementation |
|---|---|
| Random number generation | `crypto.getRandomValues()` + mouse/touch entropy XOR |
| Elliptic curve | secp256k1 via [elliptic.js](https://github.com/indutny/elliptic) |
| SHA-256 | Native Web Crypto API (`crypto.subtle.digest`) |
| RIPEMD-160 | Pure JS implementation (auditable, ~130 lines) |
| Base58Check | Pure JS implementation with double-SHA-256 checksum |
| QR codes | [qrcode](https://github.com/soldair/node-qrcode) with high error correction |

## License

[MIT](LICENSE)
