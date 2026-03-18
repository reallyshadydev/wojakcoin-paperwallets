/**
 * WojakCoin (WJK) Paper Wallet Generator
 * Client-side wallet generation using WojakCoin mainnet parameters.
 * All cryptographic operations happen in the browser - no data leaves your machine.
 */

// ============================================================
// WojakCoin Network Parameters (from src/chainparams.cpp)
// ============================================================

const WJK_NETWORK = {
    name: 'WojakCoin',
    ticker: 'WJK',
    pubKeyHash: 73,          // 0x49 → addresses start with 'W'
    scriptHash: 5,           // 0x05
    wif: 201,                // 0xC9
    bip32: {
        public: 0x0488B21E,  // xpub
        private: 0x0488ADE4  // xprv
    }
};

// secp256k1 curve order (for private key validation)
const SECP256K1_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// ============================================================
// Entropy Collection
// ============================================================

const entropyPool = {
    buffer: new Uint8Array(256),
    index: 0,
    mouseEvents: 0,

    addMouseEntropy(event) {
        if (this.mouseEvents >= 256) return;
        const val = (event.clientX ^ event.clientY ^ Date.now()) & 0xFF;
        this.buffer[this.index % 256] = this.buffer[this.index % 256] ^ val;
        this.index++;
        this.mouseEvents++;
    },

    isReady() {
        return this.mouseEvents >= 20;
    },

    getProgress() {
        return Math.min(100, Math.round((this.mouseEvents / 20) * 100));
    }
};

// Collect mouse entropy in the background
document.addEventListener('mousemove', (e) => entropyPool.addMouseEntropy(e));
document.addEventListener('touchmove', (e) => {
    if (e.touches[0]) {
        entropyPool.addMouseEntropy({
            clientX: e.touches[0].clientX,
            clientY: e.touches[0].clientY
        });
    }
});

// ============================================================
// Core Wallet Generation
// ============================================================

function generatePrivateKey() {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);

    // XOR with mouse entropy for additional randomness
    for (let i = 0; i < 32; i++) {
        key[i] ^= entropyPool.buffer[i];
    }

    // Validate: private key must be > 0 and < secp256k1 order
    const keyBigInt = BigInt('0x' + bytesToHex(key));
    if (keyBigInt === 0n || keyBigInt >= SECP256K1_ORDER) {
        return generatePrivateKey(); // Extremely unlikely, but handle it
    }

    return key;
}

async function generateWallet() {
    const privateKeyBytes = generatePrivateKey();

    // Derive compressed public key via secp256k1 (using elliptic.js)
    const ec = new elliptic.ec('secp256k1');
    const keyPair = ec.keyFromPrivate(Array.from(privateKeyBytes));
    const publicKeyBytes = new Uint8Array(keyPair.getPublic(true, 'array'));

    // Generate P2PKH address: Base58Check(version + HASH160(compressedPubKey))
    const pubKeyHash = await hash160(publicKeyBytes);
    const address = await base58CheckEncode(WJK_NETWORK.pubKeyHash, pubKeyHash);

    // Generate WIF private key: Base58Check(wifVersion + privKey + 0x01)
    const wifPayload = new Uint8Array(33);
    wifPayload.set(privateKeyBytes);
    wifPayload[32] = 0x01; // compressed flag
    const wif = await base58CheckEncode(WJK_NETWORK.wif, wifPayload);

    return {
        address,
        wif,
        privateKeyHex: bytesToHex(privateKeyBytes),
        publicKeyHex: bytesToHex(publicKeyBytes)
    };
}

async function generateBulkWallets(count) {
    const wallets = [];
    for (let i = 0; i < count; i++) {
        wallets.push(await generateWallet());
    }
    return wallets;
}

// ============================================================
// UI Controller
// ============================================================

let currentWallet = null;
let bulkWallets = [];

async function handleGenerate() {
    const btn = document.getElementById('generateBtn');
    const walletSection = document.getElementById('walletDisplay');
    const placeholder = document.getElementById('placeholder');

    btn.classList.add('generating');
    btn.textContent = 'Generating...';

    // Small delay for visual feedback
    await new Promise(r => setTimeout(r, 300));

    try {
        currentWallet = await generateWallet();

        document.getElementById('addressText').textContent = currentWallet.address;
        document.getElementById('wifText').textContent = currentWallet.wif;

        // Generate QR codes
        await generateQRCodes(currentWallet);

        // Update paper wallet
        updatePaperWallet(currentWallet);

        // Show wallet section with animation
        if (placeholder) placeholder.style.display = 'none';
        walletSection.style.display = 'block';
        walletSection.classList.remove('fade-in');
        void walletSection.offsetWidth; // Trigger reflow
        walletSection.classList.add('fade-in');

    } catch (err) {
        console.error('Wallet generation failed:', err);
        alert('Error generating wallet. Please try again.');
    } finally {
        btn.classList.remove('generating');
        btn.innerHTML = '<span class="btn-icon">&#9889;</span> Generate New Wallet';
    }
}

async function generateQRCodes(wallet) {
    const qrOptions = {
        width: 200,
        margin: 2,
        color: { dark: '#000000', light: '#ffffff' },
        errorCorrectionLevel: 'H'
    };

    try {
        const addressCanvas = document.getElementById('addressQR');
        await QRCode.toCanvas(addressCanvas, wallet.address, {
            ...qrOptions,
            color: { dark: '#1a1a2e', light: '#ffffff' }
        });

        const wifCanvas = document.getElementById('wifQR');
        await QRCode.toCanvas(wifCanvas, wallet.wif, {
            ...qrOptions,
            color: { dark: '#8b0000', light: '#ffffff' }
        });

        // Paper wallet QR codes
        const paperAddrCanvas = document.getElementById('paperAddressQR');
        if (paperAddrCanvas) {
            await QRCode.toCanvas(paperAddrCanvas, wallet.address, {
                width: 160,
                margin: 1,
                color: { dark: '#1a1a2e', light: '#ffffff' },
                errorCorrectionLevel: 'H'
            });
        }

        const paperWifCanvas = document.getElementById('paperWifQR');
        if (paperWifCanvas) {
            await QRCode.toCanvas(paperWifCanvas, wallet.wif, {
                width: 160,
                margin: 1,
                color: { dark: '#6b1520', light: '#ffffff' },
                errorCorrectionLevel: 'H'
            });
        }
    } catch (err) {
        console.error('QR code generation failed:', err);
    }
}

function updatePaperWallet(wallet) {
    const paperAddress = document.getElementById('paperAddress');
    const paperWif = document.getElementById('paperWif');
    if (paperAddress) paperAddress.textContent = wallet.address;
    if (paperWif) paperWif.textContent = wallet.wif;
}

function handlePrint() {
    window.print();
}

async function handleBulkGenerate() {
    const countInput = document.getElementById('bulkCount');
    const count = Math.min(Math.max(parseInt(countInput.value) || 1, 1), 50);
    countInput.value = count;

    const btn = document.getElementById('bulkGenerateBtn');
    const tbody = document.getElementById('bulkTableBody');
    const section = document.getElementById('bulkResults');

    btn.textContent = 'Generating...';
    btn.disabled = true;

    try {
        bulkWallets = await generateBulkWallets(count);

        tbody.innerHTML = '';
        bulkWallets.forEach((wallet, i) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${i + 1}</td>
                <td class="address-cell">${wallet.address}</td>
                <td class="wif-cell">${wallet.wif}</td>
            `;
            tbody.appendChild(row);
        });

        section.style.display = 'block';
        section.classList.remove('fade-in');
        void section.offsetWidth;
        section.classList.add('fade-in');
    } catch (err) {
        console.error('Bulk generation failed:', err);
        alert('Error generating wallets. Please try again.');
    } finally {
        btn.textContent = 'Generate Wallets';
        btn.disabled = false;
    }
}

function handleExportCSV() {
    if (!bulkWallets.length) return;

    let csv = 'Index,Address,WIF Private Key\n';
    bulkWallets.forEach((w, i) => {
        csv += `${i + 1},"${w.address}","${w.wif}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wojakcoin-wallets-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

function copyToClipboard(elementId, btn) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => {
        const originalHTML = btn.innerHTML;
        btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.classList.remove('copied');
        }, 1500);
    }).catch(() => {
        const el = document.getElementById(elementId);
        const range = document.createRange();
        range.selectNodeContents(el);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
    });
}

// ============================================================
// Tab Navigation
// ============================================================

function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `tab-${tabName}`);
    });
}

// ============================================================
// Smooth scroll & UI initialization
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            // Close mobile menu if open
            const navLinks = document.getElementById('navLinks');
            if (navLinks) navLinks.classList.remove('open');
        });
    });

    // Mobile menu toggle
    const menuToggle = document.getElementById('menuToggle');
    const navLinks = document.getElementById('navLinks');
    if (menuToggle && navLinks) {
        menuToggle.addEventListener('click', () => {
            navLinks.classList.toggle('open');
        });
    }

    // Navbar background on scroll
    const navbar = document.getElementById('navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            navbar.classList.toggle('scrolled', window.scrollY > 20);
        });
    }

    // Offline detection banner
    updateOnlineStatus();
    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);
});

function updateOnlineStatus() {
    let banner = document.getElementById('offlineBanner');
    if (!navigator.onLine) {
        if (!banner) {
            banner = document.createElement('div');
            banner.id = 'offlineBanner';
            banner.className = 'offline-banner';
            banner.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> You are offline — maximum security mode. Keys generated here never touch the network.';
            document.body.prepend(banner);
        }
    } else if (banner) {
        banner.remove();
    }
}
