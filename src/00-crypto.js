/* ============================================================================
 * cwi-verification-kit — src/00-crypto.js
 * Zero-dependency cryptography: keccak256, sha256, secp256k1 ECDSA recovery,
 * and EIP-712 typed-data hashing. Pure BigInt / integer arithmetic — no
 * external packages, works identically in Node and browsers.
 *
 * Every function here is cross-validated in test/crypto.test.js against
 * viem (the existing CWI stack) on the live attestation records.
 * ========================================================================== */

'use strict';

/* ---------------- keccak256 (Keccak-f[1600], pad10*1, domain 0x01) -------- */

const KECCAK_MASK64 = (1n << 64n) - 1n;

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets r[x][y]
const KECCAK_R = [
  [ 0, 36,  3, 41, 18],
  [ 1, 44, 10, 45,  2],
  [62,  6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39,  8, 14],
];

function rotl64(v, n) {
  if (n === 0n || n === 0) return v & KECCAK_MASK64;
  const s = BigInt(n);
  return (((v << s) | (v >> (64n - s))) & KECCAK_MASK64);
}

function keccakF1600(a) {
  for (let round = 0; round < 24; round++) {
    // θ
    const C = [0n, 0n, 0n, 0n, 0n];
    for (let x = 0; x < 5; x++) {
      C[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    const D = [0n, 0n, 0n, 0n, 0n];
    for (let x = 0; x < 5; x++) {
      D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1n);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) a[x + 5 * y] = (a[x + 5 * y] ^ D[x]) & KECCAK_MASK64;
    }
    // ρ and π
    const B = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(a[x + 5 * y], KECCAK_R[x][y]);
      }
    }
    // χ
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const bxy = B[x + 5 * y];
        const bx1 = B[((x + 1) % 5) + 5 * y];
        const bx2 = B[((x + 2) % 5) + 5 * y];
        a[x + 5 * y] = (bxy ^ ((~bx1 & KECCAK_MASK64) & bx2)) & KECCAK_MASK64;
      }
    }
    // ι
    a[0] = (a[0] ^ KECCAK_RC[round]) & KECCAK_MASK64;
  }
}

function keccak256Bytes(msg) {
  const RATE = 136; // bytes
  const bytes = msg instanceof Uint8Array ? msg : Uint8Array.from(msg);
  // pad10*1 with domain suffix 0x01
  const paddedLen = Math.floor((bytes.length + 1 + RATE - 1) / RATE) * RATE || RATE;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x01;
  padded[paddedLen - 1] |= 0x80;
  const state = new Array(25).fill(0n);
  const view = new DataView(padded.buffer);
  for (let off = 0; off < paddedLen; off += RATE) {
    for (let i = 0; i < RATE / 8; i++) {
      state[i] ^= view.getBigUint64(off + i * 8, true);
    }
    keccakF1600(state);
  }
  const out = new Uint8Array(32);
  const oview = new DataView(out.buffer);
  for (let i = 0; i < 4; i++) oview.setBigUint64(i * 8, state[i], true);
  return out;
}

/* ---------------- sha256 (FIPS 180-4, pure integer ops) ------------------- */

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256Bytes(msg) {
  const bytes = msg instanceof Uint8Array ? msg : Uint8Array.from(msg);
  const bitLen = bytes.length * 8;
  const paddedLen = (((bytes.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  // 64-bit big-endian length
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(paddedLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Array(64);

  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  for (let off = 0; off < paddedLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const oview = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => oview.setUint32(i * 4, v, false));
  return out;
}

/* ---------------- byte/hex helpers --------------------------------------- */

function hexToBytes(hex) {
  let h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length % 2) h = '0' + h;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

/* ---------------- secp256k1 ECDSA public-key recovery -------------------- */

const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP_G = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};
const SECP_INF = null;

function secpMod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function secpInv(a, m) {
  // Extended Euclidean algorithm
  let [old_r, r] = [secpMod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return secpMod(old_s, m);
}

function secpAdd(p1, p2) {
  if (p1 === SECP_INF) return p2;
  if (p2 === SECP_INF) return p1;
  const { x: x1, y: y1 } = p1, { x: x2, y: y2 } = p2;
  let lam;
  if (x1 === x2) {
    if (secpMod(y1 + y2, SECP_P) === 0n) return SECP_INF;
    // doubling
    lam = secpMod(3n * x1 * x1 * secpInv(2n * y1, SECP_P), SECP_P);
  } else {
    lam = secpMod((y2 - y1) * secpInv(x2 - x1, SECP_P), SECP_P);
  }
  const x3 = secpMod(lam * lam - x1 - x2, SECP_P);
  const y3 = secpMod(lam * (x1 - x3) - y1, SECP_P);
  return { x: x3, y: y3 };
}

function secpMul(k, pt) {
  let kk = secpMod(k, SECP_N);
  let acc = SECP_INF;
  let base = pt;
  while (kk > 0n) {
    if (kk & 1n) acc = secpAdd(acc, base);
    base = secpAdd(base, base);
    kk >>= 1n;
  }
  return acc;
}

function secpDecompress(x, yParity) {
  // y^2 = x^3 + 7 (mod p); p % 4 == 3 so sqrt via pow((p+1)/4)
  const y2 = secpMod(x * x * x + 7n, SECP_P);
  let y = modPow(y2, (SECP_P + 1n) / 4n, SECP_P);
  if ((y & 1n) !== BigInt(yParity)) y = SECP_P - y;
  return { x, y };
}

function modPow(base, exp, m) {
  let result = 1n;
  let b = secpMod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/**
 * Recover the signer's uncompressed public key (64 bytes, x||y) from an
 * ECDSA signature over a 32-byte message digest.
 * r, s: BigInt; v: 27 | 28 (or 0 | 1); digest: Uint8Array(32).
 * Returns Uint8Array(64) or null on failure.
 */
function secpRecoverPubkey(r, s, v, digest) {
  if (r <= 0n || r >= SECP_N || s <= 0n || s >= SECP_N) return null;
  const recid = v >= 27 ? v - 27 : v;
  if (recid !== 0 && recid !== 1) return null;
  const x = r + BigInt(recid >> 1) * SECP_N;
  if (x >= SECP_P) return null;
  const R = secpDecompress(x, recid & 1);
  const e = bytesToBigInt(digest) % SECP_N;
  const rInv = secpInv(r, SECP_N);
  const u1 = secpMod(-e * rInv, SECP_N);
  const u2 = secpMod(s * rInv, SECP_N);
  const Q = secpAdd(secpMul(u1, SECP_G), secpMul(u2, R));
  if (Q === SECP_INF) return null;
  const out = new Uint8Array(64);
  const view = new DataView(out.buffer);
  const xHex = Q.x.toString(16).padStart(64, '0');
  const yHex = Q.y.toString(16).padStart(64, '0');
  out.set(hexToBytes('0x' + xHex), 0);
  out.set(hexToBytes('0x' + yHex), 32);
  return out;
}

function bytesToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigIntToBytes32(v) {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

/** Ethereum address (0x hex) from a 64-byte uncompressed public key. */
function pubkeyToAddress(pubkey64) {
  const h = keccak256Bytes(pubkey64);
  return bytesToHex(h.slice(12));
}

/* ---------------- EIP-712 typed-data hashing ----------------------------- */

function eip712EncodeType(types, primaryType) {
  const deps = new Set([primaryType]);
  const findDeps = (t) => {
    for (const f of types[t] || []) {
      const bt = f.type.replace(/\[.*\]$/, '');
      if (types[bt] && !deps.has(bt)) { deps.add(bt); findDeps(bt); }
    }
  };
  findDeps(primaryType);
  const sorted = [...deps].filter((d) => d !== primaryType).sort();
  const defOf = (t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(',')})`;
  return defOf(primaryType) + sorted.map(defOf).join('');
}

function eip712TypeHash(types, primaryType) {
  return keccak256Bytes(utf8Bytes(eip712EncodeType(types, primaryType)));
}

function eip712EncodeValue(types, type, value) {
  // arrays
  const arrMatch = type.match(/^(.*)\[(\d*)\]$/);
  if (arrMatch) {
    const base = arrMatch[1];
    const enc = value.map((v) => eip712EncodeValue(types, base, v));
    return keccak256Bytes(concatBytes(...enc));
  }
  if (types[type]) {
    // custom struct -> struct hash
    return eip712HashStruct(types, type, value);
  }
  if (type === 'address') {
    const b = hexToBytes(value);
    const out = new Uint8Array(32);
    out.set(b, 32 - b.length);
    return out;
  }
  if (type === 'bool') {
    const out = new Uint8Array(32);
    out[31] = value ? 1 : 0;
    return out;
  }
  if (type === 'string') return keccak256Bytes(utf8Bytes(value));
  if (type === 'bytes') return keccak256Bytes(hexToBytes(value));
  const bytesN = type.match(/^bytes(\d+)$/);
  if (bytesN) {
    const n = parseInt(bytesN[1], 10);
    const b = hexToBytes(value);
    const out = new Uint8Array(32);
    out.set(b.slice(0, n), 0); // right-padded
    return out;
  }
  const intM = type.match(/^(u?int)(\d*)$/);
  if (intM) {
    const bits = intM[2] ? parseInt(intM[2], 10) : 256;
    let v = BigInt(value);
    if (intM[1] === 'int' && v < 0n) v = (1n << BigInt(bits)) + v;
    return bigIntToBytes32(v);
  }
  throw new Error(`eip712: unsupported type ${type}`);
}

function eip712HashStruct(types, primaryType, message) {
  const typeHash = eip712TypeHash(types, primaryType);
  const parts = [typeHash];
  for (const f of types[primaryType]) {
    parts.push(eip712EncodeValue(types, f.type, message[f.name]));
  }
  return keccak256Bytes(concatBytes(...parts));
}

function eip712HashTypedData(domain, types, primaryType, message) {
  const domainTypes = { EIP712Domain: types.EIP712Domain };
  const domainSeparator = eip712HashStruct(domainTypes, 'EIP712Domain', domain);
  const structHash = eip712HashStruct(types, primaryType, message);
  return keccak256Bytes(concatBytes(
    Uint8Array.from([0x19, 0x01]), domainSeparator, structHash));
}

/**
 * Recover the signer address of an EIP-712 typed-data signature.
 * signature: 0x hex, 65 bytes (r || s || v).
 */
function eip712RecoverAddress(domain, domainFieldTypes, types, primaryType, message, signature) {
  const sig = hexToBytes(signature);
  if (sig.length !== 65) return null;
  const r = bytesToBigInt(sig.slice(0, 32));
  const s = bytesToBigInt(sig.slice(32, 64));
  const v = sig[64];
  const digest = eip712HashTypedData(
    domain, { EIP712Domain: domainFieldTypes, ...types }, primaryType, message);
  const pubkey = secpRecoverPubkey(r, s, v, digest);
  if (!pubkey) return null;
  return pubkeyToAddress(pubkey);
}
