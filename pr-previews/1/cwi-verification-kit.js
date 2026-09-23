/*!
 * cwi-verification-kit v1.0.0 — CWI Trust Layer
 * Zero-dependency verification library: EAS attestation checks, error-bar
 * claim stamping, and trust-verdict agent scoring.
 * (c) 2026 Cumulative Web Inc — MIT License
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) define([], factory);
  else if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.CWIVerificationKit = factory();
}(typeof self !== 'undefined' ? self : this, function () {
'use strict';
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

/* ============================================================================
 * cwi-verification-kit — src/10-eas-verify.js
 * EAS-format off-chain attestation verification for the CWI memory chain.
 *
 * Checks (mirroring cli/chain-verify.test.js, 35 checks):
 *   1. schemaUid is deterministic: keccak256("CWI-MEMORY-ANCHOR-V1:" + schema)
 *   2. domain matches the EAS off-chain spec
 *   3. uid = keccak256(signature)
 *   4. EIP-712 signature recovers the attester address
 *   5. refUID hash-chain linkage across a record array
 *   6. blob binding: sha256(salt || ciphertext) == blobHash (needs ciphertext)
 *   7. ABI payload decode: (bytes32 blobHash, string agentUrn,
 *      uint64 writtenAt, string offchainUri)
 *
 * Depends on: src/00-crypto.js
 * ========================================================================== */

'use strict';

const EAS_ADDRESS = '0x4200000000000000000000000000000000000021';
const EAS_DOMAIN = {
  name: 'EAS Attestation',
  version: '2.0.0',
  chainId: 84532,
  verifyingContract: EAS_ADDRESS,
};
const EIP712_DOMAIN_FIELDS = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' },
];
const ATTEST_TYPES = {
  Attest: [
    { name: 'version', type: 'uint16' },
    { name: 'nonce', type: 'uint256' },
    { name: 'schema', type: 'bytes32' },
    { name: 'recipient', type: 'address' },
    { name: 'time', type: 'uint64' },
    { name: 'expirationTime', type: 'uint64' },
    { name: 'revocable', type: 'bool' },
    { name: 'refUID', type: 'bytes32' },
    { name: 'data', type: 'bytes' },
    { name: 'salt', type: 'bytes32' },
  ],
};
const SCHEMA_PREFIX = 'CWI-MEMORY-ANCHOR-V1:';
const SCHEMA_STR = 'bytes32 blobHash,string agentUrn,uint64 writtenAt,string offchainUri';
const BYTES32_ZERO = '0x' + '00'.repeat(32);
const REQUIRED_FIELDS = ['uid', 'layer', 'schemaUid', 'attester', 'signature',
  'domain', 'message', 'blobSha', 'blobHash', 'agentUrn', 'offchainUri', 'prevUid', 'at'];

/** Deterministic schema UID for the CWI memory-anchor schema. */
function schemaUid() {
  return bytesToHex(keccak256Bytes(utf8Bytes(SCHEMA_PREFIX + SCHEMA_STR)));
}

/** Revive a JSON-serialized message (string bigints) to typed values. */
function reviveMessage(m) {
  return {
    version: Number(m.version),
    nonce: BigInt(m.nonce),
    schema: m.schema,
    recipient: m.recipient,
    time: BigInt(m.time),
    expirationTime: BigInt(m.expirationTime),
    revocable: Boolean(m.revocable),
    refUID: m.refUID,
    data: m.data,
    salt: m.salt,
  };
}

function domainMatches(d) {
  return d && d.name === EAS_DOMAIN.name && d.version === EAS_DOMAIN.version &&
    Number(d.chainId) === EAS_DOMAIN.chainId &&
    String(d.verifyingContract).toLowerCase() === EAS_ADDRESS.toLowerCase();
}

/**
 * Minimal ABI decoder for (bytes32, string, uint64, string) tuples —
 * the exact shape of the memory-anchor `data` payload.
 * Returns { blobHash, agentUrn, writtenAt, offchainUri } or throws.
 */
function decodeAnchorData(dataHex) {
  const b = hexToBytes(dataHex);
  if (b.length < 128) throw new Error('data too short for anchor tuple');
  const view = new DataView(b.buffer, b.byteOffset, b.length);
  const blobHash = bytesToHex(b.slice(0, 32));
  const readU256 = (off) => {
    let v = 0n;
    for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[off + i]);
    return v;
  };
  const off1 = Number(readU256(32));
  const writtenAt = readU256(64);
  const off3 = Number(readU256(96));
  const readString = (off) => {
    const len = Number(readU256(off));
    const start = off + 32;
    return new TextDecoder().decode(b.slice(start, start + len));
  };
  return {
    blobHash,
    agentUrn: readString(off1),
    writtenAt: writtenAt.toString(),
    offchainUri: readString(off3),
  };
}

/**
 * Verify one attestation record.
 * `blob` (optional): { ciphertext: Uint8Array, saltHex: string } — the live
 * encrypted blob bytes plus the salt from the decrypted document. Enables the
 * blob-binding check; without it that check is reported as skipped.
 * Returns { ok, checks: [{name, ok, detail}] }.
 */
function verifyAttestation(record, blob) {
  const checks = [];
  const ck = (name, ok, detail) => {
    checks.push({ name, ok: !!ok, detail: detail || '' });
    return !!ok;
  };

  ck('has all required fields',
    REQUIRED_FIELDS.every((f) => f in record),
    REQUIRED_FIELDS.filter((f) => !(f in record)).join(',') || 'all present');

  const expectedSchema = schemaUid();
  ck('schemaUid is deterministic',
    String(record.schemaUid).toLowerCase() === expectedSchema.toLowerCase(),
    String(record.schemaUid).slice(0, 18) + '…');

  ck('domain matches EAS off-chain spec', domainMatches(record.domain),
    JSON.stringify(record.domain));

  let uidOk = false;
  try {
    uidOk = bytesToHex(keccak256Bytes(hexToBytes(record.signature))).toLowerCase() ===
      String(record.uid).toLowerCase();
  } catch (e) { uidOk = false; }
  ck('uid = keccak256(signature)', uidOk, String(record.uid).slice(0, 18) + '…');

  let recovered = null;
  let sigOk = false;
  try {
    recovered = eip712RecoverAddress(
      EAS_DOMAIN, EIP712_DOMAIN_FIELDS, ATTEST_TYPES, 'Attest',
      reviveMessage(record.message), record.signature);
    sigOk = recovered !== null &&
      recovered.toLowerCase() === String(record.attester).toLowerCase();
  } catch (e) { sigOk = false; }
  ck('signature recovers attester', sigOk,
    recovered ? `recovered ${recovered.slice(0, 10)}…` : 'recovery failed');

  // data payload decode
  let decoded = null;
  try {
    decoded = decodeAnchorData(record.message.data);
    ck('data payload decodes cleanly',
      decoded.blobHash.toLowerCase() === String(record.blobHash).toLowerCase() &&
      decoded.agentUrn === record.agentUrn,
      `urn=${decoded.agentUrn}`);
  } catch (e) {
    ck('data payload decodes cleanly', false, e.message);
  }

  // blob binding (needs the live ciphertext + the doc salt from decryption)
  if (blob && blob.ciphertext && blob.saltHex) {
    try {
      const salt = hexToBytes(blob.saltHex);
      const localHash = bytesToHex(sha256Bytes(concatBytes(salt, blob.ciphertext)));
      ck('blob hash binds (record == chain data == live blob)',
        localHash.toLowerCase() === String(record.blobHash).toLowerCase() &&
        (decoded ? decoded.blobHash.toLowerCase() === String(record.blobHash).toLowerCase() : true),
        String(record.blobHash).slice(0, 18) + '…');
    } catch (e) {
      ck('blob hash binds (record == chain data == live blob)', false, e.message);
    }
  } else {
    checks.push({ name: 'blob hash binds (record == chain data == live blob)', ok: null,
      detail: 'skipped — no ciphertext supplied' });
  }

  const ok = checks.every((c) => c.ok !== false);
  return { ok, checks };
}

/**
 * Verify refUID hash-chain linkage across an ordered record array.
 * records[0] must chain from bytes32(0) (genesis).
 */
function verifyChain(records) {
  const checks = [];
  for (let i = 0; i < records.length; i++) {
    const expected = i === 0 ? BYTES32_ZERO : records[i - 1].uid;
    const ok = String(records[i].prevUid).toLowerCase() === expected.toLowerCase();
    checks.push({
      name: `record[${i}] refUID chains to previous`,
      ok,
      detail: i === 0 ? 'genesis → zero' : `prev ${String(records[i].prevUid).slice(0, 10)}…`,
    });
  }
  return { ok: checks.every((c) => c.ok), checks };
}

/**
 * Negative control: flip one hex char of the signature; the mutated
 * signature must NOT recover the attester. Returns true when the tamper
 * is correctly detected (i.e. the mutated signature fails).
 */
function tamperCheckSignature(record) {
  const sig = String(record.signature);
  const badSig = '0x' + (sig[2] === '0' ? 'f' : '0') + sig.slice(3);
  try {
    const badRecovered = eip712RecoverAddress(
      EAS_DOMAIN, EIP712_DOMAIN_FIELDS, ATTEST_TYPES, 'Attest',
      reviveMessage(record.message), badSig);
    return badRecovered === null ||
      badRecovered.toLowerCase() !== String(record.attester).toLowerCase();
  } catch (e) {
    return true; // rejected outright — also a correct outcome
  }
}

/**
 * Negative control: flip one bit of the ciphertext; the blob hash must
 * change (tamper detected). Needs { ciphertext, saltHex }.
 */
function tamperCheckBlob(record, blob) {
  const tampered = Uint8Array.from(blob.ciphertext);
  tampered[100 % tampered.length] ^= 0x01;
  const salt = hexToBytes(blob.saltHex);
  const h = bytesToHex(sha256Bytes(concatBytes(salt, tampered)));
  return h.toLowerCase() !== String(record.blobHash).toLowerCase();
}

/* ============================================================================
 * cwi-verification-kit — src/20-error-bar.js
 * The Error Bar v1.0.0 — JS port of errorbar.py (CWI gear-line).
 *
 * "Fake precision dies on contact."
 *
 * Claim in -> the same claim stamped with a machine-readable confidence
 * interval, a provenance check, and a reproducibility record.
 *
 * Fidelity notes (honest, documented):
 *  - The seeded Monte Carlo uses an MT19937 reimplementation that is
 *    bit-exact with CPython's random.Random(seed) (same init_by_array
 *    seeding, same genrand_int32 tempering, same 53-bit random() mapping).
 *    Interval bounds are byte-identical to the Python tool for the same
 *    (claim, seed, stamped_at). Verified in test/error-bar.test.js against
 *    the live Python tool on this machine.
 *  - The Wilson interval is pure deterministic math; method_id is shared
 *    with the Python tool (eb-wilson/1.0).
 *  - The reproducibility string names the reference Python CLI verbatim, so
 *    stamped outputs are byte-identical across implementations for the same
 *    (claim, seed, stamped_at). A JS-produced stamp re-run through
 *    `python3 errorbar.py stamp` reproduces byte-for-byte, and vice versa.
 *  - Canonical JSON mirrors Python (sort_keys, compact separators,
 *    ensure_ascii). Known edge divergence: exponent-lexical floats
 *    (Python '1e-07' vs JS '1e-7') and float-lexical integers in the INPUT
 *    (307000.0) hash differently across languages because JSON erases the
 *    int/float distinction. Fixtures avoid these; cross-language `verify`
 *    on such inputs should use the same-language tool. Documented, not
 *    hidden.
 *  - JS is stricter on two inputs the Python accepts-then-crashes-on:
 *    non-finite point_estimate (throws here; Python crashes at JSON dump)
 *    and non-integer seeds for the MC path (BigInt conversion throws).
 *
 * Depends on: src/00-crypto.js (sha256Bytes, utf8Bytes)
 * ========================================================================== */

'use strict';

const EB_TOOL_VERSION = '1.0.0';
const EB_METHOD_NORMAL = 'eb-mc-normal/1.0';
const EB_METHOD_FORECAST = 'eb-mc-forecast/1.0';
const EB_METHOD_WILSON = 'eb-wilson/1.0';
const EB_DRAWS = 4096;
const EB_NOMINAL_COVERAGE = 0.90;
const EB_Z90 = 1.6448536269514722;

const EB_TIERS = {
  'verified':      { rel_sd: 0.05, min_sources: 2, confidence: 'strong' },
  'corroborated':  { rel_sd: 0.12, min_sources: 1, confidence: 'moderate' },
  'single-source': { rel_sd: 0.25, min_sources: 1, confidence: 'weak' },
  'anecdotal':     { rel_sd: 0.50, min_sources: 1, confidence: 'weak' },
  'none':          { rel_sd: null, min_sources: 0, confidence: 'insufficient-data' },
};
const EB_CLAIM_TYPES = ['stat', 'forecast', 'proportion'];
const EB_METADATA_KEYS = ['stamped_at', 'output_sha256'];

/* ---------------- CPython-exact MT19937 ---------------------------------- */

const MT_N = 624, MT_M = 397, MT_MATRIX_A = 0x9908b0df;

function mtSeedFromInt(seedBig) {
  // CPython: little-endian 32-bit words of abs(seed); seed 0 -> [0].
  let a = seedBig < 0n ? -seedBig : seedBig;
  const words = [];
  if (a === 0n) return [0];
  while (a > 0n) { words.push(Number(a & 0xffffffffn)); a >>= 32n; }
  return words;
}

function mtInitByArray(key) {
  const mt = new Array(MT_N).fill(0);
  const initGenrand = (s) => {
    mt[0] = s >>> 0;
    for (let i = 1; i < MT_N; i++) {
      mt[i] = (Math.imul(1812433253, mt[i - 1] ^ (mt[i - 1] >>> 30)) + i) >>> 0;
    }
  };
  initGenrand(19650218);
  let i = 1, j = 0;
  let k = key.length > MT_N ? key.length : MT_N;
  for (; k > 0; k--) {
    mt[i] = ((mt[i] ^ Math.imul(mt[i - 1] ^ (mt[i - 1] >>> 30), 1664525)) + key[j] + j) >>> 0;
    i++; j++;
    if (i >= MT_N) { mt[0] = mt[MT_N - 1]; i = 1; }
    if (j >= key.length) j = 0;
  }
  for (k = MT_N - 1; k > 0; k--) {
    mt[i] = ((mt[i] ^ Math.imul(mt[i - 1] ^ (mt[i - 1] >>> 30), 1566083941)) - i) >>> 0;
    i++;
    if (i >= MT_N) { mt[0] = mt[MT_N - 1]; i = 1; }
  }
  mt[0] = 0x80000000;
  return { mt, index: MT_N };
}

function mtGenrandInt32(st) {
  const { mt } = st;
  const mag01 = [0, MT_MATRIX_A];
  if (st.index >= MT_N) {
    let kk;
    for (kk = 0; kk < MT_N - MT_M; kk++) {
      const y = ((mt[kk] & 0x80000000) | (mt[kk + 1] & 0x7fffffff)) >>> 0;
      mt[kk] = (mt[kk + MT_M] ^ (y >>> 1) ^ mag01[y & 1]) >>> 0;
    }
    for (; kk < MT_N - 1; kk++) {
      const y = ((mt[kk] & 0x80000000) | (mt[kk + 1] & 0x7fffffff)) >>> 0;
      mt[kk] = (mt[kk + (MT_M - MT_N)] ^ (y >>> 1) ^ mag01[y & 1]) >>> 0;
    }
    const y = ((mt[MT_N - 1] & 0x80000000) | (mt[0] & 0x7fffffff)) >>> 0;
    mt[MT_N - 1] = (mt[MT_M - 1] ^ (y >>> 1) ^ mag01[y & 1]) >>> 0;
    st.index = 0;
  }
  let y = mt[st.index++];
  y = (y ^ (y >>> 11)) >>> 0;
  y = (y ^ ((y << 7) & 0x9d2c5680)) >>> 0;
  y = (y ^ ((y << 15) & 0xefc60000)) >>> 0;
  y = (y ^ (y >>> 18)) >>> 0;
  return y;
}

/** CPython random.Random(seed).random() — 53-bit double in [0, 1). */
function mtRandom(st) {
  const a = mtGenrandInt32(st) >>> 5;
  const b = mtGenrandInt32(st) >>> 6;
  return (a * 67108864.0 + b) / 9007199254740992.0;
}

function ebMcInterval(point, sd, seed) {
  const st = mtInitByArray(mtSeedFromInt(BigInt(seed)));
  const draws = new Array(EB_DRAWS);
  for (let i = 0; i < EB_DRAWS; i++) {
    let u1 = mtRandom(st);
    const u2 = mtRandom(st);
    if (u1 === 0.0) u1 = Math.pow(2, -53);
    const z = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
    draws[i] = point + sd * z;
  }
  draws.sort((x, y) => x - y);
  const loQ = (1.0 - EB_NOMINAL_COVERAGE) / 2.0;
  const hi = draws[Math.min(EB_DRAWS - 1, Math.floor((1.0 - loQ) * EB_DRAWS))];
  const lo = draws[Math.min(EB_DRAWS - 1, Math.floor(loQ * EB_DRAWS))];
  return [lo, hi];
}

function ebWilson(p, n) {
  const z = EB_Z90;
  const denom = 1.0 + z * z / n;
  const center = (p + z * z / (2.0 * n)) / denom;
  const half = z * Math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / denom;
  return [Math.max(0.0, center - half), Math.min(1.0, center + half)];
}

/* ---------------- canonical JSON (Python-compatible) ----------------------- */

function ebCanonical(value) {
  // sort_keys=True, separators=(",", ":"), ensure_ascii=True
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!isFinite(value)) throw new Error('non-finite number in canonical JSON');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    // JSON.stringify escapes non-ASCII as-is (keeps UTF-8); Python ensure_ascii
    // escapes them as \uXXXX. Normalize here.
    return JSON.stringify(value).replace(/[\u0080-\uFFFF]/g, (ch) => {
      const code = ch.charCodeAt(0);
      return '\\u' + code.toString(16).padStart(4, '0');
    });
  }
  if (Array.isArray(value)) {
    return '[' + value.map(ebCanonical).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => ebCanonical(k) + ':' + ebCanonical(value[k])).join(',') + '}';
}

function ebSha256Hex(str) {
  return bytesToHex(sha256Bytes(utf8Bytes(str))).slice(2);
}

/* ---------------- provenance + stamp + verify ------------------------------ */

function ebCheck(name, ok, detail) {
  return { name, ok: !!ok, detail };
}

function ebProvenance(claim) {
  const checks = [];
  const sources = claim.sources || [];
  const tier = claim.evidence_tier;
  const claimType = claim.claim_type;

  checks.push(ebCheck('claim_type_known', EB_CLAIM_TYPES.includes(claimType),
    EB_CLAIM_TYPES.includes(claimType)
      ? `claim_type '${claimType}' routed to an interval method`
      : `unknown claim_type '${claimType}' (expected one of ${EB_CLAIM_TYPES.join(', ')})`));

  checks.push(ebCheck('evidence_tier_known', tier in EB_TIERS,
    tier in EB_TIERS ? `evidence tier '${tier}'` : `unknown evidence_tier '${tier}'`));

  checks.push(ebCheck('sources_present', sources.length > 0,
    sources.length > 0 ? `${sources.length} source(s) listed` : 'no sources listed'));

  if (tier in EB_TIERS) {
    const need = EB_TIERS[tier].min_sources;
    checks.push(ebCheck('tier_source_minimum', sources.length >= need,
      `tier '${tier}' needs >=${need} source(s), has ${sources.length}`));
  }

  const badUrls = sources.filter((s) => typeof s !== 'object' || s === null || (!s.url && !s.ref));
  checks.push(ebCheck('sources_identifiable', badUrls.length === 0,
    badUrls.length === 0 ? 'all sources have a url or ref'
      : `${badUrls.length} source(s) lack both url and ref`));

  const obs = claim.observed_at;
  let obsOk = true, obsDetail = 'observed_at not given (optional)';
  if (obs) {
    const dt = new Date(String(obs).replace('Z', '+00:00'));
    if (isNaN(dt.getTime())) {
      obsOk = false; obsDetail = `observed_at '${obs}' is not ISO-8601`;
    } else {
      obsOk = dt.getTime() <= Date.now();
      obsDetail = obsOk ? `observed_at ${obs}` : `observed_at ${obs} is in the future`;
    }
  }
  checks.push(ebCheck('observed_at_sane', obsOk, obsDetail));

  let status;
  if (tier === 'none' || !(tier in EB_TIERS) || !EB_CLAIM_TYPES.includes(claimType)) {
    status = 'insufficient-data';
  } else if (checks.every((c) => c.ok)) {
    status = 'pass';
  } else {
    status = 'flagged';
  }
  return { status, checks };
}

function ebStamp(claim, seed, at) {
  if (typeof claim !== 'object' || claim === null || Array.isArray(claim)) {
    throw new Error('claim must be a JSON object');
  }
  for (const f of ['claim', 'point_estimate', 'claim_type', 'evidence_tier']) {
    if (!(f in claim)) throw new Error(`missing required field '${f}'`);
  }
  const point = claim.point_estimate;
  if (typeof point !== 'number' || !isFinite(point)) {
    throw new Error('point_estimate must be a number');
  }
  const tier = claim.evidence_tier;
  const claimType = claim.claim_type;
  const { status, checks } = ebProvenance(claim);

  let interval = null, methodId = null, methodNote = null;
  if (status !== 'insufficient-data') {
    let lo, hi;
    if (claimType === 'stat') {
      const sd = Math.abs(point) * EB_TIERS[tier].rel_sd;
      [lo, hi] = ebMcInterval(point, sd, seed);
      methodId = EB_METHOD_NORMAL;
      methodNote = `4096 seeded draws from Normal(mean=point_estimate, sd=|point|*tier_rel_sd); 5th/95th percentiles. tier_rel_sd=${EB_TIERS[tier].rel_sd}.`;
    } else if (claimType === 'forecast') {
      const horizon = claim.horizon_days !== undefined ? claim.horizon_days : 30;
      if (typeof horizon !== 'number' || horizon < 0) {
        throw new Error('horizon_days must be a non-negative number');
      }
      const sd = Math.abs(point) * EB_TIERS[tier].rel_sd * (1.0 + horizon / 30.0);
      [lo, hi] = ebMcInterval(point, sd, seed);
      methodId = EB_METHOD_FORECAST;
      methodNote = `4096 seeded draws from Normal(mean=point_estimate, sd=|point|*tier_rel_sd*(1+horizon_days/30)); 5th/95th percentiles. horizon_days=${horizon}.`;
    } else if (claimType === 'proportion') {
      const n = claim.sample_n;
      if (!Number.isInteger(n) || n <= 0) {
        throw new Error('proportion claims require a positive integer sample_n');
      }
      if (!(point >= 0.0 && point <= 1.0)) {
        throw new Error('proportion point_estimate must be in [0,1]');
      }
      [lo, hi] = ebWilson(point, n);
      methodId = EB_METHOD_WILSON;
      methodNote = `Wilson score interval, z=1.6449 (90%), n=${n}. Deterministic; seed carried but unused.`;
    }
    interval = { low: lo, high: hi, nominal_coverage: EB_NOMINAL_COVERAGE, method_id: methodId };
  }

  let confidence = tier in EB_TIERS ? EB_TIERS[tier].confidence : 'insufficient-data';
  if (status === 'insufficient-data') confidence = 'insufficient-data';

  const stampedAt = at || new Date().toISOString();
  const out = {
    tool: 'error-bar',
    tool_version: EB_TOOL_VERSION,
    label: claim.label || 'SAMPLE',
    claim: claim.claim,
    claim_type: claimType,
    point_estimate: point,
    unit: claim.unit !== undefined ? claim.unit : null,
    interval,
    confidence_tier: confidence,
    provenance: {
      status,
      checks,
      source_count: (claim.sources || []).length,
    },
    seed,
    input_sha256: ebSha256Hex(ebCanonical(claim)),
    reproducibility:
      `Re-run: python3 errorbar.py stamp --in <claim.json> ` +
      `--seed ${seed} --at ${stampedAt}  ->  byte-identical output expected. ` +
      `Method ${methodId === null ? 'None' : methodId}: ${methodNote === null ? 'None' : methodNote} ` +
      `Fields stamped_at and output_sha256 are run metadata and are ` +
      `excluded from the recompute comparison performed by ` +
      `\`errorbar.py verify\`. An output that cannot be re-run is void.`,
    stamped_at: stampedAt,
  };
  const body = {};
  for (const k of Object.keys(out)) {
    if (!EB_METADATA_KEYS.includes(k)) body[k] = out[k];
  }
  out.output_sha256 = ebSha256Hex(ebCanonical(body));
  return out;
}

function ebVerify(claim, stamped) {
  const seed = stamped.seed;
  if (!Number.isInteger(seed)) {
    return { reproduced: false, reason: 'stamped output has no integer seed' };
  }
  const at = stamped.stamped_at;
  let recomputed;
  try {
    recomputed = ebStamp(claim, seed, at);
  } catch (e) {
    return { reproduced: false, reason: 'recompute failed: ' + e.message };
  }
  const strip = (o) => {
    const b = {};
    for (const k of Object.keys(o)) if (!EB_METADATA_KEYS.includes(k)) b[k] = o[k];
    return b;
  };
  const a = strip(stamped), b = strip(recomputed);
  if (ebCanonical(a) === ebCanonical(b)) {
    return {
      reproduced: true,
      method_id: (stamped.interval || {}).method_id,
      input_sha256: stamped.input_sha256,
    };
  }
  const diffs = [...new Set([...Object.keys(a), ...Object.keys(b)])]
    .filter((k) => ebCanonical(a[k]) !== ebCanonical(b[k])).sort();
  return { reproduced: false, reason: 'fields differ', differing_fields: diffs };
}

/* ============================================================================
 * cwi-verification-kit — src/30-trust-verdict.js
 * CWI Verdict Engine v1.0.0 — JS port of trust/engine.py (spec 1.0.0).
 *
 * Deterministic, evidence-bound trust scoring for AI agents. Same inputs ->
 * byte-identical outputs (canonical comparison). Never invents a score:
 * insufficient or disputed evidence yields a refusal status, never a number.
 *
 * Fidelity notes:
 *  - input_sha256 is computed over the canonical JSON form with UTF-8
 *    preserved (ensure_ascii=False equivalent). Matches the Python engine
 *    for the same input document.
 *  - Final score rounding uses Python round-half-even semantics.
 *  - Error strings replicate Python %r (single-quote) formatting so
 *    invalid-input outputs match the Python engine canonically.
 *  - Output key ORDER is not guaranteed identical to Python's insertion
 *    order; compare canonical forms (sorted keys), as the tests do.
 *
 * Depends on: src/00-crypto.js (sha256Bytes, utf8Bytes)
 * ========================================================================== */

'use strict';

const TV_ENGINE_NAME = 'cwi-verdict-engine';
const TV_ENGINE_VERSION = '1.0.0';
const TV_SPEC_VERSION = '1.0.0';

const TV_FAMILIES = ['erc8004', 'needle_drop', 'first_spin'];
const TV_WEIGHT_CLASSES = { 1: 'self-asserted', 2: 'third-party-attested', 3: 'protocol-or-ledger-sealed' };
const TV_SELF_ASSERTION_FACTOR = 0.5;
const TV_ISSUER_CAP_PER_FAMILY = 2;
const TV_SATURATION_K = 3.0;

const TV_CONTEXTS = {
  'agent-trust': {
    description: 'General trust in an agent as an ecosystem participant.',
    min_verified: 3,
    min_families: 2,
    required_families: ['erc8004'],
    required_any_of: [],
    rationale: 'General trust requires an anchored identity (ERC-8004) plus corroboration from at least one more family.',
  },
  'music-review': {
    description: 'Trust in an agent as a music evaluator/curator.',
    min_verified: 2,
    min_families: 1,
    required_families: [],
    required_any_of: ['first_spin', 'needle_drop'],
    rationale: 'Music-domain trust requires music-domain evidence: published First Spin verdicts or verified Needle Drop history.',
  },
  'payments': {
    description: 'Trust in an agent as a payment counterparty.',
    min_verified: 2,
    min_families: 2,
    required_families: ['erc8004', 'needle_drop'],
    required_any_of: [],
    rationale: 'Payments require a verifiable identity anchor plus completed commercial history.',
  },
};

const TV_BANDS = [
  [0.80, 'established'],
  [0.60, 'emerging'],
  [0.40, 'thin'],
  [0.20, 'weak'],
  [0.00, 'negligible'],
];

const TV_VALID_STATUSES = ['verified', 'claimed', 'pending', 'disputed', 'refuted'];
const TV_VALID_ISSUER_TYPES = ['self', 'third_party', 'protocol'];

/* Python repr() for strings: single quotes (good enough for our messages). */
function pyRepr(s) {
  return `'${String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

/* Python repr() of a list: ['a', 'b'] / [1, 2, 3]. */
function pyReprList(arr) {
  return '[' + arr.map((x) => typeof x === 'string' ? pyRepr(x) : String(x)).join(', ') + ']';
}

/* Python round-half-even to 3 decimals. */
function pyRound3(x) {
  const m = x * 1000;
  const f = Math.floor(m);
  const diff = m - f;
  let r;
  if (diff < 0.5) r = f;
  else if (diff > 0.5) r = f + 1;
  else r = (f % 2 === 0) ? f : f + 1;
  return r / 1000;
}

/* Canonical JSON: sorted keys, compact, UTF-8 preserved (ensure_ascii=False).
 * Float-lexical fidelity: Python prints integral floats as "2.0" while JS
 * prints "2". Values the Python engine computes as floats are tagged with
 * pyFloat() so the canonical form matches byte-for-byte. */
function pyFloat(v) {
  const n = new Number(v);
  n.__pyFloat = true;
  return n;
}

function tvCanonical(value) {
  if (value === null || value === undefined) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (value instanceof Number) {
    const v = value.valueOf();
    if (!isFinite(v)) throw new Error('non-finite number in canonical JSON');
    if (value.__pyFloat && Number.isInteger(v)) return JSON.stringify(v) + '.0';
    return JSON.stringify(v);
  }
  if (typeof value === 'number') {
    if (!isFinite(value)) throw new Error('non-finite number in canonical JSON');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(tvCanonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => tvCanonical(k) + ':' + tvCanonical(value[k])).join(',') + '}';
}

function tvCanonicalHash(doc) {
  return bytesToHex(sha256Bytes(utf8Bytes(tvCanonical(doc)))).slice(2);
}

function tvValidate(doc) {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return 'input must be a JSON object';
  }
  if (doc.engine_version !== TV_ENGINE_VERSION) {
    return `engine_version must be ${pyRepr(TV_ENGINE_VERSION)}, got ${pyRepr(doc.engine_version)}`;
  }
  const subject = doc.subject;
  if (typeof subject !== 'object' || subject === null ||
      typeof subject.agent_id !== 'string' || !subject.agent_id) {
    return 'subject.agent_id must be a non-empty string';
  }
  if (typeof doc.context !== 'string') return 'context must be a string';
  if (typeof doc.observed_at !== 'string' || !doc.observed_at) {
    return 'observed_at must be a non-empty string (ISO-8601)';
  }
  const signals = doc.signals;
  if (typeof signals !== 'object' || signals === null || Array.isArray(signals)) {
    return 'signals must be an object';
  }
  const gotKeys = Object.keys(signals).sort();
  const wantKeys = [...TV_FAMILIES].sort();
  if (JSON.stringify(gotKeys) !== JSON.stringify(wantKeys)) {
    return `signals must contain exactly the families ${pyReprList(TV_FAMILIES)}, got ${pyReprList(gotKeys)}`;
  }
  for (const fam of TV_FAMILIES) {
    const items = signals[fam];
    if (!Array.isArray(items)) return `signals.${fam} must be a list`;
    const seen = new Set();
    for (let i = 0; i < items.length; i++) {
      const e = items[i];
      const where = `signals.${fam}[${i}]`;
      if (typeof e !== 'object' || e === null || Array.isArray(e)) {
        return `${where} must be an object`;
      }
      const eid = e.evidence_id;
      if (typeof eid !== 'string' || !eid) {
        return `${where}.evidence_id must be a non-empty string`;
      }
      if (seen.has(eid)) return `${where}: duplicate evidence_id ${pyRepr(eid)}`;
      seen.add(eid);
      for (const f of ['kind', 'issuer', 'description']) {
        if (typeof e[f] !== 'string' || !e[f]) {
          return `${where}.${f} must be a non-empty string`;
        }
      }
      if (!TV_VALID_ISSUER_TYPES.includes(e.issuer_type)) {
        return `${where}.issuer_type must be one of ${pyReprList(TV_VALID_ISSUER_TYPES)}`;
      }
      if (!TV_VALID_STATUSES.includes(e.status)) {
        return `${where}.status must be one of ${pyReprList(TV_VALID_STATUSES)}`;
      }
      if (!(e.weight_class in TV_WEIGHT_CLASSES)) {
        return `${where}.weight_class must be one of ${pyReprList(Object.keys(TV_WEIGHT_CLASSES).map(Number).sort((a, b) => a - b))}`;
      }
      if (typeof e.observed_at !== 'string' || !e.observed_at) {
        return `${where}.observed_at must be a non-empty string`;
      }
      const cluster = e.identity_cluster;
      if (cluster !== null && cluster !== undefined &&
          (typeof cluster !== 'string' || !cluster)) {
        return `${where}.identity_cluster must be a non-empty string or null`;
      }
    }
  }
  const notes = doc.evidence_notes;
  if (notes !== null && notes !== undefined &&
      (typeof notes !== 'object' || Array.isArray(notes))) {
    return 'evidence_notes must be an object if present';
  }
  return null;
}

function tvProcessFamily(items) {
  const notCounted = [];
  const verified = [];
  for (const e of items) {
    if (e.status === 'verified') verified.push(e);
    else {
      notCounted.push({
        evidence_id: e.evidence_id,
        status: e.status,
        reason: 'status is not verified — contributes 0',
      });
    }
  }
  notCounted.sort((a, b) => a.evidence_id < b.evidence_id ? -1 : a.evidence_id > b.evidence_id ? 1 : 0);

  const groups = {};
  for (const e of verified) {
    const key = e.identity_cluster || ('issuer:' + e.issuer);
    (groups[key] = groups[key] || []).push(e);
  }

  const kept = [];
  const damped = [];
  for (const key of Object.keys(groups).sort()) {
    const members = groups[key].slice().sort((a, b) =>
      (b.weight_class - a.weight_class) ||
      (a.evidence_id < b.evidence_id ? -1 : a.evidence_id > b.evidence_id ? 1 : 0));
    for (const e of members.slice(0, TV_ISSUER_CAP_PER_FAMILY)) {
      const factor = e.issuer_type === 'self' ? TV_SELF_ASSERTION_FACTOR : 1.0;
      kept.push({ e, w: e.weight_class * factor, self: e.issuer_type === 'self' });
    }
    for (const e of members.slice(TV_ISSUER_CAP_PER_FAMILY)) {
      damped.push({
        evidence_id: e.evidence_id,
        reason: 'issuer-cap',
        detail: `identity cluster ${pyRepr(key)} exceeds cap of ${TV_ISSUER_CAP_PER_FAMILY} verified items per family`,
      });
    }
  }
  kept.sort((a, b) => a.e.evidence_id < b.e.evidence_id ? -1 : a.e.evidence_id > b.e.evidence_id ? 1 : 0);
  damped.sort((a, b) => a.evidence_id < b.evidence_id ? -1 : a.evidence_id > b.evidence_id ? 1 : 0);

  const keptWeight = kept.reduce((n, t) => n + t.w, 0);
  const selfDiscounted = kept.filter((t) => t.self).map((t) => t.e.evidence_id);
  const familyScore = keptWeight / (keptWeight + TV_SATURATION_K);

  return {
    evidence_submitted: items.length,
    verified_count: verified.length,
    kept_count: kept.length,
    kept_weight: kept.length > 0 ? pyFloat(keptWeight) : keptWeight,
    self_assertion_discounted: selfDiscounted,
    damped,
    not_counted: notCounted,
    kept_evidence_ids: kept.map((t) => t.e.evidence_id),
    family_score: pyFloat(familyScore),
  };
}

function tvBandFor(score) {
  for (const [threshold, band] of TV_BANDS) {
    if (score >= threshold) return band;
  }
  return 'negligible';
}

function tvScore(doc) {
  const context = doc.context;
  const inputSha = tvCanonicalHash(doc);
  const base = {
    engine: TV_ENGINE_NAME,
    engine_version: TV_ENGINE_VERSION,
    spec_version: TV_SPEC_VERSION,
    subject: {
      agent_id: doc.subject.agent_id,
      display_name: doc.subject.display_name !== undefined ? doc.subject.display_name : null,
    },
    context,
    observed_at: doc.observed_at,
    input_sha256: inputSha,
  };

  if (!(context in TV_CONTEXTS)) {
    base.status = 'unknown-context';
    base.score = null;
    base.band = null;
    base.missing = [`context ${pyRepr(context)} is not in the context registry ${pyReprList(Object.keys(TV_CONTEXTS).sort())}`];
    base.families = {};
    base.notes = doc.evidence_notes || {};
    return base;
  }

  const disputedSet = new Set();
  for (const fam of TV_FAMILIES) {
    for (const e of doc.signals[fam]) {
      if (e.status === 'disputed') disputedSet.add(e.evidence_id);
    }
  }
  const disputed = [...disputedSet].sort();
  const families = {};
  for (const fam of TV_FAMILIES) families[fam] = tvProcessFamily(doc.signals[fam]);

  if (disputed.length > 0) {
    base.status = 'evidence-disputed';
    base.score = null;
    base.band = null;
    base.missing = [`resolve disputed evidence before scoring: ${disputed.join(', ')}`];
    base.families = families;
    base.notes = doc.evidence_notes || {};
    return base;
  }

  const cfg = TV_CONTEXTS[context];
  const verifiedTotal = TV_FAMILIES.reduce((n, f) => n + families[f].verified_count, 0);
  const famsWithVerified = TV_FAMILIES.filter((f) => families[f].verified_count > 0).sort();

  const missing = [];
  for (const fam of cfg.required_families) {
    if (families[fam].verified_count === 0) {
      missing.push(`${fam}: 0 verified evidence items (required by context ${pyRepr(context)})`);
    }
  }
  if (cfg.required_any_of.length > 0 &&
      !cfg.required_any_of.some((f) => families[f].verified_count > 0)) {
    missing.push(`none of ${pyReprList(cfg.required_any_of)} has verified evidence (context ${pyRepr(context)} requires at least one)`);
  }
  if (verifiedTotal < cfg.min_verified) {
    missing.push(`verified evidence items: ${verifiedTotal} found, ${cfg.min_verified} required by context ${pyRepr(context)}`);
  }
  if (famsWithVerified.length < cfg.min_families) {
    missing.push(`families with verified evidence: ${famsWithVerified.length} found, ${cfg.min_families} required by context ${pyRepr(context)}`);
  }

  base.gate = {
    min_verified: cfg.min_verified,
    verified_found: verifiedTotal,
    min_families: cfg.min_families,
    families_with_verified: famsWithVerified,
    required_families: cfg.required_families,
    required_any_of: cfg.required_any_of,
    rationale: cfg.rationale,
    met: missing.length === 0,
  };

  if (missing.length > 0) {
    base.status = 'insufficient-data';
    base.score = null;
    base.band = null;
    base.missing = missing;
    base.families = families;
    base.notes = doc.evidence_notes || {};
    return base;
  }

  const scored = TV_FAMILIES
    .filter((f) => families[f].kept_count > 0)
    .map((f) => families[f].family_score);
  const final = pyRound3(scored.reduce((a, b) => a + b, 0) / scored.length);
  base.status = 'scored';
  base.score = pyFloat(final);
  base.band = tvBandFor(final);
  base.missing = [];
  base.families = families;
  base.notes = doc.evidence_notes || {};
  return base;
}

function tvRun(doc) {
  const err = tvValidate(doc);
  if (err !== null) {
    const isObj = typeof doc === 'object' && doc !== null && !Array.isArray(doc);
    return [{
      engine: TV_ENGINE_NAME,
      engine_version: TV_ENGINE_VERSION,
      spec_version: TV_SPEC_VERSION,
      subject: isObj ? doc.subject : null,
      context: isObj ? doc.context : null,
      observed_at: isObj ? doc.observed_at : null,
      input_sha256: null,
      status: 'invalid-input',
      score: null,
      band: null,
      missing: [err],
      families: {},
      notes: {},
    }, 2];
  }
  return [tvScore(doc), 0];
}


/* ---------------- public API ---------------- */
function kitToBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input === 'string') return hexToBytes(input);
  if (Array.isArray(input)) return Uint8Array.from(input);
  throw new Error('expected 0x hex string, Uint8Array, or byte array');
}

const CWIVerificationKit = {
  version: '1.0.0',

  /* crypto primitives */
  keccak256Hex: (input) => bytesToHex(keccak256Bytes(kitToBytes(input))),
  sha256Hex: (input) => bytesToHex(sha256Bytes(kitToBytes(input))).slice(2),
  eip712HashTypedData,
  eip712RecoverAddress,
  hexToBytes, bytesToHex, utf8Bytes, concatBytes,

  /* EAS attestation verification */
  EAS_ADDRESS, EAS_DOMAIN, ATTEST_TYPES, SCHEMA_STR, BYTES32_ZERO,
  schemaUid, reviveMessage, decodeAnchorData,
  verifyAttestation, verifyChain, tamperCheckSignature, tamperCheckBlob,

  /* error-bar */
  errorbar: {
    TOOL_VERSION: EB_TOOL_VERSION,
    METHOD_NORMAL: EB_METHOD_NORMAL,
    METHOD_FORECAST: EB_METHOD_FORECAST,
    METHOD_WILSON: EB_METHOD_WILSON,
    stamp: ebStamp,
    verify: ebVerify,
  },

  /* trust-verdict */
  verdict: {
    ENGINE_NAME: TV_ENGINE_NAME,
    ENGINE_VERSION: TV_ENGINE_VERSION,
    SPEC_VERSION: TV_SPEC_VERSION,
    run: tvRun,
    score: tvScore,
  },
  /* test/power-user internals (canonical hashing, Python-parity rounding) */
  _internals: {
    tvCanonicalHash,
    pyRound3,
    ebCanonical,
    ebSha256Hex,
  },
};
return CWIVerificationKit;

}));
