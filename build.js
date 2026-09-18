#!/usr/bin/env node
// Build: concatenate src fragments (dependency order) into dist UMD bundle.
// The bundle is the shippable artifact — zero dependencies, works in Node,
// browsers, and any ESM/CJS loader via the UMD wrapper.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const FRAGMENTS = ['00-crypto.js', '10-eas-verify.js', '20-error-bar.js', '30-trust-verdict.js'];

const API = `
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
`;

const parts = FRAGMENTS.map((f) => readFileSync(join(ROOT, 'src', f), 'utf8'));
const body = parts.join('\n');

const bundle = `/*!
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
${body}
${API}
}));
`;

mkdirSync(join(ROOT, 'dist'), { recursive: true });
writeFileSync(join(ROOT, 'dist', 'cwi-verification-kit.js'), bundle);
console.log('built dist/cwi-verification-kit.js', bundle.length, 'bytes');
