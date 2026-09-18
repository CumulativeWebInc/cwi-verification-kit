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
