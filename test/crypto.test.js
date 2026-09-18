// Tests for src/00-crypto.js — cross-validated against viem (existing CWI stack).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const kit = createRequire(import.meta.url)('../dist/cwi-verification-kit.js');

test('bundle loads with version', () => {
  assert.equal(typeof kit.version, 'string');
});

const reqViem = createRequire('/home/hatch/workspace/cwi-company/monetization/x402/node_modules/viem/dist/index.js');
const viem = reqViem('/home/hatch/workspace/cwi-company/monetization/x402/node_modules/viem');

test('keccak256 matches viem on 17 lengths (incl. block boundaries)', () => {
  for (const len of [0, 1, 2, 3, 7, 8, 16, 31, 32, 33, 64, 100, 135, 136, 137, 200, 272, 1000]) {
    const msg = '0x' + 'ab'.repeat(len);
    assert.equal(kit.keccak256Hex(msg), viem.keccak256(msg), `len ${len}`);
  }
});

test('keccak256 known vector', () => {
  assert.equal(kit.keccak256Hex('0x'),
    '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
});

test('sha256 matches node:crypto on 8 lengths', async () => {
  const { createHash } = await import('node:crypto');
  for (const len of [0, 1, 55, 56, 57, 64, 100, 1000]) {
    const bytes = new Uint8Array(len).map((_, i) => i & 0xff);
    const want = createHash('sha256').update(bytes).digest('hex');
    assert.equal(kit.sha256Hex(bytes), want, `len ${len}`);
  }
});

test('EIP-712 digest matches viem hashTypedData', () => {
  const DOMAIN = { name: 'EAS Attestation', version: '2.0.0', chainId: 84532,
    verifyingContract: '0x4200000000000000000000000000000000000021' };
  const DF = [
    { name: 'name', type: 'string' }, { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }];
  const TYPES = { Attest: [
    { name: 'version', type: 'uint16' }, { name: 'nonce', type: 'uint256' },
    { name: 'schema', type: 'bytes32' }, { name: 'recipient', type: 'address' },
    { name: 'time', type: 'uint64' }, { name: 'expirationTime', type: 'uint64' },
    { name: 'revocable', type: 'bool' }, { name: 'refUID', type: 'bytes32' },
    { name: 'data', type: 'bytes' }, { name: 'salt', type: 'bytes32' }] };
  const r = JSON.parse(readFileSync('/tmp/muse_cwi.json', 'utf8'))[0];
  const msg = kit.reviveMessage(r.message);
  const mine = kit.bytesToHex(kit.eip712HashTypedData(DOMAIN, { EIP712Domain: DF, ...TYPES }, 'Attest', msg));
  const theirs = viem.hashTypedData({ domain: DOMAIN, types: TYPES, primaryType: 'Attest', message: { ...msg } });
  assert.equal(mine, theirs);
});

test('EIP-712 recovery matches viem on all 3 live attestation records', async () => {
  const DOMAIN = { name: 'EAS Attestation', version: '2.0.0', chainId: 84532,
    verifyingContract: '0x4200000000000000000000000000000000000021' };
  const DF = [
    { name: 'name', type: 'string' }, { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }];
  const TYPES = { Attest: [
    { name: 'version', type: 'uint16' }, { name: 'nonce', type: 'uint256' },
    { name: 'schema', type: 'bytes32' }, { name: 'recipient', type: 'address' },
    { name: 'time', type: 'uint64' }, { name: 'expirationTime', type: 'uint64' },
    { name: 'revocable', type: 'bool' }, { name: 'refUID', type: 'bytes32' },
    { name: 'data', type: 'bytes' }, { name: 'salt', type: 'bytes32' }] };
  const ATTESTER = '0x6732470224e98832386815bf09afecb29c1f6d78';
  for (const f of ['/tmp/muse_cwi.json', '/tmp/cwi_data.json']) {
    for (const r of JSON.parse(readFileSync(f, 'utf8'))) {
      const mine = kit.eip712RecoverAddress(DOMAIN, DF, TYPES, 'Attest',
        kit.reviveMessage(r.message), r.signature);
      const theirs = await viem.recoverTypedDataAddress({ domain: DOMAIN, types: TYPES,
        primaryType: 'Attest', message: { ...kit.reviveMessage(r.message) }, signature: r.signature });
      assert.equal(mine.toLowerCase(), theirs.toLowerCase());
      assert.equal(mine.toLowerCase(), ATTESTER);
    }
  }
});
