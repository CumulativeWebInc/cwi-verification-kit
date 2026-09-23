// Tests for src/10-eas-verify.js — live public attestation records,
// schema/UID/digest/signer checks, tamper negatives, refUID chain linkage.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const kit = createRequire(import.meta.url)('../dist/cwi-verification-kit.js');
const reqViem = createRequire('/home/hatch/workspace/cwi-company/monetization/x402/node_modules/viem/dist/index.js');
const viem = reqViem('/home/hatch/workspace/cwi-company/monetization/x402/node_modules/viem');

const EXPECTED_SCHEMA_UID = '0x0fda26f5e5ce5d61e2b2e344a2f1712d254711550a1667cbac143df218c163f8';
const ATTESTER = '0x6732470224e98832386815bf09afecb29c1f6d78';

function loadRecords() {
  return {
    muse: JSON.parse(readFileSync('/tmp/muse_cwi.json', 'utf8')),
    data: JSON.parse(readFileSync('/tmp/cwi_data.json', 'utf8')),
  };
}

test('schemaUid is deterministic and matches EAS registry semantics', () => {
  assert.equal(kit.schemaUid(), kit.schemaUid());
  assert.equal(kit.schemaUid(), EXPECTED_SCHEMA_UID);
  // differential vs viem keccak of prefix + schema string
  assert.equal(kit.schemaUid(),
    viem.keccak256(viem.toHex('CWI-MEMORY-ANCHOR-V1:' + kit.SCHEMA_STR)));
});

test('verifyAttestation passes every non-blob check on all 3 live records; blob is skipped', () => {
  const { muse, data } = loadRecords();
  for (const rec of [...muse, ...data]) {
    const res = kit.verifyAttestation(rec);
    for (const c of res.checks) {
      if (c.ok === null) {
        assert.ok(c.name.startsWith('blob hash binds'), `only blob check may skip, got ${c.name}`);
      } else {
        assert.equal(c.ok, true, `${c.name}: ${c.detail}`);
      }
    }
    assert.equal(res.ok, true);
  }
});

test('uid equals keccak256(signature) on live records', () => {
  const { muse } = loadRecords();
  for (const rec of muse) {
    assert.equal(rec.uid.toLowerCase(), kit.keccak256Hex(rec.signature).toLowerCase());
  }
});

test('ABI decode matches viem decodeAbiParameters', () => {
  const { muse } = loadRecords();
  const r = muse[0];
  const mine = kit.decodeAnchorData(kit.reviveMessage(r.message).data);
  const theirs = viem.decodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'string' }, { type: 'uint64' }, { type: 'string' }],
    kit.reviveMessage(r.message).data);
  assert.equal(mine.blobHash, theirs[0].toLowerCase());
  assert.equal(mine.agentUrn, theirs[1]);
  assert.equal(mine.writtenAt, theirs[2].toString());
  assert.equal(mine.offchainUri, theirs[3]);
});

test('verifyChain links the full MUSE_CWI chain via prevUid (depth = record count)', () => {
  const { muse } = loadRecords();
  const res = kit.verifyChain(muse);
  assert.equal(res.ok, true);
  assert.equal(res.checks.length, muse.length);
  assert.ok(res.checks.every((c) => c.ok));
});

test('verifyChain detects a broken prevUid link', () => {
  const { muse } = loadRecords();
  const tampered = JSON.parse(JSON.stringify(muse));
  tampered[1].prevUid = '0x' + 'ff'.repeat(32);
  const res = kit.verifyChain(tampered);
  assert.equal(res.ok, false);
  assert.equal(res.checks[1].ok, false);
});

test('tamperCheckSignature detects a mutated signature', () => {
  const { muse } = loadRecords();
  assert.equal(kit.tamperCheckSignature(muse[0]), true);
});

test('tamperCheckBlob detects mutated ciphertext', () => {
  const { muse } = loadRecords();
  const blob = { ciphertext: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), saltHex: '0x' + '11'.repeat(32) };
  // returns true when the mutated hash differs from the recorded hash
  assert.equal(typeof kit.tamperCheckBlob(muse[0], blob), 'boolean');
  assert.equal(kit.tamperCheckBlob(muse[0], blob), true);
});

test('verifyAttestation with a wrong blob fails the blob-binding check', () => {
  const { muse } = loadRecords();
  const blob = { ciphertext: new Uint8Array(16), saltHex: '0x' + 'ab'.repeat(32) };
  const res = kit.verifyAttestation(muse[0], blob);
  const blobCheck = res.checks.find((c) => c.name.startsWith('blob hash binds'));
  assert.ok(blobCheck, 'blob check present');
  assert.equal(blobCheck.ok, false); // 16 zero bytes cannot match the real hash
  assert.equal(res.ok, false);
});
