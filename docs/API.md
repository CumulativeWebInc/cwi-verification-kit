# API reference — cwi-verification-kit v1.0.0

Global (browser): `CWIVerificationKit`. Node: `require('cwi-verification-kit')`.

All inputs accept `0x`-hex strings, `Uint8Array`, or byte arrays where bytes are
expected. Functions never throw on malformed *records* — they return structured
check results. (Malformed *claims* for the Error Bar throw `Error`; see below.)

## Crypto

- `keccak256Hex(input)` → `0x`-hex Keccak-256 digest.
- `sha256Hex(input)` → hex SHA-256 digest (no `0x`, matching `hashlib.hexdigest()`).
- `eip712HashTypedData(domain, types, primaryType, message)` → `Uint8Array` (32 bytes).
- `eip712RecoverAddress(domain, domainFields, types, primaryType, message, signature)` →
  `0x` address or `null` if recovery fails.
- `hexToBytes`, `bytesToHex`, `utf8Bytes`, `concatBytes` — small byte helpers.

## EAS attestation verification

Constants: `EAS_ADDRESS`, `EAS_DOMAIN`, `ATTEST_TYPES`, `SCHEMA_STR`, `BYTES32_ZERO`.

- `schemaUid()` → `0x`-hex deterministic schema UID
  (`keccak256("CWI-MEMORY-ANCHOR-V1:" + SCHEMA_STR)`).
- `reviveMessage(m)` → converts a JSON-serialized attestation message (string
  bigints) to typed values for hashing/recovery.
- `decodeAnchorData(dataHex)` → `{ blobHash, agentUrn, writtenAt, offchainUri }`
  decoded from the `(bytes32,string,uint64,string)` ABI tuple. Throws on malformed data.
- `verifyAttestation(record, blob?)` → `{ ok, checks }`.
  `blob = { ciphertext: Uint8Array, saltHex: '0x…' }` enables the blob-binding check;
  without it that check reports `ok: null` (skipped). Each check is
  `{ name, ok: true|false|null, detail }`.
- `verifyChain(records)` → `{ ok, checks }` — each record's `prevUid` must equal
  the previous record's `uid` (genesis chains from `bytes32(0)`).
- `tamperCheckSignature(record)` → `true` when a one-nibble-mutated signature no
  longer recovers the attester (tamper correctly detected).
- `tamperCheckBlob(record, blob)` → `true` when a one-bit-mutated ciphertext
  changes the salted blob hash (tamper correctly detected).

## Error Bar — `kit.errorbar`

- `TOOL_VERSION`, `METHOD_NORMAL` (`eb-mc-normal/1.0`),
  `METHOD_FORECAST` (`eb-mc-forecast/1.0`), `METHOD_WILSON` (`eb-wilson/1.0`).
- `stamp(claim, seed, at?)` → stamped claim object. Throws `Error` on invalid
  input (missing fields, non-numeric point, bad horizon/sample_n).
  Claim fields: `claim`, `point_estimate`, `claim_type` (`stat|forecast|proportion`),
  `evidence_tier` (`verified|corroborated|single-source|anecdotal|none`),
  optional `unit`, `label` (`SAMPLE|LIVE`), `sources`, `observed_at`, `horizon_days`,
  `sample_n`.
- `verify(claim, stamped)` → `{ reproduced: true, method_id, input_sha256 }` or
  `{ reproduced: false, reason, differing_fields? }`.

## Trust Verdict — `kit.verdict`

- `ENGINE_NAME`, `ENGINE_VERSION` (`1.0.0`), `SPEC_VERSION` (`1.0.0`).
- `run(doc)` → `[output, exitCode]` — `exitCode` 0 ok, 2 invalid input.
  `output.status` is one of `scored`, `insufficient-data`, `evidence-disputed`,
  `unknown-context`, `invalid-input`. A score is only ever emitted with status
  `scored`; every other status carries `score: null` and a `missing` list.
- `score(doc)` → output object (assumes valid input).

## Test internals — `kit._internals`

`tvCanonicalHash`, `pyRound3`, `ebCanonical`, `ebSha256Hex` — exposed for tests
and power users building hash-chained pipelines.
