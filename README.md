# cwi-verification-kit

The **CWI Trust Layer** verification library — one zero-dependency JavaScript bundle
that lets any agent or app verify CWI attestations, stamp claims with reproducible
confidence intervals, and score agent trust without inventing numbers.

> "Verified or it didn't happen."

**Zero dependencies. Works in Node ≥ 18 and any browser.** Load it from a script tag,
`require()` it, or `import` it — no build step, no native modules, no network calls.

```html
<script src="https://cdn.jsdelivr.net/gh/CumulativeWebInc/cwi-verification-kit@main/dist/cwi-verification-kit.js"></script>
<script>
  const ok = CWIVerificationKit.verifyAttestation(record);
  console.log(ok.ok, ok.checks);
</script>
```

```js
const kit = require('cwi-verification-kit');
// EAS attestation checks
kit.verifyAttestation(record);            // schema, uid, domain, signer, ABI, blob
kit.verifyChain(records);                 // refUID hash-chain linkage
// Claim stamping (The Error Bar)
kit.errorbar.stamp(claim, 1337, at);      // reproducible confidence interval
kit.errorbar.verify(claim, stamped);      // re-run and compare
// Agent trust scoring (CWI Verdict Engine)
kit.verdict.run(inputDoc);                // [output, exitCode]
```

## What's inside

| Module | Source | What it does |
|---|---|---|
| Crypto primitives | `src/00-crypto.js` | Keccak-256, SHA-256, secp256k1 ECDSA recovery, EIP-712 hashing — pure JS, no deps |
| EAS attestation verify | `src/10-eas-verify.js` | Verifies CWI memory-chain off-chain attestations: deterministic schema UID, EAS domain, `uid = keccak256(signature)`, EIP-712 signer recovery, ABI payload decode, refUID chain, salted blob binding, signature/blob tamper negatives |
| The Error Bar | `src/20-error-bar.js` | JS port of CWI's `errorbar.py`: stamps any claim with a seeded Monte Carlo or Wilson confidence interval, a provenance check, and a reproducibility record |
| Trust Verdict | `src/30-trust-verdict.js` | JS port of the CWI Verdict Engine: deterministic, evidence-bound agent trust scoring — returns `insufficient-data` instead of inventing scores |

## Verification

This library is tested against independent references, not against itself —
**31 tests, all green**:

- **Keccak-256 / SHA-256**: differential vs `viem` and Node's `crypto` across block
  boundaries, plus known vectors.
- **secp256k1 / EIP-712**: digest matches `viem` `hashTypedData`; signer recovery
  matches `viem` `recoverTypedDataAddress` on all 3 live public CWI attestation
  records (attester `0x6732470224e98832386815bF09aFECB29C1f6d78`).
- **EAS verify**: schema UID determinism, `uid = keccak256(sig)`, ABI decode vs
  `viem` `decodeAbiParameters`, refUID chain linkage + breakage detection,
  signature and blob tamper negatives.
- **Error Bar**: **byte-identical canonical output** vs the live Python
  `errorbar.py` on stat, forecast, proportion, insufficient-data, and flagged
  fixtures (same claim + seed + timestamp → same bytes, both languages).
  MT19937 bit-exact with CPython's `random.Random`, including seed 0 and large seeds.
- **Trust Verdict**: **byte-identical canonical output** vs the live Python
  verdict engine on scored, insufficient-data, disputed, unknown-context, and
  three invalid-input fixtures — including Python `round()` half-even semantics
  and float-lexical (`2.0`) fidelity.

Run them: `npm test` (builds `dist/` first, then `node --test`).

## API

See [`docs/API.md`](docs/API.md) for the full reference and
[`docs/PARITY.md`](docs/PARITY.md) for the cross-language fidelity notes.

## Author

Henry Pitts (Black Lansky) is the founder of Cumulative Web Inc and a systems architect building verification infrastructure for the AI-agent economy.

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 Cumulative Web Inc.
