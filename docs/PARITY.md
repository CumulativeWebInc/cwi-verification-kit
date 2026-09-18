# Parity report — cwi-verification-kit v1.0.0

Every ported module is tested against an independent reference implementation on
this machine. "Verified or it didn't happen."

## Results (2026-09-18)

| Module | Reference | Property tested | Result |
|---|---|---|---|
| Keccak-256 | `viem` keccak256 | 18 input lengths incl. 135/136/137 block boundaries | 18/18 match |
| SHA-256 | Node `crypto` | 8 input lengths | 8/8 match |
| EIP-712 digest | `viem` hashTypedData | live attestation message | match |
| ECDSA recovery | `viem` recoverTypedDataAddress | 3 live attestation records | 3/3 recover `0x6732470224e98832386815bF09aFECB29C1f6d78` |
| Schema UID | `viem` keccak256 | prefix + schema string | match (`0x0fda26…f8`) |
| ABI decode | `viem` decodeAbiParameters | live `data` payload | field-for-field match |
| Error Bar | live `errorbar.py` | 5 fixtures: stat, forecast, proportion, insufficient-data, flagged | **byte-identical canonical output** |
| MT19937 | CPython `random.Random` | seeds 42, 0, 2⁶⁴+7; ints + doubles | bit-exact |
| Trust Verdict | live verdict `engine.py` | 7 fixtures: scored, insufficient, disputed, unknown-context, 3 invalid | **byte-identical canonical output** |
| Rounding | CPython `round(x, 3)` | ties + 7-value sweep | half-even match |

## Bugs found and fixed by parity testing

1. **secp256k1 G.y transcription** — the generator's y-coordinate was missing its
   final hex digit (`…d4b` instead of `…d4b8`). Caught because EIP-712 recovery
   returned wrong addresses on live records while digests matched viem. The
   implementation was self-consistent (n·G = ∞) but wrong vs the curve.
2. **MT19937 init_by_array precedence** — `(a ^ b) + c` was coded as `a ^ (b + c)`
   (JS `^` binds looser than `+`, same as C). Caught by direct comparison with
   CPython's `random.Random(42)`.
3. **Error Bar block-scoped `lo`/`hi`** — interval bounds declared inside
   per-type branches but used outside. Caught by the first parity run.
4. **Trust Verdict shorthand typos** — `not_counted` / `family_score` referenced
   instead of their camelCase locals. Caught by the first parity run.
5. **Float-lexical fidelity** — Python prints integral floats as `2.0`, JS as `2`.
   Fixed with explicit float tagging (`pyFloat`) for `kept_weight`, `family_score`,
   and `score`, mirroring Python's type flow (int 0 for empty families, float
   otherwise). Byte parity holds.

## Known, documented divergences

- **Float-lexical input numbers** (`307000.0` in JSON): Python parses as float and
  hashes `input_sha256` over `307000.0`; JS parses as number and hashes over
  `307000`. JSON erases the int/float distinction — cross-language `verify` on
  such inputs should use the same-language tool. Fixtures avoid these.
- **Exponent-lexical floats** (`1e-07` vs `1e-7`): Python and JS shortest-round-trip
  float printing differ in exponent padding. Same guidance as above.
- **JS is stricter** on two inputs: non-finite `point_estimate` throws here
  (Python crashes later at JSON dump); non-integer seeds throw at `BigInt()`
  conversion (Python accepts some).
- **`observed_at` future check** uses the machine clock in both; results agree
  when run at the same time.
