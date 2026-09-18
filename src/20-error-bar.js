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
