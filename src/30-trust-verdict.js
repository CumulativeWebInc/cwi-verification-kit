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
