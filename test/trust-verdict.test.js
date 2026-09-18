// Tests for src/30-trust-verdict.js — canonical-output parity against the
// live Python verdict engine (reference implementation). Same input document
// must produce byte-identical canonical output in both languages.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

const kit = createRequire(import.meta.url)('../dist/cwi-verification-kit.js');

const TV_PY = '/tmp/verdict-engine.py';

/* Canonical JSON: sorted keys, compact, UTF-8 preserved (ensure_ascii=False). */
function canon(v) {
  if (v === null || v === undefined) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (v instanceof Number) {
    const n = v.valueOf();
    if (!isFinite(n)) throw new Error('non-finite');
    if (v.__pyFloat && Number.isInteger(n)) return JSON.stringify(n) + '.0';
    return JSON.stringify(n);
  }
  if (typeof v === 'number') {
    if (!isFinite(v)) throw new Error('non-finite');
    return JSON.stringify(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => canon(k) + ':' + canon(v[k])).join(',') + '}';
}

function ev(id, fam, overrides = {}) {
  return {
    evidence_id: id,
    kind: 'published-verdict',
    issuer: 'cwi-press',
    issuer_type: 'third_party',
    description: `evidence ${id} for ${fam}`,
    weight_class: 2,
    status: 'verified',
    observed_at: '2026-09-17T00:00:00+00:00',
    identity_cluster: 'cwi-press',
    ...overrides,
  };
}

function doc(signals, overrides = {}) {
  return {
    engine_version: '1.0.0',
    subject: { agent_id: 'agent:muse_cwi', display_name: 'KingCode' },
    context: 'music-review',
    observed_at: '2026-09-18T00:00:00+00:00',
    signals: {
      erc8004: [],
      needle_drop: [],
      first_spin: [],
      ...signals,
    },
    evidence_notes: {},
    ...overrides,
  };
}

const FIXTURES = {
  // exercises: issuer-cap damping (3rd moltbook item), self-assertion 0.5x
  // discount, pending not-counted, multi-family scoring + band
  scored: doc({
    needle_drop: [
      ev('nd-001', 'needle_drop', { issuer: 'moltbook', issuer_type: 'protocol', weight_class: 3, kind: 'completed-gig', identity_cluster: 'moltbook' }),
      ev('nd-002', 'needle_drop', { issuer: 'moltbook', issuer_type: 'protocol', weight_class: 3, kind: 'completed-gig', identity_cluster: 'moltbook' }),
      ev('nd-003', 'needle_drop', { issuer: 'moltbook', issuer_type: 'protocol', weight_class: 3, kind: 'completed-gig', identity_cluster: 'moltbook' }),
      ev('nd-self-1', 'needle_drop', { issuer: 'agent:muse_cwi', issuer_type: 'self', weight_class: 1, kind: 'self-report', identity_cluster: null }),
      ev('nd-pending-1', 'needle_drop', { status: 'pending' }),
    ],
    first_spin: [ev('fs-001', 'first_spin', { weight_class: 2 })],
  }),
  insufficient: doc(
    { first_spin: [ev('fs-001', 'first_spin')] },
    { context: 'agent-trust' },
  ),
  disputed: doc({
    needle_drop: [
      ev('nd-001', 'needle_drop'),
      ev('nd-002', 'needle_drop', { status: 'disputed' }),
    ],
    first_spin: [ev('fs-001', 'first_spin')],
  }),
  unknown_context: doc(
    { first_spin: [ev('fs-001', 'first_spin')] },
    { context: 'space-law' },
  ),
  invalid_version: doc({}, { engine_version: '9.9.9' }),
  invalid_duplicate: doc({
    first_spin: [ev('fs-001', 'first_spin'), ev('fs-001', 'first_spin')],
  }),
  invalid_family: {
    engine_version: '1.0.0',
    subject: { agent_id: 'agent:muse_cwi' },
    context: 'music-review',
    observed_at: '2026-09-18T00:00:00+00:00',
    signals: { erc8004: [], needle_drop: [] },
    evidence_notes: {},
  },
};

function pythonCanonical(inputDoc) {
  const driver = `
import json, sys, importlib.util
spec = importlib.util.spec_from_file_location("engine", ${JSON.stringify(TV_PY)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
doc = json.loads(sys.argv[1])
out, code = m.run(doc)
sys.stdout.write(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
sys.stdout.write("\\n" + str(code))
`;
  const raw = execFileSync('python3', ['-c', driver, JSON.stringify(inputDoc)], { encoding: 'utf8' });
  const idx = raw.lastIndexOf('\n');
  return { canon: raw.slice(0, idx), code: Number(raw.slice(idx + 1)) };
}

for (const [name, inputDoc] of Object.entries(FIXTURES)) {
  test(`canonical parity vs Python on ${name} fixture`, () => {
    const py = pythonCanonical(inputDoc);
    const [jsOut, jsCode] = kit.verdict.run(JSON.parse(JSON.stringify(inputDoc)));
    assert.equal(canon(jsOut), py.canon, `output mismatch on ${name}`);
    assert.equal(jsCode, py.code, `exit code mismatch on ${name}`);
  });
}

test('scored fixture actually scores with a sane band', () => {
  const [out] = kit.verdict.run(JSON.parse(JSON.stringify(FIXTURES.scored)));
  assert.equal(out.status, 'scored');
  assert.ok(out.score > 0 && out.score <= 1);
  assert.ok(['established', 'emerging', 'thin', 'weak', 'negligible'].includes(out.band));
  // issuer cap: nd-003 damped
  assert.deepEqual(out.families.needle_drop.damped.map((d) => d.evidence_id), ['nd-003']);
  // self-assertion discounted
  assert.deepEqual(out.families.needle_drop.self_assertion_discounted, ['nd-self-1']);
  // pending not counted
  assert.deepEqual(out.families.needle_drop.not_counted.map((d) => d.evidence_id), ['nd-pending-1']);
});

test('round-half-even matches Python round() at ties', () => {
  const r = kit._internals.pyRound3;
  // Python: round(2.5)=2, round(3.5)=4 (banker's); to 3 decimals:
  assert.equal(r(0.1235), 0.124); // 123.5 -> 124 (even)
  assert.equal(r(0.1245), 0.124); // 124.5 -> 124 (even)
  assert.equal(r(2.5 / 1000), 0.002); // 2.5 -> 2 (even)
  assert.equal(r(3.5 / 1000), 0.004); // 3.5 -> 4 (even)
  // differential vs Python on a sweep
  const vals = [0.1, 0.12345, 0.99999, 1.0055, 2.675, 0.45454545454545453, 123.456789];
  const py = execFileSync('python3', ['-c',
    `import sys, json; print(json.dumps([round(float(x), 3) for x in ${JSON.stringify(vals)}]))`],
    { encoding: 'utf8' });
  assert.deepEqual(vals.map(r), JSON.parse(py));
});
