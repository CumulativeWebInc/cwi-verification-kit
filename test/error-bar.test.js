// Tests for src/20-error-bar.js — byte-parity against the live Python
// errorbar.py (reference implementation). Same (claim, seed, stamped_at)
// must produce byte-identical canonical output in both languages.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

const kit = createRequire(import.meta.url)('../dist/cwi-verification-kit.js');

const EB_PY = '/home/hatch/workspace/cwi-company/gear-line/error-bar/errorbar.py';
const SEED = 1337;
const AT = '2026-09-18T12:00:00+00:00';

/* Canonical JSON exactly as the kit does it (mirrors Python's canonical). */
function canon(v) {
  if (v === null || v === undefined) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!isFinite(v)) throw new Error('non-finite');
    return JSON.stringify(v);
  }
  if (typeof v === 'string') {
    return JSON.stringify(v).replace(/[\u0080-\uFFFF]/g,
      (ch) => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
  }
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => canon(k) + ':' + canon(v[k])).join(',') + '}';
}

const FIXTURES = {
  stat: {
    label: 'LIVE', claim: 'Zooted Zone has about 307000 lifetime Spotify plays',
    point_estimate: 307000, unit: 'plays', claim_type: 'stat',
    evidence_tier: 'corroborated',
    sources: [{ url: 'https://open.spotify.com/track/0emH8ktA8x4DkOFLsG5xkW', kind: 'api' }],
    observed_at: '2026-09-14T00:00:00+00:00',
  },
  forecast: {
    label: 'SAMPLE', claim: 'Catalog streams grow 12% over the next 60 days',
    point_estimate: 0.12, unit: 'fraction', claim_type: 'forecast',
    evidence_tier: 'single-source', horizon_days: 60,
    sources: [{ ref: 'cwi-intelligence/time-series-store', kind: 'internal-record' }],
    observed_at: '2026-09-17T00:00:00+00:00',
  },
  proportion: {
    label: 'SAMPLE', claim: '9 of 10 CWI agents passed the dry-run check',
    point_estimate: 0.9, unit: 'fraction', claim_type: 'proportion',
    evidence_tier: 'verified', sample_n: 10,
    sources: [
      { ref: 'twenty-minds/dry-run-log', kind: 'internal-record' },
      { url: 'https://github.com/CumulativeWebInc/cwi-agent-memory', kind: 'document' },
    ],
    observed_at: '2026-09-17T00:00:00+00:00',
  },
  insufficient: {
    label: 'SAMPLE', claim: 'An unverified rumor with no evidence tier',
    point_estimate: 42, claim_type: 'stat', evidence_tier: 'none', sources: [],
  },
  flagged: {
    label: 'SAMPLE', claim: 'A claim with no sources listed',
    point_estimate: 7, claim_type: 'stat', evidence_tier: 'verified', sources: [],
  },
};

function pythonCanonicalStamp(claim) {
  const driver = `
import json, sys, importlib.util
spec = importlib.util.spec_from_file_location("errorbar", ${JSON.stringify(EB_PY)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
claim = json.loads(sys.argv[1])
out = m.stamp(claim, ${SEED}, at=${JSON.stringify(AT)})
sys.stdout.write(m.canonical(out).decode("utf-8"))
`;
  return execFileSync('python3', ['-c', driver, JSON.stringify(claim)], { encoding: 'utf8' });
}

for (const [name, claim] of Object.entries(FIXTURES)) {
  test(`byte-parity vs Python on ${name} fixture`, () => {
    const pyCanon = pythonCanonicalStamp(claim);
    const jsStamped = kit.errorbar.stamp(JSON.parse(JSON.stringify(claim)), SEED, AT);
    assert.equal(canon(jsStamped), pyCanon);
  });
}

test('ebVerify round-trip: JS stamp verifies, tampered stamp fails', () => {
  const stamped = kit.errorbar.stamp(JSON.parse(JSON.stringify(FIXTURES.stat)), SEED, AT);
  const ok = kit.errorbar.verify(FIXTURES.stat, stamped);
  assert.equal(ok.reproduced, true);
  assert.equal(ok.method_id, 'eb-mc-normal/1.0');
  const tampered = JSON.parse(JSON.stringify(stamped));
  tampered.interval.high = tampered.interval.high + 1;
  assert.equal(kit.errorbar.verify(FIXTURES.stat, tampered).reproduced, false);
});

test('Python verify accepts the Python stamp (exit 0)', () => {
  execFileSync('python3', ['-c', `
import json, subprocess, sys, importlib.util, tempfile, os
spec = importlib.util.spec_from_file_location("errorbar", ${JSON.stringify(EB_PY)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
claim = json.loads(sys.argv[1])
out = m.stamp(claim, ${SEED}, at=${JSON.stringify(AT)})
with tempfile.TemporaryDirectory() as d:
    cp, sp = os.path.join(d, "c.json"), os.path.join(d, "s.json")
    open(cp, "w").write(json.dumps(claim)); open(sp, "w").write(json.dumps(out))
    r = subprocess.run([sys.executable, ${JSON.stringify(EB_PY)}, "verify", "--in", cp, "--stamped", sp], capture_output=True, text=True)
    sys.exit(r.returncode)
`, JSON.stringify(FIXTURES.proportion)], { stdio: 'pipe' });
});
