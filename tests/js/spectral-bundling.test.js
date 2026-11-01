'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..', '..');
const SPECTRAL = path.join(
  ROOT,
  'node_modules',
  '@stoplight',
  'spectral-cli',
  'dist',
  'index.js',
);
const OPENAPI = path.join(ROOT, 'openapi.yaml');

function runSpectral(ruleset) {
  const result = spawnSync(
    process.execPath,
    [SPECTRAL, 'lint', '--ruleset', ruleset, OPENAPI],
    {
      cwd: ROOT,
      encoding: 'utf8',
      timeout: 60_000,
    },
  );
  assert.equal(result.error, undefined, result.error?.message);
  return result;
}

function tempRuleset(t, name, contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'heimdall-spectral-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, name);
  fs.writeFileSync(file, contents);
  return file;
}

test('le bundler de ruleset JS fonctionne avec @rollup/plugin-commonjs 29', (t) => {
  const ruleset = tempRuleset(
    t,
    'ruleset.js',
    `
const { oas } = require('@stoplight/spectral-rulesets');

module.exports = {
  extends: [oas],
  rules: {},
};
`,
  );

  const result = runSpectral(ruleset);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /No results with a severity of 'error' found!/);
});

test('les overrides `files` matchent via le shim minimatch', (t) => {
  const matching = tempRuleset(
    t,
    'matching.yaml',
    `
overrides:
  - files:
      - "*.yaml"
    rules:
      test-files-match:
        description: test
        given: "$"
        severity: warn
        then:
          function: falsy
`,
  );

  const matchResult = runSpectral(matching);
  assert.equal(matchResult.status, 0, matchResult.stderr || matchResult.stdout);
  assert.match(matchResult.stdout, /test-files-match/);

  const nonMatching = tempRuleset(
    t,
    'non-matching.yaml',
    `
overrides:
  - files:
      - "*.json"
    rules:
      test-files-match:
        description: test
        given: "$"
        severity: warn
        then:
          function: falsy
`,
  );

  const nonMatchResult = runSpectral(nonMatching);
  assert.equal(nonMatchResult.status, 0, nonMatchResult.stderr || nonMatchResult.stdout);
  assert.doesNotMatch(nonMatchResult.stdout, /test-files-match/);
});
