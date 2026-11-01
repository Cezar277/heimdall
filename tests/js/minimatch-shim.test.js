'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..', '..');
const minimatch = require('minimatch');

test('le shim expose le contrat callable attendu par spectral-core', () => {
  assert.equal(typeof minimatch, 'function');
  assert.equal(typeof minimatch.minimatch, 'function');
  assert.equal(typeof minimatch.Minimatch, 'function');
  assert.equal(typeof minimatch.filter, 'function');
  assert.equal(typeof minimatch.match, 'function');
});

test('matchBase est respecté comme avec minimatch 3', () => {
  assert.equal(minimatch('openapi.yaml', '*.yaml', { matchBase: true }), true);
  assert.equal(minimatch('schemas/vault.yaml', '*.yaml', { matchBase: true }), true);
  assert.equal(minimatch('openapi.yaml', '*.json', { matchBase: true }), false);
  assert.equal(minimatch('schemas/vault.yaml', '**/*.yaml', { matchBase: true }), true);
});

test('le lockfile ne contient plus aucune version vulnérable de minimatch', () => {
  const lock = JSON.parse(fs.readFileSync(path.join(ROOT, 'package-lock.json'), 'utf8'));
  const packages = lock.packages;

  const shim = packages['node_modules/minimatch'];
  assert.equal(shim.link, true);
  assert.equal(shim.resolved, 'vendor/minimatch-cjs');

  const patched = packages['node_modules/minimatch-v11'];
  assert.equal(patched.name, 'minimatch');
  assert.equal(patched.version, '11.0.3');

  for (const [name, pkg] of Object.entries(packages)) {
    if (name !== 'node_modules/minimatch' && !name.endsWith('/node_modules/minimatch')) {
      continue;
    }
    if (pkg.version === undefined) {
      continue;
    }
    const major = Number(pkg.version.split('.')[0]);
    assert.ok(major >= 11, `${name}@${pkg.version} reste vulnérable`);
  }
});

test('npm ls ne remonte aucune version 3.x de minimatch', () => {
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const result = spawnSync(
    npm,
    ['ls', 'minimatch', 'minimatch-v11', '--json'],
    { cwd: ROOT, encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);

  const tree = JSON.parse(result.stdout);
  const found = [];
  const walk = (node) => {
    if (!node || typeof node !== 'object') return;
    for (const [name, dep] of Object.entries(node.dependencies || {})) {
      if (name === 'minimatch' || name === 'minimatch-v11') {
        found.push({ name, ...dep });
      }
      walk(dep);
    }
  };
  walk(tree);

  const shim = found.find(
    (dep) => dep.name === 'minimatch' && (dep.resolved || '').startsWith('file:'),
  );
  assert.ok(shim, 'le shim minimatch local doit être présent');

  const patched = found.find((dep) => dep.name === 'minimatch-v11');
  assert.equal(patched?.version, '11.0.3');

  for (const dep of found) {
    if (dep.name === 'minimatch' && dep.version) {
      assert.ok(
        !dep.version.startsWith('3.'),
        `minimatch@${dep.version} reste vulnérable`,
      );
    }
  }
});

test('les motifs à accolades imbriquées restent bornés', () => {
  const pattern = '{'.repeat(100) + 'a,b' + '}'.repeat(100);
  const expanded = minimatch.braceExpand(pattern, { braceExpandMax: 1000 });

  assert.ok(expanded.length <= 1000, `expanded=${expanded.length}`);
  assert.equal(typeof minimatch('x', pattern, { braceExpandMax: 1000 }), 'boolean');
});

test('le préprocessing optimizationLevel 2 reste borné par défaut', () => {
  const pattern = '**/../a/b/'.repeat(200) + 'x';

  const bounded = new minimatch.Minimatch(pattern, { optimizationLevel: 2 });
  assert.ok(bounded.set.length <= 1000, `globParts=${bounded.set.length}`);

  const overridden = new minimatch.Minimatch(pattern, {
    optimizationLevel: 2,
    braceExpandMax: 50,
  });
  assert.ok(overridden.set.length <= 50, `globParts=${overridden.set.length}`);
});
