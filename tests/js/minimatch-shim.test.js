'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
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

  // spectral-core@1.24.0 déclare encore minimatch@^3.1.4 dans ses métadonnées ;
  // c'est l'override `$minimatch` qui garantit qu'aucune version 3.x n'est
  // installée. On fige cette déclaration amont pour éviter un faux positif
  // lors d'un audit `grep` sur le lockfile.
  const spectralCore = packages['node_modules/@stoplight/spectral-core'];
  assert.equal(spectralCore.dependencies.minimatch, '^3.1.4');

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
    { cwd: ROOT, encoding: 'utf8', timeout: 30_000 },
  );
  assert.equal(result.error, undefined, result.error?.message);
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

test('les helpers filter/match/braceExpand appliquent la borne par défaut', () => {
  const pattern = '{a,b,c,d,e,f,g,h,i,j}'.repeat(10);

  const expanded = minimatch.braceExpand(pattern);
  assert.ok(expanded.length <= 1000, `expanded=${expanded.length}`);

  const limited = minimatch.braceExpand(pattern, { braceExpandMax: 50 });
  assert.ok(limited.length <= 50, `expanded=${limited.length}`);

  const simple = '{a,b}';
  const predicate = minimatch.filter(simple);
  assert.equal(typeof predicate, 'function');
  assert.equal(predicate('a'), true);
  assert.equal(predicate('z'), false);

  assert.deepEqual(minimatch.match(['a', 'z'], simple), ['a']);
});

test('le préprocessing optimizationLevel 2 reste borné par défaut', () => {
  const pattern = '**/../a/b/'.repeat(200) + 'x';

  const bounded = new minimatch.Minimatch(pattern, { optimizationLevel: 2 });
  assert.equal(bounded.set.length, 1000);

  const overridden = new minimatch.Minimatch(pattern, {
    optimizationLevel: 2,
    braceExpandMax: 50,
  });
  assert.equal(overridden.set.length, 50);

  const combined = new minimatch.Minimatch(
    '{a,b}'.repeat(20) + '/**/../a/b/x',
    { optimizationLevel: 2 },
  );
  assert.ok(combined.set.length <= 1000, `globParts=${combined.set.length}`);
});

test('le shim n\'expose que des helpers bornés (allowlist explicite)', () => {
  const upstream = require('minimatch-v11');

  // Tout export du shim doit être connu : un `Object.assign` du namespace
  // amont ferait fuiter un futur helper construisant un Minimatch interne
  // sans passer par `withDefaults` (donc sans la borne `braceExpandMax`).
  const allowed = new Set([
    'minimatch',
    'Minimatch',
    'filter',
    'match',
    'braceExpand',
    'defaults',
    'sep',
    'GLOBSTAR',
    'escape',
    'unescape',
    'default',
  ]);
  for (const key of Object.keys(minimatch)) {
    assert.ok(allowed.has(key), `export non borné exposé par le shim : ${key}`);
  }

  // `defaults(def)` renvoie une fonction `minimatch` pré-configurée : la borne
  // doit survivre à ce chemin, et rester surchargeable explicitement.
  const bounded = minimatch.defaults({});
  assert.equal(typeof bounded, 'function');
  assert.equal(bounded('a', '{a,b}'), true);
  assert.ok(bounded.braceExpand('{a,b,c,d,e,f,g,h,i,j}'.repeat(10)).length <= 1000);

  const raised = minimatch.defaults({ braceExpandMax: 50 });
  assert.ok(raised.braceExpand('{a,b,c,d,e,f,g,h,i,j}'.repeat(10)).length <= 50);

  // L'amont, lui, reste à 100 000 : c'est bien le shim qui borne.
  assert.ok(
    upstream
      .braceExpand('{a,b,c,d,e,f,g,h,i,j}'.repeat(10))
      .length > 1000,
  );
});

test('le contenu du shim vendor/ est figé (dépendance `file:` sans hash)', () => {
  // `npm ci` ne peut pas vérifier l'intégrité d'une dépendance `file:` : ce
  // test est le hash registre. Il casse volontairement à chaque modification
  // du shim — mettre à jour les digests dans le même commit que la revue.
  const expected = {
    'vendor/minimatch-cjs/index.js':
      'b81fca8a7f042db2d51fc8aed2b0c07469530311da409a69e642412685583738',
    'vendor/minimatch-cjs/package.json':
      '855f40fe431ea1b95db09c4fafce2b4619ddcc317646ab566891249fdcc4c185',
  };

  for (const [relative, digest] of Object.entries(expected)) {
    const actual = crypto
      .createHash('sha256')
      .update(fs.readFileSync(path.join(ROOT, relative)))
      .digest('hex');
    assert.equal(
      actual,
      digest,
      `${relative} a changé : revue explicite requise, puis mettre à jour le sha256 dans tests/js/minimatch-shim.test.js`,
    );
  }
});
