# `minimatch-compat` — shim CJS pour minimatch 11

Pourquoi ce dossier existe : fermer l'alerte Dependabot **#8**
(`GHSA-g3hv-75wg-m249`, *minimatch < 11.0.1*) sans casser Spectral.

## Le problème

`@stoplight/spectral-cli@6.17.0` (dernière version publiée) épingle
`@stoplight/spectral-core@1.24.0`, qui dépend de `minimatch@^3.1.4`.
La branche 3.x est signalée par l'avis ; la première version corrigée est
**11.0.1**. Aucune version de Spectral ne permet donc de sortir de la 3.x
« officiellement ».

Un simple `"overrides": { "minimatch": "^11.0.1" }` ne suffit pas :
minimatch 9+ n'exporte plus de `default`, or `spectral-core` fait

```js
tslib.__importDefault(require('minimatch')).default(source, pattern, opts)
```

→ `TypeError: m.default is not a function` (silencieux tant que le ruleset
n'a pas de `source`, donc bombe à retardement).

## La solution

- `package.json` déclare `"minimatch": "file:vendor/minimatch-compat"` en
  `devDependency`, plus `"overrides": { "minimatch": "$minimatch" }` : **tous**
  les `minimatch` de l'arbre (spectral-core, glob@7, …) pointent ici.
- Ce dossier dépend de `minimatch-upstream`, alias npm de
  **`minimatch@11.0.4`** : le code réellement exécuté est donc la version
  corrigée, pas une réécriture.
- `index.js` ne fait que rétablir l'ancienne forme d'export
  (`module.exports = fn`, `fn.default`, exports nommés).

Preuve de non-régression : `npm ci && npm run lint` doit passer, et
`spectral lint` doit toujours **détecter** une erreur (sinon les règles ne
s'appliquent plus et le lint passerait à vide).

## Limites connues

- `glob@7.2.3` (dépendance de build de `@rollup/plugin-commonjs`, jamais
  appelée par `spectral lint` sur ce dépôt) n'est pas compatible avec
  minimatch 11 : `glob.sync()` y lèverait `TypeError`. Chemin mort aujourd'hui
  (vérifié : ruleset local + `spectral:oas` passent), à garder en tête si un
  futur ruleset active les motifs `ignore` du bundler.
- `minimatch@11` déclare `engines: node "20 || >=22"` : d'où
  `"engines": { "node": ">=20" }` dans `package.json`.

## Quand supprimer ce dossier

Dès qu'une version de `@stoplight/spectral-core` dépend de `minimatch@^11`
(ou que l'on remplace `spectral-cli` par un usage direct de `spectral-core`) :
retirer la `devDependency`, l'`override` et ce dossier, puis `npm install`.
