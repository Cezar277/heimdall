# minimatch-cjs

Compat shim local, sans code métier, qui expose `minimatch >= 11` via l'API
CommonJS appelable attendue par `@stoplight/spectral-core`.

## Pourquoi ce paquet existe

L'alerte Dependabot `GHSA-g3hv-75wg-m249` (CVE-2026-118764) concerne
`minimatch < 11.0.1`. La dernière version de `@stoplight/spectral-cli`
(6.17.0) dépend de `@stoplight/spectral-core@1.24.0`, qui épingle encore
`minimatch@^3.1.4`. Aucune version publiée de Spectral ne permet donc de
monter `minimatch` sans override.

Le code compilé de `spectral-core` fait :

```js
const minimatch_1 = tslib.__importDefault(require('minimatch'));
minimatch_1.default(source, pattern, { matchBase: true });
```

Or le build CommonJS de `minimatch >= 9` expose un namespace ES
(`__esModule: true`, pas d'export `default`). Un override direct vers
`minimatch@11` ferait donc échouer Spectral avec
`minimatch_1.default is not a function`.

Ce shim réexporte la fonction `minimatch` de `minimatch@11` comme
`module.exports`. `tslib.__importDefault()` la transforme alors en
`{ default: fn }`, ce qui restaure le contrat attendu par `spectral-core`.

## Borne DoS

`minimatch@11.0.3` garde un `braceExpandMax` par défaut de 100 000. Le shim
force `braceExpandMax: 1000` pour l'appel callable et pour la classe
`Minimatch` ; un appelant peut toujours fournir une valeur explicite. Cela
borne `firstPhasePreProcess`/`secondPhasePreProcess` sur le chemin `files:`
de Spectral, sans changer les motifs légitimes du contrat.

Le contenu de `vendor/minimatch-cjs/` est couvert par `.github/CODEOWNERS`
(revue obligatoire du mainteneur, si la protection de `main` active
« Require review from Code Owners ») et par les tests
`tests/js/minimatch-shim.test.js`.

## Chaîne de dépendances

- `package.json` (racine) déclare `minimatch: file:./vendor/minimatch-cjs`
  en `devDependency` et l'override global `"minimatch": "$minimatch"`.
- Ce paquet dépend de l'alias `minimatch-v11` (`npm:minimatch@11.0.3`) pour
  éviter que l'override global ne s'applique à sa propre dépendance.
- L'override `@rollup/plugin-commonjs@29.0.3` supprime l'ancienne chaîne
  `glob@7 -> minimatch@3` utilisée par le bundler de rulesets Spectral.
  Le plugin 29 n'utilise plus `glob`.

## Node

`@stoplight/spectral-cli@6.17.0` exige Node `^22.0 || >=24.0` ; le champ
`engines` de la racine reprend cette contrainte et `.npmrc` active
`engine-strict=true` pour que `npm ci` échoue tôt sur une version non
supportée. Le shim reste, lui, compatible avec les versions déclarées par
`minimatch@11` (`18 || 20 || >=22`).

## Vérifications

```bash
npm ci --no-audit --no-fund
npm run test:js    # shim, lockfile et bundler Spectral
npm run lint
npm audit          # doit afficher 0 vulnérabilité
```

## Quand supprimer ce shim

Dès qu'une version publiée de `@stoplight/spectral-core` déclare
`minimatch >= 11` (ou publie un correctif compatible), supprimer
`vendor/minimatch-cjs`, la `devDependency` `minimatch` et l'override
`"minimatch": "$minimatch"`, puis régénérer `package-lock.json`.
