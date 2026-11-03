'use strict'

// Shim CJS de compatibilité — voir README.md avant toute modification.
//
// minimatch 9+ a supprimé `module.exports = fn` au profit d'exports nommés
// (`{ minimatch, Minimatch, ... }`). Deux appelants de l'arbre npm du dépôt
// attendent encore l'ancienne forme :
//   - @stoplight/spectral-core@1.24.0 :
//       tslib.__importDefault(require('minimatch')).default(source, pattern, opts)
//     → sans `default`, TypeError « m.default is not a function » ;
//   - glob@7.2.3 (via @rollup/plugin-commonjs) :
//       require('minimatch').Minimatch
//
// Le code exécuté reste celui de minimatch 11.0.4 (version corrigée de
// GHSA-g3hv-75wg-m249) : ce fichier ne fait que rétablir la forme d'export.
const upstream = require('minimatch-upstream')

const minimatch = upstream.minimatch

module.exports = minimatch
module.exports.default = minimatch

// Recopie les exports nommés (Minimatch, filter, braceExpand, ...).
for (const key of Object.keys(upstream)) {
  module.exports[key] = upstream[key]
}
