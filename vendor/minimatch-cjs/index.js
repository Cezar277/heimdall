'use strict';

// @stoplight/spectral-core@1.24.0 (latest) does:
//
//   const minimatch_1 = tslib.__importDefault(require('minimatch'));
//   minimatch_1.default(source, pattern, { matchBase: true });
//
// minimatch >= 9 ships a CommonJS build whose namespace object has
// `__esModule: true` but no `default` export. tslib.__importDefault() therefore
// returns that namespace as-is and `.default` is undefined. Exporting the
// callable function directly gives the wrapper the shape it expects, while
// keeping the named helpers (Minimatch, filter, match, ...) attached.
const { minimatch } = require('minimatch-v11');

module.exports = minimatch;
// Certains consommateurs utilisent l'export nommé de minimatch >= 9.
module.exports.minimatch = minimatch;
