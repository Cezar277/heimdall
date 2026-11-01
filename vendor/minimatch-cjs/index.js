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
//
// minimatch@11.0.3 defaults `braceExpandMax` to 100_000. On the Spectral
// `files:` path a hostile `**/../` pattern can still spend seconds in
// firstPhasePreProcess/secondPhasePreProcess. Spectral only passes
// `{ matchBase: true }`, so the shim injects a much lower bound by default.
// Callers can still override it explicitly.
const { minimatch, Minimatch } = require('minimatch-v11');

const DEFAULT_OPTIONS = Object.freeze({ braceExpandMax: 1000 });

function withDefaults(options) {
  return { ...DEFAULT_OPTIONS, ...options };
}

function shim(source, pattern, options) {
  return minimatch(source, pattern, withDefaults(options));
}

class ShimMinimatch extends Minimatch {
  constructor(pattern, options) {
    super(pattern, withDefaults(options));
  }
}

Object.assign(shim, minimatch);
shim.Minimatch = ShimMinimatch;
// Certains consommateurs utilisent l'export nommé de minimatch >= 9.
shim.minimatch = shim;

module.exports = shim;
