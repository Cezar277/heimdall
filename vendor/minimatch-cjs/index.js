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
// minimatch@11.0.3 defaults `braceExpandMax` to 100_000. This option bounds
// both brace expansion and the `globParts` growth in firstPhasePreProcess().
// On the Spectral `files:` path a hostile `**/../` pattern can still spend
// seconds in firstPhasePreProcess/secondPhasePreProcess. Spectral only passes
// `{ matchBase: true }`, so the shim injects a much lower bound by default for
// the callable function, the Minimatch class, and the filter/match/braceExpand
// helpers. Callers can still override it explicitly.
//
// Les exports sont une ALLOWLIST explicite : on ne recopie jamais le namespace
// amont en aveugle (`Object.assign`), sinon un futur helper qui construirait un
// `Minimatch` interne échapperait à la borne. Le test
// `tests/js/minimatch-shim.test.js` vérifie l'allowlist ET fige le sha256 de ce
// fichier (dépendance `file:` : aucun hash registre ne protège son contenu).
const upstream = require('minimatch-v11');

const {
  minimatch,
  Minimatch,
  filter,
  match,
  braceExpand,
  defaults,
  sep,
  GLOBSTAR,
  escape,
  unescape,
} = upstream;

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

shim.Minimatch = ShimMinimatch;
shim.filter = (pattern, options) => filter(pattern, withDefaults(options));
shim.match = (list, pattern, options) =>
  match(list, pattern, withDefaults(options));
shim.braceExpand = (pattern, options) =>
  braceExpand(pattern, withDefaults(options));
// `defaults(def)` renvoie une fonction `minimatch` pré-configurée (et non un
// objet d'options) : on lui passe donc la borne, puis on rétablit la forme
// d'export attendue par les appelants (`default` / `minimatch`).
shim.defaults = (options) => {
  const bound = defaults(withDefaults(options));
  return Object.assign(bound, { default: bound, minimatch: bound });
};
// Constantes et helpers purs : ils ne construisent aucun `Minimatch`.
shim.sep = sep;
shim.GLOBSTAR = GLOBSTAR;
shim.escape = escape;
shim.unescape = unescape;
// minimatch@11 n'exporte plus makeRe ; on le garde conditionnellement pour
// une future version qui le réintroduirait.
if (typeof upstream.makeRe === 'function') {
  shim.makeRe = (pattern, options) =>
    upstream.makeRe(pattern, withDefaults(options));
}
// Certains consommateurs utilisent l'export nommé de minimatch >= 9, d'autres
// la forme `default` (cf. tslib.__importDefault ci-dessus).
shim.minimatch = shim;
shim.default = shim;

module.exports = shim;
