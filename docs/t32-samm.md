# Preuves T32 — validation humaine

Snapshot vérifié : `fd65e37`. Chaque lien ci-dessous a été résolu sur ce
commit (module + ligne), pas sur une branche mouvante.

## T32.1 / #87 : rendu avant/après

- Validation des chemins et exclusion des fichiers privés, **insensible à la
  casse** (`.Git/config`, `.ENV`, `.Env.local`) :
  [TextChange](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L81).
- Valeurs exclues des représentations, proposition bornée et total des
  valeurs borné (`MAX_SECRET_BYTES`) :
  [Proposal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L109).
- Masquage avant diff, motif compilé une fois, marqueur **constant**
  `<MASKED>` (aucun oracle de longueur), `re.error` convertie en erreur
  statique, échappement des contrôles terminal :
  [_secret_pattern](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L154),
  [_masked](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L170),
  [render_diff](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L190).
- Rendu défensif (masquage/`difflib` en `MemoryError`/`KeyboardInterrupt`) :
  [_render](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L217).
- Preuves : [masquage de tous les fichiers](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L74),
  [valeurs courtes et chevauchantes](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L129),
  [marqueur sans longueur](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1278),
  [chemins refusés](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L112),
  [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L740),
  [motif de masquage borné](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L703),
  [256 valeurs longues acceptées](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L708),
  [rendu au plafond MAX_CHANGES/MAX_TEXT_CHARS](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1251),
  [rendu en MemoryError/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1040).
- Menaces : divulgation de secrets (valeur et longueur) et falsification de
  l'affichage terminal.
- Documentation : `docs/interactive-review.md`.

## T32.2 / #88 : boucle Y/N/E

- Trois actions fermées, aucune par défaut :
  [Choice et parse_choice](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L233).
- Boucle bornée, backend T30 injecté, exceptions backend converties en
  `ReviewError` statique, journal écrit **après** l'action avec `applied` :
  [review_proposal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L673).
- Points d'injection normalisés : `ask`, `apply`/`edit` et rendu capturent
  `BaseException` (donc `SystemExit("<valeur>")` et `KeyboardInterrupt`),
  le journal injecté et sa résolution sont encadrés :
  [_ask](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L511), [_journal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L554),
  [_journal_failure](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L541),
  [_resolve_journal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L531).
- Lecture clavier bornée (`readline(MAX_ANSWER_CHARS + 2)`) :
  [_stdin_ask](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L486).
- Double faute backend + journal : l'erreur statique est levée hors du
  `except`, donc sans `__context__` backend (valeur, chemin).
- Ré-ancrage après édition : `edited.finding` identique et
  `current.secrets ⊆ edited.secrets` (ajout permis, retrait refusé).
- Choix journalisé (fichier, ligne, action, date, résultat), jamais la
  valeur : [Decision](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L278),
  [DecisionJournal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L417).
- Preuves : [Y applique puis journalise applied=true](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L667),
  [N n'appelle jamais le backend](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L187),
  [E réaffiche puis valide](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L203),
  [E ne déplace pas le finding](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1209),
  [E ne retire aucune valeur connue](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1222),
  [E peut ajouter une valeur connue](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1233),
  [entrée invalide redemandée](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L227),
  [épuisement borné](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L246),
  [refus sans backend](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L263),
  [échec apply : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L630),
  [échec edit : erreur statique + journal applied=false](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L650),
  [apply en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L871),
  [edit en SystemExit/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L892),
  [double faute apply + journal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1102),
  [double faute edit + journal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1130),
  [journal injecté en OSError](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L911),
  [journal sans append](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L933),
  [erreurs statiques du journal préservées](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L967),
  [journal par défaut cassé](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1007),
  [lecture bornée](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1302),
  [flux absents](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1329),
  [EOF](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1335),
  [édition annulée](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L282),
  [boucle d'édition bornée](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L301),
  [journal falsifié détecté](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L388),
  [applied incohérent refusé](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L749),
  [champs de types étrangers](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1365),
  [permissions 0600](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L401),
  [EOF interrompt sans journal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L513).
- Menaces : auto-validation implicite (STRIDE Elevation of Privilege),
  écriture non traçable ou audit mensonger (Repudiation), fuite de valeur
  ou de longueur par l'affichage ou une exception backend (Information
  Disclosure), affaiblissement du masquage par une édition.
- Limite assumée : `apply`/`edit` restent à livrer par T30 (#83–#86) ; sans
  backend, `Y`/`E` échouent en code 2 au lieu d'écrire.

## T32.3 / #89 : mode non interactif

- `ci` prioritaire, `interactive=True` **insuffisant** sans TTY, refus par
  défaut de tout TTY douteux (`getattr` et `isatty` compris) :
  [is_interactive](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L588),
  [review_proposals](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L788).
- Session bornée et paresseuse, options validées avant consommation,
  producteur non itérable normalisé :
  [_bounded_proposals](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L770).
- Rapport seul, décompte et statut sans écriture, rendu défensif :
  [ReviewReport](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L629),
  [_status](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L663).
- Preuves : [aucun appel backend/journal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L323),
  [ci gagne sur interactive](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L340),
  [interactive=True sur stdin pipé](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L582),
  [review_proposal seul sans TTY](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L613),
  [stdin par défaut sans TTY](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L601),
  [TTY absent/faux/en erreur](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L359),
  [isatty en RuntimeError](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L695),
  [isatty en KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L826),
  [__getattr__ hostile](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1091),
  [OSError/KeyboardInterrupt statiques](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L678),
  [générateur infini borné](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L940),
  [borne exacte acceptée](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L957),
  [producteur non itérable](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1022),
  [producteur qui lève](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1027),
  [options invalides sans consommation](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1154),
  [rendu du rapport en échec](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1060),
  [scan --ci laisse git status propre](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L427).
- Menace : auto-validation sans humain (STRIDE Elevation of Privilege) et
  épuisement de disponibilité par un producteur non borné.
- Code de sortie attendu : 0 si `remaining == 0`, 1 si des propositions
  restent, 2 sur erreur d'outillage.
- Limite assumée : la borne porte sur le **nombre** de propositions
  (`MAX_PROPOSALS`) et sur chaque texte (`MAX_TEXT_CHARS`, `MAX_CHANGES`) ;
  le volume total reste la responsabilité du producteur T30, qui doit
  fournir des propositions par lots.

## T32.4 / #90 : tests du flux interactif

- Clavier simulé par injection de `ask` (alternative documentée au
  `CliRunner(input=...)`), un test par action plus les cas d'erreur :
  [tests/test_cli_review.py](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L169).
- Un test `CliRunner` réel couvre le mode CI sans écriture :
  [scan --ci](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L427).
- Validation locale : `python -m pytest tests/test_cli_review.py` :
  **145 passed** ; couverture `heimdall/cli/review.py` **95 %**.
- `ruff check`, `mypy` strict (47 fichiers) et `bandit -r heimdall` : OK.
- Suite complète : **2357 passed**, **15 skipped**, **4480 subtests passed**.
- Documentation : `docs/interactive-review.md`. CI non déclenchée, sur demande.

## Correctifs des revues de code

### Revue 1 — HIGH et MEDIUM (`50536ec`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [HIGH] `interactive=True` contournait le TTY | `is_interactive` exigé en plus du drapeau | [stdin pipé](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L582), [review_proposal seul](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L613) |
| [HIGH] exceptions backend brutes + journal mensonger | `ReviewError from None` + `applied: bool` écrit après l'action | [échec apply](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L630), [échec edit](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L650), [applied incohérent](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L749) |
| [MEDIUM] motif de masquage géant | total borné, compilation unique, `re.error` statique | [motif borné](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L703), [256 valeurs](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L708) |
| [MEDIUM] grammaire de variable trop lâche | `[A-Z][A-Z0-9_]{1,63}` pour `_VARIABLE` et `_ENV_REFERENCE` | [grammaire invariant 2](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L723), [références d'environnement](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L728) |
| [LOW] casse des gardes `.env`/`.git` | comparaison `lower()` | [chemins privés insensibles à la casse](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L740) |
| [LOW] exceptions `input`/`isatty` trop étroites | `OSError`/`ValueError`/`KeyboardInterrupt` → statique ; `isatty` en erreur → non interactif | [OSError/KeyboardInterrupt](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L678), [RuntimeError](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L695) |

### Revue 2 — LOW sur les points d'injection (`aedcc87`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] exceptions d'un `ask`/`notify` injecté non normalisées | [_ask](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L511) convertit toute exception en erreur statique ; [_notify](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L570) reste best-effort | [ask en OSError](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L772), [ReviewError préservée](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L790), [notify en OSError](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L802) |
| [LOW] `is_interactive` laissait passer `BaseException` | `except BaseException` → refus par défaut | [KeyboardInterrupt/SystemExit](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L826) |
| Garde de chemin du journal non couverte | `_prepare_path` de T33 refusé aussi ici | [relatif et `..`](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L835) |

### Revue 3 — LOW `SystemExit` d'un `ask` injecté (`5e9617d`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `_ask` laissait passer `SystemExit("<valeur>")` | [_ask](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L511) capture `BaseException` | [SystemExit portant une valeur](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L847) |
| Choix `_notify` à documenter | `_notify` garde `Exception` seul, volontairement (aucune entrée lue) | [_notify](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L570) |

### Revue 4 — LOW `apply`/`edit`, journal et borne de session (`5ed7cf6`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `apply`/`edit` ne capturaient que `Exception` | `BaseException` → journal `applied:false` puis `ReviewError` statique | [apply](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L871), [edit](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L892) |
| [LOW] journal injecté non normalisé | [_journal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L554) réémet les erreurs statiques et convertit le reste | [journal en OSError](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L911), [sans append](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L933), [statiques préservées](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L967) |
| [LOW] `review_proposals` sans borne | consommation paresseuse bornée par `MAX_PROPOSALS` (1024) | [générateur infini borné](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L940), [borne exacte](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L957) |

### Revue 5 — LOW environnement, producteur et rendu (`9cece36`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] résolution du journal hors contrat (`Path.home()`, NUL) | [decision_journal_path](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L315), [DecisionJournal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L417), [_resolve_journal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L531) | [chemin NUL](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L984), [HOME indisponible](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L991), [argument non-Path](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1002), [journal par défaut cassé](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1007), [JournalError préservée](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1075) |
| [LOW] producteur non itérable (`TypeError` brut) | [_bounded_proposals](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L770) | [None/entier/objet](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1022), [générateur qui lève](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1027) |
| [LOW] rendu non gardé (`MemoryError`, `KeyboardInterrupt`) | [_render](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L217), [ReviewReport](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L629) | [boucle](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1040), [rapport](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1060) |

### Revue 6 — LOW `getattr`, double faute, ordre, journal (`56e71c5`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `getattr` hors `try` dans `is_interactive` | `getattr` déplacé dans le `try` | [__getattr__ hostile](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1091) |
| [LOW] `__context__` backend conservée sur double faute | drapeau + erreur statique levée **hors** du `except` ; [_journal_failure](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L541) absorbe la panne du journal | [double faute apply](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1102), [double faute edit](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1130) |
| [LOW] options validées après consommation du producteur | validation `ci`/`interactive` avant [_bounded_proposals](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L770) | [aucune consommation](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1154) |
| [LOW] `read`/`append` ne capturaient pas `MemoryError`/`KeyboardInterrupt` | `BaseException` capturé, `JournalError` réémis ou converti | [read](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1173), [append](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1191) |

### Revue 7 — LOW ré-ancrage de l'édition (`bdfe3d8`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] `edit` pouvait changer le `finding` ou réduire `secrets`, affaiblissant le masquage du ré-affichage | [review_proposal](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L673) exige `edited.finding == current.finding` et `current.secrets ⊆ edited.secrets` (ajout permis, retrait refusé) | [finding déplacé refusé](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1209), [secrets réduits refusés](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1222), [ajout accepté](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1233) |
| Volume de session à documenter | borne sur le nombre (`MAX_PROPOSALS`) et par texte (`MAX_CHANGES`, `MAX_TEXT_CHARS`) ; volume total = responsabilité du producteur T30 | [rendu au plafond](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1251) |

### Revue 8 — LOW marqueur, lecture, journal (`fd65e37`)

| Constat | Correctif | Preuve |
| --- | --- | --- |
| [LOW] marqueur `<MASKED_N>` révélait `len(valeur)` | marqueur **constant** (`MASKED_MARKER` = `<MASKED>`) | [marqueur sans longueur](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1278) |
| [LOW] `input()` lisait une réponse non bornée | [_stdin_ask](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L486) lit via `readline(MAX_ANSWER_CHARS + 2)` | [lecture bornée](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1302), [flux absents](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1329), [EOF](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1335) |
| [LOW] relecture du journal sans contrôle de types | [_valid_target](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/heimdall/cli/review.py#L360) : chemin conforme Finding, entier ≥ 1, empreinte hex 64 | [champs étrangers](https://github.com/Cezar277/heimdall/blob/fd65e371257eeb10f53865959b330f9abd0808b7/tests/test_cli_review.py#L1365) |

Hors périmètre, signalé et non corrigé ici : le câblage CLI `heimdall review`
et ses codes de sortie 0/1/2 arrivent avec le backend T30 (#83–#86) ; le
regroupement de #87–#90 dans une seule PR est une exception demandée par
l'utilisateur, tracée dans la PR #192.
